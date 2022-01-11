use futures::{channel::mpsc, executor::block_on, SinkExt, StreamExt};
use std::cell::RefCell;
use structopt::StructOpt;
use zksync_api::run_api;
use zksync_core::{genesis_init, run_core, wait_for_tasks};
use zksync_eth_client::EthereumGateway;
use zksync_eth_sender::run_eth_sender;
use zksync_forced_exit_requests::run_forced_exit_requests_actors;
use zksync_gateway_watcher::run_gateway_watcher_if_multiplexed;
use zksync_prometheus_exporter::run_prometheus_exporter;
use zksync_witness_generator::run_prover_server;

use zksync_config::ZkSyncConfig;
use zksync_storage::ConnectionPool;

#[derive(Debug, Clone, Copy)]
pub enum ServerCommand {
    Genesis,
    Launch,
}

#[derive(StructOpt)]
#[structopt(name = "zkSync operator node", author = "Matter Labs")]
struct Opt {
    /// Generate genesis block for the first contract deployment
    #[structopt(long)]
    genesis: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    let config = ZkSyncConfig::from_env();
    let mut _sentry_guard = None;
    let server_mode = if opt.genesis {
        ServerCommand::Genesis
    } else {
        _sentry_guard = vlog::init();//初始化日志系统
        ServerCommand::Launch
    };

    if let ServerCommand::Genesis = server_mode {//初始化模式，进行初始化之后返回
        vlog::info!("Performing the server genesis initialization",);
        genesis_init(&config).await;//初始化
        return Ok(());
    }

    // It's a `ServerCommand::Launch`, perform the usual routine.
    vlog::info!("Running the zkSync server");

    let connection_pool = ConnectionPool::new(None);//创建连接池
    let eth_gateway = EthereumGateway::from_config(&config);//创建路由，可以1-多个路由

    let gateway_watcher_task_opt = run_gateway_watcher_if_multiplexed(eth_gateway.clone(), &config);//如果有多个client，则启动监控器

    // Handle Ctrl+C
    let (stop_signal_sender, mut stop_signal_receiver) = mpsc::channel(256);//设置停止监听
    {
        let stop_signal_sender = RefCell::new(stop_signal_sender.clone());
        ctrlc::set_handler(move || {
            let mut sender = stop_signal_sender.borrow_mut();
            block_on(sender.send(true)).expect("Ctrl+C signal send");
        })
        .expect("Error setting Ctrl+C handler");
    }

    // Run prometheus data exporter.
    let (prometheus_task_handle, counter_task_handle) =
        run_prometheus_exporter(connection_pool.clone(), config.api.prometheus.port, true);//运行监控数据导出器

    // Run core actors.
    vlog::info!("Starting the Core actors");
    let core_task_handles = run_core(
        connection_pool.clone(),
        stop_signal_sender.clone(),
        eth_gateway.clone(),
        &config,
    )
    .await
    .expect("Unable to start Core actors");

    // Run API actors.
    vlog::info!("Starting the API server actors");
    let api_task_handle = run_api(
        connection_pool.clone(),
        stop_signal_sender.clone(),
        eth_gateway.clone(),
        &config,
    );

    // Run Ethereum sender actors.
    vlog::info!("Starting the Ethereum sender actors");
    let eth_sender_task_handle =
        run_eth_sender(connection_pool.clone(), eth_gateway.clone(), config.clone());

    // Run prover server & witness generator.
    vlog::info!("Starting the Prover server actors");
    let database = zksync_witness_generator::database::Database::new(connection_pool.clone());
    run_prover_server(database, stop_signal_sender, ZkSyncConfig::from_env());

    vlog::info!("Starting the ForcedExitRequests actors");
    let forced_exit_requests_task_handle = run_forced_exit_requests_actors(connection_pool, config);

    tokio::select! {
        _ = async { wait_for_tasks(core_task_handles).await } => {
            // We don't need to do anything here, since Core actors will panic upon future resolving.
        },
        _ = async { api_task_handle.await } => {
            panic!("API server actors aren't supposed to finish their execution")
        },
        _ = async { gateway_watcher_task_opt.unwrap().await }, if gateway_watcher_task_opt.is_some() => {
            panic!("Gateway Watcher actors aren't supposed to finish their execution")
        }
        _ = async { eth_sender_task_handle.await } => {
            panic!("Ethereum Sender actors aren't supposed to finish their execution")
        },
        _ = async { prometheus_task_handle.await } => {
            panic!("Prometheus exporter actors aren't supposed to finish their execution")
        },
        _ = async { counter_task_handle.unwrap().await } => {
            panic!("Operation counting actor is not supposed to finish its execution")
        },
        _ = async { forced_exit_requests_task_handle.await } => {
            panic!("ForcedExitRequests actor is not supposed to finish its execution")
        },
        _ = async { stop_signal_receiver.next().await } => {
            vlog::warn!("Stop signal received, shutting down");
        }
    };

    Ok(())
}
