//! Ethereum watcher polls the Ethereum node for new events
//! such as PriorityQueue events or NewToken events.
//! New events are accepted to the zkSync network once they have the sufficient amount of confirmations.
//!
//! Poll interval is configured using the `ETH_POLL_INTERVAL` constant.
//! Number of confirmations is configured using the `CONFIRMATIONS_FOR_ETH_EVENT` environment variable.

// Built-in deps
use std::collections::HashMap;
use std::time::{Duration, Instant};

// External uses
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use thiserror::Error;

pub use client::{get_web3_block_number, EthHttpClient};
use itertools::Itertools;
use tokio::{task::JoinHandle, time};
use web3::types::{Address, BlockNumber};

// Workspace deps
use zksync_api_types::{
    v02::{
        pagination::{Paginated, PaginationDirection, PaginationQuery, PendingOpsRequest},
        transaction::{L1Transaction, Transaction, TransactionData, TxInBlockStatus},
    },
    Either,
};
use zksync_config::ZkSyncConfig;
use zksync_crypto::params::PRIORITY_EXPIRATION;
use zksync_eth_client::ethereum_gateway::EthereumGateway;
use zksync_types::{
    tx::TxHash, NewTokenEvent, Nonce, PriorityOp, PubKeyHash, RegisterNFTFactoryEvent, SerialId,
    ZkSyncPriorityOp, H256,
};

// Local deps
use self::{client::EthClient, eth_state::ETHState, received_ops::sift_outdated_ops};

mod client;
mod eth_state;
mod received_ops;

#[cfg(test)]
mod tests;

/// As `infura` may limit the requests, upon error we need to wait for a while
/// before repeating the request.
const RATE_LIMIT_DELAY: Duration = Duration::from_secs(30);

/// Ethereum Watcher operating mode.
///
/// Normally Ethereum watcher will always poll the Ethereum node upon request,
/// but unfortunately `infura` may decline requests if they are produced too
/// often. Thus, upon receiving the order to limit amount of request, Ethereum
/// watcher goes into "backoff" mode in which polling is disabled for a
/// certain amount of time.
#[derive(Debug)]
pub enum WatcherMode {
    /// ETHWatcher operates normally.
    Working,
    /// Polling is currently disabled.
    Backoff(Instant),
}

#[derive(Debug)]
pub enum EthWatchRequest {
    PollETHNode,
    GetPriorityOpBySerialId {
        serial_id: u64,
        resp: oneshot::Sender<Option<PriorityOp>>,
    },
    GetPriorityQueueOps {
        op_start_id: u64,
        max_chunks: usize,
        resp: oneshot::Sender<Vec<PriorityOp>>,
    },
    GetUnconfirmedDeposits {
        address: Address,
        resp: oneshot::Sender<Vec<PriorityOp>>,
    },
    GetUnconfirmedOps {
        query: PaginationQuery<PendingOpsRequest>,
        resp: oneshot::Sender<Paginated<Transaction, u64>>,
    },
    GetUnconfirmedOpByEthHash {
        eth_hash: H256,
        resp: oneshot::Sender<Option<PriorityOp>>,
    },
    GetUnconfirmedOpByTxHash {
        tx_hash: TxHash,
        resp: oneshot::Sender<Option<PriorityOp>>,
    },
    GetUnconfirmedOpByAnyHash {
        hash: TxHash,
        resp: oneshot::Sender<Option<PriorityOp>>,
    },
    GetNewTokens {
        last_eth_block: Option<u64>,
        resp: oneshot::Sender<Vec<NewTokenEvent>>,
    },
    GetRegisterNFTFactoryEvents {
        last_eth_block: Option<u64>,
        resp: oneshot::Sender<Vec<RegisterNFTFactoryEvent>>,
    },
    IsPubkeyChangeAuthorized {
        address: Address,
        nonce: Nonce,
        pubkey_hash: PubKeyHash,
        resp: oneshot::Sender<bool>,
    },
    IsContractERC20 {
        address: Address,
        resp: oneshot::Sender<bool>,
    },
}

#[derive(Debug, Error)]
#[error("A priority op log is missing: last processed id is {0}, next is {1}")]
struct MissingPriorityOpError(SerialId, SerialId);

fn is_missing_priority_op_error(error: &anyhow::Error) -> bool {
    error.is::<MissingPriorityOpError>()
}

pub struct EthWatch<W: EthClient> {
    client: W,
    eth_state: ETHState,
    /// All ethereum events are accepted after sufficient confirmations to eliminate risk of block reorg.
    /// 在充分确认以太坊重组风险后，所有以太坊事件都将被接收
    number_of_confirmations_for_event: u64,
    mode: WatcherMode,
}

impl<W: EthClient> EthWatch<W> {
    pub fn new(client: W, number_of_confirmations_for_event: u64) -> Self {
        Self {
            client,
            eth_state: ETHState::default(),
            mode: WatcherMode::Working,
            number_of_confirmations_for_event,
        }
    }

    /// Atomically replaces the stored Ethereum state.
    fn set_new_state(&mut self, new_state: ETHState) {
        self.eth_state = new_state;
    }
    //获取没有确认的事件
    async fn get_unconfirmed_ops(
        &mut self,
        current_ethereum_block: u64,
    ) -> anyhow::Result<Vec<PriorityOp>> {
        // We want to scan the interval of blocks from the latest one up to the oldest one which may
        // have unconfirmed priority ops.
        // `+ 1` is added because if we subtract number of confirmations, we'll obtain the last block
        // which has operations that must be processed. So, for the unconfirmed operations, we must
        // start from the block next to it.
        // 我们想要扫描从最新的块到可能具有未确认优先级操作的最旧的块的间隔。
        // 添加 `+ 1` 是因为如果我们减去确认次数，我们将获得最后一个必须处理的具有操作的块。所以，对于未确认的操作，我们必须从它旁边的块开始。
        let block_from_number =
            current_ethereum_block.saturating_sub(self.number_of_confirmations_for_event) + 1;
        let block_from = BlockNumber::Number(block_from_number.into());
        let block_to = BlockNumber::Latest;

        self.client
            .get_priority_op_events(block_from, block_to)//获取优先操作事件
            .await
    }
    //同步区块
    async fn process_new_blocks(&mut self, last_ethereum_block: u64) -> anyhow::Result<()> {
        debug_assert!(self.eth_state.last_ethereum_block() < last_ethereum_block);
        debug_assert!(self.eth_state.last_ethereum_block() < last_ethereum_block);//double check

        // We have to process every block between the current and previous known values.
        // This is crucial since `eth_watch` may enter the backoff mode in which it will skip many blocks.
        // Note that we don't have to add `number_of_confirmations_for_event` here, because the check function takes
        // care of it on its own. Here we calculate "how many blocks should we watch", and the offsets with respect
        // to the `number_of_confirmations_for_event` are calculated by `update_eth_state`.
        // 我们必须处理当前和先前已知值之间的每个块。这是至关重要的，因为 `eth_watch` 可能会进入退避模式，在这种模式下它会跳过许多块。
        // 请注意，我们不必在此处添加 `number_of_confirmations_for_event`，因为检查函数会自行处理它。
        // 这里我们计算“我们应该观看多少块”，相对于 `number_of_confirmations_for_event` 的偏移量由 `update_eth_state` 计算。
        let mut next_priority_op_id = self.eth_state.next_priority_op_id();//下一个应该优先处理的序列号
        let previous_ethereum_block = self.eth_state.last_ethereum_block();//上一个eth区块号
        let block_difference = last_ethereum_block.saturating_sub(previous_ethereum_block);//计算区块差额

        let updated_state = self
            .update_eth_state(last_ethereum_block, block_difference)
            .await?;

        // It's assumed that for the current state all priority operations have consecutive ids,
        // i.e. there're no gaps. Thus, there're two opportunities for missing them: either
        // we're missing last operations from the previous ethereum blocks range or there's a gap
        // in the updated state.

        // Extend the existing priority operations with the new ones.
        let mut priority_queue = sift_outdated_ops(self.eth_state.priority_queue());

        // Iterate through new priority operations sorted by their serial id.
        for (serial_id, op) in updated_state
            .priority_queue()
            .iter()
            .sorted_by_key(|(id, _)| **id)
        {
            if *serial_id > next_priority_op_id {
                // Updated state misses some logs for new priority operations.
                // We have to revert the block range back. This will only move the watcher
                // backwards for a single time since `last_ethereum_block` and its backup will
                // be equal.
                self.eth_state.reset_last_ethereum_block();
                return Err(anyhow::Error::from(MissingPriorityOpError(
                    next_priority_op_id,
                    *serial_id,
                )));
            } else {
                // Next serial id matched the expected one.
                priority_queue.insert(*serial_id, op.clone());
                next_priority_op_id = next_priority_op_id.max(*serial_id + 1);
            }
        }

        // Extend the existing token events with the new ones.
        let mut new_tokens = self.eth_state.new_tokens().to_vec();
        for token in updated_state.new_tokens() {
            new_tokens.push(token.clone());
        }
        // Remove duplicates.
        new_tokens.sort_by_key(|token_event| token_event.id.0);
        new_tokens.dedup_by_key(|token_event| token_event.id.0);

        let mut register_nft_factory_events =
            self.eth_state.new_register_nft_factory_events().to_vec();
        for event in updated_state.new_register_nft_factory_events() {
            register_nft_factory_events.push(event.clone());
        }
        // Remove duplicates.
        register_nft_factory_events.sort_by_key(|factory_event| factory_event.creator_address);
        register_nft_factory_events.dedup_by_key(|factory_event| factory_event.creator_address);

        let new_state = ETHState::new(
            last_ethereum_block,
            previous_ethereum_block,
            updated_state.unconfirmed_queue().to_vec(),
            priority_queue,
            new_tokens,
            register_nft_factory_events,
        );
        self.set_new_state(new_state);
        Ok(())
    }
    // 重新存储来自于eth的状态
    async fn restore_state_from_eth(&mut self, last_ethereum_block: u64) -> anyhow::Result<()> {
        let new_state = self
            .update_eth_state(last_ethereum_block, PRIORITY_EXPIRATION)
            .await?;//更新状态

        self.set_new_state(new_state);//设置新状态

        vlog::debug!("ETH state: {:#?}", self.eth_state);
        Ok(())
    }
    //更新存储的以太坊状态，当前区块号，以及需要更新的区块长度
    async fn update_eth_state(
        &mut self,
        current_ethereum_block: u64,
        unprocessed_blocks_amount: u64,
    ) -> anyhow::Result<ETHState> {
        let new_block_with_accepted_events =
            current_ethereum_block.saturating_sub(self.number_of_confirmations_for_event);//减去需要等待最终性的区块高度
        let previous_block_with_accepted_events =
            new_block_with_accepted_events.saturating_sub(unprocessed_blocks_amount);//减去没有同步的区块

        let unconfirmed_queue = self.get_unconfirmed_ops(current_ethereum_block).await?;//获取没有确认的操作
        let priority_queue: HashMap<u64, _> = self
            .client
            .get_priority_op_events(
                BlockNumber::Number(previous_block_with_accepted_events.into()),
                BlockNumber::Number(new_block_with_accepted_events.into()),
            )
            .await?
            .into_iter()
            .map(|priority_op| (priority_op.serial_id, priority_op.into()))
            .collect();//优先级操作
        let new_tokens = self
            .client
            .get_new_tokens_events(
                BlockNumber::Number(previous_block_with_accepted_events.into()),
                BlockNumber::Number(new_block_with_accepted_events.into()),
            )
            .await?;//新增token操作
        let new_register_nft_factory_events = self
            .client
            .get_new_register_nft_factory_events(
                BlockNumber::Number(previous_block_with_accepted_events.into()),
                BlockNumber::Number(new_block_with_accepted_events.into()),
            )
            .await?;//注册nft操作

        let mut new_priority_op_ids: Vec<_> = priority_queue.keys().cloned().collect();
        new_priority_op_ids.sort_unstable();
        vlog::debug!(
            "Updating eth state: block_range=[{},{}], new_priority_ops={:?}",
            previous_block_with_accepted_events,
            new_block_with_accepted_events,
            new_priority_op_ids
        );

        let mut new_priority_op_ids: Vec<_> = priority_queue.keys().cloned().collect();
        new_priority_op_ids.sort_unstable();
        vlog::debug!(
            "Updating eth state: block_range=[{},{}], new_priority_ops={:?}",
            previous_block_with_accepted_events,
            new_block_with_accepted_events,
            new_priority_op_ids
        );

        // The backup block number is not used.
        let state = ETHState::new(
            current_ethereum_block,
            current_ethereum_block,
            unconfirmed_queue,
            priority_queue,
            new_tokens,
            new_register_nft_factory_events,
        );
        Ok(state)
    }

    fn get_register_factory_event(
        &self,
        last_block_number: Option<u64>,
    ) -> Vec<RegisterNFTFactoryEvent> {
        let mut events = self.eth_state.new_register_nft_factory_events().to_vec();

        if let Some(last_block_number) = last_block_number {
            events = events
                .iter()
                .filter(|event| event.eth_block > last_block_number)
                .cloned()
                .collect();
        }

        events
    }
    fn get_new_tokens(&self, last_block_number: Option<u64>) -> Vec<NewTokenEvent> {
        let mut new_tokens = self.eth_state.new_tokens().to_vec();

        if let Some(last_block_number) = last_block_number {
            new_tokens = new_tokens
                .iter()
                .filter(|token| token.eth_block_number > last_block_number)
                .cloned()
                .collect();
        }

        new_tokens
    }
    //获取优先队列请求
    fn get_priority_requests(&self, first_serial_id: u64, max_chunks: usize) -> Vec<PriorityOp> {
        let mut result = Vec::new();

        let mut used_chunks = 0;
        let mut current_priority_op = first_serial_id;

        while let Some(op) = self.eth_state.priority_queue().get(&current_priority_op) {
            if used_chunks + op.as_ref().data.chunks() <= max_chunks {
                result.push(op.as_ref().clone());
                used_chunks += op.as_ref().data.chunks();
                current_priority_op += 1;
            } else {
                break;
            }
        }

        result
    }

    async fn is_new_pubkey_hash_authorized(
        &self,
        address: Address,
        nonce: Nonce,
        pub_key_hash: &PubKeyHash,
    ) -> anyhow::Result<bool> {
        let auth_fact_reset_time = self.client.get_auth_fact_reset_time(address, nonce).await?;
        if auth_fact_reset_time != 0 {
            return Ok(false);
        }
        let auth_fact = self.client.get_auth_fact(address, nonce).await?;
        Ok(auth_fact.as_slice() == tiny_keccak::keccak256(&pub_key_hash.data[..]))
    }

    fn find_ongoing_op_by_eth_hash(&self, eth_hash: H256) -> Option<PriorityOp> {
        self.eth_state
            .unconfirmed_queue()
            .iter()
            .find(|op| op.eth_hash == eth_hash)
            .cloned()
    }

    fn find_ongoing_op_by_tx_hash(&self, tx_hash: TxHash) -> Option<PriorityOp> {
        self.eth_state
            .unconfirmed_queue()
            .iter()
            .find(|op| op.tx_hash() == tx_hash)
            .cloned()
    }

    fn find_ongoing_op_by_any_hash(&self, hash: TxHash) -> Option<PriorityOp> {
        self.eth_state
            .unconfirmed_queue()
            .iter()
            .find(|op| op.tx_hash() == hash || op.eth_hash.as_ref() == hash.as_ref())
            .cloned()
    }
    //获取某地址存款优先列表
    fn get_ongoing_deposits_for(&self, address: Address) -> Vec<PriorityOp> {
        self.eth_state
            .unconfirmed_queue()
            .iter()
            .filter(|op| match &op.data {
                ZkSyncPriorityOp::Deposit(deposit) => {
                    // Address may be set to either sender or recipient.
                    deposit.from == address || deposit.to == address
                }
                _ => false,
            })
            .cloned()
            .collect()
    }
    //获取操作列表，并作了分页
    fn get_ongoing_ops_for(
        &self,
        query: PaginationQuery<PendingOpsRequest>,
    ) -> Paginated<Transaction, u64> {
        let all_ops = self
            .eth_state
            .unconfirmed_queue()
            .iter()
            .filter(|op| match &op.data {
                ZkSyncPriorityOp::Deposit(deposit) => {
                    // Address may be set to recipient.
                    deposit.to == query.from.address
                }
                ZkSyncPriorityOp::FullExit(full_exit) => query
                    .from
                    .account_id
                    .map(|account_id| account_id == full_exit.account_id)
                    .unwrap_or(false),
            });
        let count = all_ops.clone().count();
        let from_serial_id = match query.from.serial_id.inner {
            Either::Left(id) => id,
            Either::Right(_) => {
                if let Some(op) = all_ops.clone().max_by_key(|op| op.serial_id) {
                    op.serial_id
                } else {
                    return Paginated::new(
                        Vec::new(),
                        Default::default(),
                        query.limit,
                        query.direction,
                        0,
                    );
                }
            }
        };
        let ops: Vec<PriorityOp> = match query.direction {
            PaginationDirection::Newer => all_ops
                .sorted_by_key(|op| op.serial_id)
                .filter(|op| op.serial_id >= from_serial_id)
                .take(query.limit as usize)
                .cloned()
                .collect(),
            PaginationDirection::Older => all_ops
                .sorted_by(|a, b| b.serial_id.cmp(&a.serial_id))
                .filter(|op| op.serial_id <= from_serial_id)
                .take(query.limit as usize)
                .cloned()
                .collect(),
        };
        let txs: Vec<Transaction> = ops
            .into_iter()
            .map(|op| {
                let tx_hash = op.tx_hash();
                let tx = L1Transaction::from_pending_op(
                    op.data.clone(),
                    op.eth_hash,
                    op.serial_id,
                    tx_hash,
                );
                Transaction {
                    tx_hash,
                    block_number: None,
                    op: TransactionData::L1(tx),
                    status: TxInBlockStatus::Queued,
                    fail_reason: None,
                    created_at: None,
                    batch_id: None,
                }
            })
            .collect();
        Paginated::new(
            txs,
            from_serial_id,
            query.limit,
            query.direction,
            count as u32,
        )
    }

    async fn poll_eth_node(&mut self) -> anyhow::Result<()> {
        let start = Instant::now();
        let last_block_number = self.client.block_number().await?;//获取新的区块号

        if last_block_number > self.eth_state.last_ethereum_block() {//区块状态已经更新了
            self.process_new_blocks(last_block_number).await?;//进行同步新的区块
        }

        metrics::histogram!("eth_watcher.poll_eth_node", start.elapsed());
        Ok(())
    }

    // TODO try to move it to eth client
    fn is_backoff_requested(&self, error: &anyhow::Error) -> bool {
        error.to_string().contains("429 Too Many Requests")
    }

    fn enter_backoff_mode(&mut self) {
        let backoff_until = Instant::now() + RATE_LIMIT_DELAY;
        self.mode = WatcherMode::Backoff(backoff_until);
        // This is needed to track how much time is spent in backoff mode
        // and trigger grafana alerts
        metrics::histogram!("eth_watcher.enter_backoff_mode", RATE_LIMIT_DELAY);
    }

    fn polling_allowed(&mut self) -> bool {
        match self.mode {
            WatcherMode::Working => true,
            WatcherMode::Backoff(delay_until) => {
                if Instant::now() >= delay_until {
                    vlog::info!("Exiting the backoff mode");
                    self.mode = WatcherMode::Working;
                    true
                } else {
                    // We have to wait more until backoff is disabled.
                    false
                }
            }
        }
    }

    pub async fn run(mut self, mut eth_watch_req: mpsc::Receiver<EthWatchRequest>) {
        // As infura may be not responsive, we want to retry the query until we've actually got the
        // block number.
        // Normally, however, this loop is not expected to last more than one iteration.
        // 由于 infura 可能没有响应，我们想重试查询，直到我们真正得到块号。然而，通常情况下，这个循环预计不会持续超过一次迭代。
        let block = loop {
            let block = self.client.block_number().await;//获取当前的主网区块号

            match block {
                Ok(block) => {
                    break block;
                }
                Err(error) => {
                    vlog::warn!(
                        "Unable to fetch last block number: '{}'. Retrying again in {} seconds",
                        error,
                        RATE_LIMIT_DELAY.as_secs()
                    );

                    time::sleep(RATE_LIMIT_DELAY).await;
                }
            }
        };
        //已经取得区块高度，退出来
        // Code above is prepared for the possible rate limiting by `infura`, and will wait until we
        // can interact with the node again. We're not expecting the rate limiting to be applied
        // immediately after that, thus any error on this stage is considered critical and
        // irrecoverable.
        self.restore_state_from_eth(block)//存储新的区块头
            .await
            .expect("Unable to restore ETHWatcher state");

        while let Some(request) = eth_watch_req.next().await {
            match request {
                EthWatchRequest::PollETHNode => {
                    if !self.polling_allowed() {
                        // Polling is currently disabled, skip it.
                        continue;
                    }

                    let poll_result = self.poll_eth_node().await;

                    if let Err(error) = poll_result {
                        if self.is_backoff_requested(&error) {
                            vlog::warn!(
                                "Rate limit was reached, as reported by Ethereum node. \
                                Entering the backoff mode"
                            );
                            self.enter_backoff_mode();
                        } else if is_missing_priority_op_error(&error) {
                            vlog::warn!("{}\nEntering the backoff mode", error);
                            // Wait for some time and try to fetch new logs again.
                            self.enter_backoff_mode();
                        } else {
                            // Some unexpected kind of error, we won't shutdown the node because of it,
                            // but rather expect node administrators to handle the situation.
                            vlog::error!("Failed to process new blocks {}", error);
                        }
                    }
                }
                EthWatchRequest::GetPriorityQueueOps {
                    op_start_id,
                    max_chunks,
                    resp,
                } => {
                    resp.send(self.get_priority_requests(op_start_id, max_chunks))
                        .unwrap_or_default();
                }
                EthWatchRequest::GetUnconfirmedDeposits { address, resp } => {
                    let deposits_for_address = self.get_ongoing_deposits_for(address);
                    resp.send(deposits_for_address).ok();
                }
                EthWatchRequest::GetUnconfirmedOps { query, resp } => {
                    let unconfirmed_ops = self.get_ongoing_ops_for(query);
                    resp.send(unconfirmed_ops).ok();
                }
                EthWatchRequest::GetUnconfirmedOpByEthHash { eth_hash, resp } => {
                    let unconfirmed_op = self.find_ongoing_op_by_eth_hash(eth_hash);//找到对应hash的交易
                    resp.send(unconfirmed_op).unwrap_or_default();
                }
                EthWatchRequest::GetUnconfirmedOpByTxHash { tx_hash, resp } => {
                    let unconfirmed_op = self.find_ongoing_op_by_tx_hash(tx_hash);//找到对应消息整体hash的交易
                    resp.send(unconfirmed_op).unwrap_or_default();
                }
                EthWatchRequest::GetUnconfirmedOpByAnyHash { hash, resp } => {
                    let unconfirmed_op = self.find_ongoing_op_by_any_hash(hash);
                    resp.send(unconfirmed_op).unwrap_or_default();
                }
                EthWatchRequest::GetNewTokens {
                    last_eth_block,
                    resp,
                } => {
                    resp.send(self.get_new_tokens(last_eth_block)).ok();
                }
                EthWatchRequest::GetRegisterNFTFactoryEvents {
                    last_eth_block,
                    resp,
                } => {
                    resp.send(self.get_register_factory_event(last_eth_block))
                        .ok();
                }
                EthWatchRequest::IsPubkeyChangeAuthorized {
                    address,
                    nonce,
                    pubkey_hash,
                    resp,
                } => {
                    let authorized = self
                        .is_new_pubkey_hash_authorized(address, nonce, &pubkey_hash)
                        .await
                        .unwrap_or(false);
                    resp.send(authorized).unwrap_or_default();
                }
                EthWatchRequest::GetPriorityOpBySerialId { serial_id, resp } => {
                    resp.send(
                        self.eth_state
                            .priority_queue()
                            .get(&serial_id)
                            .map(|received_op| received_op.as_ref().clone()),
                    )
                    .unwrap_or_default();
                }
                EthWatchRequest::IsContractERC20 { address, resp } => resp
                    .send(self.client.is_contract_erc20(address).await)
                    .unwrap_or_default(),
            }
        }
    }
}

#[must_use]
pub fn start_eth_watch(
    eth_req_sender: mpsc::Sender<EthWatchRequest>,
    eth_req_receiver: mpsc::Receiver<EthWatchRequest>,
    eth_gateway: EthereumGateway,
    config_options: &ZkSyncConfig,
) -> JoinHandle<()> {
    let eth_client = EthHttpClient::new(//客户端
        eth_gateway,
        config_options.contracts.contract_addr,
        config_options.contracts.governance_addr,
    );

    let eth_watch = EthWatch::new(//注册监听
        eth_client,
        config_options.eth_watch.confirmations_for_eth_event,
    );

    tokio::spawn(eth_watch.run(eth_req_receiver));//线程运行监听接收

    let poll_interval = config_options.eth_watch.poll_interval();//间隔时间
    tokio::spawn(async move {
        let mut timer = time::interval(poll_interval);

        loop {
            timer.tick().await;
            eth_req_sender
                .clone()
                .send(EthWatchRequest::PollETHNode)
                .await
                .expect("ETH watch receiver dropped");
        }
    })
}
