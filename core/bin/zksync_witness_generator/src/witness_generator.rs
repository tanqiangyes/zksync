// Built-in
use std::{thread, time};
// External
use futures::channel::mpsc;
use tokio::time::sleep;
// Workspace deps
use crate::database_interface::DatabaseInterface;
use zksync_circuit::serialization::ProverData;
use zksync_circuit::witness::utils::build_block_witness;
use zksync_crypto::circuit::CircuitAccountTree;
use zksync_crypto::params::account_tree_depth;
use zksync_types::block::Block;
use zksync_types::BlockNumber;
use zksync_utils::panic_notify::ThreadPanicNotify;

/// The essential part of this structure is `maintain` function
/// which runs forever and adds data to the database.
///
/// This will generate and store in db witnesses for blocks with indexes
/// start_block, start_block + block_step, start_block + 2*block_step, ...
/// 该结构的基本部分是“维护”功能，它永远运行并将数据添加到数据库中。这将为索引为 start_block、start_block + block_step、start_block + 2block_step 的块生成并存储在数据库中。
pub struct WitnessGenerator<DB: DatabaseInterface> {
    /// Connection to the database.
    database: DB,
    /// Routine refresh interval.
    rounds_interval: time::Duration,

    start_block: BlockNumber,
    block_step: BlockNumber,
}

#[derive(Debug)]
enum BlockInfo {
    NotReadyBlock,
    WithWitness,
    NoWitness(Block),
}

impl<DB: DatabaseInterface> WitnessGenerator<DB> {
    /// Creates a new `WitnessGenerator` object.
    pub fn new(
        database: DB,
        rounds_interval: time::Duration,
        start_block: BlockNumber,
        block_step: BlockNumber,
    ) -> Self {
        Self {
            database,
            rounds_interval,
            start_block,
            block_step,
        }
    }

    /// Starts the thread running `maintain` method.
    /// 启动运行 `maintain` 方法的线程。
    pub fn start(self, panic_notify: mpsc::Sender<bool>) {
        thread::Builder::new()
            .name("prover_server_pool".to_string())
            .spawn(move || {
                let _panic_sentinel = ThreadPanicNotify(panic_notify);
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("Unable to build runtime for a witness generator");

                runtime.block_on(async move {
                    self.maintain().await;
                });
            })
            .expect("failed to start provers server");
    }

    /// Returns status of witness for block with index block_number
    /// 返回具有索引 block_number 的块的见证状态
    async fn should_work_on_block(
        &self,
        block_number: BlockNumber,
    ) -> Result<BlockInfo, anyhow::Error> {
        let mut storage = self.database.acquire_connection().await?;
        let mut transaction = storage.start_transaction().await?;
        let block = self
            .database
            .load_block(&mut transaction, block_number)
            .await?;
        let block_info = if let Some(block) = block {
            let witness = self
                .database
                .load_witness(&mut transaction, block_number)
                .await?;
            if witness.is_none() {
                BlockInfo::NoWitness(block)
            } else {
                BlockInfo::WithWitness
            }
        } else {
            BlockInfo::NotReadyBlock
        };
        transaction.commit().await?;
        Ok(block_info)
    }

    async fn load_account_tree(
        &self,
        block: BlockNumber,
    ) -> Result<CircuitAccountTree, anyhow::Error> {
        let start = time::Instant::now();
        let mut storage = self.database.acquire_connection().await?;
        let mut circuit_account_tree = CircuitAccountTree::new(account_tree_depth());

        if let Some((cached_block, account_tree_cache)) =
            self.database.load_account_tree_cache(&mut storage).await?
        {
            let (_, accounts) = self
                .database
                .load_committed_state(&mut storage, Some(block))
                .await?;
            for (id, account) in accounts {
                circuit_account_tree.insert(*id, account.into());
            }
            circuit_account_tree.set_internals(serde_json::from_value(account_tree_cache)?);
            if block != cached_block {
                let (_, accounts) = self
                    .database
                    .load_committed_state(&mut storage, Some(block))
                    .await?;
                if let Some((_, account_updates)) = self
                    .database
                    .load_state_diff(&mut storage, block, Some(cached_block))
                    .await?
                {
                    let mut updated_accounts = account_updates
                        .into_iter()
                        .map(|(id, _)| id)
                        .collect::<Vec<_>>();
                    updated_accounts.sort_unstable();
                    updated_accounts.dedup();
                    for idx in updated_accounts {
                        circuit_account_tree
                            .insert(*idx, accounts.get(&idx).cloned().unwrap_or_default().into());
                    }
                }
                circuit_account_tree.root_hash();
                let account_tree_cache = circuit_account_tree.get_internals();
                self.database
                    .store_account_tree_cache(
                        &mut storage,
                        block,
                        serde_json::to_value(account_tree_cache)?,
                    )
                    .await?;
            }
        } else {
            let (_, accounts) = self
                .database
                .load_committed_state(&mut storage, Some(block))
                .await?;
            for (id, account) in accounts {
                circuit_account_tree.insert(*id, account.into());
            }
            circuit_account_tree.root_hash();
            let account_tree_cache = circuit_account_tree.get_internals();
            self.database
                .store_account_tree_cache(
                    &mut storage,
                    block,
                    serde_json::to_value(account_tree_cache)?,
                )
                .await?;
        }

        if block != BlockNumber(0) {
            let storage_block = self
                .database
                .load_block(&mut storage, block)
                .await?
                .expect("Block for witness generator must exist");
            assert_eq!(
                storage_block.new_root_hash,
                circuit_account_tree.root_hash(),
                "account tree root hash restored incorrectly"
            );
        }

        metrics::histogram!("witness_generator.load_account_tree", start.elapsed());
        Ok(circuit_account_tree)
    }
    //为区块准备见证人，并保存它
    async fn prepare_witness_and_save_it(&self, block: Block) -> anyhow::Result<()> {
        let start = time::Instant::now();
        let timer = time::Instant::now();
        let mut storage = self.database.acquire_connection().await?;

        let mut circuit_account_tree = self.load_account_tree(block.block_number - 1).await?;//获取当前电路账户树
        vlog::trace!(
            "Witness generator loading circuit account tree {}s",
            timer.elapsed().as_secs()
        );

        let timer = time::Instant::now();
        let witness: ProverData = build_block_witness(&mut circuit_account_tree, &block)?.into();
        vlog::trace!(
            "Witness generator witness build {}s",
            timer.elapsed().as_secs()
        );

        self.database
            .store_witness(
                &mut storage,
                block.block_number,
                serde_json::to_value(witness).expect("Witness serialize to json"),
            )
            .await?;

        metrics::histogram!(
            "witness_generator.prepare_witness_and_save_it",
            start.elapsed()
        );
        Ok(())
    }

    /// Returns next block for generating witness
    /// 返回下一个块以生成见证
    fn next_witness_block(
        current_block: BlockNumber,
        block_step: BlockNumber,
        block_info: &BlockInfo,
    ) -> BlockNumber {
        match block_info {
            BlockInfo::NotReadyBlock => current_block, // Keep waiting
            BlockInfo::WithWitness | BlockInfo::NoWitness(_) => {
                BlockNumber(*current_block + *block_step)
            } // Go to the next block
        }
    }

    /// Updates witness data in database in an infinite loop,
    /// awaiting `rounds_interval` time between updates.
    /// 在无限循环中更新数据库中的见证数据，等待更新之间的“rounds_interval”时间。
    async fn maintain(self) {
        vlog::info!(
            "preparing prover data routine started with start_block({}), block_step({})",
            *self.start_block,
            *self.block_step
        );
        let mut current_block = self.start_block;
        loop {
            sleep(self.rounds_interval).await;
            let should_work = match self.should_work_on_block(current_block).await {
                Ok(should_work) => should_work,
                Err(err) => {
                    vlog::warn!("witness for block {} check failed: {}", current_block, err);
                    continue;
                }
            };

            let next_block = Self::next_witness_block(current_block, self.block_step, &should_work);//如果需要生成下一个块则添加新块；否则，返回当前块
            if let BlockInfo::NoWitness(block) = should_work {
                let block_number = block.block_number;
                if let Err(err) = self.prepare_witness_and_save_it(block).await {
                    vlog::warn!("Witness generator ({},{}) failed to prepare witness for block: {}, err: {}",
                        self.start_block, self.block_step, block_number, err);
                    continue; // Retry the same block on the next iteration.
                }
            }

            // Update current block.
            current_block = next_block;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use zksync_crypto::Fr;
    use zksync_types::{AccountId, H256, U256};

    #[test]
    fn test_next_witness_block() {
        assert_eq!(
            WitnessGenerator::<Database>::next_witness_block(
                BlockNumber(3),
                BlockNumber(4),
                &BlockInfo::NotReadyBlock
            ),
            BlockNumber(3)
        );
        assert_eq!(
            WitnessGenerator::<Database>::next_witness_block(
                BlockNumber(3),
                BlockNumber(4),
                &BlockInfo::WithWitness
            ),
            BlockNumber(7)
        );
        let empty_block = Block::new(
            BlockNumber(0),
            Fr::default(),
            AccountId(0),
            vec![],
            (0, 0),
            0,
            U256::default(),
            U256::default(),
            H256::default(),
            0,
        );
        assert_eq!(
            WitnessGenerator::<Database>::next_witness_block(
                BlockNumber(3),
                BlockNumber(4),
                &BlockInfo::NoWitness(empty_block)
            ),
            BlockNumber(7)
        );
    }
}
