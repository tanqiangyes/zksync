// Built-in deps
use std::collections::HashMap;
// External uses
// Workspace deps
use zksync_types::{NewTokenEvent, PriorityOp, RegisterNFTFactoryEvent, SerialId};
// Local deps
use super::received_ops::ReceivedPriorityOp;

/// Gathered state of the Ethereum network.
/// Contains information about the known token types and incoming
/// priority operations (such as `Deposit` and `FullExit`).
///
/// All the data held is intentionally made private: as it represents the
/// observed state of the contract on Ethereum, it should never be
/// "partially updated". The state is either updated completely, or not
/// updated at all.
#[derive(Debug, Default, Clone)]
pub struct ETHState {
    /// The last block of the Ethereum network known to the Ethereum watcher.
    last_ethereum_block: u64,
    /// The previous Ethereum block successfully processed by the watcher.
    /// Keeping track of it is required to be able to poll the node for
    /// the same range multiple times, e.g. in case it didn't return all
    /// priority operations received by the contract.
    last_ethereum_block_backup: u64,
    /// Serial id of the next priority operation Ethereum watcher should process.
    /// 以太坊观察者应该处理的下一个优先操作的序列号。
    next_priority_op_id: SerialId,
    /// Queue of priority operations that are accepted by Ethereum network,
    /// but not yet have enough confirmations to be processed by zkSync.
    ///
    /// Note that since these operations do not have enough confirmations,
    /// they may be not executed in the future, so this list is approximate.
    unconfirmed_queue: Vec<PriorityOp>,
    /// Keys in this HashMap are numbers of blocks with `PriorityOp`.
    /// Queue of priority operations that passed the confirmation
    /// threshold and are waiting to be executed.
    priority_queue: HashMap<u64, ReceivedPriorityOp>,
    /// List of tokens that have been added to the contract.
    new_tokens: Vec<NewTokenEvent>,
    /// List of events denoting registered factories for NFT withdrawing
    register_nft_factory_events: Vec<RegisterNFTFactoryEvent>,
}

impl ETHState {
    pub fn new(
        last_ethereum_block: u64,
        last_ethereum_block_backup: u64,
        unconfirmed_queue: Vec<PriorityOp>,
        priority_queue: HashMap<SerialId, ReceivedPriorityOp>,
        new_tokens: Vec<NewTokenEvent>,
        register_nft_factory_events: Vec<RegisterNFTFactoryEvent>,
    ) -> Self {
        assert!(
            last_ethereum_block_backup <= last_ethereum_block,
            "Backup block cannot be greater than last known block"
        );
        let next_priority_op_id = priority_queue
            .keys()
            .max()
            .map(|serial_id| *serial_id + 1)
            .unwrap_or(0);
        Self {
            last_ethereum_block,
            last_ethereum_block_backup,
            next_priority_op_id,
            unconfirmed_queue,
            priority_queue,
            new_tokens,
            register_nft_factory_events,
        }
    }
    //当前状态里面的区块号
    pub fn last_ethereum_block(&self) -> u64 {
        self.last_ethereum_block
    }
    //优先队列
    pub fn priority_queue(&self) -> &HashMap<u64, ReceivedPriorityOp> {
        &self.priority_queue
    }

    pub fn unconfirmed_queue(&self) -> &[PriorityOp] {
        &self.unconfirmed_queue
    }

    pub fn new_register_nft_factory_events(&self) -> &[RegisterNFTFactoryEvent] {
        &self.register_nft_factory_events
    }

    pub fn new_tokens(&self) -> &[NewTokenEvent] {
        &self.new_tokens
    }
    // 下一个应该优先处理的序列号
    pub fn next_priority_op_id(&self) -> SerialId {
        self.next_priority_op_id
    }

    pub fn reset_last_ethereum_block(&mut self) {
        self.last_ethereum_block = self.last_ethereum_block_backup;
    }

    #[cfg(test)]
    pub(crate) fn last_ethereum_block_backup(&self) -> u64 {
        self.last_ethereum_block_backup
    }
}
