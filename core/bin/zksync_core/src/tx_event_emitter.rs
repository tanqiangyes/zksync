//! Transaction event emitter is responsible for storing `Queued` events
//! in the database.
//!
//! It exists solely for isolating the state keeper from the storage since
//! it's used as the event queue backend.
//! 事务事件发射器负责将`Queued`事件存储在数据库中。
//! 它的存在仅仅是为了将状态保持者与存储隔离，因为它被用作事件队列的后端。

// External uses
use futures::{channel::mpsc, StreamExt};
use tokio::task::JoinHandle;

// Workspace deps
use zksync_storage::ConnectionPool;
use zksync_types::{BlockNumber, ExecutedOperations};

/// Miniblock operations processed by the state keeper.
#[derive(Debug)]
pub struct ProcessedOperations {
    pub block_number: BlockNumber,
    pub executed_ops: Vec<ExecutedOperations>,
}

#[must_use]
pub fn run_tx_event_emitter_task(
    db_pool: ConnectionPool,
    mut receiever: mpsc::Receiver<ProcessedOperations>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(ProcessedOperations {
            block_number,
            executed_ops,
        }) = receiever.next().await
        {
            let mut storage = db_pool
                .access_storage()
                .await
                .expect("tx event emitter failed to access the database");
            storage
                .event_schema()
                .store_executed_transaction_event(block_number, executed_ops)
                .await
                .expect("tx event emitter failed to store events in the database");
        }
    })
}
