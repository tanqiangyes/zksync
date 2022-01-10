use num::BigUint;
use serde::{Deserialize, Serialize};

use super::{Nonce, TokenId};
use zksync_basic_types::Address;

use super::PubKeyHash;
use crate::tokens::NFT;

/// Atomic change in the account state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccountUpdate {
    /// Create a new account.
    /// 创建
    Create {
        address: Address,
        nonce: Nonce,
    },
    /// Delete an existing account.
    /// Note: Currently this kind of update is not used directly in the network.
    /// However, it's used to revert made operation (e.g. to restore state back in time from the last verified block).
    /// 删除一个存在的账户。注意：目前这种更新不直接在网络中使用。但是，它用于恢复已完成的操作（例如，从上次验证的块中及时恢复状态）。
    Delete {
        address: Address,
        nonce: Nonce,
    },
    /// Change the account balance.
    /// 更改账户余额
    UpdateBalance {
        old_nonce: Nonce,
        new_nonce: Nonce,
        /// Tuple of (token, old_balance, new_balance)
        balance_update: (TokenId, BigUint, BigUint),
    },
    /// Change the account Public Key.
    /// 更改公钥
    ChangePubKeyHash {
        old_pub_key_hash: PubKeyHash,
        new_pub_key_hash: PubKeyHash,
        old_nonce: Nonce,
        new_nonce: Nonce,
    },
    MintNFT {
        token: NFT,
        nonce: Nonce,
    },
    RemoveNFT {
        token: NFT,
        nonce: Nonce,
    },
}

impl AccountUpdate {
    /// Generates an account update to revert current update.
    /// 生成帐户更新以恢复当前更新。
    pub fn reversed_update(&self) -> Self {
        match self {
            AccountUpdate::Create { address, nonce } => AccountUpdate::Delete {
                address: *address,
                nonce: *nonce,
            },
            AccountUpdate::Delete { address, nonce } => AccountUpdate::Create {
                address: *address,
                nonce: *nonce,
            },
            AccountUpdate::UpdateBalance {
                old_nonce,
                new_nonce,
                balance_update,
            } => AccountUpdate::UpdateBalance {
                old_nonce: *new_nonce,
                new_nonce: *old_nonce,
                balance_update: (
                    balance_update.0,
                    balance_update.2.clone(),
                    balance_update.1.clone(),
                ),
            },
            AccountUpdate::ChangePubKeyHash {
                old_pub_key_hash,
                new_pub_key_hash,
                old_nonce,
                new_nonce,
            } => AccountUpdate::ChangePubKeyHash {
                old_pub_key_hash: *new_pub_key_hash,
                new_pub_key_hash: *old_pub_key_hash,
                old_nonce: *new_nonce,
                new_nonce: *old_nonce,
            },
            AccountUpdate::MintNFT { token, nonce } => AccountUpdate::RemoveNFT {
                token: token.clone(),
                nonce: *nonce,
            },
            AccountUpdate::RemoveNFT { token, nonce } => AccountUpdate::MintNFT {
                token: token.clone(),
                nonce: *nonce,
            },
        }
    }
}
