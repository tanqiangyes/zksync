use zksync_crypto::primitives::GetBits;
use zksync_utils::BigUintSerdeWrapper;

use std::collections::HashMap;

use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};
use zksync_crypto::franklin_crypto::bellman::pairing::ff::PrimeField;

use super::{AccountId, AccountUpdates, Fr, Nonce, TokenId};
use zksync_basic_types::Address;
use zksync_crypto::circuit::{
    account::{Balance, CircuitAccount},
    utils::eth_address_to_fr,
};

pub use self::{account_update::AccountUpdate, pubkey_hash::PubKeyHash};
use crate::NFT;

mod account_update;
pub mod error;
mod pubkey_hash;

/// zkSync network account.
/// zkSync网络账户
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Hash of the account public key used to authorize operations for this account.
    /// Once account is created (e.g. by `Transfer` or `Deposit` operation), account owner
    /// has to set its public key hash via `ChangePubKey` transaction, so the server will be
    /// able to verify owner's identity when processing account transactions.
    /// 用于授权此帐户操作的帐户公钥的哈希值。一旦创建账户（例如通过“转账”或“存款”操作），
    /// 账户所有者必须通过“ChangePubKey”交易设置其公钥哈希，因此服务器在处理账户交易时将能够验证所有者的身份。
    pub pub_key_hash: PubKeyHash,
    /// Address of the account. Directly corresponds to the L1 address.
    /// 账户地址。直接对应L1地址。
    pub address: Address,
    balances: HashMap<TokenId, BigUintSerdeWrapper>,
    /// Current nonce of the account. All the transactions require nonce field to be set in
    /// order to not allow double spend, and the nonce must increment by one after each operation.
    ///
    pub nonce: Nonce,
    pub minted_nfts: HashMap<TokenId, NFT>,
}
//实现PartialEq trait，以检测账户相等情况
impl PartialEq for Account {
    fn eq(&self, other: &Account) -> bool {
        self.get_bits_le().eq(&other.get_bits_le())
    }
}

impl From<Account> for CircuitAccount<super::Engine> {
    fn from(acc: Account) -> Self {
        let mut circuit_account = CircuitAccount::default();//CircuitAccount默认值

        let balances: Vec<_> = acc
            .balances
            .iter()//生成为迭代器
            .map(|(id, b)| {//map处理
                (
                    *id,
                    Balance {
                        value: Fr::from_str(&b.0.to_string()).unwrap(),
                    },
                )
            })
            .collect();//处理完毕，生成迭代器，转为vec

        for (i, b) in balances.into_iter() {
            circuit_account.subtree.insert(*i, b);//插入数据
        }

        circuit_account.nonce = Fr::from_str(&acc.nonce.to_string()).unwrap();//从Account中取到nonce给到CircuitAccount里面
        circuit_account.pub_key_hash = acc.pub_key_hash.as_fr();//从Account中取到pub_key_hash给到CircuitAccount里面
        circuit_account.address = eth_address_to_fr(&acc.address);//从Account中取到address给到CircuitAccount里面
        circuit_account//返回CircuitAccount
    }
}
//实现Account的默认实现
impl Default for Account {
    fn default() -> Self {
        Self {
            balances: HashMap::new(),
            nonce: Nonce(0),
            pub_key_hash: PubKeyHash::default(),
            address: Address::zero(),
            minted_nfts: HashMap::new(),
        }
    }
}
//实现GetBits trait
impl GetBits for Account {
    fn get_bits_le(&self) -> Vec<bool> {
        CircuitAccount::<super::Engine>::from(self.clone()).get_bits_le()
    }
}

impl Account {
    /// Creates a new empty account object, and sets its address.
    /// 创建一个新的空帐户对象，并设置其地址
    pub fn default_with_address(address: &Address) -> Account {
        Account {
            address: *address,
            ..Default::default()
        }
    }

    /// Creates a new account object and the list of updates that has to be applied on the state
    /// in order to get this account created within the network.
    /// 创建一个新的帐户对象和必须应用于状态的更新列表，以便在网络内创建此帐户。
    pub fn create_account(id: AccountId, address: Address) -> (Account, AccountUpdates) {
        let account = Account::default_with_address(&address);
        let updates = vec![(
            id,
            AccountUpdate::Create {
                address: account.address,
                nonce: account.nonce,
            },
        )];
        (account, updates)
    }

    /// Returns the token balance for the account.
    /// 返回账户对应的token余额
    pub fn get_balance(&self, token: TokenId) -> BigUint {
        self.balances.get(&token).cloned().unwrap_or_default().0
    }

    /// Overrides the token balance value.
    /// 设置对应token的余额
    pub fn set_balance(&mut self, token: TokenId, amount: BigUint) {
        self.balances.insert(token, amount.into());
    }

    /// Adds the provided amount to the token balance.
    /// 增加对应token的余额
    pub fn add_balance(&mut self, token: TokenId, amount: &BigUint) {
        let mut balance = self.balances.remove(&token).unwrap_or_default();
        balance.0 += amount;
        self.balances.insert(token, balance);
    }

    /// Subtracts the provided amount from the token balance.
    ///
    /// # Panics
    ///
    /// Panics if the amount to subtract is greater than the existing token balance.
    /// 减去对应的数量，如果超过了剩余余额，则panic
    pub fn sub_balance(&mut self, token: TokenId, amount: &BigUint) {
        let mut balance = self.balances.remove(&token).unwrap_or_default();
        balance.0 -= amount;
        self.balances.insert(token, balance);
    }

    /// Given the list of updates to apply, changes the account state.
    /// 应用账户状态
    pub fn apply_updates(mut account: Option<Self>, updates: &[AccountUpdate]) -> Option<Self> {
        for update in updates {
            account = Account::apply_update(account, update.clone());
        }
        account
    }

    /// Applies an update to the account state.
    /// 应用一个更新到账户状态
    pub fn apply_update(account: Option<Self>, update: AccountUpdate) -> Option<Self> {
        match account {
            Some(mut account) => match update {
                AccountUpdate::Delete { .. } => None,
                AccountUpdate::UpdateBalance {
                    balance_update: (token, _, amount),
                    new_nonce,
                    ..
                } => {
                    account.set_balance(token, amount);
                    account.nonce = new_nonce;
                    Some(account)
                }
                AccountUpdate::ChangePubKeyHash {
                    new_pub_key_hash,
                    new_nonce,
                    ..
                } => {
                    account.pub_key_hash = new_pub_key_hash;
                    account.nonce = new_nonce;
                    Some(account)
                }
                AccountUpdate::MintNFT { token, .. } => {
                    account.minted_nfts.insert(token.id, token);
                    Some(account)
                }
                AccountUpdate::RemoveNFT { token, .. } => {
                    account.minted_nfts.remove(&token.id);
                    Some(account)
                }
                _ => {
                    vlog::error!(
                        "Incorrect update received {:?} for account {:?}",
                        update,
                        account
                    );
                    Some(account)
                }
            },
            None => match update {
                AccountUpdate::Create { address, nonce, .. } => Some(Account {
                    address,
                    nonce,
                    ..Default::default()
                }),
                _ => {
                    vlog::error!("Incorrect update received {:?} for empty account", update);
                    None
                }
            },
        }
    }

    /// Returns all the nonzero token balances for the account.
    /// 返回帐户的所有非零令牌余额。
    pub fn get_nonzero_balances(&self) -> HashMap<TokenId, BigUintSerdeWrapper> {
        let mut balances = self.balances.clone();
        balances.retain(|_, v| v.0 != BigUint::zero());
        balances
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        helpers::{apply_updates, reverse_updates},
        AccountMap,
    };

    #[test]
    fn test_default_account() {
        let a = Account::default();
        a.get_bits_le();
    }

    #[test]
    fn test_account_update() {
        let create = AccountUpdate::Create {
            address: Address::default(),
            nonce: Nonce(1),
        };

        let bal_update = AccountUpdate::UpdateBalance {
            old_nonce: Nonce(1),
            new_nonce: Nonce(2),
            balance_update: (TokenId(0), 0u32.into(), 5u32.into()),
        };

        let delete = AccountUpdate::Delete {
            address: Address::default(),
            nonce: Nonce(2),
        };

        {
            {
                let created_account = Account {
                    nonce: Nonce(1),
                    ..Default::default()
                };
                assert_eq!(
                    Account::apply_update(None, create.clone())
                        .unwrap()
                        .get_bits_le(),
                    created_account.get_bits_le()
                );
            }

            assert!(Account::apply_update(None, bal_update.clone()).is_none());
            assert!(Account::apply_update(None, delete.clone()).is_none());
        }
        {
            assert_eq!(
                Account::apply_update(Some(Account::default()), create)
                    .unwrap()
                    .get_bits_le(),
                Account::default().get_bits_le()
            );
            {
                let mut updated_account = Account {
                    nonce: Nonce(2),
                    ..Default::default()
                };
                updated_account.set_balance(TokenId(0), 5u32.into());
                assert_eq!(
                    Account::apply_update(Some(Account::default()), bal_update)
                        .unwrap()
                        .get_bits_le(),
                    updated_account.get_bits_le()
                );
            }
            assert!(Account::apply_update(Some(Account::default()), delete).is_none());
        }
    }

    #[test]
    fn test_account_updates() {
        // Create two accounts: 0, 1
        // In updates -> delete 0, update balance of 1, create account 2
        // Reverse updates

        let account_map_initial = {
            let mut map = AccountMap::default();
            let account_0 = Account {
                nonce: Nonce(8),
                ..Default::default()
            };
            let account_1 = Account {
                nonce: Nonce(16),
                ..Default::default()
            };
            map.insert(AccountId(0), account_0);
            map.insert(AccountId(1), account_1);
            map
        };

        let account_map_updated_expected = {
            let mut map = AccountMap::default();
            let mut account_1 = Account {
                nonce: Nonce(17),
                ..Default::default()
            };
            account_1.set_balance(TokenId(0), 256u32.into());
            map.insert(AccountId(1), account_1);
            let account_2 = Account {
                nonce: Nonce(36),
                ..Default::default()
            };
            map.insert(AccountId(2), account_2);
            map
        };

        let updates = vec![
            (
                AccountId(0),
                AccountUpdate::Delete {
                    address: Address::default(),
                    nonce: Nonce(8),
                },
            ),
            (
                AccountId(1),
                AccountUpdate::UpdateBalance {
                    old_nonce: Nonce(16),
                    new_nonce: Nonce(17),
                    balance_update: (TokenId(0), 0u32.into(), 256u32.into()),
                },
            ),
            (
                AccountId(2),
                AccountUpdate::Create {
                    address: Address::default(),
                    nonce: Nonce(36),
                },
            ),
        ];

        let account_map_updated = {
            let mut map = account_map_initial.clone();
            apply_updates(&mut map, updates.clone());
            map
        };

        assert_eq!(account_map_updated, account_map_updated_expected);

        let account_map_updated_back = {
            let mut map = account_map_updated;
            let mut reversed = updates;
            reverse_updates(&mut reversed);
            apply_updates(&mut map, reversed);
            map
        };

        assert_eq!(account_map_updated_back, account_map_initial);
    }
}
