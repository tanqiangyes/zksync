use crate::{
    helpers::{is_fee_amount_packable, pack_fee_amount},
    AccountId, Nonce, TokenId,
};
use num::{BigUint, Zero};

use crate::{account::PubKeyHash, Engine};
use serde::{Deserialize, Serialize};
use zksync_basic_types::Address;
use zksync_crypto::{
    franklin_crypto::eddsa::PrivateKey,
    params::{max_account_id, max_fungible_token_id, max_processable_token, CURRENT_TX_VERSION},
};
use zksync_utils::{format_units, BigUintSerdeAsRadix10Str};

use super::{TxSignature, VerifiedSignatureCache};
use crate::tx::version::TxVersion;
use crate::tx::{error::TransactionSignatureError, TimeRange};

/// `ForcedExit` transaction is used to withdraw funds from an unowned
/// account to its corresponding L1 address.
///
/// Caller of this function will pay fee for the operation, and has no
/// control over the address on which funds will be withdrawn. Account
/// to which `ForcedExit` is applied must have no public key hash set.
///
/// This operation is expected to be used in cases when account in L1
/// cannot prove its identity in L2 (e.g. it's an existing smart contract),
/// so the funds won't get "locked" in L2.
/// `ForcedExit` 交易用于从无主账户中提取资金到其对应的 L1 地址。
/// 此函数的调用者将支付操作费用，并且无法控制提取资金的地址。
/// 应用了“ForcedExit”的帐户必须没有设置公钥哈希。
/// 此操作预计用于 L1 中的帐户无法证明其在 L2 中的身份（例如，它是现有的智能合约）的情况，因此资金不会在 L2 中“锁定”。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForcedExit {
    /// zkSync network account ID of the transaction initiator.
    /// 交易发起方的zkSync网络账户ID。
    pub initiator_account_id: AccountId,
    /// Address of the account to withdraw funds from.
    /// Also this field represents the address in L1 to which funds will be withdrawn.
    /// 提取资金的账户地址。此字段还表示 L1 中的资金将被提取到的地址。
    pub target: Address,
    /// Type of token for withdrawal. Also represents the token in which fee will be paid.
    /// 提款的代币类型。也代表将支付费用的代币。
    pub token: TokenId,
    /// Fee for the transaction.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub fee: BigUint,
    /// Current initiator account nonce.
    pub nonce: Nonce,
    /// Transaction zkSync signature.
    pub signature: TxSignature,
    #[serde(skip)]
    cached_signer: VerifiedSignatureCache,
    /// Time range when the transaction is valid
    /// This fields must be Option<...> because of backward compatibility with first version of ZkSync
    #[serde(flatten)]
    pub time_range: Option<TimeRange>,
}

impl ForcedExit {
    /// Unique identifier of the transaction type in zkSync network.
    /// 交易类型唯一标识符
    pub const TX_TYPE: u8 = 8;

    /// Creates transaction from all the required fields.
    ///
    /// While `signature` field is mandatory for new transactions, it may be `None`
    /// in some cases (e.g. when restoring the network state from the L1 contract data).
    pub fn new(
        initiator_account_id: AccountId,
        target: Address,
        token: TokenId,
        fee: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        signature: Option<TxSignature>,
    ) -> Self {
        let mut tx = Self {
            initiator_account_id,
            target,
            token,
            fee,
            nonce,
            time_range: Some(time_range),
            signature: signature.clone().unwrap_or_default(),
            cached_signer: VerifiedSignatureCache::NotCached,
        };
        if signature.is_some() {
            tx.cached_signer = VerifiedSignatureCache::Cached(tx.verify_signature());
        }
        tx
    }

    /// Creates a signed transaction using private key and
    /// checks for the transaction correcteness.
    /// 使用私钥创建签名交易并检查交易的正确性。
    pub fn new_signed(
        initiator_account_id: AccountId,
        target: Address,
        token: TokenId,
        fee: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        private_key: &PrivateKey<Engine>,
    ) -> Result<Self, TransactionSignatureError> {
        let mut tx = Self::new(
            initiator_account_id,
            target,
            token,
            fee,
            nonce,
            time_range,
            None,
        );
        tx.signature = TxSignature::sign_musig(private_key, &tx.get_bytes());
        if !tx.check_correctness() {
            return Err(TransactionSignatureError);
        }
        Ok(tx)
    }

    /// Encodes the transaction data as the byte sequence according to the zkSync protocol.
    pub fn get_old_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[Self::TX_TYPE]);
        out.extend_from_slice(&self.initiator_account_id.to_be_bytes());
        out.extend_from_slice(&self.target.as_bytes());
        out.extend_from_slice(&(self.token.0 as u16).to_be_bytes());
        out.extend_from_slice(&pack_fee_amount(&self.fee));
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.time_range.unwrap_or_default().as_be_bytes());
        out
    }

    /// Encodes the transaction data as the byte sequence according to the zkSync protocol.
    pub fn get_bytes(&self) -> Vec<u8> {
        self.get_bytes_with_version(CURRENT_TX_VERSION)
    }

    pub fn get_bytes_with_version(&self, version: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[255u8 - Self::TX_TYPE]);
        out.extend_from_slice(&[version]);
        out.extend_from_slice(&self.initiator_account_id.to_be_bytes());
        out.extend_from_slice(&self.target.as_bytes());
        out.extend_from_slice(&self.token.to_be_bytes());
        out.extend_from_slice(&pack_fee_amount(&self.fee));
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.time_range.unwrap_or_default().as_be_bytes());
        out
    }

    /// Verifies the transaction correctness:
    ///
    /// - `initiator_account_id` field must be within supported range.
    /// - `token` field must be within supported range.
    /// - `fee` field must represent a packable value.
    /// - zkSync signature must correspond to the PubKeyHash of the account.
    /// 验证交易正确性：
    /// - `initiator_account_id` 字段必须在支持的范围内。
    /// - `token` 字段必须在支持的范围内。
    /// - `fee` 字段必须表示可打包的值。
    /// - zkSync 签名必须与账户的 PubKeyHash 对应。
    pub fn check_correctness(&mut self) -> bool {
        let mut valid = is_fee_amount_packable(&self.fee)
            && self.initiator_account_id <= max_account_id()
            && self.token <= max_fungible_token_id()
            && self
                .time_range
                .map(|r| r.check_correctness())
                .unwrap_or(true);

        if valid {
            if self.fee != BigUint::zero() {
                // Fee can only be paid in processable tokens
                valid = self.token <= max_processable_token();//不能超限
            }
            let signer = self.verify_signature();
            valid = valid && signer.is_some();
            self.cached_signer = VerifiedSignatureCache::Cached(signer);
        }
        valid
    }

    /// Restores the `PubKeyHash` from the transaction signature.
    pub fn verify_signature(&self) -> Option<(PubKeyHash, TxVersion)> {
        if let VerifiedSignatureCache::Cached(cached_signer) = &self.cached_signer {
            *cached_signer
        } else {
            if let Some(res) = self
                .signature
                .verify_musig(&self.get_old_bytes())
                .map(|pub_key| PubKeyHash::from_pubkey(&pub_key))
            {
                return Some((res, TxVersion::Legacy));
            }
            self.signature
                .verify_musig(&self.get_bytes())
                .map(|pub_key| (PubKeyHash::from_pubkey(&pub_key), TxVersion::V1))
        }
    }

    /// Get the first part of the message we expect to be signed by Ethereum account key.
    /// The only difference is the missing `nonce` since it's added at the end of the transactions
    /// batch message. The format is:
    ///
    /// ForcedExit {token} to: {target}
    /// [Fee: {fee} {token}]
    ///
    /// Note that the second line is optional.
    /// 获取我们希望由以太坊帐户密钥签名的消息的第一部分。唯一的区别是缺少“nonce”，因为它是在事务批处理消息的末尾添加的。
    /// 格式为：
    /// ForcedExit {token} to: {target}
    /// [Fee: {fee} {token}]
    /// 注意第二行是可选的。
    pub fn get_ethereum_sign_message_part(&self, token_symbol: &str, decimals: u8) -> String {
        let mut message = format!(
            "ForcedExit {token} to: {to:?}",
            token = token_symbol,
            to = self.target
        );
        if !self.fee.is_zero() {
            message.push_str(
                format!(
                    "\nFee: {fee} {token}",
                    fee = format_units(&self.fee, decimals),
                    token = token_symbol,
                )
                .as_str(),
            );
        }
        message
    }

    /// Gets message that should be signed by Ethereum keys of the account for 2-Factor authentication.
    pub fn get_ethereum_sign_message(&self, token_symbol: &str, decimals: u8) -> String {
        let mut message = self.get_ethereum_sign_message_part(token_symbol, decimals);
        message.push_str(format!("\nNonce: {}", self.nonce).as_str());
        message
    }
}
