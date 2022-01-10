use crate::{
    helpers::{is_fee_amount_packable, pack_fee_amount},
    AccountId, Nonce, TxFeeTypes,
};

use crate::account::PubKeyHash;
use num::{BigUint, Zero};
use parity_crypto::Keccak256;
use serde::{Deserialize, Serialize};
use zksync_basic_types::{Address, TokenId, H256};
use zksync_crypto::{
    params::{max_account_id, max_processable_token, CURRENT_TX_VERSION},
    PrivateKey,
};
use zksync_utils::{format_units, BigUintSerdeAsRadix10Str};

use super::{PackedEthSignature, TimeRange, TxSignature, VerifiedSignatureCache};
use crate::tx::version::TxVersion;
use crate::{
    tokens::ChangePubKeyFeeTypeArg,
    tx::error::{ChangePubkeySignedDataError, TransactionSignatureError},
};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
pub enum ChangePubKeyType {
    Onchain,
    ECDSA,
    CREATE2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePubKeyECDSAData {
    pub eth_signature: PackedEthSignature,
    #[serde(default)]
    pub batch_hash: H256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePubKeyCREATE2Data {
    pub creator_address: Address,
    pub salt_arg: H256,
    pub code_hash: H256,
}

impl ChangePubKeyCREATE2Data {
    pub fn get_address(&self, pubkey_hash: &PubKeyHash) -> Address {
        let salt = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(self.salt_arg.as_bytes());
            bytes.extend_from_slice(&pubkey_hash.data);
            bytes.keccak256()
        };//加密

        let mut bytes = vec![0xff];
        bytes.extend_from_slice(self.creator_address.as_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(self.code_hash.as_bytes());
        Address::from_slice(&bytes.keccak256()[12..])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChangePubKeyEthAuthData {
    Onchain,
    ECDSA(ChangePubKeyECDSAData),
    CREATE2(ChangePubKeyCREATE2Data),
}

impl ChangePubKeyEthAuthData {
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, ChangePubKeyEthAuthData::ECDSA(..))
    }

    pub fn is_onchain(&self) -> bool {
        matches!(self, ChangePubKeyEthAuthData::Onchain)
    }

    pub fn is_create2(&self) -> bool {
        matches!(self, ChangePubKeyEthAuthData::CREATE2(..))
    }

    pub fn get_eth_witness(&self) -> Vec<u8> {
        match self {
            ChangePubKeyEthAuthData::Onchain => Vec::new(),
            ChangePubKeyEthAuthData::ECDSA(ChangePubKeyECDSAData { eth_signature, .. }) => {
                let mut bytes = vec![0x00];
                bytes.extend_from_slice(&eth_signature.serialize_packed());
                // bytes.extend_from_slice(batch_hash.as_bytes());
                bytes
            }
            ChangePubKeyEthAuthData::CREATE2(ChangePubKeyCREATE2Data {
                creator_address,
                salt_arg,
                code_hash,
            }) => {
                let mut bytes = vec![0x01];
                bytes.extend_from_slice(creator_address.as_bytes());
                bytes.extend_from_slice(salt_arg.as_bytes());
                bytes.extend_from_slice(code_hash.as_bytes());
                bytes
            }
        }
    }

    pub fn get_fee_type(&self) -> ChangePubKeyType {
        match self {
            ChangePubKeyEthAuthData::Onchain => ChangePubKeyType::Onchain,
            ChangePubKeyEthAuthData::ECDSA(_) => ChangePubKeyType::ECDSA,
            ChangePubKeyEthAuthData::CREATE2(_) => ChangePubKeyType::CREATE2,
        }
    }
}

/// `ChangePubKey` transaction is used to set the owner's public key hash
/// associated with the account.
///
/// Without public key hash set, account is unable to execute any L2 transactions.
/// `ChangePubKey` 事务用于设置与帐户关联的所有者的公钥哈希。如果没有设置公钥哈希，账户将无法执行任何 L2 交易。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePubKey {
    /// zkSync network account ID to apply operation to.
    pub account_id: AccountId,//要应用操作的 zkSync 网络帐户 ID。
    /// Address of the account.
    pub account: Address,
    /// Public key hash to set.
    pub new_pk_hash: PubKeyHash,
    /// Token to be used for fee.
    #[serde(default)]
    pub fee_token: TokenId,
    /// Fee for the transaction.
    #[serde(with = "BigUintSerdeAsRadix10Str", default)]
    pub fee: BigUint,
    /// Current account nonce.
    pub nonce: Nonce,
    /// Transaction zkSync signature. Must be signed with the key corresponding to the
    /// `new_pk_hash` value. This signature is required to ensure that `fee_token` and `fee`
    /// fields can't be changed by an attacker.
    /// 交易 zkSync 签名。必须使用与“new_pk_hash”值对应的密钥进行签名。需要此签名以确保攻击者无法更改“fee_token”和“fee”字段。
    #[serde(default)]
    pub signature: TxSignature,
    /// Transaction Ethereum signature. It may be `None` if `ChangePubKey` operation is authorized
    /// onchain, otherwise the message must be signed by the Ethereum private key corresponding
    /// to the account address.
    /// 交易以太坊签名。如果 `ChangePubKey` 操作在链上被授权，则可能是 `None`，否则消息必须由账户地址对应的以太坊私钥签名。
    pub eth_signature: Option<PackedEthSignature>,
    /// Data needed to check if Ethereum address authorized ChangePubKey operation
    /// 检查以太坊地址是否授权 ChangePubKey 操作所需的数据
    pub eth_auth_data: Option<ChangePubKeyEthAuthData>,
    /// Time range when the transaction is valid
    /// This fields must be Option<...> because of backward compatibility with first version of ZkSync
    /// 交易有效的时间范围 该字段必须是 Option<...> 因为与 ZkSync 的第一个版本向后兼容
    #[serde(flatten)]
    pub time_range: Option<TimeRange>,
    #[serde(skip)]
    cached_signer: VerifiedSignatureCache,
}

impl ChangePubKey {
    /// Unique identifier of the transaction type in zkSync network.
    /// zkSync 网络中交易类型的唯一标识符。
    pub const TX_TYPE: u8 = 7;

    /// Creates transaction from all the required fields.
    ///
    /// While `signature` field is mandatory for new transactions, it may be `None`
    /// in some cases (e.g. when restoring the network state from the L1 contract data).
    /// 从所有必填字段创建交易。虽然“signature”字段对于新交易是强制性的，但在某些情况下它可能是“None”（例如，当从 L1 合约数据恢复网络状态时）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        account: Address,
        new_pk_hash: PubKeyHash,
        fee_token: TokenId,
        fee: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        signature: Option<TxSignature>,
        eth_signature: Option<PackedEthSignature>,
    ) -> Self {
        // TODO: support CREATE2 (ZKS-452)
        let eth_auth_data = Some(
            eth_signature
                .map(|eth_signature| {
                    ChangePubKeyEthAuthData::ECDSA(ChangePubKeyECDSAData {
                        eth_signature,
                        batch_hash: H256::zero(),
                    })
                })
                .unwrap_or(ChangePubKeyEthAuthData::Onchain),
        );

        let mut tx = Self {
            account_id,
            account,
            new_pk_hash,
            fee_token,
            fee,
            nonce,
            signature: signature.clone().unwrap_or_default(),
            eth_signature: None,
            eth_auth_data,
            cached_signer: VerifiedSignatureCache::NotCached,
            time_range: Some(time_range),
        };
        if signature.is_some() {
            tx.cached_signer = VerifiedSignatureCache::Cached(tx.verify_signature());
        }
        tx
    }

    /// Creates a signed transaction using private key and
    /// checks the transaction correctness.
    /// 使用私钥创建签名交易并检查交易正确性。
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        account_id: AccountId,
        account: Address,
        new_pk_hash: PubKeyHash,
        fee_token: TokenId,
        fee: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        eth_signature: Option<PackedEthSignature>,
        private_key: &PrivateKey,
    ) -> Result<Self, TransactionSignatureError> {
        let mut tx = Self::new(
            account_id,
            account,
            new_pk_hash,
            fee_token,
            fee,
            nonce,
            time_range,
            None,
            eth_signature,
        );
        tx.signature = TxSignature::sign_musig(private_key, &tx.get_bytes());//签名
        if !tx.check_correctness() {
            return Err(TransactionSignatureError);
        }
        Ok(tx)
    }

    /// Restores the `PubKeyHash` from the transaction signature.
    /// 从交易签名中恢复“PubKeyHash”。
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

    /// Encodes the transaction data as the byte sequence according to the old zkSync protocol with 2 bytes token.
    /// 根据旧的 zkSync 协议用 2 个字节的令牌将交易数据编码为字节序列。
    pub fn get_old_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[Self::TX_TYPE]);
        out.extend_from_slice(&self.account_id.to_be_bytes());
        out.extend_from_slice(&self.account.as_bytes());
        out.extend_from_slice(&self.new_pk_hash.data);
        out.extend_from_slice(&(self.fee_token.0 as u16).to_be_bytes());
        out.extend_from_slice(&pack_fee_amount(&self.fee));
        out.extend_from_slice(&self.nonce.to_be_bytes());
        if let Some(time_range) = &self.time_range {
            out.extend_from_slice(&time_range.as_be_bytes());
        }
        out
    }

    /// Encodes the transaction data as the byte sequence according to the zkSync protocol.
    /// 根据 zkSync 协议将交易数据编码为字节序列。
    pub fn get_bytes(&self) -> Vec<u8> {
        self.get_bytes_with_version(CURRENT_TX_VERSION)
    }

    pub fn get_bytes_with_version(&self, version: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[255u8 - Self::TX_TYPE]);
        out.extend_from_slice(&[version]);
        out.extend_from_slice(&self.account_id.to_be_bytes());
        out.extend_from_slice(&self.account.as_bytes());
        out.extend_from_slice(&self.new_pk_hash.data);
        out.extend_from_slice(&self.fee_token.to_be_bytes());
        out.extend_from_slice(&pack_fee_amount(&self.fee));
        out.extend_from_slice(&self.nonce.to_be_bytes());
        if let Some(time_range) = &self.time_range {
            out.extend_from_slice(&time_range.as_be_bytes());
        }
        out
    }

    /// Provides a message to be signed with the Ethereum private key.
    /// 提供要使用以太坊私钥签名的消息。
    pub fn get_eth_signed_data(&self) -> Result<Vec<u8>, ChangePubkeySignedDataError> {
        // Fee data is not included into ETH signature input, since it would require
        // to either have more chunks in pubdata (if fee amount is unpacked), unpack
        // fee on contract (if fee amount is packed), or display non human-readable
        // amount in message (if fee amount is packed and is not unpacked on contract).
        // Either of these options is either non user-friendly or increase cost of
        // operation. Instead, fee data is signed via zkSync signature, which is essentially
        // free. This signature will be verified in the circuit.
        //费用数据不包含在 ETH 签名输入中，因为它需要在 pubdata 中有更多的块（如果费用金额被解包），
        // 解包合同费用（如果费用金额被打包），或者在消息中显示非人类可读的金额（如果费用金额已打包且未在合同上拆包）。
        // 这些选项中的任何一个都不是用户友好的，或者增加了操作成本。
        // 相反，费用数据是通过 zkSync 签名来签名的，这基本上是免费的。该签名将在电路中进行验证。

        const CHANGE_PUBKEY_SIGNATURE_LEN: usize = 60;
        let mut eth_signed_msg = Vec::with_capacity(CHANGE_PUBKEY_SIGNATURE_LEN);
        eth_signed_msg.extend_from_slice(&self.new_pk_hash.data);
        eth_signed_msg.extend_from_slice(&self.nonce.to_be_bytes());
        eth_signed_msg.extend_from_slice(&self.account_id.to_be_bytes());
        // In case this transaction is not part of a batch, we simply append zeros.
        // 如果此交易不是批次的一部分，我们只需附加零。
        if let Some(ChangePubKeyEthAuthData::ECDSA(ChangePubKeyECDSAData { batch_hash, .. })) =
            self.eth_auth_data
        {
            eth_signed_msg.extend_from_slice(batch_hash.as_bytes());
        } else {
            eth_signed_msg.extend_from_slice(H256::default().as_bytes());
        }
        if eth_signed_msg.len() != CHANGE_PUBKEY_SIGNATURE_LEN {
            return Err(ChangePubkeySignedDataError::SignedMessageLengthMismatch {
                actual: eth_signed_msg.len(),
                expected: CHANGE_PUBKEY_SIGNATURE_LEN,
            });
        }
        Ok(eth_signed_msg)
    }

    /// Provides an old message to be signed with the Ethereum private key.
    /// 提供用以太坊私钥签名的旧消息。
    pub fn get_old_eth_signed_data(&self) -> Result<Vec<u8>, ChangePubkeySignedDataError> {
        // Fee data is not included into ETH signature input, since it would require
        // to either have more chunks in pubdata (if fee amount is unpacked), unpack
        // fee on contract (if fee amount is packed), or display non human-readable
        // amount in message (if fee amount is packed and is not unpacked on contract).
        // Either of these options is either non user-friendly or increase cost of
        // operation. Instead, fee data is signed via zkSync signature, which is essentially
        // free. This signature will be verified in the circuit.
        //费用数据不包含在 ETH 签名输入中，因为它需要在 pubdata 中有更多的块（如果费用金额被解包），
        // 解包合同费用（如果费用金额被打包），或者在消息中显示非人类可读的金额（如果费用金额已打包且未在合同上拆包）。
        // 这些选项中的任何一个都不是用户友好的，或者增加了操作成本。相反，费用数据是通过 zkSync 签名来签名的，
        // 这基本上是免费的。该签名将在电路中进行验证。

        const CHANGE_PUBKEY_SIGNATURE_LEN: usize = 152;
        let mut eth_signed_msg = Vec::with_capacity(CHANGE_PUBKEY_SIGNATURE_LEN);
        eth_signed_msg.extend_from_slice(b"Register zkSync pubkey:\n\n");
        eth_signed_msg.extend_from_slice(
            format!(
                "{pubkey}\n\
                 nonce: 0x{nonce}\n\
                 account id: 0x{account_id}\
                 \n\n",
                pubkey = hex::encode(&self.new_pk_hash.data).to_ascii_lowercase(),
                nonce = hex::encode(&self.nonce.to_be_bytes()).to_ascii_lowercase(),
                account_id = hex::encode(&self.account_id.to_be_bytes()).to_ascii_lowercase()
            )
            .as_bytes(),
        );
        eth_signed_msg.extend_from_slice(b"Only sign this message for a trusted client!");

        if eth_signed_msg.len() != CHANGE_PUBKEY_SIGNATURE_LEN {
            return Err(ChangePubkeySignedDataError::SignedMessageLengthMismatch {
                actual: eth_signed_msg.len(),
                expected: CHANGE_PUBKEY_SIGNATURE_LEN,
            });
        }
        Ok(eth_signed_msg)
    }

    pub fn is_eth_auth_data_valid(&self) -> bool {
        if let Some(eth_auth_data) = &self.eth_auth_data {
            match eth_auth_data {
                ChangePubKeyEthAuthData::Onchain => true, // Should query Ethereum to check it
                ChangePubKeyEthAuthData::ECDSA(ChangePubKeyECDSAData { eth_signature, .. }) => {
                    let recovered_address = self
                        .get_eth_signed_data()
                        .ok()
                        .and_then(|msg| eth_signature.signature_recover_signer(&msg).ok());
                    recovered_address == Some(self.account)
                }
                ChangePubKeyEthAuthData::CREATE2(create2_data) => {
                    let create2_address = create2_data.get_address(&self.new_pk_hash);
                    create2_address == self.account
                }
            }
        } else if let Some(old_eth_signature) = &self.eth_signature {
            let recovered_address = self
                .get_old_eth_signed_data()
                .ok()
                .and_then(|msg| old_eth_signature.signature_recover_signer(&msg).ok());
            recovered_address == Some(self.account)
        } else {
            true
        }
    }

    /// Verifies the transaction correctness:
    ///
    /// - Ethereum signature (if set) must correspond to the account address.
    /// - zkSync signature must correspond to the `new_pk_hash` field of the transaction.
    /// - `account_id` field must be within supported range.
    /// - `fee_token` field must be within supported range.
    /// - `fee` field must represent a packable value.
    /// 验证交易正确性：
    /// - 以太坊签名（如果设置）必须对应于账户地址。
    /// - zkSync 签名必须对应交易的`new_pk_hash` 字段。
    /// - `account_id` 字段必须在支持的范围内。
    /// - `fee_token` 字段必须在支持的范围内。
    /// - `fee` 字段必须表示可打包的值。
    pub fn check_correctness(&self) -> bool {
        let mut valid = self.is_eth_auth_data_valid()
            && self.account_id <= max_account_id()
            && self.fee_token <= max_processable_token()
            && is_fee_amount_packable(&self.fee)
            && self
                .time_range
                .map(|t| t.check_correctness())
                .unwrap_or(true);
        if valid {
            if let Some((pub_key_hash, _)) = self.verify_signature() {
                valid = pub_key_hash == self.new_pk_hash;
            } else {
                valid = false;
            }
        }
        valid
    }

    pub fn is_ecdsa(&self) -> bool {
        if let Some(auth_data) = &self.eth_auth_data {
            auth_data.is_ecdsa()
        } else {
            self.eth_signature.is_some()
        }
    }

    pub fn is_onchain(&self) -> bool {
        if let Some(auth_data) = &self.eth_auth_data {
            auth_data.is_onchain()
        } else {
            self.eth_signature.is_none()
        }
    }

    /// Get part of the message that should be signed with Ethereum account key for the batch of transactions.
    /// The message for single `ChangePubKey` transaction is defined differently. The pattern is:
    ///
    /// Set signing key: {pubKeyHash}
    /// [Fee: {fee} {token}]
    ///
    /// Note that the second line is optional.
    /// 获取应使用以太坊帐户密钥为批量交易签名的部分消息。
    /// 单个“ChangePubKey”交易的消息定义不同。
    /// 模式是：
    /// 设置签名密钥：{pubKeyHash}
    /// [费用：{fee} {token}]
    /// 请注意，第二行是可选的。
    pub fn get_ethereum_sign_message_part(&self, token_symbol: &str, decimals: u8) -> String {
        let mut message = format!(
            "Set signing key: {}",
            hex::encode(&self.new_pk_hash.data).to_ascii_lowercase()
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

    pub fn get_change_pubkey_fee_type(&self) -> ChangePubKeyFeeTypeArg {
        if let Some(auth_data) = &self.eth_auth_data {
            ChangePubKeyFeeTypeArg::ContractsV4Version(auth_data.get_fee_type())
        } else {
            ChangePubKeyFeeTypeArg::PreContracts4Version {
                onchain_pubkey_auth: self.eth_signature.is_none(),
            }
        }
    }

    pub fn get_fee_type(&self) -> TxFeeTypes {
        TxFeeTypes::ChangePubKey(self.get_change_pubkey_fee_type())
    }
}
