use std::{
    fmt,
    fmt::{Display, Formatter},
};

use primitive_types::U256;
use serde::{Deserialize, Serialize};
use crate::data_structures::{
    address::TariAddress,
    types::{FixedHash, MicroMinotari},
    encrypted_data::{SIZE_U256, SIZE_VALUE},
};
use crate::hex_utils::{HexEncodable, HexValidatable, HexError};
use borsh::{BorshSerialize, BorshDeserialize};


// We pad the bytes to min this size, so that we can use the same size for AddressAndData and TransactionInfo
const PADDING_SIZE: usize = 130;
const PADDING_SIZE_NO_TAG: usize = 129;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default, Hash)]
pub enum TxType {
    #[default]
    PaymentToOther = 0b0000,
    PaymentToSelf = 0b0001,
    Burn = 0b0010,
    CoinSplit = 0b0011,
    CoinJoin = 0b0100,
    ValidatorNodeRegistration = 0b0101,
    ClaimAtomicSwap = 0b0110,
    HtlcAtomicSwapRefund = 0b0111,
    CodeTemplateRegistration = 0b1000,
    ImportedUtxoNoneRewindable = 0b1001,
    Coinbase = 0b1011,
}

impl TxType {
    fn from_u8(value: u8) -> Self {
        TxType::from_u16(u16::from(value))
    }

    fn from_u16(value: u16) -> Self {
        match value & 0b1111 {
            0b0000 => TxType::PaymentToOther,
            0b0001 => TxType::PaymentToSelf,
            0b0010 => TxType::Burn,
            0b0011 => TxType::CoinSplit,
            0b0100 => TxType::CoinJoin,
            0b0101 => TxType::ValidatorNodeRegistration,
            0b0110 => TxType::ClaimAtomicSwap,
            0b0111 => TxType::HtlcAtomicSwapRefund,
            0b1000 => TxType::CodeTemplateRegistration,
            0b1001 => TxType::ImportedUtxoNoneRewindable,
            0b1011 => TxType::Coinbase,
            _ => TxType::default(),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            TxType::PaymentToOther => 0b0000,
            TxType::PaymentToSelf => 0b0001,
            TxType::Burn => 0b0010,
            TxType::CoinSplit => 0b0011,
            TxType::CoinJoin => 0b0100,
            TxType::ValidatorNodeRegistration => 0b0101,
            TxType::ClaimAtomicSwap => 0b0110,
            TxType::HtlcAtomicSwapRefund => 0b0111,
            TxType::CodeTemplateRegistration => 0b1000,
            TxType::ImportedUtxoNoneRewindable => 0b1001,
            TxType::Coinbase => 0b1011,
        }
    }

    fn as_bytes(self) -> Vec<u8> {
        vec![self.as_u8()]
    }
}

impl Display for TxType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TxType::PaymentToOther => write!(f, "PaymentToOther"),
            TxType::PaymentToSelf => write!(f, "PaymentToSelf"),
            TxType::Burn => write!(f, "Burn"),
            TxType::CoinSplit => write!(f, "CoinSplit"),
            TxType::CoinJoin => write!(f, "CoinJoin"),
            TxType::ValidatorNodeRegistration => write!(f, "ValidatorNodeRegistration"),
            TxType::ClaimAtomicSwap => write!(f, "ClaimAtomicSwap"),
            TxType::HtlcAtomicSwapRefund => write!(f, "HtlcAtomicSwapRefund"),
            TxType::CodeTemplateRegistration => write!(f, "CodeTemplateRegistration"),
            TxType::ImportedUtxoNoneRewindable => write!(f, "ImportedUtxoNoneRewindable"),
            TxType::Coinbase => write!(f, "Coinbase"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub enum PaymentId {
    /// No payment ID.
    #[default]
    Empty,
    /// A u256 number.
    U256(U256),
    /// Open - the user optionally specifies 'user_data' ('tx_type' is added by the system).
    Open { user_data: Vec<u8>, tx_type: TxType },
    /// This payment ID is automatically generated by the system for output UTXOs. The optional user specified
    /// `PaymentId::Open` payment ID will be assigned to `tx_type` and `user_data`; the system adds in the sender
    /// address.
    AddressAndData {
        sender_address: TariAddress,
        sender_one_sided: bool,
        fee: MicroMinotari,
        tx_type: TxType,
        user_data: Vec<u8>,
    },
    /// This payment ID is automatically generated by the system for change outputs. The optional user specified
    /// `PaymentId::Open` payment ID will be assigned to `tx_type` and `user_data`; the system adds in the other data
    /// address.
    TransactionInfo {
        recipient_address: TariAddress,
        sender_one_sided: bool,
        amount: MicroMinotari,
        fee: MicroMinotari,
        tx_type: TxType,
        sent_output_hashes: Vec<FixedHash>,
        user_data: Vec<u8>,
    },
    /// This is a fallback if nothing else fits, so we want to preserve the raw bytes.
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PTag {
    Empty = 0,
    U256 = 1,
    Open = 2,
    AddressAndDataV1 = 3,
    TransactionInfoV1 = 4,
    AddressAndData = 5,
    TransactionInfo = 6,
    Raw = 7,
}

impl PTag {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => PTag::Empty,
            1 => PTag::U256,
            2 => PTag::Open,
            3 => PTag::AddressAndDataV1,
            4 => PTag::TransactionInfoV1,
            5 => PTag::AddressAndData,
            6 => PTag::TransactionInfo,
            _ => PTag::Raw,
        }
    }
}

impl PaymentId {
    const SIZE_META_DATA: usize = 5;
    const SIZE_VALUE_AND_META_DATA: usize = SIZE_VALUE + PaymentId::SIZE_META_DATA;

    fn to_tag(&self) -> Vec<u8> {
        match self {
            PaymentId::Empty => vec![],
            PaymentId::U256(_) => vec![PTag::U256 as u8],
            PaymentId::Open { .. } => vec![PTag::Open as u8],
            PaymentId::AddressAndData { .. } => vec![PTag::AddressAndData as u8],
            PaymentId::TransactionInfo { .. } => vec![PTag::TransactionInfo as u8],
            PaymentId::Raw(_) => vec![PTag::Raw as u8],
        }
    }

    pub fn get_size(&self) -> usize {
        match self {
            PaymentId::Empty => 0,
            PaymentId::U256(_) => 1 + SIZE_U256,
            PaymentId::Open { user_data, .. } => 1 + user_data.len() + 1,
            PaymentId::AddressAndData {
                sender_address,
                user_data,
                ..
            } => {
                let len = 1 + 1 + sender_address.get_size() + PaymentId::SIZE_META_DATA + 1 + user_data.len();
                if len < PADDING_SIZE {
                    PADDING_SIZE
                } else {
                    len
                }
            },
            PaymentId::TransactionInfo {
                recipient_address,
                user_data,
                sent_output_hashes,
                ..
            } => {
                let len = 1 +
                    1 +
                    recipient_address.get_size() +
                    PaymentId::SIZE_VALUE_AND_META_DATA +
                    1 +
                    (sent_output_hashes.len() * FixedHash::byte_size()) +
                    1 +
                    user_data.len();
                if len < PADDING_SIZE {
                    PADDING_SIZE
                } else {
                    len
                }
            },
            PaymentId::Raw(bytes) => {
                // We add 1 for the tag byte
                1 + bytes.len()
            },
        }
    }

    pub fn get_fee(&self) -> Option<MicroMinotari> {
        match self {
            PaymentId::AddressAndData { fee, .. } | PaymentId::TransactionInfo { fee, .. } => Some(*fee),
            _ => None,
        }
    }

    pub fn get_sent_hashes(&self) -> Option<Vec<FixedHash>> {
        match self {
            PaymentId::TransactionInfo { sent_output_hashes, .. } => Some(sent_output_hashes.clone()),
            _ => None,
        }
    }

    /// Helper function to set the 'amount' of a 'PaymentId::TransactionInfo'
    pub fn transaction_info_set_amount(&mut self, amount: MicroMinotari) {
        if let PaymentId::TransactionInfo { amount: a, .. } = self {
            *a = amount;
        }
    }

    pub fn get_type(&self) -> TxType {
        match self {
            PaymentId::Open { tx_type, .. } |
            PaymentId::AddressAndData { tx_type, .. } |
            PaymentId::TransactionInfo { tx_type, .. } => *tx_type,
            _ => TxType::default(),
        }
    }

    /// Helper function to set the 'recipient_address' of a 'PaymentId::TransactionInfo'
    pub fn transaction_info_set_address(&mut self, address: TariAddress) {
        if let PaymentId::TransactionInfo { recipient_address, .. } = self {
            *recipient_address = address
        }
    }

    pub fn transaction_info_set_sent_output_hashes(&mut self, sent_output_hashes: Vec<FixedHash>) {
        if let PaymentId::TransactionInfo {
            sent_output_hashes: hashes,
            ..
        } = self
        {
            *hashes = sent_output_hashes;
        }
    }

    /// Helper function to convert a 'PaymentId::Open' or 'PaymentId::Empty' to a 'PaymentId::AddressAndData', with the
    /// optional 'tx_type' only applicable to 'PaymentId::Open', otherwise 'payment_id' is kept as is.
    pub fn add_sender_address(
        self,
        sender_address: TariAddress,
        sender_one_sided: bool,
        fee: MicroMinotari,
        tx_type: Option<TxType>,
    ) -> PaymentId {
        match self {
            PaymentId::Open { user_data, tx_type } => PaymentId::AddressAndData {
                sender_address,
                sender_one_sided,
                fee,
                tx_type,
                user_data,
            },
            PaymentId::Empty => PaymentId::AddressAndData {
                sender_address,
                sender_one_sided,
                fee,
                tx_type: tx_type.unwrap_or_default(),
                user_data: vec![],
            },
            _ => self,
        }
    }

    // This method is infallible; any out-of-bound values will be zeroed.
    fn pack_meta_data(&self) -> Vec<u8> {
        match self {
            PaymentId::TransactionInfo {
                fee,
                sender_one_sided,
                tx_type,
                ..
            } |
            PaymentId::AddressAndData {
                fee,
                sender_one_sided,
                tx_type,
                ..
            } => {
                let mut bytes = Vec::with_capacity(5);
                // Zero out-of-bound values
                // - Use 4 bytes for 'fee', max value: 4,294,967,295
                let fee = if fee.as_u64() > 2u64.pow(32) - 1 {
                    0
                } else {
                    fee.as_u64()
                };
                // Pack
                bytes.extend_from_slice(&fee.to_be_bytes()[4..]);
                let tx_type = tx_type.as_u8() & 0b00001111 | (u8::from(*sender_one_sided) << 7);

                bytes.push(tx_type);
                bytes
            },
            _ => vec![],
        }
    }

    fn unpack_meta_data(bytes: [u8; 5]) -> (MicroMinotari, bool, TxType) {
        // Extract fee from the first 4 bytes
        let fee = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        let tx_type_packed = bytes[4];
        let tx_type = TxType::from_u8(tx_type_packed & 0b00001111);
        let sender_one_sided = (tx_type_packed & 0b10000000) != 0;
        (MicroMinotari::from(fee), sender_one_sided, tx_type)
    }

    pub fn user_data_as_bytes(&self) -> Vec<u8> {
        match &self {
            PaymentId::Empty => vec![],
            PaymentId::U256(v) => {
                let bytes: &mut [u8] = &mut [0; SIZE_U256];
                v.to_little_endian(bytes);
                bytes.to_vec()
            },
            PaymentId::Open { user_data, .. } => user_data.clone(),
            PaymentId::AddressAndData { user_data, .. } => user_data.clone(),
            PaymentId::TransactionInfo { user_data, .. } => user_data.clone(),
            PaymentId::Raw(bytes) => bytes.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PaymentId::Empty => Vec::new(),
            PaymentId::U256(v) => {
                let mut bytes = self.to_tag();
                let mut value = vec![0; 32];
                v.to_little_endian(&mut value);
                bytes.extend_from_slice(&value);
                bytes
            },
            PaymentId::Open { user_data, tx_type } => {
                let mut bytes = self.to_tag();
                bytes.extend_from_slice(&tx_type.as_bytes());
                bytes.extend_from_slice(user_data);
                bytes
            },
            PaymentId::AddressAndData {
                sender_address,
                user_data,
                ..
            } => {
                let mut bytes = self.to_tag();
                bytes.extend_from_slice(&self.pack_meta_data());
                let address_bytes = sender_address.to_vec();
                bytes.push(u8::try_from(address_bytes.len()).expect("User data length should fit in a u8"));
                bytes.extend_from_slice(&address_bytes);
                bytes.push(u8::try_from(user_data.len()).expect("User data length should fit in a u8"));
                bytes.extend_from_slice(user_data);
                // Ensure we have enough padding to match the min size
                while bytes.len() < PADDING_SIZE {
                    bytes.push(0);
                }
                bytes
            },
            PaymentId::TransactionInfo {
                recipient_address,
                amount,
                user_data,
                sent_output_hashes,
                ..
            } => {
                let mut bytes = self.to_tag();
                bytes.extend_from_slice(&amount.as_u64().to_le_bytes());
                bytes.extend_from_slice(&self.pack_meta_data());
                let address_bytes = recipient_address.to_vec();
                bytes.push(u8::try_from(address_bytes.len()).expect("User data length should fit in a u8"));
                bytes.extend_from_slice(&address_bytes.to_vec());
                bytes.push(u8::try_from(user_data.len()).expect("User data length should fit in a u8"));
                bytes.extend_from_slice(user_data);
                bytes.push(
                    u8::try_from(sent_output_hashes.len()).expect("Sent output hashes length should fit in a u8"),
                );
                for hash in sent_output_hashes {
                    bytes.extend_from_slice(hash.as_slice());
                }
                // Ensure we have enough padding to match the min size
                while bytes.len() < PADDING_SIZE {
                    bytes.push(0);
                }
                bytes
            },
            PaymentId::Raw(bytes) => {
                let mut result = self.to_tag();
                result.extend_from_slice(bytes);
                result
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let raw_bytes = bytes.to_vec();
        // edge case for premine:
        if bytes.len() == SIZE_VALUE {
            let bytes_array: [u8; SIZE_VALUE] = bytes.try_into().expect("We already test the length");
            let v = u64::from_le_bytes(bytes_array);
            if v < 1000 {
                return PaymentId::Open {
                    tx_type: TxType::PaymentToOther,
                    user_data: bytes.to_vec(),
                };
            }
        }

        let p_tag = if bytes.is_empty() {
            PTag::Empty
        } else {
            PTag::from_u8(bytes[0])
        };
        let bytes = if bytes.len() > 1 { &bytes[1..] } else { &[] };
        match p_tag {
            PTag::Empty => return PaymentId::Empty,
            PTag::U256 => {
                if bytes.len() != SIZE_U256 {
                    return PaymentId::Open {
                        tx_type: TxType::from_u8(*bytes.first().unwrap_or(&0)),
                        user_data: bytes.get(1..).unwrap_or_default().to_vec(),
                    };
                }
                let v = U256::from_little_endian(bytes);
                return PaymentId::U256(v);
            },
            PTag::Open => {
                return PaymentId::Open {
                    tx_type: TxType::from_u8(*bytes.first().unwrap_or(&0)),
                    user_data: bytes.get(1..).unwrap_or_default().to_vec(),
                }
            },
            PTag::Raw => return PaymentId::Raw(bytes.to_vec()),
            _ => {},
        }

        match PaymentId::try_deserialize_address_or_transaction_data(bytes, p_tag) {
            Ok(payment_id) => payment_id,
            Err(_e) => {
                // Failed to parse PaymentId from bytes, returning Raw
                PaymentId::Raw(raw_bytes)
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn try_deserialize_address_or_transaction_data(bytes: &[u8], p_tag: PTag) -> Result<PaymentId, String> {
        if bytes.len() < PaymentId::SIZE_VALUE_AND_META_DATA {
            // if the bytes are too short, we cannot parse it as AddressAndData or TransactionInfo
            return Err("Not enough bytes to parse AddressAndData or TransactionInfo".to_string());
        }

        if p_tag == PTag::TransactionInfoV1 || p_tag == PTag::AddressAndDataV1 {
            let mut amount_bytes = [0u8; SIZE_VALUE];
            amount_bytes.copy_from_slice(&bytes[0..SIZE_VALUE]);
            let amount = MicroMinotari::from(u64::from_le_bytes(amount_bytes));
            let mut meta_data_bytes = [0u8; PaymentId::SIZE_META_DATA];
            meta_data_bytes.copy_from_slice(&bytes[SIZE_VALUE..PaymentId::SIZE_VALUE_AND_META_DATA]);
            let (fee, sender_one_sided, tx_meta_data) = PaymentId::unpack_meta_data(meta_data_bytes);
            let (address, size) =
                if let Ok((address, size)) = Self::find_tari_address(&bytes[PaymentId::SIZE_VALUE_AND_META_DATA..]) {
                    (address, size)
                } else {
                    // if we cannot find a valid TariAddress, we return the raw bytes
                    return Err("No valid TariAddress found in bytes".to_string());
                };

            // legacy support for AddressAndDataV1
            if p_tag == PTag::AddressAndDataV1 {
                let user_data = bytes[PaymentId::SIZE_VALUE_AND_META_DATA + size..].to_vec();
                return Ok(PaymentId::AddressAndData {
                    sender_address: address,
                    sender_one_sided,
                    fee,
                    tx_type: tx_meta_data,
                    user_data,
                });
            }

            // legacy support for TransactionInfoV1
            if p_tag == PTag::TransactionInfoV1 {
                let user_data = bytes[PaymentId::SIZE_VALUE_AND_META_DATA + size..].to_vec();
                return Ok(PaymentId::TransactionInfo {
                    recipient_address: address,
                    sender_one_sided,
                    amount,
                    fee,
                    tx_type: tx_meta_data,
                    user_data,
                    sent_output_hashes: vec![],
                });
            }
        }
        // now we assume this has to be off type AddressAndData or TransactionInfo
        let data_start_index = if p_tag == PTag::AddressAndData { 0 } else { SIZE_VALUE };
        let metadata_end_index = if p_tag == PTag::AddressAndData {
            PaymentId::SIZE_META_DATA
        } else {
            PaymentId::SIZE_VALUE_AND_META_DATA
        };

        let mut meta_data_bytes = [0u8; PaymentId::SIZE_META_DATA];
        meta_data_bytes.copy_from_slice(
            bytes
                .get(data_start_index..metadata_end_index)
                .ok_or("Not enough bytes for meta data")?,
        );
        let (fee, sender_one_sided, tx_meta_data) = PaymentId::unpack_meta_data(meta_data_bytes);

        let address_size = *bytes
            .get(metadata_end_index)
            .ok_or("Address bytes does not have size encoded")? as usize;
        let address = TariAddress::from_bytes(
            bytes
                .get(metadata_end_index + 1..metadata_end_index + 1 + address_size)
                .ok_or("Not enough bytes for TariAddress")?,
        )
        .map_err(|_| "Invalid TariAddress in bytes".to_string())?;
        let user_data_length = *bytes
            .get(metadata_end_index + 1 + address_size)
            .ok_or("User data bytes does not have length encoded")? as usize;
        let user_data_start = metadata_end_index + 1 + address_size + 1;
        let user_data = bytes
            .get(user_data_start..user_data_start + user_data_length)
            .ok_or("Not enough bytes for user data")?;

        if p_tag == PTag::AddressAndData {
            if !Self::check_padding(bytes, user_data_start + user_data_length) {
                return Err("Invalid padding for AddressAndData".to_string());
            }
            return Ok(PaymentId::AddressAndData {
                sender_address: address,
                sender_one_sided,
                fee,
                tx_type: tx_meta_data,
                user_data: user_data.to_vec(),
            });
        }
        // so this must be a TransactionInfo
        let mut amount_bytes = [0u8; SIZE_VALUE];
        amount_bytes.copy_from_slice(bytes.get(0..SIZE_VALUE).ok_or("Not enough bytes for amount")?);
        let amount = MicroMinotari::from(u64::from_le_bytes(amount_bytes));
        let mut sent_output_hashes = Vec::new();
        let sent_output_hashes_length = *bytes
            .get(user_data_start + user_data_length)
            .ok_or("Sent output hashes bytes does not have length encoded")?
            as usize;
        let sent_output_hashes_start = user_data_start + user_data_length + 1;
        for hash_num in 0..sent_output_hashes_length {
            let hash_start = sent_output_hashes_start + (hash_num * FixedHash::byte_size());
            let hash_end = hash_start + FixedHash::byte_size();
            let hash = bytes
                .get(hash_start..hash_end)
                .ok_or("Not enough bytes for sent output hash")?;
            let sent_output_hash = FixedHash::try_from(hash).map_err(|_| "Invalid sent output hash".to_string())?;
            sent_output_hashes.push(sent_output_hash);
        }
        if !Self::check_padding(
            bytes,
            sent_output_hashes_start + (sent_output_hashes_length * FixedHash::byte_size()),
        ) {
            return Err("Invalid padding for TransactionInfo".to_string());
        }
        Ok(PaymentId::TransactionInfo {
            recipient_address: address,
            sender_one_sided,
            amount,
            fee,
            tx_type: tx_meta_data,
            user_data: user_data.to_vec(),
            sent_output_hashes,
        })
    }

    /// helper function to check padding
    fn check_padding(bytes: &[u8], start_index: usize) -> bool {
        if bytes.len() > PADDING_SIZE_NO_TAG {
            // larger than the minimum size, so no padding here
            return true;
        }

        // Check if the last bytes are zeroed out
        for &byte in &bytes[start_index..] {
            if byte != 0 {
                return false;
            }
        }
        true
    }

    // we dont know where the tari address ends and the user data starts, so we need to find it using the checksum
    fn find_tari_address(bytes: &[u8]) -> Result<(TariAddress, usize), String> {
        const TARI_ADDRESS_INTERNAL_SINGLE_SIZE: usize = 35;
        const TARI_ADDRESS_INTERNAL_DUAL_SIZE: usize = 67;
        
        if bytes.len() < TARI_ADDRESS_INTERNAL_SINGLE_SIZE {
            return Err("Not enough bytes for single TariAddress".to_string());
        }
        // Now we have to try and brute force a match here
        let mut offset = 0;
        while (TARI_ADDRESS_INTERNAL_DUAL_SIZE + offset) <= bytes.len() {
            if let Ok(address) = TariAddress::from_bytes(&bytes[..(TARI_ADDRESS_INTERNAL_DUAL_SIZE + offset)]) {
                return Ok((address, TARI_ADDRESS_INTERNAL_DUAL_SIZE + offset));
            }
            offset += 1;
        }
        if let Ok(address) = TariAddress::from_bytes(&bytes[..TARI_ADDRESS_INTERNAL_SINGLE_SIZE]) {
            return Ok((address, TARI_ADDRESS_INTERNAL_SINGLE_SIZE));
        }
        Err("No valid TariAddress found".to_string())
    }

    /// Helper function to convert a byte slice to a string for the open and data variants
    pub fn stringify_bytes(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    /// Helper function to display the payment id's user data
    pub fn user_data_as_string(&self) -> String {
        match self {
            PaymentId::Empty => self.to_string(),
            PaymentId::U256(v) => format!("{}", v),
            PaymentId::Open { user_data, .. } => PaymentId::stringify_bytes(user_data),
            PaymentId::AddressAndData { user_data, .. } => PaymentId::stringify_bytes(user_data),
            PaymentId::TransactionInfo { user_data, .. } => PaymentId::stringify_bytes(user_data),
            PaymentId::Raw(bytes) => hex::encode(bytes),
        }
    }

    /// Helper function to create a `PaymentId::Open` from a string and the transaction type
    pub fn open_from_string(s: &str, tx_type: TxType) -> Self {
        PaymentId::Open {
            user_data: s.as_bytes().to_vec(),
            tx_type,
        }
    }

    /// Helper function to create a `PaymentId::Open` from a bytes and the transaction type
    pub fn open(bytes: Vec<u8>, tx_type: TxType) -> Self {
        PaymentId::Open {
            user_data: bytes,
            tx_type,
        }
    }
}

impl Display for PaymentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PaymentId::Empty => write!(f, "None"),
            PaymentId::U256(v) => write!(f, "u256({v})"),
            PaymentId::Open { user_data, tx_type } => {
                write!(f, "type({}), data({})", tx_type, PaymentId::stringify_bytes(user_data))
            },
            PaymentId::AddressAndData {
                sender_address,
                sender_one_sided,
                fee,
                tx_type,
                user_data,
            } => write!(
                f,
                "sender_address({}), sender_one_sided({}), fee({}), type({}), data({})",
                sender_address.to_base58(),
                sender_one_sided,
                fee,
                tx_type,
                PaymentId::stringify_bytes(user_data)
            ),
            PaymentId::TransactionInfo {
                recipient_address,
                sender_one_sided,
                amount,
                fee,
                user_data,
                tx_type: tx_meta_data,
                sent_output_hashes: _,
            } => write!(
                f,
                "recipient_address({}), sender_one_sided({}), amount({}), fee({}), type({}), data({})",
                recipient_address.to_base58(),
                sender_one_sided,
                amount,
                fee,
                tx_meta_data,
                PaymentId::stringify_bytes(user_data),
            ),
            PaymentId::Raw(bytes) => write!(f, "Raw({})", hex::encode(bytes)),
        }
    }
}

impl HexEncodable for PaymentId {
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
    
    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        Ok(Self::from_bytes(&bytes))
    }
}

impl HexValidatable for PaymentId {}

// Manual Borsh implementations since some inner types don't support Borsh
impl BorshSerialize for PaymentId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self.to_bytes();
        BorshSerialize::serialize(&bytes, writer)
    }
}

impl BorshDeserialize for PaymentId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self::from_bytes(&bytes))
    }
} 