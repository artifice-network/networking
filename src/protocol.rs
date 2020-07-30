use crate::{error::NetworkError, random_string, Header};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

#[derive(
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Clone,
    Copy,
)]
pub enum PacketType {
    RawData = 0,
    Administration = 1,
}
impl Default for PacketType {
    fn default() -> Self {
        Self::RawData
    }
}

use std::convert::TryInto;
/// used to ensure man in the middle attack doesn't occure, but used in place of the Header struct
/// because it is much smaller
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StreamHeader {
    global_hash: String,
    peer_hash: String,
    aes_key: Vec<u8>,
    packet_len: usize,
    packet_type: PacketType,
    remander: u8,
}
impl StreamHeader {
    pub fn new(global_hash: &str, peer_hash: &str, packet_len: usize) -> Self {
        let aes_key = random_string(16).into_bytes();
        Self {
            global_hash: global_hash.to_string(),
            peer_hash: peer_hash.to_string(),
            aes_key,
            packet_len,
            packet_type: PacketType::RawData,
            remander: 0,
        }
    }
    pub fn set_packet_type(&mut self, packet_type: PacketType) {
        self.packet_type = packet_type;
    }
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }
    pub fn global_peer_hash(&self) -> &str {
        &self.global_hash
    }
    pub fn peer_hash(&self) -> &str {
        &self.peer_hash
    }
    pub fn key(&self) -> &[u8] {
        &self.aes_key
    }
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
    pub fn data_len(&self) -> usize {
        self.packet_len - (self.remander as usize)
    }
    pub fn set_packet_len(&mut self, packet_len: usize) {
        self.packet_len = packet_len;
    }
    /// remander is calculated by 128 - (packet_len % 128) to break into encryptable blocks for async
    /// for sync calculated based on 16 - (packet_len % 128)
    pub fn remander(&self) -> u8 {
        self.remander
    }
    pub fn set_remander(&mut self, remander: u8) {
        self.remander = remander;
    }
    /// used in place of serde_json::to_string(), because serde_json generates un-needed data
    pub fn to_raw(&self) -> Vec<u8> {
        let mut outvec = Vec::with_capacity(125);
        outvec.extend_from_slice(&self.global_hash.as_bytes());
        outvec.extend_from_slice(&self.peer_hash.as_bytes());
        outvec.extend_from_slice(&self.aes_key);
        outvec.extend_from_slice(&self.packet_len.to_be_bytes());
        outvec.push(self.remander);
        outvec.push(self.packet_type.to_u8().unwrap_or_default());
        outvec
    }
    /// convert 125 bytes (length of data) to StreamHeader
    pub fn from_raw(data: &[u8]) -> Result<Self, NetworkError> {
        assert_eq!(data.len(), 126);
        let global_hash = String::from_utf8(data[0..50].to_vec())?;
        let peer_hash = String::from_utf8(data[50..100].to_vec())?;
        let aes_key = data[100..116].to_vec();
        let packet_len = usize::from_be_bytes(data[116..124].try_into()?);
        let remander = data[124];
        let packet_type = FromPrimitive::from_u8(data[125]).unwrap_or_default();
        Ok(Self {
            global_hash,
            peer_hash,
            aes_key,
            packet_len,
            remander,
            packet_type,
        })
    }
}
impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.peer == other.peer && self.pubkeycomp() == other.pubkeycomp()
    }
}
impl PartialEq<StreamHeader> for Header {
    fn eq(&self, other: &StreamHeader) -> bool {
        self.peer.global_peer_hash() == other.global_hash
            && self.peer.peer_hash() == other.peer_hash
    }
}
impl PartialEq<Header> for StreamHeader {
    fn eq(&self, other: &Header) -> bool {
        self.global_hash == other.peer.global_peer_hash()
            && self.peer_hash == other.peer.peer_hash()
    }
}
