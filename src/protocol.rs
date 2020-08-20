use crate::random_string;
use crate::{error::NetworkError, Header, NetworkHash};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

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
    RawDataAck = 1,
    Admin = 2,
    AdminAck = 3,
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
    global_hash: NetworkHash,
    peer_hash: NetworkHash,
    aes_key: Vec<u8>,
    packet_len: usize,
    packet_type: PacketType,
    remander: u8,
}
impl StreamHeader {
    pub fn new(global_hash: &NetworkHash, peer_hash: &NetworkHash, packet_len: usize) -> Self {
        let aes_key: Vec<u8> = random_string(16).into_bytes();
        Self::with_key(global_hash, peer_hash, aes_key, packet_len)
    }
    pub fn with_key(
        global_hash: &NetworkHash,
        peer_hash: &NetworkHash,
        aes_key: Vec<u8>,
        packet_len: usize,
    ) -> Self {
        Self {
            global_hash: global_hash.to_owned(),
            peer_hash: peer_hash.to_owned(),
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
    pub fn global_peer_hash(&self) -> &NetworkHash {
        &self.global_hash
    }
    pub fn peer_hash(&self) -> &NetworkHash {
        &self.peer_hash
    }
    pub fn key(&self) -> &[u8] {
        &self.aes_key
    }
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
    pub fn data_len(&self) -> usize {
        self.packet_len
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
        let mut outvec: Vec<u8> = Vec::with_capacity(58);
        let global_hash: Vec<u8> = Vec::from(&self.global_hash);
        assert_eq!(global_hash.len(), 16);
        outvec.extend_from_slice(&global_hash);
        let peer_hash: Vec<u8> = Vec::from(&self.peer_hash);
        assert_eq!(peer_hash.len(), 16);
        outvec.extend_from_slice(&peer_hash);
        outvec.extend_from_slice(&self.aes_key);
        outvec.extend_from_slice(&self.packet_len.to_be_bytes());
        outvec.push(self.remander);
        outvec.push(self.packet_type.to_u8().unwrap_or_default());
        outvec
    }
    pub fn to_raw_padded(&self) -> Vec<u8> {
        let mut vec = self.to_raw();
        let mut rem_vec = Vec::with_capacity(71);
        unsafe { rem_vec.set_len(71) };
        vec.extend_from_slice(&rem_vec);
        vec
    }
    pub fn from_raw_padded(data: &[u8]) -> Result<Self, NetworkError> {
        Self::from_raw(&data[0..58])
    }
    /// convert 125 bytes (length of data) to StreamHeader
    pub fn from_raw(data: &[u8]) -> Result<Self, NetworkError> {
        assert_eq!(data.len(), 58);
        let global_hash = NetworkHash::try_from(&data[0..16])?;
        let peer_hash = NetworkHash::try_from(&data[16..32])?;
        let aes_key = data[32..48].to_vec();
        let packet_len = usize::from_be_bytes(data[48..56].try_into()?);
        let remander = data[56];
        let packet_type = FromPrimitive::from_u8(data[57]).unwrap_or_default();
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
        *self.peer.global_peer_hash() == other.global_hash
            && *self.peer.peer_hash() == other.peer_hash
    }
}
impl PartialEq<Header> for StreamHeader {
    fn eq(&self, other: &Header) -> bool {
        self.global_hash == *other.peer.global_peer_hash()
            && self.peer_hash == *other.peer.peer_hash()
    }
}
