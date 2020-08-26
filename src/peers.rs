use crate::database::HashDatabase;
use crate::encryption::PubKeyComp;
use crate::{random_string, NetworkError};
use rand::{distributions::Standard, thread_rng, Rng};
use rsa::RSAPublicKey;
use serde_hex::{SerHex, StrictPfx};
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::{fmt, iter};

use crate::L4Addr;
/// represents global_peer_hash and peer_hash with wider varience then String
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct NetworkHash {
    #[serde(with = "SerHex::<StrictPfx>")]
    key: [u16; 8],
}
impl NetworkHash {
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        let key_vec: Vec<u16> = iter::repeat(())
            .map(|()| rng.sample(Standard))
            .take(8)
            .collect();
        Self::try_from(key_vec.as_slice()).unwrap()
    }
}
#[test]
fn network_hash() {
    let hash = NetworkHash::generate();
    println!("hash: {}", hash);
    let hash_string = serde_json::to_string(&hash).unwrap();
    println!("serialized: {}", hash_string);
    let de_hash: NetworkHash = serde_json::from_str(&hash_string).unwrap();
    assert_eq!(de_hash, hash);
    let hash_int: u128 = hash.into();
    let new_hash: NetworkHash = hash_int.into();
    assert_eq!(new_hash, hash);
}
impl fmt::Display for NetworkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7]
        )
    }
}
impl fmt::Debug for NetworkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
impl From<NetworkHash> for u128 {
    fn from(hash: NetworkHash) -> u128 {
        unsafe { std::mem::transmute::<[u16; 8], u128>(hash.key) }
    }
}
impl From<&Ipv6Addr> for NetworkHash {
    fn from(addr: &Ipv6Addr) -> NetworkHash {
        let array = addr.octets();
        let key = unsafe { std::mem::transmute::<[u8; 16], [u16; 8]>(array) };
        Self { key }
    }
}
impl From<&NetworkHash> for Ipv6Addr {
    fn from(hash: &NetworkHash) -> Ipv6Addr {
        Ipv6Addr::new(
            hash.key[0],
            hash.key[1],
            hash.key[2],
            hash.key[3],
            hash.key[4],
            hash.key[5],
            hash.key[6],
            hash.key[7],
        )
    }
}
impl From<NetworkHash> for Ipv6Addr {
    fn from(hash: NetworkHash) -> Ipv6Addr {
        Ipv6Addr::new(
            hash.key[0],
            hash.key[1],
            hash.key[2],
            hash.key[3],
            hash.key[4],
            hash.key[5],
            hash.key[6],
            hash.key[7],
        )
    }
}
impl From<&NetworkHash> for IpAddr {
    fn from(hash: &NetworkHash) -> IpAddr {
        IpAddr::V6(hash.into())
    }
}
impl From<NetworkHash> for IpAddr {
    fn from(hash: NetworkHash) -> IpAddr {
        IpAddr::V6(hash.into())
    }
}

impl From<[u16; 8]> for NetworkHash {
    fn from(value: [u16; 8]) -> Self {
        Self::try_from(&value[..]).unwrap()
    }
}
impl TryFrom<&[u8]> for NetworkHash {
    type Error = NetworkError;
    fn try_from(value: &[u8]) -> Result<NetworkHash, Self::Error> {
        let array: [u8; 16] = value.try_into()?;
        let key = unsafe { std::mem::transmute::<[u8; 16], [u16; 8]>(array) };
        Ok(Self { key })
    }
}
impl TryFrom<&[u16]> for NetworkHash {
    type Error = NetworkError;
    fn try_from(value: &[u16]) -> Result<NetworkHash, Self::Error> {
        let key: [u16; 8] = value.try_into()?;
        Ok(Self { key })
    }
}
impl TryFrom<&[u32]> for NetworkHash {
    type Error = NetworkError;
    fn try_from(value: &[u32]) -> Result<NetworkHash, Self::Error> {
        let array: [u32; 4] = value.try_into()?;
        let key = unsafe { std::mem::transmute::<[u32; 4], [u16; 8]>(array) };
        Ok(Self { key })
    }
}
impl TryFrom<&[u64]> for NetworkHash {
    type Error = NetworkError;
    fn try_from(value: &[u64]) -> Result<NetworkHash, Self::Error> {
        let array: [u64; 2] = value.try_into()?;
        let key = unsafe { std::mem::transmute::<[u64; 2], [u16; 8]>(array) };
        Ok(Self { key })
    }
}
impl From<u128> for NetworkHash {
    fn from(value: u128) -> Self {
        let key = unsafe { std::mem::transmute::<u128, [u16; 8]>(value) };
        Self { key }
    }
}
impl From<&NetworkHash> for Vec<u8> {
    fn from(hash: &NetworkHash) -> Vec<u8> {
        let mut outvec = Vec::with_capacity(16);
        for num in hash.key.iter() {
            outvec.extend_from_slice(&num.to_le_bytes());
        }
        outvec
    }
}
/// used as a precursor to artifice peer, principly it is used to store information about a given peer
/// that is intended to be publicly available information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemotePeer {
    global_peer_hash: String,
    addr: L4Addr,
    routable: bool,
    pubkey: PubKeyComp,
}
impl RemotePeer {
    pub fn new(global_hash: &str, pubkey: PubKeyComp, addr: L4Addr, routable: bool) -> Self {
        Self {
            global_peer_hash: global_hash.to_string(),
            pubkey,
            addr,
            routable,
        }
    }
    pub fn generate(pubkey: PubKeyComp, addr: L4Addr, routable: bool) -> Self {
        let global_peer_hash = random_string(50);
        Self {
            global_peer_hash,
            addr,
            routable,
            pubkey,
        }
    }
    pub fn global_peer_hash(&self) -> &str {
        &self.global_peer_hash
    }
    pub fn addr(&self) -> L4Addr {
        self.addr
    }
    pub fn pubkeycomp(&self) -> &PubKeyComp {
        &self.pubkey
    }
    pub fn routable(&self) -> bool {
        self.routable
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerMeta {
    pub public: bool,
}
/// this is a peer that represents a (theoretically) remote computer, this struct provides an attempt to verify the peer by holding a text string that only this particular host, and one host have access to
/// this is done in conjunction with public key authentication, as well as remote_user auth on an already encrypted channel so only those with permission can exercise their permissions
/// side noote permissions and peers operate on white list rather then blacklist for the sake of safety.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialOrd, Ord)]
pub struct ArtificePeer {
    global_peer_hash: NetworkHash,
    addr: L4Addr,
    routable: bool,
    pubkey: Option<PubKeyComp>,
    /// this is only for the pair between this server and that peer
    peer_hash: NetworkHash,
}
impl PartialEq for ArtificePeer {
    fn eq(&self, other: &Self) -> bool {
        self.global_peer_hash == other.global_peer_hash && self.peer_hash == other.peer_hash
    }
}
impl ArtificePeer {
    /// constructor that takes in pre-existing peer hash gained from the peer request
    /// global_peer_hash is something public to everyone on the network and is a means for provide hashed data access to verify the peer
    /// pubkey is sent to coordinate with keypair, if the records on the hsot match the peer, then the machine is assumed somewhat safe
    /// (used to prevent the danger of pubkey theft as each pairkey only exists between one particular peer and another)
    /// remote user provides further verification of identity, and is used in junction with peer verification to control access rights
    pub fn new(
        global_peer_hash: &NetworkHash,
        peer_hash: &NetworkHash,
        addr: L4Addr,
        pubkey: Option<PubKeyComp>,
    ) -> Self {
        let routable = true; //IpAddr::from(addr).is_global();
        Self {
            global_peer_hash: global_peer_hash.to_owned(),
            addr,
            routable,
            pubkey,
            peer_hash: peer_hash.to_owned(),
        }
    }
    pub fn global_peer_hash(&self) -> &NetworkHash {
        &self.global_peer_hash
    }
    // get ipaddr associated with this peer
    pub fn addr(&self) -> IpAddr {
        self.addr.ip().into()
    }
    /// makes public key pair available to the client program, for encryption purposes
    pub fn pubkeycomp(&self) -> &Option<PubKeyComp> {
        &self.pubkey
    }
    pub fn pubkey(&self) -> Result<RSAPublicKey, NetworkError> {
        let pubkey = match &self.pubkey {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        Ok(RSAPublicKey::new(pubkey.n().into(), pubkey.e().into())?)
    }
    /// makes key pair hash available to the client program to verify the remote peer
    pub fn peer_hash(&self) -> &NetworkHash {
        &self.peer_hash
    }
    // includes port
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        self.addr.into()
    }
    pub fn set_socket_addr(&mut self, sock_addr: SocketAddr) {
        self.addr = sock_addr.into();
    }
    pub fn set_pubkey(&mut self, pubkey: &PubKeyComp) {
        self.pubkey = Some(pubkey.to_owned());
    }
}
impl PeerList for ArtificePeer {
    fn verify_peer(&self, peer: &ArtificePeer) -> bool {
        self == peer
    }
    fn get_peer(&self, key: &NetworkHash) -> Option<&ArtificePeer> {
        if self.global_peer_hash == *key {
            return Some(self);
        }
        None
    }
}
/// type alias for the database structure in which peers should be saved
pub type PeerDatabase = HashDatabase<ArtificePeer, NetworkHash, PeerMeta>;
impl PeerList for PeerDatabase {
    fn verify_peer(&self, peer: &ArtificePeer) -> bool {
        // check if option contains value if it does return the value of meta.public, if not returns false
        self.meta().as_ref().map_or_else(|| false, |v| v.public)
            || self
                .get(peer.global_peer_hash())
                .map_or_else(|| false, |p| *p == *peer)
    }
    fn get_peer(&self, key: &NetworkHash) -> Option<&ArtificePeer> {
        self.get(key)
    }
}
/// used in ConnectionRequests verify method, anything that implements this trait
/// is assumed to be a list of peers that are allowed to connect to this device
pub trait PeerList {
    fn verify_peer(&self, peer: &ArtificePeer) -> bool;
    fn get_peer(&self, key: &NetworkHash) -> Option<&ArtificePeer>;
}
