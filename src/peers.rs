use crate::encryption::PubKeyComp;
use crate::{error::NetworkError, random_string};
use rsa::RSAPublicKey;
use std::fmt;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// a serde serializable representation of std::net::SocketAddr
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Layer3SocketAddr {
    addr: Layer3Addr,
    port: u16,
}
impl Layer3SocketAddr {
    pub fn ip(&self) -> Layer3Addr {
        self.addr
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}
impl fmt::Display for Layer3SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}
impl PartialEq<SocketAddr> for Layer3SocketAddr {
    fn eq(&self, other: &SocketAddr) -> bool {
        other.ip() == self.addr && other.port() == self.port
    }
}
impl PartialEq<Layer3SocketAddr> for SocketAddr {
    fn eq(&self, other: &Layer3SocketAddr) -> bool {
        self.ip() == other.ip() && self.port() == other.port()
    }
}
impl From<(Layer3Addr, u16)> for Layer3SocketAddr {
    fn from((addr, port): (Layer3Addr, u16)) -> Self {
        Self { addr, port }
    }
}
/// this module is only supported on std, not tokio becuase it seems whoever implemented the
/// tokio::net::ToSocketAddrs, was stingy, and made the trait a wrapper around a private trait
/// a future implementation might use a std network stream, to construct the tokio equvilent
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Layer3SocketIter {
    value: Vec<Layer3SocketAddr>,
}
impl Layer3SocketIter {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            value: Vec::with_capacity(cap),
        }
    }
    pub fn into_inner(self) -> Vec<Layer3SocketAddr> {
        self.value
    }
}
impl Default for Layer3SocketIter {
    fn default() -> Self {
        Self { value: Vec::new() }
    }
}
impl From<Layer3SocketAddr> for Layer3SocketIter {
    fn from(addr: Layer3SocketAddr) -> Self {
        let mut value = Vec::new();
        value.push(addr);
        Self { value }
    }
}
impl From<&Layer3SocketAddr> for Layer3SocketIter {
    fn from(addr: &Layer3SocketAddr) -> Self {
        Layer3SocketIter::from(*addr)
    }
}
impl Iterator for Layer3SocketIter {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<Self::Item> {
        match self.value.pop() {
            Some(addr) => Some(SocketAddr::from(addr)),
            None => None,
        }
    }
}
impl ToSocketAddrs for Layer3SocketAddr {
    type Iter = Layer3SocketIter;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        Ok(Layer3SocketIter::from(self))
    }
}
impl From<SocketAddr> for Layer3SocketAddr {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr: addr.ip().into(),
            port: addr.port(),
        }
    }
}
impl From<Layer3SocketAddr> for SocketAddr {
    fn from(addr: Layer3SocketAddr) -> Self {
        SocketAddr::new(addr.addr.into(), addr.port)
    }
}
impl From<Layer3SocketAddr> for (Layer3Addr, u16) {
    fn from(addr: Layer3SocketAddr) -> (Layer3Addr, u16) {
        (addr.addr, addr.port)
    }
}
/// representation of an IpAddr that can be saved to a file, the purpose of this being the ability to connect to stable global peers even after the cnnection has been closed for a time
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer3Addr {
    V4([u8; 4]),
    V6([u16; 8]),
}
impl Layer3Addr {
    pub fn newv4(v1: u8, v2: u8, v3: u8, v4: u8) -> Self {
        Self::V4([v1, v2, v3, v4])
    }
    pub fn newv6(v1: u16, v2: u16, v3: u16, v4: u16, v5: u16, v6: u16, v7: u16, v8: u16) -> Self {
        Self::V6([v1, v2, v3, v4, v5, v6, v7, v8])
    }
}
impl fmt::Display for Layer3Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::V4([v1, v2, v3, v4]) => format!("{}.{}.{}.{}", v1, v2, v3, v4),
            Self::V6([v1, v2, v3, v4, v5, v6, v7, v8]) => format!(
                "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
                v1, v2, v3, v4, v5, v6, v7, v8
            ),
        };
        write!(f, "{}", msg)
    }
}
impl PartialEq<IpAddr> for Layer3Addr {
    fn eq(&self, other: &IpAddr) -> bool {
        IpAddr::from(*self) == *other
    }
}
impl PartialEq<Layer3Addr> for IpAddr {
    fn eq(&self, other: &Layer3Addr) -> bool {
        Layer3Addr::from(*self) == *other
    }
}
impl From<&Layer3Addr> for IpAddr {
    fn from(addr: &Layer3Addr) -> Self {
        IpAddr::from(*addr)
    }
}
impl From<IpAddr> for Layer3Addr {
    fn from(ipaddr: IpAddr) -> Self {
        match ipaddr {
            IpAddr::V4(addr) => Self::V4(addr.octets()),
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let mut addr: [u16; 8] = [0; 8];
                let mut index: u8 = 0;
                for i in &mut addr {
                    *i = (octets[index as usize] as u16) | (octets[index as usize + 1] as u16);
                    index += 2;
                }
                Self::V6(addr)
            }
        }
    }
}
impl From<Layer3SocketAddr> for IpAddr {
    fn from(addr: Layer3SocketAddr) -> IpAddr {
        addr.into()
    }
}
impl From<Layer3Addr> for IpAddr {
    fn from(addr: Layer3Addr) -> Self {
        match addr {
            Layer3Addr::V4(addr) => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            Layer3Addr::V6(addr) => IpAddr::V6(Ipv6Addr::new(
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            )),
        }
    }
}
impl From<&IpAddr> for Layer3Addr {
    fn from(addr: &IpAddr) -> Self {
        Self::from(*addr)
    }
}
/// make sure that bit shifting/as works as expected
#[test]
pub fn back_and_forth() {
    let ipv6addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    let layer3addr = Layer3Addr::from(&ipv6addr);
    let newipaddr: IpAddr = layer3addr.into();
    assert_eq!(ipv6addr, newipaddr);
}
/// used as a precursor to artifice peer, principly it is used to store information about a given peer
/// that is intended to be publicly available information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemotePeer {
    global_peer_hash: String,
    addr: Layer3SocketAddr,
    routable: bool,
    pubkey: PubKeyComp,
}
impl RemotePeer {
    pub fn new(
        global_hash: &str,
        pubkey: PubKeyComp,
        addr: Layer3SocketAddr,
        routable: bool,
    ) -> Self {
        Self {
            global_peer_hash: global_hash.to_string(),
            pubkey,
            addr,
            routable,
        }
    }
    pub fn generate(pubkey: PubKeyComp, addr: Layer3SocketAddr, routable: bool) -> Self {
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
    pub fn addr(&self) -> Layer3SocketAddr {
        self.addr
    }
    pub fn pubkeycomp(&self) -> &PubKeyComp {
        &self.pubkey
    }
    pub fn routable(&self) -> bool {
        self.routable
    }
}
/// this is a peer that represents a (theoretically) remote computer, this struct provides an attempt to verify the peer by holding a text string that only this particular host, and one host have access to
/// this is done in conjunction with public key authentication, as well as remote_user auth on an already encrypted channel so only those with permission can exercise their permissions
/// side noote permissions and peers operate on white list rather then blacklist for the sake of safety.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialOrd, Ord)]
pub struct ArtificePeer {
    global_peer_hash: String,
    addr: Layer3SocketAddr,
    routable: bool,
    pubkey: Option<PubKeyComp>,
    /// this is only for the pair between this server and that peer
    peer_hash: String,
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
        global_peer_hash: &str,
        peer_hash: &str,
        addr: Layer3SocketAddr,
        pubkey: Option<PubKeyComp>,
    ) -> Self {
        let routable = true; //IpAddr::from(addr).is_global();
        println!("in ArtificePeer::new()");
        Self {
            global_peer_hash: global_peer_hash.to_string(),
            addr,
            routable,
            pubkey,
            peer_hash: peer_hash.to_string(),
        }
    }
    pub fn global_peer_hash(&self) -> &str {
        &self.global_peer_hash
    }
    // get ipaddr associated with this peer
    pub fn addr(&self) -> IpAddr {
        self.addr.into()
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
    pub fn peer_hash(&self) -> &str {
        &self.peer_hash
    }
    // includes port
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        self.addr.into()
    }
    pub fn set_socket_addr(&mut self, sock_addr: SocketAddr) {
        self.addr = sock_addr.into();
    }
    pub fn set_pubkey(&mut self, pubkey: PubKeyComp) {
        self.pubkey = Some(pubkey);
    }
}
impl PeerList for ArtificePeer {
    fn verify_peer(&self, peer: &ArtificePeer) -> Option<PubKeyComp> {
        println!(
            "remote global: {}, remote peer: {}, local global: {}, local peer: {}",
            self.global_peer_hash(),
            peer.global_peer_hash(),
            self.peer_hash(),
            self.peer_hash(),
        );
        if "adac".to_string() == "adac".to_string() {
            peer.pubkeycomp().clone()
        } else {
            peer.pubkeycomp().clone()
        }
    }
    fn get_peer(&self, key: &str) -> Option<ArtificePeer> {
        if self.global_peer_hash == key {
            return Some(self.clone());
        }
        None
    }
}
/// used in ConnectionRequests verify method, anything that implements this trait
/// is assumed to be a list of peers that are allowed to connect to this device
pub trait PeerList {
    fn verify_peer(&self, peer: &ArtificePeer) -> Option<PubKeyComp>;
    fn get_peer(&self, key: &str) -> Option<ArtificePeer>;
}
