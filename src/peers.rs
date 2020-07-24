use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::encryption::PubKeyPair;
use crate::random_string;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Layer3SocketAddr {
    addr: Layer3Addr,
    port: u16,
}
impl Layer3SocketAddr {
    pub fn from_layer3_addr(addr: Layer3Addr, port: u16) -> Self {
        Self { addr, port }
    }
    pub fn as_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr.as_ipaddr(), self.port)
    }
    pub fn as_ipaddr(&self) -> IpAddr {
        self.addr.as_ipaddr()
    }
}

/// representation of an IpAddr that can be saved to a file, the purpose of this being the ability to connect to stable global peers even after the cnnection has been closed for a time
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer3Addr {
    V4([u8; 4]),
    V6([u16; 8]),
}
impl Layer3Addr {
    pub fn as_ipaddr(&self) -> IpAddr {
        match self {
            Self::V4(addr) => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            Self::V6(addr) => IpAddr::V6(Ipv6Addr::new(
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            )),
        }
    }
    pub fn from_ipaddr(ipaddr: &IpAddr) -> Self {
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
    pub fn to_socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.as_ipaddr(), port)
    }
}
/// make sure that bit shifting/as works as expected
#[test]
pub fn back_and_forth() {
    let ipv6addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    let layer3addr = Layer3Addr::from_ipaddr(&ipv6addr);
    let newipaddr = layer3addr.as_ipaddr();
    assert_eq!(ipv6addr, newipaddr);
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemotePeer {
    global_peer_hash: String,
    addr: Layer3SocketAddr,
    routable: bool,
    pubkey: PubKeyPair,
}
impl RemotePeer {
    pub fn generate(pubkey: PubKeyPair, addr: Layer3SocketAddr, routable: bool) -> Self {
        let global_peer_hash = random_string(50);
        Self {
            global_peer_hash,
            addr,
            routable,
            pubkey,
        }
    }
    pub fn global_peer_hash(&self) -> String {
        self.global_peer_hash.clone()
    }
    pub fn addr(&self) -> Layer3SocketAddr {
        self.addr.clone()
    }
    pub fn pubkey(&self) -> PubKeyPair {
        self.pubkey.clone()
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
    pubkey: PubKeyPair,
    /// this is only for the pair between this server and that peer
    peer_hash: String,
}
impl PartialEq for ArtificePeer {
    fn eq(&self, other: &Self) -> bool {
        self.global_peer_hash == other.global_peer_hash
            && self.pubkey == other.pubkey
            && self.peer_hash == other.peer_hash
    }
}
impl ArtificePeer {
    /// constructor that takes in pre-existing peer hash gained from the peer request
    /// global_peer_hash is something public to everyone on the network and is a means for provide hashed data access to verify the peer
    /// pubkey is sent to coordinate with keypair, if the records on the hsot match the peer, then the machine is assumed somewhat safe
    /// (used to prevent the danger of pubkey theft as each pairkey only exists between one particular peer and another)
    /// remote user provides further verification of identity, and is used in junction with peer verification to control access rights
    pub fn new(
        peer_hash: String,
        global_peer_hash: String,
        addr: Layer3SocketAddr,
        pubkey: PubKeyPair,
    ) -> Self {
        let routable = addr.as_ipaddr().is_global();
        Self {
            global_peer_hash,
            addr,
            routable,
            pubkey,
            peer_hash,
        }
    }
    pub fn global_peer_hash(&self) -> String {
        self.global_peer_hash.clone()
    }
    // get ipaddr associated with this peer
    pub fn addr(&self) -> IpAddr{
        self.addr.as_ipaddr()
    }
    /// makes public key pair available to the client program, for encryption purposes
    pub fn pubkeypair(&self) -> PubKeyPair {
        self.pubkey.clone()
    }
    /// makes key pair hash available to the client program to verify the remote peer
    pub fn peer_hash(&self) -> String {
        self.peer_hash.clone()
    }
    // includes port 
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        self.addr.as_socket_addr()
    }
}
impl PeerList for ArtificePeer{
    fn verify_peer(&self, peer: &ArtificePeer) -> bool{
        *self == *peer
    }
}
pub trait PeerList {
    fn verify_peer(&self, peer: &ArtificePeer) -> bool;
}