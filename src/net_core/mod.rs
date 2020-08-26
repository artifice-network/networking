#[cfg(feature = "lowlevel")]
pub mod lowlevel;
#[cfg(feature = "lowlevel")]
pub use lowlevel::*;
#[cfg(feature = "adhoc")]
pub mod adhoc;
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};
/// a serde serializable representation of std::net::SocketAddr
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct L4Addr {
    addr: L3Addr,
    port: u16,
}
impl L4Addr {
    pub fn new(addr: L3Addr, port: u16) -> Self {
        Self { addr, port }
    }
    pub fn ip(&self) -> L3Addr {
        self.addr
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}
impl fmt::Display for L4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}
impl PartialEq<SocketAddr> for L4Addr {
    fn eq(&self, other: &SocketAddr) -> bool {
        other.ip() == self.addr && other.port() == self.port
    }
}
impl PartialEq<L4Addr> for SocketAddr {
    fn eq(&self, other: &L4Addr) -> bool {
        self.ip() == other.ip() && self.port() == other.port()
    }
}
impl From<(L3Addr, u16)> for L4Addr {
    fn from((addr, port): (L3Addr, u16)) -> Self {
        Self { addr, port }
    }
}
impl From<&SocketAddr> for L4Addr {
    fn from(addr: &SocketAddr) -> L4Addr {
        Self {
            addr: addr.ip().into(),
            port: addr.port(),
        }
    }
}
/// this module is only supported on std, not tokio becuase it seems whoever implemented the
/// tokio::net::ToSocketAddrs, was stingy, and made the trait a wrapper around a private trait
/// a future implementation might use a std network stream, to construct the tokio equvilent
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Layer3SocketIter {
    value: Vec<L4Addr>,
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
    pub fn into_inner(self) -> Vec<L4Addr> {
        self.value
    }
}
impl Default for Layer3SocketIter {
    fn default() -> Self {
        Self { value: Vec::new() }
    }
}
impl From<L4Addr> for Layer3SocketIter {
    fn from(addr: L4Addr) -> Self {
        let mut value = Vec::new();
        value.push(addr);
        Self { value }
    }
}
impl From<&L4Addr> for Layer3SocketIter {
    fn from(addr: &L4Addr) -> Self {
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
impl ToSocketAddrs for L4Addr {
    type Iter = Layer3SocketIter;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        Ok(Layer3SocketIter::from(self))
    }
}
impl From<SocketAddr> for L4Addr {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr: addr.ip().into(),
            port: addr.port(),
        }
    }
}
impl From<L4Addr> for SocketAddr {
    fn from(addr: L4Addr) -> Self {
        SocketAddr::new(addr.addr.into(), addr.port)
    }
}
impl From<L4Addr> for (L3Addr, u16) {
    fn from(addr: L4Addr) -> (L3Addr, u16) {
        (addr.addr, addr.port)
    }
}
/// representation of an IpAddr that can be saved to a file, the purpose of this being the ability to connect to stable global peers even after the cnnection has been closed for a time
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum L3Addr {
    V4([u8; 4]),
    V6([u16; 8]),
}
impl L3Addr {
    pub fn newv4(v1: u8, v2: u8, v3: u8, v4: u8) -> Self {
        Self::V4([v1, v2, v3, v4])
    }
    pub fn newv6(addr: [u16; 8]) -> Self {
        Self::V6(addr)
    }
}
impl fmt::Display for L3Addr {
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
impl PartialEq<IpAddr> for L3Addr {
    fn eq(&self, other: &IpAddr) -> bool {
        IpAddr::from(*self) == *other
    }
}
impl PartialEq<L3Addr> for IpAddr {
    fn eq(&self, other: &L3Addr) -> bool {
        L3Addr::from(*self) == *other
    }
}
impl From<&L3Addr> for IpAddr {
    fn from(addr: &L3Addr) -> Self {
        IpAddr::from(*addr)
    }
}
impl From<IpAddr> for L3Addr {
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
impl From<&SocketAddr> for L3Addr {
    fn from(ipaddr: &SocketAddr) -> L3Addr {
        ipaddr.ip().into()
    }
}
impl From<L4Addr> for IpAddr {
    fn from(addr: L4Addr) -> IpAddr {
        addr.ip().into()
    }
}
impl From<L3Addr> for IpAddr {
    fn from(addr: L3Addr) -> Self {
        match addr {
            L3Addr::V4(addr) => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            L3Addr::V6(addr) => IpAddr::V6(Ipv6Addr::new(
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            )),
        }
    }
}
impl From<&IpAddr> for L3Addr {
    fn from(addr: &IpAddr) -> Self {
        Self::from(*addr)
    }
}
/// make sure that bit shifting/as works as expected
#[test]
pub fn back_and_forth() {
    let ipv6addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    let L3Addr = L3Addr::from(&ipv6addr);
    let newipaddr: IpAddr = L3Addr.into();
    assert_eq!(ipv6addr, newipaddr);
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct L2Addr {
    addr: [u8; 6],
}
impl From<[u8; 6]> for L2Addr {
    fn from(addr: [u8; 6]) -> L2Addr {
        Self { addr }
    }
}
