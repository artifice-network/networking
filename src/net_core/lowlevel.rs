use crate::{L2Addr, NetworkError};
use ipnetwork::IpNetwork;
use pnet::{
    datalink::{
        channel as datalink_channel, interfaces, Channel, Config, DataLinkReceiver, DataLinkSender,
        NetworkInterface,
    },
    packet::Packet,
    util::MacAddr,
};
use std::{io::ErrorKind, net::IpAddr, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetInterface {
    name: String,
    ips: Vec<IpNetwork>,
    mac: Option<L2Addr>,
    index: u32,
    flags: u32,
}

impl NetInterface {
    pub fn get_interfaces() -> Vec<NetInterface> {
        interfaces()
            .into_iter()
            .map(|interface| interface.into())
            .collect()
    }
    pub fn by_name(name: &str) -> Option<Self> {
        interfaces()
            .into_iter()
            .filter(|interface| interface.name == name)
            .next()
            .map_or_else(|| None, |interface| Some(interface.into()))
    }
    pub fn by_ip(ip: IpAddr) -> Option<Self> {
        interfaces()
            .into_iter()
            .filter(|interface| interface.ips.contains(&ip.into()))
            .next()
            .map_or_else(|| None, |interface| Some(interface.into()))
    }
    pub fn datalink_channel(&self) -> Result<(LinkSender, LinkReceiver), NetworkError> {
        let mut config = Config::default();
        config.write_timeout = Some(Duration::from_millis(10));
        config.read_timeout = Some(Duration::from_millis(10));
        let (tx, rx) = match datalink_channel(&self.into(), config)? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => {
                return Err(NetworkError::ExecFailed(String::from(
                    "Non Ethernet Channel",
                )))
            }
        };
        Ok((LinkSender::new(tx), LinkReceiver::new(rx)))
    }
    pub fn mac(&self) -> &Option<L2Addr> {
        &self.mac
    }
}
pub trait LinkPacket: Packet {
    fn get_destination(&self) -> MacAddr;
    fn set_destination<A: Into<MacAddr>>(&mut self, addr: A);
    fn get_source(&self) -> MacAddr;
    fn set_source<A: Into<MacAddr>>(&mut self, addr: A);
}
pub struct LinkSender {
    sender: Box<dyn DataLinkSender>,
}
impl LinkSender {
    pub fn new(sender: Box<dyn DataLinkSender>) -> Self {
        Self { sender }
    }
    pub fn send_to<P: LinkPacket>(
        &mut self,
        mut packet: P,
        addr: L2Addr,
    ) -> Result<(), NetworkError> {
        packet.set_destination(addr);
        match self.sender.send_to(packet.packet(), None) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e.into()),
            None => Err(NetworkError::ExecFailed(String::from(
                "couldn't send datalink packet",
            ))),
        }
    }
    pub fn build_and_send<F: FnMut(&mut [u8])>(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), NetworkError> {
        match self.sender.build_and_send(num_packets, packet_size, func) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e.into()),
            None => Err(NetworkError::ExecFailed(String::from(
                "couldn't send datalink packet",
            ))),
        }
    }
}
pub struct LinkReceiver {
    receiver: Box<dyn DataLinkReceiver>,
}
impl LinkReceiver {
    pub fn new(receiver: Box<dyn DataLinkReceiver>) -> Self {
        Self { receiver }
    }
    /// non blocking read
    pub fn try_recv(&mut self) -> Result<&[u8], NetworkError> {
        match self.receiver.next() {
            Ok(data) => Ok(data),
            Err(e) => match e.kind() {
                ErrorKind::TimedOut => return Err(NetworkError::Empty),
                _ => Err(e.into()),
            },
        }
    }
}
impl From<&NetworkInterface> for NetInterface {
    fn from(inter: &NetworkInterface) -> NetInterface {
        NetInterface {
            name: inter.name.clone(),
            ips: inter.ips.clone(),
            mac: inter
                .mac
                .as_ref()
                .map_or_else(|| None, |mac| Some(mac.into())),
            index: inter.index,
            flags: inter.flags,
        }
    }
}
impl From<NetworkInterface> for NetInterface {
    fn from(inter: NetworkInterface) -> NetInterface {
        NetInterface {
            name: inter.name,
            ips: inter.ips,
            mac: inter.mac.map_or_else(|| None, |mac| Some(mac.into())),
            index: inter.index,
            flags: inter.flags,
        }
    }
}
impl From<&NetInterface> for NetworkInterface {
    fn from(net: &NetInterface) -> NetworkInterface {
        NetworkInterface {
            name: net.name.clone(),
            ips: net.ips.clone(),
            mac: net
                .mac
                .as_ref()
                .map_or_else(|| None, |mac| Some(mac.into())),
            index: net.index,
            flags: net.flags,
        }
    }
}
impl From<&MacAddr> for L2Addr {
    fn from(mac: &MacAddr) -> L2Addr {
        let addr: [u8; 6] = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];
        L2Addr::from(addr)
    }
}
impl From<MacAddr> for L2Addr {
    fn from(mac: MacAddr) -> L2Addr {
        let addr: [u8; 6] = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];
        L2Addr::from(addr)
    }
}
impl From<L2Addr> for MacAddr {
    fn from(addr: L2Addr) -> MacAddr {
        MacAddr(
            addr.addr[0],
            addr.addr[1],
            addr.addr[2],
            addr.addr[3],
            addr.addr[4],
            addr.addr[5],
        )
    }
}
impl From<&L2Addr> for MacAddr {
    fn from(addr: &L2Addr) -> MacAddr {
        MacAddr(
            addr.addr[0],
            addr.addr[1],
            addr.addr[2],
            addr.addr[3],
            addr.addr[4],
            addr.addr[5],
        )
    }
}
