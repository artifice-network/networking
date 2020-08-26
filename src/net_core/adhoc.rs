use crate::NetworkError;
use crate::{
    net_core::{L2Addr, LinkReceiver, LinkSender, NetInterface},
    ArtificePeer, NetworkHash,
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdhocDB {
    addresses: HashMap<NetworkHash, L2Addr>,
    keys: HashMap<NetworkHash, NetworkHash>,
    net: IpNetwork,
}
impl AdhocDB {
    pub fn bind(
        hash: &NetworkHash,
        addr: L2Addr,
        key: &NetworkHash,
        prefix: u8,
    ) -> Result<Self, NetworkError> {
        let mut addresses = HashMap::new();
        let mut keys: HashMap<NetworkHash, NetworkHash> = HashMap::new();
        addresses.insert(hash.clone(), addr);
        keys.insert(hash.to_owned(), *key);
        let net = IpNetwork::new(hash.to_owned().into(), prefix)?;
        Ok(Self {
            addresses,
            keys,
            net,
        })
    }
    pub fn insert(&mut self, hash: &NetworkHash, addr: L2Addr, key: NetworkHash) {
        self.addresses.insert(hash.clone(), addr);
        self.keys.insert(hash.to_owned(), key);
    }
}

pub struct Adhoc {
    sender: LinkSender,
    receiver: LinkReceiver,
    db: AdhocDB,
}
impl Adhoc {
    pub fn bind(peer: &ArtificePeer, iface: &str, prefix: u8) -> Result<Self, NetworkError> {
        let interface = NetInterface::by_name(iface)?;
        let db = AdhocDB::bind(
            peer.global_peer_hash(),
            match interface.mac() {
                Some(addr) => addr.clone(),
                None => return Err(NetworkError::Empty),
            },
            peer.peer_hash(),
            prefix,
        )?;
        let (sender, receiver) = interface.datalink_channel()?;
        Ok(Self {
            sender,
            receiver,
            db,
        })
    }
}
