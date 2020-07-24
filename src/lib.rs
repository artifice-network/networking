/*!
for async examples see <a href="https://crates.io/crates/networking">crates.io</a>

```
## Sync Client

```
use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
use std::fs::File;
use std::io::Read;
fn main() {
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = Vec::new();
    file.read_to_end(&mut invec).unwrap();
    let string = String::from_utf8(invec).unwrap();
    // println!("invec: {}", invec);
    let peer: ArtificePeer = serde_json::from_str(&string).unwrap();
    let host = ArtificeHost::client_only(&config);
    let mut stream = host.connect(peer).unwrap();
    let mut buffer = Vec::new();
    println!("about to read from sream");
    println!(
        "got {} bytes from server",
        stream.recv(&mut buffer).unwrap()
    );
    println!("read from stream");
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
    //stream.write(&buffer).unwrap();
}

```

## Sync Server
```
use networking::{syncronous::SyncHost, ArtificeConfig, ArtificePeer, ArtificeStream};
use std::fs::File;
use std::io::Read;
fn main() {
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let host = SyncHost::from_host_data(&config).unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = String::new();
    file.read_to_string(&mut invec).unwrap();
    let peer: ArtificePeer = serde_json::from_str(&invec).unwrap();
    for netstream in host {
        let mut stream = netstream.unwrap().verify(&peer).unwrap();
        println!("about to write to stream");
        stream
            .send(&"hello world".to_string().into_bytes())
            .unwrap();
    }
}


```
*/
#![feature(maybe_uninit_ref)]
#![feature(ip)]
#[macro_use]
extern crate serde_derive;
/// contains blowfish encryption wrapper, as well as storage solution (serde) for BigUint principly BigNum
pub mod encryption;
pub mod error;
pub use encryption::*;
pub mod asyncronous;
/// contains the ArtificePeer struct
pub mod peers;
/// used for permission requests in the manager crate
pub mod query;
pub mod syncronous;
use crate::encryption::PubKeyPair;
use crate::error::NetworkError;
pub use peers::*;
use rsa::{RSAPublicKey, RSAPrivateKey};
use std::net::{SocketAddr, IpAddr};
use std::{
    net::UdpSocket,
    sync::mpsc::{channel, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};
/// used to build and configure the local host
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtificeConfig {
    broadcast: bool,
    address: Layer3Addr,
    port: u16,
    host: ArtificeHostData,
}
impl ArtificeConfig {
    /// used to create new host, primarily designed for use by the installer crate
    pub fn generate(address: Layer3Addr) -> Self {
        let broadcast = false;
        let port = 6464;
        let host = ArtificeHostData::default();
        Self {
            broadcast,
            address,
            port,
            host,
        }
    }
    pub fn host_data(&self) -> ArtificeHostData {
        self.host.clone()
    }
    pub fn broadcast(&self) -> bool {
        self.broadcast
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn address(&self) -> Layer3Addr {
        self.address
    }
}

/// provides a means of saving private keys to files, because the process of generating the keys takes a really long time, but creating them from existing values does not
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtificeHostData {
    priv_key: PrivKeyComp,
    global_peer_hash: String,
}
impl Default for ArtificeHostData {
    fn default() -> Self {
        let global_peer_hash = random_string(50);
        let priv_key = PrivKeyComp::generate().unwrap();
        Self {
            priv_key,
            global_peer_hash,
        }
    }
}
impl ArtificeHostData {
    pub fn private_key(&self) -> PrivKeyComp {
        self.priv_key.clone()
    }
    pub fn global_peer_hash(&self) -> String {
        self.global_peer_hash.clone()
    }
}
/// contains peer information sent accross the network in an effort to prevent man in the middle attacks
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Header {
    peer: ArtificePeer,
    pubkey: PubKeyPair,
    packet_len: usize,
    new_connection: bool,
}
impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.peer == other.peer && self.pubkey == other.pubkey
    }
}
impl Header {
    pub fn new(peer: ArtificePeer, pubkey: PubKeyPair) -> Self {
        Self {
            peer,
            pubkey,
            packet_len: 0,
            new_connection: false,
        }
    }
    pub fn new_connection(peer: ArtificePeer, pubkey: PubKeyPair) -> Self{
        Self{
            peer,
            pubkey,
            packet_len: 0,
            new_connection: true,
        }
    }
    pub fn peer(&self) -> &ArtificePeer {
        &self.peer
    }
    pub fn pubkey(&self) -> RSAPublicKey {
        RSAPublicKey::new(self.pubkey.n(), self.pubkey.e()).unwrap()
    }
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
    pub fn set_len(&mut self, len: usize) {
        self.packet_len = len;
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StreamHeader {
    global_hash: String,
    peer_hash: String,
    packet_len: usize,
}
impl StreamHeader {
    pub fn new(global_hash: String, peer_hash: String, packet_len: usize) -> Self {
        Self {
            global_hash,
            peer_hash,
            packet_len,
        }
    }
}
/// trait used to implement common features between async and sync implementations of networking
pub trait ArtificeStream {
    type NetStream;
    fn new(stream: Self::NetStream, priv_key: RSAPrivateKey, peer: ArtificePeer, remote_addr: SocketAddr) -> Self;
    fn addr(&self) -> IpAddr{
        self.socket_addr().ip()
    }
    fn socket_addr(&self) -> SocketAddr;
    fn pubkey(&self) -> RSAPublicKey;
    fn peer(&self) -> &ArtificePeer;
    fn header(&self) -> Header;
}
pub trait ArtificeHost {
    fn begin_broadcast(socket_addr: SocketAddr) -> std::io::Result<Sender<bool>> {
        let (sender, recv) = channel();
        let socket = UdpSocket::bind(socket_addr)?;
        socket.set_broadcast(true)?;
        thread::spawn(move || loop {
            match recv.recv_timeout(Duration::from_millis(200)) {
                Ok(_) => break,
                Err(e) => match e {
                    RecvTimeoutError::Timeout => continue,
                    RecvTimeoutError::Disconnected => break,
                },
            }
        });
        Ok(sender)
    }
    fn stop_broadcasting(&self);
}
pub struct ConnectionRequest<T: ArtificeStream>{
    stream: T,
}
impl<T: ArtificeStream> ConnectionRequest<T>{
    pub fn new(stream: T) -> Self{
        Self {stream}
    }
    /// used to ensure only known peers are allow to connect
    pub fn verify<L: PeerList>(self, list: &L) -> Result<T, NetworkError>{
        if list.verify_peer(&self.stream.peer()) {
            Ok(self.stream)
        }else{
            Err(NetworkError::ConnectionDenied("verification of peer failed".to_string()))
        }
    }
    /// this function allows unauthorized peers to connect to this device
    /// should only be used if a pair request is being run
    pub unsafe fn unverify(self) -> T{
        self.stream
    }
}