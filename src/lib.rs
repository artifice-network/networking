/*!
for async examples see <a href="https://crates.io/crates/networking">crates.io</a>

## Sync Server

``` ignore
use networking::{syncronous::SyncHost, test_config, ArtificeConfig, ArtificePeer, ArtificeStream};

let (peer, config) = test_config();
let host = SyncHost::from_host_data(&config).unwrap();
for netstream in host {
    println!("new connection");
    let mut stream = netstream.unwrap().verify(&peer).unwrap();
    stream.send(b"hello world").unwrap();
    break;
}
```
## Sync Client

``` ignore
use networking::{syncronous::SyncHost, test_config, ArtificeConfig, ArtificePeer};
use std::{thread, time::Duration};

let (peer, config) = test_config();
//thread::sleep(Duration::from_millis(200));
let host = SyncHost::client_only(&config).unwrap();
let mut stream = host.connect(peer).unwrap();
println!("connected");
let mut buffer = Vec::new();
println!("about to read from sream");
println!(
    "got {} bytes from server",
    stream.recv(&mut buffer).unwrap()
);
println!("read from stream");
let string = String::from_utf8(buffer).unwrap();
println!("got message: {} from server", string);
```
*/
#![feature(ip)]
#[macro_use]
extern crate serde_derive;
/// contains blowfish encryption wrapper, as well as storage solution (serde) for BigUint principly BigNum
pub mod encryption;
/// generates random strings of given length
pub use encryption::random_string;
pub mod error;
use encryption::*;
/// asyncronous implementation of the tcp networking provided in this crate
///
/// # Client Example
///
/// ``` ignore
/// use networking::{asyncronous::AsyncHost, test_config};
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///    let (peer, config) = test_config();
///    let host = AsyncHost::client_only(&config).await.unwrap();
///    let mut stream = host.connect(peer).await.unwrap();
///    let mut buffer = Vec::new();
///    println!(
///        "got {} bytes from server",
///        stream.recv(&mut buffer).await.unwrap()
///    );
///    let string = String::from_utf8(buffer).unwrap();
///    println!("got message: {} from server", string);
///    Ok(())
///}
/// ```
///
/// # Server Example
///
/// ``` ignore
/// use networking::{asyncronous::AsyncHost, test_config};
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let (peer, config) = test_config();
///     let mut host = AsyncHost::from_host_config(&config).await.unwrap();
///     while let Some(Ok(strm)) = host.incoming()?.await {
///         let mut stream = strm.verify(&peer)?;
///         // make sure you got a connection from the correct peer
///         println!("sending message hello world");
///         stream.send(b"hello world").await.unwrap();
///     }
///     Ok(())
/// }
/// ```
pub mod asyncronous;
/// contains the ArtificePeer struct
pub mod peers;
mod query;
pub use query::asyncronous as async_query;
pub use query::syncronous as sync_query;
/// used for bi-directional communication
pub use query::Query;

/// provides access to Sllp (Secure Low Latency Protocol) Socket and Stream
/// note that this module has no syncronous implementation
pub mod sllp;

pub mod syncronous;
use crate::encryption::PubKeyComp;
use crate::error::NetworkError;
pub use peers::*;
use rsa::{RSAPrivateKey, RSAPublicKey};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::{
    convert::TryInto,
    net::UdpSocket,
    sync::mpsc::{channel, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};
/// used in examples, and tests, generates ArtificePeer, and ArtificeConfig because private keys take a while to generate
/// this method generates static data, so it should never be used in production environments
pub fn test_config() -> (ArtificePeer, ArtificeConfig) {
    use std::fs::File;
    use std::io::Read;
    let mut peer_string = String::new();
    let mut file = File::open("peer.json").unwrap();
    file.read_to_string(&mut peer_string).unwrap();
    let peer = serde_json::from_str(&peer_string).unwrap();
    let mut config_string = String::new();
    let mut config_file = File::open("host.json").unwrap();
    config_file.read_to_string(&mut config_string).unwrap();
    let config = serde_json::from_str(&config_string).unwrap();

    (peer, config)
}
/// used to build and configure the local host
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtificeConfig {
    broadcast: bool,
    address: Layer3Addr,
    port: u16,
    host: ArtificeHostData,
}
impl ArtificeConfig {
    pub fn new(address: Layer3Addr, port: u16, host: ArtificeHostData, broadcast: bool) -> Self {
        Self {
            broadcast,
            address,
            port,
            host,
        }
    }
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
    pub fn new(private_key: &RSAPrivateKey, global_peer_hash: String) -> Self {
        let priv_key = PrivKeyComp::from(private_key);
        Self {
            priv_key,
            global_peer_hash,
        }
    }
    /// returns the n, e, d, and primes of an RSA key
    pub fn privkeycomp(&self) -> &PrivKeyComp {
        &self.priv_key
    }
    pub fn global_peer_hash(&self) -> &str {
        &self.global_peer_hash
    }
}
/// contains peer information sent accross the network in an effort to prevent man in the middle attacks
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Header {
    peer: ArtificePeer,
    packet_len: usize,
    new_connection: bool,
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
impl Header {
    pub fn new(peer: &ArtificePeer) -> Self {
        Self {
            peer: peer.to_owned(),
            packet_len: 0,
            new_connection: false,
        }
    }
    pub fn new_pair(peer: &ArtificePeer) -> Self {
        Self {
            peer: peer.to_owned(),
            packet_len: 0,
            new_connection: true,
        }
    }
    pub fn stream_header(&self) -> StreamHeader {
        StreamHeader::from(self)
    }
    pub fn peer(&self) -> &ArtificePeer {
        &self.peer
    }
    pub fn pubkey(&self) -> Result<RSAPublicKey, NetworkError> {
        self.peer.pubkey()
    }
    pub fn pubkeycomp(&self) -> &Option<PubKeyComp> {
        self.peer.pubkeycomp()
    }
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
    pub fn set_len(&mut self, len: usize) {
        self.packet_len = len;
    }
    pub fn set_pubkey(&mut self, pubkey: PubKeyComp) {
        self.peer.set_pubkey(pubkey);
    }
}
/// used to ensure man in the middle attack doesn't occure, but used in place of the Header struct
/// because it is much smaller
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StreamHeader {
    global_hash: String,
    peer_hash: String,
    aes_key: Vec<u8>,
    packet_len: usize,
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
            remander: 0,
        }
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
        outvec
    }
    /// convert 125 bytes (length of data) to StreamHeader
    pub fn from_raw(data: &[u8]) -> Result<Self, NetworkError> {
        assert_eq!(data.len(), 125);
        let global_hash = String::from_utf8(data[0..50].to_vec())?;
        let peer_hash = String::from_utf8(data[50..100].to_vec())?;
        let aes_key = data[100..116].to_vec();
        let packet_len = usize::from_be_bytes(data[116..124].try_into()?);
        let remander = data[124];
        Ok(Self {
            global_hash,
            peer_hash,
            aes_key,
            packet_len,
            remander,
        })
    }
}
impl From<&Header> for StreamHeader {
    fn from(header: &Header) -> Self {
        StreamHeader::new(
            header.peer().global_peer_hash(),
            header.peer().peer_hash(),
            header.packet_len(),
        )
    }
}
impl From<Header> for StreamHeader {
    fn from(header: Header) -> Self{
        StreamHeader::from(&header)
    }
}
#[test]
fn header_to_raw_from_raw() {
    let stream_header = StreamHeader::new(&random_string(50), &random_string(50), 0);
    let raw = stream_header.to_raw();
    let new_header = StreamHeader::from_raw(&raw).unwrap();
    assert_eq!(stream_header, new_header);
}
/// trait used to implement common features between async and syncrounous networking protocols
/// note about this trait, it defines only the shared behavior that doesn't require high levels of IO owing to the fact that
/// async funnctions currently can't be members of traits, I would ask that any implementation of this trait, also provides
/// certain methods, found in the implementations in this crate
///
/// # methods to include
///
/// ``` ignore
/// fn send(&mut self, inbuf: &vec![u8]) -> Result<usize, Box<dyn Error>>
/// fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>>
/// fn connect(peer: &ArtificePeer) -> Result<Self, Box<dyn Error>>
/// ```
/// # why these functions
/// reason for using these functions include
/// <ul>
/// <li>increased freedom over Write/AsyncWrite and Read/AsyncRead, such as chose of error</li>
/// <li>vectors are difficult to write to when in the form of a slice, this way methods such as append, and extend_from_slice can be used</li>
/// </ul>
pub trait ArtificeStream {
    type NetStream;
    type Error: std::error::Error;
    fn new(
        stream: Self::NetStream,
        priv_key: RSAPrivateKey,
        peer: &ArtificePeer,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
    fn addr(&self) -> IpAddr {
        self.socket_addr().ip()
    }
    fn socket_addr(&self) -> SocketAddr;
    fn pubkey(&self) -> Result<RSAPublicKey, NetworkError> {
        let components = match self.pubkeycomp() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        Ok(RSAPublicKey::new(
            components.n().into(),
            components.e().into(),
        )?)
    }
    fn pubkeycomp(&self) -> &Option<PubKeyComp> {
        self.header().pubkeycomp()
    }
    fn peer(&self) -> &ArtificePeer;
    fn header(&self) -> &Header;
    fn set_pubkey(self, pubkey: PubKeyComp) -> Self;
}
/// used to set discoverability on the local network
pub trait ArtificeHost {
    fn begin_broadcast<S: ToSocketAddrs>(socket_addr: S) -> std::io::Result<Sender<bool>> {
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
/// used to unlock network streams, to provent unauthorized peers
pub struct ConnectionRequest<T: ArtificeStream> {
    stream: T,
}
impl<T: ArtificeStream> ConnectionRequest<T> {
    pub fn new(stream: T) -> Self {
        Self { stream }
    }
    /// used to ensure only known peers are allow to connect
    pub fn verify<L: PeerList>(self, list: &L) -> Result<T, NetworkError> {
        if let Some(key) = list.verify_peer(&self.stream.peer()) {
            Ok(self.stream.set_pubkey(key))
        } else {
            Err(NetworkError::ConnectionDenied(
                "verification of peer failed".to_string(),
            ))
        }
    }
    /// # Safety
    /// this function allows unauthorized peers to connect to this device
    /// should only be used if a pair request is being run
    pub unsafe fn unverify(self) -> T {
        self.stream
    }
}
