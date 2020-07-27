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
#[macro_use]
extern crate lazy_static;
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
use std::net::{IpAddr, SocketAddr};
use std::{
    convert::TryInto,
    net::UdpSocket,
    sync::mpsc::{channel, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};
/// this function is used for testing since it takes so much time to generate private key
fn get_private_key() -> RSAPrivateKey {
    use num_bigint_dig::BigUint;

    let n = BigUint::from_bytes_be(&[
        214, 82, 135, 64, 34, 118, 248, 217, 78, 42, 130, 198, 138, 28, 117, 66, 23, 74, 77, 139,
        51, 187, 14, 166, 48, 66, 217, 18, 157, 202, 175, 238, 60, 29, 39, 85, 58, 33, 145, 25, 55,
        214, 51, 72, 184, 142, 141, 183, 54, 186, 102, 59, 131, 86, 167, 220, 74, 65, 65, 43, 42,
        104, 182, 108, 144, 96, 238, 52, 145, 126, 239, 25, 41, 16, 221, 86, 26, 27, 87, 100, 171,
        205, 80, 216, 235, 202, 125, 204, 231, 254, 67, 77, 100, 154, 173, 137, 14, 154, 200, 188,
        123, 41, 96, 177, 19, 105, 23, 230, 2, 249, 66, 147, 107, 152, 108, 37, 203, 68, 228, 119,
        255, 64, 4, 53, 106, 145, 228, 191, 24, 199, 3, 232, 39, 170, 123, 227, 204, 68, 97, 216,
        182, 169, 82, 144, 88, 184, 84, 127, 118, 168, 50, 192, 241, 111, 15, 32, 12, 130, 25, 74,
        107, 187, 126, 154, 154, 194, 29, 56, 122, 3, 208, 65, 206, 216, 3, 22, 113, 227, 55, 55,
        206, 184, 132, 85, 236, 144, 7, 146, 98, 220, 37, 208, 81, 82, 21, 166, 151, 67, 14, 73,
        194, 84, 242, 234, 202, 111, 159, 5, 100, 93, 52, 120, 243, 86, 116, 123, 114, 52, 184, 74,
        99, 96, 120, 124, 19, 53, 161, 84, 133, 163, 144, 88, 163, 17, 171, 101, 164, 223, 169, 15,
        63, 80, 2, 207, 95, 248, 66, 244, 196, 207, 68, 49, 45, 25, 95, 255,
    ]);
    let e = BigUint::from_bytes_be(&[1, 0, 1]);
    let d = BigUint::from_bytes_be(&[
        11, 49, 174, 76, 196, 64, 16, 137, 81, 18, 217, 87, 195, 88, 239, 42, 239, 138, 122, 248,
        93, 80, 84, 216, 139, 70, 194, 141, 189, 94, 27, 200, 70, 173, 131, 35, 105, 112, 221, 98,
        66, 207, 86, 72, 99, 19, 87, 5, 141, 191, 56, 157, 189, 35, 102, 139, 19, 249, 202, 140,
        149, 159, 120, 127, 189, 30, 194, 242, 77, 243, 34, 75, 223, 32, 57, 95, 72, 231, 202, 173,
        192, 103, 109, 228, 150, 148, 49, 243, 228, 222, 27, 231, 203, 236, 100, 73, 247, 80, 80,
        81, 191, 225, 14, 98, 209, 79, 184, 230, 211, 154, 239, 70, 65, 229, 105, 40, 164, 48, 73,
        250, 150, 131, 98, 116, 227, 199, 16, 250, 109, 169, 223, 94, 194, 200, 235, 244, 81, 141,
        113, 70, 119, 176, 15, 189, 108, 182, 211, 139, 9, 72, 167, 91, 225, 129, 247, 159, 121,
        242, 5, 23, 91, 140, 221, 19, 184, 19, 24, 255, 255, 220, 67, 192, 150, 40, 159, 117, 191,
        35, 175, 156, 230, 134, 246, 25, 89, 45, 105, 99, 44, 246, 35, 232, 239, 248, 1, 250, 42,
        150, 86, 234, 244, 142, 204, 108, 149, 31, 236, 200, 217, 36, 169, 27, 254, 17, 99, 82, 80,
        46, 228, 129, 124, 79, 28, 156, 82, 145, 111, 220, 16, 204, 203, 24, 220, 246, 241, 15,
        206, 116, 152, 29, 56, 164, 237, 164, 101, 52, 139, 219, 66, 24, 55, 128, 116, 219, 189,
        217,
    ]);
    let primes = vec![
        BigUint::from_bytes_be(&[
            218, 18, 255, 185, 216, 198, 202, 164, 130, 230, 249, 202, 68, 69, 5, 246, 219, 99,
            170, 211, 253, 14, 210, 149, 41, 44, 110, 173, 245, 102, 19, 175, 3, 243, 129, 86, 166,
            104, 105, 78, 11, 162, 161, 239, 8, 206, 97, 222, 183, 132, 115, 39, 49, 172, 164, 33,
            43, 135, 173, 254, 37, 14, 185, 213, 129, 255, 31, 152, 100, 138, 247, 156, 59, 183,
            46, 242, 184, 222, 208, 55, 159, 29, 5, 192, 123, 12, 186, 176, 32, 237, 151, 159, 190,
            44, 144, 186, 37, 149, 107, 154, 19, 116, 16, 196, 53, 166, 113, 122, 192, 87, 122,
            124, 252, 84, 221, 91, 56, 15, 55, 74, 92, 56, 82, 176, 104, 149, 87, 195,
        ]),
        BigUint::from_bytes_be(&[
            251, 152, 125, 227, 130, 36, 160, 198, 157, 132, 251, 120, 127, 208, 105, 53, 3, 219,
            28, 218, 154, 192, 227, 251, 141, 201, 136, 237, 210, 125, 215, 149, 134, 32, 240, 187,
            116, 102, 200, 255, 174, 116, 14, 121, 133, 65, 96, 31, 211, 100, 81, 152, 87, 243,
            210, 108, 0, 120, 144, 148, 74, 68, 183, 245, 111, 38, 138, 127, 60, 84, 53, 100, 203,
            208, 82, 220, 91, 30, 137, 202, 143, 93, 123, 7, 206, 144, 171, 174, 124, 125, 114,
            116, 226, 238, 225, 189, 243, 122, 47, 123, 185, 100, 250, 200, 25, 248, 70, 89, 234,
            28, 113, 190, 180, 50, 253, 221, 215, 209, 8, 176, 82, 10, 248, 85, 73, 236, 79, 21,
        ]),
    ];
    RSAPrivateKey::from_components(n, e, d, primes)
}
lazy_static! {
    static ref PEERCONFIG: (ArtificePeer, ArtificeConfig) = {
        let private_key = get_private_key();
        let global_hash = "CzlFhuFsF7fCYIk1b8CnGuERPeJ2ywOzsMxSKyxTFKTAQlU8Fl".to_string();
        let peer_hash = "2o4iPLBTDzLDedP4xvijngPfaw99TszSrMS99IwxxuXhZZyOqi".to_string();
        let peer = ArtificePeer::new(
            global_hash.clone(),
            peer_hash,
            Layer3SocketAddr::from_layer3_addr(Layer3Addr::V4([127, 0, 0, 1]), 6464),
            PubKeyComp::from(&private_key),
        );
        let host_data = ArtificeHostData::new(&private_key, global_hash);
        let config = ArtificeConfig::new(Layer3Addr::V4([0, 0, 0, 0]), 6464, host_data, false);
        (peer, config)
    };
}
/// used in examples, and tests, generates ArtificePeer, and ArtificeConfig because private keys take a while to generate
/// this method generates static data, so it should never be used in production environments
pub fn test_config() -> (ArtificePeer, ArtificeConfig) {
    (PEERCONFIG.0.clone(), PEERCONFIG.1.clone())
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
        StreamHeader::new(
            self.peer.global_peer_hash(),
            self.peer.peer_hash(),
            self.packet_len,
        )
    }
    pub fn peer(&self) -> &ArtificePeer {
        &self.peer
    }
    pub fn pubkey(&self) -> Result<RSAPublicKey, NetworkError> {
        self.peer.pubkey()
    }
    pub fn pubkeycomp(&self) -> &PubKeyComp {
        self.peer.pubkeycomp()
    }
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
    pub fn set_len(&mut self, len: usize) {
        self.packet_len = len;
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
/// fn send(&mut self, inbuf: &[u8]) -> Result<usize, Box<dyn Error>>
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
        let components = self.pubkeycomp();
        Ok(RSAPublicKey::new(components.n(), components.e())?)
    }
    fn pubkeycomp(&self) -> &PubKeyComp {
        self.header().pubkeycomp()
    }
    fn peer(&self) -> &ArtificePeer;
    fn header(&self) -> &Header;
}
/// used to set discoverability on the local network
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
        if list.verify_peer(&self.stream.peer()) {
            Ok(self.stream)
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
