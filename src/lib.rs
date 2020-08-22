/*!
for async examples see <a href="https://crates.io/crates/networking">crates.io</a>

## Sync Server

``` ignore
use networking::{syncronous::SyncHost, test_config, ArtificeConfig, ArtificePeer, SyncDataStream};

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
#![feature(untagged_unions)]
#![allow(clippy::redundant_closure)]
#[macro_use]
extern crate serde_derive;
extern crate serde_hex;
/// contains blowfish encryption wrapper, as well as storage solution (serde) for BigUint principly BigNum
pub mod encryption;
/// generates random strings of given length
pub mod error;
use encryption::*;
/// asyncronous implementation of the tcp networking provided in this crate
///
/// # Client Example
///
/// ``` ignore
/// use networking::{asyncronous::{AsyncHost, AsyncRecv, AsyncNetworkHost}, test_config};
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
/// use networking::{
///     asyncronous::{AsyncHost, AsyncNetworkHost, AsyncSend},
///     test_config, ConnectionRequest,
/// };
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let (peer, config) = test_config();
///     let mut host = AsyncHost::from_host_config(&config).await.unwrap();
///     let mut msg = networking::random_string(43235).into_bytes();
///     // can also be done in while let Some(Ok(strm)) = host.incoming()?.await
///     // this was better for the example though
///     if let Some(Ok(strm)) = host.incoming()?.await {
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
pub mod protocol;
use protocol::StreamHeader;

/// provides access to Sllp (Secure Low Latency Protocol) Socket and Stream, and is intended for high volume low precision operations
/// such as streaming
/// note that this module has no syncronous implementation
/// # Client Example
///
/// ```ignore
/// use networking::sllp::SllpSocket;
/// use networking::test_config;
/// use networking::Layer3Addr;
/// use std::error::Error;
/// use networking::asyncronous::{AsyncSend, AsyncNetworkHost};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn Error>> {
///     let (mut peer, config) = test_config();
///     let socket = SllpSocket::from_host_config(&config).await?;
///     // this needs to be updated to remote peer, because two devices cannot bind to the smae address
///     peer.set_socket_addr((Layer3Addr::newv4(127, 0, 0, 1), 6464).into());
///     let mut stream = socket.connect(&peer).await;
///     loop { stream.send(b"hello world").await.unwrap(); }
///     Ok(())
/// }
/// ```  
/// # Server Example
///
/// ```ignore
/// use networking::sllp::SllpSocket;
/// use networking::test_config;
/// use std::error::Error;
/// use networking::asyncronous::{AsyncRecv, AsyncNetworkHost};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn Error>> {
///     let (peer, config) = test_config();
///     let mut socket = SllpSocket::from_host_config(&config).await?;
///     while let Some(strm) = socket.incoming().await {
///         let mut stream = strm?.verify(&peer)?;
///         tokio::spawn(async move {
///             println!("new connection");
///             loop {
///                 let mut invec = Vec::new();
///                 stream.recv(&mut invec).await.unwrap();
///                 println!(
///                     "got message {}, from server",
///                     String::from_utf8(invec).unwrap()
///                 );
///             }
///         });
///     }
///     Ok(())
/// }
/// ```
pub mod sllp;

/// provides access to essentially a HashMap that can be written to disk
/// implements peer list so this struct can be used to verify peers
///
/// # Example
///
/// ```
///    use networking::database::HashDatabase;
///    use networking::ArtificePeer;
///    use networking::{random_string, test_config};
///
///    let key = random_string(16).into_bytes();
///    let (peer, _config) = test_config();
///    let mut database: HashDatabase<ArtificePeer> = HashDatabase::new("./test_db", key.clone()).unwrap();
///    database.insert(peer.global_peer_hash().to_string(), peer.clone()).unwrap();
///    let mut second_database: HashDatabase<ArtificePeer> = HashDatabase::new("./test_db", key).unwrap();
///    second_database.load(&peer.global_peer_hash().to_string()).unwrap();
///    let newpeer = second_database.get(&peer.global_peer_hash().to_string()).unwrap();
///    assert_eq!(*newpeer, peer);
/// ```
pub mod database;

pub mod syncronous;
use crate::encryption::PubKeyComp;
use crate::error::NetworkError;
/*use crate::{
    asyncronous::{AsyncStream, AsyncRecv, AsyncSend, StreamSend, StreamRecv, OwnedStreamRecv, OwnedStreamSend},
    syncronous::{SyncDataStream, SyncStream},
};
use futures::executor;
use std::mem::ManuallyDrop;*/

pub use peers::*;
pub mod utils;
//use async_trait::async_trait;
use rsa::{RSAPrivateKey, RSAPublicKey};
use std::error::Error;
use std::net::ToSocketAddrs;
use std::{
    net::{SocketAddr, UdpSocket},
    //ops::{Deref, DerefMut},
    sync::mpsc::{channel, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};
// this module will cotain the network layer implementation for SLLP, and PeerStream
//pub mod core;
pub use utils::*;
/// used to build and configure the local host
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtificeConfig {
    broadcast: bool,
    addr: Layer3SocketAddr,
    host: ArtificeHostData,
}
impl ArtificeConfig {
    pub fn new(addr: Layer3SocketAddr, host: ArtificeHostData, broadcast: bool) -> Self {
        Self {
            broadcast,
            addr,
            host,
        }
    }
    /// used to create new host, primarily designed for use by the installer crate
    pub fn generate(addr: Layer3SocketAddr) -> Self {
        let broadcast = false;
        let host = ArtificeHostData::default();
        Self {
            broadcast,
            addr,
            host,
        }
    }
    pub fn host_data(&self) -> &ArtificeHostData {
        &self.host
    }
    pub fn broadcast(&self) -> bool {
        self.broadcast
    }
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
    pub fn addr(&self) -> Layer3Addr {
        self.addr.ip()
    }
    pub fn socket_addr(&self) -> Layer3SocketAddr {
        self.addr
    }
    pub fn set_socket_addr(&mut self, addr: SocketAddr) {
        self.addr = addr.into();
    }
}

/// provides a means of saving private keys to files, because the process of generating the keys takes a really long time, but creating them from existing values does not
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtificeHostData {
    priv_key: PrivKeyComp,
    global_peer_hash: NetworkHash,
}
impl Default for ArtificeHostData {
    fn default() -> Self {
        let global_peer_hash = NetworkHash::generate();
        let priv_key = PrivKeyComp::generate().unwrap();
        Self {
            priv_key,
            global_peer_hash,
        }
    }
}
impl ArtificeHostData {
    pub fn new(private_key: &RSAPrivateKey, global_peer_hash: &NetworkHash) -> Self {
        let priv_key = PrivKeyComp::from(private_key);
        Self {
            priv_key,
            global_peer_hash: global_peer_hash.to_owned(),
        }
    }
    /// returns the n, e, d, and primes of an RSA key
    pub fn privkeycomp(&self) -> &PrivKeyComp {
        &self.priv_key
    }
    pub fn global_peer_hash(&self) -> &NetworkHash {
        &self.global_peer_hash
    }
}
/// contains peer information sent accross the network in an effort to prevent man in the middle attacks
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Header {
    peer: ArtificePeer,
    packet_len: usize,
    new_connection: bool,
    key: Vec<u8>,
}
impl Header {
    pub fn new(peer: &ArtificePeer, key: Vec<u8>) -> Self {
        Self {
            peer: peer.to_owned(),
            packet_len: 0,
            new_connection: false,
            key,
        }
    }
    pub fn new_pair(peer: &ArtificePeer, key: Vec<u8>) -> Self {
        Self {
            peer: peer.to_owned(),
            packet_len: 0,
            new_connection: true,
            key,
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
    pub fn set_pubkey(&mut self, pubkey: &PubKeyComp) {
        self.peer.set_pubkey(pubkey);
    }
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

impl From<&Header> for StreamHeader {
    fn from(header: &Header) -> Self {
        StreamHeader::with_key(
            header.peer().global_peer_hash(),
            header.peer().peer_hash(),
            header.key(),
            header.packet_len(),
        )
    }
}
impl From<Header> for StreamHeader {
    fn from(header: Header) -> Self {
        StreamHeader::from(&header)
    }
}
#[test]
fn header_to_raw_from_raw() {
    let stream_header = StreamHeader::new(&NetworkHash::generate(), &NetworkHash::generate(), 0);
    let raw = stream_header.to_raw();
    let new_header = StreamHeader::from_raw(&raw).unwrap();
    assert_eq!(stream_header, new_header);
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
/// implemented on both async and sync connection requests structs to define how to verify a peer
pub trait ConnectionRequest {
    type Error: Error;
    type NetStream;
    fn new(stream: Self::NetStream) -> Self;
    /// used to ensure only known peers are allow to connect
    fn verify<L: PeerList>(self, list: &L) -> Result<Self::NetStream, Self::Error>;
    /// # Safety
    /// this function allows unauthorized peers to connect to this device
    /// should only be used if a pair request is being run
    unsafe fn unverify(self) -> Self::NetStream;
}
/*#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamType {
    /// asyncronous stream
    Async,
    /// syncronous stream
    Sync,
}
/// exists both as a SyncStream, and an AsyncStream so functions from either can be used
#[derive(Debug)]
pub struct DataStream {
    stream: Stream,
}
#[async_trait]
impl AsyncSend for DataStream {
    type SendError = NetworkError;
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, Self::SendError> {
        unsafe {
            if self.stream.s_stream.1 {
                return Err(NetworkError::ExecFailed(Box::new("Not Async")));
            }
            self.stream.a_stream.deref_mut().0.send(outbuf).await
        }
    }
    fn remote_addr(&self) -> &SocketAddr {
        unsafe {
            if self.stream.s_stream.1 {
                return self.stream.s_stream.deref().0.remote_addr();
            }
            self.stream.a_stream.deref().0.remote_addr()
        }
    }
}
impl SyncDataStream for DataStream {
    type NetStream = TcpStream;
    type Error = NetworkError;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        Ok(Self { stream: Stream::from_sync(SyncStream::new(stream, header, remote_addr)? )})
    }
    fn header(&self) -> &StreamHeader {
        unsafe {
            if self.stream.s_stream.1 {
                return self.stream.s_stream.0.header()
            }
            self.stream.a_stream.0.header()
        }
    }
    fn remote_addr(&self) -> &SocketAddr {
        unsafe {
            if self.stream.s_stream.1 {
                return self.stream.s_stream.0.remote_addr()
            }
            self.stream.a_stream.0.remote_addr()
        }
    }
}
impl DataStream {
    pub fn connect(peer: &ArtificePeer, kind: StreamType) -> Result<Self, NetworkError> {
        Ok(Self {
            stream: Stream::connect(peer, kind)?,
        })
    }
    /// this function is only enabled for Async version of this type
    pub fn into_split(mut self) -> Result<(OwnedStreamSend, OwnedStreamRecv),NetworkError>{
        unsafe {
            if self.stream.s_stream.1 {
                return Err(NetworkError::ExecFailed(Box::new(self)));
            }
            Ok(ManuallyDrop::take(&mut self.stream.a_stream).0.into_split())
        }
    }
    /// this function is only enabled for Async version of this type
    pub fn split(&mut self) -> Result<(StreamSend, StreamRecv), NetworkError>{
        unsafe {
            if self.stream.s_stream.1 {
                return Err(NetworkError::ExecFailed(Box::new("Not Async")));
            }
            Ok(self.stream.a_stream.0.split())
        }
    }
}
union Stream {
    s_stream: ManuallyDrop<(SyncStream, bool)>,
    a_stream: ManuallyDrop<(AsyncStream, bool)>,
}
impl Stream {
    pub fn connect(peer: &ArtificePeer, kind: StreamType) -> Result<Self, NetworkError> {
        Ok(match kind {
            StreamType::Async => Self {
                a_stream: ManuallyDrop::new((
                    executor::block_on(AsyncStream::connect(&peer))?,
                    false,
                )),
            },
            StreamType::Sync => Self {
                s_stream: ManuallyDrop::new((SyncStream::connect(&peer)?, true)),
            },
        })
    }
    pub fn from_sync(s_stream: SyncStream) -> Self {
        Self {s_stream: ManuallyDrop::new((s_stream, true))}
    }
}
use std::fmt;
impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error>{
        let name = unsafe {
            match self.s_stream.1 {
                true => format!("{:?}", self.s_stream),
                false => format!("{:?}", self.a_stream),
            }
        };
        f.debug_struct("Stream").field("value", &name).finish()
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        unsafe {
            if self.s_stream.1 {
                ManuallyDrop::drop(&mut self.s_stream);
            } else if !self.a_stream.1 {
                ManuallyDrop::drop(&mut self.a_stream);
            }
        }
    }
}
#[test]
fn data_stream(){
    let (peer, _) = test_config();
    let stream = DataStream::connect(&peer, StreamType::Sync).unwrap();
    println!("{:?}", stream);
    assert_eq!(1,2);
}*/