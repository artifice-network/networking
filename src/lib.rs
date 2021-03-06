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
//#![warn(missing_docs, rust_2018_idioms)]
#![feature(try_trait)]
#![feature(vec_into_raw_parts)]
#![allow(clippy::redundant_closure)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate err_derive;
/// contains blowfish encryption wrapper, as well as storage solution (serde) for BigUint principly BigNum
pub mod encryption;
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
/// use networking::L3Addr;
/// use std::error::Error;
/// use networking::asyncronous::{AsyncSend, AsyncNetworkHost};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn Error>> {
///     let (mut peer, config) = test_config();
///     let socket = SllpSocket::from_host_config(&config).await?;
///     // this needs to be updated to remote peer, because two devices cannot bind to the smae address
///     peer.set_socket_addr((L3Addr::newv4(127, 0, 0, 1), 6464).into());
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

#[cfg(feature = "unified")]
pub mod unified;

pub mod syncronous;

pub use peers::*;
pub mod utils;

pub mod net_core;
pub use net_core::*;

use rsa::RSAPrivateKey;
use std::error::Error;
use std::net::ToSocketAddrs;
use std::{
    net::{SocketAddr, UdpSocket},
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
    addr: L4Addr,
    host: ArtificeHostData,
}
impl ArtificeConfig {
    pub fn new(addr: L4Addr, host: ArtificeHostData, broadcast: bool) -> Self {
        Self {
            broadcast,
            addr,
            host,
        }
    }
    /// used to create new host, primarily designed for use by the installer crate
    pub fn generate(addr: L4Addr) -> Self {
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
    pub fn addr(&self) -> L3Addr {
        self.addr.ip()
    }
    pub fn socket_addr(&self) -> L4Addr {
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
#[test]
fn header_to_raw_from_raw() {
    let stream_header = StreamHeader::new(&NetworkHash::generate(), &NetworkHash::generate(), 0);
    let raw = stream_header.to_raw();
    let new_header = StreamHeader::from_raw(&raw).unwrap();
    assert_eq!(stream_header, new_header);
}

/// used to set discoverability on the local network
pub trait ArtificeHost {
    /// sets up a udp socket to broadcast the existence of a peer on the local network
    /// kind of stupid, but at the time I thought it was a good idea as an optional feature
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
    /// stop the udp socket from sending packets, by using the sender provided from the begin_broadcast method
    fn stop_broadcasting(&self);
}
/// implemented on both async and sync connection requests structs to define how to verify a peer
pub trait ConnectionRequest {
    type Error: Error;
    /// the data stream object that this trait operates on
    type NetStream;
    #[allow(missing_docs)]
    fn new(stream: Self::NetStream) -> Self;
    /// used to ensure only known peers are allow to connect
    fn verify<L: PeerList>(self, list: &L) -> Result<Self::NetStream, Self::Error>;
    /// # Safety
    /// this function allows unauthorized peers to connect to this device
    /// should only be used if a pair request is being run
    unsafe fn unverify(self) -> Self::NetStream;
}
/// used for getting custom identifier for objects
pub trait LongHash {
    /// select how to construct the hash
    fn hash(&self) -> &NetworkHash;
    /// get the indexes for a slice of T
    fn index<T: LongHash>(peers: &[T]) -> Vec<&NetworkHash> {
        let mut peer_vec = Vec::with_capacity(peers.len());
        for peer in peers {
            peer_vec.push(peer.hash());
        }
        peer_vec
    }
}
impl LongHash for ArtificePeer {
    fn hash(&self) -> &NetworkHash {
        self.global_peer_hash()
    }
}
