#![feature(maybe_uninit_ref)]
#![feature(ip)]
#[macro_use]
extern crate serde_derive;
pub mod encryption;

pub mod utils;
pub use utils::*;
pub mod peers;
pub mod query;
pub use peers::*;

use crate::encryption::{PrivKeyComp, PubKeyPair, BigNum};
use std::net::SocketAddr;
use std::{
    net::{
        TcpListener, 
        TcpStream, 
        UdpSocket
    },
    sync::{
        mpsc::{channel, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
    io::Read,
};

use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyParts, PaddingScheme};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtificeConfig {
    broadcast: bool,
    address: Layer3Addr,
    port: u16,
    host: ArtificeHostData,
}
impl ArtificeConfig {
    pub fn generate(address: Layer3Addr) -> Self{
        let broadcast = false;
        let port = 6464;
        let host = ArtificeHostData::default();
        Self {broadcast, address, port, host}
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
    fn default() -> Self{
        let global_peer_hash = random_string(50);
        let priv_key = PrivKeyComp::generate().unwrap();
        Self{priv_key, global_peer_hash}
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    peer: ArtificePeer,
    pubkey: PubKeyPair,
}
impl Header{
    pub fn new(peer: ArtificePeer, pubkey: PubKeyPair) -> Self{
        Self {peer, pubkey}
    }
    pub fn peer(&self) -> &ArtificePeer{
        &self.peer
    }
    pub fn pubkey(&self) -> RSAPublicKey{
        RSAPublicKey::new(self.pubkey.n(), self.pubkey.e()).unwrap()
    }
}
#[derive(Debug, Clone)]
pub struct NetworkStream {
    header: Header,
    stream: Arc<Mutex<TcpStream>>,
    priv_key: RSAPrivateKey,
}
impl NetworkStream {
    pub fn new(stream: TcpStream, priv_key: RSAPrivateKey, peer: ArtificePeer) -> Self {
        let pubkey = RSAPublicKey::from(&priv_key);
        let header = Header::new(peer, PubKeyPair::from_parts(BigNum::from_biguint(pubkey.n().clone()), BigNum::from_biguint(pubkey.e().clone())));
        Self {
            header,
            stream: Arc::new(Mutex::new(stream)),
            priv_key,
        }
    }
    pub fn peer(&self) -> &ArtificePeer{
        self.header.peer()
    }
    pub fn pubkey(&self) -> RSAPublicKey{
        self.header.pubkey()
    }
}

pub struct ArtificeHost {
    priv_key: RSAPrivateKey,
    broadcast: bool,
    socket_addr: SocketAddr,
    listener: TcpListener,
}
impl std::iter::Iterator for ArtificeHost {
    type Item = std::io::Result<NetworkStream>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.listener.incoming().next() {
            Some(resstream) => match resstream {
                Ok(mut stream) => { 
                    let mut buffer = Vec::new();
                    match stream.read(&mut buffer) {
                        Ok(bytes) => bytes,
                        Err(e) => return Some(Err(e)),
                    };
                    let padding = PaddingScheme::new_pkcs1v15_encrypt();
                    let dec_data = match self.priv_key.decrypt(padding, &buffer){
                        Ok(data) => data,
                        Err(_e) => return Some(Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unauthorized connection"))),
                    };
                    let peer = serde_json::from_str(&String::from_utf8(dec_data).unwrap()).unwrap();
                    Some(Ok(NetworkStream::new(stream, self.priv_key.clone(), peer)))
                },
                Err(e) => Some(Err(e)),
            },
            None => None,
        }
    }
}
impl ArtificeHost {
    pub fn from_host_data(config: &ArtificeConfig) -> std::io::Result<Self> {
        let broadcast = config.broadcast();
        let data = config.host_data();
        let port = config.port();
        let address = config.address();
        let socket_addr = address.to_socket_addr(port);
        let priv_key_comp = data.private_key();
        let priv_key = RSAPrivateKey::from_components(
            priv_key_comp.n().into_inner(),
            priv_key_comp.e().into_inner(),
            priv_key_comp.d().into_inner(),
            priv_key_comp
                .primes()
                .into_iter()
                .map(|v| v.into_inner())
                .collect(),
        );
        let listener = TcpListener::bind(socket_addr)?;
        Ok(Self {
            priv_key,
            broadcast,
            socket_addr,
            listener,
        })
    }
    pub fn connect(&self, peer: ArtificePeer) -> std::io::Result<NetworkStream>{
        let stream = TcpStream::connect(self.socket_addr)?;
        Ok(NetworkStream::new(stream, self.priv_key.clone(), peer))
    }
    pub fn begin_broadcast(&self) -> std::io::Result<Sender<bool>> {
        let (sender, recv) = channel();
        let socket = UdpSocket::bind(self.socket_addr)?;
        socket.set_broadcast(true)?;
        if !self.broadcast {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "this host is not configured to broadcast",
            ));
        }
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
}
