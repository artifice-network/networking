/*!

# Client

```
use networking::{random_string, ArtificeConfig, ArtificeHost, ArtificePeer, Layer3Addr};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
fn main() {
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = Vec::new();
    file.read_to_end(&mut invec).unwrap();
    let string = String::from_utf8(invec).unwrap();
    let peer: ArtificePeer = serde_json::from_str(&string).unwrap();
    let host = ArtificeHost::client_only(&config);
    let mut stream = host.connect(peer).unwrap();
    let mut buffer = Vec::new();
    stream.read(&mut buffer).unwrap();
    stream.write(&buffer).unwrap();
}
```

# Listen
```
use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
use std::fs::File;
use std::io::Read;
fn main() {
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let host = ArtificeHost::from_host_data(&config).unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = String::new();
    file.read_to_string(&mut invec).unwrap();
    let peer: ArtificePeer = serde_json::from_str(&invec).unwrap();
    for netstream in host {
        let stream = netstream.unwrap();
        // do something with the stream example:
        if *stream.peer() == peer {
            // correct peer
        }
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
pub use encryption::*;
/// contains the ArtificePeer struct
pub mod peers;
/// used for permission requests in the manager crate
pub mod query;
use crate::encryption::{BigNum, PrivKeyComp, PubKeyPair};
pub use peers::*;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{
        mpsc::{channel, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
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
/// the TcpStream version of the artifice network, implements encryption automatically in its implementation of std::io::Write, and std::io::Read
#[derive(Debug, Clone)]
pub struct NetworkStream {
    header: Header,
    stream: Arc<Mutex<TcpStream>>,
    priv_key: RSAPrivateKey,
}
impl NetworkStream {
    pub fn new(stream: TcpStream, priv_key: RSAPrivateKey, peer: ArtificePeer) -> Self {
        let pubkey = RSAPublicKey::from(&priv_key);
        let header = Header::new(
            peer,
            PubKeyPair::from_parts(
                BigNum::from_biguint(pubkey.n().clone()),
                BigNum::from_biguint(pubkey.e().clone()),
            ),
        );
        Self {
            header,
            stream: Arc::new(Mutex::new(stream)),
            priv_key,
        }
    }
    pub fn peer(&self) -> &ArtificePeer {
        self.header.peer()
    }
    pub fn pubkey(&self) -> RSAPublicKey {
        self.header.pubkey()
    }
    pub fn recv(&mut self, mut outbuf: &mut Vec<u8>) -> std::io::Result<usize> {
        let mut buffer: [u8; 65535] = [0; 65535];
        let mut stream = self.stream.lock().unwrap();
        let mut buf = Vec::new();
        let mut data_len = stream.read(&mut buffer)?;
        while data_len == 0 {
            data_len = stream.read(&mut buffer)?;
        }
        let dec_data = match rsa_decrypt(&self.priv_key, &buffer, data_len) {
            Ok(dec_data) => dec_data,
            Err(_e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "decryption failure",
                ));
            }
        };
        let header_len = u16::from_be_bytes([dec_data[0], dec_data[1]]) as usize;
        let header_str = match String::from_utf8(dec_data[2..header_len+2].to_vec()) {
        Ok(header_str) => header_str,
        Err(_e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "couldn't read input as string",
            ))
        }
    };
    //Ok((serde_json::from_str(&header_str).expect("couldn't deserialize header"), header_len))
        let header: Header = serde_json::from_str(&header_str).expect("coun't deserialize header");
        // verify that a man in the middle attack hasn't occured
        // let (header, header_len) = get_headers(&self.priv_key, &dec_data, data_len)?;
        if header != self.header {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "headers are different",
            ));
        }
        // add data not part of the header from the first packet to the greater vector
        if header.packet_len()+header_len < 65535 {
            buf.extend_from_slice(&dec_data[header_len+2..header_len+header.packet_len()+2]);
        } else {
            buf.extend_from_slice(&dec_data[header_len..65535]);
        }
        //hadle further packets
        while data_len < header.packet_len() + header_len as usize {
            let mut temp_len = stream.read(&mut buffer)?;
            while temp_len == 0 {
                temp_len = stream.read(&mut buffer)?;
            }
            data_len += temp_len;
            let dec_buffer = match rsa_decrypt(&self.priv_key, &buffer, temp_len) {
                Ok(dec_buffer) => dec_buffer,
                Err(_e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "unable to decrypt data",
                    ));
                }
            };
            let buffer = [0; 65535];
            buf.extend_from_slice(&dec_buffer);
        }
        println!("buf len: {}", buf.len());
        let string = String::from_utf8(buf.clone()).unwrap();
        println!("got message: {} from server", string);
        outbuf.append(&mut buf);
        Ok(buf.len())
    }
    pub fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("buf: {:?}", buf);
        let key = self.peer().pubkeypair();
        let public_key = RSAPublicKey::new(key.n(), key.e()).unwrap();
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut buffer = Vec::new();
        self.header.set_len(buf.len());
        let bytes = serde_json::to_string(&self.header).unwrap().into_bytes();
        let header_len: [u8; 2] = (bytes.len() as u16).to_be_bytes();
        buffer.push(header_len[0]);
        buffer.push(header_len[1]);
        buffer.extend_from_slice(bytes.as_slice());
        buffer.extend_from_slice(buf);
        let enc_data = rsa_encrypt(&public_key, &buffer).expect("failed to encrypt");
        let mut stream = self.stream.lock().unwrap();
        stream.write(&enc_data)
    }
}
fn get_headers(priv_key: &RSAPrivateKey, dec_data: &[u8], data_len: usize) -> std::io::Result<(Header, usize)> {
    let header_len = u16::from_be_bytes([dec_data[0], dec_data[1]]) as usize;
    let header_str = match String::from_utf8(dec_data[2..header_len+2].to_vec()) {
        Ok(header_str) => header_str,
        Err(_e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "couldn't read input as string",
            ))
        }
    };
    Ok((serde_json::from_str(&header_str).expect("couldn't deserialize header"), header_len))
    /*match serde_json::from_str(&header_str) {
        Ok(header) => Ok((header, header_len)),
        Err(_e) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "couldn't parse header",
        )),
    }*/
}
/// the in execution host struct built from AritificeConfig
pub struct ArtificeHost {
    priv_key: RSAPrivateKey,
    broadcast: bool,
    socket_addr: SocketAddr,
    listener: Option<TcpListener>,
}
impl std::iter::Iterator for ArtificeHost {
    type Item = std::io::Result<NetworkStream>;
    fn next(&mut self) -> Option<Self::Item> {
        match &self.listener {
            Some(listener) => match listener.incoming().next() {
                Some(resstream) => match resstream {
                    Ok(mut stream) => {
                        let mut buffer: [u8; 65535] = [0; 65535];
                        let data_len = match stream.read(&mut buffer) {
                            Ok(bytes) => bytes,
                            Err(e) => return Some(Err(e)),
                        };
                        while data_len == 0 {
                            let data_len = stream.read(&mut buffer).unwrap();
                        }
                        let padding = PaddingScheme::new_pkcs1v15_encrypt();
                        let dec_data = rsa_decrypt(&self.priv_key, &buffer[0..data_len], data_len)
                            .expect("decryption failed"); /* {
                                                              Ok(data) => data,
                                                              Err(_e) => {
                                                                  return Some(Err(std::io::Error::new(
                                                                      std::io::ErrorKind::PermissionDenied,
                                                                      "unauthorized connection",
                                                                  )))
                                                              }
                                                          };*/
                        let peer =
                            serde_json::from_str(&String::from_utf8(dec_data).unwrap()).unwrap();
                        Some(Ok(NetworkStream::new(stream, self.priv_key.clone(), peer)))
                    }
                    Err(e) => Some(Err(e)),
                },
                None => None,
            },
            None => Some(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "this host is peer only",
            ))),
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
        let listener = Some(TcpListener::bind(socket_addr)?);
        Ok(Self {
            priv_key,
            broadcast,
            socket_addr,
            listener,
        })
    }
    pub fn connect(&self, peer: ArtificePeer) -> std::io::Result<NetworkStream> {
        let mut stream = TcpStream::connect(peer.socket_addr())?;
        // encrypt the peer before sending
        let key = peer.pubkeypair();
        let public_key = RSAPublicKey::new(key.n(), key.e()).expect("couldn't create key");
        let data = serde_json::to_string(&peer).unwrap().into_bytes();
        let enc_data = rsa_encrypt(&public_key, &data).unwrap();
        stream.write(&enc_data)?;
        Ok(NetworkStream::new(stream, self.priv_key.clone(), peer))
    }
    /// designed only for testing but may be used for non global peers
    pub fn client_only(config: &ArtificeConfig) -> Self {
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
        let listener = None;
        Self {
            priv_key,
            broadcast,
            socket_addr,
            listener,
        }
    }
    /// broadcast the information about this peer to other peers on the network
    /// returns a sender that can be used to stop broadcasting
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
