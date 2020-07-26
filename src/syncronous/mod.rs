use crate::encryption::*;
use crate::peers::*;
pub mod encryption;
use crate::ArtificeHost;
use crate::{ArtificeConfig, ArtificeStream, ConnectionRequest, Header};
pub use encryption::*;
use rsa::{PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::net::SocketAddr;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc::Sender, Arc, Mutex},
};
/// the TcpStream version of the artifice network, implements encryption automatically in its implementation of std::io::Write, and std::io::Read
#[derive(Debug, Clone)]
pub struct SyncStream {
    header: Header,
    stream: Arc<Mutex<TcpStream>>,
    priv_key: RSAPrivateKey,
    remote_addr: SocketAddr,
}
impl ArtificeStream for SyncStream {
    type NetStream = TcpStream;
    fn new(
        stream: Self::NetStream,
        priv_key: RSAPrivateKey,
        peer: ArtificePeer,
        remote_addr: SocketAddr,
    ) -> Self {
        let pubkey = RSAPublicKey::from(&priv_key);
        let header = Header::new(
            peer,
            PubKeyComp::from_parts(
                BigNum::from_biguint(pubkey.n().clone()),
                BigNum::from_biguint(pubkey.e().clone()),
            ),
        );
        Self {
            header,
            stream: Arc::new(Mutex::new(stream)),
            priv_key,
            remote_addr,
        }
    }
    fn peer(&self) -> &ArtificePeer {
        self.header.peer()
    }
    fn pubkey(&self) -> RSAPublicKey {
        self.header.pubkey()
    }
    fn socket_addr(&self) -> SocketAddr {
        self.remote_addr
    }
    fn header(&self) -> Header {
        self.header.clone()
    }
}
impl SyncStream {
    /// implented in place of std::io::Read, because reading to empty vec fails
    pub fn recv(&mut self, outbuf: &mut Vec<u8>) -> std::io::Result<usize> {
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
        let header_str = match String::from_utf8(dec_data[2..header_len + 2].to_vec()) {
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
                "potential man in the middle attempt",
            ));
        }
        // add data not part of the header from the first packet to the greater vector
        if header.packet_len() + header_len < 65535 {
            buf.extend_from_slice(&dec_data[header_len + 2..header_len + header.packet_len() + 2]);
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
            buffer = [0; 65535];
            buf.extend_from_slice(&dec_buffer);
        }
        println!("buf len: {}", buf.len());
        let string = String::from_utf8(buf.clone()).unwrap();
        println!("got message: {} from server", string);
        outbuf.append(&mut buf);
        Ok(buf.len())
    }
    /// send data to the peer
    pub fn send(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("buf: {:?}", buf);
        let key = self.peer().pubkeycomp();
        let public_key = RSAPublicKey::new(key.n(), key.e()).unwrap();
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
/// host object, artifice network implementation of TcpListener
pub struct SyncHost {
    priv_key: RSAPrivateKey,
    listener: Option<TcpListener>,
    stop_broadcast: Option<Sender<bool>>,
}
impl std::iter::Iterator for SyncHost {
    type Item = std::io::Result<ConnectionRequest<SyncStream>>;
    fn next(&mut self) -> Option<Self::Item> {
        match &self.listener {
            Some(listener) => match listener.incoming().next() {
                Some(resstream) => match resstream {
                    Ok(mut stream) => {
                        let mut buffer: [u8; 65535] = [0; 65535];
                        let mut data_len = match stream.read(&mut buffer) {
                            Ok(bytes) => bytes,
                            Err(e) => return Some(Err(e)),
                        };
                        while data_len == 0 {
                            data_len = stream.read(&mut buffer).unwrap();
                        }
                        let dec_data = rsa_decrypt(&self.priv_key, &buffer[0..data_len], data_len)
                            .expect("decryption failed");
                        let addr = match stream.peer_addr() {
                            Ok(addr) => addr,
                            Err(e) => return Some(Err(e)),
                        };
                        let peer =
                            serde_json::from_str(&String::from_utf8(dec_data).unwrap()).unwrap();
                        Some(Ok(ConnectionRequest::new(SyncStream::new(
                            stream,
                            self.priv_key.clone(),
                            peer,
                            addr,
                        ))))
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
impl SyncHost {
    pub fn from_host_data(config: &ArtificeConfig) -> std::io::Result<Self> {
        let data = config.host_data();
        let port = config.port();
        let address = config.address();
        let priv_key_comp = data.private_key();
        let socket_addr = address.to_socket_addr(port);
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
        let stop_broadcast = if config.broadcast() {
            Some(Self::begin_broadcast(socket_addr)?)
        } else {
            None
        };
        let listener = Some(TcpListener::bind(socket_addr)?);
        Ok(Self {
            stop_broadcast,
            priv_key,
            listener,
        })
    }
    pub fn connect(&self, peer: ArtificePeer) -> std::io::Result<SyncStream> {
        let mut stream = TcpStream::connect(peer.socket_addr())?;
        // encrypt the peer before sending
        let key = peer.pubkeycomp();
        let public_key = RSAPublicKey::new(key.n(), key.e()).expect("couldn't create key");
        let data = serde_json::to_string(&peer).unwrap().into_bytes();
        let enc_data = rsa_encrypt(&public_key, &data).unwrap();
        stream.write_all(&enc_data)?;
        let addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => return Err(e),
        };
        Ok(SyncStream::new(stream, self.priv_key.clone(), peer, addr))
    }
    /// designed only for testing but may be used for non global peers
    pub fn client_only(config: &ArtificeConfig) -> std::io::Result<Self> {
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
        let stop_broadcast = if config.broadcast() {
            Some(Self::begin_broadcast(socket_addr)?)
        } else {
            None
        };
        let listener = None;
        Ok(Self {
            priv_key,
            stop_broadcast,
            listener,
        })
    }
}
impl ArtificeHost for SyncHost {
    fn stop_broadcasting(&self) {
        match &self.stop_broadcast {
            Some(sender) => sender.send(false).unwrap(),
            None => (),
        }
    }
}
