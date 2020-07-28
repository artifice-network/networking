use crate::error::NetworkError;
use crate::peers::*;
pub mod encryption;
use crate::ArtificeHost;
use crate::PubKeyComp;
use crate::{ArtificeConfig, ArtificeStream, ConnectionRequest, Header};
pub use encryption::*;
use rsa::{RSAPrivateKey, RSAPublicKey};
use std::net::SocketAddr;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc::Sender},
};
/// the TcpStream version of the artifice network, implements encryption automatically in its implementation of std::io::Write, and std::io::Read
#[derive(Debug)]
pub struct SyncStream {
    header: Header,
    stream: TcpStream,
    priv_key: RSAPrivateKey,
    remote_addr: SocketAddr,
}
impl ArtificeStream for SyncStream {
    type NetStream = TcpStream;
    type Error = NetworkError;
    fn new(
        stream: Self::NetStream,
        priv_key: RSAPrivateKey,
        peer: &ArtificePeer,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error> {
        let header = Header::new(peer);
        Ok(Self {
            header,
            stream,
            priv_key,
            remote_addr,
        })
    }
    fn peer(&self) -> &ArtificePeer {
        self.header.peer()
    }
    fn pubkey(&self) -> Result<RSAPublicKey, NetworkError> {
        self.header.pubkey()
    }
    fn socket_addr(&self) -> SocketAddr {
        self.remote_addr
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn set_pubkey(mut self, pubkey: PubKeyComp) -> Self {
        self.header.set_pubkey(pubkey);
        self
    }
}
impl SyncStream {
    /// implented in place of std::io::Read, because reading to empty vec fails
    pub fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let mut buffer: [u8; 65535] = [0; 65535];
        let mut buf = Vec::new();
        let mut data_len = self.stream.read(&mut buffer)?;
        while data_len == 0 {
            data_len = self.stream.read(&mut buffer)?;
        }
        let (dec_data, mut header) = asym_aes_decrypt(&self.priv_key, &buffer[0..data_len])?;
        if header != self.header {
            return Err(NetworkError::ConnectionDenied(
                "headers don't match".to_string(),
            ));
        }
        // add data not part of the header from the first packet to the greater vector
        if header.packet_len() < 65536 {
            buf.extend_from_slice(&dec_data[0..header.data_len()]);
        } else {
            buf.extend_from_slice(&dec_data[0..65535]);
        }
        //hadle further packetsheader_len +
        while data_len < header.packet_len() {
            let mut temp_len = self.stream.read(&mut buffer)?;
            while temp_len == 0 {
                temp_len = self.stream.read(&mut buffer)?;
            }
            let (dec_buffer, stream_header) =
                asym_aes_decrypt(&self.priv_key, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            buf.extend_from_slice(&dec_buffer);
        }
        outbuf.append(&mut buf);
        Ok(buf.len())
    }
    /// send data to the peer
    pub fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let key = match self.peer().pubkeycomp() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        let public_key = RSAPublicKey::new(key.n().into(), key.e().into())?;
        self.header.set_len(buffer.len());
        let stream_header = self.header.stream_header();
        let enc_data = asym_aes_encrypt(&public_key, stream_header, &buffer)?;
        Ok(self.stream.write(&enc_data)?)
    }
}
/// host object, artifice network implementation of TcpListener
pub struct SyncHost {
    priv_key: RSAPrivateKey,
    listener: Option<TcpListener>,
    stop_broadcast: Option<Sender<bool>>,
}
impl std::iter::Iterator for SyncHost {
    type Item = Result<ConnectionRequest<SyncStream>, NetworkError>;
    fn next(&mut self) -> Option<Self::Item> {
        match &self.listener {
            Some(listener) => match listener.incoming().next() {
                Some(resstream) => match resstream {
                    Ok(mut stream) => {
                        let mut buffer: [u8; 65535] = [0; 65535];
                        let mut data_len = match stream.read(&mut buffer) {
                            Ok(bytes) => bytes,
                            Err(e) => return Some(Err(NetworkError::from(e))),
                        };
                        while data_len == 0 {
                            data_len = stream.read(&mut buffer).unwrap();
                        }
                        let (dec_data, _header) = asym_aes_decrypt(&self.priv_key, &buffer[0..data_len])
                            .expect("decryption failed");
                        let addr = match stream.peer_addr() {
                            Ok(addr) => addr,
                            Err(e) => return Some(Err(e.into())),
                        };
                        let peer =
                            serde_json::from_str(&String::from_utf8(dec_data).unwrap()).unwrap();
                        Some(Ok(ConnectionRequest::new(
                            match SyncStream::new(stream, self.priv_key.clone(), &peer, addr) {
                                Ok(stream) => stream,
                                Err(e) => return Some(Err(e)),
                            },
                        )))
                    }
                    Err(e) => Some(Err(NetworkError::from(e))),
                },
                None => None,
            },
            None => Some(Err(NetworkError::UnSet(
                "this host is outgoing only".to_string(),
            ))),
        }
    }
}
impl SyncHost {
    pub fn from_host_data(config: &ArtificeConfig) -> std::io::Result<Self> {
        let data = config.host_data();
        let port = config.port();
        let addr = config.address();
        let priv_key_comp = data.privkeycomp();
        let socket_addr = Layer3SocketAddr::from((addr, port));
        let priv_key = RSAPrivateKey::from_components(
            priv_key_comp.n().into(),
            priv_key_comp.e().into(),
            priv_key_comp.d().into(),
            priv_key_comp.primes().iter().map(|v| v.into()).collect(),
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
    pub fn connect(&self, peer: ArtificePeer) -> Result<SyncStream, NetworkError> {
        let mut stream = TcpStream::connect(peer.socket_addr())?;
        // encrypt the peer before sending
        let key = match peer.pubkeycomp() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        let public_key =
            RSAPublicKey::new(key.n().into(), key.e().into()).expect("couldn't create key");
        let data = serde_json::to_string(&peer).unwrap().into_bytes();
        let enc_data = asym_aes_encrypt(&public_key, Header::new(&peer).into(), &data).unwrap();
        stream.write_all(&enc_data)?;
        let addr = stream.peer_addr()?;
        Ok(SyncStream::new(stream, self.priv_key.clone(), &peer, addr)?)
    }
    /// designed only for testing but may be used for non global peers
    pub fn client_only(config: &ArtificeConfig) -> std::io::Result<Self> {
        let data = config.host_data();
        let port = config.port();
        let addr = config.address();
        let socket_addr = Layer3SocketAddr::from((addr, port));
        let priv_key_comp = data.privkeycomp();
        let priv_key = RSAPrivateKey::from_components(
            priv_key_comp.n().into(),
            priv_key_comp.e().into(),
            priv_key_comp.d().into(),
            priv_key_comp.primes().iter().map(|v| v.into()).collect(),
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
