use crate::encryption::{
    asym_aes_decrypt, asym_aes_encrypt, header_peak, sym_aes_decrypt, sym_aes_encrypt,
};
use crate::error::NetworkError;
use crate::peers::*;
use crate::protocol::StreamHeader;
use crate::random_string;
use crate::ArtificeHost;
use crate::PeerList;
use crate::{ArtificeConfig, ConnectionRequest, Header};
use rsa::{RSAPrivateKey, RSAPublicKey};
use std::net::{IpAddr, SocketAddr};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
/// the TcpStream version of the artifice network, implements encryption automatically in its implementation of std::io::Write, and std::io::Read
#[derive(Debug)]
pub struct SyncStream {
    header: StreamHeader,
    stream: TcpStream,
    remote_addr: SocketAddr,
}
impl SyncDataStream for SyncStream {
    type NetStream = TcpStream;
    type Error = NetworkError;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            header,
            stream,
            remote_addr,
        })
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
    fn header(&self) -> &StreamHeader {
        &self.header
    }
}
impl SyncStream {
    pub fn connect(peer: &ArtificePeer) -> Result<SyncStream, NetworkError> {
        let mut stream = TcpStream::connect(peer.socket_addr())?;
        // encrypt the peer before sending
        let key = match peer.pubkeycomp() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        let public_key =
            RSAPublicKey::new(key.n().into(), key.e().into()).expect("couldn't create key");
        let data = serde_json::to_string(&peer).unwrap().into_bytes();
        let aes_key = random_string(16).into_bytes();
        let header: StreamHeader = Header::new(&peer, aes_key).into();
        let enc_data = asym_aes_encrypt(&public_key, header.clone(), &data).unwrap();
        stream.write_all(&enc_data)?;
        let addr = stream.peer_addr()?;
        Ok(SyncStream::new(stream, header, addr)?)
    }
    /// implented in place of std::io::Read, because reading to empty vec fails
    pub fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let mut buffer: [u8; 65535] = [0; 65535];
        let mut buf = Vec::new();
        let mut data_len = self.stream.read(&mut buffer)?;
        let first_header = header_peak(self.header.key(), &buffer[0..data_len])?;
        let packet_len = first_header.packet_len();
        while data_len < packet_len {
            data_len += self.stream.read(&mut buffer[data_len..65535])?;
        }
        let (dec_data, mut header, _indexes) = sym_aes_decrypt(&self.header, &buffer[0..data_len])?;
        if header.peer_hash() != self.header.peer_hash() {
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
            let (dec_buffer, stream_header, _indexes) =
                sym_aes_decrypt(&self.header, &buffer[data_len..data_len + temp_len])?;
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
        let enc_data = sym_aes_encrypt(&self.header, &buffer);
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
    type Item = Result<SyncRequest<SyncStream>, NetworkError>;
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
                        let (_dec_data, header) =
                            asym_aes_decrypt(&self.priv_key, &buffer[0..data_len])
                                .expect("decryption failed");
                        let addr = match stream.peer_addr() {
                            Ok(addr) => addr,
                            Err(e) => return Some(Err(e.into())),
                        };
                        Some(Ok(SyncRequest::new(
                            match SyncStream::new(stream, header, addr) {
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
        let priv_key_comp = data.privkeycomp();
        let socket_addr: SocketAddr = config.socket_addr().into();
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
        let aes_key = random_string(16).into_bytes();
        let header: StreamHeader = Header::new(&peer, aes_key).into();
        let enc_data = asym_aes_encrypt(&public_key, header.clone(), &data).unwrap();
        stream.write_all(&enc_data)?;
        let addr = stream.peer_addr()?;
        Ok(SyncStream::new(stream, header, addr)?)
    }
    /// designed only for testing but may be used for non global peers
    pub fn client_only(config: &ArtificeConfig) -> std::io::Result<Self> {
        let data = config.host_data();
        let socket_addr: SocketAddr = config.socket_addr().into();
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
pub trait SyncDataStream {
    type NetStream;
    type Error: std::error::Error;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
    fn addr(&self) -> IpAddr {
        self.remote_addr().ip()
    }
    fn remote_addr(&self) -> &SocketAddr;
    fn header(&self) -> &StreamHeader;
}
pub struct SyncRequest<T: SyncDataStream> {
    stream: T,
}
impl<T: SyncDataStream> ConnectionRequest for SyncRequest<T> {
    type Error = NetworkError;
    type NetStream = T;
    fn new(stream: Self::NetStream) -> Self {
        Self { stream }
    }
    fn verify<L: PeerList>(self, list: &L) -> Result<Self::NetStream, NetworkError> {
        let peer = ArtificePeer::new(
            self.stream.header().global_peer_hash(),
            self.stream.header().peer_hash(),
            self.stream.remote_addr().into(),
            None,
        );
        if list.verify_peer(&peer) {
            Ok(self.stream)
        } else {
            Err(NetworkError::ConnectionDenied(
                "verification of peer failed".to_string(),
            ))
        }
    }
    unsafe fn unverify(self) -> Self::NetStream {
        self.stream
    }
}
