// ===================================================================
//                                 Dependencies
// ===================================================================
use crate::ArtificeConfig;
use crate::PubKeyComp;
use crate::{error::NetworkError, ArtificePeer, ArtificeStream, Header, StreamHeader};
use crate::{ArtificeHost, ConnectionRequest};
use async_trait::async_trait;
use std::error::Error;
use futures::{
    future::Future,
    task::{Context, Poll},
};
pub mod encryption;
use encryption::{asym_aes_decrypt as aes_decrypt, asym_aes_encrypt as aes_encrypt};
use rsa::{RSAPrivateKey, RSAPublicKey};

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::mpsc::Sender;
use tokio::io::AsyncRead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpListener, net::TcpStream, stream::Stream};

// ===============================================================================
//                                   Async Stream
// ================================================================================
/// networking implementation that uses TCP to send information over the network
#[derive(Debug)]
pub struct AsyncStream {
    header: Header,
    stream: TcpStream,
    priv_key: RSAPrivateKey,
    remote_addr: SocketAddr,
}
impl ArtificeStream for AsyncStream {
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
    fn addr(&self) -> IpAddr {
        self.remote_addr.ip()
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn set_pubkey(mut self, pubkey: PubKeyComp) -> Self {
        self.header.set_pubkey(pubkey);
        self
    }
}
// ====================================== ====================================================
//                                    Impl Async Stream
// =============================================================================================
#[async_trait]
impl AsyncRecv for AsyncStream {
    type Error = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let mut buffer: [u8; 65535] = [0; 65535];
        let mut buf = Vec::new();
        let mut data_len = self.stream.read(&mut buffer).await?;
        while data_len == 0 {
            data_len = self.stream.read(&mut buffer).await?;
        }
        let (dec_data, mut header) = aes_decrypt(&self.priv_key, &buffer[0..data_len])?;
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
            let mut temp_len = self.stream.read(&mut buffer).await?;
            while temp_len == 0 {
                temp_len = self.stream.read(&mut buffer).await?;
            }
            let (dec_buffer, stream_header) =
                aes_decrypt(&self.priv_key, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            buf.extend_from_slice(&dec_buffer);
        }
        outbuf.append(&mut buf);
        Ok(buf.len())
    }
}
#[async_trait]
impl AsyncSend for AsyncStream {
    type Error = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let key = match self.peer().pubkeycomp() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        let public_key = RSAPublicKey::new(key.n().into(), key.e().into())?;
        self.header.set_len(buffer.len());
        let stream_header = self.header.stream_header();
        let enc_data = aes_encrypt(&public_key, stream_header, &buffer)?;
        Ok(self.stream.write(&enc_data).await?)
    }
}
impl AsyncDataStream for AsyncStream {
    type Error = NetworkError;
}
// ===================================================================================
//                                 Async Host
// ====================================================================================
/// host object, artifice network implementation of TcpListener
#[derive(Debug)]
pub struct AsyncHost {
    priv_key: RSAPrivateKey,
    stop_broadcast: Option<Sender<bool>>,
    listener: Option<TcpListener>,
}
impl ArtificeHost for AsyncHost {
    fn stop_broadcasting(&self) {
        match &self.stop_broadcast {
            Some(sender) => sender.send(false).unwrap(),
            None => (),
        }
    }
}
impl AsyncHost {
    pub async fn from_host_config(config: &ArtificeConfig) -> Result<Self, NetworkError> {
        let data = config.host_data();
        let port = config.port();
        let address = config.address();
        let priv_key_comp = data.privkeycomp();
        let socket_addr = SocketAddr::from((address, port));
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
        let listener = Some(match TcpListener::bind(socket_addr).await {
            Ok(listener) => listener,
            Err(e) => return Err(NetworkError::IOError(e)),
        });
        Ok(Self {
            stop_broadcast,
            priv_key,
            listener,
        })
    }
    pub async fn client_only(config: &ArtificeConfig) -> Result<Self, NetworkError> {
        let data = config.host_data();
        let port = config.port();
        let address = config.address();
        let priv_key_comp = data.privkeycomp();
        let socket_addr = SocketAddr::from((address, port));
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
            stop_broadcast,
            priv_key,
            listener,
        })
    }
    pub async fn connect(&self, peer: ArtificePeer) -> Result<AsyncStream, NetworkError> {
        let mut stream = TcpStream::connect(peer.socket_addr()).await?;
        // encrypt the peer before sending
        let key = match peer.pubkeycomp() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        let public_key =
            RSAPublicKey::new(key.n().into(), key.e().into()).expect("couldn't create key");
        let data = serde_json::to_string(&peer)?.into_bytes();
        let stream_header = StreamHeader::new(peer.global_peer_hash(), peer.peer_hash(), 0);
        let enc_data = aes_encrypt(&public_key, stream_header, &data)?;
        stream.write(&enc_data).await?;
        let addr = peer.socket_addr();
        Ok(AsyncStream::new(
            stream,
            self.priv_key.clone(),
            &peer,
            addr,
        )?)
    }
    pub fn incoming(&mut self) -> Result<Incoming<'_>, NetworkError> {
        match &mut self.listener {
            Some(listener) => Ok(Incoming::new(listener, self.priv_key.clone())),
            None => Err(NetworkError::UnSet("client only".to_string())),
        }
    }
}
// ======================================================================================
//                                       Incoming
// ======================================================================================
pub struct Incoming<'a> {
    listener: &'a mut TcpListener,
    priv_key: RSAPrivateKey,
}
impl<'a> Incoming<'a> {
    pub fn new(listener: &'a mut TcpListener, priv_key: RSAPrivateKey) -> Incoming<'_> {
        Self { listener, priv_key }
    }
}
impl<'a> Stream for Incoming<'a> {
    type Item = Result<ConnectionRequest<AsyncStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(ctx) {
            Poll::Ready(stream) => {
                match stream {
                    Ok((mut strm, addr)) => {
                        let mut buffer: [u8; 65535] = [0; 65535];
                        let mut data_len = 0;
                        let mut bstream = Box::pin(&mut strm);
                        while data_len == 0 {
                            let stream = Pin::as_mut(&mut bstream);
                            data_len = match AsyncRead::poll_read(stream, ctx, &mut buffer) {
                                Poll::Ready(Ok(data_len)) => data_len,
                                Poll::Ready(Err(e)) => {
                                    return Poll::Ready(Some(Err(NetworkError::from(e))))
                                }
                                Poll::Pending => continue,
                            };
                        }
                        let (dec_data, _) = match aes_decrypt(&self.priv_key, &buffer[0..data_len])
                        {
                            Ok(data_len) => data_len,
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        };
                        let peer = match serde_json::from_str(&match String::from_utf8(dec_data) {
                            Ok(data_len) => data_len,
                            Err(e) => return Poll::Ready(Some(Err(NetworkError::from(e)))),
                        }) {
                            Ok(peer) => peer,
                            Err(e) => return Poll::Ready(Some(Err(NetworkError::from(e)))),
                        };
                        //Some(Ok(SyncStream::new(stream, self.priv_key.clone(), peer)))
                        Poll::Ready(Some(Ok(ConnectionRequest::new(
                            match AsyncStream::new(strm, self.priv_key.clone(), &peer, addr) {
                                Ok(stream) => stream,
                                Err(e) => return Poll::Ready(Some(Err(e))),
                            },
                        ))))
                    }
                    Err(e) => Poll::Ready(Some(Err(NetworkError::IOError(e)))),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl<'a> Future for Incoming<'a> {
    type Output = Option<Result<ConnectionRequest<AsyncStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        Stream::poll_next(self, ctx)
    }
}
#[async_trait]
pub trait AsyncSend {
    type Error: Error;
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, Self::Error>;
}
#[async_trait]
pub trait AsyncRecv {
    type Error: Error;
    async fn recv(&mut self, inbuf: &mut Vec<u8>) -> Result<usize, Self::Error>;
}
#[async_trait]
pub trait AsyncDataStream: AsyncSend + AsyncRecv {
    type Error: Error;
}
#[async_trait]
pub trait AsyncNetworkHost {}