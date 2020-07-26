use crate::encryption::{BigNum, PubKeyComp};
use crate::ArtificeConfig;
use crate::{error::NetworkError, ArtificePeer, ArtificeStream, Header, StreamHeader};
use crate::{ArtificeHost, ConnectionRequest};
use futures::{
    future::Future,
    task::{Context, Poll},
};
pub mod encryption;
use encryption::{aes_decrypt, aes_encrypt};
use rsa::{PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::mpsc::Sender;
use tokio::io::AsyncRead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpListener, net::TcpStream, stream::Stream};
/// stream object for writing and reading on the network
#[derive(Debug)]
pub struct AsyncStream {
    header: Header,
    stream: TcpStream,
    priv_key: RSAPrivateKey,
    remote_addr: SocketAddr,
}
impl ArtificeStream for AsyncStream {
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
            stream,
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
    fn addr(&self) -> IpAddr {
        self.remote_addr.ip()
    }
    fn header(&self) -> Header {
        self.header.clone()
    }
}
impl AsyncStream {
    pub async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
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
            let (dec_buffer, stream_header) = aes_decrypt(&self.priv_key, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            buf.extend_from_slice(&dec_buffer);
        }
        outbuf.append(&mut buf);
        Ok(buf.len())
    }
    /// send data to the peer
    pub async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let key = self.peer().pubkeycomp();
        let public_key = RSAPublicKey::new(key.n(), key.e())?;
        self.header.set_len(buffer.len());
        let stream_header = self.header.stream_header();
        let enc_data = aes_encrypt(&public_key, stream_header, &buffer)?;
        Ok(self.stream.write(&enc_data).await?)
    }
}

/// host object, artifice network implementation of TcpListener
#[derive(Debug)]
pub struct AsyncHost {
    priv_key: RSAPrivateKey,
    stop_broadcast: Option<Sender<bool>>,
    listener: Option<TcpListener>,
}
impl AsyncHost {
    pub async fn from_host_config(config: &ArtificeConfig) -> Result<Self, NetworkError> {
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
        let key = peer.pubkeycomp();
        let public_key = RSAPublicKey::new(key.n(), key.e()).expect("couldn't create key");
        let data = serde_json::to_string(&peer)?.into_bytes();
        let stream_header = StreamHeader::new(peer.global_peer_hash(), peer.peer_hash(), 0);
        let enc_data = aes_encrypt(&public_key, stream_header,&data)?;
        stream.write(&enc_data).await?;
        let addr = peer.socket_addr();
        Ok(AsyncStream::new(stream, self.priv_key.clone(), peer, addr))
    }
    pub fn incoming(&mut self) -> Result<Incoming<'_>, NetworkError> {
        match &mut self.listener {
            Some(listener) => Ok(Incoming::new(listener, self.priv_key.clone())),
            None => Err(NetworkError::UnSet("client only".to_string())),
        }
    }
}
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
                        let (dec_data, _) = match aes_decrypt(&self.priv_key, &buffer[0..data_len]) {
                            Ok(data_len) => data_len,
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        };
                        let peer = match serde_json::from_str(&match String::from_utf8(dec_data) {
                            Ok(data_len) => data_len,
                            Err(e) => return Poll::Ready(Some(Err(NetworkError::from(e)))),
                        }) {
                            Ok(data_len) => data_len,
                            Err(e) => return Poll::Ready(Some(Err(NetworkError::from(e)))),
                        };
                        //Some(Ok(SyncStream::new(stream, self.priv_key.clone(), peer)))
                        Poll::Ready(Some(Ok(ConnectionRequest::new(AsyncStream::new(
                            strm,
                            self.priv_key.clone(),
                            peer,
                            addr,
                        )))))
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
impl ArtificeHost for AsyncHost {
    fn stop_broadcasting(&self) {
        match &self.stop_broadcast {
            Some(sender) => sender.send(false).unwrap(),
            None => (),
        }
    }
}
