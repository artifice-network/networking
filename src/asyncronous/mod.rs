// ===================================================================
//                                 Dependencies
// ===================================================================
use crate::ArtificeConfig;
use crate::PeerList;
use crate::PubKeyComp;
use crate::{error::NetworkError, ArtificePeer, Header, StreamHeader};
use crate::{ArtificeHost, ConnectionRequest};
use async_trait::async_trait;
use futures::{
    future::Future,
    task::{Context, Poll},
};
use std::error::Error;
pub mod encryption;
use encryption::{asym_aes_decrypt as aes_decrypt, asym_aes_encrypt as aes_encrypt};
use rsa::{RSAPrivateKey, RSAPublicKey};

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::mpsc::Sender;
use tokio::io::AsyncRead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf, ReadHalf, WriteHalf},
    net::TcpListener,
    net::TcpStream,
    stream::Stream,
};

// ================================================================================
//                                   Async Stream
// ================================================================================
pub struct OwnedStreamSend {
    header: StreamHeader,
    writer: OwnedWriteHalf,
    pub_key: RSAPublicKey,
    remote_addr: SocketAddr,
}
impl OwnedStreamSend {
    pub fn new(
        header: StreamHeader,
        writer: OwnedWriteHalf,
        pub_key: RSAPublicKey,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            header,
            writer,
            pub_key,
            remote_addr,
        }
    }
}
#[async_trait]
impl AsyncSend for OwnedStreamSend {
    type SendError = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let enc_data = aes_encrypt(&self.pub_key, self.header.clone(), &buffer)?;
        Ok(self.writer.write(&enc_data).await?)
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}
pub struct StreamSend<'a> {
    header: StreamHeader,
    writer: WriteHalf<'a>,
    remote_addr: SocketAddr,
    pub_key: &'a RSAPrivateKey,
}
impl<'a> StreamSend<'a> {
    pub fn new(
        writer: WriteHalf<'a>,
        pub_key: &'a RSAPrivateKey,
        remote_addr: SocketAddr,
        header: StreamHeader,
    ) -> Self {
        Self {
            writer,
            remote_addr,
            header,
            pub_key,
        }
    }
}
#[async_trait]
impl<'a> AsyncSend for StreamSend<'a> {
    type SendError = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let enc_data = aes_encrypt(&self.pub_key, self.header.clone(), &buffer)?;
        Ok(self.writer.write(&enc_data).await?)
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}
pub struct OwnedStreamRecv {
    header: Header,
    reader: OwnedReadHalf,
    priv_key: RSAPrivateKey,
}
impl OwnedStreamRecv {
    pub fn new(header: Header, reader: OwnedReadHalf, priv_key: RSAPrivateKey) -> Self {
        Self {
            header,
            reader,
            priv_key,
        }
    }
}
#[async_trait]
impl AsyncRecv for OwnedStreamRecv {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let mut buffer: [u8; 65535] = [0; 65535];
        let mut data_len = self.reader.read(&mut buffer).await?;
        while data_len == 0 {
            data_len = self.reader.read(&mut buffer).await?;
        }
        let (dec_data, mut header) = aes_decrypt(&self.priv_key, &buffer[0..data_len])?;
        if header != self.header {
            return Err(NetworkError::ConnectionDenied(
                "headers don't match".to_string(),
            ));
        }
        // add data not part of the header from the first packet to the greater vector
        if header.packet_len() < 65536 {
            outbuf.extend_from_slice(&dec_data[0..header.data_len()]);
        } else {
            outbuf.extend_from_slice(&dec_data[0..65535]);
        }
        //hadle further packetsheader_len +
        while data_len < header.packet_len() {
            let temp_len = self.reader.read(&mut buffer).await?;
            let (dec_buffer, stream_header) =
                aes_decrypt(&self.priv_key, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            outbuf.extend_from_slice(&dec_buffer);
        }
        Ok(outbuf.len())
    }
    fn pubkey(&self) -> &Option<PubKeyComp> {
        self.header.pubkeycomp()
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn set_pubkey(&mut self, pubkey: &PubKeyComp) {
        self.header.set_pubkey(pubkey)
    }
}
pub struct StreamRecv<'a> {
    reader: ReadHalf<'a>,
    header: &'a mut Header,
    priv_key: &'a RSAPrivateKey,
}
impl<'a> StreamRecv<'a> {
    pub fn new(reader: ReadHalf<'a>, header: &'a mut Header, priv_key: &'a RSAPrivateKey) -> Self {
        Self {
            reader,
            header,
            priv_key,
        }
    }
}
#[async_trait]
impl<'a> AsyncRecv for StreamRecv<'a> {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let mut buffer: [u8; 65535] = [0; 65535];
        let mut data_len = self.reader.read(&mut buffer).await?;
        while data_len == 0 {
            data_len = self.reader.read(&mut buffer).await?;
        }
        let (dec_data, mut header) = aes_decrypt(&self.priv_key, &buffer[0..data_len])?;
        if header != *self.header {
            return Err(NetworkError::ConnectionDenied(
                "headers don't match".to_string(),
            ));
        }
        // add data not part of the header from the first packet to the greater vector
        if header.packet_len() < 65536 {
            outbuf.extend_from_slice(&dec_data[0..header.data_len()]);
        } else {
            outbuf.extend_from_slice(&dec_data[0..65535]);
        }
        //hadle further packetsheader_len +
        while data_len < header.packet_len() {
            let temp_len = self.reader.read(&mut buffer).await?;
            let (dec_buffer, stream_header) =
                aes_decrypt(&self.priv_key, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            outbuf.extend_from_slice(&dec_buffer);
        }
        Ok(outbuf.len())
    }
    fn pubkey(&self) -> &Option<PubKeyComp> {
        self.header.pubkeycomp()
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn set_pubkey(&mut self, pubkey: &PubKeyComp) {
        self.header.set_pubkey(pubkey)
    }
}

/// networking implementation that uses TCP to send information over the network
#[derive(Debug)]
pub struct AsyncStream {
    header: Header,
    stream: TcpStream,
    priv_key: RSAPrivateKey,
    remote_addr: SocketAddr,
}
impl AsyncStream{
    pub fn into_split(self) -> (OwnedStreamSend, OwnedStreamRecv) 
    {
        let (read_half, write_half) = self.stream.into_split();
        (
            OwnedStreamSend::new(
                self.header.stream_header(),
                write_half,
                RSAPublicKey::from(&self.priv_key),
                self.remote_addr,
            ),
            OwnedStreamRecv::new(self.header, read_half, self.priv_key),
        )
    }
    pub fn split(&mut self) -> (StreamSend, StreamRecv){
        let (reader, writer) = self.stream.split();
        (
            StreamSend::new( writer, &self.priv_key, self.remote_addr,self.header.stream_header()),
            StreamRecv::new(reader, &mut self.header, &self.priv_key)
        )
    }
}
impl AsyncDataStream for AsyncStream {
    type NetStream = TcpStream;
    type StreamError = NetworkError;
    fn new(
        stream: Self::NetStream,
        priv_key: RSAPrivateKey,
        peer: &ArtificePeer,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::StreamError> {
        let header = Header::new(peer);
        Ok(Self {
            header,
            stream,
            priv_key,
            remote_addr,
        })
    }
}
// ====================================== ====================================================
//                                    Impl Async Stream
// =============================================================================================
#[async_trait]
impl AsyncRecv for AsyncStream {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let mut buffer: [u8; 65535] = [0; 65535];
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
            outbuf.extend_from_slice(&dec_data[0..header.data_len()]);
        } else {
            outbuf.extend_from_slice(&dec_data[0..65535]);
        }
        //hadle further packetsheader_len +
        while data_len < header.packet_len() {
            let temp_len = self.stream.read(&mut buffer).await?;
            let (dec_buffer, stream_header) =
                aes_decrypt(&self.priv_key, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            outbuf.extend_from_slice(&dec_buffer);
        }
        Ok(outbuf.len())
    }
    fn pubkey(&self) -> &Option<PubKeyComp> {
        self.header.pubkeycomp()
    }
    fn header(&self) -> &Header {
        &self.header
    }
    fn set_pubkey(&mut self, pubkey: &PubKeyComp) {
        self.header.set_pubkey(pubkey)
    }
}
#[async_trait]
impl AsyncSend for AsyncStream {
    type SendError = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let key = match self.pubkey() {
            Some(pubkey) => pubkey,
            None => return Err(NetworkError::UnSet("public key not set".to_string())),
        };
        let public_key = RSAPublicKey::new(key.n().into(), key.e().into())?;
        let stream_header = self.header.stream_header();
        let enc_data = aes_encrypt(&public_key, stream_header, &buffer)?;
        Ok(self.stream.write(&enc_data).await?)
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
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
#[async_trait]
impl AsyncNetworkHost for AsyncHost {
    type Error = NetworkError;
    async fn from_host_config(config: &ArtificeConfig) -> Result<Self, NetworkError> {
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
}
impl AsyncHost {
    pub async fn client_only(config: &ArtificeConfig) -> Result<Self, NetworkError> {
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
            Some(listener) => Ok(Incoming::new(listener, &self.priv_key)),
            None => Err(NetworkError::UnSet("client only".to_string())),
        }
    }
}
impl Stream for AsyncHost {
    type Item = Result<AsyncRequest<AsyncStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        Incoming::poll_next(
            Pin::new(&mut match self.incoming() {
                Ok(incoming) => incoming,
                Err(e) => return Poll::Ready(Some(Err(e))),
            }),
            ctx,
        )
    }
}
// ======================================================================================
//                            split types for connections
// ======================================================================================
pub struct Outgoing<'a> {
    priv_key: &'a RSAPrivateKey,
}
impl<'a> Outgoing<'a> {
    pub fn new(priv_key: &'a RSAPrivateKey) -> Self {
        Self { priv_key }
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
}
pub struct Incoming<'a> {
    listener: &'a mut TcpListener,
    priv_key: &'a RSAPrivateKey,
}
impl<'a> Incoming<'a> {
    pub fn new(listener: &'a mut TcpListener, priv_key: &'a RSAPrivateKey) -> Incoming<'a> {
        Self { listener, priv_key }
    }
}
impl<'a> Stream for Incoming<'a> {
    type Item = Result<AsyncRequest<AsyncStream>, NetworkError>;
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
                        Poll::Ready(Some(Ok(AsyncRequest::new(
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
    type Output = Option<Result<AsyncRequest<AsyncStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        Stream::poll_next(self, ctx)
    }
}
#[async_trait]
pub trait AsyncSend {
    type SendError: Error;
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, Self::SendError>;
    fn remote_addr(&self) -> &SocketAddr;
}
#[async_trait]
pub trait AsyncRecv {
    type RecvError: Error;
    async fn recv(&mut self, inbuf: &mut Vec<u8>) -> Result<usize, Self::RecvError>;
    fn pubkey(&self) -> &Option<PubKeyComp>;
    fn header(&self) -> &Header;
    fn set_pubkey(&mut self, pubkey: &PubKeyComp);
}
/// currently only used as a marker, will implement more functionality in the future
#[async_trait]
pub trait AsyncDataStream: AsyncSend + AsyncRecv {
    type NetStream;
    type StreamError: Error;
    fn new(
        stream: Self::NetStream,
        priv_key: RSAPrivateKey,
        peer: &ArtificePeer,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::StreamError>
    where
        Self: std::marker::Sized;
    fn remote_port(&self) -> u16 {
        self.remote_addr().port()
    }
    fn remote_ip(&self) -> IpAddr {
        self.remote_addr().ip()
    }
    fn peer(&self) -> &ArtificePeer {
        self.header().peer()
    }
}
/// shared behavior between SllpSocket, and AsyncHost
#[async_trait]
pub trait AsyncNetworkHost: Stream {
    type Error: Error;
    async fn from_host_config(config: &ArtificeConfig) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
}
pub struct AsyncRequest<T: AsyncDataStream> {
    stream: T,
}

impl<T: AsyncDataStream> ConnectionRequest for AsyncRequest<T> {
    type Error = NetworkError;
    type NetStream = T;
    fn new(stream: Self::NetStream) -> Self {
        Self { stream }
    }
    fn verify<L: PeerList>(mut self, list: &L) -> Result<Self::NetStream, Self::Error> {
        if let Some(key) = list.verify_peer(&self.stream.peer()) {
            self.stream.set_pubkey(&key);
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
