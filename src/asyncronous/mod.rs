// ===================================================================
//                                 Dependencies
// ===================================================================
use crate::ArtificeConfig;
use crate::PeerList;
use crate::{error::NetworkError, ArtificePeer, StreamHeader};
use crate::{ArtificeHost, ConnectionRequest};
use async_trait::async_trait;
use futures::{
    future::Future,
    task::{Context, Poll},
};
use std::error::Error;
pub mod encryption;
use encryption::{
    asym_aes_decrypt as aes_decrypt, asym_aes_encrypt as aes_encrypt, sym_aes_decrypt,
    sym_aes_encrypt, header_peak,
};
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

async fn recv_data<S: AsyncRead + std::marker::Unpin>(header: &StreamHeader, stream: &mut S, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError>{
    let mut buffer: [u8; 65535] = [0; 65535];
        let mut data_len = stream.read(&mut buffer).await?;
        let first_header = header_peak(header.key(), &buffer[0..data_len])?;
        let packet_len = first_header.packet_len();
        while data_len < packet_len {
            data_len += stream.read(&mut buffer[data_len..65535]).await?;
        }
        println!("data_len: {}", data_len);
        let (dec_data, mut header, indexes) = sym_aes_decrypt(&header, &buffer[0..data_len])?;
        if header.peer_hash() != header.peer_hash() {
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
            let temp_len = stream.read(&mut buffer).await?;
            let (dec_buffer, stream_header, _indexes) =
                sym_aes_decrypt(&header, &buffer[data_len..data_len + temp_len])?;
            header = stream_header;
            data_len += temp_len;
            buffer = [0; 65535];
            outbuf.extend_from_slice(&dec_buffer);
        }
        Ok(indexes)
}

// ================================================================================
//                                   Async Stream
// ================================================================================
/// owned version of StreamSend
pub struct OwnedStreamSend {
    header: StreamHeader,
    writer: OwnedWriteHalf,
    remote_addr: SocketAddr,
}
impl OwnedStreamSend {
    pub fn new(header: StreamHeader, writer: OwnedWriteHalf, remote_addr: SocketAddr) -> Self {
        Self {
            header,
            writer,
            remote_addr,
        }
    }
}
#[async_trait]
impl AsyncSend for OwnedStreamSend {
    type SendError = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let enc_data = sym_aes_encrypt(&self.header, &buffer);
        Ok(self.writer.write(&enc_data).await?)
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}
/// borrowed half of an async stream that can be used for sending data
pub struct StreamSend<'a> {
    header: &'a StreamHeader,
    writer: WriteHalf<'a>,
    remote_addr: SocketAddr,
}
impl<'a> StreamSend<'a> {
    pub fn new(writer: WriteHalf<'a>, remote_addr: SocketAddr, header: &'a StreamHeader) -> Self {
        Self {
            writer,
            remote_addr,
            header,
        }
    }
}
#[async_trait]
impl<'a> AsyncSend for StreamSend<'a> {
    type SendError = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let enc_data = sym_aes_encrypt(&self.header, &buffer);
        Ok(self.writer.write(&enc_data).await?)
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}
/// owned version of StreamRecv
pub struct OwnedStreamRecv {
    header: StreamHeader,
    reader: OwnedReadHalf,
}
impl OwnedStreamRecv {
    pub fn new(header: StreamHeader, reader: OwnedReadHalf) -> Self {
        Self { header, reader }
    }
}
#[async_trait]
impl AsyncRecv for OwnedStreamRecv {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError> {
        recv_data(&self.header, &mut self.reader, outbuf).await
    }
    fn header(&self) -> &StreamHeader {
        &self.header
    }
}
/// borrowed half of async stream used for receiving data
pub struct StreamRecv<'a> {
    reader: ReadHalf<'a>,
    header: &'a StreamHeader,
}
impl<'a> StreamRecv<'a> {
    pub fn new(reader: ReadHalf<'a>, header: &'a StreamHeader) -> Self {
        Self { reader, header }
    }
}
#[async_trait]
impl<'a> AsyncRecv for StreamRecv<'a> {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError> {
        recv_data(&self.header, &mut self.reader, outbuf).await
    }
    fn header(&self) -> &StreamHeader {
        &self.header
    }
}

/// networking implementation that uses TCP to send information over the network
#[derive(Debug)]
pub struct AsyncStream {
    header: StreamHeader,
    stream: TcpStream,
    remote_addr: SocketAddr,
}
impl AsyncStream {
    pub fn into_split(self) -> (OwnedStreamSend, OwnedStreamRecv) {
        let (read_half, write_half) = self.stream.into_split();
        (
            OwnedStreamSend::new(self.header.clone(), write_half, self.remote_addr),
            OwnedStreamRecv::new(self.header, read_half),
        )
    }
    pub fn split(&mut self) -> (StreamSend, StreamRecv) {
        let (reader, writer) = self.stream.split();
        (
            StreamSend::new(writer, self.remote_addr, &self.header),
            StreamRecv::new(reader, &self.header),
        )
    }
}
impl AsyncDataStream for AsyncStream {
    type NetStream = TcpStream;
    type StreamError = NetworkError;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::StreamError> {
        Ok(Self {
            header,
            stream,
            remote_addr,
        })
    }
}
// =============================================================================================
//                                    Impl Async Stream
// =============================================================================================
#[async_trait]
impl AsyncRecv for AsyncStream {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError> {
        recv_data(&self.header, &mut self.stream, outbuf).await
    }
    fn header(&self) -> &StreamHeader {
        &self.header
    }
}
#[async_trait]
impl AsyncSend for AsyncStream {
    type SendError = NetworkError;
    /// send data to the peer
    async fn send(&mut self, buffer: &[u8]) -> Result<usize, NetworkError> {
        let enc_data = sym_aes_encrypt(&self.header, &buffer);
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
        let priv_key = priv_key_comp.into();
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
        let priv_key = priv_key_comp.into();
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
        let enc_data = aes_encrypt(&public_key, stream_header.clone(), &data)?;
        stream.write(&enc_data).await?;
        let addr = peer.socket_addr();
        Ok(AsyncStream::new(stream, stream_header, addr)?)
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
/// used for constructing an outgoing tcp connection
/// an owned implementation doesn't exist, because it would be unneeded code
pub struct Outgoing {}

impl Default for Outgoing {
    fn default() -> Self {
        Self {}
    }
}
impl Outgoing {
    pub fn new() -> Self {
        Self::default()
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
        let enc_data = aes_encrypt(&public_key, stream_header.clone(), &data)?;
        stream.write(&enc_data).await?;
        let addr = peer.socket_addr();
        Ok(AsyncStream::new(stream, stream_header, addr)?)
    }
}
/// used to listen for incoming connections
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
                        let (_dec_data, header) =
                            match aes_decrypt(&self.priv_key, &buffer[0..data_len]) {
                                Ok(data_len) => data_len,
                                Err(e) => return Poll::Ready(Some(Err(e))),
                            };
                        //Some(Ok(SyncStream::new(stream, self.priv_key.clone(), peer)))
                        Poll::Ready(Some(Ok(AsyncRequest::new(
                            match AsyncStream::new(strm, header, addr) {
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
/// trait for sending data over the network
#[async_trait]
pub trait AsyncSend {
    type SendError: Error;
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, Self::SendError>;
    fn remote_addr(&self) -> &SocketAddr;
}
/// trait for receiving network data
#[async_trait]
pub trait AsyncRecv {
    type RecvError: Error;
    async fn recv(&mut self, inbuf: &mut Vec<u8>) -> Result<Vec<usize>, Self::RecvError>;
    fn header(&self) -> &StreamHeader;
}
/// currently only used as a marker, will implement more functionality in the future
#[async_trait]
pub trait AsyncDataStream: AsyncSend + AsyncRecv {
    type NetStream;
    type StreamError: Error;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
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
    fn verify<L: PeerList>(self, list: &L) -> Result<Self::NetStream, Self::Error> {
        let peer = ArtificePeer::new(
            self.stream.header().global_peer_hash(),
            self.stream.header().peer_hash(),
            self.stream.remote_addr().into(),
            None,
        );
        if list.verify_peer(&peer).is_some() {
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
