// ===================================================================
//                                 Dependencies
// ===================================================================
use crate::async_query::AsyncQuery;
use crate::asyncronous::encryption::{
    asym_aes_decrypt as aes_decrypt, asym_aes_encrypt as aes_encrypt,
};
use crate::asyncronous::{AsyncRecv, AsyncSend, AsyncNetworkHost};
use crate::ArtificeConfig;
use crate::ConnectionRequest;
use crate::Layer3SocketAddr;
use crate::PubKeyComp;
use crate::Query;
use crate::{error::NetworkError, ArtificePeer, ArtificeStream, Header, StreamHeader};
use async_trait::async_trait;
use futures::{
    future::Future,
    task::{Context, Poll},
};
use rsa::RSAPrivateKey;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex, MutexGuard,
};
use tokio::{net::UdpSocket, stream::Stream};
// ==========================================================================
//                          Split type for Sllp Stream
// ==========================================================================
/// send half of SllpStream

#[derive(Debug)]
pub struct StreamRecv<'a> {
    header: &'a mut Header,
    priv_key: &'a RSAPrivateKey,
    receiver: &'a mut Receiver<IncomingMsg>,
}

impl<'a> StreamRecv<'a> {
    pub fn new(
        header: &'a mut Header,
        priv_key: &'a RSAPrivateKey,
        receiver: &'a mut Receiver<IncomingMsg>,
    ) -> Self {
        Self {
            header,
            priv_key,
            receiver,
        }
    }
}
#[async_trait]
impl<'a> AsyncRecv for StreamRecv<'a> {
    type Error = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let (data, data_len) = match self.receiver.recv().await {
            Some(result) => result,
            None => {
                return Err(NetworkError::IOError(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "channel closed",
                )))
            }
        };
        let (dec_data, header) = aes_decrypt(&self.priv_key, &data[0..data_len])?;
        if header != self.header.stream_header() {
            return Err(NetworkError::ConnectionDenied(
                "potential man in the middle attack".to_string(),
            ));
        }
        outbuf.extend_from_slice(&dec_data);
        Ok(data_len)
    }
}

/// send half of SllpStream
#[derive(Debug)]
pub struct StreamSend<'a> {
    header: StreamHeader,
    pubkey: &'a RSAPrivateKey,
    remote_addr: SocketAddr,
    sender: &'a mut Sender<OutgoingMsg>,
}
impl<'a> StreamSend<'a> {
    pub fn new(
        header: StreamHeader,
        pubkey: &'a RSAPrivateKey,
        remote_addr: SocketAddr,
        sender: &'a mut Sender<OutgoingMsg>,
    ) -> Self {
        Self {
            header,
            pubkey,
            remote_addr,
            sender,
        }
    }
}
#[async_trait]
impl<'a> AsyncSend for StreamSend<'a> {
    type Error = NetworkError;
    async fn send(&mut self, inbuf: &[u8]) -> Result<usize, NetworkError> {
        self.sender
            .send((
                aes_encrypt(&self.pubkey, self.header.clone(), inbuf)?,
                self.remote_addr,
            ))
            .await?;
        Ok(inbuf.len())
    }
}

/// this represents a UDP connection to a peer.
/// while that may seem oxymoronic, in practice, implementing a structure this way allows for a finer grain of
/// what data transfer methods are nessisary, as this crate implements high security, an increase in efficiency wouldn't rely on
/// lack of connection, instead, the connection is maintained, and the efficiency gain comes from the lack of packet ordering,
/// and extraneous network transmissions

// ==========================================================================
//                                 Sllp Stream
// ===========================================================================
#[derive(Debug)]
pub struct SllpStream {
    header: Header,
    priv_key: RSAPrivateKey,
    query: AsyncQuery<OutgoingMsg, IncomingMsg>,
    remote_addr: SocketAddr,
}
#[async_trait]
impl AsyncSend for SllpStream {
    type Error = NetworkError;
    async fn send(&mut self, inbuf: &[u8]) -> Result<usize, NetworkError> {
        self.query
            .send((
                aes_encrypt(&self.priv_key, self.header.stream_header(), inbuf)?,
                self.remote_addr,
            ))
            .await?;
        Ok(inbuf.len())
    }
}
#[async_trait]
impl AsyncRecv for SllpStream {
    type Error = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<usize, NetworkError> {
        let (data, data_len) = match self.query.recv().await {
            Some(result) => result,
            None => {
                return Err(NetworkError::IOError(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "channel closed",
                )))
            }
        };
        let (dec_data, header) = aes_decrypt(&self.priv_key, &data[0..data_len])?;
        if header != self.header {
            return Err(NetworkError::ConnectionDenied(
                "potential man in the middle attack".to_string(),
            ));
        }
        outbuf.extend_from_slice(&dec_data);
        Ok(data_len)
    }
}
impl SllpStream {
    pub fn split(&mut self) -> (StreamSend, StreamRecv) {
        let (sender, receiver) = self.query.ref_split();
        (
            StreamSend::new(
                self.header.stream_header(),
                &self.priv_key,
                self.remote_addr,
                sender,
            ),
            StreamRecv::new(&mut self.header, &self.priv_key, receiver),
        )
    }
}
impl ArtificeStream for SllpStream {
    type NetStream = AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>;
    type Error = NetworkError;
    fn new(
        query: AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>,
        priv_key: RSAPrivateKey,
        peer: &ArtificePeer,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error> {
        let header = Header::new(peer);
        Ok(Self {
            header,
            priv_key,
            query,
            remote_addr,
        })
    }
    fn peer(&self) -> &ArtificePeer {
        self.header.peer()
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
// ===================================================================================
//                             Convenience types
// ===================================================================================
/// messages sent from the socket to the main program use this format
pub type IncomingMsg = (Vec<u8>, usize);
/// messages sent from main to the socket use this format
pub type OutgoingMsg = (Vec<u8>, SocketAddr);

pub type NewConnection = (
    Vec<u8>,
    usize,
    SocketAddr,
    AsyncQuery<OutgoingMsg, IncomingMsg>,
);
/// a type alias, more or less for Arc<Mutex<HashMap<SocketAddr, Sender<IncomingMsg>>>>
#[derive(Debug, Clone)]
pub struct Streams {
    value: Arc<Mutex<HashMap<SocketAddr, Sender<IncomingMsg>>>>,
}
impl Streams {
    pub async fn lock(&self) -> MutexGuard<'_, HashMap<SocketAddr, Sender<IncomingMsg>>> {
        self.value.lock().await
    }
}
impl Default for Streams {
    fn default() -> Self {
        let value = Arc::new(Mutex::new(HashMap::new()));
        Self { value }
    }
}
// =================================================================
//               Split Types for SLLP Socket
// ==================================================================

/// incoming half of SllpSocket allows for listening for new connections but not opening new connections
#[derive(Debug)]
pub struct SllpIncoming<'a> {
    priv_key: &'a RSAPrivateKey,
    receiver: &'a mut Receiver<NewConnection>,
}
impl<'a> SllpIncoming<'a> {
    pub fn new(priv_key: &'a RSAPrivateKey, receiver: &'a mut Receiver<NewConnection>) -> Self {
        Self { priv_key, receiver }
    }
}
impl<'a> Stream for SllpIncoming<'a> {
    type Item = Result<ConnectionRequest<SllpStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let (data, data_len, addr, query) = match self.receiver.poll_recv(ctx) {
            Poll::Ready(data) => match data {
                Some(data) => data,
                None => return Poll::Ready(None),
            },
            Poll::Pending => return Poll::Pending,
        };
        let (_dec_data, header) = match aes_decrypt(&self.priv_key, &data[0..data_len]) {
            Ok(retval) => retval,
            Err(e) => return Poll::Ready(Some(Err(e))),
        };

        let peer = ArtificePeer::new(
            header.global_peer_hash(),
            header.peer_hash(),
            addr.into(),
            None,
        );

        Poll::Ready(Some(Ok(ConnectionRequest::new(
            match SllpStream::new(query, self.priv_key.clone(), &peer, addr) {
                Ok(stream) => stream,
                Err(e) => return Poll::Ready(Some(Err(e))),
            },
        ))))
    }
}
impl<'a> Future for SllpIncoming<'a> {
    type Output = Option<Result<ConnectionRequest<SllpStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        match self.poll_next(ctx) {
            Poll::Ready(val) => Poll::Ready(val),
            Poll::Pending => Poll::Pending,
        }
    }
}
/// owned outgoing half of SllpSocket
#[derive(Debug, Clone)]
pub struct OwnedSllpOutgoing {
    streams: Streams,
    priv_key: RSAPrivateKey,
    outgoing_sender: Sender<OutgoingMsg>,
}
/// outgoing half of SllpSocket allows for opening connections, but not listening for new ones
#[derive(Debug, Clone)]
pub struct SllpOutgoing<'a> {
    streams: &'a Streams,
    priv_key: &'a RSAPrivateKey,
    outgoing_sender: &'a Sender<OutgoingMsg>,
}
impl<'a> SllpOutgoing<'a> {
    /// could've been private, but functionality and transparency are important
    pub fn new(
        streams: &'a Streams,
        priv_key: &'a RSAPrivateKey,
        outgoing_sender: &'a Sender<OutgoingMsg>,
    ) -> Self {
        Self {
            streams,
            priv_key,
            outgoing_sender,
        }
    }
    /// same as SllpSocket, couldn't find an easy way of putting it in a trait
    pub async fn connect(&self, peer: &ArtificePeer) -> SllpStream {
        let (incoming_sender, incoming_receiver) = channel(1);
        let query = AsyncQuery::create(self.outgoing_sender.clone(), incoming_receiver);
        let stream = SllpStream::new(query, self.priv_key.clone(), &peer, peer.socket_addr());
        self.streams
            .lock()
            .await
            .insert(peer.socket_addr(), incoming_sender);
        stream.unwrap()
    }
}

// =====================================================================
//                          SLLP Socket
// =====================================================================
/// this structure provides an alternative to TCP Networking, but is not connectionless
/// while this structure uses an owned UdpSocket for networking, it also maintains a connection through the standard means that this crate provides
/// this is offered as a way to increase the efficiency of the network of TCP at the cost of a lack of garuntee of packet order
/// future implementations may implement a system of dropping out dated packets
#[derive(Debug)]
pub struct SllpSocket {
    priv_key: RSAPrivateKey,
    receiver: Receiver<NewConnection>,
    streams: Streams,
    outgoing_sender: Sender<OutgoingMsg>,
}
#[async_trait]
impl AsyncNetworkHost for SllpSocket {
    type Error = NetworkError;
    async fn from_host_config(config: &ArtificeConfig) -> Result<Self, NetworkError> {
        let data = config.host_data();
        let port = config.port();
        let address = config.address();
        let priv_key_comp = data.privkeycomp();
        let socket_addr: SocketAddr = Layer3SocketAddr::from((address, port)).into();
        let priv_key = RSAPrivateKey::from_components(
            priv_key_comp.n().into(),
            priv_key_comp.e().into(),
            priv_key_comp.d().into(),
            priv_key_comp.primes().iter().map(|v| v.into()).collect(),
        );
        let socket = UdpSocket::bind(socket_addr).await?;
        let (mut request_sender, request_receiver): (
            Sender<NewConnection>,
            Receiver<NewConnection>,
        ) = channel(200);
        let (outgoing_sender, mut outgoing_receiver): (
            Sender<OutgoingMsg>,
            Receiver<(Vec<u8>, SocketAddr)>,
        ) = channel(200);
        let senders: Streams = Streams::default();
        let (mut recv_half, mut send_half) = socket.split();
        // spawn incoming
        let streams = senders.clone();
        let out_sender = outgoing_sender.clone();
        tokio::spawn(async move {
            loop {
                let mut buffer: [u8; 65535] = [0; 65535];
                match recv_half.recv_from(&mut buffer).await {
                    Ok((data_len, addr)) => {
                        let mut senders = streams.lock().await;
                        match senders.get_mut(&addr) {
                            Some(sender) => {
                                sender
                                    .send((buffer[0..data_len].to_vec(), data_len))
                                    .await
                                    .unwrap();
                            }
                            None => {
                                // SllpSocket -> SllpStream Vec<u8> = data recv, usize = data length
                                let (incoming_sender, incoming_receiver): (
                                    Sender<IncomingMsg>,
                                    Receiver<(Vec<u8>, usize)>,
                                ) = channel(1);
                                // moved into the stream and pocesses a reciever to get incoming data, and a sender = outgoing_sender
                                // to send to the sending thread
                                let foward: AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)> =
                                    AsyncQuery::create(outgoing_sender.clone(), incoming_receiver);
                                // used to send new connection request to the impl of Stream
                                request_sender
                                    .send((buffer[0..data_len].to_vec(), data_len, addr, foward))
                                    .await
                                    .unwrap();
                                // store incoming sender
                                senders.insert(addr, incoming_sender);
                            }
                        }
                    }
                    Err(e) => panic!("error: {}", e),
                }
            }
        });
        // spawn outgoing
        tokio::spawn(async move {
            loop {
                let (out_data, remote_addr) = outgoing_receiver.recv().await.unwrap();
                send_half.send_to(&out_data, &remote_addr).await.unwrap();
            }
        });
        Ok(Self {
            priv_key,
            receiver: request_receiver,
            streams: senders,
            outgoing_sender: out_sender,
        })
    }
}
impl SllpSocket {
    pub async fn connect(&self, peer: &ArtificePeer) -> SllpStream {
        let (incoming_sender, incoming_receiver) = channel(1);
        let query = AsyncQuery::create(self.outgoing_sender.clone(), incoming_receiver);
        let stream = SllpStream::new(query, self.priv_key.clone(), &peer, peer.socket_addr());
        self.streams
            .lock()
            .await
            .insert(peer.socket_addr(), incoming_sender);
        stream.unwrap()
    }
    pub fn split(&mut self) -> (SllpOutgoing, SllpIncoming) {
        (
            SllpOutgoing::new(&self.streams, &self.priv_key, &self.outgoing_sender),
            SllpIncoming::new(&self.priv_key, &mut self.receiver),
        )
    }
    pub fn incoming(&mut self) -> &mut Self {
        self
    }
}
impl Stream for SllpSocket {
    type Item = Result<ConnectionRequest<SllpStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let (data, data_len, addr, query) = match self.receiver.poll_recv(ctx) {
            Poll::Ready(data) => match data {
                Some(data) => data,
                None => return Poll::Ready(None),
            },
            Poll::Pending => return Poll::Pending,
        };
        let (_dec_data, header) = match aes_decrypt(&self.priv_key, &data[0..data_len]) {
            Ok(retval) => retval,
            Err(e) => return Poll::Ready(Some(Err(e))),
        };

        let peer = ArtificePeer::new(
            header.global_peer_hash(),
            header.peer_hash(),
            addr.into(),
            None,
        );
        Poll::Ready(Some(Ok(ConnectionRequest::new(
            match SllpStream::new(query, self.priv_key.clone(), &peer, addr) {
                Ok(stream) => stream,
                Err(e) => return Poll::Ready(Some(Err(e))),
            },
        ))))
    }
}
impl Future for SllpSocket {
    type Output = Option<Result<ConnectionRequest<SllpStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        match self.poll_next(ctx) {
            Poll::Ready(val) => Poll::Ready(val),
            Poll::Pending => Poll::Pending,
        }
    }
}
