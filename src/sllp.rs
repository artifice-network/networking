// ===================================================================
//                                 Dependencies
// ===================================================================
use crate::async_query::{AsyncQuery};
use crate::Query;
use crate::asyncronous::encryption::{
    asym_aes_decrypt as aes_decrypt, asym_aes_encrypt as aes_encrypt,
};
use crate::ArtificeConfig;
use crate::{error::NetworkError, ArtificePeer, ArtificeStream, Header};
use crate::{ConnectionRequest};
use futures::{
    task::{Context, Poll},
};
use rsa::{RSAPrivateKey};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use tokio::sync::{mpsc::{channel, Receiver, Sender}, Mutex};
use std::sync::Arc;
use tokio::{net::UdpSocket, stream::Stream};
/// this represents a UDP connection to a peer.
/// while that may seem oxymoronic, in practice, implementing a structure this way allows for a finer grain of
/// what data transfer methods are nessisary, as this crate implements high security, an increase in efficiency wouldn't rely on
/// lack of connection, instead, the connection is maintained, and the efficiency gain comes from the lack of packet ordering,
/// and extraneous network transmissions
#[derive(Debug)]
pub struct SllpStream {
    header: Header,
    priv_key: RSAPrivateKey,
    query: AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>,
    remote_addr: SocketAddr,
}
impl SllpStream {
    pub async fn send(&mut self, inbuf: &[u8]) -> Result<(), NetworkError> {
        Ok(self
            .query
            .send((
                aes_encrypt(&self.priv_key, self.header.stream_header(), inbuf)?,
                self.remote_addr,
            ))
            .await?)
    }
    pub async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<(), NetworkError> {
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
        Ok(())
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
}
// ===================================================================================
//                             Async Socket Listener
// ===================================================================================
/// this structure provides an alternative to TCP Networking, but is not connectionless
/// while this structure uses an owned UdpSocket for networking, it also maintains a connection through the standard means that this crate provides
/// this is offered as a way to increase the efficiency of the network of TCP at the cost of a lack of garuntee of packet order
/// future implementations may implement a system of dropping out dated packets
#[derive(Debug)]
pub struct SllpSocket {
    priv_key: RSAPrivateKey,
    receiver: Receiver<(
        Vec<u8>,
        usize,
        SocketAddr,
        AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>,
    )>,
    streams: Arc<Mutex<HashMap<SocketAddr, Sender<(Vec<u8>, usize)>>>>,
    outgoing_sender: Sender<(Vec<u8>, SocketAddr)>,
}
impl SllpSocket {
    pub async fn from_host_data(config: &ArtificeConfig) -> Result<Self, NetworkError> {
        let data = config.host_data();
        let port = config.port();
        let address = config.address();
        let priv_key_comp = data.privkeycomp();
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
        let socket = UdpSocket::bind(socket_addr).await?;
        let (mut request_sender, request_receiver): (Sender<(
            Vec<u8>,
            usize,
            SocketAddr,
            AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>,
        )>, Receiver<(
            Vec<u8>,
            usize,
            SocketAddr,
            AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>,
        )>) = channel(200);
        let (outgoing_sender, mut outgoing_receiver): (
            Sender<(Vec<u8>, SocketAddr)>,
            Receiver<(Vec<u8>, SocketAddr)>,
        ) = channel(200);
        let senders: Arc<Mutex<HashMap<SocketAddr, Sender<(Vec<u8>, usize)>>>> = Arc::new(Mutex::new(HashMap::new()));
        let (mut recv_half, mut send_half) = socket.split();
        // spawn incoming
        let streams = senders.clone();
        let out_sender = outgoing_sender.clone();
        tokio::spawn(async move {
            loop {
                let mut buffer: [u8; 65535] = [0; 65535];
                match recv_half.recv_from(&mut buffer).await {
                    Ok((data_len, addr)) => match streams.lock().await.get_mut(&addr) {
                        Some(sender) => {
                            sender.send((buffer[0..data_len].to_vec(), data_len)).await.unwrap();
                        }
                        None => {
                            // SllpSocket -> SllpStream Vec<u8> = data recv, usize = data length
                            let (incoming_sender, incoming_receiver): (Sender<(Vec<u8>, usize)>, Receiver<(Vec<u8>, usize)>) = channel(1);
                            // moved into the stream and pocesses a reciever to get incoming data, and a sender = outgoing_sender
                            // to send to the sending thread
                            let foward: AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)> = AsyncQuery::create(outgoing_sender.clone(), incoming_receiver);
                            // used to send new connection request to the impl of Stream
                            request_sender.send((buffer[0..data_len].to_vec(), data_len, addr, foward)).await.unwrap();              
                            // store incoming sender
                            streams.lock().await.insert(addr, incoming_sender);
                        }
                    },
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
    pub async fn connect(&self, peer: &ArtificePeer) -> SllpStream{
        let (incoming_sender, incoming_receiver) = channel(1);
        let query = AsyncQuery::create(self.outgoing_sender.clone(), incoming_receiver);
        let stream = SllpStream::new(query, self.priv_key.clone(), &peer, peer.socket_addr());
        self.streams.lock().await.insert(peer.socket_addr(), incoming_sender);
        stream.unwrap()
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
        let (dec_data, _header) = match aes_decrypt(&self.priv_key, &data[0..data_len]) {
            Ok(retval) => retval,
            Err(e) => return Poll::Ready(Some(Err(e))),
        };

        let peer = match serde_json::from_str(&match String::from_utf8(dec_data) {
            Ok(data_len) => data_len,
            Err(e) => return Poll::Ready(Some(Err(NetworkError::from(e)))),
        }) {
            Ok(peer) => peer,
            Err(e) => return Poll::Ready(Some(Err(NetworkError::from(e)))),
        };

        Poll::Ready(Some(Ok(ConnectionRequest::new(
            match SllpStream::new(query, self.priv_key.clone(), &peer, addr) {
                Ok(stream) => stream,
                Err(e) => return Poll::Ready(Some(Err(e))),
            },
        ))))
    }
}
