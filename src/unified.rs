use crate::{
    asyncronous::{
        AsyncDataStream, AsyncRecv, AsyncSend, AsyncStream, OwnedStreamRecv, OwnedStreamSend,
        StreamRecv, StreamSend,
    },
    error::NetworkError,
    peers::ArtificePeer,
    protocol::StreamHeader,
    syncronous::{SyncDataStream, SyncStream},
};
use async_trait::async_trait;
use futures::executor;
use std::{
    net::{SocketAddr, TcpStream},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamType {
    /// asyncronous stream
    Async,
    /// syncronous stream
    Sync,
}
/// provides a means for implementing functionality either asyncronously or syncronously, based on two different types
/// there is not requirement that the async type implements future, since the type my use stream, or some other similar trait that allows it to be considered async
/// even if it doesn't implement future
#[derive(Debug, Clone)]
pub enum SyncAsync<A, S> {
    /// type is the async version
    Async(A),
    /// type is sync version
    Sync(S),
}
impl<A, S> SyncAsync<A, S> {
    /// # Warning
    /// this function can only be used on the tokio runtime
    pub async fn async_or_default<'a, T, U: futures::Future<Output = T>, D: FnOnce(&'a S) -> T>(
        &'a self,
        default_fn: D,
        async_fn: impl Fn(&'a A) -> U,
    ) -> T {
        match &self {
            SyncAsync::Async(stream) => async_fn(stream).await,
            SyncAsync::Sync(stream) => default_fn(stream),
        }
    }
    pub fn sync_or_default<'a, T, F: FnOnce(&'a S) -> T, D: FnOnce(&'a A) -> T>(
        &'a self,
        default_fn: D,
        sync_fn: F,
    ) -> T {
        match &self {
            SyncAsync::Async(stream) => default_fn(stream),
            SyncAsync::Sync(stream) => sync_fn(stream),
        }
    }
    /// maps if async, otherwise returns NetworkError::NotAsync
    pub async fn async_map<'a, T, U: futures::Future<Output = T>>(
        &'a self,
        func: impl Fn(&'a A) -> U,
    ) -> Result<T, NetworkError> {
        match &self {
            SyncAsync::Async(stream) => Ok(func(stream).await),
            SyncAsync::Sync(_) => Err(NetworkError::NotAsync),
        }
    }
    /// maps if sync, otherwise returns NetworkError::NotSync
    pub fn sync_map<'a, T, F: FnOnce(&'a S) -> T>(&'a self, func: F) -> Result<T, NetworkError> {
        match &self {
            SyncAsync::Sync(stream) => Ok(func(stream)),
            SyncAsync::Async(_) => Err(NetworkError::NotSync),
        }
    }
    /// maps if async, otherwise returns NetworkError::NotAsync
    pub async fn async_map_mut<'a, T, U: futures::Future<Output = T>>(
        &'a mut self,
        func: impl Fn(&'a mut A) -> U,
    ) -> Result<T, NetworkError> {
        match self {
            SyncAsync::Async(stream) => Ok(func(stream).await),
            SyncAsync::Sync(_) => Err(NetworkError::NotAsync),
        }
    }
    /// maps if sync, otherwise returns NetworkError::NotSync
    pub fn sync_map_mut<'a, T, F: FnOnce(&'a S) -> T>(
        &'a mut self,
        func: F,
    ) -> Result<T, NetworkError> {
        match self {
            SyncAsync::Sync(stream) => Ok(func(stream)),
            SyncAsync::Async(_) => Err(NetworkError::NotSync),
        }
    }
    /// maps if async, consuming the enum and passing in its value, otherwise returns NetworkError::NotAsync
    pub async fn async_map_into<T, U: futures::Future<Output = T>>(
        self,
        func: impl Fn(A) -> U,
    ) -> Result<T, NetworkError> {
        match self {
            SyncAsync::Async(stream) => Ok(func(stream).await),
            SyncAsync::Sync(_) => Err(NetworkError::NotAsync),
        }
    }
    /// maps if sync, consuming the enum and passing in its value, otherwise returns NetworkError::NotSync
    pub fn sync_map_into<T, F: FnOnce(S) -> T>(self, func: F) -> Result<T, NetworkError> {
        match self {
            SyncAsync::Sync(stream) => Ok(func(stream)),
            SyncAsync::Async(_) => Err(NetworkError::NotSync),
        }
    }
    /// borrow the value mutably if async
    pub fn borrow_async_mut<'a>(&'a mut self) -> Result<&'a mut A, NetworkError> {
        match self {
            SyncAsync::Async(a) => Ok(a),
            SyncAsync::Sync(_) => Err(NetworkError::NotAsync),
        }
    }
    /// borrow value mutably if sync
    pub fn borrow_sync_mut<'a>(&'a mut self) -> Result<&'a mut S, NetworkError> {
        match self {
            SyncAsync::Sync(s) => Ok(s),
            SyncAsync::Async(_) => Err(NetworkError::NotAsync),
        }
    }
    /// borrow the value if async
    pub fn borrow_async<'a>(&'a self) -> Result<&'a A, NetworkError> {
        match self {
            SyncAsync::Async(a) => Ok(a),
            SyncAsync::Sync(_) => Err(NetworkError::NotAsync),
        }
    }
    /// borrow value if sync
    pub fn borrow_sync<'a>(&'a self) -> Result<&'a S, NetworkError> {
        match self {
            SyncAsync::Sync(s) => Ok(s),
            SyncAsync::Async(_) => Err(NetworkError::NotAsync),
        }
    }
    /// similar to std unwrap, but checks if is async
    pub fn async_unwrap(self) -> Result<A, NetworkError> {
        match self {
            SyncAsync::Async(a) => Ok(a),
            SyncAsync::Sync(_) => Err(NetworkError::NotAsync),
        }
    }
    /// similar to std unwrap, but checks if is sync
    pub fn sync_unwrap(self) -> Result<S, NetworkError> {
        match self {
            SyncAsync::Sync(s) => Ok(s),
            SyncAsync::Async(_) => Err(NetworkError::NotAsync),
        }
    }
    pub fn is_async(&self) -> bool {
        match self {
            SyncAsync::Async(_) => true,
            SyncAsync::Sync(_) => false,
        }
    }
    pub fn is_sync(&self) -> bool {
        !self.is_async()
    }
}
pub struct DataStream {
    stream: SyncAsync<AsyncStream, SyncStream>,
}
impl DataStream {
    /// will fail if attempting to split sync
    pub fn split(&mut self) -> Result<(StreamSend, StreamRecv), NetworkError> {
        Ok(self.stream.borrow_async_mut()?.split())
    }
    /// will fail if attempting to split sync
    pub fn into_split(self) -> Result<(OwnedStreamSend, OwnedStreamRecv), NetworkError> {
        Ok(self.stream.async_unwrap()?.into_split())
    }
    pub fn connect(peer: &ArtificePeer, kind: StreamType) -> Result<Self, NetworkError> {
        match kind {
            StreamType::Async => Ok(Self {
                stream: SyncAsync::Async(executor::block_on(AsyncStream::connect(peer))?),
            }),
            StreamType::Sync => Ok(Self {
                stream: SyncAsync::Sync(SyncStream::connect(peer)?),
            }),
        }
    }
}
impl SyncDataStream for DataStream {
    type NetStream = TcpStream;
    type Error = NetworkError;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            stream: SyncAsync::Sync(SyncStream::new(stream, header, remote_addr)?),
        })
    }
    fn remote_addr(&self) -> &SocketAddr {
        self.stream
            .sync_or_default(|stream| stream.remote_addr(), |stream| stream.remote_addr())
    }
    fn header(&self) -> &StreamHeader {
        self.stream
            .sync_or_default(|stream| stream.header(), |stream| stream.header())
    }
}
#[async_trait]
impl AsyncSend for DataStream {
    type SendError = NetworkError;
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, NetworkError> {
        self.stream.borrow_async_mut()?.send(outbuf).await
    }
    fn remote_addr(&self) -> &SocketAddr {
        self.stream
            .sync_or_default(|stream| stream.remote_addr(), |stream| stream.remote_addr())
    }
}
#[async_trait]
impl AsyncRecv for DataStream {
    type RecvError = NetworkError;
    async fn recv(&mut self, inbuf: &mut Vec<u8>) -> Result<Vec<usize>, Self::RecvError> {
        self.stream.borrow_async_mut()?.recv(inbuf).await
    }
    fn header(&self) -> &StreamHeader {
        self.stream
            .sync_or_default(|stream| stream.header(), |stream| stream.header())
    }
}
#[async_trait]
impl AsyncDataStream for DataStream {
    type NetStream = tokio::net::TcpStream;
    type StreamError = NetworkError;
    fn new(
        stream: tokio::net::TcpStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::StreamError>
    where
        Self: std::marker::Sized,
    {
        Ok(Self {
            stream: SyncAsync::Async(AsyncStream::new(stream, header, remote_addr)?),
        })
    }
}
