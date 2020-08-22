use crate::{
    asyncronous::{AsyncStream, AsyncRecv, AsyncSend, StreamSend, StreamRecv, OwnedStreamRecv, OwnedStreamSend},
    syncronous::{SyncDataStream, SyncStream},
    error::NetworkError,
    protocol::StreamHeader,
    peers::ArtificePeer,
};
use async_trait::async_trait;
use futures::executor;
use std::{mem::ManuallyDrop, ops::{Deref, DerefMut}, net::{SocketAddr, TcpStream}};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamType {
    /// asyncronous stream
    Async,
    /// syncronous stream
    Sync,
}
/// exists both as a SyncStream, and an AsyncStream so functions from either can be used
#[derive(Debug)]
pub struct DataStream {
    stream: Stream,
}
#[async_trait]
impl AsyncSend for DataStream {
    type SendError = NetworkError;
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, Self::SendError> {
        unsafe {
            if self.stream.s_stream.1 {
                return Err(NetworkError::ExecFailed(Box::new("Not Async")));
            }
            self.stream.a_stream.deref_mut().0.send(outbuf).await
        }
    }
    fn remote_addr(&self) -> &SocketAddr {
        unsafe {
            if self.stream.s_stream.1 {
                return self.stream.s_stream.deref().0.remote_addr();
            }
            self.stream.a_stream.deref().0.remote_addr()
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
    ) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized,
    {
        Ok(Self { stream: Stream::from_sync(SyncStream::new(stream, header, remote_addr)? )})
    }
    fn header(&self) -> &StreamHeader {
        unsafe {
            if self.stream.s_stream.1 {
                return self.stream.s_stream.0.header()
            }
            self.stream.a_stream.0.header()
        }
    }
    fn remote_addr(&self) -> &SocketAddr {
        unsafe {
            if self.stream.s_stream.1 {
                return self.stream.s_stream.0.remote_addr()
            }
            self.stream.a_stream.0.remote_addr()
        }
    }
}
impl DataStream {
    pub fn connect(peer: &ArtificePeer, kind: StreamType) -> Result<Self, NetworkError> {
        Ok(Self {
            stream: Stream::connect(peer, kind)?,
        })
    }
    /// this function is only enabled for Async version of this type
    pub fn into_split(mut self) -> Result<(OwnedStreamSend, OwnedStreamRecv),NetworkError>{
        unsafe {
            if self.stream.s_stream.1 {
                return Err(NetworkError::ExecFailed(Box::new(self)));
            }
            Ok(ManuallyDrop::take(&mut self.stream.a_stream).0.into_split())
        }
    }
    /// this function is only enabled for Async version of this type
    pub fn split(&mut self) -> Result<(StreamSend, StreamRecv), NetworkError>{
        unsafe {
            if self.stream.s_stream.1 {
                return Err(NetworkError::ExecFailed(Box::new("Not Async")));
            }
            Ok(self.stream.a_stream.0.split())
        }
    }
}
union Stream {
    s_stream: ManuallyDrop<(SyncStream, bool)>,
    a_stream: ManuallyDrop<(AsyncStream, bool)>,
}
impl Stream {
    pub fn connect(peer: &ArtificePeer, kind: StreamType) -> Result<Self, NetworkError> {
        Ok(match kind {
            StreamType::Async => Self {
                a_stream: ManuallyDrop::new((
                    executor::block_on(AsyncStream::connect(&peer))?,
                    false,
                )),
            },
            StreamType::Sync => Self {
                s_stream: ManuallyDrop::new((SyncStream::connect(&peer)?, true)),
            },
        })
    }
    pub fn from_sync(s_stream: SyncStream) -> Self {
        Self {s_stream: ManuallyDrop::new((s_stream, true))}
    }
}
use std::fmt;
impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error>{
        let name = unsafe {
            match self.s_stream.1 {
                true => format!("{:?}", self.s_stream),
                false => format!("{:?}", self.a_stream),
            }
        };
        f.debug_struct("Stream").field("value", &name).finish()
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        unsafe {
            if self.s_stream.1 {
                ManuallyDrop::drop(&mut self.s_stream);
            } else if !self.a_stream.1 {
                ManuallyDrop::drop(&mut self.a_stream);
            }
        }
    }
}
#[test]
fn data_stream(){
    let (peer, _) = test_config();
    let stream = DataStream::connect(&peer, StreamType::Sync).unwrap();
    println!("{:?}", stream);
    assert_eq!(1,2);
}