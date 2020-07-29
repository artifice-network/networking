// the point of this example is to show large data transimissions over the network
// future example implementation will support data transmission greater then 65535
use networking::{sllp::SllpSocket, test_config, ConnectionRequest};
use opencv::{core, imgcodecs::*, prelude::*, videoio};
use std::error::Error;
use std::fmt;
use tokio::runtime::{Handle, Runtime};
use networking::asyncronous::{AsyncSend, AsyncNetworkHost};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

#[derive(Debug)]
pub enum ExampleError {
    OpencvError(opencv::Error),
    NetworkError(networking::error::NetworkError),
}
impl fmt::Display for ExampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for ExampleError {}

impl From<opencv::Error> for ExampleError {
    fn from(error: opencv::Error) -> Self {
        ExampleError::OpencvError(error)
    }
}
impl From<networking::error::NetworkError> for ExampleError {
    fn from(error: networking::error::NetworkError) -> Self {
        ExampleError::NetworkError(error)
    }
}

async fn run(_handle: Handle) -> Result<(), ExampleError> {
    let (mut peer, mut config) = test_config();
    config.set_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 3232));
    let socket = SllpSocket::from_host_config(&config).await.unwrap();
    // the test peers address is localhost, but this example can only be run between two computersheader)
    // file in ip with remote ip
    peer.set_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 6464));
    let mut stream = socket.connect(&peer).await;
    println!("connected");
    let mut cam = videoio::VideoCapture::new(0, videoio::CAP_ANY)?; // 0 is the default camera
    let opened = videoio::VideoCapture::is_opened(&cam)?;
    if !opened {
        panic!("Unable to open default camera!");
    }

    let mut params: core::Vector<i32> = core::Vector::new();
    params.push(IMWRITE_JPEG_QUALITY);
    params.push(30);
    loop {
        let mut frame = core::Mat::default()?;
        cam.read(&mut frame)?;
        let mut outbuf: core::Vector<u8> = core::Vector::with_capacity(640 * 480 * 3);
        if frame.size()?.width > 0 {
            imencode(".jpg", &frame, &mut outbuf, &params)?;
            stream.send(&outbuf.to_vec()).await?;
        }
    }
}
fn main() {
    let mut runtime = Runtime::new().unwrap();
    let handle = runtime.handle().clone();
    runtime.block_on(run(handle)).unwrap();
}
