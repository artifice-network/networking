// this crate is an example of sending a large amount of data through this network
// in the future it will implement data transmisions with lengths greater then 65535
use networking::{
    sllp::{SllpSocket, SllpStream},
    test_config,
    ConnectionRequest,
};
use opencv::{core, highgui, imgcodecs::imdecode, prelude::VectorTrait};
use std::error::Error;
use tokio::runtime::Runtime;
use networking::asyncronous::{AsyncRecv, AsyncNetworkHost};

fn main() {
    let mut runtime = Runtime::new().unwrap();
    runtime.block_on(run()).unwrap();
}
async fn run() -> Result<(), ExampleError> {
    let (peer, config) = test_config();
    let mut socket = SllpSocket::from_host_config(&config).await.unwrap();
    // peer can be anything that implements PeerList
    while let Some(Ok(strm)) = socket.incoming().await {
        // verifies that a peer is allow to connect
        let stream = strm.verify(&peer).unwrap();
        println!("new connection verified");
        run_server(stream).await.unwrap();
    }
    Ok(())
}
async fn run_server(mut socket: SllpStream) -> Result<(), ExampleError> {
    let window = "video capture";
    highgui::named_window(window, 1)?;
    let mut read_buf = Vec::new();
    let mut vec: core::Vector<u8> = core::Vector::with_capacity(65535);
    loop {
        let recv_len = socket.recv(&mut read_buf).await?;
        for i in &read_buf {
            if 1 == recv_len {
                break;
            }
            vec.push(*i);
        }
        let newframe = imdecode(&vec, -1)?;
        highgui::imshow(window, &newframe)?;
        let key = highgui::wait_key(10)?;
        if key > 0 && key != 255 {
            break;
        }
        vec.clear();
        read_buf.clear();
    }
    Ok(())
}
use std::fmt;
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
