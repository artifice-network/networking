use networking::{
    asyncronous::{AsyncHost, AsyncStream},
    ArtificeConfig, ArtificePeer,
};
use opencv::{
    core, highgui,
    imgcodecs::imdecode,
    prelude::{VectorTrait},
};
use std::error::Error;
use std::fs::File;
use std::io::{Read};
use tokio::runtime::{Handle, Runtime};

fn main() {
    let mut runtime = Runtime::new().unwrap();
    let handle = runtime.handle().clone();
    runtime.block_on(run(handle)).unwrap();
}
async fn run(handle: Handle) -> Result<(), ExampleError> {
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let mut host = AsyncHost::from_host_config(&config).await.unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = String::new();
    file.read_to_string(&mut invec).unwrap();
    // peer can be anything that implements PeerList
    let peer: ArtificePeer = serde_json::from_str(&invec).unwrap();
    while let Some(Ok(strm)) = host.incoming()?.await {
        let stream = strm.verify(&peer)?;
        println!("new connection verified");
        run_server(stream).await.unwrap();
    }
    Ok(())
}
async fn run_server(mut socket: AsyncStream) -> Result<(), ExampleError> {
    let window = "video capture";
    println!("before loop");
    highgui::named_window(window, 1)?;
    //let mut socket = UdpSocket::bind("0.0.0.0:6464").unwrap();
    let mut read_buf = Vec::new();
    let mut vec: core::Vector<u8> = core::Vector::with_capacity(65535);
    loop {
        let recv_len = socket.recv(&mut read_buf).await?;
        println!("received data");
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