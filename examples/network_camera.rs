use opencv::{core, imgcodecs::*, prelude::*, videoio};
use std::io::{Read};
use std::fs::File;
use networking::{
    asyncronous::{AsyncHost},
    ArtificeConfig, ArtificePeer,
};
use std::error::Error;
use std::fmt;
use tokio::runtime::{Runtime, Handle};
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

async fn run(_handle: Handle) -> Result<(), ExampleError>{
    
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = Vec::new();
    file.read_to_end(&mut invec).unwrap();
    let string = String::from_utf8(invec).unwrap();
    // println!("invec: {}", invec);
    let peer: ArtificePeer = serde_json::from_str(&string).unwrap();
    let host = AsyncHost::client_only(&config).await.unwrap();
    let mut socket = host.connect(peer).await.unwrap();
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
            println!("about to send");
            socket.send(&outbuf.to_vec()).await?;
        }
    }
}
fn main() {
    let mut runtime = Runtime::new().unwrap();
    let handle = runtime.handle().clone();
    runtime.block_on(run(handle)).unwrap();
}