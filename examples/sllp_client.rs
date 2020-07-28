use networking::asyncronous::{AsyncNetworkHost, AsyncSend};
use networking::sllp::SllpSocket;
use networking::test_config;
use networking::Layer3Addr;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut peer, config) = test_config();
    let socket = SllpSocket::from_host_config(&config).await?;
    // this needs to be updated to remote peer, because two devices cannot bind to the smae address
    peer.set_socket_addr((Layer3Addr::newv4(127, 0, 0, 1), 6464).into());
    let mut stream = socket.connect(&peer).await;
    loop {
        stream.send(b"hello world").await.unwrap();
    }
    Ok(())
}
