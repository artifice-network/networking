use networking::sllp::SllpSocket;
use networking::test_config;
use networking::Layer3Addr;
use std::error::Error;
use networking::asyncronous::AsyncSend;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut peer, config) = test_config();
    let socket = SllpSocket::from_host_data(&config).await?;
    peer.set_socket_addr((Layer3Addr::newv4(127, 0, 0, 1), 6464).into());
    let mut stream = socket.connect(&peer).await;
    stream.send(b"hello world").await.unwrap();
    Ok(())
}
