use networking::sllp::SllpSocket;
use networking::Layer3Addr;
use networking::test_config;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut peer, config) = test_config();
    let mut socket = SllpSocket::from_host_data(&config).await?;
    peer.set_socket_addr((Layer3Addr::newv4(127,0,0,1), 6464).into());
    let mut stream = socket.connect(&peer).await;
    Ok(())
}
