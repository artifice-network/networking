use networking::asyncronous::{AsyncNetworkHost, AsyncSend};
use networking::sllp::SllpSocket;
use networking::test_config;
use networking::Layer3Addr;
use std::error::Error;
use networking::random_string;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut peer, mut config) = test_config();
    println!("peer addr: {}", peer.socket_addr());
    // update default addr because only one udp socket per addr
    config.set_socket_addr((Layer3Addr::newv4(127, 0, 0, 1), 3232).into());
    println!("about to create socket");
    let socket = SllpSocket::client_only(&config).await?;
    println!("created socket");
    let mut stream = socket.connect(&peer).await?;
    println!("entering loop");
    loop {
        stream.send(&random_string(65).into_bytes()).await.unwrap();
    }
}
