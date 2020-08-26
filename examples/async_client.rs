use networking::{
    asyncronous::{AsyncHost, AsyncRecv},
    test_config,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut peer, config) = test_config();
    let host = AsyncHost::client_only(&config).await.unwrap();
    peer.set_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 2, 5)),
        6464,
    ));
    let mut stream = host.connect(peer).await.unwrap();
    let mut buffer = Vec::new();
    println!(
        "got {:?} bytes from server",
        stream.recv(&mut buffer).await.unwrap()
    );
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
    Ok(())
}
