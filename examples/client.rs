use networking::{syncronous::SyncHost, test_config};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {
    // this function is for testing only
    let (mut peer, config) = test_config();
    peer.set_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 81)),
        6464,
    ));
    let host = SyncHost::client_only(&config).unwrap();
    let mut stream = host.connect(peer).unwrap();
    println!("connected");
    let mut buffer = Vec::new();
    println!("about to read from sream");
    println!(
        "got {} bytes from server",
        stream.recv(&mut buffer).unwrap()
    );
    println!("read from stream");
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
}
