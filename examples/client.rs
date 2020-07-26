use networking::{syncronous::SyncHost, test_config};

fn main() {
    // this function is for testing only
    let (peer, config) = test_config();
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
