use networking::{asyncronous::AsyncHost, ArtificeConfig, ArtificePeer};
use std::fs::File;
use std::io::Read;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let mut stream = host.connect(peer).await.unwrap();
    let mut buffer = Vec::new();
    println!("about to read from sream");
    println!(
        "got {} bytes from server",
        stream.recv(&mut buffer).await.unwrap()
    );
    println!("read from stream");
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
    Ok(())
}
