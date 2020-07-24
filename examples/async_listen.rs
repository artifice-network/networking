use networking::{asyncronous::AsyncHost, ArtificeConfig, ArtificePeer};
use std::fs::File;
use std::io::Read;
use tokio::stream::StreamExt;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // currently not functioning
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let mut host = AsyncHost::from_host_config(&config).await.unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = String::new();
    file.read_to_string(&mut invec).unwrap();
    let peer: ArtificePeer = serde_json::from_str(&invec).unwrap();
    println!("peer created");
    /*while let Some(netstream) = host.next().await {
        println!("stream created");
        let mut stream = netstream.unwrap();
        stream.send(b"hello world").await.unwrap();
    }*/
    for mut stream in host.incoming()?.await {
        println!("stream created");
        stream.send(b"hello world").await.unwrap();
    }
    Ok(())
}