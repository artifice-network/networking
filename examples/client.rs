use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
use std::io::{Read, Write};
fn main(){
    let config: ArtificeConfig = serde_json::from_str("some_str").unwrap();
    let host = ArtificeHost::from_host_data(&config).unwrap();
    let peer: ArtificePeer = serde_json::from_str("peer_str").unwrap();
    let mut stream = host.connect(peer).unwrap();
    let mut buffer = Vec::new();
    stream.read(&mut buffer).unwrap();
    stream.write(&buffer).unwrap();
}