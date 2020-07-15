use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
fn main(){
    let config: ArtificeConfig = serde_json::from_str("some_str").unwrap();
    let host = ArtificeHost::from_host_data(&config).unwrap();
    let peer: ArtificePeer = serde_json::from_str("peer_str").unwrap();
    for netstream in host {
        let stream = netstream.unwrap();
        // do something with the stream example:
        if *stream.peer() == peer {
            // correct peer
        }
    }
}