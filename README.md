# Networking for the Aritice Network
### Purpose
the point of this crate is to provide networking support between peers on MAC, Linux, and Windows it will also act as the artifice server

# Example usage

it would be better to use a management crate buf this example would technically work

# Client

```rust
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
```

# Listen 
```rust
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
```