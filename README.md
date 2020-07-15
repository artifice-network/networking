# Networking for the Aritice Network
### Purpose
the point of this crate is to provide networking support between peers on MAC, Linux, and Windows it will also act as the artifice server

# Example usage

it would be better to use a management crate buf this example would technically work

# Client

```rust
use networking::{random_string, ArtificeConfig, ArtificeHost, ArtificePeer, Layer3Addr};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
fn main() {
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
    let host = ArtificeHost::client_only(&config);
    let mut stream = host.connect(peer).unwrap();
    let mut buffer = Vec::new();
    println!("about to read from sream");
    stream.read(&mut buffer).unwrap();
    println!("read from stream");
    stream.write(&buffer).unwrap();
}
```

# Listen 
```rust
use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
use std::fs::File;
use std::io::Read;
fn main() {
    let mut config_file = File::open("host.json").unwrap();
    let mut conf_vec = String::new();
    config_file.read_to_string(&mut conf_vec).unwrap();
    let config: ArtificeConfig = serde_json::from_str(&conf_vec).unwrap();
    let host = ArtificeHost::from_host_data(&config).unwrap();
    let mut file = File::open("peer.json").unwrap();
    let mut invec = String::new();
    file.read_to_string(&mut invec).unwrap();
    let peer: ArtificePeer = serde_json::from_str(&invec).unwrap();
    for netstream in host {
        let stream = netstream.unwrap();
        // do something with the stream example:
        if *stream.peer() == peer {
            // correct peer
        }
    }
}

```