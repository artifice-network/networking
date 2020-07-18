# Networking for the Aritice Network
### Purpose
the point of this crate is to provide networking support between peers on MAC, Linux, and Windows it will also act as the artifice server

## 
future implementations include async read/write, as well as async compression

## Example usage

it would be better to use a management crate but these example would technically work

## Async

### Dependencies

```toml
tokio = {version = "0.2.21", features = ["full"]}
```

### Async Client
```rust
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

```
## Sync

### Sync Client

```rust
use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
use std::fs::File;
use std::io::Read;
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
    println!(
        "got {} bytes from server",
        stream.recv(&mut buffer).unwrap()
    );
    println!("read from stream");
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
    //stream.write(&buffer).unwrap();
}

```

### Sync Server
```rust
use networking::{ArtificeConfig, ArtificeHost, ArtificePeer};
use std::fs::File;
use std::io::{Read};
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
        let mut stream = netstream.unwrap();
        println!("about to write to stream");
        stream
            .send(&"hello world".to_string().into_bytes())
            .unwrap();
        // do something with the stream example:
        if *stream.peer() == peer {
            // correct peer
        }
    }
}

```