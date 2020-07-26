# RSA + AES based peer to peer networking
### Purpose
the purpose of this network is to provide secured RSA based networking between devices. it also aims to prevent man in the middle attacks by encrypting pre-shared keys that are sent in each packet. by doing this, even if a hacker has a public key, they will be unable to feed false information to either of the peers.

## Version details

this version adds support for the ConnectionRequest struct that requires a list of peers that can be checked for a given peer, to verify that peer is allowed to connect, this is done throught the PeerList trait. however ConnectionRequest also provides support for directly accessing the stream, intended to be used for establishing new pairs of peers.
## Example usage

it would be better to use a management crate but these example would technically work

## Async

### Dependencies

```toml
tokio = {version = "0.2.21", features = ["full"]}
```

### Async Client
```rust
use networking::{asyncronous::AsyncHost, test_config};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, config) = test_config();
    let host = AsyncHost::client_only(&config).await.unwrap();
    let mut stream = host.connect(peer).await.unwrap();
    let mut buffer = Vec::new();
    println!(
        "got {} bytes from server",
        stream.recv(&mut buffer).await.unwrap()
    );
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
    Ok(())
}
```
### Async Server
```rust
use networking::{asyncronous::AsyncHost, test_config};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, config) = test_config();
    let mut host = AsyncHost::from_host_config(&config).await.unwrap();
    while let Some(Ok(strm)) = host.incoming()?.await {
        let mut stream = strm.verify(&peer)?;
        // make sure you got a connection from the correct peer
        println!("sending message hello world");
        stream.send(b"hello world").await.unwrap();
    }
    Ok(())
}
```
## Sync

for sync examples see <a href="https://docs.rs/networking/0.1.4/networking">docs</a>