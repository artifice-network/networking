# RSA + AES based peer to peer networking
### Purpose
the purpose of this network is to provide secured AES asymetric implementation that uses RSA to implement the asymetric nature of this projects encryption. 

## divergence from classic TLS
this crate aims to prevent man in the middle attacks by encrypting pre-shared keys that are sent in each packet. by doing this, even if a hacker has a public key, they will be unable to feed false information that could cause a crash to either of the peers. in this way each peer can mantain knowledge of the other in both directions, which allows for a more decentralized approach than draditional TLS.

## Version details

see repository's RELEASE.md

## future implementations
Syncronous version asymetric AES encryption, data transfer rates exceeding 65535 bytes, by sending multiple blocks of data broken into packets of length 65535

## Example usage

a management crate, or database would be a better means of supplying peers to this network, each host having a databse containg a list of their paired peers.

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

for sync examples see <a href="https://docs.rs/networking/0.1.5/networking">docs</a>