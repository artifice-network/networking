# RSA + AES Based Peer to Peer Networking

## Purpose

The purpose of this network is to provide secured AES asymmetric implementation that uses RNA to implement the asymmetric nature of this project's encryption.

## Divergence From Classic TLS

This crate aims to prevent man in the middle attacks by encrypting pre-shared keys that are sent in each packet. By doing this, even if a hacker has a public key, they will be unable to feed false information that could cause a crash to either of the peers. in this way each peer can maintain knowledge of the other in both directions, which allows for a more decentralized approach than traditional TLS.

## Version Details

This version is the first stabalized version, as such nightly is no longer required to use it. This version doesn't include anything that 0.1.7 doesn't except the ability to generate an in memory tar file of the HashDatabase type.

## Implementation of SLLP

The SLLP implementation in this project ensures a pseudo connection that is private between two peers, by authenticating encrypted pre-shared keys. it is done for the sake of transfering large amounts of data quickly when precision is not needed.

## Future Implementations
<ul>
<li>proper SLLP error handling to notify a stream when connection has been terminated.</li>
<li>data order tracking, for SLLP.</li>
<li>data transfer rates exceeding 65535 bytes, by sending multiple blocks of data broken into packets of length 65535 for TCP implementations. </li>
<li>Increase in packet types, currently only has raw data, and administrative packet types see protocol.</li>
</ul>

## Example usage


### Database usage

```rust
use networking::database::HashDatabase;
use networking::ArtificePeer;
use networking::{random_string, test_config};

fn main(){
   // generate aes encryption key
   let key = random_string(16).into_bytes();
   let (peer, _config) = test_config();
   
   let mut database: HashDatabase<ArtificePeer> = HashDatabase::new("./test_db", key.clone()).unwrap();
   database.insert(peer.global_peer_hash().to_string(), peer.clone()).unwrap();
   
   let mut second_database: HashDatabase<ArtificePeer> = HashDatabase::new("./test_db", key).unwrap();
   second_database.load(&peer.global_peer_hash().to_string()).unwrap();
   let newpeer = second_database.get(&peer.global_peer_hash().to_string()).unwrap();
}
```
## Async

### Dependencies

```toml
tokio = {version = "0.2.21", features = ["full"]}
```

### Async Client
```rust
use networking::{asyncronous::{AsyncHost, AsyncRecv}, test_config};
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
use networking::{asyncronous::{AsyncHost, AsyncSend, AsyncNetworkHost}, test_config};
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

for sync examples and sllp examples see <a href="https://docs.rs/networking/0.1.7/networking">docs</a>
the camera example is to show a practical application, and test the network by supplying high load