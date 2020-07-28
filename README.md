# RSA + AES based peer to peer networking
### Purpose
the purpose of this network is to provide secured AES asymetric implementation that uses RSA to implement the asymetric nature of this projects encryption. 

## divergence from classic TLS
this crate aims to prevent man in the middle attacks by encrypting pre-shared keys that are sent in each packet. by doing this, even if a hacker has a public key, they will be unable to feed false information that could cause a crash to either of the peers. in this way each peer can mantain knowledge of the other in both directions, which allows for a more decentralized approach than draditional TLS.

## Version details

this version comes with an SLLP (Secure Low Latency Protocol) implementation. this protocol created for the purpose of this project
is a semi-connection enabled protocol based on udp.

## implementation of SLLP

the SLLP implementation in this project, ensures a psudo connection that is private between two peers, by authenticating 
encrypted pre-shared keys.

## future implementations
<ul>
<li>proper SLLp error handiling to notifiy a stream when connection has been terminated. </li>
<li>data order tracking, for SLLP</li>
<li>in place encrpytion and decryption for increased efficiency.</li>
<li>data transfer rates exceeding 65535 bytes, by sending multiple blocks of data broken into packets of length 65535 for Tcp implementations.</li>
</ul>
## Example usage

a management crate, or database would be a better means of supplying peers to this network, each host having a databse containg a list of their paired peers.
## SLLP
### SLLP Client
 
```rust
use networking::sllp::SllpSocket;
use networking::test_config;
use networking::Layer3Addr;
use std::error::Error;
use networking::asyncronous::{AsyncSend, AsyncNetworkHost};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut peer, config) = test_config();
    let socket = SllpSocket::from_host_config(&config).await?;
    // this needs to be updated to remote peer, because two devices cannot bind to the smae address
    peer.set_socket_addr((Layer3Addr::newv4(127, 0, 0, 1), 6464).into());
    let mut stream = socket.connect(&peer).await;
    loop { stream.send(b"hello world").await.unwrap(); }
    Ok(())
}
```  
### SLLP Server

```rust
use networking::sllp::SllpSocket;
use networking::test_config;
use std::error::Error;
use networking::asyncronous::{AsyncRecv, AsyncNetworkHost};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (peer, config) = test_config();
    let mut socket = SllpSocket::from_host_config(&config).await?;
    while let Some(strm) = socket.incoming().await {
        let mut stream = strm?.verify(&peer)?;
        tokio::spawn(async move {
            println!("new connection");
            loop {
                let mut invec = Vec::new();
                stream.recv(&mut invec).await.unwrap();
                println!(
                    "got message {}, from server",
                    String::from_utf8(invec).unwrap()
                );
            }
        });
    }
    Ok(())
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

for sync examples see <a href="https://docs.rs/networking/0.1.5/networking">docs</a>
the camera example is to show a practical application, and test the network by supplying high load