use networking::asyncronous::{AsyncNetworkHost, AsyncSend, AsyncRecv};
use networking::ConnectionRequest;
use networking::sllp::SllpSocket;
use networking::test_config;

#[tokio::main]
async fn main(){
    let (peer, config) = test_config();
    let mut socket = SllpSocket::from_host_config(&config).await.unwrap();
    let (outgoing, mut incoming) = socket.into_split();
    let artifice_peer = peer.clone();
    tokio::spawn(async move {
        while let Some(strm) = incoming.incoming().await {
            println!("got new connection");
            let mut stream = strm.unwrap().verify(&artifice_peer).unwrap();
            loop { 
                let mut invec = Vec::new();
                stream.send(b"hello from the server").await.unwrap(); 
                println!("got meessage: {}, from server", String::from_utf8(invec).unwrap());
            };
        }
    });
    println!("about to connect");
    let mut stream = outgoing.connect(&peer).await;
    loop { stream.send(b"hello from the client").await.unwrap(); }
}