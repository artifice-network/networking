use networking::asyncronous::{AsyncNetworkHost, AsyncRecv};
use networking::sllp::SllpSocket;
use networking::{test_config, ConnectionRequest};
use std::error::Error;

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
