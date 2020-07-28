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