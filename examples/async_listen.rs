use networking::{
    asyncronous::{AsyncHost, AsyncNetworkHost, AsyncSend},
    test_config, ConnectionRequest,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, config) = test_config();
    let mut host = AsyncHost::from_host_config(&config).await.unwrap();
    let mut msg = networking::random_string(43235).into_bytes();
    while let Some(Ok(strm)) = host.incoming()?.await {
        let mut stream = strm.verify(&peer)?;
        // make sure you got a connection from the correct peer
        println!("sending message hello world");
        loop {
            stream.send(b"hello world").await.unwrap();
        }
    }
    Ok(())
}
