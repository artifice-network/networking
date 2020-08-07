use networking::{
    asyncronous::{AsyncHost, AsyncNetworkHost, AsyncSend},
    test_config, ConnectionRequest, random_string,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, config) = test_config();
    let mut host = AsyncHost::from_host_config(&config).await.unwrap();
    let mut msg = networking::random_string(43235).into_bytes();
    // can also be done in while let Some(Ok(strm)) = host.incoming()?.await
    // this was better for the example though
    if let Some(Ok(strm)) = host.incoming()?.await {
        let mut stream = strm.verify(&peer)?;
        // make sure you got a connection from the correct peer
        println!("sending message hello world");
        stream.send(&random_string(65120).into_bytes()).await.unwrap();
    }
    Ok(())
}
