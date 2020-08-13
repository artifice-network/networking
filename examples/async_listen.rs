use networking::{
    asyncronous::{AsyncHost, AsyncNetworkHost, AsyncSend},
    random_string, test_config, ConnectionRequest,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, config) = test_config();
    let mut host = AsyncHost::from_host_config(&config).await.unwrap();
    println!(
        "peer len: {}",
        serde_json::to_string(&peer)?.into_bytes().len()
    );
    // can also be done in while let Some(Ok(strm)) = host.incoming()?.await
    // this was better for the example though
    if let Some(Ok(strm)) = host.incoming()?.await {
        let mut stream = strm.verify(&peer)?;
        // make sure you got a connection from the correct peer
        println!("sending message hello world");
        stream
            .send(&random_string(65120).into_bytes())
            .await
            .unwrap();
    }
    Ok(())
}
