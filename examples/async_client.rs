use networking::{
    asyncronous::{AsyncHost, AsyncRecv},
    test_config,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer, config) = test_config();
    let host = AsyncHost::client_only(&config).await.unwrap();
    let mut stream = host.connect(peer).await.unwrap();
    let mut buffer = Vec::new();
    loop { println!(
        "got {} bytes from server",
        stream.recv(&mut buffer).await.unwrap()
    ); buffer.clear();}
    let string = String::from_utf8(buffer).unwrap();
    println!("got message: {} from server", string);
    Ok(())
}
