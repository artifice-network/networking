use networking::sllp::SllpSocket;
use networking::test_config;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (peer, config) = test_config();
    println!("about to spawn socket");
    let mut socket = SllpSocket::from_host_data(&config).await?;
    println!("no problem yet");
    while let Some(strm) = socket.incoming().await {
        let mut stream = strm?.verify(&peer)?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}
