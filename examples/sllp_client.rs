use networking::sllp::SllpSocket;
use networking::test_config;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (peer, config) = test_config();
    let mut socket = SllpSocket::from_host_data(&config).await?;
    let mut stream = socket.connect(&peer).await;
    Ok(())
}
