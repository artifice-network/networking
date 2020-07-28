use networking::sllp::SllpSocket;
use networking::test_config;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (peer, config) = test_config();
    let mut socket = SllpSocket::from_host_data(&config).await?;
    while let Some(strm) = socket.incoming().await {
        let mut stream = unsafe { strm.unwrap().unverify() };
        tokio::spawn(async move {
            loop {
                let mut invec = Vec::new();
                stream.recv(&mut invec).await;
                println!(
                    "got message {}, from server",
                    String::from_utf8(invec).unwrap()
                );
            }
        });
    }
    Ok(())
}
