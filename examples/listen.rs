use networking::{random_string, syncronous::SyncHost, test_config, ConnectionRequest};

fn main() {
    let (peer, config) = test_config();
    let host = SyncHost::from_host_data(&config).unwrap();
    for netstream in host {
        println!("new connection");
        let mut stream = netstream.unwrap().verify(&peer).unwrap();
        stream.send(&random_string(55555).into_bytes()).unwrap();
        break;
    }
}
