use networking::{syncronous::SyncHost, test_config, ArtificeConfig, ArtificePeer, ArtificeStream};
use std::fs::File;
use std::io::Read;

fn main() {
    let (peer, config) = test_config();
    let host = SyncHost::from_host_data(&config).unwrap();
    for netstream in host {
        println!("new connection");
        let mut stream = netstream.unwrap().verify(&peer).unwrap();
        stream.send(b"hello world").unwrap();
        break;
    }
}
