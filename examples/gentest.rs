use networking::{
    encryption::PubKeyPair, random_string, ArtificeConfig, ArtificePeer, Layer3Addr,
    Layer3SocketAddr,
};
use std::fs::File;
use std::io::Write;
fn main() {
    let global_peer_hash = random_string(50);
    let peer_hash = random_string(50);
    let addr: Layer3Addr = Layer3Addr::V4([0, 0, 0, 0]);
    let peer_addr = Layer3SocketAddr::from_layer3_addr(Layer3Addr::V4([127, 0, 0, 1]), 6464);
    println!("generating config");
    let config: ArtificeConfig = ArtificeConfig::generate(addr.clone());

    let priv_key = config.host_data().private_key();
    let pubkey = PubKeyPair::from_parts(priv_key.n(), priv_key.e());

    let peer: ArtificePeer = ArtificePeer::new(peer_hash, global_peer_hash, peer_addr, pubkey);
    println!("saving files");
    let mut file = File::create("peer.json").unwrap();
    file.write_all(&serde_json::to_string(&peer).unwrap().into_bytes())
        .unwrap();

    let mut host_file = File::create("host.json").unwrap();
    host_file
        .write_all(&serde_json::to_string(&config).unwrap().into_bytes())
        .unwrap();
}
