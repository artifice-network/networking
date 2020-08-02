use networking::database::HashDatabase;
use networking::ArtificePeer;
use networking::{random_string, test_config};
fn main() {
    let key = random_string(16).into_bytes();
    let (peer, _config) = test_config();
    let mut database: HashDatabase<ArtificePeer> =
        HashDatabase::new("./test_db", key.clone()).unwrap();
    database
        .insert(peer.global_peer_hash().to_string(), peer.clone())
        .unwrap();
    let mut second_database: HashDatabase<ArtificePeer> =
        HashDatabase::new("./test_db", key).unwrap();
    second_database
        .load(&peer.global_peer_hash().to_string())
        .unwrap();
    let newpeer = second_database
        .get(&peer.global_peer_hash().to_string())
        .unwrap();
    assert_eq!(*newpeer, peer);
}
