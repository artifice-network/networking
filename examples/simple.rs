use networking::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter;
use std::net::{IpAddr, Ipv6Addr};
fn main() {
    let user = ArtificeUser::new("test_user", "hello_world");
    let hash = user.login("hello_world").unwrap();
    //assert_eq!(hash.len(), 32);
    let mut peers = ArtificePeers::empty();
    let mut rng = thread_rng();
    let peer_hash1: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(50)
        .collect();

    let ipaddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    use rand::rngs::OsRng;
    use rsa::{PaddingScheme, PublicKeyParts, RSAPrivateKey, RSAPublicKey};

    let mut rng = OsRng;
    let bits = 2048;
    let priv_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RSAPublicKey::from(&priv_key);
    let peer1 = ArtificePeer::new(
        peer_hash1.clone(),
        peer_hash1,
        Layer3Addr::from_ipaddr(&ipaddr),
        PubKeyPair::from_parts(
            BigNum::from_biguint(pub_key.n().clone()),
            BigNum::from_biguint(pub_key.e().clone()),
        ),
    );

    peers.push(peer1);
    peers.save(&hash[0..32]).unwrap();

    let decypted = ArtificePeers::from_file(&hash[0..32], "./peers.json");
}
