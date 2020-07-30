use crate::encryption::PubKeyComp;
pub use crate::{ArtificeConfig, ArtificeHostData, ArtificePeer};
use crate::{Layer3Addr, Layer3SocketAddr};
use num_bigint_dig::BigUint;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rsa::RSAPrivateKey;
use std::sync::mpsc::{channel, Receiver, Sender};

use crate::error::NetworkError;
use std::iter;
use tokio::sync::mpsc::{
    channel as tokio_channel, Receiver as AsyncReceiver, Sender as AsyncSender,
};

pub fn get_private_key() -> RSAPrivateKey {
    let n = BigUint::from_bytes_be(&vec![
        214, 82, 135, 64, 34, 118, 248, 217, 78, 42, 130, 198, 138, 28, 117, 66, 23, 74, 77, 139,
        51, 187, 14, 166, 48, 66, 217, 18, 157, 202, 175, 238, 60, 29, 39, 85, 58, 33, 145, 25, 55,
        214, 51, 72, 184, 142, 141, 183, 54, 186, 102, 59, 131, 86, 167, 220, 74, 65, 65, 43, 42,
        104, 182, 108, 144, 96, 238, 52, 145, 126, 239, 25, 41, 16, 221, 86, 26, 27, 87, 100, 171,
        205, 80, 216, 235, 202, 125, 204, 231, 254, 67, 77, 100, 154, 173, 137, 14, 154, 200, 188,
        123, 41, 96, 177, 19, 105, 23, 230, 2, 249, 66, 147, 107, 152, 108, 37, 203, 68, 228, 119,
        255, 64, 4, 53, 106, 145, 228, 191, 24, 199, 3, 232, 39, 170, 123, 227, 204, 68, 97, 216,
        182, 169, 82, 144, 88, 184, 84, 127, 118, 168, 50, 192, 241, 111, 15, 32, 12, 130, 25, 74,
        107, 187, 126, 154, 154, 194, 29, 56, 122, 3, 208, 65, 206, 216, 3, 22, 113, 227, 55, 55,
        206, 184, 132, 85, 236, 144, 7, 146, 98, 220, 37, 208, 81, 82, 21, 166, 151, 67, 14, 73,
        194, 84, 242, 234, 202, 111, 159, 5, 100, 93, 52, 120, 243, 86, 116, 123, 114, 52, 184, 74,
        99, 96, 120, 124, 19, 53, 161, 84, 133, 163, 144, 88, 163, 17, 171, 101, 164, 223, 169, 15,
        63, 80, 2, 207, 95, 248, 66, 244, 196, 207, 68, 49, 45, 25, 95, 255,
    ]);
    let e = BigUint::from_bytes_be(&vec![1, 0, 1]);
    let d = BigUint::from_bytes_be(&vec![
        11, 49, 174, 76, 196, 64, 16, 137, 81, 18, 217, 87, 195, 88, 239, 42, 239, 138, 122, 248,
        93, 80, 84, 216, 139, 70, 194, 141, 189, 94, 27, 200, 70, 173, 131, 35, 105, 112, 221, 98,
        66, 207, 86, 72, 99, 19, 87, 5, 141, 191, 56, 157, 189, 35, 102, 139, 19, 249, 202, 140,
        149, 159, 120, 127, 189, 30, 194, 242, 77, 243, 34, 75, 223, 32, 57, 95, 72, 231, 202, 173,
        192, 103, 109, 228, 150, 148, 49, 243, 228, 222, 27, 231, 203, 236, 100, 73, 247, 80, 80,
        81, 191, 225, 14, 98, 209, 79, 184, 230, 211, 154, 239, 70, 65, 229, 105, 40, 164, 48, 73,
        250, 150, 131, 98, 116, 227, 199, 16, 250, 109, 169, 223, 94, 194, 200, 235, 244, 81, 141,
        113, 70, 119, 176, 15, 189, 108, 182, 211, 139, 9, 72, 167, 91, 225, 129, 247, 159, 121,
        242, 5, 23, 91, 140, 221, 19, 184, 19, 24, 255, 255, 220, 67, 192, 150, 40, 159, 117, 191,
        35, 175, 156, 230, 134, 246, 25, 89, 45, 105, 99, 44, 246, 35, 232, 239, 248, 1, 250, 42,
        150, 86, 234, 244, 142, 204, 108, 149, 31, 236, 200, 217, 36, 169, 27, 254, 17, 99, 82, 80,
        46, 228, 129, 124, 79, 28, 156, 82, 145, 111, 220, 16, 204, 203, 24, 220, 246, 241, 15,
        206, 116, 152, 29, 56, 164, 237, 164, 101, 52, 139, 219, 66, 24, 55, 128, 116, 219, 189,
        217,
    ]);
    let primes = vec![
        BigUint::from_bytes_be(&vec![
            218, 18, 255, 185, 216, 198, 202, 164, 130, 230, 249, 202, 68, 69, 5, 246, 219, 99,
            170, 211, 253, 14, 210, 149, 41, 44, 110, 173, 245, 102, 19, 175, 3, 243, 129, 86, 166,
            104, 105, 78, 11, 162, 161, 239, 8, 206, 97, 222, 183, 132, 115, 39, 49, 172, 164, 33,
            43, 135, 173, 254, 37, 14, 185, 213, 129, 255, 31, 152, 100, 138, 247, 156, 59, 183,
            46, 242, 184, 222, 208, 55, 159, 29, 5, 192, 123, 12, 186, 176, 32, 237, 151, 159, 190,
            44, 144, 186, 37, 149, 107, 154, 19, 116, 16, 196, 53, 166, 113, 122, 192, 87, 122,
            124, 252, 84, 221, 91, 56, 15, 55, 74, 92, 56, 82, 176, 104, 149, 87, 195,
        ]),
        BigUint::from_bytes_be(&vec![
            251, 152, 125, 227, 130, 36, 160, 198, 157, 132, 251, 120, 127, 208, 105, 53, 3, 219,
            28, 218, 154, 192, 227, 251, 141, 201, 136, 237, 210, 125, 215, 149, 134, 32, 240, 187,
            116, 102, 200, 255, 174, 116, 14, 121, 133, 65, 96, 31, 211, 100, 81, 152, 87, 243,
            210, 108, 0, 120, 144, 148, 74, 68, 183, 245, 111, 38, 138, 127, 60, 84, 53, 100, 203,
            208, 82, 220, 91, 30, 137, 202, 143, 93, 123, 7, 206, 144, 171, 174, 124, 125, 114,
            116, 226, 238, 225, 189, 243, 122, 47, 123, 185, 100, 250, 200, 25, 248, 70, 89, 234,
            28, 113, 190, 180, 50, 253, 221, 215, 209, 8, 176, 82, 10, 248, 85, 73, 236, 79, 21,
        ]),
    ];
    RSAPrivateKey::from_components(n, e, d, primes)
}
/// used in examples, and tests, generates ArtificePeer, and ArtificeConfig because private keys take a while to generate
/// this method generates static data, so it should never be used in production environments
pub fn test_config() -> (ArtificePeer, ArtificeConfig) {
    let peer_addr: Layer3SocketAddr = Layer3SocketAddr::new(Layer3Addr::newv4(127, 0, 0, 1), 6464);
    let host_addr: Layer3SocketAddr = Layer3SocketAddr::new(Layer3Addr::newv4(0, 0, 0, 0), 6464);
    let private_key = get_private_key();
    let pubkey = PubKeyComp::from(&private_key);
    // poorly named, global is unique to each host, and peer hash is a pre-shared key
    let host_hash = "f7Cgkll1EegEa5UyuUEADpYAXRXwrhbSB0FLLiYxHpBotzNrw9";
    let peer_hash = "7VKkjONo1txtTAiR1vQWUTsGxh8jwQJips1ClMv9zv1CsOo3ZX";
    let remote_hash = "73C0YnEJRpTd56wPwR8zHa3egpW8iM1ShCRAtutkcssenNkJ0T";
    let peer = ArtificePeer::new(remote_hash, peer_hash, peer_addr, Some(pubkey));
    let host_data = ArtificeHostData::new(&private_key, host_hash);
    let config = ArtificeConfig::new(host_addr, host_data, false);
    (peer, config)
}
/// used to generate things such as pair keys, and global peer hash, see ArtificePeer
pub fn random_string(len: usize) -> String {
    let mut rng = thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(len)
        .collect()
}

pub trait Query {
    type Left;
    type Right;
    /// manually create using an existing sender and receiver
    fn create(sender: Self::Left, receiver: Self::Right) -> Self;
    /// split a query into its components
    fn into_split(self) -> (Self::Left, Self::Right);
    fn split(&mut self) -> (&mut Self::Left, &mut Self::Right);
}

pub fn async_channel<S, R>(len: usize) -> (AsyncQuery<R, S>, AsyncQuery<S, R>) {
    let (l_sender, l_receiver): (AsyncSender<R>, AsyncReceiver<R>) = tokio_channel(len);
    let (r_sender, r_receiver): (AsyncSender<S>, AsyncReceiver<S>) = tokio_channel(len);
    (
        AsyncQuery {
            sender: l_sender,
            receiver: r_receiver,
        },
        AsyncQuery {
            sender: r_sender,
            receiver: l_receiver,
        },
    )
}
#[derive(Debug)]
pub struct AsyncQuery<S, R> {
    sender: AsyncSender<S>,
    receiver: AsyncReceiver<R>,
}
impl<S, R> AsyncQuery<S, R> {
    pub async fn send(&mut self, data: S) -> Result<(), NetworkError> {
        Ok(self.sender.send(data).await?)
    }
    pub async fn recv(&mut self) -> Option<R> {
        Some(self.receiver.recv().await?)
    }
}
impl<S, R> Query for AsyncQuery<S, R> {
    type Left = AsyncSender<S>;
    type Right = AsyncReceiver<R>;
    fn create(sender: Self::Left, receiver: Self::Right) -> Self {
        Self { sender, receiver }
    }
    fn into_split(self) -> (Self::Left, Self::Right) {
        (self.sender, self.receiver)
    }
    fn split(&mut self) -> (&mut Self::Left, &mut Self::Right) {
        (&mut self.sender, &mut self.receiver)
    }
}
pub fn sync_channel<R, S>() -> (SyncQuery<R, S>, SyncQuery<S, R>) {
    let (l_sender, l_receiver) = channel();
    let (r_sender, r_receiver) = channel();
    (
        SyncQuery {
            sender: l_sender,
            receiver: r_receiver,
        },
        SyncQuery {
            sender: r_sender,
            receiver: l_receiver,
        },
    )
}
#[derive(Debug)]
pub struct SyncQuery<S, R> {
    sender: Sender<S>,
    receiver: Receiver<R>,
}
impl<S, R> SyncQuery<S, R> {
    pub fn send(&mut self, data: S) -> Result<(), NetworkError> {
        Ok(self.sender.send(data)?)
    }
    pub fn recv(&mut self) -> Result<R, NetworkError> {
        Ok(self.receiver.recv()?)
    }
}
impl<S, R> Query for SyncQuery<S, R> {
    type Left = Sender<S>;
    type Right = Receiver<R>;
    fn create(sender: Self::Left, receiver: Self::Right) -> Self {
        Self { sender, receiver }
    }
    fn into_split(self) -> (Self::Left, Self::Right) {
        (self.sender, self.receiver)
    }
    fn split(&mut self) -> (&mut Self::Left, &mut Self::Right) {
        (&mut self.sender, &mut self.receiver)
    }
}

// ================================================================
//                          Tests
// ================================================================
/*#[test]
fn random_string_test(){
    use std::time::SystemTime;
    let time1 = SystemTime::now();
    let first_string = random_string(16);
    assert!(time1.elapsed().unwrap().as_micros() < 400);
}*/
