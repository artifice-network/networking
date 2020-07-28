use crypto::digest::Digest;
use crypto::sha3::Sha3;
use num_bigint_dig::BigUint;
use rand::rngs::OsRng;
use rsa::{PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::fmt;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter;

/// used to generate things such as pair keys, and global peer hash, see ArtificePeer
pub fn random_string(len: usize) -> String {
    let mut rng = thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(len)
        .collect()
}

/// used to encrypt password and generate a key that can be used to encrypt, and decrypt data
pub fn generate_key(password: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3::sha3_256();
    hasher.input(password);
    let mut retvec = Vec::new();
    hasher.result(&mut retvec);
    retvec
}

/*pub async fn async_rsa_encrypt(public_key: RSAPublicKey, data: &[u8]) -> Result<Vec<u8>, rsa::errors::Error>{

}*/

/// the purpose of this structure is to provide an implementation of BigUint, as is used by the rsa crate, that can be serialized for the sake of storing an retriving rsa keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BigNum {
    value: Vec<u8>,
}
impl From<&BigUint> for BigNum {
    fn from(num: &BigUint) -> Self {
        Self {
            value: num.to_bytes_be(),
        }
    }
}
impl From<&BigNum> for BigUint {
    fn from(num: &BigNum) -> Self {
        BigUint::from_bytes_be(&num.value)
    }
}
impl PartialEq<BigUint> for BigNum {
    fn eq(&self, other: &BigUint) -> bool{
        self.value == other.to_bytes_be()
    }
}
impl PartialEq<BigNum> for BigUint {
    fn eq(&self, other: &BigNum) -> bool {
        self.to_bytes_be() == other.value
    }
}

impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.value)
    }
}
/// this struct is used within ArtificePeer, that is transmittted over then network so as to provide the public key of the peer to the hsot
/// like BigNum, this is an abstraction of RSAPublicKey that can be serialized using the serde crate
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PubKeyComp {
    n: BigNum,
    e: BigNum,
}
impl PubKeyComp {
    pub fn from_parts(n: BigNum, e: BigNum) -> Self {
        Self { n, e }
    }
    pub fn n(&self) -> &BigNum {
        &self.n
    }
    pub fn e(&self) -> &BigNum {
        &self.e
    }
}
impl PartialEq<RSAPublicKey> for PubKeyComp {
    fn eq(&self, pubkey: &RSAPublicKey) -> bool{
        self.n == *pubkey.n() && self.e == *pubkey.e()
    }
}
impl PartialEq<PubKeyComp> for RSAPublicKey {
    fn eq(&self, pubkey: &PubKeyComp) -> bool{
        *self.n() == pubkey.n && *self.e() == pubkey.e
    }
}
impl From<&RSAPublicKey> for PubKeyComp {
    fn from(public_key: &RSAPublicKey) -> Self {
        Self::from_parts(BigNum::from(public_key.n()), BigNum::from(public_key.e()))
    }
}
impl From<&RSAPrivateKey> for PubKeyComp {
    fn from(private_key: &RSAPrivateKey) -> Self {
        Self::from(&RSAPublicKey::from(private_key))
    }
}
impl From<&PrivKeyComp> for PubKeyComp {
    fn from(priv_key: &PrivKeyComp) -> Self{
        Self { n: priv_key.n().to_owned(), e: priv_key.e().to_owned()}
    }
}
/// private key version of PubKeyComp
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivKeyComp {
    n: BigNum,
    e: BigNum,
    d: BigNum,
    primes: Vec<BigNum>,
}
impl PrivKeyComp {
    pub fn n(&self) -> &BigNum {
        &self.n
    }
    pub fn e(&self) -> &BigNum {
        &self.e
    }
    pub fn d(&self) -> &BigNum {
        &self.d
    }
    pub fn primes(&self) -> &Vec<BigNum> {
        &self.primes
    }
    pub fn into_components(self) -> (BigNum, BigNum, BigNum, Vec<BigNum>) {
        (self.n, self.e, self.d, self.primes)
    }
    /// used to create the key (should only be run once per host owing to the long execution time)
    /// designed for use in the installer only
    pub fn generate() -> rsa::errors::Result<Self> {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RSAPrivateKey::new(&mut rng, bits)?;
        let d = BigNum::from(private_key.d());
        let primes: Vec<BigNum> = private_key
            .primes()
            .iter()
            .map(|p| BigNum::from(p))
            .collect();
        let n = BigNum::from(private_key.n());
        let e = BigNum::from(private_key.e());
        Ok(Self { n, e, d, primes })
    }
}
impl From<&RSAPrivateKey> for PrivKeyComp {
    fn from(key: &RSAPrivateKey) -> Self {
        let primes = key.primes().iter().map(|p| BigNum::from(p)).collect();
        let d = BigNum::from(key.d());
        let public_key = RSAPublicKey::from(key);
        let n = BigNum::from(public_key.n());
        let e = BigNum::from(public_key.e());
        Self { n, e, d, primes }
    }
}
impl From<&PrivKeyComp> for RSAPrivateKey {
    fn from(comp: &PrivKeyComp) -> RSAPrivateKey {
        RSAPrivateKey::from_components(
            comp.n().into(),
            comp.e().into(),
            comp.d().into(),
            comp.primes.iter().map(|p| BigUint::from(p)).collect(),
        )
    }
}
