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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigNum {
    value: Vec<u8>,
}
impl BigNum {
    pub fn from_biguint(biguint: BigUint) -> Self {
        Self {
            value: biguint.to_bytes_be(),
        }
    }
    pub fn to_inner(&self) -> BigUint {
        BigUint::from_bytes_be(&self.value)
    }
    pub fn into_inner(self) -> BigUint {
        BigUint::from_bytes_be(&self.value)
    }
}
impl From<&BigUint> for BigNum {
    fn from(num: &BigUint) -> Self{
        Self {value: num.to_bytes_be()}
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
    pub fn n(&self) -> BigUint {
        self.n.clone().into_inner()
    }
    pub fn e(&self) -> BigUint {
        self.e.clone().into_inner()
    }
}
impl From<&RSAPublicKey> for PubKeyComp {
    fn from(public_key: &RSAPublicKey) -> Self{
        Self::from_parts(BigNum::from(public_key.n()), BigNum::from(public_key.e()))
    }
}
impl From<&RSAPrivateKey> for PubKeyComp {
    fn from(private_key: &RSAPrivateKey) -> Self{
        Self::from(&RSAPublicKey::from(private_key))
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
    pub fn n(&self) -> BigNum {
        self.n.clone()
    }
    pub fn e(&self) -> BigNum {
        self.e.clone()
    }
    pub fn d(&self) -> BigNum {
        self.d.clone()
    }
    pub fn primes(&self) -> Vec<BigNum> {
        self.primes.clone()
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
        let d = BigNum::from_biguint(private_key.d().clone());
        let primes: Vec<BigNum> = private_key
            .primes()
            .iter()
            .map(|p| BigNum::from_biguint(p.clone()))
            .collect();
        let n = BigNum::from_biguint(private_key.n().clone());
        let e = BigNum::from_biguint(private_key.e().clone());
        Ok(Self { n, e, d, primes })
    }
}
impl From<&RSAPrivateKey> for PrivKeyComp {
    fn from(key: &RSAPrivateKey) -> Self {
        let primes = key
            .primes()
            .iter()
            .map(|p| BigNum::from_biguint(p.clone()))
            .collect();
        let d = BigNum::from_biguint(key.d().clone());
        let public_key = RSAPublicKey::from(key);
        let n = BigNum::from_biguint(public_key.n().clone());
        let e = BigNum::from_biguint(public_key.e().clone());
        Self { n, e, d, primes }
    }
}
