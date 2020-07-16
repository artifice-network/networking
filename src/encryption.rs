use crypto::blowfish::Blowfish;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use rsa::{PaddingScheme, PublicKeyParts, RSAPrivateKey, RSAPublicKey, PublicKey};
use std::fmt;
use std::str::FromStr;
use rand::rngs::OsRng;

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
/// usese blowfish symetrical encryption to protect information such as peers, permissions, installed applications, and configs in teh case of a system compromise
/// the intent is not t ohide this information from the user, rather to protect the network in case of a compromise of a peer
/// the implementation of this program wide encryption is such that in order for a user to use the network they must provide a decyption key as a password for the network
pub fn encrypt(key: &[u8], input: &[u8], output_vec: &mut Vec<u8>) {
    //assert!((4 < key.len() <= 56));
    let cap = if input.len() % 8 != 0 {
        input.len() + (8 - (input.len() % 8))
    } else {
        input.len()
    };
    let mut encypt_buffer = Vec::with_capacity(cap);
    encypt_buffer.extend_from_slice(input);
    if input.len() != cap {
        for _ in input.len()..cap {
            encypt_buffer.push(0);
        }
    }
    let blowfish = Blowfish::new(key);
    let mut index = 0;
    while index < cap {
        let mut output: [u8; 8] = [0; 8];
        blowfish.encrypt_block(&encypt_buffer[index..index + 8], &mut output);
        index += 8;
        output_vec.extend_from_slice(&output);
    }
}
/// uses blowfish symetrical decryption so that the program is able to access the installation information for artifice
pub fn decrypt(key: &[u8], input: &[u8], output_vec: &mut Vec<u8>) {
    assert!(input.len() % 8 == 0);
    let blowfish = Blowfish::new(key);
    let cap = input.len();
    let mut index = 0;
    while index < cap {
        let mut output: [u8; 8] = [0; 8];
        blowfish.decrypt_block(&input[index..index + 8], &mut output);
        index += 8;
        output_vec.extend_from_slice(&output);
    }
}
pub fn rsa_decrypt(
    priv_key: &RSAPrivateKey,
    enc_data: &[u8],
    data_len: usize,
) -> Result<Vec<u8>, rsa::errors::Error> {
    println!("in_data len: {}", data_len);
    let mut dec_data = Vec::new();
    let mut dec = 0;
    while dec < data_len {
        let start = dec;
        let end = if dec + 256 > data_len {
            dec = data_len;
            data_len
        } else {
            dec += 256;
            dec
        };
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        println!("decrypting, start: {}, end: {}", start, end);
        
        dec_data.append(
            &mut priv_key
                .decrypt(padding, &enc_data[start..end])
                .expect("failed to decrypt"),
        );
    }
    //std::thread::sleep(std::time::Duration::from_millis(100));
    println!("dec_data len: {}", dec_data.len());
    Ok(dec_data)
}
pub fn rsa_encrypt(public_key: &RSAPublicKey, data: &[u8]) -> Result<Vec<u8>, rsa::errors::Error> {
    let mut rng = OsRng;
    let mut index = 0;
    let mut enc_data = Vec::new();
    while index < data.len() {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let start = index;
        let end = if index + 245 > data.len() {
            index += data.len();
            data.len()
        } else {
            index += 245;
            index
        };
        println!("enc_len: {}", enc_data.len());
        enc_data.append(
            &mut public_key
                .encrypt(&mut rng, padding, &data[start..end])
                .expect("failed to encrypt"),
        );
    }
    Ok(enc_data)
}

use num_bigint_dig::BigUint;
use serde::{
    de::{self, Deserialize, Deserializer, Visitor},
    ser::{Serialize, Serializer},
};
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
    pub fn into_inner(&self) -> BigUint {
        BigUint::from_bytes_be(&self.value)
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
pub struct PubKeyPair {
    n: BigNum,
    e: BigNum,
}
impl PubKeyPair {
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
/// private key version of PubKeyPair
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
        use rand::rngs::OsRng;

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
