use num_bigint_dig::BigUint;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::fmt;

use crate::error::NetworkError;
use crate::{StreamHeader};
use crypto::{
    aessafe::{AesSafe128DecryptorX8, AesSafe128EncryptorX8},
    symmetriccipher::{BlockDecryptorX8, BlockEncryptorX8},
};

/// the purpose of this structure is to provide an implementation of BigUint, as is used by the rsa crate, that can be serialized for the sake of storing an retriving rsa keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BigNum {
    value: Vec<u8>,
}
impl BigNum {
    pub fn to_string_unstable(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.value.clone()) }
    }
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
    fn eq(&self, other: &BigUint) -> bool {
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
    fn eq(&self, pubkey: &RSAPublicKey) -> bool {
        self.n == *pubkey.n() && self.e == *pubkey.e()
    }
}
impl PartialEq<PubKeyComp> for RSAPublicKey {
    fn eq(&self, pubkey: &PubKeyComp) -> bool {
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
    fn from(priv_key: &PrivKeyComp) -> Self {
        Self {
            n: priv_key.n().to_owned(),
            e: priv_key.e().to_owned(),
        }
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

// ==================================================================================
//                               AES Encryption
// =================================================================================

/// view the header for the packet, without decrypting anything else
pub fn header_peak(key: &[u8], input: &[u8]) -> Result<StreamHeader, NetworkError> {
    let decryptor = AesSafe128DecryptorX8::new(key);
    let mut header_vec = Vec::with_capacity(128);
    unsafe { header_vec.set_len(128) }
    // decrypt the StreamHeader
    decryptor.decrypt_block_x8(&input[0..128], &mut header_vec);
    let remote_header = StreamHeader::from_raw_padded(&header_vec)?;
    Ok(remote_header)
}

/// uses rsa to encrypt an aes key, that is used to encrypt the main body of the data
pub fn asym_aes_encrypt(
    pub_key: &RSAPublicKey,
    mut header: StreamHeader,
    input: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    assert!(input.len() < (65536));
    // returned from the function
    let mut output = Vec::new();
    // used in rsa encryption
    let mut rng = OsRng;
    // vector containing input data
    let mut data = Vec::new();
    data.extend_from_slice(&input);
    // ensure data can be modulated by 128
    let rem: u8 = 128 - ((input.len() % 128) as u8);
    let mut aes_padding = Vec::with_capacity(rem as usize);
    unsafe {
        aes_padding.set_len(rem as usize);
    }
    // place padding in the input vector
    data.append(&mut aes_padding);
    assert_eq!(data.len() % 128, 0);
    let encryptor = AesSafe128EncryptorX8::new(header.key());
    header.set_remander(rem);
    // make sure data length is tracted in case multiple packets are sent at the same time
    header.set_packet_len(data.len());
    // convert header to binary, should only be of length 126, 50 byte global hash, 50 byte peer hash, 16 bytes aes key, 8 bytes data len, 1 byte remander len
    let key = header.to_raw();
    assert!(key.len() < 246);
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    // use rsa to encrypt the aes key
    let mut enc_key = pub_key.encrypt(&mut rng, padding, &key)?;
    output.append(&mut enc_key);
    let full_len = input.len() + rem as usize;
    for index in (0..full_len).step_by(128) {
        let mut read_data: [u8; 128] = [0; 128];
        // encrypt in sections of 8 blocks, each block having 16 bytes for a total of 128 bytes
        encryptor.encrypt_block_x8(&data[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
    }
    Ok(output)
}
/*pub fn aes_inplace_decrypt(
    priv_key: &RSAPrivateKey,
    input: &mut Vec<u8>,
) -> Result<StreamHeader, NetworkError> {
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let header = StreamHeader::from_raw(&priv_key.decrypt(padding, &input[0..256])?)?;
    let rem = header.remander();
    let data_len = header.packet_len();
    let decryptor = AesSafe128DecryptorX8::new(header.key());
    //let mut read_data: [u8; 128] = [0; 128];
    for index in (0..data_len).step_by(128) {
        let (outbuf, inbuf) = input.split_at_mut(index + 256);
        decryptor.decrypt_block_x8(&inbuf[0..128], &mut outbuf[index..index + 128]);
    }
    input.truncate(input.len() - (rem as usize + 256));
    //assert_eq!(String::from_utf8(input), instr.to_string());
    Ok(header)
}*/
// ===============================================================================
//                          AES Decryption
// ================================================================================
pub fn asym_aes_decrypt(
    priv_key: &RSAPrivateKey,
    input: &[u8],
) -> Result<(Vec<u8>, StreamHeader), NetworkError> {
    //assert!(input.len() < (65537));
    // create output vector
    let mut output = Vec::new();
    // decrypt the StreamHeader
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let mut header = StreamHeader::from_raw(&priv_key.decrypt(padding, &input[0..256])?)?;
    println!("header: {:?}", header);
    let rem = header.remander();
    let data_len = header.packet_len();
    println!("packet len in asym: {}", data_len);
    let decryptor = AesSafe128DecryptorX8::new(header.key());
    let mut read_data: [u8; 128] = [0; 128];
    for index in (256..data_len + 256).step_by(128) {
        decryptor.decrypt_block_x8(&input[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
    }
    let newlen = output.len() - (rem as usize);
    output.truncate(newlen);
    if (newlen + rem as usize + 256) < input.len() {
        let (next_packet, stream_header) =
            asym_aes_decrypt(priv_key, &input[data_len + 256..input.len()])?;
        header = stream_header;
        output.extend_from_slice(&next_packet);
    }
    Ok((output, header))
}
/// decrypt using last byte as indicator of padding
pub fn simple_aes_decrypt(key: &[u8], outbuf: &mut Vec<u8>) {
    if outbuf.is_empty() || key.is_empty() {
        return;
    }
    let remander = outbuf[outbuf.len() - 1];
    let decryptor = AesSafe128DecryptorX8::new(key);
    let mut temp_vec = Vec::with_capacity(128);
    outbuf.truncate(outbuf.len() - 1);
    for index in (0..outbuf.len()).step_by(128) {
        unsafe { temp_vec.set_len(128) }
        decryptor.decrypt_block_x8(&outbuf[index..index + 128], &mut temp_vec[0..128]);
        std::io::copy(&mut &temp_vec[..], &mut &mut outbuf[index..index + 128]).unwrap();
        temp_vec.clear();
    }
    outbuf.truncate(outbuf.len() - remander as usize);
}
/// encrypt and put padding on the end as unencrypted 8bit integer
pub fn simple_aes_encrypt(key: &[u8], outbuf: &mut Vec<u8>) {
    if outbuf.is_empty() || key.is_empty() {
        return;
    }
    let remander = 128 - (outbuf.len() % 128);
    let encryptor = AesSafe128EncryptorX8::new(key);
    let mut temp_vec = Vec::with_capacity(128);
    let mut rem_vec = Vec::with_capacity(remander);
    unsafe { rem_vec.set_len(remander) };
    outbuf.extend_from_slice(&rem_vec);
    for index in (0..outbuf.len()).step_by(128) {
        temp_vec.extend_from_slice(&outbuf[index..index + 128]);
        encryptor.encrypt_block_x8(&temp_vec, &mut outbuf[index..index + 128]);
        temp_vec.clear();
    }
    outbuf.push(remander as u8);
}
/// used tp encrypt outgoing network data, setting remander, and packet len for outgoing packet
pub fn sym_aes_encrypt(header_ref: &StreamHeader, input: &[u8]) -> Vec<u8> {
    let mut header = header_ref.clone();
    let mut output = Vec::new();
    let remander: u8 = 128 - (input.len() % 128) as u8;
    let mut rem_vec = Vec::with_capacity(remander as usize);
    unsafe { rem_vec.set_len(remander as usize) }
    let key = header.key();
    let encryptor = AesSafe128EncryptorX8::new(key);
    let mut data = Vec::with_capacity(input.len() + 128);
    header.set_packet_len(input.len());
    header.set_remander(remander);
    let header_vec = header.to_raw_padded();
    println!("header vec len: {}", header_vec.len());
    data.extend_from_slice(&header_vec);
    data.extend_from_slice(input);
    data.extend_from_slice(&rem_vec);
    let full_len = input.len();
    for index in (0..full_len + 128).step_by(128) {
        let mut read_data: [u8; 128] = [0; 128];
        // encrypt in sections of 8 blocks, each block having 16 bytes for a total of 128 bytes
        encryptor.encrypt_block_x8(&data[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
    }
    output
}
/// used to decrypt incoming network data of length and remander stored in packet.
/// this also keeps track of which peer sent it, in case that came into question
pub fn sym_aes_decrypt(
    header: &StreamHeader,
    input: &[u8],
) -> Result<(Vec<u8>, StreamHeader, Vec<usize>), NetworkError> {
    println!("sym decrypt");
    let mut indexes = Vec::new();
    let decryptor = AesSafe128DecryptorX8::new(header.key());
    let mut header_vec = Vec::with_capacity(128);
    unsafe { header_vec.set_len(128) }
    // create output vector
    let mut output = Vec::new();
    // decrypt the StreamHeader
    decryptor.decrypt_block_x8(&input[0..128], &mut header_vec);
    let remote_header = StreamHeader::from_raw_padded(&header_vec)?;
    let rem = remote_header.remander();
    let data_len = remote_header.packet_len();
    let mut read_data: [u8; 128] = [0; 128];
    for index in (128..data_len + 128).step_by(128) {
        decryptor.decrypt_block_x8(&input[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
    }
    let newlen = output.len() - (rem as usize);
    output.truncate(newlen);
    indexes.push(data_len);
    if (newlen + rem as usize + 128) < input.len() {
        let (next_packet, second_header, rec_indexes) =
            sym_aes_decrypt(header, &input[data_len + (rem as usize) + 128..input.len()])?;
        indexes.extend_from_slice(&rec_indexes);
        output.extend_from_slice(&next_packet);
        if second_header.peer_hash() != remote_header.peer_hash() {
            return Err(NetworkError::ConnectionDenied(
                "headers don't match in decryption".to_string(),
            ));
        }
    }
    Ok((output, remote_header, indexes))
}

// =============================================================================
//                              Tests
// =============================================================================
/*#[test]
fn sym_encrypt_test() {
    use crate::random_string;
    use rand::Rng;
    use std::time::SystemTime;
    for _ in 0..100 {
        let time = SystemTime::now();
        let mut rng = rand::thread_rng();
        let ffloat: f64 = rng.gen();
        let instr = random_string((ffloat * 65410f64) as usize);
        let key = random_string(16).into_bytes();
        let mut inbuf = instr.clone().into_bytes();
        let peer_hash = NetworkHash::generate();
        let global_hash = NetworkHash::generate();
        let mut header =
            StreamHeader::with_key(&global_hash, &peer_hash, key.clone(), inbuf.len());
        let mut output = sym_aes_encrypt(&mut header, &mut inbuf);
        let sfloat: f64 = rng.gen();
        let second_str = random_string((sfloat * 65410f64) as usize);
        let mut second_buf = second_str.clone().into_bytes();
        let mut second_header =
            StreamHeader::with_key(&global_hash, &peer_hash, key, second_buf.len());
        output.extend_from_slice(&sym_aes_encrypt(&mut second_header, &mut second_buf));
        let (inbuf, _stream_header, indexes) = sym_aes_decrypt(&header, &output).unwrap();
        let remstr = instr.into_bytes();
        let remsecstr = second_str.into_bytes();
        assert_eq!(remstr.len(), *indexes.get(0).unwrap());
        assert_eq!(remstr, inbuf[0..*indexes.get(0).unwrap()].to_vec());
        assert_eq!(remsecstr.len(), *indexes.get(1).unwrap());
        assert_eq!(
            remsecstr[0..256].to_vec(),
            inbuf[*indexes.get(0).unwrap()..*indexes.get(0).unwrap() + 256].to_vec()
        );
        let elapsed = time.elapsed().unwrap().as_millis();
        println!("elapsed: {}", elapsed);
        assert!(500 > elapsed);
    }
}*/
#[test]
fn asym_encrypt_test() {
    use std::time::SystemTime;
    use crate::NetworkHash;
    let time = SystemTime::now();
    use crate::random_string;
    let peer_hash = NetworkHash::generate();
    let global_hash = NetworkHash::generate();
    let stream_header = StreamHeader::new(&global_hash, &peer_hash, 0);
    let private_key = crate::get_private_key();
    let public_key = RSAPublicKey::from(&private_key);
    let instr = random_string(65535 - 256);
    let indata = instr.clone().into_bytes();
    let mut outvec = asym_aes_encrypt(&public_key, stream_header.clone(), &indata).unwrap();
    let second_string = random_string(353);
    let secindata = second_string.clone().into_bytes();
    outvec.extend_from_slice(&asym_aes_encrypt(&public_key, stream_header, &secindata).unwrap());
    let (outvec, _header) = asym_aes_decrypt(&private_key, &mut outvec).unwrap();
    //assert_eq!(indata.len(), outvec.len());
    assert_eq!(indata, outvec[0..indata.len()].to_vec());
    assert_eq!(
        second_string.into_bytes(),
        outvec[indata.len()..outvec.len()].to_vec()
    );
    let elapsed = time.elapsed().unwrap().as_millis();
    println!("{}", elapsed);
    assert!(600 > elapsed);
}
