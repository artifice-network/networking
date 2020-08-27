use aes_soft::{Aes128, BlockCipher, NewBlockCipher};
use num_bigint_dig::BigUint;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::fmt;

use crate::NetworkError;
use crate::{StreamHeader, NetworkHash};

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
    /// constructs the public key from n, and e
    pub fn from_parts(n: BigNum, e: BigNum) -> Self {
        Self { n, e }
    }
    /// returns the modulus of the public key
    pub fn n(&self) -> &BigNum {
        &self.n
    }
    /// returns the exponent of the public key
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
    /// returns the public key modulus
    pub fn n(&self) -> &BigNum {
        &self.n
    }
    /// returns the exponent
    pub fn e(&self) -> &BigNum {
        &self.e
    }
    /// returns the private key modulus
    pub fn d(&self) -> &BigNum {
        &self.d
    }
    /// returns the root primes, from which totient of pg, d, and n are derived
    pub fn primes(&self) -> &Vec<BigNum> {
        &self.primes
    }
    /// returns all data in the structure
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
    let decryptor = Aes128::new(key);
    let mut header_vec = Vec::with_capacity(128);
    header_vec.extend_from_slice(&input[0..128]);
    // decrypt the StreamHeader
    decryptor.decrypt_blocks(&mut header_vec);
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
    let encryptor = Aes128::new(header.key());
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
        // encrypt in sections of 8 blocks, each block having 16 bytes for a total of 128 bytes
        encryptor.encrypt_blocks(&mut data[index..index + 128]);
        output.extend_from_slice(&data[index..index + 128]);
    }
    Ok(output)
}
// ===============================================================================
//                          AES Decryption
// ================================================================================
/// uses rsa private key to decrypt data, returning the decrypted data
pub fn asym_aes_decrypt(
    priv_key: &RSAPrivateKey,
    input: &mut [u8],
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
    let decryptor = Aes128::new(header.key());
    for index in (256..data_len + 256).step_by(128) {
        decryptor.decrypt_blocks(&mut input[index..index + 128]);
        output.extend_from_slice(&input[index..index+128]);
    }
    let newlen = output.len() - (rem as usize);
    output.truncate(newlen);
    if (newlen + rem as usize + 256) < input.len() {
        let the_len = input.len();
        let (next_packet, stream_header) =
            asym_aes_decrypt(priv_key, &mut input[data_len + 256..the_len])?;
        header = stream_header;
        output.extend_from_slice(&next_packet);
    }
    Ok((output, header))
}
/// decrypt using last byte as indicator of padding
#[deprecated(since = "0.2.0", note = "please use sym_inplace_decrypt instead")]
pub fn simple_aes_decrypt(key: &[u8], outbuf: &mut Vec<u8>) {
    if outbuf.is_empty() || key.is_empty() {
        return;
    }
    let header = StreamHeader::with_key(&NetworkHash::generate(), &NetworkHash::generate(), key.to_vec(), 0);
    sym_inplace_encrypt(&header, outbuf);
}
/// encrypt and put padding on the end as unencrypted 8bit integer
#[deprecated(since = "0.2.0", note = "please use sym_inplace_encrypt instead")]
pub fn simple_aes_encrypt(key: &[u8], outbuf: &mut Vec<u8>) {
    if outbuf.is_empty() || key.is_empty() {
        return;
    }
    let header = StreamHeader::with_key(&NetworkHash::generate(), &NetworkHash::generate(), key.to_vec(), 0);
    sym_inplace_encrypt(&header, outbuf);
}
/// used to encrypt outgoing network data, setting remander, and packet len for outgoing packet
#[deprecated(since = "0.2.0", note = "please use sym_inplace_encrypt instead")]
pub fn sym_aes_encrypt(header_ref: &StreamHeader, input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(input);
    sym_inplace_encrypt(header_ref, &mut output);
    output
}
/// used to decrypt incoming network data of length and remander stored in packet.
/// this also keeps track of which peer sent it, in case that came into question
#[deprecated(since = "0.2.0", note = "please use sym_inplace_decrypt instead")]
pub fn sym_aes_decrypt(
    header: &StreamHeader,
    input: &mut [u8],
) -> Result<(Vec<u8>, StreamHeader, Vec<usize>), NetworkError> {
    let mut output = Vec::new();
    output.extend_from_slice(input);
    let (mut headers, indexes) = sym_inplace_decrypt(header, &mut output)?;
    Ok((output, headers.pop().unwrap(), indexes))
}

// =============================================================================
//                              Tests
// =============================================================================
#[test]
fn sym_encrypt_test() {
    use crate::random_string;
    use crate::NetworkHash;
    use rand::Rng;
    use std::time::SystemTime;
    let mut avg = 0;
    for _ in 0..100 {
        // start timer
        let time = SystemTime::now();
        let mut rng = rand::thread_rng();

        // create first random test data
        let random_0: usize = rng.gen();
        let instr = random_string((random_0 % 62432) + 256);
        let mut inbuf = instr.clone().into_bytes();

        // create aes key
        let key = random_string(16).into_bytes();

        // create identity of StreamHeaders
        let peer_hash = NetworkHash::generate();
        let global_hash = NetworkHash::generate();
        let mut header = StreamHeader::with_key(&global_hash, &peer_hash, key.clone(), inbuf.len());

        sym_inplace_encrypt(&mut header, &mut inbuf);

        // generate second test data
        let random_1: usize = rng.gen();
        let second_str = random_string((random_1 % 65410) + 256);
        let mut second_buf = second_str.clone().into_bytes();
        let mut second_header =
            StreamHeader::with_key(&global_hash, &peer_hash, key, second_buf.len());
        sym_inplace_encrypt(&mut second_header, &mut second_buf);

        // concat the two packets
        inbuf.extend_from_slice(&second_buf);

        // decrypt into inbuf
        let (_headers, indexes) = sym_inplace_decrypt(&header, &mut inbuf).unwrap();
        let remstr = instr.into_bytes();

        /*let mut trans_vec = inbuf.clone();
        let hashes: Vec<u128> = unsafe {
            let (ptr, len, cap) = trans_vec.into_raw_parts();
            Vec::from_raw_parts(ptr as *mut u128, len, cap)
        };
        let matches: Vec<NetworkHash> = hashes.into_iter().map(|h| {NetworkHash::from(h)}).filter(|h| {*h == global_hash}).collect();
        println!("matches: {:?}", matches);
        assert_eq!(matches.len(), 5);*/

        println!("global hash: {}\n\n\n\n", global_hash);
        let remsecstr = second_str.into_bytes();
        println!("remsecstr len: {}", remsecstr.len());
        println!("indexes: {:?}", indexes);
        assert_eq!(remstr.len(), *indexes.get(0).unwrap());
        assert_eq!(remstr, inbuf[0..*indexes.get(0).unwrap()].to_vec());
        assert_eq!(remsecstr.len(), *indexes.get(1).unwrap());
        assert_eq!(
            remsecstr[0..256].to_vec(),
            inbuf[*indexes.get(0).unwrap()..*indexes.get(0).unwrap() + 256].to_vec()
        );
        let elapsed = time.elapsed().unwrap().as_millis();
        avg += elapsed;
        println!("elapsed: {}", elapsed);
        assert!(200 > elapsed);
    }
    avg = avg / 100;
    assert!(avg < 150);
}
#[test]
fn asym_encrypt_test() {
    use crate::NetworkHash;
    use std::time::SystemTime;
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
/// in place encryption, vector instead of slice is used in case buffer is to small
// this lint is used here because what is being done, can't fail, but the compiler doesn't know that
#[allow(unused_must_use)]
pub fn sym_inplace_encrypt(header: &StreamHeader, data: &mut Vec<u8>) {
    // create padding and space for header
    let mut owned_header = header.clone();
    owned_header.set_packet_len(data.len());
    let remander: u8 = 128 - (data.len() % 128) as u8;
    owned_header.set_remander(remander);
    println!("header in encrypt: {:?}\n\n\n\n", owned_header);
    let header_vec = owned_header.to_raw_padded();

    // add created padding and header
    let mut remvec = Vec::with_capacity(128 + (remander as usize));
    unsafe { remvec.set_len(128 + (remander as usize)) }
    data.extend_from_slice(&remvec);
    data.rotate_right(128);
    std::io::copy(&mut header_vec.as_slice(), &mut &mut data[0..128]);//.unwrap();

    // create the encryptor
    let encryptor = Aes128::new(header.key());

    for index in (0..data.len()).step_by(128) {
        encryptor.encrypt_blocks(&mut data[index..index + 128]);
    }
}
/// in place decryption, vector instead of slice is used in case the buffer is to small
pub fn sym_inplace_decrypt(
    header: &StreamHeader,
    data: &mut Vec<u8>,
) -> Result<(Vec<StreamHeader>, Vec<usize>), NetworkError> {
    assert_eq!(data.len() % 128, 0);
    let decryptor = Aes128::new(header.key());

    for index in (0..data.len()).step_by(128) {
        decryptor.decrypt_blocks(&mut data[index..index + 128]);
    }

    let remote_header = StreamHeader::from_raw_padded(&data[0..128])?;
    let mut packet_len = 0;//remote_header.packet_len();
    let mut remander = 0;//remote_header.remander() as usize;
    //data.drain(0..128);
    let mut indexes = Vec::new();
    let mut headers = Vec::new();
    //indexes.push(remote_header.packet_len());
    println!("remote_header: {:?}\n\n\n\n", remote_header);
    headers.push(remote_header);

    while packet_len + remander < data.len() {
        let new_header = StreamHeader::from_raw_padded(&data[packet_len+remander..packet_len +remander + 128])?;
        println!("new_header: {:?}\n\n\n\n", new_header);
        println!("packet_len: {}, remander: {}\n\n", packet_len, remander);
        data.drain(packet_len..packet_len + 128 + remander);
        remander = new_header.remander() as usize;
        indexes.push(new_header.packet_len());
        packet_len += new_header.packet_len();
        headers.push(new_header);
    }
    Ok((headers, indexes))
}