use crate::error::NetworkError;
use crate::StreamHeader;
use crypto::{
    aessafe::{AesSafe128DecryptorX8, AesSafe128EncryptorX8},
    symmetriccipher::{BlockDecryptorX8, BlockEncryptorX8},
};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
// ==================================================================================
//                               AES Encryption
// =================================================================================
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
    let mut index = 0;
    let encryptor = AesSafe128EncryptorX8::new(header.key());
    header.set_remander(rem);
    // make sure data length is tracted in case multiple packets are sent at the same time
    header.set_packet_len(data.len());
    // convert header to binary, should only be of length 126, 50 byte global hash, 50 byte peer hash, 16 bytes aes key, 8 bytes data len, 1 byte remander len
    let key = header.to_raw();
    println!("header len: {}", key.len());
    assert!(key.len() < 246);
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    // use rsa to encrypt the aes key
    let mut enc_key = pub_key.encrypt(&mut rng, padding, &key)?;
    output.append(&mut enc_key);
    let full_len = input.len() + rem as usize;
    while index < full_len {
        let mut read_data: [u8; 128] = [0; 128];
        // encrypt in sections of 8 blocks, each block having 16 bytes for a total of 128 bytes
        encryptor.encrypt_block_x8(&data[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
        index += 128;
    }
    //output.append(&mut outvec);
    Ok(output)
}
pub fn aes_inplace_decrypt(
    priv_key: &RSAPrivateKey,
    input: &mut Vec<u8>,
) -> Result<StreamHeader, NetworkError> {
    println!("function called");
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let header = StreamHeader::from_raw(&priv_key.decrypt(padding, &input[0..256])?)?;
    let rem = header.remander();
    let data_len = header.packet_len();
    let decryptor = AesSafe128DecryptorX8::new(header.key());
    let mut index = 0;
    //let mut read_data: [u8; 128] = [0; 128];
    while index < data_len {
        let (outbuf, inbuf) = input.split_at_mut(index + 256);
        decryptor.decrypt_block_x8(&inbuf[0..128], &mut outbuf[index..index + 128]);
        index = index + 128;
    }
    input.truncate(input.len() - (rem as usize + 256));
    println!("len: {}", input.len());
    //assert_eq!(String::from_utf8(input), instr.to_string());
    Ok(header)
}
// ===============================================================================
//                          AES Decryption
// ================================================================================
pub fn asym_aes_decrypt(
    priv_key: &RSAPrivateKey,
    input: &[u8],
) -> Result<(Vec<u8>, StreamHeader), NetworkError> {
    assert!(input.len() < (65537));
    // create output vector
    let mut output = Vec::new();
    // decrypt the StreamHeader
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let mut header = StreamHeader::from_raw(&priv_key.decrypt(padding, &input[0..256])?)?;
    let rem = header.remander();
    let data_len = header.packet_len();
    let decryptor = AesSafe128DecryptorX8::new(header.key());
    let mut index = 256;
    let mut read_data: [u8; 128] = [0; 128];
    while index < data_len + 256 {
        decryptor.decrypt_block_x8(&input[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
        index += 128;
    }
    let newlen = output.len() - (rem as usize);
    output.truncate(newlen);
    if (data_len - rem as usize) < newlen {
        let (next_packet, stream_header) =
            asym_aes_decrypt(priv_key, &input[data_len..input.len()])?;
        header = stream_header;
        output.extend_from_slice(&next_packet);
    }
    Ok((output, header))
}
pub fn sym_aes_decrypt(key: &[u8], outbuf: &mut Vec<u8>){
    if outbuf.len() == 0 {return}
    let remander = outbuf[0];
    let decryptor = AesSafe128DecryptorX8::new(key);
    let mut index = 0;
    let mut temp_vec = Vec::with_capacity(128);
    while index < outbuf.len() {
        temp_vec.extend_from_slice(&outbuf[index..index+128]);
        decryptor.decrypt_block_x8(&temp_vec, &mut outbuf[index..128]);
        temp_vec.clear();
        index += 128;
    }
    outbuf.truncate(outbuf.len() - remander as usize);
}
// =============================================================================
//                              Tests
// =============================================================================
#[test]
fn encrypt_test() {
    use std::time::SystemTime;
    let time = SystemTime::now();
    use crate::random_string;
    let stream_header = StreamHeader::new(&random_string(50), &random_string(50), 0);
    let private_key = crate::get_private_key();
    let public_key = RSAPublicKey::from(&private_key);
    let instr = random_string(65535 - 256);
    let indata = instr.clone().into_bytes();
    println!("meta data len: {}", indata.len());
    //let mut outvec = Vec::new();
    let mut outvec = asym_aes_encrypt(&public_key, stream_header, &indata).unwrap();
    aes_inplace_decrypt(&private_key, &mut outvec).unwrap();
    assert_eq!(indata.len(), outvec.len());
    assert_eq!(indata, outvec);
    let elapsed = time.elapsed().unwrap().as_millis();
    println!("{}", elapsed);
    assert!(200 > elapsed);
}
