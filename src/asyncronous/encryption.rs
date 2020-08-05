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
pub fn aes_inplace_decrypt(
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
    let mut read_data: [u8; 128] = [0; 128];
    for index in (256..data_len + 256).step_by(128) {
        decryptor.decrypt_block_x8(&input[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
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
pub fn database_aes_decrypt(key: &[u8], outbuf: &mut Vec<u8>) {
    if outbuf.is_empty() || key.is_empty() {
        return;
    }
    let remander = outbuf[outbuf.len() - 1];
    let decryptor = AesSafe128DecryptorX8::new(key);
    let mut temp_vec = Vec::with_capacity(128);
    outbuf.truncate(outbuf.len() - 1);
    println!("entering decrypt loop");
    for index in (0..outbuf.len()).step_by(128) {
        unsafe { temp_vec.set_len(128) }
        decryptor.decrypt_block_x8(&outbuf[index..index + 128], &mut temp_vec[0..128]);
        std::io::copy(&mut &temp_vec[..], &mut &mut outbuf[index..index + 128]).unwrap();
        temp_vec.clear();
    }
    outbuf.truncate(outbuf.len() - remander as usize);
}
pub fn database_aes_encrypt(key: &[u8], outbuf: &mut Vec<u8>) {
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
pub fn sym_aes_encrypt(header: &mut StreamHeader, outbuf: &mut Vec<u8>) {
    let remander = 128 - (outbuf.len() % 128);
    let key = header.key();
    let encryptor = AesSafe128EncryptorX8::new(key);
    let mut rem_vec = Vec::with_capacity(remander + 128);
    unsafe { rem_vec.set_len(remander + 128) };
    outbuf.extend_from_slice(&rem_vec);
    println!("before encrypt loop, len: {}", outbuf.len());
    for index in (0..outbuf.len() - 128).step_by(128) {
        let (input, output) = outbuf.split_at_mut(index + 128);
        println!(
            "input len: {}, output len: {}, index: {}",
            input.len(),
            output.len(),
            index
        );
        encryptor.encrypt_block_x8(&input[index..index + 128], &mut output[0..128]);
    }
    header.set_remander(remander as u8);
    encryptor.encrypt_block_x8(&header.to_raw_padded(), &mut outbuf[0..128]);
}
pub fn sym_aes_decrypt(
    header: &StreamHeader,
    outbuf: &mut Vec<u8>,
    start: usize,
) -> Result<Vec<usize>, NetworkError> {
    println!("in decrypt, start: {}",start);
    let mut indexes = Vec::new();
    let key = header.key();
    let mut header_vec = Vec::with_capacity(128);
    unsafe { header_vec.set_len(128) };
    let decryptor = AesSafe128DecryptorX8::new(key);
    decryptor.decrypt_block_x8(&outbuf[start..start + 128], &mut header_vec);
    let remote_header = StreamHeader::from_raw_padded(&header_vec)?;
    let remander = remote_header.remander();
    let packet_len = remote_header.packet_len();
    println!("entering decrypt loop");
    for index in (start..(start + packet_len + remander as usize)).step_by(128) {
        println!("decrypting at index: {}, outbuf: {}, packet_len: {}", index, outbuf.len(), packet_len);
        let (input, output) = outbuf.split_at_mut(index + 128);
        let orig = output[0..128].to_vec();
        decryptor.decrypt_block_x8(&output[0..128], &mut input[index..index + 128]);
        assert_ne!(orig, input[index..index+128].to_vec());
        println!("result string: {}", String::from_utf8(input[index..index+128].to_vec()).unwrap());
    }
    let end = start + packet_len + 128 + (remander as usize);
    if end < outbuf.len() {
        outbuf.drain(start+packet_len..end);
        indexes.push(start+packet_len);
        indexes.extend_from_slice(&sym_aes_decrypt(header, outbuf, start+packet_len)?);
    } else {
        outbuf.truncate(start+packet_len);
        indexes.push(outbuf.len());
    }
    Ok(indexes)
}

// =============================================================================
//                              Tests
// =============================================================================
#[test]
fn sym_encrypt_test() {
    use crate::random_string;
    use std::time::SystemTime;
    let time = SystemTime::now();
    let instr = random_string(50);
    let key = random_string(16).into_bytes();
    let mut inbuf = instr.clone().into_bytes();
    let mut header = StreamHeader::with_key(&random_string(50), &instr, key.clone(), inbuf.len());
    sym_aes_encrypt(&mut header, &mut inbuf);
    let second_str = random_string(456);
    let mut second_buf = second_str.clone().into_bytes();
    let mut second_header = StreamHeader::with_key(&random_string(50), &instr, key, second_buf.len());
    println!("second_buf: {:?}", second_buf[128..256].to_vec());
    sym_aes_encrypt(&mut second_header, &mut second_buf);
    //println!("second_buf: {:?}", second_buf[256..384].to_vec());
    inbuf.extend_from_slice(&second_buf);
    println!("inbuf len: {}", inbuf.len());
    let indexes = sym_aes_decrypt(&header, &mut inbuf, 0).unwrap();
    println!("indexes: {:?}", indexes);
    let remstr = instr.into_bytes();
    let remsecstr = second_str.into_bytes();
    assert_eq!(remstr.len(), *indexes.get(0).unwrap());
    assert_eq!(remstr, inbuf[0..*indexes.get(0).unwrap()].to_vec());
    println!("first asserts passed");
    assert_eq!(remsecstr.len(), *indexes.get(1).unwrap() - *indexes.get(0).unwrap());
    assert_eq!(remsecstr[0..256].to_vec(), inbuf[*indexes.get(0).unwrap()..*indexes.get(0).unwrap()+256].to_vec());
}
#[test]
fn asym_encrypt_test() {
    use std::time::SystemTime;
    let time = SystemTime::now();
    use crate::random_string;
    let stream_header = StreamHeader::new(&random_string(50), &random_string(50), 0);
    let private_key = crate::get_private_key();
    let public_key = RSAPublicKey::from(&private_key);
    let instr = random_string(65535 - 256);
    let indata = instr.clone().into_bytes();
    let mut outvec = asym_aes_encrypt(&public_key, stream_header, &indata).unwrap();
    aes_inplace_decrypt(&private_key, &mut outvec).unwrap();
    assert_eq!(indata.len(), outvec.len());
    assert_eq!(indata, outvec);
    let elapsed = time.elapsed().unwrap().as_millis();
    println!("{}", elapsed);
    assert!(400 > elapsed);
}
