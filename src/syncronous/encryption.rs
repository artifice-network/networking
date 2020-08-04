//use crate::error::NetworkError;
//use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use crate::error::NetworkError;
use crate::StreamHeader;
use crypto::{
    aessafe::{AesSafe128Decryptor, AesSafe128Encryptor},
    symmetriccipher::{BlockDecryptor, BlockEncryptor},
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
    // ensure data can be modulated by 16
    let rem: u8 = 16 - ((input.len() % 16) as u8);
    let mut aes_padding = Vec::with_capacity(rem as usize);
    unsafe {
        aes_padding.set_len(rem as usize);
    }
    // place padding in the input vector
    data.append(&mut aes_padding);
    assert_eq!(data.len() % 16, 0);
    let encryptor = AesSafe128Encryptor::new(header.key());
    header.set_remander(rem);
    // make sure data length is tracted in case multiple packets are sent at the same time
    header.set_packet_len(data.len());
    // convert header to binary, should only be of length 125, 50 byte global hash, 50 byte peer hash, 16 bytes aes key, 8 bytes data len, 1 byte remander len
    let key = header.to_raw();
    assert!(key.len() < 246);
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    // use rsa to encrypt the aes key
    let mut enc_key = pub_key.encrypt(&mut rng, padding, &key)?;
    output.append(&mut enc_key);
    let full_len = input.len() + rem as usize;
    for index in (0..full_len).step_by(16) {
        let mut read_data: [u8; 16] = [0; 16];
        // encrypt in sections of 16 bytes
        encryptor.encrypt_block(&data[index..index + 16], &mut read_data[..]);
        output.extend_from_slice(&read_data);
    }
    //output.append(&mut outvec);
    Ok(output)
}
// ===============================================================================
//                          AES Decryption
// ================================================================================
pub fn asym_aes_decrypt(
    priv_key: &RSAPrivateKey,
    input: &[u8],
) -> Result<(Vec<u8>, StreamHeader), NetworkError> {
    assert!(input.len() < (65536));
    // create output vector
    let mut output = Vec::new();
    // decrypt the StreamHeader
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let mut header = StreamHeader::from_raw(&priv_key.decrypt(padding, &input[0..256])?)?;
    let rem = header.remander();
    let data_len = header.packet_len();
    let decryptor = AesSafe128Decryptor::new(header.key());
    let mut read_data: [u8; 16] = [0; 16];
    for index in (256..data_len + 256).step_by(16) {
        decryptor.decrypt_block(&input[index..index + 16], &mut read_data[..]);
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
