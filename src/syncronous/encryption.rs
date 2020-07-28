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
    let mut index = 0;
    let encryptor = AesSafe128Encryptor::new(header.key());
    header.set_remander(rem);
    // make sure data length is tracted in case multiple packets are sent at the same time
    header.set_packet_len(data.len());
    // convert header to binary, should only be of length 125, 50 byte global hash, 50 byte peer hash, 16 bytes aes key, 8 bytes data len, 1 byte remander len
    let key = header.to_raw();
    assert_eq!(key.len(), 125);
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    // use rsa to encrypt the aes key
    let mut enc_key = pub_key.encrypt(&mut rng, padding, &key)?;
    output.append(&mut enc_key);
    let full_len = input.len() + rem as usize;
    while index < full_len {
        let mut read_data: [u8; 16] = [0; 16];
        // encrypt in sections of 16 bytes
        encryptor.encrypt_block(&data[index..index + 16], &mut read_data[..]);
        output.extend_from_slice(&read_data);
        index += 16;
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
    let mut index = 256;
    let mut read_data: [u8; 16] = [0; 16];
    while index < data_len + 256 {
        decryptor.decrypt_block(&input[index..index + 16], &mut read_data[..]);
        output.extend_from_slice(&read_data);
        index += 16;
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
/// encrypts purely using rsa
pub fn rsa_decrypt(
    priv_key: &RSAPrivateKey,
    enc_data: &[u8],
    data_len: usize,
) -> Result<Vec<u8>, rsa::errors::Error> {
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

        dec_data.append(
            &mut priv_key
                .decrypt(padding, &enc_data[start..end])
                .expect("failed to decrypt"),
        );
    }
    Ok(dec_data)
}
/// encrypts purely using rsa
pub fn rsa_encrypt(public_key: &RSAPublicKey, data: &[u8]) -> Result<Vec<u8>, rsa::errors::Error> {
    let mut rng = OsRng;
    let mut index = 0;
    let mut enc_data = Vec::new();
    while index < data.len() {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let start = index;
        let end = if index + 245 > data.len() {
            index = data.len();
            data.len()
        } else {
            index += 245;
            index
        };
        enc_data.append(
            &mut public_key
                .encrypt(&mut rng, padding, &data[start..end])
                .expect("failed to encrypt"),
        );
    }
    Ok(enc_data)
}
