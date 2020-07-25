use crate::error::NetworkError;
use crate::random_string;
use crypto::{
    aessafe::{AesSafe128DecryptorX8, AesSafe128EncryptorX8},
    symmetriccipher::{BlockDecryptorX8, BlockEncryptorX8},
};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use std::error::Error;
pub fn aes_encrypt(
    pub_key: &RSAPublicKey,
    input: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    assert!(input.len() < (65535));
    let mut output = Vec::new();
    let mut rng = OsRng;
    let key = random_string(16);
    let key = key.into_bytes();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let mut enc_key = pub_key.encrypt(&mut rng, padding, &key)?;
    let mut data = Vec::new();
    data.extend_from_slice(&input);
    let rem: u8 = 128 - ((input.len() % 128) as u8);
    let mut aes_padding = Vec::with_capacity(rem as usize);
    unsafe {
        aes_padding.set_len(rem as usize);
    }
    data.append(&mut aes_padding);
    assert_eq!(data.len() % 128, 0);
    let mut index = 0;
    let encryptor = AesSafe128EncryptorX8::new(&key);
    output.append(&mut enc_key);
    output.push(rem);
    while index < data.len() {
        let mut read_data: [u8;128] = [0;128];
        encryptor.encrypt_block_x8(&data[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
        index = index + 128;
    }
    //output.append(&mut outvec);
    Ok(output)
}
#[test]
fn encrypt_test() -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);
    let indata = random_string(43235).into_bytes();
    //let mut outvec = Vec::new();
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    let outvec = aes_encrypt(&public_key, &indata).unwrap();
    //let mut dec_buf = Vec::new();
    let dec_buf = aes_decrypt(&private_key, &outvec).unwrap();
    assert_eq!(indata,dec_buf);
    Ok(())
}
pub fn aes_decrypt(
    priv_key: &RSAPrivateKey,
    input: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    assert!(input.len() < (65535));
    let mut output = Vec::new();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let key = priv_key.decrypt(padding, &input[0..256])?;
    let rem = input[256];
    let mut index = 257;
    let decryptor = AesSafe128DecryptorX8::new(&key);
    while index < input.len() {
        let mut read_data: [u8;128] = [0;128];
        decryptor.decrypt_block_x8(&input[index..index + 128], &mut read_data[..]);
        output.extend_from_slice(&read_data);
        index = index + 128;
    }
    output.truncate(output.len() - rem as usize);
    Ok(output)
}
