use crate::error::NetworkError;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
/// sequencially encrypts, rather then encrypting 8 blocks at a time
pub fn asym_aes_encrypt(pubkey: &RSAPublicKey, input: &[u8]) -> Result<Vec<u8>, NetworkError> {
    unimplemented!()
}
/// sequencially decrypts, rather than decrypting 8 blocks at a time
pub fn asym_aes_decrypt(privkey: &RSAPrivateKey, input: &[u8]) -> Result<Vec<u8>, NetworkError> {
    unimplemented!()
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
