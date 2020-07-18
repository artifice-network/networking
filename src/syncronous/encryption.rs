use crypto::blowfish::Blowfish;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
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
