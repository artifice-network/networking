use networking::random_string;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};

fn main() {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);

    // Encrypt
    let data_str = random_string(1153);
    println!("data str: {}", data_str);
    let data = data_str.into_bytes();
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
    assert_ne!(&data[..], &enc_data[..]);

    // Decrypt
    let mut dec_data = Vec::new();
    let mut dec = 0;
    while dec < enc_data.len() {
        let start = dec;
        let end = if dec + 256 > enc_data.len() {
            dec += enc_data.len();
            enc_data.len()
        } else {
            dec += 256;
            dec
        };
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        println!("decrypting");
        dec_data.append(
            &mut private_key
                .decrypt(padding, &enc_data[start..end])
                .expect("failed to decrypt"),
        );
    }
    assert_eq!(&data[..], &dec_data[..]);
}
