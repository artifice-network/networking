use aes_soft::{Aes128, BlockCipher, NewBlockCipher};

fn main() {
    let mut key = Vec::with_capacity(16);
    unsafe {key.set_len(16)};

    let d = [0u8;128];
    let mut data = Vec::new();
    data.extend_from_slice(&d);
    let aes = Aes128::new(&key);
    let data_copy = data.clone();
    aes.encrypt_blocks(&mut data);
    assert_ne!(data, data_copy);
    aes.decrypt_blocks(&mut data);
    assert_eq!(data, data_copy);
}