/*!
```
    use aes_soft::{Aes128, BlockCipher, NewBlockCipher};

    // create aes key
    let mut key = Vec::with_capacity(16);
    unsafe {key.set_len(16)};
    // create test data
    let d = [0u8;128];
    let mut data = Vec::new();
    data.extend_from_slice(&d);
    // create the encryptor/decryptor, with given key
    let aes = Aes128::new(&key);
    let data_copy = data.clone();
    // copy unencrypted for test
    aes.encrypt_blocks(&mut data);
    // make sure test data, and encrypted data are different
    assert_ne!(data, data_copy);
    aes.decrypt_blocks(&mut data);
    assert_eq!(data, data_copy);
```
!*/
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
//#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#[macro_use]extern crate serde_derive;


mod bitslice;
mod consts;
mod impls;
mod simd;

pub use crate::impls::{Aes128, Aes192, Aes256};

pub trait NewBlockCipher {
    fn new(key: &[u8]) -> Self;
}

pub trait BlockCipher {
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);
    fn decrypt_blocks(&self, blocks: &mut [u8]);
    fn encrypt_blocks(&self, blocks: &mut [u8]);
}