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

/// used as a trait to define creating new block ciphers
pub trait NewBlockCipher {
    /// create new block cipher type, note for aes use 128 bit | 192 bit | 256 bit aka 16byte, 24byte, 32byte keys
    fn new(key: &[u8]) -> Self;
}

/// implemented on block cipher types, to define shared behavior of encryption and decryption
pub trait BlockCipher {
    /// encrypt 16/24/32 blocks at a time respectively
    fn encrypt_block(&self, block: &mut [u8]);
    /// decrypt 16/24/32 bytes at a time respectively
    fn decrypt_block(&self, block: &mut [u8]);
    /// encrypt 128/192/256 bytes at a time respectively
    fn decrypt_blocks(&self, blocks: &mut [u8]);
    /// decrypt 128/192/256 blocks at a time respectively
    fn encrypt_blocks(&self, blocks: &mut [u8]);
}