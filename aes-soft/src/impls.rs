use crate::bitslice::{
    bit_slice_1x128_with_u32x4, bit_slice_1x16_with_u16, bit_slice_4x4_with_u16,
    bit_slice_fill_4x4_with_u32x4, decrypt_core, encrypt_core, un_bit_slice_1x128_with_u32x4,
    un_bit_slice_1x16_with_u16, Bs8State,
};
use crate::consts::U32X4_0;
use crate::simd::u32x4;
use crate::{BlockCipher, NewBlockCipher};
use crate::bitslice::{bit_slice_4x1_with_u16, un_bit_slice_4x1_with_u16, AesOps};
use crate::consts::RCON;

fn ffmulx(x: u32) -> u32 {
    let m1: u32 = 0x80808080;
    let m2: u32 = 0x7f7f7f7f;
    let m3: u32 = 0x0000001b;
    ((x & m2) << 1) ^ (((x & m1) >> 7) * m3)
}

fn inv_mcol(x: u32) -> u32 {
    let f2 = ffmulx(x);
    let f4 = ffmulx(f2);
    let f8 = ffmulx(f4);
    let f9 = x ^ f8;

    f2 ^ f4 ^ f8 ^ (f2 ^ f9).rotate_right(8) ^ (f4 ^ f9).rotate_right(16) ^ f9.rotate_right(24)
}

fn sub_word(x: u32) -> u32 {
    let bs = bit_slice_4x1_with_u16(x).sub_bytes();
    un_bit_slice_4x1_with_u16(&bs)
}
pub fn expand_key(
    key: &[u8],
    key_len: usize,
    rounds: usize,
) -> (
    Vec<Vec<u32>>,
    Vec<Vec<u32>>
) {
    let key_words = match key_len {
        16 => 4,
        24 => 6,
        32 => 8,
        _ => panic!("Invalid AES key size."),
    };
    let mut ek: Vec<Vec<u32>> = Vec::with_capacity(rounds);
    unsafe {
        for _ in 0..ek.capacity(){
        let mut dvec = Vec::with_capacity(key_len);
        dvec.set_len(key_len);
        ek.push(dvec);
        }
    }
    // The key is copied directly into the first few round keys
    let mut j = 0;
    for i in 0..key_len / 4 {
        ek[j / 4][j % 4] = u32::from(key[4 * i])
            | (u32::from(key[4 * i + 1]) << 8)
            | (u32::from(key[4 * i + 2]) << 16)
            | (u32::from(key[4 * i + 3]) << 24);
        j += 1;
    }

    // Calculate the rest of the round keys
    for i in key_words..rounds * 4 {
        let mut tmp = ek[(i - 1) / 4][(i - 1) % 4];
        if (i % key_words) == 0 {
            tmp = sub_word(tmp.rotate_right(8)) ^ RCON[(i / key_words) - 1];
        } else if (key_words == 8) && ((i % key_words) == 4) {
            // This is only necessary for AES-256 keys
            tmp = sub_word(tmp);
        }
        ek[i / 4][i % 4] = ek[(i - key_words) / 4][(i - key_words) % 4] ^ tmp;
    }

    // Decryption round keys require extra processing
    let mut dk = Vec::with_capacity(rounds);
    unsafe {
        for _ in 0..dk.capacity(){
        let mut dvec = Vec::with_capacity(key_len);
        dvec.set_len(key_len);
        dk.push(dvec);
        }
    }
    dk[0] = ek[0].clone();
    for j in 1..rounds - 1 {
        for i in 0..4 {
            dk[j][i] = inv_mcol(ek[j][i]);
        }
    }
    dk[rounds - 1] = ek[rounds - 1].clone();

    (ek, dk)
}

macro_rules! define_aes_impl {
    (
        $name:ident,
        $key_size:expr,
        $rounds:expr,
        $rounds2:expr,
        $doc:expr
    ) => {
        #[doc=$doc]
        #[derive(Clone, Serialize, Deserialize)]
        pub struct $name {
            enc_keys: [Bs8State<u16>; $rounds],
            dec_keys: [Bs8State<u16>; $rounds],
            enc_keys8: [Bs8State<u32x4>; $rounds],
            dec_keys8: [Bs8State<u32x4>; $rounds],
        }

        impl NewBlockCipher for $name {

            #[inline]
            fn new(key: &[u8]) -> Self {
                assert_eq!($key_size, key.len());
                let (ek, dk) = expand_key(key, $key_size, $rounds2);
                let k8 = Bs8State(
                    U32X4_0, U32X4_0, U32X4_0, U32X4_0,
                    U32X4_0, U32X4_0, U32X4_0, U32X4_0
                );
                let mut c =  Self {
                    enc_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                    dec_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                    enc_keys8: [k8; $rounds],
                    dec_keys8: [k8; $rounds],
                };
                for i in 0..$rounds {
                    c.enc_keys[i] = bit_slice_4x4_with_u16(
                        ek[i][0], ek[i][1], ek[i][2], ek[i][3],
                    );
                    c.dec_keys[i] = bit_slice_4x4_with_u16(
                        dk[i][0], dk[i][1], dk[i][2], dk[i][3],
                    );
                    c.enc_keys8[i] = bit_slice_fill_4x4_with_u32x4(
                        ek[i][0], ek[i][1], ek[i][2], ek[i][3],
                    );
                    c.dec_keys8[i] = bit_slice_fill_4x4_with_u32x4(
                        dk[i][0], dk[i][1], dk[i][2], dk[i][3],
                    );
                }
                c
            }
        }

        impl BlockCipher for $name {

            #[inline]
            fn encrypt_block(&self, block: &mut [u8]) {
                assert_eq!($key_size, block.len());
                let mut bs = bit_slice_1x16_with_u16(block);
                bs = encrypt_core(&bs, &self.enc_keys);
                un_bit_slice_1x16_with_u16(&bs, block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8]) {
                assert_eq!($key_size, block.len());
                let mut bs = bit_slice_1x16_with_u16(block);
                bs = decrypt_core(&bs, &self.dec_keys);
                un_bit_slice_1x16_with_u16(&bs, block);
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut [u8]) {
                assert_eq!($key_size*8, blocks.len());
                let bs = bit_slice_1x128_with_u32x4(blocks);
                let bs2 = encrypt_core(&bs, &self.enc_keys8);
                un_bit_slice_1x128_with_u32x4(bs2, blocks);
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut [u8]) {
                assert_eq!($key_size*8, blocks.len());
                let bs = bit_slice_1x128_with_u32x4(blocks);
                let bs2 = decrypt_core(&bs, &self.dec_keys8);
                un_bit_slice_1x128_with_u32x4(bs2, blocks);
            }
        }

        opaque_debug::implement!($name);
    }
}

define_aes_impl!(Aes128, 16, 11, 11, "AES-128 block cipher instance");
define_aes_impl!(Aes192, 24, 13, 13, "AES-192 block cipher instance");
define_aes_impl!(Aes256, 32, 15, 15, "AES-256 block cipher instance");