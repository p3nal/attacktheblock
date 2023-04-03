use crate::aes;

use base64;
use rand::Rng;

pub struct Cipher {
    selected_string: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Cipher {
    pub fn new() -> Cipher {
        // texts to decrypt encoded in base64
        let st = "c29tZXRoaW5nIHRvIGRlY3J5cHQgd2l0aCBhIHBhZGRpbmcgb3JhY2xlIGF0dGFjay4uIGhlcmUgd2UgZ28BCg==";
        Cipher {
            selected_string: base64::decode(st).unwrap(),
            key: aes::generate_random_bytes(16),
            iv: aes::generate_random_bytes(16),
        }
    }
}

/// returns ciphertext and IV
pub fn client(cipher: &Cipher) -> (Vec<u8>, &Vec<u8>) {
    (
        aes::aes_cbc_encrypt(
            &cipher.selected_string,
            &cipher.key,
            &cipher.iv,
        ),
        &cipher.iv,
    )
}

/// a decryption function that side-channel leaks
pub fn server<T: AsRef<[u8]>>(cipher: &Cipher, ciphertext: T) -> bool {
    let plaintext = aes::aes_cbc_decrypt(
        ciphertext.as_ref(),
        &cipher.key,
        &cipher.iv,
    );
    match aes::validate_padding(plaintext) {
        Ok(_) => true,
        Err(_) => false,
    }
}

