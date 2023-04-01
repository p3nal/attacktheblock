use aes::Aes128;
use rand::Rng;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};

pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|_| rand::thread_rng().gen::<u8>())
        .collect()
}


pub fn pkcs_7_padding<T: AsRef<[u8]>>(text: T, block_length: usize) -> Vec<u8> {
    let mut text = text.as_ref().clone().to_vec();
    let len = text.len();
    let remainder = block_length - len % block_length;
    text.extend([remainder as u8].repeat(remainder));
    text
}

pub fn aes_ecb_encrypt<T: AsRef<[u8]>>(plaintext: T, key: T) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_ref());
    let cipher = Aes128::new(&key);
    let padded_plaintext = pkcs_7_padding(plaintext, 16);
    let mut ciphertext: Vec<u8> = Vec::new();
    for block in padded_plaintext.chunks(16) {
        let mut encrypted_block = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut encrypted_block);
        encrypted_block.iter().for_each(|&x| ciphertext.push(x));
    }
    ciphertext
}
