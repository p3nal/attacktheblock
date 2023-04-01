use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

pub fn xor<T: AsRef<[u8]>>(t1: T, t2: T) -> Vec<u8> {
    let t1 = t1.as_ref();
    let t2 = t2.as_ref();
    let length = t1.len().max(t2.len());
    let xor_bytes: Vec<u8> = t1
        .iter()
        .take(length)
        .zip(t2.iter().take(length))
        .map(|(b1, b2)| b1 ^ b2)
        .collect();
    xor_bytes
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

pub fn aes_ecb_decrypt<T: AsRef<[u8]>>(ciphertext: T, key: T) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_ref());
    let cipher = Aes128::new(&key);
    let mut plaintext: Vec<u8> = Vec::new();
    for block in ciphertext.as_ref().chunks(16) {
        let mut decrypted_block = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut decrypted_block);
        decrypted_block.iter().for_each(|&x| plaintext.push(x));
    }
    plaintext
}

pub fn aes_cbc_encrypt<T: AsRef<[u8]>>(plaintext: T, key: T, iv: T) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_ref());
    let cipher = Aes128::new(&key);
    let padded_plaintext = pkcs_7_padding(plaintext, 16);
    let mut ciphertext: Vec<Vec<u8>> = Vec::new();
    for block in padded_plaintext.chunks(16) {
        let block = block.to_vec();
        let xor_block = xor(block, ciphertext.last().unwrap_or(&iv.as_ref().to_vec()).to_vec());
        let mut encrypted_block = GenericArray::clone_from_slice(&xor_block);
        cipher.encrypt_block(&mut encrypted_block);
        ciphertext.push(encrypted_block.to_vec());
    }
    ciphertext.into_iter().flatten().collect()
}

/// does not validate padding
pub fn aes_cbc_decrypt<T: AsRef<[u8]>>(ciphertext: T, key: T, iv: T) -> Vec<u8> {
    let ciphertext = ciphertext.as_ref();
    let key = GenericArray::clone_from_slice(key.as_ref());
    let cipher = Aes128::new(&key);
    let mut plaintext: Vec<Vec<u8>> = Vec::new();
    for i in (0..ciphertext.len()).step_by(16) {
        let prev_cipherblock = if i==0 {
            &iv.as_ref()
        } else {
            &ciphertext[i-16..i]
        };
        let mut block = GenericArray::clone_from_slice(&ciphertext[i..i+16]);
        cipher.decrypt_block(&mut block);
        let block_to_xor = block.to_vec();
        let xored_block = xor(block_to_xor, prev_cipherblock.to_vec());
        plaintext.push(xored_block);
    }
    let plaintext: Vec<u8> = plaintext.into_iter().flatten().collect();
    // plaintext.get(..plaintext.len() - *plaintext.last().unwrap_or(&0) as usize).unwrap().to_vec()
    // padding not removed
    plaintext
}

/// returns plaintext upon valid string
pub fn validate_padding<T: AsRef<[u8]>>(input: T) -> Result<String, String> {
    let string_to_validate = input.as_ref();
    let length = string_to_validate.len();
    let supposed_padding_size = *string_to_validate.last().unwrap() as usize;
    if supposed_padding_size < 1 || supposed_padding_size > 16 {
        return Err("wrong padding".to_string())
    }
    let padding = string_to_validate
        .iter()
        .rev()
        .take(supposed_padding_size)
        .collect::<Vec<&u8>>();
    if supposed_padding_size != padding.len() {
        return Err("wrong padding".to_string())
    }
    for i in padding {
        if *i as usize != supposed_padding_size {
            return Err("wrong padding".to_string())
        }
    }
    Ok(String::from_utf8_lossy(
        &string_to_validate
            .iter()
            .take(length - supposed_padding_size)
            .map(|x| *x)
            .collect::<Vec<u8>>(),
    ).to_string())
}

