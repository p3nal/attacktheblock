use base64;

use crate::aes;

#[derive(Debug)]
pub struct Oracle {
    random_string: Vec<u8>,
    random_key: Vec<u8>,
}

impl Oracle {
    /// constructs new Oracle struct, takes in random key length and the random_string in base64
    pub fn new(length: usize, random_string: &str) -> Oracle {
        Oracle {
            random_string: base64::decode(random_string).unwrap().to_vec(),
            random_key: aes::generate_random_bytes(length),
        }
    }

    /// encrypts text under a given key and appends a given string
    pub fn encrypt<T: AsRef<[u8]>>(&self, text: T) -> Vec<u8> {
        let plaintext: Vec<u8> = vec![text.as_ref().to_vec(), self.random_string.clone()]
            .into_iter()
            .flatten()
            .collect();
        aes::aes_ecb_encrypt(&plaintext, &self.random_key)
    }
}

pub fn crack_a_block(oracle: &Oracle, block_size: usize) -> Vec<u8> {
    let mut cracked_bytes: Vec<u8> = Vec::new();
    // for as long as the secret string
    for byte in 0..oracle.encrypt("").len() {
        let chunk_index = byte / block_size;
        let block: Vec<u8> = 
            (0..(chunk_index + 1) * block_size - 1 - cracked_bytes.len())
            .map(|_| 65_u8) // ascii('A') is 65, 65_u8, then, is the byte 'A'
            .collect::<Vec<u8>>();
        let cipherblocks_to_compare_with = oracle.encrypt(&block)
            [chunk_index * block_size..(chunk_index + 1) * block_size]
            .to_vec();
        for i in 0..=255_u8 {
            if cipherblocks_to_compare_with
                == oracle.encrypt(
                    vec![block.clone(), cracked_bytes.clone(), vec![i]]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<u8>>(),
                )[chunk_index * block_size..(chunk_index + 1) * block_size]
                    .to_vec()
            {
                cracked_bytes.push(i);
                break;
            }
        }
    }
    cracked_bytes
}

pub fn demo() {
    let secret_string =
"YSB2ZXJ5IHNlY3JldCBtZXNzYWdlIHRoYXQgc2hvdWxkbnQgYmUgZGVjcnlwdGVkIGV2ZW4gdGhvdWdoIHdlIGFwcGVuZCB1c2VyIGlucHV0IHRvIGl0";
    let oracle = Oracle::new(16, secret_string);
    let block_size = 16;
    println!(
        "{}",
        String::from_utf8(crack_a_block(&oracle, block_size)).unwrap()
    );
}
