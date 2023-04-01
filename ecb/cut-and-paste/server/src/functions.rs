// server for ecb cut and paste
// 
/// cipher struct, uses the same key throughout its lifetime
pub struct Cipher {
    key: Vec<u8>,
}

impl Cipher {
    pub fn new(key: Vec<u8>) -> Cipher {
        Cipher { key }
    }
    /// server
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Vec<u8> {
        crate::aes::aes_ecb_decrypt(&ciphertext, &self.key)
    }
}
// server code
//
pub fn server(cipher: &Cipher, ciphertext: Vec<u8>) -> bool {
    check_admin(kv_parsing_routine(
        String::from_utf8_lossy(&cipher.decrypt(ciphertext)).as_ref(),
    ))
}

pub fn kv_parsing_routine(input: &str) -> Vec<(&str, &str)> {
    input
        .trim()
        .splitn(3, '&')
        .map(|x| x.split_once('=').unwrap())
        .collect::<Vec<(&str, &str)>>()
}
pub fn check_admin(vec: Vec<(&str, &str)>) -> bool {
    vec.into_iter()
        .find(|x| x.0 == "role")
        .unwrap_or(("role", "not admin lol"))
        .1
        == "admin"
}
// server code done
