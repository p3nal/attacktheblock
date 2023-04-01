// client for ecb cut and paste
// 
/// cipher struct, uses the same key throughout its lifetime
pub struct Cipher {
    key: Vec<u8>,
}

impl Cipher {
    pub fn new(key: Vec<u8>) -> Cipher {
        Cipher { key }
    }
    /// client
    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        crate::aes::aes_ecb_encrypt(plaintext.as_bytes(), &self.key)
    }
}


// client code
pub fn client(cipher: &Cipher, email: &str) -> Vec<u8> {
    cipher.encrypt(&profile_for(email))
}

pub fn profile_for(email: &str) -> String {
    format!("email={email}&uid=10&role=user")
}

