use crate::aes;

pub struct Cipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Cipher {
    pub fn new() -> Cipher {
        Cipher {
            key: aes::generate_random_bytes(16),
            iv: aes::generate_random_bytes(16),
        }
    }
    fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        aes::aes_cbc_encrypt(plaintext.as_bytes(), &self.key, &self.iv)
    }
    fn decrypt(&self, ciphertext: Vec<u8>) -> Vec<u8> {
        aes::aes_cbc_decrypt(&ciphertext, &self.key, &self.iv)
    }
}

pub fn client(cipher: &Cipher, input_str: String) -> Vec<u8> {
    let input_str = input_str.chars().filter(|x| *x != ';' && *x != '=').collect::<String>();
    let encoded_str = format!("username=some_username;userdata={input_str};comment=a%20thug%20changes%20and%20love%20changes%20And%20best%20friends%20become%20strangers");
    cipher.encrypt(&encoded_str)
}

pub fn server(cipher: &Cipher, ciphertext: Vec<u8>) -> bool {
    String::from_utf8_lossy(&cipher.decrypt(ciphertext)).contains(";admin=true;")
}


/// here is a demo of a cbc bitflipping attack
/// ; in ascii is 00111011 we bitflip the 3rd bit to get 00111111 which is ascii
/// for ?, escaping the filters. same thing goes for = which is 00111101 and
/// becomes also 00111111
/// comment1=cooking%20MCs;userdata=some;admin=true;comment2=%20like%20a%20pound%20of%20bacon
pub fn demo() {
    let cipher = Cipher::new();
    // ?'s to bitflip later
    let my_arbitrary_controlled_input_string = format!("some?admin?true");
    let mut ciphertext =
        client(&cipher, my_arbitrary_controlled_input_string);
    // after capturing the ciphertext we have to bitflip the ?'s to make ; and =
    ciphertext[36 - 16] = ciphertext[36 - 16] ^ 0b0000100;
    ciphertext[42 - 16] = ciphertext[42 - 16] ^ 0b0000010;
    let result = server(&cipher, ciphertext);
    println!("are we admin yet?\n{}", if result {
        "yes!"
    } else {
        "no..."
    });
}
