use rand::Rng;

// ecb cut and paste
//
/// cipher struct, uses the same key throughout its lifetime
pub struct Cipher {
    key: Vec<u8>,
}

impl Cipher {
    pub fn new() -> Cipher {
        Cipher {
            key: (0..16).map(|_| rand::thread_rng().gen::<u8>()).collect(),
        }
    }
    /// client
    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        crate::aes::aes_ecb_encrypt(plaintext.as_bytes(), &self.key)
    }
    /// server
    pub fn decrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        crate::aes::aes_ecb_decrypt(&plaintext, &self.key)
    }
}

// client code
pub fn client(cipher: &Cipher, email: &str) -> Vec<u8> {
    cipher.encrypt(&profile_for(email))
}

pub fn profile_for(email: &str) -> String {
    format!("email={email}&uid=10&role=user")
}

// server code
//
pub fn server(cipher: &Cipher, ciphertext: Vec<u8>) -> bool {
    check_admin(kv_parsing_routine(
        std::str::from_utf8(&cipher.decrypt(ciphertext)).unwrap(),
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

//
//
pub fn perform_ecb_cut_and_paste() {
    //              client(input_email) ---------------------------------------------> server(cipher)
    // encrypt(profile_for(input_email)) -> cipher ------ check_admin(parsing_routing(decrypt(cipher)))
    let cipher = Cipher::new();
    let ciphertext = client(
        &cipher,
        &std::str::from_utf8(&crate::aes::pkcs_7_padding("AAAAAAAAAAadmin", 26)).unwrap(),
        // the 26
        // is put there to get the padding at exactly 16 so i can get a good encrypted block of the
        // admin padded to 16
    );
    // client sending to server, intercepting...
    let intercepted_ciphertext = ciphertext;
    // crafting input
    let admin_block = intercepted_ciphertext.chunks(16).nth(1).unwrap().to_vec();
    let ciphertext = client(&cipher, "abc@gmail.com");
    let first_block = ciphertext
        .chunks(16)
        .take(2)
        .flatten()
        .map(|x| *x)
        .collect::<Vec<u8>>();
    let payload = vec![first_block, admin_block]
        .into_iter()
        .flatten()
        .collect();
    let result = server(&cipher, payload);
    println!("admin role = {result}");
}
