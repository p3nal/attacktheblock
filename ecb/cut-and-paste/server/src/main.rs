use functions::Cipher;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
mod aes;
mod functions;

// fn dh_exchange_key(mut stream: TcpStream, key: PublicKey) -> (bool, [u8; 1024]) {
//     let mut data = [0 as u8; 1024]; // using 50 byte buffer
//     match stream.read(&mut data) {
//         Ok(_) => {
//             // echo everything!
//             stream.write(&key.to_bytes()).unwrap();
//             (true, data)
//         },
//         Err(_) => {
//             println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
//             stream.shutdown(Shutdown::Both).unwrap();
//             (false, data)
//         }
//     }
// }

fn handle_client(mut stream: TcpStream, cipher: &Cipher) {
    let mut data = [0 as u8; 1024]; // using 50 byte buffer
    while match stream.read(&mut data) {
        Ok(_) => {
            // echo everything!
            let msg = functions::server(cipher, data.to_vec());
            if msg {
                stream.write("success!\n".as_bytes()).unwrap();
            } else {
                stream.write("failed!\n".as_bytes()).unwrap();
            }
            data = [0 as u8; 1024];
            true
        }
        Err(_) => {
            println!(
                "An error occurred, terminating connection with {}",
                stream.peer_addr().unwrap()
            );
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn main() {
    // let alice_secret = EphemeralSecret::new(OsRng);
    // let alice_public = PublicKey::from(&alice_secret);
    // let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    println!("Hello, world!");

    let key = String::from("YELLOW SUBMARINE").as_bytes().to_vec();
    println!("len {}", key.len());
    let cipher = Cipher::new(key);
    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                // connection succeeded
                handle_client(stream, &cipher)
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
    drop(listener);
}
