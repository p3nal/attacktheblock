use functions::Cipher;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::str::from_utf8;
mod aes;
mod functions;

fn main() {
    println!("Hello, world!");
    let cipher = Cipher::new("YELLOW SUBMARINE".as_bytes().to_vec());
    let mut email = String::new();

    if let Ok(mut stream) = TcpStream::connect("localhost:3333") {
        println!("Successfully connected to server in port 3333");
        loop {
            println!("enter your email:");
            std::io::stdin().read_line(&mut email).unwrap();
            let msg = functions::client(&cipher, email.trim());

            stream.write(&msg).unwrap();
            println!("Sent email, awaiting reply...");

            let mut data = [0 as u8; 10];
            match stream.read(&mut data) {
                Ok(_) => {
                    let text = from_utf8(&data).unwrap();
                    println!("Reply: {}", text);
                    continue;
                }
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                    break;
                }
            }
        }
    } else {
        println!("Failed to connect");
    }
    println!("Terminated.");
}
