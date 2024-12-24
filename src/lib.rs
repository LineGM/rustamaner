//! src/lib.rs

use aes_gcm::aead::{generic_array, AeadInPlace, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose, Engine as _};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub id: i32,
    pub service: String,
    pub username: String,
    pub password: String,
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    match pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key) {
        Ok(_) => key,
        Err(e) => {
            eprintln!("Failed to derive key from password: {}", e);
            panic!("Failed to derive key from password");
        }
    }
}

pub fn encrypt(password: &str, data: &str) -> Result<String, Box<dyn Error>> {
    let salt: [u8; 16] = OsRng.gen();
    let key = derive_key_from_password(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let nonce: [u8; 12] = OsRng.gen();
    let mut buffer = data.as_bytes().to_vec();
    match cipher.encrypt_in_place(
        generic_array::GenericArray::from_slice(&nonce),
        b"",
        &mut buffer,
    ) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Encryption error: {}", e);
            panic!("Encryption error");
        }
    };

    let mut result = vec![];
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&buffer);
    Ok(general_purpose::STANDARD.encode(&result))
}

pub fn decrypt(password: &str, encrypted_data: &str) -> Result<String, Box<dyn Error>> {
    let data = general_purpose::STANDARD.decode(encrypted_data)?;
    let (salt, rest) = data.split_at(16);
    let (nonce, ciphertext) = rest.split_at(12);

    let key = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let mut buffer = ciphertext.to_vec();
    match cipher.decrypt_in_place(
        generic_array::GenericArray::from_slice(&nonce),
        b"",
        &mut buffer,
    ) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Decryption error: {}", e);
            panic!("Decryption error");
        }
    };

    Ok(String::from_utf8(buffer)?)
}
