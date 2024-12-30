use base64::engine::general_purpose;
use base64::{alphabet, engine, DecodeError, Engine};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::error::Unspecified;
use std::string::FromUtf8Error;
use thiserror::Error;

pub const ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::NO_PAD);

/// A nonce sequence implementation that uses a 32-bit counter
struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];
        let bytes = self.0.to_be_bytes();

        nonce_bytes[8..].copy_from_slice(&bytes);
        self.0 += 1;
        
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Key creation failed")]
    KeyCreation,
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] DecodeError),
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),
}

/// Encrypts data using AES-GCM.
///
/// # Arguments
/// * `data` - The plaintext data to encrypt.
/// * `key` - The encryption key (32 bytes).
///
/// # Returns
/// * A base64-encoded string containing the ciphertext
pub fn encrypt(data: &str, key: &[u8; 32]) -> Result<String, EncryptionError> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| EncryptionError::KeyCreation)?;
    let nonce_sequence = CounterNonceSequence(1);
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);
    let mut in_out = data.as_bytes().to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .map_err(|err| EncryptionError::Encryption(err.to_string()))?;

    Ok(ENGINE.encode(&in_out))
}

/// Decrypts data using AES-GCM.
///
/// # Arguments
/// * `encrypted` - A base64-encoded string containing the ciphertext.
/// * `key` - The encryption key (32 bytes).
/// * `nonce_b64` - The base64-encoded nonce used in the AES-GCM encryption.
///
/// # Returns
/// * The decrypted plaintext as a string.
pub fn decrypt(encrypted: &str, key: &[u8; 32]) -> Result<String, EncryptionError> {
    let mut encrypted_in_out = ENGINE.decode(encrypted)?;
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| EncryptionError::KeyCreation)?;
    let nonce_seq = CounterNonceSequence(1);
    let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);
    let opened_in_out = opening_key
        .open_in_place(Aad::empty(), &mut encrypted_in_out)
        .map_err(|err| EncryptionError::Decryption(err.to_string()))?;

    Ok(String::from_utf8(opened_in_out.to_vec())?)
}
