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
struct CounterNonceSequence(pub u32);

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
    let mut encrypted_in_out = ENGINE
        .decode(encrypted)
        .map_err(|e| EncryptionError::from(e))?;

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| EncryptionError::KeyCreation)?;
    let nonce_seq = CounterNonceSequence(1);
    let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);
    let opened_in_out = opening_key
        .open_in_place(Aad::empty(), &mut encrypted_in_out)
        .map_err(|err| EncryptionError::Decryption(err.to_string()))?;

    Ok(String::from_utf8(opened_in_out.to_vec()).map_err(|e| EncryptionError::from(e))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};

    #[test]
    fn test_encrypt_decrypt_success() {
        let rng = SystemRandom::new();
        let mut test_key = [0u8; 32];
        rng.fill(&mut test_key).unwrap();

        let plaintxt = "Some plain text to encrypt";
        println!("Plaintext:- {plaintxt}");

        let encrypted = encrypt(&plaintxt, &test_key).unwrap();
        println!("Encrypted data:- {encrypted}");

        let decrypted = decrypt(&encrypted, &test_key).unwrap();
        println!("Decrypted data:- {decrypted}");

        assert_eq!(plaintxt, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let rng = SystemRandom::new();
        let mut test_key = [0u8; 32];
        rng.fill(&mut test_key).unwrap();

        let plaintxt = "";
        println!("Plaintext:- {plaintxt}");

        let encrypted = encrypt(&plaintxt, &test_key).unwrap();
        println!("Encrypted data:- {encrypted}");

        let decrypted = decrypt(&encrypted, &test_key).unwrap();
        println!("Decrypted data:- {decrypted}");

        assert_eq!(plaintxt, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_large_string() {
        let rng = SystemRandom::new();
        let mut test_key = [0u8; 32];
        rng.fill(&mut test_key).unwrap();

        let plaintxt = "verylongstring".repeat(100_000);
        let encrypted = encrypt(&plaintxt, &test_key).unwrap();
        let decrypted = decrypt(&encrypted, &test_key).unwrap();

        assert_eq!(plaintxt, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_with_wrong_key() {
        let rng = SystemRandom::new();
        let mut test_key = [0u8; 32];
        rng.fill(&mut test_key).unwrap();

        let faulty_key = [0u8; 32];
        let plaintxt = "verylongstring".repeat(100_000);
        let encrypted = encrypt(&plaintxt, &test_key).unwrap();
        let decrypted = decrypt(&encrypted, &faulty_key);

        assert!(decrypted.is_err());
        if let Err(err) = decrypted {
            assert!(matches!(err, EncryptionError::Decryption(_)));
        }
    }

    #[test]
    fn test_decrypt_with_invalid_ciphertext() {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).unwrap();

        let invalid_ciphertext = "NotBase64EncodedString";
        let result = decrypt(invalid_ciphertext, &key);
        println!("{result:?}");

        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, EncryptionError::Decryption(_)));
        }
    }

    // #[test]
    // fn test_nonce_overflow() {
    //     let mut nonce_sequence = CounterNonceSequence(u32::MAX);
    //     println!("{}", nonce_sequence.0);
    //     let nonce_result = nonce_sequence.advance();
    //     println!("{}", nonce_sequence.0);
    //     assert!(nonce_result.is_err());
    // }
}
