use crate::encryption::ENGINE;
use base64::Engine;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;

pub fn hash_password(password: &str) -> Result<String, ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)?;

    let mut hash = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(200_000).unwrap(),
        &salt,
        password.as_bytes(),
        &mut hash,
    );

    let salt_and_hash = format!("{}${}", ENGINE.encode(&salt), ENGINE.encode(&hash));

    Ok(salt_and_hash)
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let parts: Vec<&str> = password_hash.split('$').collect();
    if parts.len() != 2 {
        return false;
    }

    let salt = ENGINE.decode(parts[0].as_bytes()).unwrap();
    let stored_hash = ENGINE.decode(parts[1].as_bytes()).unwrap();
    let mut hash = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(200_000).unwrap(),
        &salt,
        password.as_bytes(),
        &mut hash,
    );

    stored_hash == hash
}

pub fn derive_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(200_000).unwrap(),
        salt,
        master_password.as_bytes(),
        &mut key,
    );

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let password = "secure_password";
        let hashed = hash_password(password);

        assert!(hashed.is_ok());
        let hashed = hashed.unwrap();
        let parts: Vec<&str> = hashed.split('$').collect();

        assert_eq!(parts.len(), 2);

        assert!(ENGINE.decode(parts[0].as_bytes()).is_ok());
        assert!(ENGINE.decode(parts[1].as_bytes()).is_ok());
    }

    #[test]
    fn test_verify_password() {
        let password = "secure_password";
        let wrong_password = "wrong_password";
        let hashed = hash_password(password).unwrap();

        assert!(verify_password(password, &hashed));
        assert!(!verify_password(wrong_password, &hashed));
        assert!(!verify_password(password, "invalid_hash_format"));
    }

    #[test]
    fn test_derive_key() {
        let master_password = "master_password";
        let rng = SystemRandom::new();
        let mut salt = [0u8; 16];
        rng.fill(&mut salt).unwrap();

        let key = derive_key(master_password, &salt);
        assert_eq!(key.len(), 32);

        let key_rederived = derive_key(master_password, &salt);
        assert_eq!(key, key_rederived);

        let different_key = derive_key("different_password", &salt);
        assert_ne!(key, different_key);

        let mut different_salt = [0u8; 16];
        rng.fill(&mut different_salt).unwrap();

        let key_with_different_salt = derive_key(master_password, &different_salt);
        assert_ne!(key, key_with_different_salt);
    }
}
