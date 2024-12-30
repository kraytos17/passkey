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
        NonZeroU32::new(500_000).unwrap(),
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
        NonZeroU32::new(500_000).unwrap(),
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
        NonZeroU32::new(500_000).unwrap(),
        salt,
        master_password.as_bytes(),
        &mut key,
    );

    key
}
