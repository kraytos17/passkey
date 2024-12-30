#![allow(dead_code)]
use rand::{seq::SliceRandom, Rng};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:',.<>?/";

pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> String {
    let mut rng = rand::thread_rng();
    let mut character_set = LOWERCASE.to_string();
    let mut password = String::new();

    if include_uppercase {
        character_set.push_str(UPPERCASE);
        password.push(
            UPPERCASE
                .chars()
                .nth(rng.gen_range(0..UPPERCASE.len()))
                .unwrap(),
        );
    }

    if include_numbers {
        character_set.push_str(NUMBERS);
        password.push(
            NUMBERS
                .chars()
                .nth(rng.gen_range(0..NUMBERS.len()))
                .unwrap(),
        );
    }

    if include_symbols {
        character_set.push_str(SYMBOLS);
        password.push(
            SYMBOLS
                .chars()
                .nth(rng.gen_range(0..SYMBOLS.len()))
                .unwrap(),
        );
    }

    while password.len() < length {
        let idx = rng.gen_range(0..character_set.len());
        password.push(character_set.chars().nth(idx).unwrap());
    }

    let mut password_chars: Vec<char> = password.chars().collect();
    password_chars.shuffle(&mut rng);

    password_chars.into_iter().collect()
}
