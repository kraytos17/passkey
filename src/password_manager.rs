#![allow(dead_code)]

use crate::{encryption, hashing};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{params, Connection, Error as SqliteError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordManagerError {
    #[error("Database error: {0}")]
    Database(#[from] SqliteError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),
    #[error("Password hashing error: {0}")]
    PasswordHashing(String),
    #[error("Password verification failed")]
    PasswordVerificationFailed,
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

// Custom type alias for Result
type Result<T> = std::result::Result<T, PasswordManagerError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredPassword {
    service_name: String,
    username: String,
    password: String,
}

pub fn init_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;

    conn.execute_batch(
        "BEGIN;
         CREATE TABLE IF NOT EXISTS users (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT NOT NULL UNIQUE,
             master_password_hash TEXT NOT NULL UNIQUE,
             salt TEXT NOT NULL UNIQUE
         );
         CREATE TABLE IF NOT EXISTS passwords (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             user_id INTEGER NOT NULL,
             service_name TEXT NOT NULL,
             username TEXT NOT NULL,
             encrypted_password TEXT NOT NULL,
             FOREIGN KEY (user_id) REFERENCES users (id)
         );
         COMMIT;",
    )?;

    Ok(conn)
}

pub fn add_user(conn: &mut Connection, username: &str, master_password: &str) -> Result<()> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).unwrap();

    let mp_hash = hashing::hash_password(master_password)
        .map_err(|e| PasswordManagerError::PasswordHashing(e.to_string()))?;

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO users (username, master_password_hash, salt) VALUES (?1, ?2, ?3)",
        params![username, mp_hash, String::from_utf8(salt.to_vec()).unwrap()],
    )?;
    tx.commit()?;

    Ok(())
}

pub fn validate_user(conn: &Connection, username: &str, master_password: &str) -> Result<i64> {
    let result = conn.query_row(
        "SELECT id, master_password_hash FROM users WHERE username = ?1",
        params![username],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    );

    match result {
        Ok((id, hash)) => {
            if hashing::verify_password(&hash, master_password) {
                Ok(id)
            } else {
                Err(PasswordManagerError::PasswordVerificationFailed)
            }
        }
        Err(SqliteError::QueryReturnedNoRows) => {
            Err(PasswordManagerError::UserNotFound(username.to_string()))
        }
        Err(e) => Err(PasswordManagerError::Database(e)),
    }
}

pub fn add_password(
    conn: &mut Connection,
    user_id: i64,
    master_password: &str,
    service_name: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    let salt: String = conn.query_row(
        "SELECT salt FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;

    let key = hashing::derive_key(master_password, salt.as_bytes());
    let encrypted_password = encryption::encrypt(password, &key)
        .map_err(|e| PasswordManagerError::Encryption(e.to_string()))?;

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO passwords (user_id, service_name, username, encrypted_password)
         VALUES (?1, ?2, ?3, ?4)",
        params![user_id, service_name, username, encrypted_password],
    )?;
    tx.commit()?;

    Ok(())
}

pub fn get_passwords(
    conn: &Connection,
    user_id: i64,
    master_password: &str,
) -> Result<Vec<StoredPassword>> {
    let salt: String = conn.query_row(
        "SELECT salt FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;

    let key = hashing::derive_key(master_password, salt.as_bytes());
    let mut stmt = conn.prepare(
        "SELECT service_name, username, encrypted_password 
         FROM passwords WHERE user_id = ?1",
    )?;

    let password_iter = stmt.query_map(params![user_id], |row| {
        Ok(StoredPassword {
            service_name: row.get(0)?,
            username: row.get(1)?,
            password: {
                let encrypted: String = row.get(2)?;
                encryption::decrypt(&encrypted, &key)
                    .map_err(|err| PasswordManagerError::Decryption(err.to_string()))
                    .unwrap()
            },
        })
    })?;

    password_iter
        .map(|result| result.map_err(PasswordManagerError::Database))
        .collect()
}

pub fn search_passwords(
    conn: &Connection,
    user_id: i64,
    master_password: &str,
    query: &str,
) -> Result<Vec<StoredPassword>> {
    if query.is_empty() {
        return Err(PasswordManagerError::InvalidData(
            "Search query cannot be empty".to_string(),
        ));
    }

    let salt = conn.query_row(
        "SELECT salt FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get::<_, String>(0),
    )?;

    let key = hashing::derive_key(master_password, salt.as_bytes());
    let query = format!("%{}%", query);

    let mut stmt = conn.prepare(
        "SELECT service_name, username, encrypted_password 
         FROM passwords 
         WHERE user_id = ?1 AND (service_name LIKE ?2 OR username LIKE ?2)",
    )?;

    let password_iter = stmt.query_map(params![user_id, query], |row| {
        Ok(StoredPassword {
            service_name: row.get(0)?,
            username: row.get(1)?,
            password: {
                let encrypted: String = row.get(2)?;
                encryption::decrypt(&encrypted, &key).unwrap()
            },
        })
    })?;

    password_iter
        .map(|result| result.map_err(PasswordManagerError::Database))
        .collect()
}

pub fn update_password(
    conn: &mut Connection,
    user_id: i64,
    master_password: &str,
    service_name: &str,
    username: &str,
    new_password: &str,
) -> Result<()> {
    let salt: String = conn.query_row(
        "SELECT salt FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;

    let key = hashing::derive_key(master_password, salt.as_bytes());
    let enc_pw = encryption::encrypt(new_password, &key)
        .map_err(|err| PasswordManagerError::Encryption(err.to_string()))?;

    let tx = conn.transaction()?;
    let rows_affected = tx.execute(
        "UPDATE passwords 
         SET encrypted_password = ?1
         WHERE user_id = ?2 AND service_name = ?3 AND username = ?4",
        params![enc_pw, user_id, service_name, username],
    )?;

    if rows_affected == 0 {
        tx.rollback()?;
        return Err(PasswordManagerError::InvalidData(format!(
            "No password found for service '{}' and username '{}'",
            service_name, username
        )));
    }

    tx.commit()?;

    Ok(())
}

pub fn delete_password(
    conn: &mut Connection,
    user_id: i64,
    service_name: &str,
    username: &str,
) -> Result<()> {
    let tx = conn.transaction()?;
    let rows_affected = tx.execute(
        "DELETE FROM passwords WHERE user_id = ?1 AND service_name = ?2 AND username = ?3",
        params![user_id, service_name, username],
    )?;

    if rows_affected == 0 {
        tx.rollback()?;
        return Err(PasswordManagerError::InvalidData(format!(
            "No password found for service '{}' and username '{}'",
            service_name, username
        )));
    }

    tx.commit()?;

    Ok(())
}

pub fn export_passwords(
    conn: &Connection,
    user_id: i64,
    master_password: &str,
    file_path: &str,
) -> Result<()> {
    let passwords = get_passwords(conn, user_id, master_password)?;
    let serialized_pw = serde_json::to_string_pretty(&passwords)?;
    std::fs::write(file_path, serialized_pw).map_err(|err| PasswordManagerError::from(err))?;

    Ok(())
}

pub fn import_passwords(
    conn: &mut Connection,
    user_id: i64,
    master_password: &str,
    file_path: &str,
) -> Result<()> {
    let data = std::fs::read_to_string(file_path)?;
    let passwords: Vec<StoredPassword> = serde_json::from_str(&data)?;

    let salt = conn.query_row(
        "SELECT salt FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get::<_, String>(0),
    )?;

    let key = hashing::derive_key(master_password, salt.as_bytes());
    let tx = conn.transaction()?;

    for pw in passwords {
        let encrypted_password = encryption::encrypt(&pw.password, &key)
            .map_err(|err| PasswordManagerError::Encryption(err.to_string()))?;

        tx.execute(
            "INSERT INTO passwords (user_id, service_name, username, encrypted_password)
             VALUES (?1, ?2, ?3, ?4)",
            params![user_id, pw.service_name, pw.username, encrypted_password],
        )?;
    }

    tx.commit()?;

    Ok(())
}
