//! Field-level encryption for sensitive session data stored at rest.
//!
//! Uses AES-256-GCM (authenticated encryption with associated data) to
//! encrypt individual fields before they are written to SQLite. Each
//! encrypted value is prefixed with a random 12-byte nonce, then
//! base64-encoded for safe storage in TEXT columns.
//!
//! Encryption is **optional**: when no key is configured, the storage
//! layer stores data in plaintext (backward compatible). The key is
//! loaded from the `ARBITER_STORAGE_ENCRYPTION_KEY` environment variable
//! as a 64-character hex string (32 bytes).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;

/// Errors from encryption / decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("invalid key length: expected 32 bytes (64 hex chars), got {0}")]
    InvalidKeyLength(usize),

    #[error("invalid hex in encryption key: {0}")]
    InvalidHex(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),
}

/// Field-level encryption using AES-256-GCM.
///
/// Each encrypted field has the wire format:
///   `base64(nonce_12_bytes || ciphertext_with_tag)`
///
/// A fresh random nonce is generated for every `encrypt_*` call, so
/// encrypting the same plaintext twice yields different ciphertext.
#[derive(Clone)]
pub struct FieldEncryptor {
    cipher: Aes256Gcm,
}

impl FieldEncryptor {
    /// Create from a raw 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Create from a hex-encoded key string (64 hex chars = 32 bytes).
    pub fn from_hex_key(hex_key: &str) -> Result<Self, EncryptionError> {
        let hex_key = hex_key.trim();
        if hex_key.len() != 64 {
            return Err(EncryptionError::InvalidKeyLength(hex_key.len()));
        }
        let bytes = hex_decode(hex_key)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidKeyLength(0))?;
        Ok(Self::new(&key))
    }

    /// Create from the `ARBITER_STORAGE_ENCRYPTION_KEY` environment variable.
    ///
    /// Returns `Ok(None)` when the variable is absent or empty (encryption
    /// disabled). Returns `Err` when the variable is present but malformed.
    pub fn from_env() -> Result<Option<Self>, EncryptionError> {
        match std::env::var("ARBITER_STORAGE_ENCRYPTION_KEY") {
            Ok(val) if !val.trim().is_empty() => Ok(Some(Self::from_hex_key(&val)?)),
            _ => Ok(None),
        }
    }

    /// Encrypt a UTF-8 string field.
    ///
    /// Returns a base64-encoded blob containing `nonce || ciphertext`.
    pub fn encrypt_field(&self, plaintext: &str) -> Result<String, EncryptionError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // nonce || ciphertext
        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&combined))
    }

    /// Decrypt a base64-encoded `nonce || ciphertext` blob back to the
    /// original UTF-8 string.
    pub fn decrypt_field(&self, encoded: &str) -> Result<String, EncryptionError> {
        let combined = BASE64
            .decode(encoded)
            .map_err(|e| EncryptionError::InvalidCiphertext(e.to_string()))?;

        if combined.len() < 13 {
            // 12-byte nonce + at least 1 byte ciphertext
            return Err(EncryptionError::InvalidCiphertext(
                "ciphertext too short".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        String::from_utf8(plaintext)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt a `Vec<String>` by JSON-serializing then encrypting.
    pub fn encrypt_string_vec(&self, values: &[String]) -> Result<String, EncryptionError> {
        let json = serde_json::to_string(values)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
        self.encrypt_field(&json)
    }

    /// Decrypt back to `Vec<String>`.
    pub fn decrypt_string_vec(&self, ciphertext: &str) -> Result<Vec<String>, EncryptionError> {
        let json = self.decrypt_field(ciphertext)?;
        serde_json::from_str(&json)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
    }
}

/// Decode a hex string to bytes (no external hex crate needed).
fn hex_decode(hex: &str) -> Result<Vec<u8>, EncryptionError> {
    if hex.len() % 2 != 0 {
        return Err(EncryptionError::InvalidHex(
            "odd number of hex characters".into(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| EncryptionError::InvalidHex(e.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    fn key_to_hex(key: &[u8; 32]) -> String {
        key.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let original = "sensitive session intent: read all financials";
        let encrypted = enc.encrypt_field(original).unwrap();
        let decrypted = enc.decrypt_field(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypted_bytes_differ_from_plaintext() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let plaintext = "my-secret-intent";
        let encrypted = enc.encrypt_field(plaintext).unwrap();

        // The encrypted output (base64) must not contain the plaintext
        assert!(
            !encrypted.contains(plaintext),
            "encrypted output must not contain plaintext substring"
        );
    }

    #[test]
    fn different_encryptions_produce_different_ciphertext() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let plaintext = "deterministic input";
        let ct1 = enc.encrypt_field(plaintext).unwrap();
        let ct2 = enc.encrypt_field(plaintext).unwrap();

        assert_ne!(
            ct1, ct2,
            "two encryptions of the same plaintext must differ (random nonce)"
        );
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = test_key();
        let key2 = test_key();

        let enc1 = FieldEncryptor::new(&key1);
        let enc2 = FieldEncryptor::new(&key2);

        let encrypted = enc1.encrypt_field("secret").unwrap();
        let result = enc2.decrypt_field(&encrypted);

        assert!(
            result.is_err(),
            "decryption with wrong key must fail"
        );
    }

    #[test]
    fn missing_env_key_returns_none() {
        // Ensure the variable is not set
        std::env::remove_var("ARBITER_STORAGE_ENCRYPTION_KEY");
        let result = FieldEncryptor::from_env().unwrap();
        assert!(result.is_none(), "from_env with no var must return None");
    }

    #[test]
    fn encrypt_decrypt_string_vec_roundtrip() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let tools = vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "execute_command".to_string(),
        ];
        let encrypted = enc.encrypt_string_vec(&tools).unwrap();
        let decrypted = enc.decrypt_string_vec(&encrypted).unwrap();

        assert_eq!(decrypted, tools);
    }

    #[test]
    fn corrupt_ciphertext_fails() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let encrypted = enc.encrypt_field("valid data").unwrap();

        // Decode, corrupt a byte in the ciphertext portion, re-encode
        let mut raw = BASE64.decode(&encrypted).unwrap();
        if raw.len() > 12 {
            // Flip a bit in the ciphertext (past the nonce)
            raw[13] ^= 0xFF;
        }
        let corrupted = BASE64.encode(&raw);

        let result = enc.decrypt_field(&corrupted);
        assert!(
            result.is_err(),
            "corrupted ciphertext must fail AEAD verification"
        );
    }

    #[test]
    fn from_hex_key_roundtrip() {
        let key = test_key();
        let hex = key_to_hex(&key);

        let enc = FieldEncryptor::from_hex_key(&hex).unwrap();
        let encrypted = enc.encrypt_field("hex key test").unwrap();
        let decrypted = enc.decrypt_field(&encrypted).unwrap();

        assert_eq!(decrypted, "hex key test");
    }

    #[test]
    fn from_hex_key_invalid_length() {
        let result = FieldEncryptor::from_hex_key("0011aabb");
        assert!(result.is_err());
    }

    #[test]
    fn from_hex_key_invalid_chars() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let result = FieldEncryptor::from_hex_key(bad);
        assert!(result.is_err());
    }

    #[test]
    fn env_key_present_and_valid() {
        let key = test_key();
        let hex = key_to_hex(&key);

        std::env::set_var("ARBITER_STORAGE_ENCRYPTION_KEY", &hex);
        let result = FieldEncryptor::from_env();
        std::env::remove_var("ARBITER_STORAGE_ENCRYPTION_KEY");

        let enc = result.unwrap().expect("should return Some when key is set");
        let ct = enc.encrypt_field("env test").unwrap();
        let pt = enc.decrypt_field(&ct).unwrap();
        assert_eq!(pt, "env test");
    }

    #[test]
    fn empty_string_roundtrip() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let encrypted = enc.encrypt_field("").unwrap();
        let decrypted = enc.decrypt_field(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn empty_vec_roundtrip() {
        let key = test_key();
        let enc = FieldEncryptor::new(&key);

        let encrypted = enc.encrypt_string_vec(&[]).unwrap();
        let decrypted = enc.decrypt_string_vec(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }
}
