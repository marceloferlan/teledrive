//! Encrypted-at-rest storage for the credential files (vault and session).
//!
//! A random 256-bit master key lives in the OS credential store (macOS
//! Keychain, Windows Credential Manager, Linux Secret Service). The JSON
//! documents are sealed with AES-256-GCM and written atomically with owner-only
//! permissions. There is deliberately no plaintext fallback: when the OS
//! credential store is unavailable every call fails with `SECURE_STORE_UNAVAILABLE`.
//!
//! Mobile targets (Android, iOS) are the exception: there is no credential
//! store integration yet, so they keep the original plain JSON file, which
//! lives in the OS-isolated private app directory.
//!
//! Blob layout: `MAGIC (4) || nonce (12) || ciphertext+tag`. A per-file
//! associated-data label is authenticated, so a vault blob cannot be swapped
//! in as a session blob.
//!
//! Legacy plaintext JSON files are migrated on first read: encrypt, write,
//! decrypt and compare, and only then delete the plaintext.

#[cfg(any(not(mobile), test))]
use aes_gcm::aead::{Aead, OsRng, Payload};
#[cfg(any(not(mobile), test))]
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use serde_json::Value;
use std::path::Path;
#[cfg(not(mobile))]
use std::sync::{Mutex, OnceLock};

#[cfg(not(mobile))]
pub const ERR_UNAVAILABLE: &str = "SECURE_STORE_UNAVAILABLE";

#[cfg(any(not(mobile), test))]
const MAGIC: &[u8; 4] = b"TDS1";
#[cfg(any(not(mobile), test))]
const NONCE_LEN: usize = 12;
#[cfg(any(not(mobile), test))]
const KEY_LEN: usize = 32;

#[cfg(not(mobile))]
fn unavailable(detail: impl std::fmt::Display) -> String {
    format!("{ERR_UNAVAILABLE}: {detail}")
}

// ----------------------------------------------------------------------------
// Master key
// ----------------------------------------------------------------------------

#[cfg(not(mobile))]
static MASTER_KEY: OnceLock<[u8; KEY_LEN]> = OnceLock::new();
#[cfg(not(mobile))]
static KEY_INIT: Mutex<()> = Mutex::new(());

/// Returns the master key, creating it in the OS credential store on first use.
/// The key is cached for the life of the process so the OS is asked once.
#[cfg(not(mobile))]
fn master_key() -> Result<[u8; KEY_LEN], String> {
    if let Some(key) = MASTER_KEY.get() {
        return Ok(*key);
    }
    let _guard = KEY_INIT
        .lock()
        .map_err(|_| unavailable("key initialisation lock poisoned"))?;
    if let Some(key) = MASTER_KEY.get() {
        return Ok(*key);
    }
    let key = load_or_create_os_key()?;
    let _ = MASTER_KEY.set(key);
    Ok(key)
}

#[cfg(all(
    not(mobile),
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn load_or_create_os_key() -> Result<[u8; KEY_LEN], String> {
    let entry = keyring::Entry::new("com.teledrive.app", "vault-master-key")
        .map_err(unavailable)?;
    match entry.get_secret() {
        Ok(bytes) => <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
            // Never replace a malformed key: that would orphan the existing data.
            unavailable("stored master key has an unexpected length")
        }),
        Err(keyring::Error::NoEntry) => {
            let key: [u8; KEY_LEN] = Aes256Gcm::generate_key(OsRng).into();
            entry.set_secret(&key).map_err(unavailable)?;
            Ok(key)
        }
        Err(e) => Err(unavailable(e)),
    }
}

#[cfg(all(
    not(mobile),
    not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
))]
fn load_or_create_os_key() -> Result<[u8; KEY_LEN], String> {
    Err(unavailable("no OS credential store support on this platform"))
}

// ----------------------------------------------------------------------------
// Sealing
// ----------------------------------------------------------------------------

#[cfg(any(not(mobile), test))]
fn encrypt(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| "Failed to encrypt secure store payload".to_string())?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

#[cfg(any(not(mobile), test))]
fn decrypt(key: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < MAGIC.len() + NONCE_LEN || &blob[..MAGIC.len()] != MAGIC {
        return Err("Secure store file is corrupt or has an unknown format".to_string());
    }
    let (nonce, sealed) = blob[MAGIC.len()..].split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map_err(|_| {
            "Secure store file cannot be decrypted (wrong key or tampered data)".to_string()
        })
}

// ----------------------------------------------------------------------------
// Files
// ----------------------------------------------------------------------------

#[cfg(any(not(mobile), test))]
fn load_with_key(
    key: &[u8; KEY_LEN],
    enc_path: &Path,
    legacy_path: &Path,
    aad: &[u8],
) -> Result<Option<Value>, String> {
    if enc_path.exists() {
        let blob = std::fs::read(enc_path)
            .map_err(|e| format!("Failed to read {}: {e}", enc_path.display()))?;
        let plain = decrypt(key, aad, &blob)?;
        return serde_json::from_slice(&plain)
            .map(Some)
            .map_err(|e| format!("Secure store content is not valid JSON: {e}"));
    }
    if !legacy_path.exists() {
        return Ok(None);
    }

    // Migrate the legacy plaintext file. The plaintext is removed only after
    // the encrypted copy has been read back and matches.
    let legacy = std::fs::read_to_string(legacy_path)
        .map_err(|e| format!("Failed to read {}: {e}", legacy_path.display()))?;
    let value: Value = serde_json::from_str(&legacy).map_err(|e| {
        format!(
            "Legacy file {} is corrupt (refusing to migrate): {e}",
            legacy_path.display()
        )
    })?;
    store_with_key(key, enc_path, &value, aad)?;
    let reread = load_with_key(key, enc_path, legacy_path, aad)?;
    if reread.as_ref() != Some(&value) {
        let _ = std::fs::remove_file(enc_path);
        return Err("Migration verification failed; legacy file kept".to_string());
    }
    std::fs::remove_file(legacy_path)
        .map_err(|e| format!("Failed to remove {}: {e}", legacy_path.display()))?;
    Ok(Some(value))
}

#[cfg(any(not(mobile), test))]
fn store_with_key(
    key: &[u8; KEY_LEN],
    enc_path: &Path,
    value: &Value,
    aad: &[u8],
) -> Result<(), String> {
    let plain = serde_json::to_vec(value).map_err(|e| format!("Failed to encode JSON: {e}"))?;
    crate::atomic_write(enc_path, &encrypt(key, aad, &plain)?)
}

/// Loads a sealed JSON document, migrating `legacy_path` when needed.
/// Returns `Ok(None)` when neither file exists, without touching the OS
/// credential store.
#[cfg(not(mobile))]
pub fn load(enc_path: &Path, legacy_path: &Path, aad: &[u8]) -> Result<Option<Value>, String> {
    if !enc_path.exists() && !legacy_path.exists() {
        return Ok(None);
    }
    load_with_key(&master_key()?, enc_path, legacy_path, aad)
}

/// Seals and atomically writes a JSON document.
#[cfg(not(mobile))]
pub fn store(
    enc_path: &Path,
    _legacy_path: &Path,
    value: &Value,
    aad: &[u8],
) -> Result<(), String> {
    store_with_key(&master_key()?, enc_path, value, aad)
}

/// Mobile: plain JSON in the private app directory (no credential store yet).
#[cfg(mobile)]
pub fn load(_enc_path: &Path, legacy_path: &Path, _aad: &[u8]) -> Result<Option<Value>, String> {
    if !legacy_path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(legacy_path)
        .map_err(|e| format!("Failed to read {}: {e}", legacy_path.display()))?;
    serde_json::from_str(&contents)
        .map(Some)
        .map_err(|e| format!("File {} is corrupt: {e}", legacy_path.display()))
}

#[cfg(mobile)]
pub fn store(
    _enc_path: &Path,
    legacy_path: &Path,
    value: &Value,
    _aad: &[u8],
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("Failed to encode JSON: {e}"))?;
    crate::atomic_write(legacy_path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];
    const AAD: &[u8] = b"test:vault";

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "teledrive-secure-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_returns_the_original_plaintext() {
        let blob = encrypt(&KEY, AAD, b"secret").unwrap();
        assert_eq!(decrypt(&KEY, AAD, &blob).unwrap(), b"secret");
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let blob = encrypt(&KEY, AAD, b"telegram-session-token").unwrap();
        assert!(!blob.windows(8).any(|w| w == b"telegram"));
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        assert_ne!(
            encrypt(&KEY, AAD, b"x").unwrap(),
            encrypt(&KEY, AAD, b"x").unwrap()
        );
    }

    #[test]
    fn tampered_blob_is_rejected() {
        let mut blob = encrypt(&KEY, AAD, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt(&KEY, AAD, &blob).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let blob = encrypt(&KEY, AAD, b"secret").unwrap();
        assert!(decrypt(&[9u8; KEY_LEN], AAD, &blob).is_err());
    }

    #[test]
    fn blob_is_bound_to_its_associated_data() {
        let blob = encrypt(&KEY, b"test:vault", b"secret").unwrap();
        assert!(decrypt(&KEY, b"test:session", &blob).is_err());
    }

    #[test]
    fn truncated_or_foreign_blob_is_rejected() {
        assert!(decrypt(&KEY, AAD, b"TDS1").is_err());
        assert!(decrypt(&KEY, AAD, &[0u8; 64]).is_err());
    }

    #[test]
    fn store_then_load_round_trips_json() {
        let dir = temp_dir("roundtrip");
        let enc = dir.join("v.enc");
        let legacy = dir.join("v.json");
        let value = json!({"telegram_session": "abc", "n": 1});

        store_with_key(&KEY, &enc, &value, AAD).unwrap();

        assert_eq!(
            load_with_key(&KEY, &enc, &legacy, AAD).unwrap(),
            Some(value)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_files_load_as_none() {
        let dir = temp_dir("missing");
        assert_eq!(
            load_with_key(&KEY, &dir.join("a.enc"), &dir.join("a.json"), AAD).unwrap(),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn legacy_file_is_migrated_and_plaintext_removed() {
        let dir = temp_dir("migrate");
        let enc = dir.join("v.enc");
        let legacy = dir.join("v.json");
        std::fs::write(&legacy, br#"{"telegram_session":"abc"}"#).unwrap();

        let loaded = load_with_key(&KEY, &enc, &legacy, AAD).unwrap();

        assert_eq!(loaded, Some(json!({"telegram_session": "abc"})));
        assert!(!legacy.exists(), "plaintext must be deleted after migration");
        let raw = std::fs::read(&enc).unwrap();
        assert!(!raw.windows(3).any(|w| w == b"abc"));
        assert_eq!(
            load_with_key(&KEY, &enc, &legacy, AAD).unwrap(),
            Some(json!({"telegram_session": "abc"}))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_legacy_file_is_kept_and_not_migrated() {
        let dir = temp_dir("corrupt-legacy");
        let enc = dir.join("v.enc");
        let legacy = dir.join("v.json");
        std::fs::write(&legacy, b"{not json").unwrap();

        assert!(load_with_key(&KEY, &enc, &legacy, AAD).is_err());
        assert!(legacy.exists());
        assert!(!enc.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn existing_encrypted_file_wins_and_legacy_is_left_untouched() {
        let dir = temp_dir("both");
        let enc = dir.join("v.enc");
        let legacy = dir.join("v.json");
        store_with_key(&KEY, &enc, &json!({"from": "enc"}), AAD).unwrap();
        std::fs::write(&legacy, br#"{"from":"legacy"}"#).unwrap();

        assert_eq!(
            load_with_key(&KEY, &enc, &legacy, AAD).unwrap(),
            Some(json!({"from": "enc"}))
        );
        assert!(legacy.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn undecryptable_file_is_an_error_not_an_empty_store() {
        let dir = temp_dir("undecryptable");
        let enc = dir.join("v.enc");
        let legacy = dir.join("v.json");
        store_with_key(&KEY, &enc, &json!({"a": 1}), AAD).unwrap();

        assert!(load_with_key(&[9u8; KEY_LEN], &enc, &legacy, AAD).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
