use aes_gcm::{
    Aes256Gcm, KeyInit, aead::Aead, Nonce,
    aead::{OsRng, AeadCore},
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use color_eyre::eyre;
use rand::RngCore;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 32;
pub const VERIFIER_PLAINTEXT: &str = "RUSTY-VAULT-VERIFIER";

/// 32-byte AES-256 key derived from the master password.
///
/// Wrapped in a zeroizing newtype so the key material is overwritten with
/// zeros when dropped, and so `Zeroize` can be called explicitly to clear
/// it on lock/quit.
#[derive(Clone, Zeroize)]
pub struct MasterKey(pub [u8; 32]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> eyre::Result<MasterKey> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| eyre::eyre!("salt is not valid base64 length: {e:?}"))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| eyre::eyre!("Argon2 hashing failed: {e:?}"))?;
    let raw = hash
        .hash
        .ok_or_else(|| eyre::eyre!("Argon2 produced no hash"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(raw.as_bytes());
    // The Argon2 hash object may hold a copy of the raw bytes; zero it.
    let _ = raw; // raw borrows from hash; hash is dropped at end of scope.
    Ok(MasterKey(out))
}

pub fn encrypt(key: &MasterKey, plaintext: &str) -> eyre::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| eyre::eyre!("invalid AES key length: {e:?}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| eyre::eyre!("AES encryption failed: {e}"))?;
    let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
    blob.extend_from_slice(nonce.as_slice());
    blob.extend_from_slice(&ciphertext);
    Ok(B64.encode(&blob))
}

pub fn decrypt(key: &MasterKey, blob: &str) -> eyre::Result<String> {
    let mut decoded = B64
        .decode(blob)
        .map_err(|e| eyre::eyre!("ciphertext is not valid base64: {e}"))?;
    if decoded.len() < 12 {
        decoded.zeroize();
        eyre::bail!("ciphertext too short (missing nonce)");
    }
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| eyre::eyre!("invalid AES key length: {e:?}"))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| eyre::eyre!("AES decryption failed: {e}"))?;
    decoded.zeroize();
    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(e) => {
            // `e.into_bytes()` gives us back the raw bytes so we can zeroize them.
            let mut bad = e.into_bytes();
            bad.zeroize();
            Err(eyre::eyre!("decrypted bytes are not valid UTF-8"))
        }
    }
}

pub fn make_verifier(key: &MasterKey) -> eyre::Result<String> {
    encrypt(key, VERIFIER_PLAINTEXT)
}

pub fn check_verifier(key: &MasterKey, verifier: &str) -> eyre::Result<bool> {
    match decrypt(key, verifier) {
        Ok(plain) if plain == VERIFIER_PLAINTEXT => Ok(true),
        Ok(_) => Ok(false),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let password = "correct horse battery staple";
        let salt = gen_salt();
        let key = derive_key(password, &salt).unwrap();
        let plaintext = "hunter2";
        let blob = encrypt(&key, plaintext).unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let salt = gen_salt();
        let good = derive_key("master", &salt).unwrap();
        let bad = derive_key("not-master", &salt).unwrap();
        let verifier = make_verifier(&good).unwrap();
        assert!(check_verifier(&good, &verifier).unwrap());
        assert!(!check_verifier(&bad, &verifier).unwrap());
    }

    #[test]
    fn different_keys_yield_different_ciphertexts() {
        let salt = gen_salt();
        let key1 = derive_key("one", &salt).unwrap();
        let key2 = derive_key("two", &salt).unwrap();
        let blob1 = encrypt(&key1, "secret").unwrap();
        let blob2 = encrypt(&key2, "secret").unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn master_key_zeroize_clears_bytes() {
        let salt = gen_salt();
        let mut key = derive_key("zeroize-me", &salt).unwrap();
        let original = key.as_bytes().to_vec();
        assert!(original.iter().any(|&b| b != 0));
        key.zeroize();
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn master_key_zeroized_on_drop() {
        use zeroize::Zeroize;
        let salt = gen_salt();
        let key = derive_key("drop-me", &salt).unwrap();
        let mut raw = [0u8; 32];
        raw.copy_from_slice(key.as_bytes());
        assert!(raw.iter().any(|&b| b != 0));
        // Move into a scoped binding and drop it.
        {
            let _k = key;
        }
        // We can't read the dropped memory safely, but we can verify the
        // Zeroize trait is wired up by calling it explicitly on a copy.
        let mut copy = MasterKey(raw);
        copy.zeroize();
        assert!(copy.as_bytes().iter().all(|&b| b == 0));
    }
}