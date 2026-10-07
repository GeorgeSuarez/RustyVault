use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use color_eyre::eyre;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const VERIFIER_PLAINTEXT: &str = "RUSTY-VAULT-VERIFIER";

/// Argon2id cost parameters.
///
/// These are persisted per vault (see [`KdfParams::META_KEY`]) so that a
/// vault created with one set of costs stays unlockable even if the defaults
/// chosen here — or the defaults inside the `argon2` crate — change later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Argon2id OWASP-recommended baseline (19 MiB, 2 iterations, 1 lane).
        Self {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// `meta` table key under which the parameters are stored.
    pub const META_KEY: &str = "argon2_params";

    /// Serialize as `m=<kib>,t=<passes>,p=<lanes>`.
    pub fn encode(&self) -> String {
        format!("m={},t={},p={}", self.m_cost_kib, self.t_cost, self.p_cost)
    }

    /// Parse the format produced by [`KdfParams::encode`]. Returns `None`
    /// for anything malformed rather than silently falling back to defaults.
    pub fn decode(encoded: &str) -> Option<Self> {
        let mut m_cost_kib = None;
        let mut t_cost = None;
        let mut p_cost = None;
        for part in encoded.split(',') {
            let (name, value) = part.split_once('=')?;
            let value: u32 = value.trim().parse().ok()?;
            match name.trim() {
                "m" => m_cost_kib = Some(value),
                "t" => t_cost = Some(value),
                "p" => p_cost = Some(value),
                _ => return None,
            }
        }
        Some(Self {
            m_cost_kib: m_cost_kib?,
            t_cost: t_cost?,
            p_cost: p_cost?,
        })
    }

    fn to_argon2(self) -> eyre::Result<Params> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| eyre::eyre!("invalid Argon2 parameters: {e}"))
    }
}

/// 32-byte AES-256 key derived from the master password.
///
/// `ZeroizeOnDrop` guarantees the key material is overwritten with zeros when
/// the value is dropped, including transient clones. `Zeroize` remains
/// available for explicit clearing on lock.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive the vault key from the master password.
///
/// Uses `hash_password_into` so the derived bytes are written straight into a
/// stack buffer that we control and zeroize on failure — no `PasswordHash`
/// object (and therefore no stray copy of the key) is allocated.
pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> eyre::Result<MasterKey> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2()?);
    let mut raw = [0u8; KEY_LEN];
    match argon2.hash_password_into(password.as_bytes(), salt, &mut raw) {
        Ok(()) => Ok(MasterKey(raw)),
        Err(e) => {
            raw.zeroize();
            Err(eyre::eyre!("Argon2 hashing failed: {e}"))
        }
    }
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
    let plaintext_result = cipher.decrypt(nonce, ciphertext);
    // The decoded buffer is scrubbed even when decryption fails.
    decoded.zeroize();
    let plaintext = plaintext_result.map_err(|e| eyre::eyre!("AES decryption failed: {e}"))?;
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

    /// Derived by the original `hash_password`-based implementation with
    /// `Argon2::default()` and salt `[0x11; 32]`. If this test breaks,
    /// existing vaults can no longer be unlocked.
    const LEGACY_KDF_VECTOR: [u8; KEY_LEN] = [
        0x49, 0xfe, 0x0f, 0x5b, 0x24, 0x83, 0xea, 0xad, 0x9e, 0x27, 0x04, 0x38, 0x65, 0xab, 0x59,
        0x72, 0x97, 0x77, 0x54, 0xbc, 0x78, 0x8f, 0xcd, 0xa8, 0x3a, 0x77, 0xa4, 0x98, 0x34, 0xe2,
        0x82, 0x21,
    ];

    #[test]
    fn default_params_match_legacy_derivation() {
        let salt = [0x11u8; SALT_LEN];
        let key = derive_key("compat-test-password", &salt, KdfParams::default()).unwrap();
        assert_eq!(key.as_bytes(), &LEGACY_KDF_VECTOR);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let password = "correct horse battery staple";
        let salt = gen_salt();
        let key = derive_key(password, &salt, KdfParams::default()).unwrap();
        let plaintext = "hunter2";
        let blob = encrypt(&key, plaintext).unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let salt = gen_salt();
        let params = KdfParams::default();
        let good = derive_key("master", &salt, params).unwrap();
        let bad = derive_key("not-master", &salt, params).unwrap();
        let verifier = make_verifier(&good).unwrap();
        assert!(check_verifier(&good, &verifier).unwrap());
        assert!(!check_verifier(&bad, &verifier).unwrap());
    }

    #[test]
    fn different_keys_yield_different_ciphertexts() {
        let salt = gen_salt();
        let params = KdfParams::default();
        let key1 = derive_key("one", &salt, params).unwrap();
        let key2 = derive_key("two", &salt, params).unwrap();
        let blob1 = encrypt(&key1, "secret").unwrap();
        let blob2 = encrypt(&key2, "secret").unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn master_key_zeroize_clears_bytes() {
        let salt = gen_salt();
        let mut key = derive_key("zeroize-me", &salt, KdfParams::default()).unwrap();
        assert!(key.as_bytes().iter().any(|&b| b != 0));
        key.zeroize();
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    /// Compile-time guard: the type must run its zeroizing drop glue.
    /// `#[derive(Zeroize)]` alone does *not* provide this.
    #[test]
    fn master_key_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MasterKey>();
    }

    #[test]
    fn kdf_params_encode_decode_roundtrip() {
        let params = KdfParams {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 4,
        };
        assert_eq!(KdfParams::decode(&params.encode()), Some(params));
    }

    #[test]
    fn kdf_params_decode_rejects_garbage() {
        for bad in [
            "",
            "m=19456,t=2",
            "m=19456,t=2,p=1,extra=9",
            "m=abc,t=2,p=1",
            "m=19456;t=2;p=1",
            "m=-1,t=2,p=1",
        ] {
            assert_eq!(KdfParams::decode(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn kdf_params_reject_impossible_costs() {
        let params = KdfParams {
            m_cost_kib: 1,
            t_cost: 2,
            p_cost: 1,
        };
        assert!(derive_key("pw", &[0u8; SALT_LEN], params).is_err());
    }

    #[test]
    fn decrypt_rejects_short_blob() {
        let key = derive_key("pw", &[7u8; SALT_LEN], KdfParams::default()).unwrap();
        assert!(decrypt(&key, &B64.encode([0u8; 4])).is_err());
    }
}
