//! Cryptographically random password generation.

use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;

/// Length used when the UI requests a generated password.
pub const DEFAULT_LEN: usize = 20;

const MIN_LEN: usize = 8;
const MAX_LEN: usize = 128;

// Ambiguous glyphs (l, I, O, 0, 1) are intentionally omitted.
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";

/// Generate a random password from OS entropy.
///
/// `len` is clamped to `[MIN_LEN, MAX_LEN]`. The result always contains at
/// least one lowercase letter, uppercase letter, digit, and symbol.
pub fn generate_password(len: usize) -> String {
    let len = len.clamp(MIN_LEN, MAX_LEN);
    let alphabet: Vec<char> = LOWER
        .iter()
        .chain(UPPER)
        .chain(DIGITS)
        .chain(SYMBOLS)
        .map(|&b| b as char)
        .collect();

    let mut rng = OsRng;
    let mut chars: Vec<char> = Vec::with_capacity(len);
    for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
        chars.push(class[rng.gen_range(0..class.len())] as char);
    }
    while chars.len() < len {
        chars.push(alphabet[rng.gen_range(0..alphabet.len())]);
    }
    chars.shuffle(&mut rng);

    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn respects_requested_length() {
        assert_eq!(generate_password(32).chars().count(), 32);
        assert_eq!(generate_password(DEFAULT_LEN).chars().count(), DEFAULT_LEN);
    }

    #[test]
    fn clamps_absurd_lengths() {
        assert_eq!(generate_password(0).chars().count(), MIN_LEN);
        assert_eq!(generate_password(usize::MAX).chars().count(), MAX_LEN);
    }

    #[test]
    fn includes_every_character_class() {
        for _ in 0..32 {
            let pw = generate_password(DEFAULT_LEN);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| c.is_ascii_punctuation()));
        }
    }

    #[test]
    fn consecutive_passwords_are_unique() {
        let generated: HashSet<String> = (0..64).map(|_| generate_password(DEFAULT_LEN)).collect();
        assert_eq!(generated.len(), 64);
    }
}
