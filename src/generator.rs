//! Password and passphrase generation, plus the entropy estimate shown in the
//! generator panel.
//!
//! Randomness comes from the OS CSPRNG via [`getrandom`]; indices are drawn
//! with rejection sampling so every character is equally likely (a plain
//! modulo would bias the first `256 % n` characters).

use serde::{Deserialize, Serialize};

pub use crate::words::WORDS;

/// Characters that Bitwarden's generator offers, grouped by class.
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
/// Upper-case letters.
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Digits.
pub const DIGITS: &str = "0123456789";
/// Symbols Bitwarden includes.
pub const SYMBOLS: &str = "!@#$%^&*";

/// Ambiguous characters Bitwarden can leave out.
const AMBIGUOUS: &[char] = &['l', 'I', '1', 'O', '0', 'o'];

/// Failures the generator can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratorError {
    /// The OS random source failed.
    RandomUnavailable,
    /// The settings would produce an empty character set or result.
    InvalidSettings,
}

impl GeneratorError {
    /// A message for the UI.
    pub const fn message(self) -> &'static str {
        match self {
            Self::RandomUnavailable => "OS の乱数源を利用できません",
            Self::InvalidSettings => "生成設定が不正です（文字種または長さを確認）",
        }
    }
}

/// Password generator settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordSettings {
    /// Length in characters.
    pub length: usize,
    /// Include `a-z`.
    pub lowercase: bool,
    /// Include `A-Z`.
    pub uppercase: bool,
    /// Include `0-9`.
    pub digits: bool,
    /// Include `!@#$%^&*`.
    pub symbols: bool,
    /// Exclude characters that are easy to confuse (`l`, `I`, `1`, `O`, `0`).
    pub avoid_ambiguous: bool,
}

impl Default for PasswordSettings {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

impl PasswordSettings {
    /// The character pool these settings select, in a stable order.
    ///
    /// The pool is the concatenation of the enabled classes, so its length and
    /// therefore the entropy estimate only depend on which classes are on.
    pub fn alphabet(&self) -> String {
        let mut pool = String::new();
        if self.lowercase {
            pool.push_str(LOWERCASE);
        }
        if self.uppercase {
            pool.push_str(UPPERCASE);
        }
        if self.digits {
            pool.push_str(DIGITS);
        }
        if self.symbols {
            pool.push_str(SYMBOLS);
        }
        if self.avoid_ambiguous {
            pool.retain(|c| !AMBIGUOUS.contains(&c));
        }
        pool
    }

    /// Draw one password.
    ///
    /// # Errors
    ///
    /// [`GeneratorError::InvalidSettings`] when no class is enabled or the
    /// length is zero; [`GeneratorError::RandomUnavailable`] if the OS source
    /// fails.
    pub fn generate(&self) -> Result<String, GeneratorError> {
        let pool: Vec<char> = self.alphabet().chars().collect();
        if pool.is_empty() || self.length == 0 {
            return Err(GeneratorError::InvalidSettings);
        }
        let mut out = String::with_capacity(self.length);
        for _ in 0..self.length {
            out.push(pool[usize::from(draw_below(pool.len() as u16)?)]);
        }
        Ok(out)
    }
}

/// Passphrase generator settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseSettings {
    /// Number of words.
    pub words: usize,
    /// Separator between words.
    pub separator: String,
    /// Capitalise each word.
    pub capitalize: bool,
    /// Append a one-digit number.
    pub include_number: bool,
}

impl Default for PassphraseSettings {
    fn default() -> Self {
        Self {
            words: 4,
            separator: "-".to_string(),
            capitalize: true,
            include_number: false,
        }
    }
}

impl PassphraseSettings {
    /// Draw one passphrase.
    ///
    /// # Errors
    ///
    /// [`GeneratorError::InvalidSettings`] when the word count is zero or the
    /// list is empty; [`GeneratorError::RandomUnavailable`] if the OS source
    /// fails.
    pub fn generate(&self) -> Result<String, GeneratorError> {
        if self.words == 0 || WORDS.is_empty() {
            return Err(GeneratorError::InvalidSettings);
        }
        let mut parts = Vec::with_capacity(self.words);
        for _ in 0..self.words {
            let index = usize::from(draw_below(WORDS.len() as u16)?);
            let word = WORDS.get(index).copied().unwrap_or("word");
            parts.push(if self.capitalize {
                capitalize(word)
            } else {
                word.to_string()
            });
        }
        let mut out = parts.join(&self.separator);
        if self.include_number {
            let digit = draw_below(10)?;
            out.push_str(&digit.to_string());
        }
        Ok(out)
    }
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Draw a uniform value in `0..bound` from the OS CSPRNG.
///
/// Rejection sampling keeps the distribution flat: bytes at or above the
/// largest multiple of `bound` are discarded rather than folded in.
fn draw_below(bound: u16) -> Result<u16, GeneratorError> {
    if bound == 0 {
        return Err(GeneratorError::InvalidSettings);
    }
    let bound = u32::from(bound);
    // For bounds that do not divide 256 evenly we need a wider buffer to
    // avoid discarding too many draws; the loop retries up to 1024 times.
    let mut buf = [0u8; 4];
    for _ in 0..1024 {
        getrandom::fill(&mut buf).map_err(|_| GeneratorError::RandomUnavailable)?;
        // Pack four bytes into a u32 so `bound << 8` still fits comfortably.
        let value = u32::from_le_bytes(buf);
        if bound <= 256 {
            // Fast path: only the low byte is meaningful.
            let byte = value as u8;
            let limit = 256 - (256 % bound);
            if u32::from(byte) < limit {
                return u16::try_from(u32::from(byte) % bound)
                    .map_err(|_| GeneratorError::InvalidSettings);
            }
        } else {
            // General rejection sampling over the whole u32 range.
            let limit = u32::MAX - (u32::MAX % bound);
            if value < limit {
                return u16::try_from(value % bound).map_err(|_| GeneratorError::InvalidSettings);
            }
        }
    }
    Err(GeneratorError::RandomUnavailable)
}

/// Draw a uniform index in `0..bound` from the OS CSPRNG.
///
/// Uses the same rejection sampling as the internal password generator.
///
/// # Errors
///
/// [`GeneratorError::InvalidSettings`] when `bound` is zero, or
/// [`GeneratorError::RandomUnavailable`] if the OS source fails.
pub fn random_index(bound: u16) -> Result<u16, GeneratorError> {
    draw_below(bound)
}

/// Shannon entropy in bits for a uniform choice among `alphabet` symbols
/// repeated `length` times.
pub fn entropy_bits(alphabet: usize, length: usize) -> f64 {
    if alphabet <= 1 || length == 0 {
        return 0.0;
    }
    length as f64 * (alphabet as f64).log2()
}

/// A coarse strength bucket derived from entropy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// Less than 40 bits: weak.
    Weak,
    /// 40-64 bits: fair.
    Fair,
    /// 64-90 bits: good.
    Good,
    /// 90 bits or more: strong.
    Strong,
}

impl Strength {
    /// Bucket `bits`.
    pub fn from_bits(bits: f64) -> Self {
        if bits < 40.0 {
            Self::Weak
        } else if bits < 64.0 {
            Self::Fair
        } else if bits < 90.0 {
            Self::Good
        } else {
            Self::Strong
        }
    }

    /// The bucket's label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Weak => "弱い",
            Self::Fair => "ふつう",
            Self::Good => "良い",
            Self::Strong => "強い",
        }
    }

    /// A 0-100 estimate of offline guessing difficulty, shown as a bar.
    ///
    /// This is a display heuristic, not a crack-time model.
    pub fn score(self, bits: f64) -> u8 {
        let capped = bits.clamp(0.0, 128.0);
        let base = (capped / 128.0 * 100.0).round();
        u8::try_from(base as i64).unwrap_or(100)
    }
}

/// The entropy of a drawn password, for the strength meter.
pub fn password_entropy(settings: &PasswordSettings) -> f64 {
    entropy_bits(settings.alphabet().chars().count(), settings.length)
}

/// The entropy of a drawn passphrase.
pub fn passphrase_entropy(settings: &PassphraseSettings) -> f64 {
    let base = entropy_bits(WORDS.len(), settings.words);
    if settings.include_number {
        base + (10.0f64).log2()
    } else {
        base
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_follows_the_enabled_classes() {
        let all = PasswordSettings::default();
        assert_eq!(
            all.alphabet().chars().count(),
            LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len()
        );
        let digits_only = PasswordSettings {
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            ..PasswordSettings::default()
        };
        assert_eq!(digits_only.alphabet(), DIGITS);
        let none = PasswordSettings {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordSettings::default()
        };
        assert!(none.alphabet().is_empty());
        assert_eq!(none.generate(), Err(GeneratorError::InvalidSettings));
    }

    #[test]
    fn avoid_ambiguous_removes_only_the_listed_characters() {
        let settings = PasswordSettings {
            avoid_ambiguous: true,
            symbols: false,
            ..PasswordSettings::default()
        };
        let pool = settings.alphabet();
        for ch in AMBIGUOUS {
            assert!(!pool.contains(*ch), "{ch} should be gone");
        }
        assert!(pool.contains('a') && pool.contains('Z') && pool.contains('5'));
        assert_eq!(
            pool.chars().count(),
            LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() - 6
        );
    }

    #[test]
    fn generated_passwords_respect_the_settings() {
        let settings = PasswordSettings {
            length: 32,
            avoid_ambiguous: true,
            ..PasswordSettings::default()
        };
        let pool = settings.alphabet();
        for _ in 0..64 {
            let password = settings.generate().unwrap();
            assert_eq!(password.chars().count(), 32);
            assert!(password.chars().all(|c| pool.contains(c)));
        }
    }

    #[test]
    fn zero_length_is_rejected() {
        let settings = PasswordSettings {
            length: 0,
            ..PasswordSettings::default()
        };
        assert_eq!(settings.generate(), Err(GeneratorError::InvalidSettings));
    }

    #[test]
    fn passwords_are_not_all_the_same() {
        let settings = PasswordSettings::default();
        let first = settings.generate().unwrap();
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..32 {
            distinct.insert(settings.generate().unwrap());
        }
        assert!(distinct.len() > 30, "only {} distinct", distinct.len());
        assert!(distinct.contains(&first) || distinct.len() == 32);
    }

    #[test]
    fn passphrases_use_words_and_the_separator() {
        let settings = PassphraseSettings {
            words: 5,
            separator: ".".to_string(),
            capitalize: false,
            include_number: false,
        };
        let phrase = settings.generate().unwrap();
        let parts: Vec<&str> = phrase.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|part| WORDS.contains(part)));
    }

    #[test]
    fn passphrases_capitalize_and_append_a_digit() {
        let settings = PassphraseSettings {
            words: 3,
            separator: "-".to_string(),
            capitalize: true,
            include_number: true,
        };
        let phrase = settings.generate().unwrap();
        let last = phrase.chars().last().unwrap();
        assert!(last.is_ascii_digit(), "{phrase}");
        let body = &phrase[..phrase.len() - 1];
        for part in body.split('-') {
            let first = part.chars().next().unwrap();
            assert!(first.is_uppercase(), "{part}");
        }
        assert_eq!(settings.words, body.split('-').count());
    }

    #[test]
    fn zero_words_is_rejected() {
        let settings = PassphraseSettings {
            words: 0,
            ..PassphraseSettings::default()
        };
        assert_eq!(settings.generate(), Err(GeneratorError::InvalidSettings));
    }

    #[test]
    fn word_list_is_clean_and_prefix_free_enough() {
        assert!(!WORDS.is_empty(), "empty word list");
        let mut sorted: Vec<&str> = WORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), WORDS.len(), "duplicate words");
        assert!(WORDS.iter().all(|word| {
            !word.is_empty() && word.len() >= 3 && word.chars().all(|c| c.is_ascii_lowercase())
        }));
    }

    #[test]
    fn entropy_and_strength_buckets() {
        assert_eq!(entropy_bits(0, 10), 0.0);
        assert_eq!(entropy_bits(1, 10), 0.0);
        assert_eq!(entropy_bits(2, 0), 0.0);
        // 64 symbols * 16 chars = 96 bits.
        assert!((entropy_bits(64, 16) - 96.0).abs() < 1e-9);

        assert_eq!(Strength::from_bits(10.0), Strength::Weak);
        assert_eq!(Strength::from_bits(50.0), Strength::Fair);
        assert_eq!(Strength::from_bits(70.0), Strength::Good);
        assert_eq!(Strength::from_bits(200.0), Strength::Strong);
        assert_eq!(Strength::Weak.score(0.0), 0);
        assert_eq!(Strength::Strong.score(128.0), 100);
        assert_eq!(Strength::Good.score(1000.0), 100);
        assert_eq!(Strength::Good.label(), "良い");
    }

    #[test]
    fn settings_entropy_tracks_length_and_classes() {
        let settings = PasswordSettings {
            length: 16,
            ..PasswordSettings::default()
        };
        let full = password_entropy(&settings);
        let fewer = password_entropy(&PasswordSettings {
            symbols: false,
            ..settings.clone()
        });
        assert!(full > fewer);
        let longer = password_entropy(&PasswordSettings {
            length: 32,
            ..settings
        });
        assert!((longer - full * 2.0).abs() < 1e-9);
    }

    #[test]
    fn passphrase_entropy_follows_word_count() {
        let base = PassphraseSettings {
            words: 4,
            include_number: false,
            ..PassphraseSettings::default()
        };
        let with_number = PassphraseSettings {
            include_number: true,
            ..base.clone()
        };
        let more_words = PassphraseSettings {
            words: 6,
            ..base.clone()
        };
        assert!(passphrase_entropy(&with_number) > passphrase_entropy(&base));
        assert!(passphrase_entropy(&more_words) > passphrase_entropy(&base));
    }

    #[test]
    fn random_index_respects_the_bound() {
        for bound in [1u16, 2, 10, 62] {
            for _ in 0..256 {
                let value = random_index(bound).unwrap();
                assert!(value < bound, "{value} >= {bound}");
            }
        }
        assert_eq!(random_index(0), Err(GeneratorError::InvalidSettings));
    }

    #[test]
    fn error_messages_are_present() {
        assert!(!GeneratorError::RandomUnavailable.message().is_empty());
        assert!(!GeneratorError::InvalidSettings.message().is_empty());
    }

    #[test]
    fn settings_round_trip_through_json() {
        let settings = PasswordSettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        let back: PasswordSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(settings, back);
        let phrase = PassphraseSettings::default();
        let json = serde_json::to_string(&phrase).unwrap();
        let back: PassphraseSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(phrase, back);
    }
}
