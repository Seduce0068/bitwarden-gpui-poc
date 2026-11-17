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
#[serde(default)]
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
        self.class_pools().into_iter().flatten().collect()
    }

    /// The non-empty character pools of the enabled classes, in a stable order.
    /// Generation and the entropy estimate both derive from these pools.
    fn class_pools(&self) -> Vec<Vec<char>> {
        [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, class)| {
            class
                .chars()
                .filter(|c| !self.avoid_ambiguous || !AMBIGUOUS.contains(c))
                .collect::<Vec<char>>()
        })
        .filter(|pool| !pool.is_empty())
        .collect()
    }

    /// Draw one password containing at least one character from every enabled
    /// class. The mandatory characters are shuffled into random positions.
    ///
    /// # Errors
    ///
    /// [`GeneratorError::InvalidSettings`] when no class is enabled, the length
    /// is zero, or the length is smaller than the number of enabled classes;
    /// [`GeneratorError::RandomUnavailable`] if the OS source fails.
    pub fn generate(&self) -> Result<String, GeneratorError> {
        let pools = self.class_pools();
        if pools.is_empty() || self.length == 0 || self.length < pools.len() {
            return Err(GeneratorError::InvalidSettings);
        }
        let full: Vec<char> = pools.iter().flat_map(|pool| pool.iter().copied()).collect();
        let mut out: Vec<char> = Vec::with_capacity(self.length);
        for pool in &pools {
            out.push(pool[usize::from(draw_below(pool.len() as u16)?)]);
        }
        while out.len() < self.length {
            out.push(full[usize::from(draw_below(full.len() as u16)?)]);
        }
        for i in (1..out.len()).rev() {
            let j = usize::from(draw_below((i + 1) as u16)?);
            out.swap(i, j);
        }
        Ok(out.into_iter().collect())
    }
}

/// Passphrase generator settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseSettings {
    /// Number of words. Four is the default: the prefix-free list in
    /// [`crate::words::WORDS`] has more than 1024 entries, so a four-word
    /// passphrase is above the 40-bit `Weak` boundary.
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
#[path = "generator_tests.rs"]
mod tests;
