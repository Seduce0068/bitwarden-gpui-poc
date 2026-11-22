//! Password and passphrase generation, plus the entropy estimate shown in the
//! generator panel.
//!
//! Randomness comes from the OS CSPRNG via [`getrandom`]; indices are drawn
//! with rejection sampling so every character is equally likely (a plain
//! modulo would bias the first `256 % n` characters).

use serde::{Deserialize, Serialize};

use crate::words::WORDS;

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
///
/// Alias of [`AppError`](crate::error::AppError); a failed OS random draw keeps
/// the `getrandom::Error` in `Error::source()`.
pub type GeneratorError = crate::error::AppError;

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
    /// Exclude characters that are easy to confuse (`l`, `I`, `1`, `O`, `0`, `o`).
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
        getrandom::fill(&mut buf).map_err(|error| {
            GeneratorError::RandomUnavailableCause(crate::error::BoxedCause::new(error))
        })?;
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

/// Entropy boundary between `Weak` and `Fair`, in bits.
///
/// Also used by the health audit's default [`crate::health::Thresholds`], so a
/// password the generator calls `Weak` cannot be scored as acceptable by the
/// audit (and vice versa).
pub const WEAK_BITS: u32 = 40;

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
        if bits < f64::from(WEAK_BITS) {
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
///
/// For a digits-only alphabet without the ambiguous-character filter this
/// mirrors the health audit's numeric-PIN model, which rounds the same
/// `entropy_bits(10, len)` value to whole bits
/// (`crate::health::estimate_entropy`). Without that mirror a 12-digit decimal
/// password is 39.86… bits here, so `Strength::from_bits` calls it `Weak`
/// while the UI prints "40 bit" and the audit's rounded 40 bits are no longer
/// below its weak threshold. Rounding only this category keeps all three
/// surfaces on the same side of the 40-bit boundary; mixed-class alphabets
/// keep the unrounded estimate used by the rest of the generator contract.
///
/// Known constraint (digits only + `avoid_ambiguous`): the estimate is still
/// computed from [`PasswordSettings::alphabet`]'s real size — 8 symbols after
/// `0` and `1` are filtered out — so a 12-character PIN scores `12 * log2(8)`
/// = 36 bits and is labelled `Weak`. The health audit always models an
/// all-digit password with the full 10-symbol pool and rounds to 40 bits for
/// the same length, so a generated PIN can be scored as acceptable by the
/// report while the meter says `Weak`. Widening this calculation to 10 would
/// overstate the entropy of the pool actually drawn, so the discrepancy is
/// recorded instead of hidden. Callers that need the two surfaces to agree
/// must leave `avoid_ambiguous` off for digit-only passwords.
pub fn password_entropy(settings: &PasswordSettings) -> f64 {
    let bits = entropy_bits(settings.alphabet().chars().count(), settings.length);
    if !settings.lowercase && !settings.uppercase && settings.digits && !settings.symbols {
        bits.round()
    } else {
        bits
    }
}

/// The entropy of a drawn passphrase.
///
/// The word choices dominate; capitalizing a word adds one free bit (upper or
/// lower first letter) and the optional trailing digit adds `log2(10)`. The
/// separator carries no entropy: the word list is prefix-free, so boundaries
/// are unambiguous even with an empty separator. The audit uses the same
/// model when it recognizes a generated passphrase (see
/// [`crate::health::estimate_entropy`]).
pub fn passphrase_entropy(settings: &PassphraseSettings) -> f64 {
    let mut bits = entropy_bits(WORDS.len(), settings.words);
    if settings.capitalize {
        bits += settings.words as f64;
    }
    if settings.include_number {
        bits += (10.0f64).log2();
    }
    bits
}

#[cfg(test)]
#[path = "generator_tests.rs"]
mod tests;

#[cfg(test)]
mod strength_alignment_tests {
    use super::*;

    #[test]
    fn twelve_decimal_digits_agree_between_meter_and_audit() {
        let digits = PasswordSettings {
            length: 12,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            ..PasswordSettings::default()
        };
        let bits = password_entropy(&digits);
        // 12 * log2(10) = 39.86… -> 40, the exact boundary that used to make
        // the UI show "40 bit / 弱い" while the audit treated it as acceptable.
        assert!(entropy_bits(10, 12) < f64::from(WEAK_BITS));
        assert_eq!(bits, 40.0);
        assert_eq!(Strength::from_bits(bits), Strength::Fair);
        assert_eq!(crate::health::estimate_entropy("123456789012"), 40);
    }

    #[test]
    fn mixed_alphabets_keep_the_unrounded_estimate() {
        // The existing `generator_tests.rs` contract for non-digit settings is
        // exact equality with `entropy_bits`; pin it here too so a future
        // broadening of the rounding cannot silently change those values.
        let settings = PasswordSettings {
            length: 16,
            ..PasswordSettings::default()
        };
        let expected = entropy_bits(
            LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len(),
            settings.length,
        );
        assert!((password_entropy(&settings) - expected).abs() < 1e-9);
        let avoid = PasswordSettings {
            avoid_ambiguous: true,
            ..settings
        };
        let expected = entropy_bits(avoid.alphabet().chars().count(), avoid.length);
        assert!((password_entropy(&avoid) - expected).abs() < 1e-9);
    }
}
