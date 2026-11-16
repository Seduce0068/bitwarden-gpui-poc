//! TOTP (RFC 6238) shown in the detail pane.
//!
//! The heavy lifting is [`openwarden::totp::generate`], which already accepts
//! Bitwarden's three `totp` field forms (`otpauth://` URI, `steam://`, and a
//! bare base32 secret). This module adds the presentation concerns the UI
//! needs: a redacted wrapper so an accidental `{:?}` or log line can't leak a
//! live code, a countdown, and the next-code preview.

use openwarden::{SecretString, TotpCode};

/// A generated code plus its validity window.
///
/// The code is held in a [`SecretString`] and this type never implements
/// `Display`, so a code only reaches the screen where the UI asks for it.
///
/// `PartialEq` compares only the validity window metadata, not the secret
/// code itself, so equality checks in tests do not require exposing the code.
pub struct Code {
    inner: TotpCode,
}

impl PartialEq for Code {
    fn eq(&self, other: &Self) -> bool {
        self.inner.period == other.inner.period && self.inner.remaining == other.inner.remaining
    }
}

impl Eq for Code {}

impl core::fmt::Debug for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Code")
            .field("code", &"[redacted]")
            .field("period", &self.inner.period)
            .field("remaining", &self.inner.remaining)
            .finish()
    }
}

impl Code {
    /// The code itself.
    pub fn code(&self) -> &str {
        use openwarden::ExposeSecret as _;
        self.inner.code.expose_secret()
    }

    /// The period, in seconds.
    pub const fn period(&self) -> u64 {
        self.inner.period
    }

    /// Seconds left in the current period.
    pub const fn remaining(&self) -> u64 {
        self.inner.remaining
    }

    /// How far through the period we are, 0.0..=1.0 (for the countdown bar).
    pub fn progress(&self) -> f32 {
        if self.inner.period == 0 {
            return 1.0;
        }
        let elapsed = self.inner.period.saturating_sub(self.inner.remaining);
        (elapsed as f32 / self.inner.period as f32).clamp(0.0, 1.0)
    }

    /// Whether the code expires within `seconds`.
    pub const fn expires_within(&self, seconds: u64) -> bool {
        self.inner.remaining <= seconds
    }

    /// The code split for display, e.g. `123 456` for six digits.
    pub fn grouped(&self) -> String {
        let code = self.code();
        if code.len() <= 3 || !code.chars().all(|c| c.is_ascii_digit()) {
            return code.to_string();
        }
        let chars: Vec<char> = code.chars().collect();
        let mid = chars.len() / 2;
        let head: String = chars[..mid].iter().collect();
        let tail: String = chars[mid..].iter().collect();
        format!("{head} {tail}")
    }
}

/// Why a code could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpError {
    /// The item has no `totp` field.
    Missing,
    /// The field is not a readable secret.
    Invalid,
}

impl TotpError {
    /// A message for the detail pane.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Missing => "この項目には TOTP が設定されていません",
            Self::Invalid => "TOTP シークレットを解釈できません",
        }
    }
}

/// Generate the code for a login's `totp` field at `unix_time`.
///
/// # Errors
///
/// [`TotpError::Missing`] when the field is empty; [`TotpError::Invalid`] when
/// `openwarden` cannot parse it.
pub fn code_at(secret: &str, unix_time: u64) -> Result<Code, TotpError> {
    if secret.trim().is_empty() {
        return Err(TotpError::Missing);
    }
    let secret = SecretString::from(secret.trim().to_string());
    openwarden::totp::generate(&secret, unix_time)
        .map(|inner| Code { inner })
        .map_err(|_| TotpError::Invalid)
}

/// Whether `secret` is a well-formed `totp` field, without exposing the code.
pub fn is_valid_secret(secret: &str) -> bool {
    code_at(secret, 0).is_ok()
}

/// A snapshot the UI keeps between ticks so a re-render doesn't re-do parsing.
#[derive(Debug)]
pub struct Tick {
    /// The code, when one could be produced.
    pub code: Option<Code>,
    /// The failure, when one could not.
    pub error: Option<TotpError>,
    /// The `unix_time` the snapshot was taken at.
    pub at: u64,
}

impl Tick {
    /// Take a snapshot for `secret` at `unix_time`.
    pub fn sample(secret: &str, unix_time: u64) -> Self {
        match code_at(secret, unix_time) {
            Ok(code) => Self {
                code: Some(code),
                error: None,
                at: unix_time,
            },
            Err(error) => Self {
                code: None,
                error: Some(error),
                at: unix_time,
            },
        }
    }

    /// Whether the snapshot is still valid at `unix_time` (same period).
    pub fn is_fresh(&self, unix_time: u64) -> bool {
        if unix_time < self.at {
            return false;
        }
        match &self.code {
            Some(code) => {
                code.period() != 0 && unix_time / code.period() == self.at / code.period()
            }
            // A failing secret doesn't change over time; re-parsing it every
            // tick would be pointless.
            None => true,
        }
    }

    /// The seconds left, if a code is present.
    pub fn remaining(&self) -> Option<u64> {
        self.code.as_ref().map(Code::remaining)
    }
}

/// The current time as Unix seconds.
///
/// Returns `0` if the clock is before the epoch, which keeps the UI from
/// panicking on a broken clock.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B test vector: the ASCII secret "12345678901234567890"
    /// base32-encoded, at T = 59s (SHA-1, 8 digits).
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vector_matches_for_eight_digits() {
        // The default is 6 digits, so the 8-digit vector is checked through
        // the otpauth URI form, which carries `digits`.
        let uri =
            format!("otpauth://totp/RFC?secret={RFC_SECRET}&digits=8&period=30&algorithm=SHA1");
        let code = code_at(&uri, 59).unwrap();
        assert_eq!(code.code(), "94287082");
        assert_eq!(code.period(), 30);
        assert_eq!(code.remaining(), 1);
    }

    #[test]
    fn rfc6238_vectors_across_the_time_range() {
        let uri =
            format!("otpauth://totp/RFC?secret={RFC_SECRET}&digits=8&period=30&algorithm=SHA1");
        for (time, expected) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(code_at(&uri, time).unwrap().code(), expected, "t={time}");
        }
    }

    #[test]
    fn bare_base32_secret_defaults_to_six_digits_sha1() {
        let code = code_at(RFC_SECRET, 59).unwrap();
        assert_eq!(code.code(), "287082");
        assert_eq!(code.period(), 30);
    }

    #[test]
    fn bare_secret_ignores_spaces_and_padding() {
        let spaced = "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ";
        let padded = format!("{RFC_SECRET}====");
        assert_eq!(code_at(spaced, 59).unwrap().code(), "287082");
        assert_eq!(code_at(&padded, 59).unwrap().code(), "287082");
        assert_eq!(
            code_at(&RFC_SECRET.to_lowercase(), 59).unwrap().code(),
            "287082"
        );
    }

    #[test]
    fn steam_secrets_produce_five_letter_codes() {
        let code = code_at("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(code.code().len(), 5);
        assert!(code
            .code()
            .chars()
            .all(|c| "23456789BCDFGHJKMNPQRTVWXY".contains(c)));
    }

    #[test]
    fn sha256_and_sha512_are_honoured() {
        let sha256 = format!("otpauth://totp/RFC?secret={RFC_SECRET}&algorithm=SHA256&digits=8");
        let sha512 = format!("otpauth://totp/RFC?secret={RFC_SECRET}&algorithm=SHA512&digits=8");
        let a = code_at(&sha256, 59).unwrap();
        let b = code_at(&sha512, 59).unwrap();
        assert_ne!(a.code(), b.code());
        assert_eq!(a.code().len(), 8);
    }

    #[test]
    fn a_custom_period_changes_the_window() {
        let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&period=60");
        let code = code_at(&uri, 59).unwrap();
        assert_eq!(code.period(), 60);
        assert_eq!(code.remaining(), 1);
        let code = code_at(&uri, 60).unwrap();
        assert_eq!(code.remaining(), 60);
    }

    #[test]
    fn missing_and_invalid_secrets_are_distinguished() {
        assert_eq!(code_at("", 0), Err(TotpError::Missing));
        assert_eq!(code_at("   ", 0), Err(TotpError::Missing));
        assert_eq!(code_at("not base32!", 0), Err(TotpError::Invalid));
        assert_eq!(code_at("otpauth://totp/x", 0), Err(TotpError::Invalid));
        assert!(!is_valid_secret("not base32!"));
        assert!(is_valid_secret(RFC_SECRET));
    }

    #[test]
    fn countdown_and_progress_track_the_period() {
        let code = code_at(RFC_SECRET, 0).unwrap();
        assert_eq!(code.remaining(), 30);
        assert_eq!(code.progress(), 0.0);
        let code = code_at(RFC_SECRET, 15).unwrap();
        assert_eq!(code.remaining(), 15);
        assert!((code.progress() - 0.5).abs() < 1e-6);
        let code = code_at(RFC_SECRET, 29).unwrap();
        assert!(code.expires_within(5));
        assert!(!code_at(RFC_SECRET, 0).unwrap().expires_within(5));
    }

    #[test]
    fn codes_change_at_the_period_boundary() {
        let before = code_at(RFC_SECRET, 29).unwrap().code().to_string();
        let after = code_at(RFC_SECRET, 30).unwrap().code().to_string();
        assert_ne!(before, after);
        let same = code_at(RFC_SECRET, 31).unwrap().code().to_string();
        assert_eq!(after, same);
        assert_eq!(code_at(RFC_SECRET, 30).unwrap().remaining(), 30);
    }

    #[test]
    fn grouping_splits_digits_and_leaves_steam_alone() {
        assert_eq!(code_at(RFC_SECRET, 59).unwrap().grouped(), "287 082");
        let steam = code_at("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(steam.grouped(), steam.code());
    }

    #[test]
    fn debug_never_reveals_the_code() {
        let code = code_at(RFC_SECRET, 59).unwrap();
        let rendered = format!("{code:?}");
        assert!(!rendered.contains("287082"), "{rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[::core::prelude::v1::test]
    fn code_equality_uses_only_the_validity_window() {
        let a = code_at(RFC_SECRET, 40).unwrap();
        let b = code_at(RFC_SECRET, 40).unwrap();
        let c = code_at(RFC_SECRET, 50).unwrap();
        // Equality uses only period + remaining, never the code value. Two
        // samples at the same instant are equal without exposing the code.
        assert_eq!(a, b);
        // A different remaining time is not equal.
        assert_ne!(a, c);
        // Equality never exposes the code value.
        let debug = format!("{a:?}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    #[test]
    fn tick_caches_within_a_period_and_refreshes_across_it() {
        let tick = Tick::sample(RFC_SECRET, 100);
        assert!(tick.code.is_some());
        assert!(tick.error.is_none());
        assert_eq!(tick.remaining(), Some(20));
        assert!(tick.is_fresh(105));
        assert!(tick.is_fresh(100));
        // 100 / 30 == 3, 119 / 30 == 3 (same period), 120 / 30 == 4.
        assert!(tick.is_fresh(119));
        assert!(!tick.is_fresh(120));
        assert!(!tick.is_fresh(99), "a backwards clock is never fresh");

        let failed = Tick::sample("not base32!", 100);
        assert!(failed.code.is_none());
        assert_eq!(failed.error, Some(TotpError::Invalid));
        assert_eq!(failed.remaining(), None);
        assert!(failed.is_fresh(100_000));
    }

    #[test]
    fn now_unix_is_plausible() {
        let now = now_unix();
        // 2020-01-01 .. 2100-01-01
        assert!(now > 1_577_836_800, "{now}");
        assert!(now < 4_102_444_800, "{now}");
    }

    #[test]
    fn error_messages_are_present() {
        assert!(!TotpError::Missing.message().is_empty());
        assert!(!TotpError::Invalid.message().is_empty());
    }
}
