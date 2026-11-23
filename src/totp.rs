//! TOTP (RFC 6238) shown in the detail pane.
//!
//! The heavy lifting is [`openwarden::totp::generate`], which already accepts
//! Bitwarden's three `totp` field forms (`otpauth://` URI, `steam://`, and a
//! bare base32 secret). This module adds the presentation concerns the UI
//! needs: a redacted wrapper so an accidental `{:?}` or log line can't leak a
//! live code and a countdown. The next-code preview was not implemented.

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
///
/// Alias of [`AppError`](crate::error::AppError); for a secret that `openwarden`
/// rejects, [`code_at`] stores only the failure's rendered text through
/// [`BoxedCause::text`](crate::error::BoxedCause::text), so `Error::source()`
/// exposes that text — the typed original error itself is not kept.
pub type TotpError = crate::error::AppError;

/// Generate the code for a login's `totp` field at `unix_time`.
///
/// # Errors
///
/// [`TotpError::Missing`] when the field is empty; [`TotpError::Invalid`] when
/// `openwarden` cannot parse it.
pub fn code_at(secret: &str, unix_time: u64) -> Result<Code, TotpError> {
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(TotpError::Missing);
    }
    // openwarden 0.1.1 detects the `otpauth://` form with the byte slice
    // `secret[..10]` (compared case-insensitively). A field whose first bytes
    // are multi-byte can put byte 10 inside a UTF-8 code point and panic before
    // any error is returned. When the first ten bytes are exactly the ASCII
    // `otpauth://` prefix the slice is on a char boundary, and openwarden parses
    // the remainder as a URI whose label/issuer may legitimately be non-ASCII.
    // Only the other forms (bare base32 / steam secrets) are rejected here: the
    // health audit calls this on untrusted vault data and must never crash.
    let has_otpauth_prefix = secret
        .get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"));
    if !has_otpauth_prefix && !secret.is_ascii() {
        return Err(TotpError::Invalid);
    }
    let secret = SecretString::from(secret.to_string());
    openwarden::totp::generate(&secret, unix_time)
        .map(|inner| Code { inner })
        .map_err(|error| TotpError::InvalidCause(crate::error::BoxedCause::text(error.to_string())))
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
#[path = "totp_tests.rs"]
mod tests;
