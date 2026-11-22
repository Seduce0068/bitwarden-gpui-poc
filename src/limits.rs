//! Neutral input limits shared by the auth and settings layers.
//!
//! Keeping these here prevents the pure settings module from depending on the
//! network-oriented auth module just to validate two text fields.

/// Maximum length of an email address, in characters. RFC 5321 caps the local
/// part at 64 octets and the domain at 255; 254 is the practical ceiling mail
/// servers enforce, so longer addresses cannot be real deliverable addresses.
pub const MAX_EMAIL_LEN: usize = 254;
/// Maximum length of a server URL, in characters. Well above a normal
/// self-hosted URL, but below the ~2 KiB limit many HTTP stacks apply.
pub const MAX_SERVER_URL_LEN: usize = 2048;
/// Maximum length of a Client ID, in characters. Bitwarden personal keys are
/// short (`user.<uuid>`); this leaves room for custom installations.
pub const MAX_CLIENT_ID_LEN: usize = 256;
/// Maximum length of a Client Secret, in characters.
pub const MAX_CLIENT_SECRET_LEN: usize = 1024;
/// Maximum length of a master password, in characters. Long passphrases are
/// legitimate, but the in-memory buffer still needs a finite bound.
pub const MAX_MASTER_PASSWORD_LEN: usize = 1024;
/// Default time budget for the whole login sequence.
pub const DEFAULT_LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Default inactivity before auto-lock, in seconds.
pub const DEFAULT_IDLE_LOCK_SECONDS: u64 = 300;
/// Default clipboard restore delay, in seconds.
pub const DEFAULT_CLIPBOARD_RESTORE_SECONDS: u64 = 30;

// Bounds applied by `Settings::sanitized` before a settings value is persisted
// or used. They live here, next to the text caps, so the stored value and the
// effective runtime value cannot drift apart between modules. Types follow the
// fields they clamp (seconds/generator lengths/thresholds respectively).
/// Minimum inactivity before auto-lock, in seconds.
pub const MIN_IDLE_LOCK_SECONDS: u64 = 60;
/// Maximum inactivity before auto-lock, in seconds.
pub const MAX_IDLE_LOCK_SECONDS: u64 = 3600;
/// Minimum idle-lock value expressed in the UI's minute step.
///
/// The UI adjuster works in whole minutes; these two constants and their
/// seconds counterparts above are the single source of truth so the stored
/// value, the clamp and the displayed range cannot drift apart.
pub const MIN_IDLE_LOCK_MINUTES: u64 = 1;
/// Maximum idle-lock value expressed in the UI's minute step.
pub const MAX_IDLE_LOCK_MINUTES: u64 = 60;
/// Minimum login time budget, in seconds.
pub const MIN_LOGIN_TIMEOUT_SECONDS: u64 = 1;
/// Maximum login time budget, in seconds.
pub const MAX_LOGIN_TIMEOUT_SECONDS: u64 = 3600;
/// Minimum clipboard restore delay, in seconds.
pub const MIN_CLIPBOARD_RESTORE_SECONDS: u64 = 1;
/// Maximum clipboard restore delay, in seconds.
pub const MAX_CLIPBOARD_RESTORE_SECONDS: u64 = 3600;
/// Minimum generated password length, in characters.
pub const MIN_PASSWORD_LENGTH: usize = 4;
/// Maximum generated password length, in characters.
pub const MAX_PASSWORD_LENGTH: usize = 128;
/// Minimum passphrase word count.
pub const MIN_PASSPHRASE_WORDS: usize = 2;
/// Maximum passphrase word count.
pub const MAX_PASSPHRASE_WORDS: usize = 20;
/// Minimum weak-password entropy threshold, in bits.
pub const MIN_WEAK_BITS: u32 = 1;
/// Maximum weak-password entropy threshold, in bits.
pub const MAX_WEAK_BITS: u32 = 200;
/// Minimum stale-item threshold, in days.
pub const MIN_STALE_DAYS: i64 = 1;
/// Maximum stale-item threshold, in days.
pub const MAX_STALE_DAYS: i64 = 3650;

/// Whether `value` contains a Unicode `Cf` (format) character.
///
/// Zero-width spaces, bidi overrides and similar invisible controls can hide
/// lookalike addresses or change how an address is rendered, so they are
/// rejected explicitly instead of being silently tolerated by the structural
/// check below. The list is the `Cf` category of Unicode 16.0.
pub(crate) fn is_format_character(ch: char) -> bool {
    matches!(
        ch,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
    )
}

/// Whether `value` contains a Unicode `Cf` (format) character.
pub(crate) fn has_format_character(value: &str) -> bool {
    value.chars().any(is_format_character)
}

/// Byte offset just past `limit` characters, or `None` when `value` fits.
pub(crate) fn char_boundary_at(value: &str, limit: usize) -> Option<usize> {
    value.char_indices().nth(limit).map(|(index, _)| index)
}

/// Shorten `value` to at most `limit` characters without splitting a UTF-8
/// code point. Following the policy above, this can never fail.
pub fn truncate_to_limit(value: &mut String, limit: usize) {
    if let Some(index) = char_boundary_at(value, limit) {
        value.truncate(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_utf8_boundaries() {
        let mut value = "あいうえお".to_string();
        truncate_to_limit(&mut value, 3);
        assert_eq!(value, "あいう");
        let mut ascii = "abcdef".to_string();
        truncate_to_limit(&mut ascii, 2);
        assert_eq!(ascii, "ab");
    }

    #[test]
    fn auth_field_caps_have_one_source_of_truth() {
        // Auth re-exports these from here so the lock-screen input state, the
        // clamp on the login path and the settings layer share the same caps.
        assert_eq!(MAX_EMAIL_LEN, 254);
        assert_eq!(MAX_SERVER_URL_LEN, 2048);
        assert_eq!(MAX_CLIENT_ID_LEN, 256);
        assert_eq!(MAX_CLIENT_SECRET_LEN, 1024);
        assert_eq!(MAX_MASTER_PASSWORD_LEN, 1024);
        assert_eq!(DEFAULT_LOGIN_TIMEOUT, std::time::Duration::from_secs(30));
        const { assert!(MAX_CLIENT_ID_LEN < MAX_SERVER_URL_LEN) };
        const { assert!(MAX_EMAIL_LEN < MAX_SERVER_URL_LEN) };
    }
}
