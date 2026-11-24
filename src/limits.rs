//! Neutral input limits shared by the auth and settings layers.
//!
//! Keeping these here prevents the pure settings module from depending on the
//! network-oriented auth module just to validate two text fields.

/// Maximum length of an email address, in Unicode characters (not octets).
///
/// The *number* comes from RFC 5321's octet limits: §4.5.3.1.1 caps the local
/// part at 64 octets, §4.5.3.1.2 caps the domain at 255 octets, and
/// §4.5.3.1.3 caps the whole forward/reverse path at 256 octets including
/// punctuation; removing the angle brackets leaves the familiar 254-octet
/// practical ceiling. See <https://www.rfc-editor.org/rfc/rfc5321#section-4.5.3.1>.
///
/// The *unit* deliberately does not match that basis. [`truncate_to_limit`]
/// counts `str::chars()`, and the login field check in `crate::auth` does the
/// same, so 254 multi-byte characters (762 UTF-8 bytes for a run of `あ`)
/// pass here even though they exceed every octet budget above. No separate
/// local-part/domain split is enforced either. This cap is a UI/storage bound
/// against unbounded input and its allocations, not a promise of SMTP
/// deliverability: a server may reject an address that fits in 254 characters
/// when its local part or its UTF-8 encoding exceeds the wire limits.
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
/// Maximum raw `/api/sync` body accepted on the live path and from the offline cache.
///
/// Single source of truth for `crate::vault_sync::MAX_SYNC_BODY_BYTES` and
/// `crate::cache::MAX_CACHE_BODY_BYTES`. Keeping the cap in this neutral module
/// removes the constant-level `cache` <-> `vault_sync` cycle: neither consumer
/// has to look into the other for the same number, and the cache's remaining
/// dependency on `vault_sync::parse_sync` is one-way.
pub const MAX_SYNC_BODY_BYTES: usize = 8 * 1024 * 1024;
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
/// Minimum idle-lock bound expressed in the UI's minute step.
///
/// This is a derived convenience value for tests and diagnostics, not the
/// constant the production UI clamps against. The adjuster in
/// `crate::ui::logic::adjust_idle_lock` reads `MIN_IDLE_LOCK_SECONDS` and
/// `MAX_IDLE_LOCK_SECONDS` directly and multiplies the one-minute step by 60,
/// so changing this value alone does not move the UI range. The derivation
/// only pins the unit relationship between the two spellings.
#[allow(dead_code)]
pub const MIN_IDLE_LOCK_MINUTES: u64 = MIN_IDLE_LOCK_SECONDS / 60;
/// Maximum idle-lock bound expressed in the UI's minute step.
///
/// Derived from `MAX_IDLE_LOCK_SECONDS` for the same reason as the minimum:
/// the production UI clamp reads the seconds constant directly.
#[allow(dead_code)]
pub const MAX_IDLE_LOCK_MINUTES: u64 = MAX_IDLE_LOCK_SECONDS / 60;
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

/// Whether `ch` is a Unicode `Cf` (format) character.
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
    fn email_cap_counts_characters_not_rfc_octets() {
        // Pin the documented mismatch: the 254 is an RFC 5321 octet ceiling,
        // but the implementation counts Unicode scalar values. A multi-byte
        // address can therefore fill the cap and still be far over the wire
        // budget; switching to byte counting is an explicit, reviewed change.
        let multibyte = "あ".repeat(MAX_EMAIL_LEN);
        assert_eq!(multibyte.chars().count(), MAX_EMAIL_LEN);
        assert_eq!(multibyte.len(), MAX_EMAIL_LEN * 'あ'.len_utf8());
        assert!(multibyte.len() > MAX_EMAIL_LEN);

        let mut at_cap = multibyte.clone();
        truncate_to_limit(&mut at_cap, MAX_EMAIL_LEN);
        assert_eq!(at_cap, multibyte);
        let mut over_cap = format!("{multibyte}あ");
        truncate_to_limit(&mut over_cap, MAX_EMAIL_LEN);
        assert_eq!(over_cap, multibyte);
    }

    #[test]
    fn sync_body_cap_is_the_single_source_of_truth() {
        // Both the live parser and the offline cache alias this value; pin the
        // value and the two aliases so a drift is an explicit, reviewed edit.
        assert_eq!(MAX_SYNC_BODY_BYTES, 8 * 1024 * 1024);
        assert_eq!(crate::vault_sync::MAX_SYNC_BODY_BYTES, MAX_SYNC_BODY_BYTES);
        assert_eq!(crate::cache::MAX_CACHE_BODY_BYTES, MAX_SYNC_BODY_BYTES);
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

    #[test]
    fn idle_lock_minutes_are_derived_from_the_seconds_bounds() {
        // The UI's minute bounds are not independent magic numbers: they are
        // the seconds bounds converted to whole minutes. A change to the
        // seconds clamp must move the adjuster with it, and the conversion
        // must stay exact so no configured value is silently truncated.
        const { assert!(MIN_IDLE_LOCK_SECONDS.is_multiple_of(60)) };
        const { assert!(MAX_IDLE_LOCK_SECONDS.is_multiple_of(60)) };
        assert_eq!(MIN_IDLE_LOCK_MINUTES, MIN_IDLE_LOCK_SECONDS / 60);
        assert_eq!(MAX_IDLE_LOCK_MINUTES, MAX_IDLE_LOCK_SECONDS / 60);
        assert_eq!(MIN_IDLE_LOCK_MINUTES * 60, MIN_IDLE_LOCK_SECONDS);
        assert_eq!(MAX_IDLE_LOCK_MINUTES * 60, MAX_IDLE_LOCK_SECONDS);
        // Pin the current values too: a deliberate change to either seconds
        // bound then has to be acknowledged here as an explicit edit.
        assert_eq!(MIN_IDLE_LOCK_MINUTES, 1);
        assert_eq!(MAX_IDLE_LOCK_MINUTES, 60);
        const { assert!(MIN_IDLE_LOCK_MINUTES < MAX_IDLE_LOCK_MINUTES) };
    }
}
