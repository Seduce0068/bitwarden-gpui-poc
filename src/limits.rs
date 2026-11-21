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
/// Default time budget for the whole login sequence.
pub const DEFAULT_LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Byte offset just past `limit` characters, or `None` when `value` fits.
fn char_boundary_at(value: &str, limit: usize) -> Option<usize> {
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
}
