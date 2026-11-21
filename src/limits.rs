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

/// Whether `value` contains a Unicode `Cf` (format) character.
///
/// Zero-width spaces, bidi overrides and similar invisible controls can hide
/// lookalike addresses or change how an address is rendered, so they are
/// rejected explicitly instead of being silently tolerated by the structural
/// check below. The list is the `Cf` category of Unicode 16.0.
pub(crate) fn has_format_character(value: &str) -> bool {
    value.chars().any(|ch| {
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
    })
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
}
