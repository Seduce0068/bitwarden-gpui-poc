//! Pure UI predicates that can be tested without a GPUI window.

/// Whether the lock screen has enough credential input to attempt a login.
///
/// The server URL and email may be pre-filled from settings, so they are not
/// considered here. An empty client id, secret or master password means the
/// demo vault is opened instead.
pub fn has_credentials(client_id: &str, client_secret: &str, master_password: &str) -> bool {
    !client_id.is_empty() || !client_secret.is_empty() || !master_password.is_empty()
}

/// Whether `selected` still points at a row in a view with `count` items.
pub fn selection_is_valid(selected: usize, count: usize) -> bool {
    count == 0 || selected < count
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn credentials_need_at_least_one_field() {
        assert!(!has_credentials("", "", ""));
        assert!(has_credentials("user.1234", "", ""));
        assert!(has_credentials("", "secret", ""));
        assert!(has_credentials("", "", "master"));
    }

    #[test]
    fn selection_validity_covers_empty_and_bounded_views() {
        assert!(selection_is_valid(0, 0), "empty view keeps the reset value");
        assert!(selection_is_valid(0, 1));
        assert!(selection_is_valid(4, 5));
        assert!(!selection_is_valid(5, 5));
        assert!(!selection_is_valid(6, 5));
    }
}
