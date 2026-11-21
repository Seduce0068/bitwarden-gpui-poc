//! Lock-screen credential state, independent of GPUI types.

use zeroize::Zeroizing;

use crate::auth::{
    truncate_to_limit, MAX_CLIENT_ID_LEN, MAX_CLIENT_SECRET_LEN, MAX_MASTER_PASSWORD_LEN,
};
#[cfg(test)]
use crate::ui::logic::has_credentials;
use crate::ui::state::AuthField;

/// Append `text` while keeping `target` within `limit` characters.
///
/// Only the part that fits is appended, cutting on a UTF-8 character boundary,
/// so even a large paste cannot grow the buffer past the cap. Excess input is
/// dropped rather than reported as an error (see the input-length policy in
/// `crate::auth`). The final `truncate_to_limit` also guards against a field
/// that was pre-filled beyond its cap by a caller.
fn push_capped(target: &mut String, text: &str, limit: usize) {
    let room = limit.saturating_sub(target.chars().count());
    let fitting = crate::limits::char_boundary_at(text, room).map_or(text, |index| &text[..index]);
    target.push_str(fitting);
    truncate_to_limit(target, limit);
}

/// Credentials entered on the lock screen and the active edit field.
///
/// Secret inputs are held in [`Zeroizing<String>`] so the final buffer is
/// wiped when the state is dropped or a field is replaced (as on lock).
///
/// Like all `Vec`/`String`-based zeroization, this cannot wipe copies left
/// behind by earlier reallocations while characters were appended one by one.
#[derive(Default)]
pub(super) struct AuthState {
    field: Option<AuthField>,
    client_id: String,
    client_secret: Zeroizing<String>,
    master_password: Zeroizing<String>,
    login_failed: bool,
}

impl AuthState {
    /// Create empty state.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// The field currently being edited, if any.
    pub(super) fn field(&self) -> Option<AuthField> {
        self.field
    }

    /// Start or stop editing a field.
    pub(super) fn set_field(&mut self, field: Option<AuthField>) {
        self.field = field;
    }

    /// Stop editing and return the previous field.
    pub(super) fn take_field(&mut self) -> Option<AuthField> {
        self.field.take()
    }

    /// Whether any credential field has input.
    #[cfg(test)]
    pub(super) fn has_credentials(&self) -> bool {
        has_credentials(&self.client_id, &self.client_secret, &self.master_password)
    }

    /// The API key client id.
    pub(super) fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The API key client secret.
    pub(super) fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// The master password.
    pub(super) fn master_password(&self) -> &str {
        &self.master_password
    }

    /// Whether the last login attempt failed.
    pub(super) fn login_failed(&self) -> bool {
        self.login_failed
    }

    /// Set the login-failure flag.
    pub(super) fn set_login_failed(&mut self, value: bool) {
        self.login_failed = value;
    }

    /// Append a character to the active credential field, capped at the
    /// field's input limit.
    ///
    /// Over-long input is truncated on a UTF-8 boundary, never rejected with
    /// an error; the policy and the caps live in `crate::auth`.
    /// `ServerUrl` and `Email` are shared with settings and handled by the
    /// caller, so they are ignored here. Their caps are applied by
    /// `crate::auth::clamp_auth_config` when the `AuthConfig` is built.
    pub(super) fn push_text(&mut self, text: &str) {
        match self.field {
            Some(AuthField::ClientId) => push_capped(&mut self.client_id, text, MAX_CLIENT_ID_LEN),
            Some(AuthField::ClientSecret) => {
                push_capped(&mut self.client_secret, text, MAX_CLIENT_SECRET_LEN);
            }
            Some(AuthField::MasterPassword) => {
                push_capped(&mut self.master_password, text, MAX_MASTER_PASSWORD_LEN);
            }
            _ => {}
        }
    }

    /// Remove the last character from the active credential field.
    pub(super) fn pop_char(&mut self) {
        match self.field {
            Some(AuthField::ClientId) => {
                self.client_id.pop();
            }
            Some(AuthField::ClientSecret) => {
                self.client_secret.pop();
            }
            Some(AuthField::MasterPassword) => {
                self.master_password.pop();
            }
            _ => {}
        }
    }

    /// Clear secrets and the failure flag on lock, keeping the client id as a
    /// convenience for the next unlock attempt.
    pub(super) fn clear_secrets(&mut self) {
        // Replacing the value drops the old Zeroizing buffer, which wipes it.
        self.client_secret = Zeroizing::new(String::new());
        self.master_password = Zeroizing::new(String::new());
        self.login_failed = false;
        self.field = None;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_has_no_credentials() {
        let state = AuthState::new();
        assert!(!state.has_credentials());
        assert!(!state.login_failed());
    }

    #[test]
    fn edits_target_the_active_field() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientId));
        state.push_text("u");
        state.push_text("s");
        assert_eq!(state.client_id(), "us");

        state.set_field(Some(AuthField::ClientSecret));
        state.push_text("s");
        assert_eq!(state.client_secret(), "s");
        assert!(state.has_credentials());

        state.pop_char();
        assert!(state.client_secret().is_empty());
    }

    #[test]
    fn push_text_appends_a_whole_ime_string() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientSecret));
        state.push_text("日本語");
        state.push_text("abc");
        assert_eq!(state.client_secret(), "日本語abc");
    }

    #[test]
    fn take_field_returns_and_clears_the_active_field() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::MasterPassword));
        assert_eq!(state.take_field(), Some(AuthField::MasterPassword));
        assert_eq!(state.field(), None);
        assert_eq!(state.take_field(), None);
    }

    #[test]
    fn backspace_on_empty_fields_is_a_no_op() {
        let mut state = AuthState::new();
        for field in [
            AuthField::ClientId,
            AuthField::ClientSecret,
            AuthField::MasterPassword,
        ] {
            state.set_field(Some(field));
            state.pop_char();
            assert!(state.client_id().is_empty());
            assert!(state.client_secret().is_empty());
            assert!(state.master_password().is_empty());
        }
        assert!(!state.has_credentials());
    }

    #[test]
    fn clear_secrets_replaces_secret_buffers() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientSecret));
        state.push_text("s");
        state.set_field(Some(AuthField::MasterPassword));
        state.push_text("p");
        assert_eq!(state.client_secret(), "s");
        assert_eq!(state.master_password(), "p");

        state.clear_secrets();
        assert!(state.client_secret().is_empty());
        assert!(state.master_password().is_empty());

        // This verifies replacement, not the memory wipe itself: the old
        // buffer is dropped (and zeroized) by the assignment above. Observing
        // the bytes would require unsafe, which this crate forbids.
        state.set_field(Some(AuthField::ClientSecret));
        state.push_text("n");
        assert_eq!(state.client_secret(), "n");
    }

    #[test]
    fn clear_secrets_keeps_client_id() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientId));
        state.push_text("i");
        state.set_field(Some(AuthField::MasterPassword));
        state.push_text("p");
        state.set_login_failed(true);

        state.clear_secrets();
        assert_eq!(state.client_id(), "i");
        assert!(state.master_password().is_empty());
        assert!(!state.login_failed());
        assert_eq!(state.field(), None);
    }

    #[test]
    fn server_url_and_email_fields_ignore_all_edits() {
        let mut state = AuthState::new();
        for field in [AuthField::ServerUrl, AuthField::Email] {
            state.set_field(Some(field));
            state.push_text("https://vault.example.com");
            state.push_text("user@example.com");
            state.pop_char();

            assert_eq!(state.field(), Some(field));
            assert!(state.client_id().is_empty());
            assert!(state.client_secret().is_empty());
            assert!(state.master_password().is_empty());
            assert!(!state.has_credentials());
        }
    }

    #[test]
    fn shared_fields_leave_existing_credentials_untouched() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientId));
        state.push_text("client");
        state.set_field(Some(AuthField::ClientSecret));
        state.push_text("secret");

        for field in [AuthField::ServerUrl, AuthField::Email] {
            state.set_field(Some(field));
            state.push_text("ignored");
            state.pop_char();

            assert_eq!(state.client_id(), "client");
            assert_eq!(state.client_secret(), "secret");
            assert!(state.master_password().is_empty());
        }
    }

    #[test]
    fn push_text_caps_each_owned_field_on_a_character_boundary() {
        for (field, limit) in [
            (AuthField::ClientId, MAX_CLIENT_ID_LEN),
            (AuthField::ClientSecret, MAX_CLIENT_SECRET_LEN),
            (AuthField::MasterPassword, MAX_MASTER_PASSWORD_LEN),
        ] {
            let mut state = AuthState::new();
            state.set_field(Some(field));
            // A multibyte paste whose cap lands mid-code-point must be cut on
            // a UTF-8 boundary, never in the middle of a character.
            state.push_text(&"あ".repeat(limit + 1));

            let current = match field {
                AuthField::ClientId => state.client_id(),
                AuthField::ClientSecret => state.client_secret(),
                AuthField::MasterPassword => state.master_password(),
                _ => unreachable!("only the three owned fields are tested"),
            };
            assert_eq!(current.chars().count(), limit, "{field:?}");
            assert_eq!(current, "あ".repeat(limit), "{field:?}");
        }
    }

    #[test]
    fn push_text_ignores_input_once_a_field_is_full() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientId));
        state.push_text(&"i".repeat(MAX_CLIENT_ID_LEN));
        state.push_text("EXTRA");

        assert_eq!(state.client_id().chars().count(), MAX_CLIENT_ID_LEN);
        assert!(!state.client_id().contains("EXTRA"));
    }

    #[test]
    fn a_zeroizing_snapshot_outlives_clearing_the_source_state() {
        // The spawned login task keeps its own credential snapshot. Wrapping
        // that copy in `Zeroizing` bounds its lifetime explicitly, while
        // clearing the lock-screen state does not disturb the in-flight task.
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientSecret));
        state.push_text("secret");
        state.set_field(Some(AuthField::MasterPassword));
        state.push_text("password");

        let snapshot = Zeroizing::new(state.client_secret().to_string());
        assert_eq!(snapshot.as_str(), "secret");

        state.clear_secrets();
        assert!(state.client_secret().is_empty());
        assert!(state.master_password().is_empty());
        // The task's copy is independent and is wiped when it is dropped.
        assert_eq!(snapshot.as_str(), "secret");
        drop(snapshot);
    }

    #[test]
    fn shared_fields_still_ignore_pushes_beyond_any_cap() {
        // ServerUrl/Email are owned by Settings; their input caps are applied
        // by clamp_auth_config when the AuthConfig is assembled, not here.
        let mut state = AuthState::new();
        for field in [AuthField::ServerUrl, AuthField::Email] {
            state.set_field(Some(field));
            state.push_text(&"x".repeat(crate::auth::MAX_SERVER_URL_LEN + 10));
            state.push_text(&"y".repeat(crate::auth::MAX_EMAIL_LEN + 10));
            assert!(state.client_id().is_empty());
            assert!(state.client_secret().is_empty());
            assert!(state.master_password().is_empty());
        }
    }
}
