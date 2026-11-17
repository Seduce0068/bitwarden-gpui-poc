//! Lock-screen credential state, independent of GPUI types.

use zeroize::Zeroizing;

use crate::ui::logic::has_credentials;
use crate::ui::state::AuthField;

/// Credentials entered on the lock screen and the active edit field.
///
/// Secret inputs are held in [`Zeroizing<String>`] so the final buffer is
/// wiped when the state is dropped or a field is replaced (as on lock).
///
/// Like all `Vec`/`String`-based zeroization, this cannot wipe copies left
/// behind by earlier reallocations while characters were appended one by one.
#[derive(Default)]
pub struct AuthState {
    field: Option<AuthField>,
    client_id: String,
    client_secret: Zeroizing<String>,
    master_password: Zeroizing<String>,
    login_failed: bool,
}

impl AuthState {
    /// Create empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// The field currently being edited, if any.
    pub fn field(&self) -> Option<AuthField> {
        self.field
    }

    /// Start or stop editing a field.
    pub fn set_field(&mut self, field: Option<AuthField>) {
        self.field = field;
    }

    /// Stop editing and return the previous field.
    pub fn take_field(&mut self) -> Option<AuthField> {
        self.field.take()
    }

    /// Whether any credential field has input.
    pub fn has_credentials(&self) -> bool {
        has_credentials(&self.client_id, &self.client_secret, &self.master_password)
    }

    /// The API key client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The API key client secret.
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// The master password.
    pub fn master_password(&self) -> &str {
        &self.master_password
    }

    /// Whether the last login attempt failed.
    pub fn login_failed(&self) -> bool {
        self.login_failed
    }

    /// Set the login-failure flag.
    pub fn set_login_failed(&mut self, value: bool) {
        self.login_failed = value;
    }

    /// Append a character to the active credential field.
    ///
    /// `ServerUrl` and `Email` are shared with settings and handled by the
    /// caller, so they are ignored here.
    pub fn push_char(&mut self, character: char) {
        match self.field {
            Some(AuthField::ClientId) => self.client_id.push(character),
            Some(AuthField::ClientSecret) => self.client_secret.push(character),
            Some(AuthField::MasterPassword) => self.master_password.push(character),
            _ => {}
        }
    }

    /// Remove the last character from the active credential field.
    pub fn pop_char(&mut self) {
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
    pub fn clear_secrets(&mut self) {
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

    #[::core::prelude::v1::test]
    fn empty_state_has_no_credentials() {
        let state = AuthState::new();
        assert!(!state.has_credentials());
        assert!(!state.login_failed());
    }

    #[::core::prelude::v1::test]
    fn edits_target_the_active_field() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientId));
        state.push_char('u');
        state.push_char('s');
        assert_eq!(state.client_id(), "us");

        state.set_field(Some(AuthField::ClientSecret));
        state.push_char('s');
        assert_eq!(state.client_secret(), "s");
        assert!(state.has_credentials());

        state.pop_char();
        assert!(state.client_secret().is_empty());
    }

    #[::core::prelude::v1::test]
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

    #[::core::prelude::v1::test]
    fn clear_secrets_replaces_secret_buffers() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientSecret));
        state.push_char('s');
        state.set_field(Some(AuthField::MasterPassword));
        state.push_char('p');
        assert_eq!(state.client_secret(), "s");
        assert_eq!(state.master_password(), "p");

        state.clear_secrets();
        assert!(state.client_secret().is_empty());
        assert!(state.master_password().is_empty());

        // This verifies replacement, not the memory wipe itself: the old
        // buffer is dropped (and zeroized) by the assignment above. Observing
        // the bytes would require unsafe, which this crate forbids.
        state.set_field(Some(AuthField::ClientSecret));
        state.push_char('n');
        assert_eq!(state.client_secret(), "n");
    }

    #[::core::prelude::v1::test]
    fn clear_secrets_keeps_client_id() {
        let mut state = AuthState::new();
        state.set_field(Some(AuthField::ClientId));
        state.push_char('i');
        state.set_field(Some(AuthField::MasterPassword));
        state.push_char('p');
        state.set_login_failed(true);

        state.clear_secrets();
        assert_eq!(state.client_id(), "i");
        assert!(state.master_password().is_empty());
        assert!(!state.login_failed());
        assert_eq!(state.field(), None);
    }
}
