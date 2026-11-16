//! Shared view state types.

use crate::generator::{PassphraseSettings, PasswordSettings};
use crate::settings::Settings;

/// Which top-level screen is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Credentials are entered here.
    Locked,
    /// The vault is available.
    Unlocked,
}

/// Which panel occupies the main area while unlocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    /// Vault item list.
    Vault,
    /// Health audit report.
    Audit,
    /// Password and passphrase generator.
    Generator,
    /// Persistent settings.
    Settings,
}

/// A text field being edited in the settings panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsField {
    /// Server URL.
    ServerUrl,
    /// Account email.
    Email,
}

/// A credential field being edited on the lock screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthField {
    /// Server URL.
    ServerUrl,
    /// Account email.
    Email,
    /// Personal API key client id.
    ClientId,
    /// Personal API key client secret.
    ClientSecret,
    /// Master password.
    MasterPassword,
}

/// Editable generator settings and the last values drawn from them.
///
/// `Debug` masks the last generated values so secrets are not printed.
#[derive(Clone, Default)]
pub struct GeneratorState {
    /// Password generator settings.
    pub password: PasswordSettings,
    /// Passphrase generator settings.
    pub passphrase: PassphraseSettings,
    /// Last generated password.
    pub last_password: Option<String>,
    /// Last generated passphrase.
    pub last_passphrase: Option<String>,
}

impl core::fmt::Debug for GeneratorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratorState")
            .field("password", &self.password)
            .field("passphrase", &self.passphrase)
            .field(
                "last_password",
                &self.last_password.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "last_passphrase",
                &self.last_passphrase.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl GeneratorState {
    /// Build generator state from persisted settings.
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            password: settings.password_generator.clone(),
            passphrase: settings.passphrase_generator.clone(),
            last_password: None,
            last_passphrase: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn debug_masks_generated_secrets() {
        let state = GeneratorState {
            last_password: Some("generated-password".into()),
            last_passphrase: Some("correct-horse-battery".into()),
            ..Default::default()
        };
        let debug = format!("{state:?}");
        assert!(!debug.contains("generated-password"), "{debug}");
        assert!(!debug.contains("correct-horse-battery"), "{debug}");
        assert_eq!(debug.matches("[redacted]").count(), 2, "{debug}");

        let empty = GeneratorState::default();
        let debug = format!("{empty:?}");
        assert!(!debug.contains("[redacted]"), "{debug}");
        assert!(debug.contains("None"), "{debug}");
    }
}
