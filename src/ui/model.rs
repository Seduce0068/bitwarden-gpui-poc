//! Shared view state types.

use crate::generator::{PassphraseSettings, PasswordSettings};
use crate::settings::Settings;

/// Which top-level screen is visible.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Credentials are entered here.
    Locked,
    /// The vault is available.
    Unlocked,
}

/// Which panel occupies the main area while unlocked.
#[derive(Clone, Copy, PartialEq, Eq)]
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    /// Server URL.
    ServerUrl,
    /// Account email.
    Email,
}

/// A credential field being edited on the lock screen.
#[derive(Clone, Copy, PartialEq, Eq)]
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
#[derive(Clone, Debug, Default)]
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
