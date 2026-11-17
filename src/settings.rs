//! Persistent settings: server URL, email, generator defaults, thresholds.
//!
//! The PoC stores settings in JSON under the user's config directory. No
//! secrets are persisted here: master passwords and keys live only in memory.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::generator::{PassphraseSettings, PasswordSettings};
use crate::health::Thresholds;

/// Top-level settings object.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Server URL (Bitwarden or Vaultwarden).
    pub server_url: String,
    /// Last-used email address.
    pub email: String,
    /// Default password generator settings.
    pub password_generator: PasswordSettings,
    /// Default passphrase generator settings.
    pub passphrase_generator: PassphraseSettings,
    /// Vault-health thresholds.
    pub thresholds: Thresholds,
    /// Seconds of inactivity before the vault auto-locks.
    pub idle_lock_seconds: u64,
    /// Time budget for a real login attempt.
    pub login_timeout_seconds: u64,
    /// Seconds before a copied secret is restored to the clipboard.
    pub clipboard_restore_seconds: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server_url: "https://vault.bitwarden.com".to_string(),
            email: String::new(),
            password_generator: PasswordSettings::default(),
            passphrase_generator: PassphraseSettings::default(),
            thresholds: Thresholds::default(),
            idle_lock_seconds: 300,
            login_timeout_seconds: 30,
            clipboard_restore_seconds: 30,
        }
    }
}

/// Why settings could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsLoadError {
    /// The file does not exist yet; defaults are expected on first launch.
    NotFound,
    /// The file exists but could not be read.
    ReadFailed,
    /// The file exists but is not valid settings JSON.
    ParseFailed,
}

impl SettingsLoadError {
    /// A message for the UI status bar.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::NotFound => "設定ファイルが未作成です（既定値を使用）",
            Self::ReadFailed => "設定ファイルを読み込めません（既定値を使用）",
            Self::ParseFailed => "設定ファイルが破損しています（既定値を使用）",
        }
    }
}

impl core::fmt::Debug for Settings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Settings")
            .field("server_url", &self.server_url)
            .field(
                "email",
                &if self.email.is_empty() {
                    ""
                } else {
                    "[redacted]"
                },
            )
            .field("password_generator", &self.password_generator)
            .field("passphrase_generator", &self.passphrase_generator)
            .field("thresholds", &self.thresholds)
            .field("idle_lock_seconds", &self.idle_lock_seconds)
            .field("login_timeout_seconds", &self.login_timeout_seconds)
            .field("clipboard_restore_seconds", &self.clipboard_restore_seconds)
            .finish()
    }
}

impl Settings {
    /// Clamp editable fields to safe ranges before persisting or applying
    /// them. Bounds match the UI adjusters: 1..=60 minutes for idle lock,
    /// 1..=3600 seconds for login/clipboard delays, 4..=128 characters and
    /// 2..=20 words for the generators.
    pub fn sanitized(&self) -> Self {
        let mut result = self.clone();
        result.idle_lock_seconds = result.idle_lock_seconds.clamp(60, 3600);
        result.login_timeout_seconds = result.login_timeout_seconds.clamp(1, 3600);
        result.clipboard_restore_seconds = result.clipboard_restore_seconds.clamp(1, 3600);
        result.password_generator.length = result.password_generator.length.clamp(4, 128);
        result.passphrase_generator.words = result.passphrase_generator.words.clamp(2, 20);
        result
    }

    /// The default config file path.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("settings.json"))
    }

    /// Load settings from `path`, distinguishing missing, unreadable and
    /// malformed files.
    ///
    /// # Errors
    ///
    /// [`SettingsLoadError`] when the file cannot be used as settings.
    pub fn load_detailed(path: impl AsRef<std::path::Path>) -> Result<Self, SettingsLoadError> {
        let contents = std::fs::read_to_string(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SettingsLoadError::NotFound
            } else {
                SettingsLoadError::ReadFailed
            }
        })?;
        let settings: Self =
            serde_json::from_str(&contents).map_err(|_| SettingsLoadError::ParseFailed)?;
        Ok(settings.sanitized())
    }

    /// Load settings from `path`, or fall back to defaults on any error.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        Self::load_detailed(path).unwrap_or_default()
    }

    /// Save settings to `path`, creating parent directories if needed.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` on filesystem or serialization failure.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let path = path.as_ref();
        let contents = serde_json::to_string_pretty(self)?;
        crate::private_file::write_private(path, contents.as_bytes())
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
