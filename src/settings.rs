//! Persistent settings: server URL, email, generator defaults, thresholds.
//!
//! The PoC stores settings in JSON under the user's config directory. No
//! secrets are persisted here: master passwords and keys live only in memory.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::generator::{PassphraseSettings, PasswordSettings};
use crate::health::Thresholds;

/// Top-level settings object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl Settings {
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
        serde_json::from_str(&contents).map_err(|_| SettingsLoadError::ParseFailed)
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let settings = Settings::default();
        assert!(settings.server_url.contains("bitwarden"));
        assert!(settings.email.is_empty());
        assert_eq!(settings.idle_lock_seconds, 300);
        assert_eq!(settings.login_timeout_seconds, 30);
    }

    #[test]
    fn round_trip_through_temp_file() {
        let dir = std::env::temp_dir().join("bitwarden-gpui-poc-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");

        let settings = Settings {
            email: "alice@example.com".to_string(),
            server_url: "https://vault.example.com".to_string(),
            thresholds: crate::health::Thresholds {
                weak_bits: 60,
                ..Default::default()
            },
            idle_lock_seconds: 600,
            login_timeout_seconds: 45,
            ..Default::default()
        };
        settings.save(&path).expect("failed to save settings");

        let loaded = Settings::load(&path);
        assert_eq!(loaded, settings);
    }

    #[test]
    fn missing_file_falls_back_to_defaults() {
        let path = std::env::temp_dir().join("bitwarden-gpui-poc-does-not-exist.json");
        let settings = Settings::load(&path);
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn load_detailed_distinguishes_missing_and_malformed() {
        let missing = std::env::temp_dir().join("bitwarden-gpui-poc-load-missing.json");
        let _ = std::fs::remove_file(&missing);
        assert_eq!(
            Settings::load_detailed(&missing).err(),
            Some(SettingsLoadError::NotFound)
        );

        let broken = std::env::temp_dir().join("bitwarden-gpui-poc-load-broken.json");
        std::fs::write(&broken, b"not json").unwrap();
        assert_eq!(
            Settings::load_detailed(&broken).err(),
            Some(SettingsLoadError::ParseFailed)
        );

        for error in [
            SettingsLoadError::NotFound,
            SettingsLoadError::ReadFailed,
            SettingsLoadError::ParseFailed,
        ] {
            assert!(!error.message().is_empty());
        }
    }
}
