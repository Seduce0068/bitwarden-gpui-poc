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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server_url: "https://vault.bitwarden.com".to_string(),
            email: String::new(),
            password_generator: PasswordSettings::default(),
            passphrase_generator: PassphraseSettings::default(),
            thresholds: Thresholds::default(),
        }
    }
}

impl Settings {
    /// The default config file path.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("settings.json"))
    }

    /// Load settings from `path`, or fall back to defaults on any error.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
            .unwrap_or_default()
    }

    /// Save settings to `path`, creating parent directories if needed.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` on filesystem or serialization failure.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(path, contents)
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
}
