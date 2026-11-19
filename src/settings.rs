//! Persistent settings: server URL, email, generator defaults, thresholds and
//! the installation's stable device identifier.
//!
//! The PoC stores settings in JSON under the user's config directory. No
//! secrets are persisted here: master passwords and keys live only in memory.
//!
//! The file carries a [`CURRENT_SCHEMA_VERSION`] marker. Files that predate
//! the marker (missing field) are treated as compatible with the current
//! schema, while a *newer* version is never trusted: the whole file is
//! discarded in favour of defaults because its field meanings may differ.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;

use crate::error::{AppError, BoxedCause};
use crate::generator::{PassphraseSettings, PasswordSettings};
use crate::health::Thresholds;

/// Maximum accepted size of `settings.json` (1 MiB). Anything larger is
/// rejected before parsing so a truncated/garbled file cannot consume memory
/// or hide a single bad field behind a flood of data.
pub const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// Schema version written to every settings file produced by this build.
///
/// Bump this when the meaning or shape of a field changes incompatibly.
/// Values `0..=CURRENT_SCHEMA_VERSION` are accepted (0 covers legacy files
/// that used 0 explicitly); anything larger is rejected as unknown.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Top-level settings object.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Schema version of the file this struct came from.
    ///
    /// Missing in legacy files, in which case serde's container-level
    /// `#[serde(default)]` fills it with [`CURRENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Server URL (Bitwarden or Vaultwarden).
    pub server_url: String,
    /// Last-used email address.
    pub email: String,
    /// Stable per-installation device identifier sent on login and resync.
    ///
    /// A pristine in-memory `Settings` has an empty value; [`Self::ensure_device_id`]
    /// fills it from the OS CSPRNG on first use and persists it so later
    /// launches and resync attempts reuse the same identifier.
    pub device_id: String,
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
            schema_version: CURRENT_SCHEMA_VERSION,
            server_url: "https://vault.bitwarden.com".to_string(),
            email: String::new(),
            // Deliberately empty: generation is an explicit, fallible step so
            // `Default` stays deterministic for the tolerance pass and tests.
            device_id: String::new(),
            password_generator: PasswordSettings::default(),
            passphrase_generator: PassphraseSettings::default(),
            thresholds: Thresholds::default(),
            idle_lock_seconds: 300,
            login_timeout_seconds: crate::auth::DEFAULT_LOGIN_TIMEOUT.as_secs(),
            clipboard_restore_seconds: 30,
        }
    }
}

/// A settings field that is also editable from the lock screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedSettingsField {
    /// Server URL.
    ServerUrl,
    /// Account email.
    Email,
}

impl Settings {
    /// Append text to a field owned by `Settings`, from either UI path.
    pub fn push_shared_text(&mut self, field: SharedSettingsField, text: &str) {
        match field {
            SharedSettingsField::ServerUrl => self.server_url.push_str(text),
            SharedSettingsField::Email => self.email.push_str(text),
        }
    }

    /// Remove the last character from a field owned by `Settings`.
    pub fn pop_shared_char(&mut self, field: SharedSettingsField) {
        match field {
            SharedSettingsField::ServerUrl => {
                self.server_url.pop();
            }
            SharedSettingsField::Email => {
                self.email.pop();
            }
        }
    }
}

/// Why settings could not be loaded.
///
/// Kept as its own type so the UI's `&'static str` status messages stay valid.
/// Read and parse failures are also converted into [`AppError`], which retains
/// the original `std::io::Error` / `serde_json::Error` in `Error::source()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsLoadError {
    /// The file does not exist yet; defaults are expected on first launch.
    NotFound,
    /// The file exists but could not be read.
    ReadFailed,
    /// The file exists but is not valid settings JSON.
    ParseFailed,
    /// The file is larger than [`MAX_SETTINGS_BYTES`].
    TooLarge,
    /// A failure from another layer that this small enum cannot describe.
    Other(&'static str),
}

impl SettingsLoadError {
    /// A message for the UI status bar.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::NotFound => "設定ファイルが未作成です（既定値を使用）",
            Self::ReadFailed => "設定ファイルを読み込めません（既定値を使用）",
            Self::ParseFailed => "設定ファイルが破損しています（既定値を使用）",
            Self::TooLarge => "設定ファイルがサイズ上限（1 MiB）を超えています（既定値を使用）",
            Self::Other(text) => text,
        }
    }
}

impl core::fmt::Display for SettingsLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SettingsLoadError {}

impl core::fmt::Debug for Settings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Settings")
            .field("schema_version", &self.schema_version)
            .field("server_url", &self.server_url)
            .field(
                "email",
                &if self.email.is_empty() {
                    ""
                } else {
                    "[redacted]"
                },
            )
            .field("device_id", &self.device_id)
            .field("password_generator", &self.password_generator)
            .field("passphrase_generator", &self.passphrase_generator)
            .field("thresholds", &self.thresholds)
            .field("idle_lock_seconds", &self.idle_lock_seconds)
            .field("login_timeout_seconds", &self.login_timeout_seconds)
            .field("clipboard_restore_seconds", &self.clipboard_restore_seconds)
            .finish()
    }
}

/// Whether two JSON values share a type tag. Numbers of different widths or
/// ranges share a tag; the per-field trial parse below rejects those.
fn same_json_type(left: &Value, right: &Value) -> bool {
    matches!(
        (left, right),
        (Value::Null, Value::Null)
            | (Value::Bool(_), Value::Bool(_))
            | (Value::Number(_), Value::Number(_))
            | (Value::String(_), Value::String(_))
            | (Value::Array(_), Value::Array(_))
            | (Value::Object(_), Value::Object(_))
    )
}

/// Deserialize `T` from `input`, falling back to the default **per field**.
///
/// `#[serde(default)]` supplies missing fields, but a single field with a
/// wrong type (or an out-of-range number) still makes `serde_json` reject the
/// whole struct. Here each input field is offered to a fresh copy of
/// `T::default()` and kept only when the candidate struct still parses. That
/// preserves every correctly typed sibling while replacing only the bad field.
fn tolerant_struct<T>(input: Value) -> T
where
    T: DeserializeOwned + Serialize + Default,
{
    if let Ok(value) = serde_json::from_value::<T>(input.clone()) {
        return value;
    }
    let Some(input_obj) = input.as_object() else {
        return T::default();
    };
    let Ok(default_value) = serde_json::to_value(T::default()) else {
        return T::default();
    };
    let Some(default_obj) = default_value.as_object() else {
        return T::default();
    };

    let mut candidate = default_obj.clone();
    for (key, input_field) in input_obj {
        // Unknown keys are ignored; a field whose JSON type differs from its
        // default cannot be represented by `T` and is replaced by that default.
        let Some(default_field) = candidate.get(key) else {
            continue;
        };
        if !same_json_type(input_field, default_field) {
            continue;
        }
        let mut trial = candidate.clone();
        trial.insert(key.clone(), input_field.clone());
        if serde_json::from_value::<T>(Value::Object(trial.clone())).is_ok() {
            candidate = trial;
        }
    }
    serde_json::from_value::<T>(Value::Object(candidate)).unwrap_or_default()
}

/// Length of a canonical, hyphenated UUID (`8-4-4-4-12`) in characters.
const UUID_TEXT_LEN: usize = 36;

/// Generate a version 4 (random) UUID as canonical lowercase text.
///
/// The `uuid` crate is intentionally not added: an installation identifier
/// only needs 16 CSPRNG bytes with the version/variant bits fixed, and
/// `getrandom` is already a direct dependency. Randomness is never replaced
/// by a hardcoded fallback, because that would reintroduce collisions
/// between installations.
///
/// # Errors
///
/// Returns [`getrandom::Error`] when the OS random source is unavailable.
pub fn generate_device_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    // RFC 9562 version 4 and the RFC 4122 variant (10xx) bit patterns.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(UUID_TEXT_LEN);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(text)
}

/// Whether `value` is a canonical version 4 UUID in hyphenated form.
///
/// Used to decide whether a stored identifier can be safely reused. Anything
/// else (including the empty string and the old hardcoded PoC value) is
/// treated as "not yet generated" and replaced on the next sync attempt.
pub fn is_valid_device_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != UUID_TEXT_LEN {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    // Position 14 is the version nibble, position 19 the variant nibble.
    bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
}

impl Settings {
    /// Clamp editable fields to safe ranges before persisting or applying
    /// them. Bounds match the UI adjusters: 1..=60 minutes for idle lock,
    /// 1..=3600 seconds for login/clipboard delays, 4..=128 characters and
    /// 2..=20 words for the generators, 1..=200 bits / 1..=3650 days for the
    /// audit thresholds.
    pub fn sanitized(&self) -> Self {
        let mut result = self.clone();
        // A hand-edited, malformed identifier must not be sent to the server;
        // clearing it makes the next `ensure_device_id` generate a fresh one.
        if !is_valid_device_id(&result.device_id) {
            result.device_id.clear();
        }
        result.idle_lock_seconds = result.idle_lock_seconds.clamp(60, 3600);
        result.login_timeout_seconds = result.login_timeout_seconds.clamp(1, 3600);
        result.clipboard_restore_seconds = result.clipboard_restore_seconds.clamp(1, 3600);
        result.password_generator.length = result.password_generator.length.clamp(4, 128);
        result.passphrase_generator.words = result.passphrase_generator.words.clamp(2, 20);
        result.thresholds.weak_bits = result.thresholds.weak_bits.clamp(1, 200);
        result.thresholds.stale_days = result.thresholds.stale_days.clamp(1, 3650);
        result
    }

    /// Return this installation's device identifier, creating and persisting
    /// one on first use.
    ///
    /// The initial login and every resync/retry go through this method, so a
    /// valid stored value is always reused unchanged. When the value is empty
    /// or malformed, a version 4 UUID is generated from the OS CSPRNG and,
    /// if `path` is supplied, written back immediately so later launches see
    /// the same identifier. A failed write is reported to the caller and leaves
    /// the in-memory value unchanged, so the next call generates and persists a
    /// fresh identifier instead of silently using an unsaved one.
    ///
    /// # Errors
    ///
    /// [`AppError::RandomUnavailableCause`] when no random source is available,
    /// or [`AppError::SettingsSaveCause`] when the settings file cannot be
    /// written (the original io error stays in `Error::source()`). There is no
    /// hardcoded fallback for the RNG because that would defeat
    /// per-installation uniqueness.
    pub fn ensure_device_id(&mut self, path: Option<&std::path::Path>) -> Result<&str, AppError> {
        if !is_valid_device_id(&self.device_id) {
            let generated = generate_device_id()
                .map_err(|error| AppError::RandomUnavailableCause(BoxedCause::new(error)))?;
            if let Some(path) = path {
                let previous = std::mem::replace(&mut self.device_id, generated);
                if let Err(error) = self.save(path) {
                    // Never use an identifier that was not persisted: the next
                    // call must generate and try again.
                    self.device_id = previous;
                    let detail = format!("デバイス ID を保存できませんでした: {error}");
                    return Err(AppError::SettingsSaveCause(detail, BoxedCause::new(error)));
                }
            } else {
                self.device_id = generated;
            }
        }
        Ok(&self.device_id)
    }

    /// The default config file path.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("settings.json"))
    }

    /// Load settings from `path`, distinguishing missing, unreadable,
    /// oversized and malformed files.
    ///
    /// Reading is capped at [`MAX_SETTINGS_BYTES`] so a runaway file cannot be
    /// parsed. Valid fields are kept even when a sibling has the wrong type.
    ///
    /// # Errors
    ///
    /// [`SettingsLoadError`] when the file cannot be used as settings.
    pub fn load_detailed(path: impl AsRef<std::path::Path>) -> Result<Self, SettingsLoadError> {
        let file = std::fs::File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SettingsLoadError::NotFound
            } else {
                SettingsLoadError::from(AppError::ReadFailedCause(BoxedCause::new(error)))
            }
        })?;
        let metadata = file.metadata().map_err(|error| {
            SettingsLoadError::from(AppError::ReadFailedCause(BoxedCause::new(error)))
        })?;
        if metadata.is_dir() {
            return Err(SettingsLoadError::ReadFailed);
        }
        if metadata.len() > MAX_SETTINGS_BYTES {
            return Err(SettingsLoadError::TooLarge);
        }
        // Read at most one byte past the limit to detect files that grew
        // between the metadata call and the read without loading everything.
        let mut contents = String::new();
        file.take(MAX_SETTINGS_BYTES.saturating_add(1))
            .read_to_string(&mut contents)
            .map_err(|error| {
                SettingsLoadError::from(AppError::ReadFailedCause(BoxedCause::new(error)))
            })?;
        if contents.len() as u64 > MAX_SETTINGS_BYTES {
            return Err(SettingsLoadError::TooLarge);
        }
        Ok(Self::parse_settings(&contents)?.sanitized())
    }

    /// Parse JSON with per-field tolerance, including the nested structs.
    ///
    /// A numeric `schema_version` newer than [`CURRENT_SCHEMA_VERSION`] is
    /// rejected before any other field is read: a future writer may have
    /// changed the meaning of otherwise familiar keys, so no field from such
    /// a file is safe to keep. The whole struct falls back to defaults.
    /// A missing or wrong-typed marker stays compatible and is filled in by
    /// the tolerance pass below.
    ///
    /// The nested objects are repaired first so that a single bad leaf does
    /// not discard its correctly typed siblings; the top level is then parsed
    /// with the same rule. Invalid JSON syntax and a non-object root are the
    /// only cases that still fail as a whole.
    fn parse_settings(contents: &str) -> Result<Self, SettingsLoadError> {
        let mut value: Value = serde_json::from_str(contents).map_err(|error| {
            SettingsLoadError::from(AppError::ParseFailedCause(BoxedCause::new(error)))
        })?;
        let Some(obj) = value.as_object_mut() else {
            return Err(SettingsLoadError::ParseFailed);
        };
        if obj
            .get("schema_version")
            .and_then(Value::as_u64)
            .is_some_and(|version| version > u64::from(CURRENT_SCHEMA_VERSION))
        {
            return Ok(Self::default());
        }
        if let Some(nested) = obj.get_mut("password_generator") {
            *nested = serde_json::to_value(tolerant_struct::<PasswordSettings>(nested.clone()))
                .map_err(|error| {
                    SettingsLoadError::from(AppError::ParseFailedCause(BoxedCause::new(error)))
                })?;
        }
        if let Some(nested) = obj.get_mut("passphrase_generator") {
            *nested = serde_json::to_value(tolerant_struct::<PassphraseSettings>(nested.clone()))
                .map_err(|error| {
                SettingsLoadError::from(AppError::ParseFailedCause(BoxedCause::new(error)))
            })?;
        }
        if let Some(nested) = obj.get_mut("thresholds") {
            *nested = serde_json::to_value(tolerant_struct::<Thresholds>(nested.clone())).map_err(
                |error| SettingsLoadError::from(AppError::ParseFailedCause(BoxedCause::new(error))),
            )?;
        }
        Ok(tolerant_struct::<Settings>(value))
    }

    /// Load settings from `path`, or fall back to defaults on any error.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        Self::load_detailed(path).unwrap_or_default()
    }

    /// Save settings to `path`, creating parent directories if needed.
    ///
    /// The file always records [`CURRENT_SCHEMA_VERSION`], so loading a
    /// compatible legacy struct upgrades it on the next write. `self` is not
    /// mutated.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` on filesystem or serialization failure.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let path = path.as_ref();
        let mut stamped = self.clone();
        stamped.schema_version = CURRENT_SCHEMA_VERSION;
        let contents = serde_json::to_string_pretty(&stamped)?;
        crate::private_file::write_private(path, contents.as_bytes())
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
