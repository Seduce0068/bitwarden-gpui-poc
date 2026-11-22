//! Persistent settings: server URL, email, generator defaults, thresholds and
//! the installation's stable device identifier.
//!
//! The PoC stores settings in JSON under the user's config directory. No
//! secrets are persisted here: master passwords and keys live only in memory.
//!
//! The file carries a [`CURRENT_SCHEMA_VERSION`] marker. Files that predate
//! the marker (missing field) are kept as [`LEGACY_SCHEMA_VERSION`] and never
//! silently promoted to the current version: they remain compatible field by
//! field, but the loaded struct reports the legacy marker until it is written
//! back. An explicit `0` — including the integral float spelling `0.0` — is
//! the legacy marker, not a claim to be current. A *newer* version is never
//! trusted: the whole file is discarded in
//! favour of defaults because its field meanings may differ. The only field
//! rescued from such a file is a valid `device_id`, which is an opaque local
//! identifier whose meaning cannot change with the schema.
//!
//! # Known constraints (test seams)
//!
//! Neither the file I/O nor the OS random source has an injected seam on any
//! public path here. `read_bounded_settings_text` opens the path through
//! `std::fs` directly, and [`generate_device_id`] calls `getrandom`
//! directly. Tests therefore exercise the classification through real
//! temporary files and assert the structural shape of generated identifiers;
//! they cannot inject a failing reader or a failing RNG.
//!
//! This is a scope choice, not an API constraint: a private helper can be
//! extracted for each source (for example `read_bounded_settings_text_with`
//! taking a reader factory, or `generate_device_id_with` taking a fill
//! closure) while [`Settings::load_detailed`], [`load_advisories`],
//! `file_schema_version` and [`Settings::ensure_device_id`] keep their
//! public signatures. No test-only feature in `Cargo.toml` is needed either,
//! because the seam can stay private to this module's test harness. That
//! refactor is outside this module's change scope; the two limits are recorded
//! here so a reader does not mistake the test coverage for a proof of those
//! failure branches.
//!
//! # Known constraint: direct dependency on `health::Thresholds`
//!
//! [`Settings`] stores `thresholds: Thresholds` by value,
//! [`Settings::sanitized`] clamps `weak_bits` / `stale_days`, and
//! `Settings::parse_settings` repairs the nested object through
//! `tolerant_struct::<Thresholds>`. That is a direct dependency from the
//! persistence layer on the audit layer: the opposite direction from
//! dependency inversion, where settings would own a neutral DTO/port and
//! `health` would depend on it.
//!
//! This inversion is a known, accepted PoC constraint rather than an
//! overlooked boundary. The persisted JSON shape *is* the audit's `Thresholds`
//! shape, the clamp bounds come from the shared `crate::limits` constants,
//! and introducing a DTO/trait seam would change the serde contract and every
//! call site that reads `settings.thresholds`. There is no injected seam for
//! the type here, so this note records the constraint instead of implying a
//! layer boundary that does not exist.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::error::{AppError, BoxedCause};
use crate::generator::{PassphraseSettings, PasswordSettings};
use crate::health::Thresholds;
use crate::limits::{
    has_format_character, truncate_to_limit, DEFAULT_CLIPBOARD_RESTORE_SECONDS,
    DEFAULT_IDLE_LOCK_SECONDS, MAX_CLIPBOARD_RESTORE_SECONDS, MAX_EMAIL_LEN, MAX_IDLE_LOCK_SECONDS,
    MAX_LOGIN_TIMEOUT_SECONDS, MAX_PASSPHRASE_WORDS, MAX_PASSWORD_LENGTH, MAX_SERVER_URL_LEN,
    MAX_STALE_DAYS, MAX_WEAK_BITS, MIN_CLIPBOARD_RESTORE_SECONDS, MIN_IDLE_LOCK_SECONDS,
    MIN_LOGIN_TIMEOUT_SECONDS, MIN_PASSPHRASE_WORDS, MIN_PASSWORD_LENGTH, MIN_STALE_DAYS,
    MIN_WEAK_BITS,
};

/// Leading zero-width code points that may be stripped from a pasted email.
///
/// The generic Unicode `Cf` set lives in `crate::limits`; only this narrow
/// `U+200B..=U+200F` run is treated as a removable prefix. Keeping the two
/// bounds together means the UI input path and `Settings::sanitized()` cannot
/// drift apart when the policy is revised.
const LEADING_ZERO_WIDTH_FIRST: char = '\u{200b}';
const LEADING_ZERO_WIDTH_LAST: char = '\u{200f}';

/// Whether `ch` belongs to the removable leading zero-width run.
fn is_leading_zero_width(ch: char) -> bool {
    (LEADING_ZERO_WIDTH_FIRST..=LEADING_ZERO_WIDTH_LAST).contains(&ch)
}

/// Maximum accepted size of `settings.json` (1 MiB). Anything larger is
/// rejected before parsing so a truncated/garbled file cannot consume memory
/// or hide a single bad field behind a flood of data.
pub const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// Schema version written to every settings file produced by this build.
///
/// Bump this when the meaning or shape of a field changes incompatibly.
/// Values `0..=CURRENT_SCHEMA_VERSION` are accepted (0 covers legacy files
/// that used 0 explicitly); anything larger is rejected as unknown, regardless
/// of the JSON type used to encode it.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Marker for files written before `schema_version` existed, for files whose
/// marker has the wrong type, and for an explicit `0` (including `0.0`).
/// Their known fields stay usable, but the value is not promoted to
/// [`CURRENT_SCHEMA_VERSION`] until the next save.
pub const LEGACY_SCHEMA_VERSION: u32 = 0;

/// Top-level settings object.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Schema version of the file this struct came from.
    ///
    /// Missing or wrongly typed in legacy files: serde's container-level
    /// `#[serde(default)]` first fills it with [`CURRENT_SCHEMA_VERSION`], and
    /// `parse_settings` then explicitly rewrites it to
    /// [`LEGACY_SCHEMA_VERSION`] so a legacy file is not reported as current.
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
            idle_lock_seconds: DEFAULT_IDLE_LOCK_SECONDS,
            login_timeout_seconds: crate::limits::DEFAULT_LOGIN_TIMEOUT.as_secs(),
            clipboard_restore_seconds: DEFAULT_CLIPBOARD_RESTORE_SECONDS,
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

/// Apply the email `Cf` policy shared by the UI input path and `sanitized()`.
///
/// A leading run of zero-width characters (U+200B..U+200F) is common when
/// pasting from a web form: strip it and keep the rest of the address. Every
/// code point in that range is accepted as the first character, including
/// U+200C (ZWNJ) and U+200D (ZWJ); any other format character (a bidi
/// override, a soft hyphen anywhere, a zero-width character after the first
/// non-zero-width character) rejects the whole value. `None` therefore means
/// "reject wholesale", and the caller either drops the pasted chunk or clears
/// the stored email.
fn normalize_email_text(text: &str) -> Option<String> {
    let only_leading_zero_width = text.chars().next().is_some_and(is_leading_zero_width)
        && text
            .chars()
            .skip_while(|ch| is_leading_zero_width(*ch))
            .all(|ch| !crate::limits::is_format_character(ch));
    if !has_format_character(text) || only_leading_zero_width {
        Some(
            text.chars()
                .filter(|ch| !crate::limits::is_format_character(*ch))
                .collect(),
        )
    } else {
        None
    }
}

impl Settings {
    /// Append text to a field owned by `Settings`, from either UI path.
    ///
    /// The same caps used for the network config and for `sanitized()` apply
    /// here, so a large paste cannot grow a stored field past its limit. Like
    /// `AuthState::push_text`, excess input is dropped rather than reported as
    /// an error, and truncation happens on a UTF-8 character boundary.
    ///
    /// Email input additionally drops Unicode `Cf` (format) characters from the
    /// appended text. `valid_email` rejects them at login time, so accepting
    /// them here would persist an address that can never pass validation — a
    /// silent mismatch between the stored settings and the login form. Keeping
    /// the filter at the input source (rather than only in `valid_email`) also
    /// covers IME/paste paths that type invisible zero-width or bidi controls.
    /// Other fields are unaffected: format characters in a server URL are not
    /// subject to the email structural check.
    pub fn push_shared_text(&mut self, field: SharedSettingsField, text: &str) {
        match field {
            SharedSettingsField::ServerUrl => {
                self.server_url.push_str(text);
                truncate_to_limit(&mut self.server_url, MAX_SERVER_URL_LEN);
            }
            SharedSettingsField::Email => {
                // Share the exact normalization policy with `sanitized()` so a
                // hand-edited settings file cannot reintroduce `Cf` characters
                // that the UI input path would have rejected or stripped.
                if let Some(filtered) = normalize_email_text(text) {
                    self.email.push_str(&filtered);
                }
                truncate_to_limit(&mut self.email, MAX_EMAIL_LEN);
            }
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
/// Read and parse failures originate as [`AppError`] with a retained cause, but
/// converting them to `SettingsLoadError` drops that cause: this type has no
/// `source()` chain. Diagnostics beyond the status text are only available
/// while the failure is still an `AppError`.
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

impl From<SettingsLoadError> for AppError {
    fn from(error: SettingsLoadError) -> Self {
        match error {
            SettingsLoadError::NotFound => Self::NotFound,
            SettingsLoadError::ReadFailed => Self::ReadFailed,
            SettingsLoadError::ParseFailed => Self::ParseFailed,
            SettingsLoadError::TooLarge => Self::TooLarge,
            SettingsLoadError::Other(text) => Self::Other(text.to_string()),
        }
    }
}

impl From<AppError> for SettingsLoadError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::NotFound => SettingsLoadError::NotFound,
            AppError::ReadFailed | AppError::ReadFailedCause(_) => SettingsLoadError::ReadFailed,
            AppError::ParseFailed | AppError::ParseFailedCause(_) => SettingsLoadError::ParseFailed,
            AppError::TooLarge => SettingsLoadError::TooLarge,
            _ => SettingsLoadError::Other(crate::error::OTHER_ERROR_MESSAGE),
        }
    }
}

impl core::fmt::Debug for Settings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Settings")
            .field("schema_version", &self.schema_version)
            // A server URL is credential-bearing: `https://user:pass@host` and
            // `...?token=...` are both valid inputs. The cache layer's
            // `mask_url_secrets` establishes the policy that embedded
            // credentials never reach a log line; here the whole value is
            // replaced so even a plain default URL is not rendered verbatim.
            // The empty case stays empty, matching the email field below.
            .field(
                "server_url",
                &if self.server_url.is_empty() {
                    ""
                } else {
                    "[redacted]"
                },
            )
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

/// Read a settings file under the shared size cap.
///
/// This is the single bounded read used by every settings path: the full load,
/// the advisory scan and the write-path marker guard. A `metadata()` length
/// check followed by `read_to_string()` was a TOCTOU — a file that grew in
/// between (or whose metadata lies) could be loaded in full just to inspect one
/// marker. Reading at most one byte past the cap and rejecting that case makes
/// the cap itself the only boundary; there is no pre-check to race with.
///
/// Known constraint: there is no injected reader seam. The path is opened with
/// `std::fs::File::open` and the byte limit is applied through `Read::take`, so
/// a test cannot supply a failing/counting reader here; it must create a real
/// file (see `settings_tests.rs`). The full load, the advisory scan and the
/// write-path marker guard all go through this one function so their
/// classifications cannot drift apart despite the missing seam.
fn read_bounded_settings_text(path: &std::path::Path) -> Result<String, SettingsLoadError> {
    let file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SettingsLoadError::NotFound
        } else {
            SettingsLoadError::from(AppError::ReadFailedCause(BoxedCause::new(error)))
        }
    })?;
    let mut contents = String::new();
    file.take(MAX_SETTINGS_BYTES.saturating_add(1))
        .read_to_string(&mut contents)
        .map_err(|error| {
            SettingsLoadError::from(AppError::ReadFailedCause(BoxedCause::new(error)))
        })?;
    if contents.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(SettingsLoadError::TooLarge);
    }
    Ok(contents)
}

/// Read a settings file under the shared size cap and parse it as JSON.
///
/// `load_advisories` (top-level key inspection) and `file_schema_version`
/// (write-path guard) only need metadata, so both collapse every read or parse
/// failure into `None` — "no metadata" — while sharing the bounded reader with
/// the full load.
fn read_settings_json(path: &std::path::Path) -> Option<Value> {
    let contents = read_bounded_settings_text(path).ok()?;
    serde_json::from_str::<Value>(&contents).ok()
}

/// Known constraint: the [`KNOWN`] key list is managed by hand, separately
/// from [`Settings`]'s serde field list — there is no generated single source
/// of truth. Adding a field to `Settings` without adding its key to [`KNOWN`]
/// makes every file containing that key report a spurious "unknown key"
/// advisory, so the two lists must be updated together. The regression test
/// `every_serialized_settings_field_is_in_the_known_key_list` checks the
/// one-way subset relation (every serialized field is known) on each run.
///
/// The list is `pub(crate)` so the reverse-relation test reads the live value
/// instead of a hand-copied mirror that could silently drift from it.
pub(crate) const KNOWN: &[&str] = &[
    "schema_version",
    "server_url",
    "email",
    "device_id",
    "password_generator",
    "passphrase_generator",
    "thresholds",
    "idle_lock_seconds",
    "login_timeout_seconds",
    "clipboard_restore_seconds",
];

/// Warnings for a file that parsed, but whose metadata cannot be fully
/// trusted: a future schema marker or unknown keys. See `KNOWN` for the
/// hand-maintained key list and its drift constraint.
pub fn load_advisories(path: &std::path::Path) -> Vec<String> {
    // Both advisory and marker reads share `read_settings_json`, so the cap
    // and TOCTOU handling cannot drift between them.
    let Some(value) = read_settings_json(path) else {
        return Vec::new();
    };
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut notices = Vec::new();
    if let Some(version) = schema_version_of(object.get("schema_version")) {
        if version > u64::from(CURRENT_SCHEMA_VERSION) {
            notices.push(format!(
                "設定ファイルのバージョン {version} は未対応です。既定値で起動します"
            ));
        }
    }
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !KNOWN.contains(&key.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        notices.push(format!(
            "未知の設定キーは無視されます: {}",
            unknown.join(", ")
        ));
    }
    notices
}

/// Interpret a version marker encoded as a floating-point number.
///
/// A future writer can serialize a marker as `2.0` or as a numeric string that
/// no longer fits [`u64`]. Integral values stay on the future side of the
/// guard: the `as` cast saturates at [`u64::MAX`], and an infinity is mapped to
/// the same sentinel. Negative, fractional and `NaN` values are not version
/// markers and return `None` (legacy).
fn version_from_float(value: f64) -> Option<u64> {
    if value.is_nan() || value < 0.0 {
        return None;
    }
    if value.is_infinite() {
        return Some(u64::MAX);
    }
    (value.fract() == 0.0).then_some(value as u64)
}

/// Read a schema marker as a number regardless of its JSON type.
///
/// A future writer might have serialized the version as a string (e.g.
/// `"9999"`). Treating that as "wrong type, therefore current" would silently
/// downgrade an unknown schema to one we claim to understand, so numeric
/// strings are parsed here and rejected by the same future-version guard as a
/// JSON number. A string beyond [`u64`] is still numeric and is classified as
/// the maximum version, never as legacy. Non-numeric values return `None` and
/// are treated as legacy.
fn schema_version_of(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().and_then(version_from_float)),
        Value::String(text) => {
            let trimmed = text.trim();
            trimmed
                .parse::<u64>()
                .ok()
                .or_else(|| trimmed.parse::<f64>().ok().and_then(version_from_float))
        }
        _ => None,
    }
}

/// Read the schema marker directly from a file without applying fallbacks.
///
/// `load_detailed` intentionally falls back to defaults for a future version,
/// but write paths must not replace such a file: doing so would destroy keys
/// whose meaning this build does not understand. The read is capped at
/// [`MAX_SETTINGS_BYTES`] just like [`Settings::load_detailed`]: an oversized
/// file returns `None` rather than being loaded into memory just to inspect a
/// marker. Unreadable and malformed files are likewise treated as "no marker".
fn file_schema_version(path: &std::path::Path) -> Option<u64> {
    let value = read_settings_json(path)?;
    schema_version_of(value.get("schema_version"))
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
///
/// Known constraint (test seam): there is deliberately no injected RNG
/// parameter here. A failing source can be injected without changing this
/// public signature by extracting a private `generate_device_id_with(fill)`
/// helper and leaving this function as a thin wrapper that passes
/// `getrandom::fill`; no test-only dependency or `Cargo.toml` feature is
/// required. That refactor is outside this module's change scope, so tests
/// cover the structural contract (canonical v4 UUID shape and non-collision
/// between draws) and the persisted/reused-value paths, but cannot force the
/// `getrandom::fill` failure branch. The same constraint is recorded for the
/// file-I/O path in the module docs above.
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
    /// audit thresholds. The same auth caps apply to `server_url` and `email`,
    /// reusing the constants from `crate::limits` so the stored value and the
    /// effective (clamped) login config cannot diverge.
    ///
    /// Known constraint: `passphrase_generator.separator` is a free-form
    /// string, so a single alphanumeric character (e.g. `x`) is accepted here
    /// and by the generator (`generator.rs:129,169`). The health audit's
    /// passphrase recognizer only handles a repeated *non*-alphanumeric
    /// separator or no separator at all, so such a passphrase falls back to
    /// the character-pool estimate and can be scored far above its real
    /// word-list entropy. This carries the same regression risk as the
    /// multiple-character-separator case and is deliberately left unchanged:
    /// rejecting or rewriting the separator would be a behaviour change
    /// outside this module's scope. Callers that must avoid the overestimate
    /// should keep the separator non-alphanumeric (the default `-`) or empty.
    pub fn sanitized(&self) -> Self {
        let mut result = self.clone();
        // A hand-edited, malformed identifier must not be sent to the server;
        // clearing it makes the next `ensure_device_id` generate a fresh one.
        if !is_valid_device_id(&result.device_id) {
            result.device_id.clear();
        }
        truncate_to_limit(&mut result.server_url, MAX_SERVER_URL_LEN);
        // A hand-edited settings file can carry Unicode `Cf` characters that
        // the UI input path never accepts. Apply the same policy as
        // `push_shared_text`: strip a leading zero-width run, reject (clear)
        // any value containing other format characters. Without this, load()
        // could persist an address that `auth::valid_email` always rejects.
        if let Some(normalized) = normalize_email_text(&result.email) {
            result.email = normalized;
        } else {
            result.email.clear();
        }
        truncate_to_limit(&mut result.email, MAX_EMAIL_LEN);
        result.idle_lock_seconds = result
            .idle_lock_seconds
            .clamp(MIN_IDLE_LOCK_SECONDS, MAX_IDLE_LOCK_SECONDS);
        result.login_timeout_seconds = result
            .login_timeout_seconds
            .clamp(MIN_LOGIN_TIMEOUT_SECONDS, MAX_LOGIN_TIMEOUT_SECONDS);
        result.clipboard_restore_seconds = result
            .clipboard_restore_seconds
            .clamp(MIN_CLIPBOARD_RESTORE_SECONDS, MAX_CLIPBOARD_RESTORE_SECONDS);
        result.password_generator.length = result
            .password_generator
            .length
            .clamp(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        result.passphrase_generator.words = result
            .passphrase_generator
            .words
            .clamp(MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS);
        result.thresholds.weak_bits = result
            .thresholds
            .weak_bits
            .clamp(MIN_WEAK_BITS, MAX_WEAK_BITS);
        result.thresholds.stale_days = result
            .thresholds
            .stale_days
            .clamp(MIN_STALE_DAYS, MAX_STALE_DAYS);
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
    /// or [`AppError::SettingsSaveCause`] when the settings file cannot be read
    /// or written (the original io error stays in `Error::source()`). There is no
    /// hardcoded fallback for the RNG because that would defeat
    /// per-installation uniqueness.
    pub fn ensure_device_id(&mut self, path: Option<&std::path::Path>) -> Result<&str, AppError> {
        if !is_valid_device_id(&self.device_id) {
            let generated = generate_device_id()
                .map_err(|error| AppError::RandomUnavailableCause(BoxedCause::new(error)))?;
            if let Some(path) = path {
                if let Err(error) = Self::save_device_id_only(path, &generated) {
                    // Never use an identifier that was not persisted: the next
                    // call must generate and try again.
                    let detail = format!("デバイス ID を保存できませんでした: {error}");
                    return Err(AppError::SettingsSaveCause(detail, BoxedCause::new(error)));
                }
            }
            self.device_id = generated;
        }
        Ok(&self.device_id)
    }

    /// Persist only the device identifier, preserving other on-disk fields.
    ///
    /// The login screen may hold unsaved shared-field edits; writing `self`
    /// would silently persist them. Re-read the file, replace just the id and
    /// stamp the current schema before writing.
    ///
    /// Only [`SettingsLoadError::NotFound`] is treated as "no file yet": any
    /// other load failure (unreadable, oversized or malformed) is returned as
    /// an [`std::io::Error`] and the write is aborted, so a broken file is never
    /// overwritten with defaults and its other fields are not silently lost.
    ///
    /// Known constraint: this helper writes `id` verbatim and does **not** call
    /// [`is_valid_device_id`]. Validation lives on the reuse path
    /// ([`Settings::ensure_device_id`]); a direct caller can therefore persist
    /// an arbitrary string as the device id. `load_detailed` keeps such an id,
    /// but [`Settings::sanitized`] clears it and [`Settings::ensure_device_id`]
    /// generates a fresh one on the next sync, so no invalid id is sent to the
    /// server. This is a documented limitation rather than a silent contract.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` when the existing file cannot be read/parsed,
    /// when serialization fails, or when the write itself fails.
    pub fn save_device_id_only(path: &std::path::Path, id: &str) -> std::io::Result<()> {
        if let Some(version) = file_schema_version(path) {
            if version > u64::from(CURRENT_SCHEMA_VERSION) {
                return Err(std::io::Error::other(format!(
                    "設定ファイルのバージョン {version} は未対応のため上書きを中止しました"
                )));
            }
        }
        let mut current = match Self::load_detailed(path) {
            Ok(settings) => settings,
            Err(SettingsLoadError::NotFound) => Self::default(),
            Err(error) => {
                // Do not reuse SettingsLoadError's message here: it promises
                // default values, while this path deliberately aborts without
                // touching the existing file.
                return Err(std::io::Error::other(format!(
                    "保存済みの設定を読み込めないため上書きを中止しました（{error:?}）"
                )));
            }
        };
        current.device_id = id.to_string();
        current.schema_version = CURRENT_SCHEMA_VERSION;
        let contents = serde_json::to_string_pretty(&current).map_err(std::io::Error::other)?;
        crate::private_file::write_private(path, contents.as_bytes())
    }

    /// The default config file path.
    ///
    /// Resolved once per process so every UI call site observes the same
    /// location even if the environment changes later.
    pub fn default_path() -> Option<PathBuf> {
        static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
        PATH.get_or_init(|| {
            dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("settings.json"))
        })
        .clone()
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
        // The same bounded reader serves the advisory and marker checks, so a
        // file that grows mid-read is classified identically on every path.
        let contents = read_bounded_settings_text(path.as_ref())?;
        Ok(Self::parse_settings(&contents)?.sanitized())
    }

    /// Parse JSON with per-field tolerance, including the nested structs.
    ///
    /// A `schema_version` newer than [`CURRENT_SCHEMA_VERSION`] is rejected
    /// before any other field is read, regardless of its JSON type (a numeric
    /// string such as `"9999"` counts as a future version too): a future writer
    /// may have changed what otherwise familiar keys mean. Only a valid
    /// `device_id` survives, because it is an opaque local identifier whose
    /// meaning cannot change with the schema. Everything else falls back to
    /// defaults.
    ///
    /// A missing or wrong-typed marker stays compatible and is explicitly
    /// reported as [`LEGACY_SCHEMA_VERSION`], never silently promoted to the
    /// current version. Only a correctly typed numeric marker is trusted.
    /// An integral numeric marker that serde cannot coerce into the `u32`
    /// field (notably `0.0`) is reported from the raw JSON value instead of
    /// falling back to [`CURRENT_SCHEMA_VERSION`]: `0.0` is the legacy marker.
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
        let raw_version = obj.get("schema_version");
        let numeric_version = schema_version_of(raw_version);
        let well_typed = matches!(raw_version, Some(Value::Number(_)));
        if numeric_version.is_some_and(|version| version > u64::from(CURRENT_SCHEMA_VERSION)) {
            let mut result = Self::default();
            // The device id is an opaque UUID, not a schema-governed field: a
            // valid one is safe to reuse even when the rest of the file comes
            // from an unknown writer. A malformed value is dropped as usual.
            if let Some(id) = obj.get("device_id").and_then(Value::as_str) {
                if is_valid_device_id(id) {
                    result.device_id = id.to_string();
                }
            }
            return Ok(result);
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
        let mut parsed = tolerant_struct::<Settings>(value);
        if !well_typed || numeric_version.is_none() {
            // serde's container default would otherwise present a legacy file
            // as if it had explicitly declared the current schema.
            parsed.schema_version = LEGACY_SCHEMA_VERSION;
        } else if let Some(version) = numeric_version {
            // A JSON number such as `0.0` cannot be deserialized into the u32
            // field, so `tolerant_struct` leaves the default (`1`) there.
            // That would silently promote an explicit legacy marker to the
            // current schema. Trust the raw numeric marker instead; future
            // versions already returned above, so this is always in range.
            if version <= u64::from(u32::MAX) {
                parsed.schema_version = version as u32;
            } else {
                parsed.schema_version = LEGACY_SCHEMA_VERSION;
            }
        }
        Ok(parsed)
    }

    /// Load settings from `path`, or fall back to defaults on any error.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        Self::load_detailed(path).unwrap_or_default()
    }

    /// Save settings to `path`, creating parent directories if needed.
    ///
    /// A compatible file records [`CURRENT_SCHEMA_VERSION`] on write, so
    /// loading a legacy struct upgrades it on the next save. As in
    /// [`Self::save_device_id_only`], a *future* marker already on disk aborts
    /// the write: replacing such a file with a struct this build claims to
    /// understand would destroy keys whose meaning it does not know. Missing,
    /// oversized, unreadable and malformed files are still replaced with the
    /// sanitized struct, matching the existing load fallbacks. The write uses
    /// [`Self::sanitized`] on a clone so the persisted value matches the
    /// effective (clamped) one; `self` is never mutated.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` on filesystem or serialization failure, or
    /// when the existing file carries a future schema version.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let path = path.as_ref();
        if let Some(version) = file_schema_version(path) {
            if version > u64::from(CURRENT_SCHEMA_VERSION) {
                return Err(std::io::Error::other(format!(
                    "設定ファイルのバージョン {version} は未対応のため上書きを中止しました"
                )));
            }
        }
        let mut stamped = self.sanitized();
        stamped.schema_version = CURRENT_SCHEMA_VERSION;
        let contents = serde_json::to_string_pretty(&stamped)?;
        crate::private_file::write_private(path, contents.as_bytes())
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
