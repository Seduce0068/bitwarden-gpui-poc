//! Offline cache of the *encrypted* sync response.
//!
//! Only the raw `/api/sync` JSON and the user id are stored. Decryption keys,
//! master passwords and API secrets are never written to disk: keeping the
//! protected key alone would allow an offline master-password guess.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::vault_sync;

/// Errors produced while reading an offline sync cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncCacheError {
    /// The cached body is missing or cannot be parsed.
    InvalidCache,
    /// The cache belongs to a different account.
    UserMismatch,
    /// The cache was fetched from a different server.
    ServerMismatch,
}

impl core::fmt::Display for SyncCacheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(cache_error_message(*self))
    }
}

impl std::error::Error for SyncCacheError {}

/// A cached sync response, still encrypted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCache {
    /// Schema version, so a future format change can be detected.
    pub version: u32,
    /// The account the response belongs to.
    pub user_id: String,
    /// Server URL the response came from.
    pub server_url: String,
    /// Raw `/api/sync` JSON body.
    pub body: Vec<u8>,
}

impl core::fmt::Debug for SyncCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncCache")
            .field("version", &self.version)
            .field("user_id", &self.user_id)
            .field("server_url", &self.server_url)
            .field("body", &format!("<{} bytes redacted>", self.body.len()))
            .finish()
    }
}

impl SyncCache {
    /// The current schema version.
    pub const VERSION: u32 = 1;

    /// Build a cache entry from a sync response body.
    ///
    /// The `profile.key` and `profile.private_key` fields are stripped before
    /// storage: keeping the protected key on disk would allow an offline
    /// master-password guess. `apply_sync` tolerates their absence because
    /// the live `Session` supplies the protected key at unlock time.
    ///
    /// # Errors
    ///
    /// [`SyncCacheError::InvalidCache`] when the body is not a valid sync
    /// response.
    pub fn from_body(body: Vec<u8>, server_url: &str) -> Result<Self, SyncCacheError> {
        let sync = vault_sync::parse_sync(&body).map_err(|_| SyncCacheError::InvalidCache)?;
        let user_id = sync.user_id().to_string();
        let sanitized = redact_profile_keys(&body)?;
        Ok(Self {
            version: Self::VERSION,
            user_id,
            server_url: server_url.to_string(),
            body: sanitized,
        })
    }

    /// Parse the cached body back into an `openwarden::SyncData`.
    ///
    /// # Errors
    ///
    /// [`SyncCacheError::InvalidCache`] when the body no longer parses.
    pub fn sync(&self) -> Result<openwarden::SyncData, SyncCacheError> {
        vault_sync::parse_sync(&self.body).map_err(|_| SyncCacheError::InvalidCache)
    }
}

/// Remove key material from a raw sync body, keeping the rest of the
/// encrypted ciphers and folders intact.
fn redact_profile_keys(body: &[u8]) -> Result<Vec<u8>, SyncCacheError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| SyncCacheError::InvalidCache)?;
    if let Some(profile) = value
        .get_mut("profile")
        .and_then(|entry| entry.as_object_mut())
    {
        profile.remove("key");
        profile.remove("privateKey");
        profile.remove("private_key");
    }
    serde_json::to_vec(&value).map_err(|_| SyncCacheError::InvalidCache)
}

/// The default cache file path.
///
/// The sync cache is disposable (it can be rebuilt from the server), so it
/// belongs under the platform cache directory rather than the config
/// directory. On Linux this is
/// `$XDG_CACHE_HOME/bitwarden-gpui-poc/sync-cache.json`, falling back to
/// `$HOME/.cache/bitwarden-gpui-poc/sync-cache.json` when `XDG_CACHE_HOME`
/// is unset. All new writes must use this path (see [`save_default`]).
pub fn default_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("sync-cache.json"))
}

/// The legacy cache path under the config directory, kept **read-only**.
///
/// Older releases stored the sync cache in `dirs::config_dir()`. A file left
/// there by such a release is still readable through [`load_default`] and
/// [`load_with_fallback`], so upgrading does not lose the offline cache. It
/// is never written to again: the legacy file is left untouched, and the next
/// write goes to [`default_path`] (see [`save_default`]), which then takes
/// precedence on subsequent reads. No automatic copy/move is performed on
/// read, so loading a cache has no filesystem side effects.
pub fn legacy_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("sync-cache.json"))
}

/// Read a cache from `primary`, falling back to `fallback` only when the
/// primary file does not exist.
///
/// This is the read side of the cache-directory migration: the fallback is
/// purely for backward compatibility and is never copied, moved or rewritten.
/// A primary file that exists but is unreadable, malformed or outdated is
/// reported as-is instead of silently falling back to potentially stale
/// legacy data.
///
/// # Errors
///
/// [`CacheLoadError`] when neither location holds a usable cache.
pub fn load_with_fallback(
    primary: impl AsRef<std::path::Path>,
    fallback: impl AsRef<std::path::Path>,
) -> Result<SyncCache, CacheLoadError> {
    match load_detailed(primary) {
        Ok(cache) => Ok(cache),
        Err(CacheLoadError::NotFound) => load_detailed(fallback),
        Err(error) => Err(error),
    }
}

/// Read the cache from [`default_path`], falling back to the read-only
/// [`legacy_path`] when no cache-dir file exists yet.
///
/// # Errors
///
/// [`CacheLoadError`] when no usable cache exists, or when no platform
/// cache/config directory is available at all.
pub fn load_default() -> Result<SyncCache, CacheLoadError> {
    match (default_path(), legacy_path()) {
        (Some(primary), Some(fallback)) => load_with_fallback(primary, fallback),
        (Some(primary), None) => load_detailed(primary),
        (None, Some(fallback)) => load_detailed(fallback),
        (None, None) => Err(CacheLoadError::NotFound),
    }
}

/// Why a cache entry could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheLoadError {
    /// The cache file does not exist yet.
    NotFound,
    /// The file exists but could not be read.
    ReadFailed,
    /// The file exists but is not valid cache JSON.
    ParseFailed,
    /// The cache was written by an incompatible version.
    VersionMismatch,
}

impl core::fmt::Display for CacheLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for CacheLoadError {}

impl CacheLoadError {
    /// A message for the UI status bar.
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotFound => "キャッシュが未作成です",
            Self::ReadFailed => "キャッシュを読み込めません",
            Self::ParseFailed => "キャッシュが破損しています",
            Self::VersionMismatch => "キャッシュのバージョンが古いです",
        }
    }
}

/// Read a cache entry, distinguishing missing, unreadable, malformed and
/// outdated files.
///
/// # Errors
///
/// [`CacheLoadError`] when the file cannot be used as a cache.
pub fn load_detailed(path: impl AsRef<std::path::Path>) -> Result<SyncCache, CacheLoadError> {
    let contents = std::fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CacheLoadError::NotFound
        } else {
            CacheLoadError::ReadFailed
        }
    })?;
    let cache: SyncCache =
        serde_json::from_slice(&contents).map_err(|_| CacheLoadError::ParseFailed)?;
    if cache.version != SyncCache::VERSION {
        return Err(CacheLoadError::VersionMismatch);
    }
    Ok(cache)
}

/// Read a cache entry, returning `None` when missing or unreadable.
pub fn load(path: impl AsRef<std::path::Path>) -> Option<SyncCache> {
    load_detailed(path).ok()
}

/// Write a cache entry to an explicit path.
///
/// Callers should pass [`default_path`] (or use [`save_default`]) so that new
/// data is written under the cache directory. [`legacy_path`] must never be
/// used for writes: an old config-dir file is left in place and simply stops
/// being read once a cache-dir file exists.
///
/// # Errors
///
/// Returns `std::io::Error` on filesystem or serialization failure.
pub fn save(path: impl AsRef<std::path::Path>, cache: &SyncCache) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    let contents = serde_json::to_vec_pretty(cache)?;
    crate::private_file::write_private(path, &contents)
}

/// Write a cache entry to [`default_path`] only.
///
/// This never creates or updates [`legacy_path`], enforcing the migration
/// policy: existing config-dir caches remain readable, but all new writes go
/// exclusively under the cache directory.
///
/// # Errors
///
/// Returns `std::io::Error` when no platform cache directory is available,
/// or on a filesystem/serialization failure.
pub fn save_default(cache: &SyncCache) -> Result<(), std::io::Error> {
    let path = default_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no platform cache directory available",
        )
    })?;
    save(path, cache)
}

/// Validate a cache before it is used for the given account and server.
///
/// # Errors
///
/// [`SyncCacheError::UserMismatch`] when the account differs,
/// [`SyncCacheError::ServerMismatch`] when the server differs, or
/// [`SyncCacheError::InvalidCache`] when the body cannot be parsed.
pub fn validate(cache: &SyncCache, user_id: &str, server_url: &str) -> Result<(), SyncCacheError> {
    if cache.user_id != user_id {
        return Err(SyncCacheError::UserMismatch);
    }
    if cache.server_url != server_url {
        return Err(SyncCacheError::ServerMismatch);
    }
    cache.sync()?;
    Ok(())
}

/// Map a cache error to the status-bar error type used by the auth layer.
pub const fn cache_error_message(error: SyncCacheError) -> &'static str {
    match error {
        SyncCacheError::InvalidCache => "キャッシュが破損しています",
        SyncCacheError::UserMismatch => "キャッシュが別のアカウントのものです",
        SyncCacheError::ServerMismatch => "キャッシュが別のサーバーのものです",
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
