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
pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("sync-cache.json"))
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

/// Write a cache entry.
///
/// # Errors
///
/// Returns `std::io::Error` on filesystem or serialization failure.
pub fn save(path: impl AsRef<std::path::Path>, cache: &SyncCache) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    let contents = serde_json::to_vec_pretty(cache)?;
    crate::private_file::write_private(path, &contents)
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
