//! Offline cache of the *encrypted* sync response.
//!
//! Only the raw `/api/sync` JSON and the user id are stored. Decryption keys,
//! master passwords and API secrets are never written to disk: keeping the
//! protected key alone would allow an offline master-password guess.
//!
//! Wiring (see [`cached_sync_for`]): the auth layer reads this cache when
//! `/api/sync` fails *after* a successful login, then unlocks with the
//! protected key from the live `Session`. This is a read-only, best-effort
//! restore. There is currently no production writer: `openwarden` 0.1.0's
//! `Client::sync()` returns a parsed `SyncData` without the raw body and keeps
//! `Session::access_token` private, so `from_body`/`save_default` cannot be
//! fed from the login flow. A cache file therefore exists only if a legacy
//! release wrote one or it was provisioned out of band. A missing cache keeps
//! the original `AuthError::Sync` status; a present but unusable cache reports
//! the classified reason (corrupt / unreadable / outdated / mismatched).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::vault_sync;

/// Errors produced while reading an offline sync cache.
///
/// Alias of [`AppError`](crate::error::AppError). Parsing, redaction and
/// serialization have separate `CacheParse` / `CacheRedact` / `CacheSerialize`
/// variants, each retaining the underlying error through `Error::source()`.
pub type SyncCacheError = crate::error::AppError;

/// Maximum age of a cached sync response before it is refused.
///
/// Seven days balances offline availability with the risk of acting on stale
/// vault data (for example after a key rotation on the server).
pub const MAX_CACHE_AGE_SECS: i64 = 7 * 24 * 60 * 60;

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
    /// When the body was captured, in Unix seconds.
    ///
    /// Absent in caches written by earlier builds; those remain usable as a
    /// best-effort fallback because the writer is not connected in this PoC.
    #[serde(default)]
    pub created_at: Option<i64>,
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
        let sync = vault_sync::parse_sync(&body)
            .map_err(|error| SyncCacheError::CacheParse(crate::error::BoxedCause::new(error)))?;
        let user_id = sync.user_id().to_string();
        let sanitized = redact_profile_keys(&body)?;
        Ok(Self {
            version: Self::VERSION,
            user_id,
            server_url: server_url.to_string(),
            body: sanitized,
            created_at: Some(i64::try_from(crate::totp::now_unix()).unwrap_or(i64::MAX)),
        })
    }

    /// Parse the cached body back into an `openwarden::SyncData`.
    ///
    /// # Errors
    ///
    /// [`SyncCacheError::InvalidCache`] when the body no longer parses.
    pub fn sync(&self) -> Result<openwarden::SyncData, SyncCacheError> {
        vault_sync::parse_sync(&self.body)
            .map_err(|error| SyncCacheError::CacheParse(crate::error::BoxedCause::new(error)))
    }
}

/// Whether a captured-at timestamp is older than the accepted offline window.
///
/// `None` means a cache written before timestamps existed; it stays usable as
/// a best-effort fallback rather than silently disabling offline restore.
pub(crate) fn is_cache_expired(created_at: Option<i64>, now: i64) -> bool {
    created_at.is_some_and(|captured| now.saturating_sub(captured) > MAX_CACHE_AGE_SECS)
}

/// Remove key material from a raw sync body, keeping the rest of the
/// encrypted ciphers and folders intact.
fn redact_profile_keys(body: &[u8]) -> Result<Vec<u8>, SyncCacheError> {
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| SyncCacheError::CacheRedact(crate::error::BoxedCause::new(error)))?;
    if let Some(profile) = value
        .get_mut("profile")
        .and_then(|entry| entry.as_object_mut())
    {
        profile.remove("key");
        profile.remove("privateKey");
        profile.remove("private_key");
    }
    serde_json::to_vec(&value)
        .map_err(|error| SyncCacheError::CacheSerialize(crate::error::BoxedCause::new(error)))
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
///
/// Alias of [`AppError`](crate::error::AppError); read and parse failures keep
/// the original `std::io::Error` / `serde_json::Error` in `Error::source()`.
pub type CacheLoadError = crate::error::AppError;

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
            CacheLoadError::ReadFailedCause(crate::error::BoxedCause::new(error))
        }
    })?;
    let cache: SyncCache = serde_json::from_slice(&contents)
        .map_err(|error| CacheLoadError::ParseFailedCause(crate::error::BoxedCause::new(error)))?;
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

/// Load the encrypted cache for a best-effort offline restore.
///
/// The auth layer calls this when `/api/sync` fails but the API-key login has
/// already succeeded. Only the server URL can be checked here: a failed sync
/// supplies no fresh user id, so a cross-account cache cannot be detected.
/// Key material is never taken from the cache — its
/// `profile.key` / `privateKey` are stripped by [`SyncCache::from_body`] and
/// the live `Session` supplies the protected key at unlock time. A key change
/// since the cache was written can therefore leave cached items undecryptable.
///
/// Returns the classified failure so the caller can tell a missing cache from
/// a corrupt or outdated one instead of collapsing every case into `None`.
///
/// # Errors
///
/// [`SyncCacheError::NotFound`] when no cache file exists,
/// [`SyncCacheError::ReadFailedCause`] when it cannot be read,
/// [`SyncCacheError::ParseFailedCause`] / [`SyncCacheError::CacheParse`] when
/// the stored body is invalid, [`SyncCacheError::VersionMismatch`] when the
/// format changed, [`SyncCacheError::ServerMismatch`] when it belongs to
/// another server, and [`SyncCacheError::CacheRedact`] /
/// [`SyncCacheError::CacheSerialize`] when sanitizing the body fails.
pub fn cached_sync_for_detailed(server_url: &str) -> Result<openwarden::SyncData, SyncCacheError> {
    let cache = load_default()?;
    if cache.server_url != server_url {
        return Err(SyncCacheError::ServerMismatch);
    }
    let now = i64::try_from(crate::totp::now_unix()).unwrap_or(i64::MAX);
    if is_cache_expired(cache.created_at, now) {
        return Err(SyncCacheError::CacheExpired);
    }
    cache.sync()
}

/// Best-effort wrapper around [`cached_sync_for_detailed`] for callers that
/// only need to know whether a usable cache was found.
pub fn cached_sync_for(server_url: &str) -> Option<openwarden::SyncData> {
    cached_sync_for_detailed(server_url).ok()
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

/// Reason strings shared by the cache layer and the auth status mapper.
pub(crate) const REASON_CORRUPT: &str = "キャッシュが破損しています";
pub(crate) const REASON_UNREADABLE: &str = "キャッシュを読み込めません";
pub(crate) const REASON_MISSING: &str = "キャッシュがありません";
pub(crate) const REASON_OUTDATED: &str = "キャッシュのバージョンが古いです";
pub(crate) const REASON_EXPIRED: &str = "キャッシュが有効期限を過ぎています";
pub(crate) const REASON_USER_MISMATCH: &str = "キャッシュが別のアカウントのものです";
pub(crate) const REASON_SERVER_MISMATCH: &str = "キャッシュが別のサーバーのものです";
pub(crate) const REASON_TOO_LARGE: &str = "キャッシュがサイズ上限を超えています";

/// Map a cache error to a short reason for a status-bar message.
pub fn cache_error_message(error: SyncCacheError) -> &'static str {
    match error {
        SyncCacheError::InvalidCache
        | SyncCacheError::CacheParse(_)
        | SyncCacheError::CacheRedact(_)
        | SyncCacheError::CacheSerialize(_)
        | SyncCacheError::ParseFailed
        | SyncCacheError::ParseFailedCause(_) => REASON_CORRUPT,
        SyncCacheError::UserMismatch => REASON_USER_MISMATCH,
        SyncCacheError::ServerMismatch => REASON_SERVER_MISMATCH,
        SyncCacheError::NotFound => REASON_MISSING,
        SyncCacheError::ReadFailed | SyncCacheError::ReadFailedCause(_) => REASON_UNREADABLE,
        SyncCacheError::VersionMismatch => REASON_OUTDATED,
        SyncCacheError::CacheExpired => REASON_EXPIRED,
        SyncCacheError::TooLarge => REASON_TOO_LARGE,
        SyncCacheError::Other(_) => crate::error::OTHER_ERROR_MESSAGE,
        // A future variant must never be reported as proven corruption.
        _ => crate::error::OTHER_ERROR_MESSAGE,
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
