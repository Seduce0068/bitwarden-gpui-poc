//! Offline cache of the *encrypted* sync response.
//!
//! Only the raw `/api/sync` JSON and the user id are stored. Decryption keys,
//! master passwords and API secrets are never written to disk: keeping the
//! protected key alone would allow an offline master-password guess.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::auth::SyncCacheError;
use crate::vault_sync;

/// A cached sync response, still encrypted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Read a cache entry, returning `None` when missing or unreadable.
pub fn load(path: impl AsRef<std::path::Path>) -> Option<SyncCache> {
    let contents = std::fs::read(path).ok()?;
    let cache: SyncCache = serde_json::from_slice(&contents).ok()?;
    (cache.version == SyncCache::VERSION).then_some(cache)
}

/// Write a cache entry.
///
/// # Errors
///
/// Returns `std::io::Error` on filesystem or serialization failure.
pub fn save(path: impl AsRef<std::path::Path>, cache: &SyncCache) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(cache)?)
}

/// Validate a cache before it is used for the given account and server.
///
/// # Errors
///
/// [`SyncCacheError::UserMismatch`] when the account differs, or
/// [`SyncCacheError::InvalidCache`] when the body cannot be parsed.
pub fn validate(cache: &SyncCache, user_id: &str, server_url: &str) -> Result<(), SyncCacheError> {
    if cache.user_id != user_id || cache.server_url != server_url {
        return Err(SyncCacheError::UserMismatch);
    }
    cache.sync()?;
    Ok(())
}

/// Map a cache error to the status-bar error type used by the auth layer.
pub const fn cache_error_message(error: SyncCacheError) -> &'static str {
    match error {
        SyncCacheError::InvalidCache => "キャッシュが破損しています",
        SyncCacheError::UserMismatch => "キャッシュが別のアカウントのものです",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn body() -> Vec<u8> {
        br#"{
            "profile": {"id": "user-1"},
            "folders": [{"id": "f1", "name": "2.work"}],
            "ciphers": []
        }"#
        .to_vec()
    }

    #[test]
    fn cache_round_trips_through_file() {
        let dir = std::env::temp_dir().join("bitwarden-gpui-poc-cache-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sync-cache.json");
        let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();

        save(&path, &cache).unwrap();
        let loaded = load(&path).expect("cache should load");
        assert_eq!(loaded, cache);
        assert_eq!(loaded.user_id, "user-1");
        assert!(loaded.sync().is_ok());
    }

    #[test]
    fn missing_and_broken_files_return_none() {
        let missing = std::env::temp_dir().join("bitwarden-gpui-poc-no-cache.json");
        assert!(load(&missing).is_none());

        let path = std::env::temp_dir().join("bitwarden-gpui-poc-broken-cache.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(load(&path).is_none());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
        cache.version += 1;
        let path = std::env::temp_dir().join("bitwarden-gpui-poc-version-cache.json");
        save(&path, &cache).unwrap();
        assert!(load(&path).is_none());
    }

    #[test]
    fn validation_checks_account_and_server() {
        let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
        assert!(validate(&cache, "user-1", "https://vault.example.com").is_ok());
        assert_eq!(
            validate(&cache, "other", "https://vault.example.com"),
            Err(SyncCacheError::UserMismatch)
        );
        assert_eq!(
            validate(&cache, "user-1", "https://other.example.com"),
            Err(SyncCacheError::UserMismatch)
        );
    }

    #[test]
    fn profile_keys_are_stripped_before_storage() {
        let body = br#"{
            "profile": {
                "id": "user-1",
                "key": "2.aWxvdGhlcg==",
                "privateKey": "2.encrypted"
            },
            "ciphers": []
        }"#;
        let cache = SyncCache::from_body(body.to_vec(), "https://vault.example.com").unwrap();
        let stored = String::from_utf8(cache.body.clone()).unwrap();
        assert!(!stored.contains("aWxvdGhlcg"), "{stored}");
        assert!(!stored.contains("encrypted"), "{stored}");
        assert!(!stored.contains("privateKey"), "{stored}");
        assert!(stored.contains("user-1"), "{stored}");
        // A key-less sync body must still be parseable for offline display.
        assert!(cache.sync().is_ok());
    }

    #[test]
    fn invalid_body_is_rejected() {
        assert_eq!(
            SyncCache::from_body(b"not json".to_vec(), "https://vault.example.com"),
            Err(SyncCacheError::InvalidCache)
        );
    }

    #[test]
    fn error_messages_are_present() {
        assert!(!cache_error_message(SyncCacheError::InvalidCache).is_empty());
        assert!(!cache_error_message(SyncCacheError::UserMismatch).is_empty());
    }
}
