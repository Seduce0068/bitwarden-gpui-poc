#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::cache::*;

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

#[::core::prelude::v1::test]
fn load_detailed_distinguishes_failure_modes() {
    let missing = std::env::temp_dir().join("bitwarden-gpui-poc-detailed-missing.json");
    let _ = std::fs::remove_file(&missing);
    assert_eq!(
        load_detailed(&missing).err(),
        Some(CacheLoadError::NotFound)
    );

    let broken = std::env::temp_dir().join("bitwarden-gpui-poc-detailed-broken.json");
    std::fs::write(&broken, b"not json").unwrap();
    assert_eq!(
        load_detailed(&broken).err(),
        Some(CacheLoadError::ParseFailed)
    );

    // Reading a directory as a file fails (EISDIR on Unix).
    let directory = std::env::temp_dir().join("bitwarden-gpui-poc-detailed-dir");
    std::fs::create_dir_all(&directory).unwrap();
    assert_eq!(
        load_detailed(&directory).err(),
        Some(CacheLoadError::ReadFailed)
    );

    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    cache.version += 1;
    let outdated = std::env::temp_dir().join("bitwarden-gpui-poc-detailed-old.json");
    save(&outdated, &cache).unwrap();
    assert_eq!(
        load_detailed(&outdated).err(),
        Some(CacheLoadError::VersionMismatch)
    );

    for error in [
        CacheLoadError::NotFound,
        CacheLoadError::ReadFailed,
        CacheLoadError::ParseFailed,
        CacheLoadError::VersionMismatch,
    ] {
        assert!(!error.message().is_empty());
    }
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
        Err(SyncCacheError::ServerMismatch)
    );
}

#[::core::prelude::v1::test]
fn debug_never_reveals_the_body() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let rendered = format!("{cache:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(!rendered.contains("ciphers"), "{rendered}");
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
    assert!(!cache_error_message(SyncCacheError::ServerMismatch).is_empty());
}

// --- Cache-directory migration (default path -> XDG cache, legacy read-only) ---

/// Environment variables are process-global; serialize tests that change them.
#[cfg(target_os = "linux")]
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
struct EnvGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

#[cfg(target_os = "linux")]
impl EnvGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

#[cfg(target_os = "linux")]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

#[test]
fn default_path_uses_cache_dir_and_legacy_path_uses_config_dir() {
    let cache_name = std::path::Path::new("bitwarden-gpui-poc").join("sync-cache.json");
    assert_eq!(
        default_path(),
        dirs::cache_dir().map(|dir| dir.join(&cache_name))
    );
    assert_eq!(
        legacy_path(),
        dirs::config_dir().map(|dir| dir.join(&cache_name))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn xdg_cache_home_selects_cache_dir_and_new_writes_land_there() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-xdg-cache-test");
    let _ = std::fs::remove_dir_all(&root);
    let xdg = root.join("xdg-cache-home");
    let _env = EnvGuard::set("XDG_CACHE_HOME", &xdg);

    let expected = xdg.join("bitwarden-gpui-poc").join("sync-cache.json");
    assert_eq!(default_path(), Some(expected.clone()));
    // The legacy path is config-based and must not follow XDG_CACHE_HOME.
    assert_eq!(
        legacy_path(),
        dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("sync-cache.json"))
    );
    assert_ne!(default_path(), legacy_path());

    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save_default(&cache).unwrap();
    assert!(expected.is_file(), "new writes must go under the cache dir");
    assert_eq!(load_default(), Ok(cache));
}

#[test]
fn legacy_cache_is_read_but_never_rewritten() {
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-migration-test");
    let _ = std::fs::remove_dir_all(&root);
    let new = root.join("cache").join("sync-cache.json");
    let old = root.join("config").join("sync-cache.json");

    let legacy = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&old, &legacy).unwrap();
    let legacy_bytes = std::fs::read(&old).unwrap();

    // A file left under the old config dir is still readable. Reading it must
    // not copy/move it: a load has no filesystem side effects.
    assert_eq!(load_with_fallback(&new, &old), Ok(legacy.clone()));
    assert!(
        !new.exists(),
        "reading legacy data must not create a new cache"
    );

    // A fresh write goes only to the cache-dir path.
    save(&new, &legacy).unwrap();
    assert!(new.is_file());
    assert_eq!(
        std::fs::read(&old).unwrap(),
        legacy_bytes,
        "the legacy file must remain untouched"
    );

    // Once the new file exists it wins, even if the legacy file now differs.
    let other = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-2".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: body(),
    };
    save(&old, &other).unwrap();
    assert_eq!(load_with_fallback(&new, &old), Ok(legacy));
}

#[test]
fn corrupt_primary_does_not_silently_fall_back_to_legacy() {
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-fallback-error-test");
    let _ = std::fs::remove_dir_all(&root);
    let new = root.join("cache").join("sync-cache.json");
    let old = root.join("config").join("sync-cache.json");

    save(
        &old,
        &SyncCache::from_body(body(), "https://vault.example.com").unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    std::fs::write(&new, b"not json").unwrap();

    assert_eq!(
        load_with_fallback(&new, &old).err(),
        Some(CacheLoadError::ParseFailed)
    );
}

#[test]
fn fallback_returns_not_found_when_both_locations_are_missing() {
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-fallback-missing-test");
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        load_with_fallback(
            root.join("cache/sync-cache.json"),
            root.join("config/sync-cache.json")
        )
        .err(),
        Some(CacheLoadError::NotFound)
    );
}
