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
