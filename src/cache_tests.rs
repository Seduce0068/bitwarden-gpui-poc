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

/// Write a fixture with the same owner-only mode the production writer uses.
/// Raw `std::fs::write` creates group/world-readable files under a typical
/// umask, which the read-side private-file check now refuses.
fn write_fixture(path: &std::path::Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
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
    write_fixture(&path, b"not json");
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
    write_fixture(&broken, b"not json");
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
fn validation_checks_only_what_the_restore_path_can_know() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    assert!(validate(&cache, "user-1", "https://vault.example.com").is_ok());
    // The production restore path runs after a failed sync, so it has no fresh
    // user id. `validate` documents that it cannot reject a different account
    // instead of offering a check that is unreachable in production.
    assert!(validate(&cache, "other", "https://vault.example.com").is_ok());
    assert_eq!(cache.user_id, "user-1");
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
fn debug_masks_url_embedded_credentials_but_keeps_the_host() {
    // A server URL may carry userinfo (`https://user:pass@host`). `Debug` must
    // drop that part while leaving enough host information for diagnostics
    // (cache.rs:68-77). The stored field itself stays verbatim for the
    // byte-for-byte mismatch check, which is documented as a known constraint.
    let url = "https://user:SECRET-PASS@vault.example.com:8443/path?x=1";
    let cache = SyncCache::from_body(body(), url).unwrap();
    assert_eq!(cache.server_url, url, "storage keeps the exact URL");

    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("SECRET-PASS"), "{rendered}");
    assert!(!rendered.contains("user:"), "{rendered}");
    assert!(rendered.contains("vault.example.com:8443"), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
}

#[test]
fn validate_reports_a_parse_failure_and_a_detailed_server_mismatch() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();

    // A cache whose body no longer parses is classified as a parse failure by
    // validate(), not silently accepted because the server matched.
    let mut corrupt = cache.clone();
    corrupt.body = b"not json".to_vec();
    assert!(matches!(
        validate(&corrupt, "user-1", "https://vault.example.com"),
        Err(SyncCacheError::CacheParse(_))
    ));

    // A matching server but a different account stays accepted by design; the
    // mismatch check is strictly about the server URL (cache.rs:449-468).
    assert!(validate(&cache, "other", "https://vault.example.com").is_ok());
    assert_eq!(
        validate(&cache, "user-1", "https://other.example.com"),
        Err(SyncCacheError::ServerMismatch)
    );
    assert_eq!(
        cache_error_message(SyncCacheError::ServerMismatch),
        "キャッシュが別のサーバーのものです"
    );
}

#[test]
fn profile_keys_are_stripped_before_storage() {
    let body = br#"{
        "profile": {
            "id": "user-1",
            "key": "TEST_KEY_PLACEHOLDER",
            "privateKey": "TEST_PRIVATE_KEY_PLACEHOLDER"
        },
        "ciphers": []
    }"#;
    let cache = SyncCache::from_body(body.to_vec(), "https://vault.example.com").unwrap();
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    assert!(!stored.contains("TEST_KEY_PLACEHOLDER"), "{stored}");
    assert!(!stored.contains("TEST_PRIVATE_KEY_PLACEHOLDER"), "{stored}");
    assert!(!stored.contains("privateKey"), "{stored}");
    assert!(!stored.contains("\"key\""), "{stored}");
    assert!(stored.contains("user-1"), "{stored}");
    // A key-less sync body must still be parseable for offline display.
    assert!(cache.sync().is_ok());
}

#[test]
fn pascal_case_profile_keys_are_stripped_before_storage() {
    // A raw body may spell the profile and its key fields in PascalCase,
    // upper case or snake_case. All of them are protected key material and
    // must never reach the on-disk cache, even though `from_body` parses a
    // normalized *copy* of this body for the user id.
    let body = br#"{
        "Profile": {
            "Id": "user-1",
            "Key": "TEST_PASCAL_KEY",
            "PrivateKey": "TEST_PASCAL_PRIVATE_KEY",
            "private_key": "TEST_SNAKE_PRIVATE_KEY",
            "KEY": "TEST_UPPER_KEY",
            "KeyId": "keep-me"
        },
        "Ciphers": []
    }"#;
    let cache = SyncCache::from_body(body.to_vec(), "https://vault.example.com").unwrap();
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    for secret in [
        "TEST_PASCAL_KEY",
        "TEST_PASCAL_PRIVATE_KEY",
        "TEST_SNAKE_PRIVATE_KEY",
        "TEST_UPPER_KEY",
    ] {
        assert!(!stored.contains(secret), "leaked {secret}: {stored}");
    }
    assert!(!stored.contains("\"Key\""), "{stored}");
    assert!(!stored.contains("\"PrivateKey\""), "{stored}");
    // A similarly named but non-secret field must survive the redactor.
    assert!(stored.contains("keep-me"), "{stored}");
    assert!(cache.sync().is_ok());
}

#[test]
fn every_profile_spelling_is_stripped_before_storage() {
    // A crafted body can carry several case variants of `profile`. Redacting
    // only the first one would leave protected keys on disk.
    let body = br#"{
        "PROFILE": { "Id": "user-1" },
        "profile": {
            "Id": "user-1",
            "Key": "SECOND_PROFILE_KEY",
            "PrivateKey": "SECOND_PROFILE_PRIVATE_KEY"
        },
        "Ciphers": []
    }"#;
    let cache = SyncCache::from_body(body.to_vec(), "https://vault.example.com").unwrap();
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    assert!(!stored.contains("SECOND_PROFILE_KEY"), "{stored}");
    assert!(!stored.contains("SECOND_PROFILE_PRIVATE_KEY"), "{stored}");
    assert!(cache.sync().is_ok());
}

#[test]
fn nested_per_item_keys_are_stripped_before_storage() {
    // Per-item keys are just as sensitive as the profile key: leaving one on
    // disk would let an attacker decrypt that item offline. The walk must be
    // recursive over objects and arrays while keeping the JSON shape intact.
    let body = serde_json::json!({
        "profile": {
            "id": "user-1",
            "key": "PROFILE_KEY",
            "privateKey": "PROFILE_PRIVATE_KEY",
            "keyId": "keep-profile-key-id"
        },
        "folders": [
            { "id": "f1", "name": "2.work", "Key": "FOLDER_KEY" }
        ],
        "ciphers": [{
            "id": "c1",
            "type": 1,
            "name": null,
            "revisionDate": "2024-01-01T00:00:00Z",
            "key": "CIPHER_ITEM_KEY",
            "login": {
                "uris": [{ "uri": null, "match": null }],
                "attachments": [{ "id": "a1", "key": "ATTACHMENT_KEY" }],
                "keyId": "keep-login-key-id"
            }
        }],
        "object": "sync"
    });
    let cache = SyncCache::from_body(body.to_string().into_bytes(), "https://vault.example.com")
        .expect("a keyless copy of the body must still be valid sync JSON");
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    for secret in [
        "PROFILE_KEY",
        "PROFILE_PRIVATE_KEY",
        "FOLDER_KEY",
        "CIPHER_ITEM_KEY",
        "ATTACHMENT_KEY",
    ] {
        assert!(!stored.contains(secret), "leaked {secret}: {stored}");
    }
    // Non-secret fields, arrays and object nesting must survive the redactor.
    assert!(stored.contains("keep-profile-key-id"), "{stored}");
    assert!(stored.contains("keep-login-key-id"), "{stored}");
    assert!(stored.contains("\"ciphers\""), "{stored}");
    assert!(stored.contains("\"folders\""), "{stored}");
    assert!(stored.contains("\"attachments\""), "{stored}");
    assert!(stored.contains("\"name\":null"), "{stored}");
    let parsed: serde_json::Value = serde_json::from_slice(&cache.body).unwrap();
    assert_eq!(parsed["ciphers"][0]["id"], "c1");
    assert_eq!(parsed["folders"][0]["id"], "f1");
    assert!(cache.sync().is_ok());
}

#[test]
fn mask_url_userinfo_handles_missing_userinfo_scheme_and_query_at_signs() {
    // No userinfo: unchanged (cache.rs:82-96).
    assert_eq!(
        super::mask_url_userinfo("https://vault.example.com/path"),
        "https://vault.example.com/path"
    );
    // No scheme: the whole prefix before the first `/` is the authority, so
    // an `@` there is still userinfo and must be masked.
    assert_eq!(
        super::mask_url_userinfo("user:SECRET@vault.example.com/path"),
        "[redacted]@vault.example.com/path"
    );
    // An `@` outside the authority (query/fragment) is not userinfo and must
    // not be rewritten: doing so would corrupt the diagnostic URL.
    assert_eq!(
        super::mask_url_userinfo("https://vault.example.com/login?email=a@b.example#f@x"),
        "https://vault.example.com/login?email=a@b.example#f@x"
    );
    // Only the last `@` in a real authority separates userinfo from host.
    assert_eq!(
        super::mask_url_userinfo("https://u:p@host@vault.example.com/x"),
        "https://[redacted]@vault.example.com/x"
    );
}

#[test]
fn restore_status_distinguishes_missing_and_user_mismatch() {
    // A missing cache is the normal first-launch case: no status text.
    assert_eq!(super::cache_restore_status(SyncCacheError::NotFound), None);
    // A cache from another account is an explicit failure with its own text.
    assert_eq!(
        super::cache_restore_status(SyncCacheError::UserMismatch),
        Some("同期に失敗しました（キャッシュが別のアカウントのものです）")
    );
    assert_eq!(REASON_MISSING, "キャッシュがありません");
    assert_eq!(REASON_USER_MISMATCH, "キャッシュが別のアカウントのものです");
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

#[test]
fn cache_errors_are_not_all_reported_as_corruption() {
    use crate::error::BoxedCause;

    let corrupt = cache_error_message(SyncCacheError::CacheParse(BoxedCause::text("bad json")));
    let unreadable =
        cache_error_message(SyncCacheError::ReadFailedCause(BoxedCause::text("denied")));
    let missing = cache_error_message(SyncCacheError::NotFound);
    let outdated = cache_error_message(SyncCacheError::VersionMismatch);
    let other = cache_error_message(SyncCacheError::Other("unrelated".into()));

    assert_eq!(corrupt, "キャッシュが破損しています");
    assert_eq!(unreadable, "キャッシュを読み込めません");
    assert_eq!(missing, "キャッシュがありません");
    assert_eq!(outdated, "キャッシュのバージョンに互換性がありません");
    assert_eq!(other, crate::error::OTHER_ERROR_MESSAGE);
    assert_ne!(unreadable, corrupt);
    assert_ne!(missing, corrupt);
    // An unrelated failure from another layer must never be labelled corruption.
    assert_eq!(
        cache_error_message(SyncCacheError::RandomUnavailable),
        crate::error::OTHER_ERROR_MESSAGE
    );
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
    #[cfg(target_os = "linux")]
    let _lock = ENV_LOCK.lock().unwrap();
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
        created_at: None,
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
    write_fixture(&new, b"not json");

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

// --- Auth-facing restore path (cache is no longer test-only) ---

/// Uses the same process-global env lock as the XDG test above.
#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_restores_only_a_usable_cache_for_this_server() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-restore-test");
    let _ = std::fs::remove_dir_all(&root);
    let cache_home = root.join("xdg-cache-home");
    let config_home = root.join("xdg-config-home");
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &cache_home);
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &config_home);

    // No file: restore is a silent no-op so auth reports the sync failure.
    assert!(cached_sync_for("https://vault.example.com").is_none());

    save_default(&SyncCache::from_body(body(), "https://vault.example.com").unwrap()).unwrap();
    let restored = cached_sync_for("https://vault.example.com").expect("cache should restore");
    assert_eq!(restored.user_id(), "user-1");

    // A cache from another server must never be restored.
    assert!(cached_sync_for("https://other.example.com").is_none());

    // A corrupted cache is ignored just like a missing one.
    let path = default_path().expect("cache path");
    write_fixture(&path, b"not json");
    assert!(cached_sync_for("https://vault.example.com").is_none());
}

#[test]
fn cache_expiry_uses_a_fixed_window_and_keeps_legacy_files() {
    let now = 1_800_000_000_i64;
    assert!(!is_cache_expired(None, now), "legacy caches stay usable");
    assert!(!is_cache_expired(Some(now), now));
    assert!(!is_cache_expired(Some(now - MAX_CACHE_AGE_SECS), now));
    assert!(is_cache_expired(Some(now - MAX_CACHE_AGE_SECS - 1), now));
    // A capture time in the future cannot be trusted and is expired, not
    // treated as an infinitely fresh cache.
    assert!(is_cache_expired(Some(now + 100), now));
    assert_eq!(
        cache_error_message(SyncCacheError::CacheExpired),
        REASON_EXPIRED
    );
}

#[test]
fn future_and_sentinel_capture_times_are_expired() {
    let now = 1_800_000_000_i64;
    assert!(is_cache_expired(Some(now + 1), now));
    assert!(is_cache_expired(Some(i64::MAX), now));
    // The sentinel stays expired even if the reader's clock is equally broken.
    assert!(is_cache_expired(Some(i64::MAX), i64::MAX));
    assert!(!is_cache_expired(Some(now - 1), now));
    assert!(!is_cache_expired(None, i64::MAX));
}

#[test]
fn legacy_json_without_created_at_stays_restorable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    let legacy = serde_json::json!({
        "version": SyncCache::VERSION,
        "user_id": "user-1",
        "server_url": "https://vault.example.com",
        "body": body(),
    });
    write_fixture(&path, &serde_json::to_vec(&legacy).unwrap());

    let loaded = load_detailed(&path).unwrap();
    assert_eq!(loaded.created_at, None);
    assert!(!is_cache_expired(loaded.created_at, 1_800_000_000));
}

#[test]
fn expired_cache_survives_serde_roundtrip_as_expired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    let now = i64::try_from(crate::totp::now_unix()).unwrap();
    let stale = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: body(),
        created_at: Some(now - MAX_CACHE_AGE_SECS - 1),
    };
    save(&path, &stale).unwrap();

    let loaded = load_detailed(&path).unwrap();
    assert!(is_cache_expired(loaded.created_at, now));
}

#[test]
fn oversized_cache_is_rejected_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    std::fs::write(&path, vec![b'x'; (MAX_CACHE_BYTES + 1) as usize]).unwrap();
    assert_eq!(load_detailed(&path), Err(CacheLoadError::CacheTooLarge));
    assert_eq!(
        cache_error_message(CacheLoadError::CacheTooLarge),
        REASON_TOO_LARGE
    );
}

#[test]
fn load_default_resolves_all_four_location_combinations() {
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-load-default-branches");
    let _ = std::fs::remove_dir_all(&root);
    let primary = root.join("primary.json");
    let fallback = root.join("fallback.json");
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();

    // (None, None): no platform directory at all.
    assert_eq!(
        super::load_from_paths(None, None).err(),
        Some(CacheLoadError::NotFound)
    );

    // (Some, None): primary only; missing and then present.
    assert_eq!(
        super::load_from_paths(Some(primary.clone()), None).err(),
        Some(CacheLoadError::NotFound)
    );
    save(&primary, &cache).unwrap();
    assert_eq!(
        super::load_from_paths(Some(primary.clone()), None),
        Ok(cache.clone())
    );

    // (None, Some): read-only legacy path only; missing and then present.
    assert_eq!(
        super::load_from_paths(None, Some(fallback.clone())).err(),
        Some(CacheLoadError::NotFound)
    );
    save(&fallback, &cache).unwrap();
    assert_eq!(
        super::load_from_paths(None, Some(fallback.clone())),
        Ok(cache.clone())
    );

    // (Some, Some): primary wins when both exist.
    let mut different = cache.clone();
    different.server_url = "https://other.example.com".to_string();
    save(&fallback, &different).unwrap();
    assert_eq!(
        super::load_from_paths(Some(primary.clone()), Some(fallback.clone())),
        Ok(cache.clone())
    );

    // (Some, Some): the fallback is used only when the primary is absent.
    let missing = root.join("missing.json");
    assert_eq!(
        super::load_from_paths(Some(missing), Some(fallback)),
        Ok(different)
    );
}

#[test]
fn from_body_stamps_a_finite_capture_time() {
    let before = i64::try_from(crate::totp::now_unix()).unwrap();
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let after = i64::try_from(crate::totp::now_unix()).unwrap();

    let created = cache
        .created_at
        .expect("from_body must stamp a capture time");
    assert!(created >= before && created <= after, "{created}");
    assert_ne!(
        created,
        i64::MAX,
        "a working clock must not hit the sentinel"
    );
    assert!(!is_cache_expired(cache.created_at, after));
}

#[test]
fn from_body_rejects_an_oversized_raw_body() {
    let oversized = vec![b'x'; MAX_CACHE_BODY_BYTES + 1];
    assert_eq!(
        SyncCache::from_body(oversized, "https://vault.example.com"),
        Err(SyncCacheError::CacheTooLarge)
    );
    let at_limit = vec![b' '; MAX_CACHE_BODY_BYTES];
    // The limit itself must pass the size gate; parsing may still fail.
    let at_limit_result = SyncCache::from_body(at_limit, "https://vault.example.com");
    assert!(
        at_limit_result.is_err(),
        "invalid JSON at the boundary must fail"
    );
    assert!(
        !matches!(at_limit_result, Err(SyncCacheError::CacheTooLarge)),
        "the size gate must be inclusive at MAX_CACHE_BODY_BYTES"
    );
}

#[test]
fn every_corrupt_group_error_maps_to_the_corrupt_reason() {
    use crate::error::BoxedCause;
    for error in [
        SyncCacheError::InvalidCache,
        SyncCacheError::CacheParse(BoxedCause::text("bad json")),
        SyncCacheError::CacheRedact(BoxedCause::text("bad json")),
        SyncCacheError::CacheSerialize(BoxedCause::text("write failed")),
        SyncCacheError::ParseFailed,
        SyncCacheError::ParseFailedCause(BoxedCause::text("bad json")),
    ] {
        assert_eq!(cache_error_message(error), REASON_CORRUPT);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn expired_cache_is_rejected_by_the_restore_path() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-expired-restore-test");
    let _ = std::fs::remove_dir_all(&root);
    let cache_home = root.join("xdg-cache-home");
    let config_home = root.join("xdg-config-home");
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &cache_home);
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &config_home);

    let stale = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: body(),
        created_at: Some(1),
    };
    save_default(&stale).unwrap();
    assert_eq!(
        cached_sync_for_detailed("https://vault.example.com").err(),
        Some(SyncCacheError::CacheExpired)
    );
    assert!(cached_sync_for("https://vault.example.com").is_none());
}

#[test]
fn oversized_cache_body_is_rejected_after_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: vec![b'x'; MAX_CACHE_BODY_BYTES + 1],
        created_at: None,
    };
    save(&path, &cache).unwrap();
    assert_eq!(load_detailed(&path), Err(CacheLoadError::CacheTooLarge));
}

#[cfg(unix)]
#[test]
fn group_or_world_access_is_refused_on_read() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&path, &cache).unwrap();

    // Any group/other read or write bit violates the private_file policy,
    // including a group-write-only mode that has no read bit.
    for mode in [0o644u32, 0o660, 0o606, 0o620] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = load_detailed(&path).unwrap_err();
        assert!(
            matches!(&error, CacheLoadError::ReadFailedCause(_)),
            "mode {mode:04o} must be refused: {error:?}"
        );
        assert_eq!(cache_error_message(error), REASON_UNREADABLE);
        assert!(load(&path).is_none());
    }

    // Owner-only modes still load.
    for mode in [0o600u32, 0o700] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(load_detailed(&path).unwrap(), cache, "mode {mode:04o}");
    }
}

#[test]
fn oversized_world_readable_file_keeps_its_size_classification() {
    // The size gate runs before the permission gate, so callers still get the
    // specific "too large" reason rather than a generic unreadable status.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    std::fs::write(&path, vec![b'x'; (MAX_CACHE_BYTES + 1) as usize]).unwrap();
    assert_eq!(load_detailed(&path), Err(CacheLoadError::CacheTooLarge));
}

#[test]
fn unreadable_or_outdated_primary_never_falls_back_to_legacy() {
    // The fallback is only for a *missing* primary file (the cache-directory
    // migration). A primary that exists but cannot be trusted must report its
    // own failure, otherwise a broken cache-dir file could silently revive
    // stale legacy data. See `load_with_fallback` in cache.rs:216-236.
    let root = std::env::temp_dir().join("bitwarden-gpui-poc-fallback-strict-test");
    let _ = std::fs::remove_dir_all(&root);
    let new = root.join("cache").join("sync-cache.json");
    let old = root.join("config").join("sync-cache.json");
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    let legacy = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&old, &legacy).unwrap();
    let legacy_bytes = std::fs::read(&old).unwrap();

    // An outdated (version-mismatched) primary is an error, not a reason to
    // read the legacy file.
    let mut outdated = legacy.clone();
    outdated.version += 1;
    save(&new, &outdated).unwrap();
    assert_eq!(
        load_with_fallback(&new, &old).err(),
        Some(CacheLoadError::VersionMismatch)
    );

    // The legacy file was not touched by either failed load.
    assert_eq!(std::fs::read(&old).unwrap(), legacy_bytes);
    assert_eq!(load_detailed(&old).unwrap(), legacy);
}

#[cfg(unix)]
#[test]
fn unreadable_primary_is_not_replaced_by_the_legacy_fallback() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join("bitwarden-gpui-poc-fallback-permission-test");
    let _ = std::fs::remove_dir_all(&root);
    let new = root.join("cache").join("sync-cache.json");
    let old = root.join("config").join("sync-cache.json");
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    let legacy = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&old, &legacy).unwrap();
    save(&new, &legacy).unwrap();

    // Group/world permissions make the primary unreadable under the
    // private-file policy, but the legacy file stays valid.
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = load_with_fallback(&new, &old).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::ReadFailedCause(_)),
        "unreadable primary must be reported as-is: {error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);
    assert_eq!(load_detailed(&old).unwrap(), legacy);
}

#[test]
fn secret_profile_keys_ignore_hyphen_and_underscore_separators() {
    // `is_secret_profile_key` folds every separator away before comparing, so
    // a body that spells the fields with hyphens or mixed case cannot smuggle
    // key material onto disk. See cache.rs:143-158.
    for key in [
        "key",
        "Key",
        "KEY",
        "privateKey",
        "private_key",
        "private-key",
        "PRIVATE-KEY",
        "Private-Key",
        "private--key",
        "-key-",
    ] {
        assert!(super::is_secret_profile_key(key), "must be redacted: {key}");
    }
    // Similarly named but non-secret fields must stay searchable/importable.
    for key in [
        "keyId",
        "privateKeyValue",
        "key-id-extra",
        "monkey",
        "id",
        "",
    ] {
        assert!(
            !super::is_secret_profile_key(key),
            "must not be redacted: {key}"
        );
    }
}
