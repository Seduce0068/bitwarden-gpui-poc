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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn cache_round_trips_through_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync-cache.json");
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();

    save(&path, &cache).unwrap();
    let loaded = load(&path).expect("cache should load");
    assert_eq!(loaded, cache);
    assert_eq!(loaded.user_id, "user-1");
    assert!(loaded.sync().is_ok());
}

#[test]
fn missing_and_broken_files_return_none() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-cache.json");
    assert!(load(&missing).is_none());

    let path = dir.path().join("broken-cache.json");
    write_fixture(&path, b"not json");
    assert!(load(&path).is_none());
}

#[::core::prelude::v1::test]
fn load_detailed_distinguishes_failure_modes() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("detailed-missing.json");
    // `AppError`'s PartialEq compares rendered messages, so an `assert_eq!`
    // could pass for a different variant with the same message. Pin the exact
    // variant with `matches!` for every failure mode.
    assert!(matches!(
        load_detailed(&missing).err(),
        Some(CacheLoadError::NotFound)
    ));

    let broken = dir.path().join("detailed-broken.json");
    write_fixture(&broken, b"not json");
    assert!(matches!(
        load_detailed(&broken).err(),
        Some(CacheLoadError::ParseFailedCause(_))
    ));

    // Reading a directory as a file fails (EISDIR on Unix).
    let directory = dir.path().join("detailed-dir");
    std::fs::create_dir_all(&directory).unwrap();
    assert!(matches!(
        load_detailed(&directory).err(),
        Some(CacheLoadError::ReadFailedCause(_))
    ));

    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    cache.version += 1;
    let outdated = dir.path().join("detailed-old.json");
    save(&outdated, &cache).unwrap();
    assert!(matches!(
        load_detailed(&outdated).err(),
        Some(CacheLoadError::VersionMismatch)
    ));

    for error in [
        CacheLoadError::NotFound,
        CacheLoadError::ReadFailed,
        CacheLoadError::ParseFailed,
        CacheLoadError::VersionMismatch,
    ] {
        assert!(!error.message().is_empty());
    }
}

#[cfg(unix)]
#[test]
fn file_open_non_not_found_error_is_classified_as_read_failed_cause() {
    // `File::open` maps only `NotFound` to the silent missing case; every other
    // `io::ErrorKind` becomes `ReadFailedCause` (cache.rs:627-633). Opening a
    // directory succeeds on Unix and only fails at `read`, so the sibling test
    // above does not exercise this arm. A regular file used as a directory
    // component makes `open(2)` fail with ENOTDIR: the path exists but cannot be
    // opened, which is distinct from ENOENT/NotFound.
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let path = blocker.join("sync-cache.json");

    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::ReadFailedCause(_)),
        "a path component that is a file must be unreadable, not missing: {error:?}"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the io error must stay reachable as the typed cause"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);

    // The NotFound sibling still takes the other arm of the same match.
    let missing = dir.path().join("no-such-cache.json");
    assert!(matches!(
        load_detailed(missing).err(),
        Some(CacheLoadError::NotFound)
    ));
}

#[test]
fn wrong_version_is_rejected() {
    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    cache.version += 1;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("version-cache.json");
    save(&path, &cache).unwrap();
    assert!(load(&path).is_none());
}

#[test]
fn validation_checks_the_server_and_the_account() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    assert!(validate(&cache, "user-1", "https://vault.example.com").is_ok());
    // The account id comes from the personal API key's `client_id`, so both
    // this helper and the restore path reject another account's cache.
    assert_eq!(
        validate(&cache, "other", "https://vault.example.com"),
        Err(SyncCacheError::UserMismatch)
    );
    assert_eq!(cache.user_id, "user-1");
    assert_eq!(
        validate(&cache, "user-1", "https://other.example.com"),
        Err(SyncCacheError::ServerMismatch)
    );
    // The server check wins when both values differ.
    assert_eq!(
        validate(&cache, "other", "https://other.example.com"),
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
    // (cache.rs:371-381). The stored field itself stays verbatim for the
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

    // A matching server but a different account is rejected by the account
    // check that shares the restore path's policy.
    assert_eq!(
        validate(&cache, "other", "https://vault.example.com"),
        Err(SyncCacheError::UserMismatch)
    );
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
    // No userinfo: unchanged (cache.rs:94-119).
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
fn sensitive_param_keys_cover_pass_pwd_pw_and_credential() {
    // A bare `pass`/`pwd`/`pw`/`credential` key is just as secret as
    // `password`/`api_key`; the case-insensitive substring match must catch
    // them and the common camel/upper-case spellings (cache.rs:218-237).
    for key in [
        "pass",
        "pwd",
        "pw",
        "credential",
        "PassWord",
        "passphrase",
        "x-pwd",
        "apiCredential",
        "CREDENTIALS",
        "pW",
    ] {
        assert!(super::is_sensitive_param_key(key), "must be masked: {key}");
    }
    for key in ["state", "redirect", "nonce", "scope"] {
        assert!(
            !super::is_sensitive_param_key(key),
            "harmless key must stay: {key}"
        );
    }

    let url = "https://vault.example.com/sync?pass=P1&pwd=P2&pw=P3&credential=P4&state=ok";
    let masked = super::mask_url_secrets(url);
    for secret in ["P1", "P2", "P3", "P4"] {
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
    }
    for key in ["pass", "pwd", "pw", "credential"] {
        assert!(
            masked.contains(&format!("{key}=[redacted]")),
            "{key} not masked: {masked}"
        );
    }
    assert!(masked.contains("state=ok"), "{masked}");
}

#[test]
fn userinfo_is_masked_when_the_authority_contains_question_or_hash() {
    // A '?' or '#' before the '@' is part of an unescaped userinfo value, not a
    // query/fragment delimiter. Stopping the authority scan there used to hide
    // the '@' and leave the credential in the diagnostic URL (cache.rs:94-150).
    for (url, expected) in [
        (
            "https://user:p?ss@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
        ),
        (
            "https://user:p#ss@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
        ),
        (
            "https://user:p?ss@vault.example.com:8443",
            "https://[redacted]@vault.example.com:8443",
        ),
        (
            "user:p?ss@vault.example.com/x",
            "[redacted]@vault.example.com/x",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains("p?ss"), "{rendered}");
        assert!(!rendered.contains("p#ss"), "{rendered}");
        assert!(
            rendered.contains("[redacted]@vault.example.com"),
            "{rendered}"
        );
    }

    // An '@' that really belongs to a query stays untouched: the `key=`
    // parameter before it marks the '?' as a genuine delimiter.
    let query = "https://vault.example.com?email=a@b.example";
    assert_eq!(super::mask_url_userinfo(query), query);
}

#[test]
fn userinfo_separator_is_found_even_with_query_at_signs_and_unescaped_delimiters() {
    // The separator is the last '@' of the authority, not the last '@' of the
    // pre-path text (cache.rs:94-150). A password may itself hold `?`/`#`/`=`
    // or an '@', and a query after the host may hold another '@'.
    for (url, expected) in [
        // No path: the query '@' must not be mistaken for the separator.
        (
            "https://user:pass@host?email=a@b",
            "https://[redacted]@host?email=a@b",
        ),
        // An unescaped '?' (even with a `key=`-shaped value) inside the
        // password is not a query delimiter.
        ("https://user:pass?x=1@host", "https://[redacted]@host"),
        // The same holds for '#', including a fragment after the real path.
        (
            "https://user:pa#ss=w@host/path#f=x",
            "https://[redacted]@host/path#f=x",
        ),
        // Multiple '@'s in userinfo: the last one before the host separates.
        (
            "https://u:p@ss@host/path?email=a@b",
            "https://[redacted]@host/path?email=a@b",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
    }

    // A bare host (no userinfo marker) followed by a query/fragment '@' stays
    // untouched, including the pre-existing `?email=` regression case and a
    // numeric port (which is not a userinfo password).
    for url in [
        "https://host?email=a@b",
        "https://host:8443?email=a@b",
        "https://host#frag@x",
    ] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[test]
fn debug_masks_userinfo_when_a_query_at_sign_is_present() {
    // The search starts at the first separator in the authority, so a query
    // '@' cannot hide a credential from the top-level `Debug` masker either.
    let url = "https://user:SECRET@host?email=a@b";
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(rendered.contains("[redacted]@host?email=a@b"), "{rendered}");
    // The stored URL remains byte-for-byte identical for the mismatch check.
    assert_eq!(cache.server_url, url);
}

#[test]
fn debug_masks_secret_query_values_but_keeps_harmless_parameters() {
    let url = "https://vault.example.com/sync?token=TOPSECRET&state=abc&api_key=KEY123#frag";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("TOPSECRET"), "{masked}");
    assert!(!masked.contains("KEY123"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");
    assert!(masked.contains("api_key=[redacted]"), "{masked}");
    assert!(masked.contains("state=abc"), "{masked}");
    assert!(masked.ends_with("#frag"), "{masked}");

    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("TOPSECRET"), "{rendered}");
    assert!(!rendered.contains("KEY123"), "{rendered}");
    // The stored URL is still the exact value used for the mismatch check.
    assert_eq!(cache.server_url, url);
}

#[test]
fn every_sensitive_query_key_is_masked_including_uppercase_spellings() {
    // The audit contract requires secret/password/passwd/auth/sig/session/code
    // in addition to the original token/key entries (cache.rs:218-237).
    for key in [
        "secret", "password", "passwd", "auth", "sig", "session", "code", "token", "key",
    ] {
        let value = format!("SENSITIVE-{key}-VALUE");
        let url = format!("https://vault.example.com/sync?{key}={value}&state=ok");
        let masked = super::mask_url_secrets(&url);
        assert!(!masked.contains(&value), "{masked}");
        assert!(masked.contains(&format!("{key}=[redacted]")), "{masked}");
        assert!(masked.contains("state=ok"), "{masked}");

        let upper_key = key.to_ascii_uppercase();
        let upper_url = format!("https://vault.example.com/sync?{upper_key}={value}");
        let upper_masked = super::mask_url_secrets(&upper_url);
        assert!(!upper_masked.contains(&value), "{upper_masked}");
    }
}

#[test]
fn fragment_values_are_masked_like_query_values() {
    let url = "https://vault.example.com/cb#access_token=FRAGMENT_SECRET&state=ok";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("FRAGMENT_SECRET"), "{masked}");
    assert!(masked.contains("access_token=[redacted]"), "{masked}");
    assert!(masked.contains("state=ok"), "{masked}");
    assert!(masked.contains('#'), "{masked}");

    // The same URL reaches Debug through `SyncCache`, and the stored value
    // remains byte-for-byte identical for the server-mismatch check.
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("FRAGMENT_SECRET"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn nested_url_values_are_masked_recursively() {
    let url = "https://vault.example.com/login?redirect=https://cb.example.com/done?token=NESTED_SECRET&state=ok";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("NESTED_SECRET"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");
    assert!(
        masked.contains("redirect=https://cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // A nested fragment value is masked as well.
    let with_fragment =
        "https://vault.example.com/login?next=https://cb.example.com/done#code=NESTED_CODE";
    let masked = super::mask_url_secrets(with_fragment);
    assert!(!masked.contains("NESTED_CODE"), "{masked}");
    assert!(masked.contains("code=[redacted]"), "{masked}");
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
fn cache_restore_status_covers_all_nine_branches_table_driven() {
    use crate::error::BoxedCause;

    // `cache_restore_status` (cache.rs:820-832) has one arm per reason plus
    // the missing-cache arm and the catch-all. A table pins all nine so a
    // future variant cannot silently inherit the generic message.
    const GENERIC: &str = "同期に失敗しました（キャッシュを復元できませんでした）";
    let cases: Vec<(CacheLoadError, Option<&str>, &str)> = vec![
        (SyncCacheError::NotFound, None, "missing"),
        (
            SyncCacheError::CacheParse(BoxedCause::text("bad json")),
            Some("同期に失敗しました（キャッシュが破損しています）"),
            "corrupt",
        ),
        (
            SyncCacheError::ReadFailedCause(BoxedCause::text("denied")),
            Some("同期に失敗しました（キャッシュを読み込めません）"),
            "unreadable",
        ),
        (
            SyncCacheError::VersionMismatch,
            Some("同期に失敗しました（キャッシュのバージョンに互換性がありません）"),
            "outdated",
        ),
        (
            SyncCacheError::CacheExpired,
            Some("同期に失敗しました（キャッシュが有効期限を過ぎています）"),
            "expired",
        ),
        (
            SyncCacheError::UserMismatch,
            Some("同期に失敗しました（キャッシュが別のアカウントのものです）"),
            "user_mismatch",
        ),
        (
            SyncCacheError::ServerMismatch,
            Some("同期に失敗しました（キャッシュが別のサーバーのものです）"),
            "server_mismatch",
        ),
        (
            SyncCacheError::CacheTooLarge,
            Some("同期に失敗しました（キャッシュがサイズ上限を超えています）"),
            "too_large",
        ),
        (
            SyncCacheError::Other("unrelated".into()),
            Some(GENERIC),
            "fallback",
        ),
    ];
    assert_eq!(cases.len(), 9);
    for (error, expected, name) in cases {
        assert_eq!(super::cache_restore_status(error), expected, "{name}");
    }
}

#[test]
fn bounded_read_rechecks_the_size_after_metadata() {
    // `load_detailed` checks `metadata.len()` first, then re-checks while
    // reading (cache.rs:637-658). The helper is generic so the guard can be
    // exercised with a small limit instead of a 64 MiB fixture: a file that
    // grew by one byte is still rejected, and the reader is capped at
    // limit + 1 bytes so no unbounded body is loaded.
    let mut at_limit = std::io::Cursor::new(vec![b'x'; 8]);
    assert_eq!(super::read_bounded(&mut at_limit, 8).unwrap().len(), 8);

    let mut one_too_many = std::io::Cursor::new(vec![b'x'; 9]);
    assert_eq!(
        super::read_bounded(&mut one_too_many, 8),
        Err(CacheLoadError::CacheTooLarge)
    );

    let mut much_too_many = std::io::Cursor::new(vec![b'x'; 1_000]);
    assert_eq!(
        super::read_bounded(&mut much_too_many, 8),
        Err(CacheLoadError::CacheTooLarge)
    );
}

#[test]
fn bounded_read_reports_a_failing_reader_as_read_failed_cause() {
    use std::io::{self, Read};

    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "simulated read failure",
            ))
        }
    }

    let error = super::read_bounded(&mut FailingReader, 8).unwrap_err();
    assert!(
        matches!(error, CacheLoadError::ReadFailedCause(_)),
        "{error:?}"
    );
    let source = std::error::Error::source(&error).map(ToString::to_string);
    assert_eq!(
        source.as_deref(),
        Some("simulated read failure"),
        "{error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);
}

#[test]
fn invalid_body_is_rejected() {
    // from_body returns the cause-carrying `CacheParse` variant, not the
    // generic `InvalidCache` marker. PartialEq compares only message/detail,
    // so an assert_eq! against InvalidCache passed without proving the type.
    let error = SyncCache::from_body(b"not json".to_vec(), "https://vault.example.com")
        .expect_err("invalid JSON must be rejected");
    assert!(matches!(error, SyncCacheError::CacheParse(_)), "{error:?}");
}

#[test]
fn error_messages_are_present() {
    assert!(!cache_error_message(SyncCacheError::InvalidCache).is_empty());
    assert!(!cache_error_message(SyncCacheError::UserMismatch).is_empty());
    assert!(!cache_error_message(SyncCacheError::ServerMismatch).is_empty());
}

#[test]
fn plain_read_failure_uses_the_unreadable_reason() {
    // The cause-carrying sibling is covered by the bounded-read test; the
    // plain `ReadFailed` arm (cache.rs:846) must map to the same reason so a
    // caller that drops the cause still sees "unreadable", not "corrupt".
    assert_eq!(
        cache_error_message(SyncCacheError::ReadFailed),
        REASON_UNREADABLE
    );
    assert_ne!(
        cache_error_message(SyncCacheError::ReadFailed),
        cache_error_message(SyncCacheError::ParseFailed)
    );
    assert_eq!(
        super::cache_restore_status(SyncCacheError::ReadFailed),
        Some("同期に失敗しました（キャッシュを読み込めません）")
    );
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
    let root = tempfile::tempdir().unwrap();
    let xdg = root.path().join("xdg-cache-home");
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
    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("cache").join("sync-cache.json");
    let old = root.path().join("config").join("sync-cache.json");

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
    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("cache").join("sync-cache.json");
    let old = root.path().join("config").join("sync-cache.json");

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
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        load_with_fallback(
            root.path().join("cache/sync-cache.json"),
            root.path().join("config/sync-cache.json")
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
    let root = tempfile::tempdir().unwrap();
    let cache_home = root.path().join("xdg-cache-home");
    let config_home = root.path().join("xdg-config-home");
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &cache_home);
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &config_home);

    // No file: restore is a silent no-op so auth reports the sync failure.
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());

    save_default(&SyncCache::from_body(body(), "https://vault.example.com").unwrap()).unwrap();
    let restored =
        cached_sync_for("https://vault.example.com", "user-1").expect("cache should restore");
    assert_eq!(restored.user_id(), "user-1");

    // A cache from another server must never be restored.
    assert!(cached_sync_for("https://other.example.com", "user-1").is_none());

    // A corrupted cache is ignored just like a missing one.
    let path = default_path().expect("cache path");
    write_fixture(&path, b"not json");
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
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
fn cache_expiry_upper_saturating_sub_clamp_is_expired() {
    // cache.rs:441-447: `now.saturating_sub(captured)` overflows i64 when now
    // is i64::MAX and the capture time is i64::MIN, so it saturates at
    // i64::MAX. A wrapping subtraction would produce -1 and wrongly report a
    // freshly captured cache. Guard the premise, then pin the verdict.
    assert_eq!(i64::MAX.checked_sub(i64::MIN), None);
    assert!(is_cache_expired(Some(i64::MIN), i64::MAX));
    // Just below the overflow boundary the ordinary subtraction still runs.
    assert!(!is_cache_expired(Some(i64::MAX - 1), i64::MAX));
    assert!(is_cache_expired(
        Some(i64::MAX - MAX_CACHE_AGE_SECS - 1),
        i64::MAX
    ));
    // The *lower* saturation (captured > now) is intercepted by the explicit
    // future-time guard at cache.rs:445 rather than by the subtraction.
    assert!(is_cache_expired(Some(i64::MAX), i64::MIN));
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
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));
    assert_eq!(
        cache_error_message(CacheLoadError::CacheTooLarge),
        REASON_TOO_LARGE
    );
}

#[test]
fn load_default_resolves_all_four_location_combinations() {
    let root = tempfile::tempdir().unwrap();
    let primary = root.path().join("primary.json");
    let fallback = root.path().join("fallback.json");
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
    let missing = root.path().join("missing.json");
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
    let root = tempfile::tempdir().unwrap();
    let cache_home = root.path().join("xdg-cache-home");
    let config_home = root.path().join("xdg-config-home");
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
        cached_sync_for_detailed("https://vault.example.com", "user-1").err(),
        Some(SyncCacheError::CacheExpired)
    );
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
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
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));
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
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));
}

#[test]
fn unreadable_or_outdated_primary_never_falls_back_to_legacy() {
    // The fallback is only for a *missing* primary file (the cache-directory
    // migration). A primary that exists but cannot be trusted must report its
    // own failure, otherwise a broken cache-dir file could silently revive
    // stale legacy data. See `load_with_fallback` in cache.rs:546-555.
    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("cache").join("sync-cache.json");
    let old = root.path().join("config").join("sync-cache.json");
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

    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("cache").join("sync-cache.json");
    let old = root.path().join("config").join("sync-cache.json");
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
    // key material onto disk. See cache.rs:459-466.
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

#[test]
fn fragment_with_a_late_question_mark_is_masked() {
    // A `?` inside a fragment is not a query delimiter. The old code looked
    // for `?` first and copied everything before it verbatim, leaking the
    // fragment's credentials (cache.rs:344-369).
    let url = "https://vault.example.com/cb#access_token=FRAGMENT_SECRET&next=1?x=2";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("FRAGMENT_SECRET"), "{masked}");
    assert!(masked.contains("access_token=[redacted]"), "{masked}");
    assert!(masked.contains('#'), "{masked}");
    assert!(
        masked.ends_with("access_token=[redacted]&next=1?x=2"),
        "{masked}"
    );

    // A late `?` inside a fragment pair makes that pair's key contain
    // `?token`; the substring match still recognizes the credential.
    let with_queryish_key = "https://vault.example.com/cb#frag?token=QUERY_IN_FRAGMENT";
    let masked = super::mask_url_secrets(with_queryish_key);
    assert!(!masked.contains("QUERY_IN_FRAGMENT"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");

    // A URL with both sections in the canonical order is still handled.
    let both = "https://vault.example.com/cb?token=QUERY_SECRET#code=FRAGMENT_SECRET";
    let masked = super::mask_url_secrets(both);
    assert!(!masked.contains("QUERY_SECRET"), "{masked}");
    assert!(!masked.contains("FRAGMENT_SECRET"), "{masked}");
    assert!(
        masked.contains("token=[redacted]#code=[redacted]"),
        "{masked}"
    );
}

#[test]
fn percent_encoded_nested_urls_are_decoded_and_masked() {
    // An encoded `?`/`#` cannot hide a nested URL's credentials from the
    // recursive masker.
    let encoded_query = "https://vault.example.com/login?next=https%3A%2F%2Fcb.example.com%2Fdone%3Ftoken%3DNESTED_SECRET&state=ok";
    let masked = super::mask_url_secrets(encoded_query);
    assert!(!masked.contains("NESTED_SECRET"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");
    assert!(masked.contains("state=ok"), "{masked}");

    let encoded_fragment =
        "https://vault.example.com/cb#next=https%3A%2F%2Fcb.example.com%2Fdone%23code%3DFRAG_SECRET";
    let masked = super::mask_url_secrets(encoded_fragment);
    assert!(!masked.contains("FRAG_SECRET"), "{masked}");
    assert!(masked.contains("code=[redacted]"), "{masked}");

    // A literal scheme plus an encoded delimiter must be decoded too.
    let mixed = "https://vault.example.com/login?redirect=https://cb.example.com/done%3Ftoken%3DMIXED_SECRET";
    let masked = super::mask_url_secrets(mixed);
    assert!(!masked.contains("MIXED_SECRET"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");

    // Malformed escapes and harmless encoded values are left verbatim.
    let literal = "https://vault.example.com/p?state=abc%zz&next=%2Fdone";
    assert_eq!(super::mask_url_secrets(literal), literal);
    assert_eq!(super::percent_decode("%3F%23%3a%2F%2F"), "?#://");
    assert_eq!(super::percent_decode("%E3%81%82"), "%E3%81%82");
}

#[test]
fn percent_encoded_keys_are_matched_after_decoding() {
    // A key can hide a sensitive name behind escapes. `is_sensitive_param_key`
    // is fed the decoded form (cache.rs:303-304), but the diagnostic keeps the
    // original spelling so the URL stays traceable.
    for (encoded, secret) in [
        ("%74oken", "ENCODED_TOKEN_SECRET"),
        ("%61pi%5Fkey", "ENCODED_KEY_SECRET"),
        ("%73ession%5Fid", "ENCODED_SESSION_SECRET"),
    ] {
        let url = format!("https://vault.example.com/sync?{encoded}={secret}&state=ok");
        let masked = super::mask_url_secrets(&url);
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
        assert!(
            masked.contains(&format!("{encoded}=[redacted]")),
            "{masked}"
        );
        assert!(masked.contains("state=ok"), "{masked}");
    }
}

#[test]
fn double_encoded_nested_urls_are_decoded_twice_before_masking() {
    // `%253F` decodes to `%3F` and only a second pass yields `?`. Without the
    // second pass the nested `?token=...` would be copied verbatim.
    let query = "https://vault.example.com/login?next=https%3A%2F%2Fcb.example.com%2Fdone%253Ftoken%253DDOUBLE_SECRET&state=ok";
    let masked = super::mask_url_secrets(query);
    assert!(!masked.contains("DOUBLE_SECRET"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");
    assert!(masked.contains("state=ok"), "{masked}");

    // The same applies to a doubly encoded fragment delimiter (`%2523`).
    let fragment =
        "https://vault.example.com/cb#next=https%3A%2F%2Fcb.example.com%2Fdone%2523code%253DDOUBLE_FRAGMENT";
    let masked = super::mask_url_secrets(fragment);
    assert!(!masked.contains("DOUBLE_FRAGMENT"), "{masked}");
    assert!(masked.contains("code=[redacted]"), "{masked}");

    // A doubly encoded but harmless value is not a nested URL: the pair must
    // remain verbatim rather than being rewritten by the extra decode pass.
    let harmless = "https://vault.example.com/p?state=%252Fdone";
    assert_eq!(super::mask_url_secrets(harmless), harmless);
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_reports_a_direct_server_mismatch() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    save_default(&SyncCache::from_body(body(), "https://vault.example.com").unwrap()).unwrap();
    assert!(cached_sync_for_detailed("https://vault.example.com", "user-1").is_ok());
    // The detailed entry point keeps the classified reason rather than
    // collapsing it into `None` like the best-effort wrapper does.
    assert!(matches!(
        cached_sync_for_detailed("https://other.example.com", "user-1"),
        Err(SyncCacheError::ServerMismatch)
    ));
    assert!(cached_sync_for("https://other.example.com", "user-1").is_none());
}

#[test]
fn sensitive_param_keys_match_camel_case_and_partial_names() {
    // The match is a case-insensitive substring, so casing and word
    // separators cannot be used to smuggle a credential past the masker.
    for key in [
        "accessToken",
        "token",
        "api_key",
        "session_id",
        "X-Session-ID",
        "oauth_code",
        "x-api-key",
        "Sig",
        "AuthToken",
    ] {
        assert!(super::is_sensitive_param_key(key), "must be masked: {key}");
    }
    for key in ["state", "redirect", "nonce", "scope", "expires", "locale"] {
        assert!(
            !super::is_sensitive_param_key(key),
            "harmless key must stay: {key}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_reports_a_broken_body_in_a_valid_envelope() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    // The envelope passes every load-time check (valid JSON, current version,
    // matching server, no expiry), so `load_default()` succeeds and the only
    // failure is the final `cache.sync()` call (cache.rs:749-765). This is the
    // branch a hand-edited or partially written cache file can reach.
    let broken = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: b"not json".to_vec(),
        created_at: None,
    };
    save_default(&broken).unwrap();

    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-1"),
        Err(SyncCacheError::CacheParse(_))
    ));
    // The best-effort wrapper still collapses the classified reason to None.
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
}

#[test]
fn value_less_parameters_survive_masking_verbatim() {
    // `mask_param_pairs` splits on `=` (cache.rs:288-328). A bare flag has no
    // value, so it takes the `else` branch and must be copied verbatim rather
    // than dropped or rewritten.
    assert_eq!(
        super::mask_param_pairs("flag&token=TOPSECRET&state=ok&bare", 0),
        "flag&token=[redacted]&state=ok&bare"
    );
    assert_eq!(super::mask_param_pairs("bare", 0), "bare");
    assert_eq!(super::mask_param_pairs("a&b&c", 0), "a&b&c");

    // The same branch is reached from a query and from a fragment.
    let masked = super::mask_url_secrets("https://vault.example.com/p?flag&token=SECRET#bare");
    assert!(masked.contains("?flag&token=[redacted]"), "{masked}");
    assert!(masked.ends_with("#bare"), "{masked}");
    assert!(!masked.contains("SECRET"), "{masked}");
}

#[test]
fn mask_url_userinfo_without_a_path_delimiter_masks_the_authority() {
    // With no '/', '?' or '#' after the authority, `authority_end` is the end
    // of the string (cache.rs:95-103). The whole remainder is still scanned for
    // the last '@', so userinfo must be masked on this path too.
    assert_eq!(
        super::mask_url_userinfo("https://user:SECRET@vault.example.com"),
        "https://[redacted]@vault.example.com"
    );
    assert_eq!(
        super::mask_url_userinfo("https://u:p@host:8443"),
        "https://[redacted]@host:8443"
    );
    assert_eq!(
        super::mask_url_userinfo("user:SECRET@vault.example.com"),
        "[redacted]@vault.example.com"
    );
    // No userinfo means no rewrite, even without a delimiter.
    assert_eq!(
        super::mask_url_userinfo("https://vault.example.com:8443"),
        "https://vault.example.com:8443"
    );

    let url = "https://user:SECRET@vault.example.com";
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(
        rendered.contains("[redacted]@vault.example.com"),
        "{rendered}"
    );
    // Debug-only masking: the stored URL stays byte-for-byte identical.
    assert_eq!(cache.server_url, url);
}

#[cfg(target_os = "linux")]
#[test]
fn future_and_sentinel_created_at_are_expired_on_the_restore_path() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    let now = i64::try_from(crate::totp::now_unix()).unwrap();
    for created_at in [now + MAX_CACHE_AGE_SECS, i64::MAX] {
        let cache = SyncCache {
            version: SyncCache::VERSION,
            user_id: "user-1".to_string(),
            server_url: "https://vault.example.com".to_string(),
            body: body(),
            created_at: Some(created_at),
        };
        save_default(&cache).unwrap();
        assert!(
            matches!(
                cached_sync_for_detailed("https://vault.example.com", "user-1"),
                Err(SyncCacheError::CacheExpired)
            ),
            "created_at={created_at} must be rejected by the restore path"
        );
        assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
    }
}

#[test]
fn doubly_encoded_sensitive_keys_are_still_redacted() {
    // A key needs two decode passes: `%2574oken` -> `%74oken` -> `token`.
    // Decoding only once used to miss the sensitive-key list and leave the
    // credential value in the diagnostic URL (cache.rs:296-304).
    for (encoded, secret) in [
        ("%2574oken", "DOUBLE_TOKEN_SECRET"),
        ("%2561pi%255Fkey", "DOUBLE_API_KEY_SECRET"),
        ("%2573ession%255Fid", "DOUBLE_SESSION_SECRET"),
    ] {
        let url = format!("https://vault.example.com/sync?{encoded}={secret}&state=ok");
        let masked = super::mask_url_secrets(&url);
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
        assert!(
            masked.contains(&format!("{encoded}=[redacted]")),
            "{masked}"
        );
        assert!(masked.contains("state=ok"), "{masked}");
    }

    // A harmless doubly encoded key is left in its original spelling.
    let harmless = "https://vault.example.com/p?state%253Dok=plain";
    assert_eq!(super::mask_url_secrets(harmless), harmless);
}

#[test]
fn short_and_trailing_percent_escapes_stay_literal() {
    // An incomplete escape at the end of input, or one with a non-hex second
    // digit, is not a `%XX` pair and must be copied verbatim.
    assert_eq!(super::percent_decode("%"), "%");
    assert_eq!(super::percent_decode("abc%"), "abc%");
    assert_eq!(super::percent_decode("abc%2"), "abc%2");
    assert_eq!(super::percent_decode("%2G"), "%2G");
    assert_eq!(super::percent_decode("%zz"), "%zz");
    // An incomplete escape must not swallow a following valid one.
    assert_eq!(super::percent_decode("%2%74"), "%2t");

    // The masker must not rewrite an otherwise harmless URL just because it
    // contains such escapes; the sensitive key beside it is still masked.
    let url = "https://vault.example.com/p?token=ok&state=abc%&next=%2";
    let masked = super::mask_url_secrets(url);
    assert!(masked.contains("token=[redacted]"), "{masked}");
    assert!(masked.contains("state=abc%&next=%2"), "{masked}");
}

#[test]
fn save_and_save_default_report_write_and_path_failures() {
    let dir = tempfile::tempdir().unwrap();
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();

    // Persisting onto an existing directory fails after the temporary file
    // has been written; the error must reach the caller unchanged.
    assert!(save(dir.path(), &cache).is_err());

    // `save_default` has no environment-mutable seam, so its failure branch is
    // exercised through the shared helper used by the public wrapper.
    let missing = super::save_to_path(None, &cache).unwrap_err();
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    assert!(
        missing.to_string().contains("no platform cache directory"),
        "{missing}"
    );
    let unwritable = super::save_to_path(Some(dir.path().to_path_buf()), &cache).unwrap_err();
    assert_ne!(unwritable.kind(), std::io::ErrorKind::NotFound);

    // The destination is untouched on failure: it is still a directory and no
    // stray cache file was created beside it.
    assert!(dir.path().is_dir());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_cache_is_used_by_the_offline_restore_path() {
    // `cached_sync_for_detailed` goes through `load_default` (cache.rs:753),
    // so a cache left in the old config directory is restorable even though
    // all new writes land under the cache directory.
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let cache_home = root.path().join("xdg-cache-home");
    let config_home = root.path().join("xdg-config-home");
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &cache_home);
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &config_home);

    let primary = default_path().expect("a cache directory from XDG_CACHE_HOME");
    let legacy = legacy_path().expect("a config directory from XDG_CONFIG_HOME");
    assert_ne!(primary, legacy);
    assert!(!primary.exists(), "the new cache file must not pre-exist");

    // A pre-timestamp cache is the harshest legacy case: it has no created_at
    // and therefore relies on the documented "legacy stays usable" rule.
    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    cache.created_at = None;
    save(&legacy, &cache).unwrap();
    let before = std::fs::read(&legacy).unwrap();

    let restored = cached_sync_for_detailed("https://vault.example.com", "user-1")
        .expect("the legacy cache must restore through load_default");
    assert_eq!(restored.user_id(), "user-1");
    // The fallback is read-only: neither location is created or rewritten.
    assert!(
        !primary.exists(),
        "reading legacy data must not create a new cache"
    );
    assert_eq!(
        std::fs::read(&legacy).unwrap(),
        before,
        "legacy file was rewritten"
    );
    assert!(matches!(
        cached_sync_for_detailed("https://other.example.com", "user-1"),
        Err(SyncCacheError::ServerMismatch)
    ));

    // A missing primary still falls back, but an unusable primary does not.
    write_fixture(&primary, b"not json");
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-1"),
        Err(SyncCacheError::ParseFailedCause(_))
    ));
    assert_eq!(std::fs::read(&legacy).unwrap(), before);
}

#[test]
fn validate_does_not_apply_the_restore_expiry_window() {
    // `validate` (cache.rs:796-805) checks only the server and body. The
    // expiry window is a restore-path policy enforced by
    // `cached_sync_for_detailed` (cache.rs:760-763); an already-held object
    // therefore passes `validate` even when its timestamp is unusable.
    let now = i64::try_from(crate::totp::now_unix()).unwrap();
    for created_at in [
        Some(now - MAX_CACHE_AGE_SECS - 1),
        Some(now + 100),
        Some(i64::MAX),
    ] {
        let cache = SyncCache {
            version: SyncCache::VERSION,
            user_id: "user-1".to_string(),
            server_url: "https://vault.example.com".to_string(),
            body: body(),
            created_at,
        };
        assert!(is_cache_expired(created_at, now), "{created_at:?}");
        assert!(
            validate(&cache, "user-1", "https://vault.example.com").is_ok(),
            "validate must not consult the clock: {created_at:?}"
        );
        // The body check is still applied, so this is not a blanket bypass.
        let mut corrupt = cache;
        corrupt.body = b"not json".to_vec();
        assert!(matches!(
            validate(&corrupt, "user-1", "https://vault.example.com"),
            Err(SyncCacheError::CacheParse(_))
        ));
    }
    let fresh = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    assert!(!is_cache_expired(fresh.created_at, now));
    assert!(validate(&fresh, "user-1", "https://vault.example.com").is_ok());
}

#[test]
fn mask_url_userinfo_handles_ipv6_hosts_and_query_at_signs() {
    // The colons in `[::1]` were read as a `user:password` marker, so a query
    // '@' became the userinfo separator and the real credential stayed in the
    // diagnostic URL (cache.rs:94-208). Both must now be distinguished.
    for (url, expected) in [
        (
            "https://user:SECRET@[::1]?email=a@b",
            "https://[redacted]@[::1]?email=a@b",
        ),
        (
            "https://user:SECRET@[::1]:8443?email=a@b",
            "https://[redacted]@[::1]:8443?email=a@b",
        ),
        (
            "https://user:SECRET@[::1]/path?email=a@b",
            "https://[redacted]@[::1]/path?email=a@b",
        ),
        (
            "user:SECRET@[2001:db8::1]?email=a@b",
            "[redacted]@[2001:db8::1]?email=a@b",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
    }
    // A host without userinfo is unchanged even when its query holds an '@':
    // the address's colons must not invent a separator.
    for url in [
        "https://[::1]?email=a@b",
        "https://[::1]:8443?email=a@b",
        "https://[2001:db8::1]/path?email=a@b",
    ] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
    // The Debug masker reaches the same helper and must not leak the password.
    let url = "https://user:IPv6SECRET@[::1]:8443?email=a@b";
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("IPv6SECRET"), "{rendered}");
    assert!(rendered.contains("[redacted]@[::1]:8443"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn user_id_is_extracted_from_pascal_case_and_uppercase_bodies() {
    // `from_body` parses a normalized *copy* of the raw body for the account id
    // (cache.rs:404-418). Casing variants must not make the cache anonymous,
    // otherwise the restore's account check could never match a real login.
    let pascal = br#"{"Profile":{"Id":"user-pascal","Key":"K1"},"Ciphers":[]}"#;
    let cache = SyncCache::from_body(pascal.to_vec(), "https://vault.example.com").unwrap();
    assert_eq!(cache.user_id, "user-pascal");
    assert!(!String::from_utf8(cache.body).unwrap().contains("K1"));

    let upper = br#"{
        "PROFILE": {"Id": "user-upper", "Key": "K2"},
        "profile": {"Id": "user-upper", "PrivateKey": "K3"},
        "CIPHERS": []
    }"#;
    let cache = SyncCache::from_body(upper.to_vec(), "https://vault.example.com").unwrap();
    assert_eq!(cache.user_id, "user-upper");
    let stored = String::from_utf8(cache.body).unwrap();
    assert!(!stored.contains("K2"), "{stored}");
    assert!(!stored.contains("K3"), "{stored}");
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_rejects_a_cache_for_another_account() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    save_default(&SyncCache::from_body(body(), "https://vault.example.com").unwrap()).unwrap();
    // Same server and still fresh, but a different account: refuse to restore.
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-2"),
        Err(SyncCacheError::UserMismatch)
    ));
    assert!(cached_sync_for("https://vault.example.com", "user-2").is_none());
    // An empty or wrong id cannot unlock another account's cache either.
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", ""),
        Err(SyncCacheError::UserMismatch)
    ));
    // The matching account still restores; the server check still wins first.
    assert!(cached_sync_for_detailed("https://vault.example.com", "user-1").is_ok());
    assert!(matches!(
        cached_sync_for_detailed("https://other.example.com", "user-1"),
        Err(SyncCacheError::ServerMismatch)
    ));
}

#[test]
fn bounded_read_consumes_no_more_than_limit_plus_one_byte() {
    use std::io::{self, Read};

    // Records how much of the source was actually pulled through the reader.
    struct CountingReader {
        data: Vec<u8>,
        pos: usize,
    }
    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.data[self.pos..];
            let count = remaining.len().min(buf.len());
            buf[..count].copy_from_slice(&remaining[..count]);
            self.pos += count;
            Ok(count)
        }
    }

    // `read_bounded` caps the reader at limit+1 bytes (cache.rs:603-613). The
    // oversized body must be rejected without draining the remaining bytes.
    let mut over = CountingReader {
        data: vec![b'x'; 1_000],
        pos: 0,
    };
    let error = super::read_bounded(&mut over, 8).unwrap_err();
    assert!(matches!(error, CacheLoadError::CacheTooLarge), "{error:?}");
    assert_eq!(over.pos, 9, "only limit+1 bytes may be consumed");
    assert_eq!(over.data.len() - over.pos, 991, "the rest stays unread");

    // A file exactly at the limit consumes exactly the limit, not one more.
    let mut exact = CountingReader {
        data: vec![b'x'; 8],
        pos: 0,
    };
    assert_eq!(super::read_bounded(&mut exact, 8).unwrap().len(), 8);
    assert_eq!(exact.pos, 8);
}

#[test]
fn undecryptable_uri_from_a_cached_body_has_no_match_type() {
    // A cached sync body whose URI ciphertext cannot be opened becomes the
    // UNDECRYPTABLE_URI marker. A decryption failure carries no wire `match`
    // value, so the marker's `match_type` must be None (vault_sync.rs:313-318).
    let raw = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [],
        "ciphers": [{
            "id": "c1",
            "type": 1,
            "name": null,
            "login": { "uris": [{ "uri": "NOT_AN_ENC_STRING" }] },
            "revisionDate": "2024-01-01T00:00:00Z",
        }],
    });
    let cache =
        SyncCache::from_body(raw.to_string().into_bytes(), "https://vault.example.com").unwrap();
    let sync = cache.sync().unwrap();
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).unwrap();
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    vault.apply_sync(sync).unwrap();
    let model = crate::vault_sync::import_logins(&vault).unwrap();

    let uris = model.item("c1").unwrap().uris();
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, crate::vault_sync::UNDECRYPTABLE_URI);
    assert!(
        crate::vault_sync::is_undecryptable_uri(&uris[0].uri),
        "the marker must stay recognizable"
    );
    assert_eq!(uris[0].match_type, None);
}

#[test]
fn unclosed_ipv6_bracket_takes_the_no_closing_bracket_branches() {
    // Without a closing ']', `without_ipv6_literals` stops and keeps the text
    // (cache.rs:158-171), and `host_with_optional_port_ok` refuses the host
    // (cache.rs:183-186). A truncated `[::1` literal reaches both branches.
    let scan = "user:SECRET@[::1?email=a@b";
    assert_eq!(
        super::without_ipv6_literals("user:p?x=1@[::1?email=a@b"),
        "user:p?x=1@[::1?email=a@b"
    );
    assert!(!super::host_with_optional_port_ok("[::1"));
    assert!(!super::host_with_optional_port_ok("["));
    // A closed literal still takes the normal arm, so the assertions above
    // are about the missing bracket rather than IPv6 in general.
    assert!(super::host_with_optional_port_ok("[::1]"));
    assert!(super::host_with_optional_port_ok("[::1]:8443"));

    // The host cannot be marked complete without ']', so the '@' after '?'
    // is not classified as a query separator (cache.rs:135-149).
    let at = scan.rfind('@').expect("an '@' after the query marker");
    assert!(!super::at_is_in_query(scan, at));
}

#[test]
fn host_with_optional_port_ok_rejects_malformed_brackets_and_ports() {
    // A bracketed literal must be a closed '[...]' containing a colon
    // (cache.rs:183-190): `[]` has no address and `[host]` is not IPv6.
    assert!(!super::host_with_optional_port_ok("[]"));
    assert!(!super::host_with_optional_port_ok("[host]"));
    // Only an empty tail or ':port' may follow ']' (cache.rs:191-196).
    assert!(!super::host_with_optional_port_ok("[::1]x"));
    assert!(!super::host_with_optional_port_ok("[::1]:8443x"));
    // A port, when present, must be non-empty and all ASCII digits
    // (cache.rs:207).
    assert!(!super::host_with_optional_port_ok("vault.example.com:"));
    assert!(!super::host_with_optional_port_ok("vault.example.com:http"));
    assert!(!super::host_with_optional_port_ok("[::1]:"));
    assert!(!super::host_with_optional_port_ok("[::1]:http"));
    // Controls: the rejections above are about malformed input, not about
    // bracketed IPv6 or ports in general.
    assert!(super::host_with_optional_port_ok("vault.example.com"));
    assert!(super::host_with_optional_port_ok("vault.example.com:8443"));
    assert!(super::host_with_optional_port_ok("[::1]"));
    assert!(super::host_with_optional_port_ok("[::1]:8443"));
}

#[test]
fn nested_url_userinfo_is_masked_by_the_recursive_pass() {
    // A nested URL in a harmless-looking parameter still goes through
    // `mask_url_secrets` (cache.rs:344-369), whose first step masks userinfo
    // (cache.rs:94-119). Credentials in the nested authority must not leak.
    let with_query = "https://vault.example.com/login?next=https://user:NESTED_USER_SECRET@cb.example.com/done?state=ok";
    let masked = super::mask_url_secrets(with_query);
    assert!(!masked.contains("NESTED_USER_SECRET"), "{masked}");
    assert!(masked.contains("[redacted]@cb.example.com"), "{masked}");
    assert!(masked.contains("next=https://"), "{masked}");
    assert!(masked.contains("state=ok"), "{masked}");

    // The same holds for a nested URL carried in a fragment value.
    let with_fragment =
        "https://vault.example.com/cb#next=https://u:FRAG_USER_SECRET@cb.example.com/done#x=1";
    let masked = super::mask_url_secrets(with_fragment);
    assert!(!masked.contains("FRAG_USER_SECRET"), "{masked}");
    assert!(masked.contains("[redacted]@cb.example.com"), "{masked}");

    // Percent-encoded nested userinfo is decoded before the recursive pass.
    let encoded = "https://vault.example.com/login?next=https%3A%2F%2Fu%3AENCODED_USER_SECRET%40cb.example.com%2Fdone%3Fstate%3Dok";
    let masked = super::mask_url_secrets(encoded);
    assert!(!masked.contains("ENCODED_USER_SECRET"), "{masked}");
    assert!(masked.contains("[redacted]@cb.example.com"), "{masked}");
}

#[test]
fn host_with_optional_port_ok_rejects_authority_delimiters_and_empty_hosts() {
    // `host_with_optional_port_ok` refuses an empty host (cache.rs:180) and any
    // hostname containing '@', '=', '?' or '#' (cache.rs:204). These checks keep
    // `host_complete` in `at_is_in_query` from accepting a query tail as the
    // authority. One case per delimiter so a regression is easy to localize.
    let cases = [
        ("", "empty host"),
        (":8443", "empty host with a port"),
        ("user@host", "'@' in hostname"),
        ("host@", "trailing '@' in hostname"),
        ("user@host:8443", "'@' with a valid port"),
        ("ho=st", "'=' in hostname"),
        ("ho?st", "'?' in hostname"),
        ("ho#st", "'#' in hostname"),
    ];
    for (host, reason) in cases {
        assert!(
            !super::host_with_optional_port_ok(host),
            "{host} must be rejected ({reason})"
        );
    }
    // Controls: clean hostnames and numeric ports still pass, so the
    // rejections above are about the delimiters rather than about ports.
    assert!(super::host_with_optional_port_ok("vault.example.com"));
    assert!(super::host_with_optional_port_ok("vault.example.com:8443"));
}

#[test]
fn host_with_optional_port_ok_rejects_non_ascii_digit_ports() {
    // cache.rs:207 checks `value.bytes().all(|byte| byte.is_ascii_digit())`,
    // so Unicode decimal digits are not a port even when they look like one.
    // Both the plain-host and the bracketed-IPv6 arms must agree.
    for port in ["１２３", "١٢٣", "१२३", "844３"] {
        let plain = format!("vault.example.com:{port}");
        let bracketed = format!("[::1]:{port}");
        assert!(!super::host_with_optional_port_ok(&plain), "{plain}");
        assert!(
            !super::host_with_optional_port_ok(&bracketed),
            "{bracketed}"
        );
    }
    // ASCII digits still pass on both arms, including a mixed ASCII/Unicode
    // spelling whose non-ASCII part must still be rejected.
    assert!(super::host_with_optional_port_ok("vault.example.com:8443"));
    assert!(super::host_with_optional_port_ok("[::1]:8443"));
    assert!(!super::host_with_optional_port_ok(
        "vault.example.com:84４3"
    ));
}

#[test]
fn deeply_nested_urls_stop_at_the_mask_depth_limit() {
    // cache.rs:279-345: a harmless parameter whose value is another URL is
    // masked recursively, but the recursion is capped so a hostile URL cannot
    // exhaust the stack. Legitimate one- and two-level nesting keeps working.
    assert_eq!(super::MAX_MASK_DEPTH, 8);

    let shallow =
        "https://outer.example.com/next?next=https://cb.example.com/done?token=SHALLOW_SECRET";
    let shallow_masked = super::mask_url_secrets(shallow);
    assert!(
        shallow_masked.contains("token=[redacted]"),
        "{shallow_masked}"
    );
    assert!(
        !shallow_masked.contains("SHALLOW_SECRET"),
        "{shallow_masked}"
    );

    // Sixteen levels: the first eight are rendered, the rest is replaced by a
    // single `[redacted]` rather than descended into (so the call returns
    // instead of recursing without bound).
    let mut nested = "https://deep.example.com/cb?token=DEEPEST_SECRET".to_string();
    for layer in 0..16 {
        nested = format!("https://layer{layer}.example.com/next?next={nested}");
    }
    let masked = super::mask_url_secrets(&nested);
    assert!(masked.contains("next=[redacted]"), "{masked}");
    assert!(masked.contains("layer15.example.com"), "{masked}");
    assert!(masked.contains("layer7.example.com"), "{masked}");
    for unreachable in ["layer6", "layer0", "deep.example.com", "DEEPEST_SECRET"] {
        assert!(
            !masked.contains(unreachable),
            "leaked {unreachable} beyond the depth cap: {masked}"
        );
    }
}

#[test]
fn username_only_userinfo_keeps_the_query_at_sign_via_host_complete() {
    // cache.rs:135-149: with no `user:password` marker, `has_userinfo_colon`
    // alone would classify the query '@' as the userinfo separator. The
    // `host_complete` rescue recognizes the clean host after the real '@'.
    let scan = "user@host?email=a@b";
    let userinfo_at = scan.find('@').expect("userinfo '@'");
    let query_at = scan.rfind('@').expect("query '@'");
    assert!(!super::at_is_in_query(scan, userinfo_at));
    assert!(
        super::at_is_in_query(scan, query_at),
        "host_complete must classify the query '@' as in-query"
    );

    let url = "https://user@host?email=a@b";
    assert_eq!(
        super::mask_url_userinfo(url),
        "https://[redacted]@host?email=a@b"
    );
    assert_eq!(
        super::mask_url_userinfo("https://user@host:8443?email=a@b"),
        "https://[redacted]@host:8443?email=a@b"
    );

    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(rendered.contains("[redacted]@host?email=a@b"), "{rendered}");
    assert!(!rendered.contains("[redacted]@b"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn validate_rejects_a_body_user_id_that_disagrees_with_the_envelope() {
    // cache.rs:834-846: matching the envelope is not enough; the parsed body's
    // `Profile.Id` must name the same account. A hand-edited envelope can claim
    // a different id while the encrypted body still belongs to another user.
    let body = br#"{
        "profile": {"id": "user-in-body"},
        "folders": [{"id": "f1", "name": "2.work"}],
        "ciphers": []
    }"#;
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-in-envelope".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: body.to_vec(),
        created_at: None,
    };
    assert!(cache.sync().is_ok(), "the body itself must be parseable");

    assert_eq!(
        validate(&cache, "user-in-envelope", "https://vault.example.com"),
        Err(SyncCacheError::UserMismatch)
    );
    // Matching the body id does not help: the envelope check still wins.
    assert_eq!(
        validate(&cache, "user-in-body", "https://vault.example.com"),
        Err(SyncCacheError::UserMismatch)
    );

    // A cache whose envelope and body agree remains valid.
    let consistent = SyncCache {
        user_id: "user-in-body".to_string(),
        ..cache
    };
    assert!(validate(&consistent, "user-in-body", "https://vault.example.com").is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_rejects_a_body_user_id_that_disagrees_with_the_envelope() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    let body = br#"{
        "profile": {"id": "user-in-body"},
        "folders": [{"id": "f1", "name": "2.work"}],
        "ciphers": []
    }"#;
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-in-envelope".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: body.to_vec(),
        created_at: None,
    };
    save_default(&cache).unwrap();

    // Server, envelope id and freshness all check out; only the body disagrees.
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-in-envelope"),
        Err(SyncCacheError::UserMismatch)
    ));
    assert!(
        cached_sync_for("https://vault.example.com", "user-in-envelope").is_none(),
        "the best-effort wrapper must collapse the classified mismatch"
    );
}

#[test]
fn protocol_relative_nested_urls_are_masked_within_the_depth_limit() {
    // cache.rs:94-119 and 288-345: a protocol-relative URL has no `://`, so it
    // needs its own nested-URL detection and its own authority scan. Without
    // both, `//user:SECRET@host/p` would be copied verbatim into a log line.
    assert_eq!(
        super::mask_url_secrets("//user:SECRET@host.example.com/p"),
        "//[redacted]@host.example.com/p"
    );

    for (url, expected) in [
        (
            "https://vault.example.com/login?next=//user:NESTED_SECRET@cb.example.com/done",
            "next=//[redacted]@cb.example.com/done",
        ),
        (
            "https://vault.example.com/cb#next=//u:FRAG_SECRET@cb.example.com/done",
            "#next=//[redacted]@cb.example.com/done",
        ),
        (
            "https://vault.example.com/login?next=%2F%2Fu%3AENC_SECRET%40cb.example.com%2Fdone",
            "next=//[redacted]@cb.example.com/done",
        ),
    ] {
        let masked = super::mask_url_secrets(url);
        assert!(masked.contains(expected), "{url} -> {masked}");
        for secret in ["NESTED_SECRET", "FRAG_SECRET", "ENC_SECRET"] {
            assert!(!masked.contains(secret), "leaked {secret}: {masked}");
        }
    }

    // The same recursion cap applies to protocol-relative nesting: layers down
    // to `layer7` are rendered, the deeper tail is a single `[redacted]`.
    assert_eq!(super::MAX_MASK_DEPTH, 8);
    let mut nested = "//deep.example.com/cb?token=DEEPEST_SECRET".to_string();
    for layer in 0..16 {
        nested = format!("//layer{layer}.example.com/next?next={nested}");
    }
    let masked = super::mask_url_secrets(&nested);
    assert!(masked.contains("next=[redacted]"), "{masked}");
    assert!(masked.contains("layer15.example.com"), "{masked}");
    assert!(masked.contains("layer7.example.com"), "{masked}");
    for unreachable in ["layer6", "layer0", "deep.example.com", "DEEPEST_SECRET"] {
        assert!(
            !masked.contains(unreachable),
            "leaked {unreachable} beyond the depth cap: {masked}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_reports_not_found_with_no_cache_file() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    assert!(!default_path().expect("a cache directory").exists());
    assert!(!legacy_path().expect("a config directory").exists());

    // load_default() tries the cache path and then the read-only legacy path;
    // both miss, so the restore path keeps the classified NotFound reason
    // instead of silently turning it into a ServerMismatch or a parse failure.
    let error = cached_sync_for_detailed("https://vault.example.com", "user-1").unwrap_err();
    assert!(matches!(&error, SyncCacheError::NotFound), "{error:?}");
    assert_eq!(cache_error_message(error.clone()), REASON_MISSING);
    assert!(cache_restore_status(error).is_none());
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
}

#[test]
fn sync_cache_sync_reports_cache_parse_for_an_invalid_body() {
    // `SyncCache::sync()` (cache.rs:451-454) is the body-only parse used by the
    // restore and validate paths. A corrupt body must be a CacheParse with the
    // underlying parse error still reachable through Error::source(), not an
    // envelope-level ParseFailedCause.
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: b"not json".to_vec(),
        created_at: Some(0),
    };
    let error = cache.sync().unwrap_err();
    assert!(matches!(&error, SyncCacheError::CacheParse(_)), "{error:?}");
    let source = std::error::Error::source(&error).expect("the parse error must stay reachable");
    assert!(!source.to_string().is_empty());
    assert_eq!(cache_error_message(error), REASON_CORRUPT);
}

#[test]
fn nested_scheme_less_authorities_and_semicolon_separators_are_masked() {
    // A nested value without a scheme (`user:SECRET@host`) has neither `?`,
    // `#` nor `//`, so the old recursion trigger never fired and the password
    // reached Debug verbatim. The authority helper closes that gap.
    let plain =
        "https://vault.example.com/login?next=user:NESTED_NO_SCHEME_SECRET@cb.example.com/done";
    let masked = super::mask_url_secrets(plain);
    assert!(!masked.contains("NESTED_NO_SCHEME_SECRET"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // Percent-encoded delimiters are decoded before the same authority check.
    let encoded =
        "https://vault.example.com/login?next=user%3ANESTED_ENC_SECRET%40cb.example.com%2Fdone";
    let masked = super::mask_url_secrets(encoded);
    assert!(!masked.contains("NESTED_ENC_SECRET"), "{masked}");
    assert!(
        masked.contains("[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // A harmless '@' without a userinfo colon stays untouched.
    let harmless = "https://vault.example.com/p?state=a@b&note=ok";
    assert_eq!(super::mask_url_secrets(harmless), harmless);

    // ';' is a query separator too; a secret behind it must not survive.
    let semicolon = "https://vault.example.com/sync?token=SEMI_TOKEN;state=ok;api_key=SEMI_KEY";
    let masked = super::mask_url_secrets(semicolon);
    assert!(!masked.contains("SEMI_TOKEN"), "{masked}");
    assert!(!masked.contains("SEMI_KEY"), "{masked}");
    assert!(
        masked.contains("token=[redacted];state=ok;api_key=[redacted]"),
        "{masked}"
    );

    // Both fixes reach Debug through the cache's stored server_url.
    let url = "https://vault.example.com/login?next=user:DEBUG_NESTED_SECRET@cb.example.com/done;token=DEBUG_SEMI_SECRET";
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("DEBUG_NESTED_SECRET"), "{rendered}");
    assert!(!rendered.contains("DEBUG_SEMI_SECRET"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn debug_pins_the_stored_body_byte_count() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let stored = String::from_utf8(cache.body.clone()).expect("the cached JSON body is UTF-8");
    let rendered = format!("{cache:?}");

    // Debug reports the exact byte length of the *stored* body, not of the
    // caller's raw input (from_body strips keys and re-serializes compactly).
    let expected = format!("body: \"<{} bytes redacted>\"", stored.len());
    assert!(rendered.contains(&expected), "{rendered}");
    assert_eq!(cache.body.len(), stored.len());
    assert!(!rendered.contains(&stored), "{rendered}");
    assert!(
        stored.len() < body().len(),
        "redaction must shrink the body"
    );

    // A different body size produces a different pinned count.
    let mut bigger_body = cache.body.clone();
    bigger_body.extend_from_slice(&[b' '; 10]);
    let bigger = SyncCache {
        body: bigger_body,
        ..cache
    };
    let bigger_rendered = format!("{bigger:?}");
    assert!(
        bigger_rendered.contains(&format!("body: \"<{} bytes redacted>\"", bigger.body.len())),
        "{bigger_rendered}"
    );
}

#[test]
fn percent_decode_keeps_control_character_escapes_literal() {
    // Decoding `%0A`/`%00` would inject a newline or NUL into a Debug line;
    // percent_decode (cache.rs:277-305) only decodes printable ASCII.
    for escape in ["%00", "%01", "%09", "%0A", "%0D", "%1F", "%7F"] {
        assert_eq!(super::percent_decode(escape), escape, "{escape}");
        let byte = u8::from_str_radix(&escape[1..], 16).unwrap();
        assert!(byte.is_ascii_control(), "{escape} must be a control byte");
    }

    // Printable escapes in the same value are still decoded and recognized.
    assert_eq!(
        super::percent_decode("%74%6F%6B%65%6E%3D%0A%53%45%43%52%45%54"),
        "token=%0ASECRET"
    );
    let url = "https://vault.example.com/p?to%6B%65n%0A=SECRET_VALUE";
    let masked = super::mask_url_secrets(url);
    assert!(masked.contains("to%6B%65n%0A=[redacted]"), "{masked}");
    assert!(!masked.contains("SECRET_VALUE"), "{masked}");
    assert!(!masked.contains('\n'), "{masked}");
}

#[test]
fn authority_start_accepts_uppercase_schemes_and_ignores_query_schemes() {
    // A leading `://` is a scheme delimiter regardless of the scheme's case;
    // a `://` inside a query is just text and must not move the authority scan
    // (cache.rs:94-98).
    assert!(super::is_scheme("HTTPS"));
    assert!(super::is_scheme("hTtP+1.0-x"));
    assert!(!super::is_scheme("1https"));
    assert!(!super::is_scheme("https:"));
    assert!(!super::is_scheme(""));

    assert_eq!(super::authority_start("HTTPS://user:p@host/p"), 8);
    assert_eq!(super::authority_start("//user:p@host/p"), 2);
    assert_eq!(super::authority_start("user:p@host/p"), 0);
    assert_eq!(
        super::authority_start("//user:SECRET@host/p?next=https://cb.example.com/done"),
        2,
        "the nested query scheme must not become the outer scheme"
    );
    assert_eq!(
        super::authority_start("user:SECRET@host/p?next=https://cb.example.com/done"),
        0
    );
    assert_eq!(
        super::authority_start("HTTPS://host?next=https://cb.example.com"),
        8
    );
}

#[test]
fn uppercase_scheme_and_query_scheme_userinfo_are_masked() {
    for (url, expected) in [
        (
            "HTTPS://user:UPPER_SCHEME_SECRET@host.example.com/p",
            "HTTPS://[redacted]@host.example.com/p",
        ),
        (
            "//user:REL_SECRET@host.example.com/p?next=https://cb.example.com/done",
            "//[redacted]@host.example.com/p?next=https://cb.example.com/done",
        ),
        (
            "user:NO_SCHEME_SECRET@host.example.com/p?next=https://cb.example.com/done",
            "[redacted]@host.example.com/p?next=https://cb.example.com/done",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
    }

    // The Debug masker reaches the same helper for the stored server URL.
    let url = "HTTPS://user:DEBUG_UPPER_SECRET@host.example.com/p?next=https://cb.example.com/done";
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("DEBUG_UPPER_SECRET"), "{rendered}");
    assert!(
        rendered.contains("HTTPS://[redacted]@host.example.com"),
        "{rendered}"
    );
    assert_eq!(cache.server_url, url);
}

#[test]
fn semicolon_in_nested_userinfo_is_masked_before_pair_splitting() {
    // A ';' is a pair separator, but it is also legal inside a password. A
    // nested URL in a value must have its userinfo masked *before* the pair is
    // split, otherwise the credential survives in the diagnostic URL.
    let with_scheme = "https://vault.example.com/login?next=https://user:SEMI_USER_SECRET;a=s@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(with_scheme);
    assert!(!masked.contains("SEMI_USER_SECRET"), "{masked}");
    assert!(
        masked.contains("next=https://[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    let without_scheme =
        "https://vault.example.com/login?next=user:NO_SCHEME_SEMI;a=s@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(without_scheme);
    assert!(!masked.contains("NO_SCHEME_SEMI"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // A real ';' separator after a harmless '@' is still applied.
    let harmless_at = "https://vault.example.com/p?state=a@b;token=SEMI_AFTER_AT";
    let masked = super::mask_url_secrets(harmless_at);
    assert!(!masked.contains("SEMI_AFTER_AT"), "{masked}");
    assert!(masked.contains("state=a@b;token=[redacted]"), "{masked}");

    // Debug goes through the same path for the stored server URL.
    let cache = SyncCache::from_body(body(), with_scheme).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("SEMI_USER_SECRET"), "{rendered}");
    assert_eq!(cache.server_url, with_scheme);
}

#[test]
fn amp_in_nested_userinfo_password_is_masked_before_pair_splitting() {
    // '&' is a pair separator but also a legal password character. The
    // pre-pass must see the whole authority before `mask_param_pairs` splits on
    // '&', otherwise the credential survives in the diagnostic URL
    // (cache.rs:359-412).
    let with_scheme =
        "https://vault.example.com/login?next=https://user:P&SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(with_scheme);
    assert!(!masked.contains("P&SS"), "{masked}");
    assert!(
        masked.contains("next=https://[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // A scheme-less nested authority has no '/', '?' or '#' before the '@', so
    // it takes the `pair_start == 0` branch: the `key=` prefix is kept and the
    // first '=' is the pair separator (cache.rs:385-393).
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("next=user:P&SS@cb.example.com/done"),
        "next=[redacted]@cb.example.com/done"
    );
    let no_scheme = "https://vault.example.com/login?next=user:P&SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(no_scheme);
    assert!(!masked.contains("P&SS"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // A harmless '@' without a `user:secret` marker is not rewritten by the
    // pre-pass, so the pair separator still applies normally after it.
    let harmless = "https://vault.example.com/p?state=a@b&token=AMP_AFTER_AT";
    let masked = super::mask_url_secrets(harmless);
    assert!(!masked.contains("AMP_AFTER_AT"), "{masked}");
    assert!(masked.contains("state=a@b&token=[redacted]"), "{masked}");

    // Percent-encoded '&' reaches the recursive masker through the nested
    // authority check, which decodes before inspecting the candidate.
    let encoded = "https://vault.example.com/login?next=user:P%26SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(encoded);
    assert!(!masked.contains("P%26SS"), "{masked}");
    assert!(
        masked.contains("[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // Debug reaches the same path through the stored server URL.
    let cache = SyncCache::from_body(body(), with_scheme).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("P&SS"), "{rendered}");
    assert_eq!(cache.server_url, with_scheme);
}

#[test]
fn non_ascii_percent_escaped_keys_are_a_documented_masking_limit() {
    // `percent_decode` keeps non-ASCII escapes as `%XX`, so an ASCII key name
    // split by such an escape never matches the sensitive-name list. This is a
    // known constraint of the Debug redactor, not a failure of the ASCII path.
    let url = "https://vault.example.com/sync?%74%E3%81%82oken=NON_ASCII_KEY_SECRET&state=ok";
    let masked = super::mask_url_secrets(url);
    assert!(
        masked.contains("NON_ASCII_KEY_SECRET"),
        "documented limit: {masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    let ascii = "https://vault.example.com/sync?token=NON_ASCII_KEY_SECRET&state=ok";
    let masked = super::mask_url_secrets(ascii);
    assert!(!masked.contains("NON_ASCII_KEY_SECRET"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_classifies_version_size_and_read_failures() {
    let _lock = ENV_LOCK.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    let url = "https://vault.example.com";
    let path = default_path().expect("a cache directory from XDG_CACHE_HOME");

    // VersionMismatch: load_detailed rejects the envelope before the restore
    // path compares server, account or freshness (cache.rs:836-838).
    let mut outdated = SyncCache::from_body(body(), url).unwrap();
    outdated.version = SyncCache::VERSION + 1;
    save_default(&outdated).unwrap();
    assert!(matches!(
        cached_sync_for_detailed(url, "user-1"),
        Err(SyncCacheError::VersionMismatch)
    ));
    assert!(cached_sync_for(url, "user-1").is_none());

    // CacheTooLarge: the size gate runs before parsing and the private-file
    // permission check (cache.rs:809-811).
    write_fixture(&path, &vec![b'x'; (MAX_CACHE_BYTES + 1) as usize]);
    assert!(matches!(
        cached_sync_for_detailed(url, "user-1"),
        Err(SyncCacheError::CacheTooLarge)
    ));
    assert_eq!(
        cache_error_message(SyncCacheError::CacheTooLarge),
        REASON_TOO_LARGE
    );

    // ReadFailedCause: a valid envelope left group-readable is refused by the
    // private-file policy, and the io/permission cause stays reachable
    // (cache.rs:816-827).
    let valid = SyncCache::from_body(body(), url).unwrap();
    save_default(&valid).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let error = cached_sync_for_detailed(url, "user-1").unwrap_err();
    assert!(
        matches!(&error, SyncCacheError::ReadFailedCause(_)),
        "{error:?}"
    );
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);

    // A matching, owner-only cache still restores, so the three classifications
    // above are about the specific failures rather than a broken fixture.
    save_default(&valid).unwrap();
    assert_eq!(
        cached_sync_for_detailed(url, "user-1").unwrap().user_id(),
        "user-1"
    );
}
