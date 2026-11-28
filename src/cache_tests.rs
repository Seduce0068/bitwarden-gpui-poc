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

    // Reading a directory as a file fails (EISDIR on Unix). Set owner-only
    // mode first: with the default 0755 the private-file permission gate would
    // reject the directory before `read_to_end`, so the assertion would pass
    // for the wrong reason. 0700 lets the read happen and pins EISDIR itself.
    let directory = dir.path().join("detailed-dir");
    std::fs::create_dir_all(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
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
fn older_versions_are_version_mismatches_not_parse_failures() {
    // `load_detailed` deserializes the envelope before it compares the version
    // (cache.rs:1145-1152). The sibling tests only pin a *newer* version. Both
    // older shapes must deserialize and then take the same VersionMismatch arm:
    // an explicit `version: 0`, and the pre-version envelope with no key at all.
    let dir = tempfile::tempdir().unwrap();

    let explicit_zero = serde_json::json!({
        "version": 0,
        "user_id": "user-1",
        "server_url": "https://vault.example.com",
        "body": body(),
        "created_at": null,
    });
    let zero_path = dir.path().join("version-zero.json");
    write_fixture(&zero_path, &serde_json::to_vec(&explicit_zero).unwrap());
    let error = load_detailed(&zero_path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::VersionMismatch),
        "version=0 must be a version mismatch, not a parse failure: {error:?}"
    );

    let no_version_key = serde_json::json!({
        "user_id": "user-1",
        "server_url": "https://vault.example.com",
        "body": body(),
        "created_at": null,
    });
    let absent_path = dir.path().join("version-absent.json");
    write_fixture(&absent_path, &serde_json::to_vec(&no_version_key).unwrap());
    let error = load_detailed(&absent_path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::VersionMismatch),
        "a missing version key must be a version mismatch, not a parse failure: {error:?}"
    );
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
fn scheme_less_nested_ipv6_authority_userinfo_is_masked() {
    // A decoded nested value can be a scheme-less authority whose host is a
    // bracketed IPv6 literal. `authority_start` must skip the leading `/` (or
    // `//`) instead of treating it as the end of the authority, and the colons
    // inside `[::1]` must not look like a `user:password` marker or a port
    // (cache.rs:120-146, 274-330, 376-411).
    for (url, expected) in [
        (
            "/user:SECRET@[::1]:8443/path",
            "/[redacted]@[::1]:8443/path",
        ),
        (
            "//user:SECRET@[2001:db8::1]/path",
            "//[redacted]@[2001:db8::1]/path",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        assert!(!super::mask_url_secrets(url).contains("SECRET"), "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains("SECRET"), "{rendered}");
        assert!(rendered.contains("[redacted]@["), "{rendered}");
        // Debug masking never rewrites the stored value used by the mismatch
        // check.
        assert_eq!(cache.server_url, url);
    }

    // The same scheme-less IPv6 authority nested in a harmless query value is
    // masked recursively, while the surrounding key and URL stay traceable.
    let nested = "https://vault.example.com/?next=/user:NESTED@[::1]/p";
    assert_eq!(
        super::mask_url_secrets(nested),
        "https://vault.example.com/?next=/[redacted]@[::1]/p"
    );
    let cache = SyncCache::from_body(body(), nested).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("NESTED"), "{rendered}");
    assert_eq!(cache.server_url, nested);
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
fn userinfo_password_question_and_hash_are_masked_with_a_real_query() {
    // A '?'/'#' inside the userinfo password is password data, while the later
    // '?'/'#' after the host is a genuine query/fragment. The authority scan
    // must keep the first pair together (cache.rs:161-221) and the full
    // `mask_url_secrets` pass must still redact the real query/fragment secrets
    // that coexist in the same URL (cache.rs:616-649).
    for (url, userinfo_masked, expected, password_secret, other_secrets) in [
        (
            "https://user:p?ss@vault.example.com/path?token=QUERY_SECRET&state=ok",
            "https://[redacted]@vault.example.com/path?token=QUERY_SECRET&state=ok",
            "https://[redacted]@vault.example.com/path?token=[redacted]&state=ok",
            "p?ss",
            &["QUERY_SECRET"][..],
        ),
        (
            "https://user:p#ss@vault.example.com/path?token=QUERY_SECRET#code=FRAGMENT_SECRET",
            "https://[redacted]@vault.example.com/path?token=QUERY_SECRET#code=FRAGMENT_SECRET",
            "https://[redacted]@vault.example.com/path?token=[redacted]#code=[redacted]",
            "p#ss",
            &["QUERY_SECRET", "FRAGMENT_SECRET"][..],
        ),
        (
            "https://user:p?#ss@vault.example.com/path?token=QUERY_SECRET&state=ok#code=FRAGMENT_SECRET",
            "https://[redacted]@vault.example.com/path?token=QUERY_SECRET&state=ok#code=FRAGMENT_SECRET",
            "https://[redacted]@vault.example.com/path?token=[redacted]&state=ok#code=[redacted]",
            "p?#ss",
            &["QUERY_SECRET", "FRAGMENT_SECRET"][..],
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), userinfo_masked, "{url}");
        assert_eq!(super::mask_url_secrets(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(password_secret), "leaked {password_secret}: {rendered}");
        for secret in other_secrets {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
        assert!(rendered.contains("[redacted]@vault.example.com/path"), "{rendered}");
        // Debug-only masking: the stored URL stays byte-for-byte identical for
        // the server-mismatch check.
        assert_eq!(cache.server_url, url);
    }
}

#[test]
fn slash_followed_by_question_or_hash_in_userinfo_password_is_masked() {
    // An unescaped '/' may be part of the password. A '?'/'#' directly after
    // that '/' is still password data, not a query/fragment delimiter: cutting
    // the authority scan there used to hide the real '@' and leave the whole
    // credential in the diagnostic URL (cache.rs:149-210).
    for (url, expected, secret) in [
        (
            "https://user:p/?@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "p/?",
        ),
        (
            "https://user:p/#@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "p/#",
        ),
        (
            "https://user:p/ass?word@vault.example.com:8443/path",
            "https://[redacted]@vault.example.com:8443/path",
            "p/ass?word",
        ),
        (
            "https://user:p/ass#word@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "p/ass#word",
        ),
        (
            "user:p/?@vault.example.com/path",
            "[redacted]@vault.example.com/path",
            "p/?",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(
            rendered.contains("[redacted]@vault.example.com"),
            "{rendered}"
        );
        // Debug-only masking: the stored URL stays byte-for-byte identical.
        assert_eq!(cache.server_url, url);
    }
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
fn empty_valued_query_or_fragment_at_sign_after_a_confirmed_host_is_not_userinfo() {
    // Regression: `at_is_in_query` dismissed every '@' directly after a
    // '?'/'#' as password decoration (cache.rs:333-343). Once an earlier '@'
    // plus a plausible host has closed the authority, that delimiter is a
    // genuine query/fragment start even with an empty value, so the reverse
    // separator search (cache.rs:268-278) must keep the first '@' as the
    // userinfo separator instead of cutting at the query '@'.
    for (url, expected) in [
        ("https://user:p@host?@evil", "https://[redacted]@host?@evil"),
        ("https://user:p@host#@evil", "https://[redacted]@host#@evil"),
        (
            "https://user:p@host?@evil/x",
            "https://[redacted]@host?@evil/x",
        ),
        (
            "https://user:p?x@host?@evil",
            "https://[redacted]@host?@evil",
        ),
        // An '@' inside the password followed by `?@host`: the real separator
        // is still the first one, so the password tail stays redacted too.
        ("https://user:p@ss?@host", "https://[redacted]@ss?@host"),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        assert_eq!(super::mask_url_secrets(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(rendered.contains(expected), "{url}: {rendered}");
        assert!(!rendered.contains("user:p"), "{url}: {rendered}");
        // Debug masking never rewrites the stored value used by the mismatch
        // check.
        assert_eq!(cache.server_url, url);
    }

    // Control: with no completed host the adjacent delimiter is still password
    // decoration, so short/non-canonical numeric secrets remain masked.
    assert_eq!(
        super::mask_url_userinfo("https://user:12345?@host"),
        "https://[redacted]@host"
    );
    assert_eq!(
        super::mask_url_userinfo("https://user:p?@host"),
        "https://[redacted]@host"
    );
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

// Environment variables are process-global. Use the same mutex as
// `settings_tests` so an `XDG_CONFIG_HOME` swap there cannot overlap one here.
#[cfg(target_os = "linux")]
use crate::limits::env_lock;

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
    let _lock = env_lock();
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
    let _lock = env_lock();
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

#[cfg(target_os = "linux")]
#[test]
fn save_default_never_rewrites_the_legacy_path() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let cache_home = root.path().join("xdg-cache-home");
    let config_home = root.path().join("xdg-config-home");
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &cache_home);
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &config_home);

    let primary = default_path().expect("a cache directory from XDG_CACHE_HOME");
    let legacy = legacy_path().expect("a config directory from XDG_CONFIG_HOME");
    assert_ne!(primary, legacy, "the two locations must be distinct");

    let old = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&legacy, &old).unwrap();
    let legacy_bytes = std::fs::read(&legacy).unwrap();

    let replacement = SyncCache {
        user_id: "user-2".to_string(),
        ..old.clone()
    };
    save_default(&replacement).unwrap();

    // The new cache lands under the cache directory and becomes the one that
    // loads; the config-dir file is left byte-for-byte untouched, with its
    // original account still intact.
    assert_eq!(load_detailed(&primary).unwrap(), replacement);
    assert_eq!(std::fs::read(&legacy).unwrap(), legacy_bytes);
    assert_eq!(load_detailed(&legacy).unwrap(), old);
}

#[test]
fn size_limit_beats_version_mismatch_in_load_detailed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized-and-outdated.json");

    // A file that is both past MAX_CACHE_BYTES and stamped with an unknown
    // version must be classified by the size gate: it runs before parsing, so
    // the wrong version is never even inspected.
    let mut payload =
        br#"{"version":999,"user_id":"user-1","server_url":"https://vault.example.com","body":[],"created_at":null}"#.to_vec();
    payload.resize(MAX_CACHE_BYTES as usize + 1, b' ');
    std::fs::write(&path, &payload).unwrap();
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));

    // The same priority holds at the post-parse body-size gate: an oversized
    // body is rejected as too large even though the version also mismatches.
    // Build the envelope directly because `save` refuses an oversized body.
    let mut envelope =
        br#"{"version":999,"user_id":"user-1","server_url":"https://vault.example.com","body":["#
            .to_vec();
    for index in 0..=MAX_CACHE_BODY_BYTES {
        if index > 0 {
            envelope.push(b',');
        }
        envelope.push(b'0');
    }
    envelope.extend_from_slice(br#"],"created_at":null}"#);
    write_fixture(&path, &envelope);
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));
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

    // `AppError`'s PartialEq compares rendered messages, so an `assert_eq!`
    // against the plain `ParseFailed` passed for the actual, cause-carrying
    // variant. Pin the exact variant with `matches!` instead.
    assert!(matches!(
        load_with_fallback(&new, &old).err(),
        Some(CacheLoadError::ParseFailedCause(_))
    ));
}

#[test]
fn missing_primary_propagates_the_corrupt_fallback_error() {
    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("cache").join("sync-cache.json");
    let old = root.path().join("config").join("sync-cache.json");
    assert!(!new.exists(), "premise: the primary must really be absent");

    // `load_with_fallback` consults the legacy file only on NotFound
    // (cache.rs:1126-1135), but it does not swallow the fallback's own error:
    // a corrupt legacy envelope must surface as ParseFailedCause instead of
    // being downgraded to NotFound or silently ignored.
    write_fixture(&old, b"not json");
    let error = load_with_fallback(&new, &old).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::ParseFailedCause(_)),
        "the fallback's parse error must propagate unchanged: {error:?}"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the original serde error must stay reachable"
    );
    assert_eq!(cache_error_message(error), REASON_CORRUPT);
    // The read path has no repair side effects: nothing is created or rewritten.
    assert_eq!(std::fs::read(&old).unwrap(), b"not json".to_vec());
    assert!(!new.exists());

    // Control: with a readable fallback the same call succeeds, proving the
    // error above came from the fallback rather than from the missing primary.
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&old, &cache).unwrap();
    assert_eq!(load_with_fallback(&new, &old), Ok(cache));
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
    let _lock = env_lock();
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
    let _lock = env_lock();
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
    // `save` now refuses an over-large body, so place the hand-crafted envelope
    // on disk directly to exercise the *read-side* post-parse check. The
    // write-side guard is pinned by `save_rejects_an_oversized_body`.
    write_fixture(&path, &serde_json::to_vec(&cache).unwrap());
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
            matches!(
                &error,
                CacheLoadError::CacheInsecureMode {
                    actual_mode,
                    expected_mode: 0o600,
                } if *actual_mode == mode
            ),
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

#[cfg(unix)]
#[test]
fn special_mode_bits_do_not_change_the_permission_verdict() {
    use std::os::unix::fs::PermissionsExt;

    // The read-side gate masks only `0o066` (cache.rs:1040-1049), so setuid,
    // setgid and sticky bits are deliberately ignored: an owner-only file that
    // carries any of them stays readable. The same bits combined with a
    // group/other bit are still refused.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("special-bits.json");
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&path, &cache).unwrap();

    for mode in [0o4600u32, 0o2600, 0o1600, 0o6600] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let applied = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            applied & 0o7000,
            mode & 0o7000,
            "mode {mode:04o} was not applied"
        );
        assert_eq!(load_detailed(&path).unwrap(), cache, "mode {mode:04o}");
    }

    for mode in [0o4660u32, 0o2660, 0o1604] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = load_detailed(&path).unwrap_err();
        assert!(
            matches!(&error, CacheLoadError::CacheInsecureMode { .. }),
            "mode {mode:04o} must still be refused: {error:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn oversized_world_readable_file_keeps_its_size_classification() {
    use std::os::unix::fs::PermissionsExt;

    // The size gate runs before the permission gate (cache.rs:923-941), so an
    // oversized file keeps its "too large" reason even when its mode would
    // otherwise be refused. Set the mode explicitly: relying on `std::fs::write`
    // and the ambient umask would silently create 0600 under a restrictive
    // umask, making the world-readable premise false.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    std::fs::write(&path, vec![b'x'; (MAX_CACHE_BYTES + 1) as usize]).unwrap();

    for mode in [0o600u32, 0o644] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(load_detailed(&path), Err(CacheLoadError::CacheTooLarge)),
            "mode {mode:04o}: the size gate must win over the permission gate"
        );
    }

    // Control at the very same 0644 mode: a normally sized file IS refused by
    // the private-file check. This proves the permission gate is active and
    // the assertions above are about priority, not a disabled check.
    let normal = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&path, &normal).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::CacheInsecureMode { .. }),
        "mode 0644 must be unreadable for a normal-sized file: {error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);
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

#[cfg(target_os = "linux")]
#[test]
fn expired_primary_is_not_replaced_by_a_fresh_legacy_cache() {
    // Both locations hold a usable-looking cache, but only the primary is
    // expired. `load_default` falls back solely on NotFound, so the fresh
    // legacy file must not revive the offline restore: the caller sees the
    // primary's CacheExpired and the legacy file stays untouched.
    let _lock = env_lock();
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

    let fresh = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let legacy = legacy_path().expect("a config directory from XDG_CONFIG_HOME");
    assert_ne!(default_path().unwrap(), legacy, "premise: distinct paths");
    save(&legacy, &fresh).unwrap();
    let legacy_bytes = std::fs::read(&legacy).unwrap();

    assert_eq!(
        cached_sync_for_detailed("https://vault.example.com", "user-1").err(),
        Some(SyncCacheError::CacheExpired)
    );
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
    // The legacy cache is still present and readable; it was merely ignored.
    assert_eq!(std::fs::read(&legacy).unwrap(), legacy_bytes);
    assert_eq!(load_detailed(&legacy).unwrap(), fresh);
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
        matches!(&error, CacheLoadError::CacheInsecureMode { .. }),
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
fn secret_profile_keys_fold_non_ascii_separators() {
    // Stripping only ASCII '-'/'_' let a field decorated with an invisible Cf
    // character or a full-width dash keep its separator and survive redaction.
    // The fold now drops the separator families listed in `is_key_separator`.
    for key in [
        "k\u{200b}ey", // zero-width space (Cf)
        "k\u{200d}ey", // zero-width joiner (Cf)
        "k\u{00ad}ey", // soft hyphen (Cf)
        "k\u{feff}ey", // BOM (Cf)
        "private\u{200b}key",
        "private\u{ff0d}key", // full-width hyphen-minus
        "k\u{2014}ey",        // em dash
        "k\u{ff0d}ey-",       // full-width plus ASCII separator
        "private\u{3000}key", // ideographic space
        "PRIVATE\u{ff3f}KEY", // full-width low line
        "\u{200b}key\u{200b}",
    ] {
        assert!(
            super::is_secret_profile_key(key),
            "must be redacted: {key:?}"
        );
    }
    // Documented limits: symbols/marks outside the explicit separator list are
    // still part of the name, and non-ASCII letters receive no full case fold.
    for key in [
        "k.e.y",
        "k!ey",
        "ke\u{0301}y",
        "Ｋｅｙ",
        "keyId",
        "privateKeyValue",
        "\u{200b}",
        "",
    ] {
        assert!(
            !super::is_secret_profile_key(key),
            "must not be redacted: {key:?}"
        );
    }
}

#[test]
fn every_dash_and_connector_separator_is_redacted_from_keys_and_cached_body() {
    // `is_key_separator` (cache.rs:903-923) keeps a hand-maintained list of
    // dash/connector punctuation after the ASCII, `Cf` and whitespace families.
    // Pin every code point of that list: one missing arm would leave a field
    // such as `k<sep>ey` in the stored body with its key material intact.
    const DASH_SEPARATORS: &[char] = &[
        '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}', '\u{2212}',
        '\u{2e17}', '\u{2e3a}', '\u{2e3b}', '\u{301c}', '\u{30a0}', '\u{fe31}', '\u{fe32}',
        '\u{fe33}', '\u{fe34}', '\u{fe4d}', '\u{fe4e}', '\u{fe4f}', '\u{fe58}', '\u{fe63}',
        '\u{ff0d}', '\u{ff3f}',
    ];

    for &separator in DASH_SEPARATORS {
        for (base, expected) in [("k", "ey"), ("private", "key")] {
            let key = format!("{base}{separator}{expected}");
            assert!(
                super::is_secret_profile_key(&key),
                "U+{:04X} must be folded: {key:?}",
                u32::from(separator)
            );
        }
    }

    // Classification alone is not enough: the same list must also strip every
    // field from the serialized body before it reaches disk (cache.rs:958-973).
    let mut profile = serde_json::json!({ "id": "user-1" });
    let mut secrets = Vec::new();
    for (index, &separator) in DASH_SEPARATORS.iter().enumerate() {
        let key = format!("k{separator}ey");
        let secret = format!("SEPARATOR_SECRET_{index}");
        profile[key.as_str()] = serde_json::json!(secret.as_str());
        secrets.push(secret);
    }
    let body = serde_json::json!({
        "profile": profile,
        "folders": [],
        "ciphers": [],
        "object": "sync",
    });
    let cache = SyncCache::from_body(body.to_string().into_bytes(), "https://vault.example.com")
        .expect("a keyless copy of the body must still be valid sync JSON");
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    for secret in secrets {
        assert!(
            !stored.contains(secret.as_str()),
            "leaked {secret}: {stored}"
        );
    }
    assert!(cache.sync().is_ok());
}

#[test]
fn non_ascii_separated_key_is_stripped_from_the_cached_body() {
    // `from_body` writes the raw JSON after redaction, so the fold must remove
    // the field before serialization, not merely classify it correctly.
    let body = serde_json::json!({
        "profile": {
            "id": "user-1",
            "k\u{200b}ey": "ZWSP_PROFILE_KEY",
            "private\u{ff0d}key": "FULLWIDTH_PRIVATE_KEY"
        },
        "folders": [],
        "ciphers": [],
        "object": "sync"
    });
    let cache = SyncCache::from_body(body.to_string().into_bytes(), "https://vault.example.com")
        .expect("a keyless copy of the body must still be valid sync JSON");
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    assert!(!stored.contains("ZWSP_PROFILE_KEY"), "{stored}");
    assert!(!stored.contains("FULLWIDTH_PRIVATE_KEY"), "{stored}");
    // Removing an unknown field must not change the body's parseability.
    assert!(cache.sync().is_ok());
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
    let _lock = env_lock();
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
    let _lock = env_lock();
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
    // `save` now applies `from_body`'s redaction at the write boundary and
    // refuses a body that is not JSON. Place the hand-crafted envelope on disk
    // directly (as the other invalid-body tests do) so this still exercises the
    // restore path's classification instead of the write-side guard.
    let path = default_path().expect("a cache directory from XDG_CACHE_HOME");
    write_fixture(&path, &serde_json::to_vec(&broken).unwrap());

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
    let _lock = env_lock();
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
    let _lock = env_lock();
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
    // the address's colons must not invent a separator. The combined
    // host + port + path forms exercise both delimiters at once: the ':8443'
    // port and the '/path' segment must not turn the query '@' into userinfo.
    for url in [
        "https://[::1]?email=a@b",
        "https://[::1]:8443?email=a@b",
        "https://[2001:db8::1]/path?email=a@b",
        "https://[::1]:8443/path?email=a@b",
        "https://[2001:db8::1]:8443/path?email=a@b",
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
    let _lock = env_lock();
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
    let _lock = env_lock();
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
    let _lock = env_lock();
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
fn literal_hash_in_nested_userinfo_password_is_masked() {
    // A scheme-less nested authority whose password carries a *literal* '#'
    // used to be cut at the outer fragment boundary before `mask_param_pairs`
    // could recurse into it. The delimiter is now re-encoded for the nested
    // authority so the whole `user:secret@host` pair is redacted. Percent-
    // encoding the same '#' follows the same recursive path.
    let literal =
        "https://vault.example.com/login?next=user:p#NESTED_HASH_SECRET@cb.example.com/done";
    let masked = super::mask_url_secrets(literal);
    assert!(
        !masked.contains("NESTED_HASH_SECRET"),
        "literal '#' must not shield the nested password: {masked}"
    );

    let encoded =
        "https://vault.example.com/login?next=user:p%23NESTED_HASH_SECRET@cb.example.com/done";
    let masked = super::mask_url_secrets(encoded);
    assert!(!masked.contains("NESTED_HASH_SECRET"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // Debug reaches the same redactor through the stored server URL, so the
    // same limit applies to a cached entry while the stored value itself stays
    // byte-for-byte the one used for the mismatch check.
    let cache = SyncCache::from_body(body(), literal).unwrap();
    let rendered = format!("{cache:?}");
    assert!(
        !rendered.contains("NESTED_HASH_SECRET"),
        "Debug must not leak the nested password: {rendered}"
    );
    assert_eq!(cache.server_url, literal);
}

#[test]
fn genuine_fragment_delimiter_is_not_rewritten_as_a_nested_password_hash() {
    // A real fragment may contain an '@' while the query has a '?'. The old
    // re-encode condition (`tail.contains('@') && head.contains('?')`) turned
    // that delimiter into `%23`, erasing the query/fragment boundary. The
    // refined check requires a `user:secret` marker in the query value, so
    // these URLs must come back byte-for-byte unchanged.
    for url in [
        "https://vault.example.com/cb?state=ok#section@docs.example",
        "https://vault.example.com/cb?status=OK#frag@example.com",
        "https://vault.example.com/p?next=done#step@wizard.example",
    ] {
        assert_eq!(
            super::mask_url_secrets(url),
            url,
            "fragment must survive: {url}"
        );
    }

    // The credential-bearing form still takes the re-encode path: the whole
    // nested authority is redacted and no password text reaches Debug.
    let nested =
        "https://vault.example.com/login?next=user:p#NESTED_HASH_SECRET@cb.example.com/done";
    let masked = super::mask_url_secrets(nested);
    assert!(!masked.contains("NESTED_HASH_SECRET"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );
    let cache = SyncCache::from_body(body(), nested).unwrap();
    assert!(!format!("{cache:?}").contains("NESTED_HASH_SECRET"));
    assert_eq!(cache.server_url, nested);
}

#[test]
fn ambiguous_hash_is_treated_as_a_nested_password_and_fails_closed() {
    // `hash_continues_nested_password` (cache.rs:707-744) deliberately fails
    // closed: a `user:secret`-shaped query value plus a tail whose '@' is
    // followed by a plausible host is treated as a nested authority even when
    // the text is ambiguous (`?next=a:b#frag@x`). Re-encoding that '#' keeps
    // the credential inside the value instead of exposing it as fragment text.
    let head = "https://vault.example.com/login?next=a:b";
    assert!(super::hash_continues_nested_password(head, "frag@x"));
    assert!(super::hash_continues_nested_password(
        head,
        "frag@docs.example:8443/path"
    ));

    // Each half of the ambiguity is required: no user:secret marker, an
    // all-digit "secret" (a port, not a password), no query in the head, and
    // no plausible host after '@' all stay on the genuine-fragment path.
    for (plain_head, tail) in [
        ("https://vault.example.com/login?state=ok", "frag@x"),
        ("https://vault.example.com/login?next=a:12345", "frag@x"),
        ("https://vault.example.com/login/path", "frag@x"),
        (head, "frag"),
        (head, "frag@"),
    ] {
        assert!(
            !super::hash_continues_nested_password(plain_head, tail),
            "ambiguous branch must not rewrite {plain_head} #{tail}"
        );
    }

    // End to end: the ambiguity is redacted like any other credential, so a
    // sensitive key's value never reaches Debug even though the '#' was the
    // only character that looked like a fragment delimiter.
    let url = "https://vault.example.com/login?token=a:b#frag@x";
    assert_eq!(
        super::mask_url_secrets(url),
        "https://vault.example.com/login?token=[redacted]"
    );
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("a:b"), "{rendered}");
    assert!(!rendered.contains("frag@x"), "{rendered}");
    // Debug-only masking: the stored URL stays byte-for-byte identical.
    assert_eq!(cache.server_url, url);
}

#[test]
fn real_fragment_with_sensitive_key_and_colonless_value_is_not_rewritten() {
    // `hash_continues_nested_password` only re-encodes a '#' when the query
    // carries a `user:secret` marker. A genuine fragment whose text merely
    // holds an '@', combined with a sensitive key whose value has no colon,
    // must keep its delimiter (cache.rs:720-744).
    let tail = "section@docs.example";
    for head in [
        "https://vault.example.com/cb?token=PLAIN_SECRET",
        "https://vault.example.com/cb?access_token=PLAIN_SECRET&state=ok",
        "https://vault.example.com/cb?password=PLAIN_SECRET",
        "https://vault.example.com/cb?next=done",
    ] {
        assert!(
            !super::hash_continues_nested_password(head, tail),
            "genuine fragment after {head}"
        );
    }

    // End to end: the '#' stays a fragment delimiter, the sensitive query key
    // is still redacted by the ordinary query pass, and no secret reaches Debug.
    let url = "https://vault.example.com/cb?token=FRAG_TOKEN_SECRET#section@docs.example";
    assert_eq!(
        super::mask_url_secrets(url),
        "https://vault.example.com/cb?token=[redacted]#section@docs.example"
    );
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("FRAG_TOKEN_SECRET"), "{rendered}");
    assert!(rendered.contains("#section@docs.example"), "{rendered}");
    // Debug-only masking: the stored URL stays byte-for-byte identical.
    assert_eq!(cache.server_url, url);
}

#[test]
fn hash_continues_nested_password_requires_a_usable_user_and_secret() {
    // Both halves of the `user:secret` marker are checked independently
    // (cache.rs:725-733): an empty user, a user carrying '@'/'?'/'/' and an
    // empty secret must each leave a genuine fragment delimiter intact.
    let tail = "frag@cb.example.com";
    let good = "https://vault.example.com/login?next=user:NESTED_SECRET";
    assert!(
        super::hash_continues_nested_password(good, tail),
        "premise: a real user:secret marker takes the re-encode path"
    );

    for head in [
        "https://vault.example.com/login?next=:NESTED_SECRET", // empty user
        "https://vault.example.com/login?next=u@ser:NESTED_SECRET", // '@' in user
        "https://vault.example.com/login?next=u?ser:NESTED_SECRET", // '?' in user
        "https://vault.example.com/login?next=u/ser:NESTED_SECRET", // '/' in user
        "https://vault.example.com/login?next=user:",          // empty secret
    ] {
        assert!(
            !super::hash_continues_nested_password(head, tail),
            "invalid user/secret must not rewrite {head} #{tail}"
        );
    }
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
fn has_userinfo_colon_empty_value_does_not_count_as_userinfo() {
    // `has_userinfo_colon` (cache.rs:166-171) requires a non-empty value after
    // the colon, so a bare `host:` (empty port) is not mistaken for a password.
    assert!(!super::has_userinfo_colon("host:"));
    assert!(!super::has_userinfo_colon(":"));
    assert!(!super::has_userinfo_colon("user:"));
    // A canonical port is still not userinfo; a non-empty non-digit value is.
    assert!(!super::has_userinfo_colon("host:8443"));
    assert!(super::has_userinfo_colon("user:pass"));
    // A non-canonical digit run counts as a numeric password.
    assert!(super::has_userinfo_colon("user:12345"));
    assert!(super::has_userinfo_colon("user:0"));

    // Integration: the empty value keeps the path delimiter authoritative, so
    // a later '@' in the path is not reinterpreted as the userinfo separator
    // and the whole URL is not masked. Without the guard the authority would
    // be extended past '/' and the credential-looking text would be rewritten.
    let url = "https://host:/user:SECRET@evil.example.com/p";
    assert_eq!(super::mask_url_userinfo(url), url);
}

#[test]
fn authority_start_skips_non_scheme_delimiters_and_counts_leading_slashes() {
    // `authority_start` (cache.rs:133-146) only accepts `://` at the very
    // front after a valid scheme. Every other candidate is skipped by the
    // loop and the fallback counts leading '/' bytes for scheme-less values.
    assert!(!super::is_scheme("1bad"));
    assert!(!super::is_scheme("/a"));
    assert_eq!(super::authority_start("1bad://user:p@host/p"), 0);
    assert_eq!(super::authority_start("/a://b://user:p@host/p"), 1);
    assert_eq!(
        super::authority_start("//host/p?next=https://cb.example.com/done"),
        2
    );
    // Two non-scheme delimiters before the leading slash: the loop advances
    // past both and the fallback still starts the authority after '/'.
    assert_eq!(
        super::authority_start("/a://b://user:p@host/p?next=x://y"),
        1
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
fn slash_and_amp_in_nested_userinfo_password_are_masked() {
    // '/' is a legal password character too. When a nested password holds both
    // '/' and '&', treating that '/' as the end of the enclosing pair used to
    // cut the authority before the userinfo colon was visible, so the pre-pass
    // skipped the mask and the pair splitter leaked the credential
    // (cache.rs:416-482).
    let with_scheme =
        "https://vault.example.com/login?next=https://user:P/&SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(with_scheme);
    assert!(!masked.contains("P/&SS"), "{masked}");
    assert!(
        masked.contains("next=https://[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    let without_scheme =
        "https://vault.example.com/login?next=user:P/&SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(without_scheme);
    assert!(!masked.contains("P/&SS"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // Pin the pre-pass directly: the whole `user:secret` candidate is
    // rewritten, not just the tail after the '/'.
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("next=https://user:P/&SS@cb.example.com/done"),
        "next=https://[redacted]@cb.example.com/done"
    );
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("next=user:P/&SS@cb.example.com/done"),
        "next=[redacted]@cb.example.com/done"
    );
    // A harmless '@' is still copied verbatim by the same pre-pass.
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("state=a@b&token=AMP_AFTER_AT"),
        "state=a@b&token=AMP_AFTER_AT"
    );

    // Debug reaches the same path through the stored server URL; the stored
    // value itself remains byte-for-byte identical for the mismatch check.
    let cache = SyncCache::from_body(body(), with_scheme).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("P/&SS"), "{rendered}");
    assert_eq!(cache.server_url, with_scheme);
}

#[test]
fn at_signs_inside_nested_passwords_with_pair_separators_are_masked() {
    // '@' is legal inside a password. When the password also holds '&' or ';',
    // the pre-pass used to stop at the first '@', see a host containing another
    // '@', and leave the whole credential in the diagnostic URL (cache.rs:
    // 415-511). The real separator is the last '@' of the nested authority.
    let with_scheme = "https://vault.example.com/login?next=https://user:AMP_AT_P&SS@INSIDE@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(with_scheme);
    for secret in ["AMP_AT_P&SS", "INSIDE"] {
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
    }
    assert!(
        masked.contains("next=https://[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    let without_scheme = "https://vault.example.com/login?next=user:SEMI_AT_P;SS@INSIDE@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(without_scheme);
    for secret in ["SEMI_AT_P;SS", "INSIDE"] {
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
    }
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // Both separators at once, and an '@' followed by a host-looking prefix
    // inside the password: the rightmost '@' with a plausible host still wins.
    let mixed = "https://vault.example.com/login?next=https://user:MIX&P;SS@evil.example@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(mixed);
    for secret in ["MIX&P;SS", "evil.example"] {
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
    }
    assert!(
        masked.contains("next=https://[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // Pin the pre-pass directly: it rewrites the whole userinfo, not just the
    // tail after the in-password '@'.
    assert_eq!(
        super::mask_nested_userinfo_in_pairs(
            "next=https://user:AMP_AT_P&SS@INSIDE@cb.example.com/done"
        ),
        "next=https://[redacted]@cb.example.com/done"
    );
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("next=user:SEMI_AT_P;SS@INSIDE@cb.example.com/done"),
        "next=[redacted]@cb.example.com/done"
    );

    // Debug reaches the same path through the stored server URL, and the
    // stored value is still byte-for-byte the one used for the mismatch check.
    let cache = SyncCache::from_body(body(), with_scheme).unwrap();
    let rendered = format!("{cache:?}");
    for secret in ["AMP_AT_P&SS", "INSIDE"] {
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
    }
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
    let _lock = env_lock();
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

    // CacheInsecureMode: a valid envelope left group-readable is refused by the
    // private-file policy. The two modes are structured fields rather than a
    // flattened cause string, so no source chain is needed here.
    let valid = SyncCache::from_body(body(), url).unwrap();
    save_default(&valid).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let error = cached_sync_for_detailed(url, "user-1").unwrap_err();
    assert!(
        matches!(
            &error,
            SyncCacheError::CacheInsecureMode {
                actual_mode: 0o644,
                expected_mode: 0o600,
            }
        ),
        "{error:?}"
    );
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);

    // A matching, owner-only cache still restores, so the three classifications
    // above are about the specific failures rather than a broken fixture.
    save_default(&valid).unwrap();
    assert_eq!(
        cached_sync_for_detailed(url, "user-1").unwrap().user_id(),
        "user-1"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn body_without_profile_id_fails_closed_on_both_validation_paths() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    let url = "https://vault.example.com";

    // A syntactically valid body without `profile.id` is not a sync response:
    // `parse_sync` rejects it, so an envelope naming the right server/account
    // must still fail closed instead of being restored offline. The documented
    // second branch ("the resulting id cannot match a non-empty envelope") is
    // reachable after all: an empty-string id is a present `String` and parses,
    // but cannot match a real account (see the sibling test below).
    for raw in [
        br#"{"folders":[],"ciphers":[]}"#.as_slice(),
        br#"{"profile":{},"folders":[],"ciphers":[]}"#.as_slice(),
        br#"{"Profile":{},"Ciphers":[]}"#.as_slice(),
    ] {
        let cache = SyncCache {
            version: SyncCache::VERSION,
            user_id: "user-1".to_string(),
            server_url: url.to_string(),
            body: raw.to_vec(),
            created_at: None,
        };

        assert!(
            matches!(cache.sync(), Err(SyncCacheError::CacheParse(_))),
            "{raw:?}"
        );
        assert!(
            matches!(
                validate(&cache, "user-1", url),
                Err(SyncCacheError::CacheParse(_))
            ),
            "{raw:?}"
        );

        save_default(&cache).unwrap();
        assert!(
            matches!(
                cached_sync_for_detailed(url, "user-1"),
                Err(SyncCacheError::CacheParse(_))
            ),
            "{raw:?}"
        );
        assert!(cached_sync_for(url, "user-1").is_none(), "{raw:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn empty_profile_id_fails_closed_on_both_validation_paths() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    let url = "https://vault.example.com";

    // Unlike a *missing* id, an empty-string id is a present `String`: openwarden
    // accepts it and `parse_sync` succeeds. The account comparison in `validate`
    // and in `cached_sync_for_detailed` is therefore the only guard, and an
    // envelope naming a real account must fail closed on both paths.
    for raw in [
        br#"{"profile":{"id":""},"folders":[],"ciphers":[]}"#.as_slice(),
        br#"{"Profile":{"Id":""},"Ciphers":[]}"#.as_slice(),
    ] {
        let cache = SyncCache {
            version: SyncCache::VERSION,
            user_id: "user-1".to_string(),
            server_url: url.to_string(),
            body: raw.to_vec(),
            created_at: None,
        };

        // Pin the premise: parsing succeeds with an empty id, so the rejection
        // below is an account mismatch, not a parse failure.
        assert_eq!(cache.sync().unwrap().user_id(), "", "{raw:?}");
        assert_eq!(
            validate(&cache, "user-1", url),
            Err(SyncCacheError::UserMismatch),
            "{raw:?}"
        );

        save_default(&cache).unwrap();
        assert_eq!(
            cached_sync_for_detailed(url, "user-1").err(),
            Some(SyncCacheError::UserMismatch),
            "{raw:?}"
        );
        assert!(cached_sync_for(url, "user-1").is_none(), "{raw:?}");
    }
}

#[test]
fn nested_userinfo_password_with_equals_uses_the_pair_start_zero_branch() {
    // With no `?`/`#`/`/` before the '@', `pair_start == 0` and the *first*
    // '=' is the `key=` separator; later '=' characters are part of the
    // password (cache.rs:598-625). A `rfind('=')` shortcut would cut at
    // `x=1` and leave the real credential in the diagnostic URL.
    for pairs in [
        "next=user:P=SS&x=1@cb.example.com/done",
        "next=user:P=SS;x=1@cb.example.com/done",
        "next=user:a=b=c&flag=1@cb.example.com/done",
    ] {
        assert_eq!(
            super::mask_nested_userinfo_in_pairs(pairs),
            "next=[redacted]@cb.example.com/done",
            "{pairs}"
        );
    }

    let url = "https://vault.example.com/login?next=user:P=SS&x=1@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("P=SS"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");
}

#[test]
fn bare_authority_password_with_equals_is_masked_before_pair_splitting() {
    // A scheme-less authority used directly as a query value has no `key=`
    // prefix, so the '=' in its password is *not* a pair separator. The old
    // `split_once('=')` read `user:pa` as a key and copied the whole pair
    // verbatim, leaking `pa=ss` through `Debug` (cache.rs:725). The same
    // assumption in `mask_nested_userinfo_in_pairs` cut the candidate at '='
    // and skipped the pre-pass rewrite (cache.rs:610-625).
    let pairs = "user:pa=ss@cb.example.com/done";
    assert_eq!(
        super::mask_param_pairs(pairs, 0),
        "[redacted]@cb.example.com/done"
    );

    // An '&' inside the password used to be split into separate pairs before
    // the authority masker could see the whole `user:secret` marker.
    let with_separator = "user:p&a=b@cb.example.com/done";
    assert!(
        super::nested_authority_with_userinfo(with_separator),
        "premise: this is an authority with userinfo"
    );
    assert_eq!(
        super::mask_nested_userinfo_in_pairs(with_separator),
        "[redacted]@cb.example.com/done"
    );

    for (url, expected) in [
        (
            "https://vault.example.com/login?user:pa=ss@cb.example.com/done",
            "https://vault.example.com/login?[redacted]@cb.example.com/done",
        ),
        (
            "https://vault.example.com/login?user:p&a=b@cb.example.com/done",
            "https://vault.example.com/login?[redacted]@cb.example.com/done",
        ),
    ] {
        let masked = super::mask_url_secrets(url);
        assert_eq!(masked, expected, "{url}");
        assert!(!masked.contains("pa=ss"), "{masked}");
        assert!(!masked.contains("a=b"), "{masked}");
    }

    // `Debug` uses the same masker; the stored URL stays byte-for-byte intact
    // for the server-mismatch check.
    let url = "https://vault.example.com/login?user:pa=ss@cb.example.com/done";
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("pa=ss"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn bare_authority_with_equals_also_masks_a_second_query_after_the_host() {
    // The bare-authority branch used to `continue` right after
    // `mask_url_userinfo`, which only rewrites the userinfo and copies the rest
    // verbatim. A scheme-less authority followed by a second '?'
    // (`?user:pa=ss@host?token=SECRET`) therefore left its own secret-bearing
    // query unmasked. Both the authority password and the second query key must
    // be redacted, while harmless parameters survive.
    let pairs = "user:pa=ss@cb.example.com/done?token=SECOND_QUERY_SECRET&state=ok";
    assert_eq!(
        super::mask_param_pairs(pairs, 0),
        "[redacted]@cb.example.com/done?token=[redacted]&state=ok"
    );

    let url = "https://vault.example.com/login?user:pa=ss@cb.example.com/done?token=SECOND_QUERY_SECRET&state=ok";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("pa=ss"), "{masked}");
    assert!(!masked.contains("SECOND_QUERY_SECRET"), "{masked}");
    assert_eq!(
        masked,
        "https://vault.example.com/login?[redacted]@cb.example.com/done?token=[redacted]&state=ok"
    );

    // `Debug` uses the same masker; the stored URL stays byte-for-byte intact
    // for the server-mismatch check.
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("pa=ss"), "{rendered}");
    assert!(!rendered.contains("SECOND_QUERY_SECRET"), "{rendered}");
    assert!(rendered.contains("token=[redacted]"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn bare_authority_equals_redescent_stops_at_the_mask_depth_limit() {
    // The bare-authority-with-'=' branch of `mask_param_pairs` masks the
    // userinfo and then descends once more (cache.rs:708-723) so a second
    // query behind the host is redacted too. That descent shares the
    // MAX_MASK_DEPTH cap with the ordinary nested-URL branch: at the cap the
    // whole tail becomes `[redacted]` instead of being rendered, so nothing
    // behind the limit can reach a diagnostic line.
    assert_eq!(super::MAX_MASK_DEPTH, 8);
    let leaf = "https://leaf.example.com/p?user:pa=ss@cb.example.com/done";

    // Seven `next=` wrappers place the leaf at depth 7, just below the cap:
    // the branch still descends and keeps the redacted authority's host.
    let mut below = leaf.to_string();
    for layer in 0..7 {
        below = format!("https://layer{layer}.example.com/next?next={below}");
    }
    let below_masked = super::mask_url_secrets(&below);
    assert!(
        below_masked.contains("leaf.example.com/p?[redacted]@cb.example.com/done"),
        "{below_masked}"
    );
    assert!(!below_masked.contains("pa=ss"), "{below_masked}");

    // At the cap, the bare-authority branch must redact the whole pair
    // instead of descending again: neither the password nor the authority
    // host may be rendered. Drive the branch directly with depth=8 so the
    // guard is exercised independently of the `next=` recursion depth.
    let at_cap = super::mask_param_pairs(leaf, super::MAX_MASK_DEPTH);
    assert_eq!(at_cap, "[redacted]");
    for hidden in ["pa=ss", "cb.example.com", "leaf.example.com"] {
        assert!(!at_cap.contains(hidden), "leaked {hidden}: {at_cap}");
    }
    // One level below the cap the branch still descends and keeps the host.
    let below_cap = super::mask_param_pairs(leaf, super::MAX_MASK_DEPTH - 1);
    assert_eq!(below_cap, "https://leaf.example.com/p?[redacted]");
}

#[test]
fn nested_hash_password_coexists_with_a_real_fragment() {
    // The nested authority's password carries a literal '#', while the URL
    // also has a genuine fragment with a sensitive key. Only the first '#'
    // may be re-encoded as `%23`; the second must stay a fragment delimiter so
    // both secrets are redacted independently (cache.rs:834-845).
    let url = "https://vault.example.com/login?next=user:p#NESTED_HASH_SECRET@cb.example.com#code=FRAGMENT_SECRET";
    let head = "https://vault.example.com/login?next=user:p";
    let tail = "NESTED_HASH_SECRET@cb.example.com#code=FRAGMENT_SECRET";
    assert!(
        super::hash_continues_nested_password(head, tail),
        "premise: the first '#' belongs to the nested password"
    );
    assert_eq!(
        super::mask_url_secrets(url),
        "https://vault.example.com/login?next=[redacted]@cb.example.com#code=[redacted]"
    );

    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("NESTED_HASH_SECRET"), "{rendered}");
    assert!(!rendered.contains("FRAGMENT_SECRET"), "{rendered}");
    assert!(rendered.contains("#code=[redacted]"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn leading_slash_scheme_less_authority_userinfo_is_masked() {
    // A scheme-less nested authority can reach the recursive masker with a
    // leading '/': `?next=%2Fuser%3ASECRET%40host%2Fp` decodes to
    // `/user:SECRET@host/p`. `nested_authority_with_userinfo` correctly sends
    // it down the recursive path, but the old `authority_start` treated that
    // single '/' as the end of the authority, so `mask_url_userinfo` saw an
    // empty scan and left the credential untouched (cache.rs:81-107, 132-157).
    let nested = "/user:LEADING_SLASH_SECRET@cb.example.com/done";
    assert!(
        super::nested_authority_with_userinfo(nested),
        "this value must take the nested-authority recursion path"
    );
    assert_eq!(
        super::authority_start("/user:p@host/p"),
        1,
        "the authority starts after the leading '/'"
    );
    assert_eq!(super::authority_start("//user:p@host/p"), 2);
    assert_eq!(super::authority_start("user:p@host/p"), 0);

    assert_eq!(
        super::mask_url_userinfo("/user:SECRET@host.example.com/p"),
        "/[redacted]@host.example.com/p"
    );
    assert_eq!(
        super::mask_url_userinfo("/user:SECRET@host.example.com"),
        "/[redacted]@host.example.com"
    );
    // A path-absolute value without userinfo stays verbatim; an '@' in its
    // query is still not promoted to a userinfo separator.
    assert_eq!(
        super::mask_url_userinfo("/vault.example.com/p?email=a@b.example"),
        "/vault.example.com/p?email=a@b.example"
    );

    // The same value reaches the recursive masker directly when the query
    // carries it literally, not only through percent-decoding.
    let literal =
        "https://vault.example.com/login?next=/user:LITERAL_SLASH_SECRET@cb.example.com/done";
    let masked = super::mask_url_secrets(literal);
    assert!(!masked.contains("LITERAL_SLASH_SECRET"), "{masked}");
    assert!(
        masked.contains("next=/[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // The recursive path: decoding the leading slash must not defeat masking.
    let encoded = "https://vault.example.com/login?next=%2Fuser%3ALEADING_SLASH_SECRET%40cb.example.com%2Fdone&state=ok";
    let masked = super::mask_url_secrets(encoded);
    assert!(!masked.contains("LEADING_SLASH_SECRET"), "{masked}");
    assert!(
        masked.contains("next=/[redacted]@cb.example.com/done"),
        "{masked}"
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // Debug reaches the same recursive masker for the stored server URL, and
    // the stored value remains byte-for-byte identical for the mismatch check.
    let cache = SyncCache::from_body(body(), encoded).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("LEADING_SLASH_SECRET"), "{rendered}");
    assert!(
        rendered.contains("next=/[redacted]@cb.example.com/done"),
        "{rendered}"
    );
    assert_eq!(cache.server_url, encoded);
}

#[test]
fn trailing_pair_separator_preserves_the_empty_final_pair() {
    // `mask_param_pairs` keeps the original delimiter and always pushes the
    // trailing slice, even when a query ends with `&`/`;` and that final pair
    // is empty (cache.rs:441-453). The empty pair must survive verbatim rather
    // than being dropped, duplicated, or turned into a stray rewrite.
    assert_eq!(
        super::mask_param_pairs("a=1&token=SECRET&", 0),
        "a=1&token=[redacted]&"
    );
    assert_eq!(super::mask_param_pairs("a=1&", 0), "a=1&");
    assert_eq!(super::mask_param_pairs("&", 0), "&");
    assert_eq!(
        super::mask_param_pairs("token=SECRET;", 0),
        "token=[redacted];"
    );
    assert_eq!(super::mask_param_pairs(";;", 0), ";;");
    assert_eq!(super::mask_param_pairs("a=1&;", 0), "a=1&;");

    // The same branch is reached through the public query and fragment masks.
    let url = "https://vault.example.com/p?token=SECRET&state=ok&";
    assert_eq!(
        super::mask_url_secrets(url),
        "https://vault.example.com/p?token=[redacted]&state=ok&"
    );
    let fragment = "https://vault.example.com/cb#code=FRAGMENT_SECRET;";
    assert_eq!(
        super::mask_url_secrets(fragment),
        "https://vault.example.com/cb#code=[redacted];"
    );
}

#[test]
fn percent_decode_advances_by_whole_non_ascii_characters() {
    // A non-'%' character is copied and the remaining slice advances by
    // `first.len_utf8()` (cache.rs:334-350). Advancing by one byte would slice
    // inside a multibyte scalar and panic, so each case puts a valid escape
    // directly after a multibyte character: both the byte advance and the
    // decoded result are observable.
    assert_eq!(super::percent_decode("あ%41"), "あA");
    assert_eq!(super::percent_decode("あい%3F%23"), "あい?#");
    assert_eq!(super::percent_decode("🔑%74oken"), "🔑token");
    assert_eq!(super::percent_decode("%41あ%42"), "AあB");
    // A multibyte character between incomplete escapes keeps both literal.
    assert_eq!(super::percent_decode("%2あ%"), "%2あ%");
}

#[test]
fn save_rejects_an_oversized_body_without_touching_the_file() {
    // `save` (cache.rs:867+) now mirrors the read-side body cap: an oversized
    // body is refused before serialization or any filesystem write, so a file
    // this build could never load is never created.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    let oversized = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: vec![b'x'; MAX_CACHE_BODY_BYTES + 1],
        created_at: None,
    };

    let error = save(&path, &oversized).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("MAX_CACHE_BODY_BYTES"),
        "{error}"
    );
    assert!(!path.exists(), "an oversized cache must not be persisted");

    // Control: a normal body still saves and loads. The exact numeric boundary
    // of the same cap is already pinned by
    // `from_body_rejects_an_oversized_raw_body` on the `from_body` side.
    let normal = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    assert!(normal.body.len() <= MAX_CACHE_BODY_BYTES);
    save(&path, &normal).unwrap();
    assert_eq!(load_detailed(&path).unwrap(), normal);
}

#[test]
fn unescaped_slash_in_a_password_is_masked_before_the_path_boundary() {
    // An unescaped '/' is legal inside userinfo. Stopping the authority at the
    // first '/' used to leave the password tail in a diagnostic URL. The
    // `user:secret` marker plus an `@` with a plausible host after the '/'
    // identifies such a slash as part of the password (cache.rs:145-192).
    for (url, expected) in [
        (
            "https://user:p/ss@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
        ),
        (
            "https://user:p/a/b@vault.example.com:8443/path?state=ok",
            "https://[redacted]@vault.example.com:8443/path?state=ok",
        ),
        (
            "user:p/ss@vault.example.com",
            "[redacted]@vault.example.com",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains("p/ss"), "{rendered}");
        assert!(!rendered.contains("p/a/b"), "{rendered}");
        assert!(
            rendered.contains("[redacted]@vault.example.com"),
            "{rendered}"
        );
        assert_eq!(cache.server_url, url, "masking is Debug-only");
    }

    // A '/' in an ordinary path still closes the authority: an '@' in its
    // query must not be promoted to a userinfo separator.
    let plain = "https://vault.example.com/path?q=a@b";
    assert_eq!(super::mask_url_userinfo(plain), plain);
    // A numeric port before the '/' is not a password marker either.
    let with_port = "https://vault.example.com:8443/path?email=a@b";
    assert_eq!(super::mask_url_userinfo(with_port), with_port);
}

#[test]
fn oversized_primary_does_not_fall_back_to_legacy() {
    // `load_with_fallback` (cache.rs:792-801) falls back to the legacy file
    // only on `CacheLoadError::NotFound`. A primary that exists but is too
    // large must keep its own classification, even when a perfectly good
    // legacy cache sits next to it; silently reviving stale legacy data is
    // exactly what the migration rule forbids.
    let root = tempfile::tempdir().unwrap();
    let new = root.path().join("cache").join("sync-cache.json");
    let old = root.path().join("config").join("sync-cache.json");
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    let legacy = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&old, &legacy).unwrap();
    let legacy_bytes = std::fs::read(&old).unwrap();

    // `save` refuses an oversized body, so write the envelope directly. An
    // 8 MiB `body` stays under MAX_CACHE_BYTES (the file-size gate) and is
    // rejected by the post-parse body check (cache.rs:907-909) instead.
    let oversized = SyncCache {
        body: vec![b'x'; MAX_CACHE_BODY_BYTES + 1],
        ..legacy.clone()
    };
    write_fixture(&new, &serde_json::to_vec(&oversized).unwrap());
    assert!(matches!(
        load_with_fallback(&new, &old).err(),
        Some(CacheLoadError::CacheTooLarge)
    ));
    assert_eq!(std::fs::read(&old).unwrap(), legacy_bytes);
    assert_eq!(load_detailed(&old).unwrap(), legacy);

    // Control: the fallback still applies when the primary is genuinely
    // absent, so the assertion above is about the size classification rather
    // than a disabled fallback.
    std::fs::remove_file(&new).unwrap();
    assert_eq!(load_with_fallback(&new, &old), Ok(legacy));
}

#[test]
fn parse_failed_cause_keeps_the_serde_error_as_source() {
    // An envelope that is not JSON reaches `load_detailed`'s
    // `ParseFailedCause` arm (cache.rs:905-906), which must keep the original
    // serde error reachable through `Error::source()` instead of flattening it
    // into the family message.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken-envelope.json");
    write_fixture(&path, b"not json");

    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::ParseFailedCause(_)),
        "{error:?}"
    );
    let source_text = std::error::Error::source(&error)
        .expect("the serde parse error must stay reachable")
        .to_string();
    assert!(
        !source_text.is_empty(),
        "the source must carry the parser text"
    );
    assert_ne!(source_text, error.message());
    assert_eq!(cache_error_message(error), REASON_CORRUPT);

    // The plain sibling still reports no source: `source()` is only wired for
    // the `Cause` variants (error.rs:415-439).
    let plain = CacheLoadError::ParseFailed;
    assert!(std::error::Error::source(&plain).is_none());
    assert_eq!(cache_error_message(plain), REASON_CORRUPT);
}

#[test]
fn save_redacts_profile_keys_at_the_write_boundary() {
    // A caller can construct `SyncCache` directly (there is no production
    // writer), bypassing `from_body`'s redactor. `save` must apply the same
    // recursive redaction before serializing, without mutating the caller's
    // value (it takes `&SyncCache`).
    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&cache.body).unwrap();
    document["profile"]["key"] = serde_json::json!("WRITE_PROFILE_KEY");
    document["profile"]["privateKey"] = serde_json::json!("WRITE_PROFILE_PRIVATE_KEY");
    document["folders"][0]["Key"] = serde_json::json!("WRITE_FOLDER_KEY");
    document["ciphers"] = serde_json::json!([{
        "id": "c1",
        "type": 1,
        "name": null,
        "revisionDate": "2024-01-01T00:00:00Z",
        "login": { "uris": [] },
        "key": "WRITE_CIPHER_KEY",
    }]);
    cache.body = serde_json::to_vec(&document).unwrap();
    let before = cache.body.clone();
    assert!(String::from_utf8_lossy(&cache.body).contains("WRITE_PROFILE_KEY"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("redacted-on-save.json");
    save(&path, &cache).expect("a key-bearing body must be sanitized, not refused");
    let on_disk = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    for secret in [
        "WRITE_PROFILE_KEY",
        "WRITE_PROFILE_PRIVATE_KEY",
        "WRITE_FOLDER_KEY",
        "WRITE_CIPHER_KEY",
    ] {
        assert!(!on_disk.contains(secret), "leaked {secret}: {on_disk}");
    }
    assert!(!on_disk.contains("\"privateKey\""), "{on_disk}");
    assert!(!on_disk.contains("\"key\""), "{on_disk}");
    // The caller's in-memory cache is untouched by the write-boundary copy.
    assert_eq!(cache.body, before);

    // The saved body is exactly what `from_body` would have stored, and it is
    // still a usable offline sync body.
    let loaded = load_detailed(&path).unwrap();
    let via_constructor =
        SyncCache::from_body(before, "https://vault.example.com").expect("valid sync body");
    assert_eq!(loaded.body, via_constructor.body);
    assert_ne!(loaded.body, cache.body);
    assert!(loaded.sync().is_ok());

    // A body that cannot be redacted is refused before touching the file.
    let invalid = SyncCache {
        body: b"not json".to_vec(),
        ..cache
    };
    let invalid_path = dir.path().join("invalid-on-save.json");
    assert_eq!(
        save(&invalid_path, &invalid).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(!invalid_path.exists());
}

#[test]
fn redacted_round_trip_keeps_encrypted_logins_decryptable() {
    // Redaction runs twice on this path (`from_body` and `save`). Both passes
    // remove key fields; neither may damage the ciphertext of a login whose
    // fields are encrypted directly under the user key (no per-item key, which
    // would itself be redacted). The on-disk copy must still decrypt.
    let user_bytes = [0x1au8; 64];
    let symmetric =
        openwarden::SymmetricKey::from_bytes(&user_bytes).expect("a 64-byte symmetric key");
    let enc = |plain: &[u8]| {
        openwarden::EncString::encrypt(&symmetric, plain)
            .expect("a field must encrypt")
            .to_string()
    };
    let raw = serde_json::json!({
        "profile": {
            "id": "user-1",
            "key": "PROFILE_KEY_MUST_BE_STRIPPED",
            "privateKey": "PRIVATE_KEY_MUST_BE_STRIPPED",
        },
        "folders": [],
        "ciphers": [{
            "id": "login-1",
            "type": 1,
            "name": enc(b"Redacted Login"),
            "login": {
                "username": enc(b"alice@example.com"),
                "password": enc(b"correct horse battery staple"),
                "uris": [{ "uri": enc(b"https://example.com") }],
            },
            "revisionDate": "2024-01-01T00:00:00Z",
            "key": "CIPHER_KEY_MUST_BE_STRIPPED",
        }],
    });

    let cache = SyncCache::from_body(raw.to_string().into_bytes(), "https://vault.example.com")
        .expect("a keyless copy of the body must still be valid sync JSON");
    let stored = String::from_utf8(cache.body.clone()).unwrap();
    for secret in [
        "PROFILE_KEY_MUST_BE_STRIPPED",
        "PRIVATE_KEY_MUST_BE_STRIPPED",
        "CIPHER_KEY_MUST_BE_STRIPPED",
    ] {
        assert!(!stored.contains(secret), "leaked {secret}: {stored}");
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync-cache.json");
    save(&path, &cache).unwrap();
    let loaded = load_detailed(&path).unwrap();
    assert_eq!(loaded, cache, "the redaction at save must be idempotent");

    // Decrypt from the reloaded envelope, not from the caller's original body.
    let sync = loaded.sync().expect("the redacted body must still parse");
    let user_key = openwarden::UserKey::from_bytes(&user_bytes).unwrap();
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(user_key, state);
    vault.apply_sync(sync).expect("the keyless sync must apply");
    let model = crate::vault_sync::import_logins(&vault).expect("the login must decrypt");

    assert_eq!(model.items.len(), 1);
    let item = &model.items[0];
    assert_eq!(item.name, "Redacted Login");
    let (username, password, _totp, uris) = item.login().expect("the item is a login");
    assert_eq!(username, "alice@example.com");
    assert_eq!(password, "correct horse battery staple");
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, "https://example.com");
}

#[test]
fn max_cache_body_bytes_boundary_is_accepted_by_from_body_save_and_load() {
    // The cap is inclusive: a valid sync body padded to exactly
    // MAX_CACHE_BODY_BYTES passes the raw-body gate, the write gate and the
    // post-parse read gate. One byte past it is still refused on write.
    let base = String::from_utf8(body()).unwrap();
    let padding = MAX_CACHE_BODY_BYTES - base.len();
    let at_limit = format!("{base}{}", " ".repeat(padding)).into_bytes();
    assert_eq!(at_limit.len(), MAX_CACHE_BODY_BYTES);

    let from_constructor = SyncCache::from_body(at_limit.clone(), "https://vault.example.com")
        .expect("the exact raw-body boundary must be accepted");
    assert_eq!(from_constructor.user_id, "user-1");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exact-body.json");
    let exact = SyncCache {
        body: at_limit.clone(),
        ..from_constructor
    };
    save(&path, &exact).expect("the exact write boundary must be accepted");
    assert!(path.is_file());

    // Read side: an envelope whose stored body is exactly at the cap loads.
    let read_path = dir.path().join("exact-read.json");
    write_fixture(&read_path, &serde_json::to_vec(&exact).unwrap());
    assert_eq!(
        load_detailed(&read_path).unwrap().body.len(),
        MAX_CACHE_BODY_BYTES
    );

    let mut over = exact;
    over.body.push(b' ');
    assert_eq!(over.body.len(), MAX_CACHE_BODY_BYTES + 1);
    let over_path = dir.path().join("over-body.json");
    assert_eq!(
        save(&over_path, &over).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert!(!over_path.exists());
}

#[test]
fn simultaneous_server_and_user_mismatch_prefers_server_in_validate() {
    // `validate` (cache.rs:1073-1085) checks the server before the account, so
    // a cache that disagrees on both must report the server reason.
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let error = validate(&cache, "user-2", "https://other.example.com").unwrap_err();
    assert!(
        matches!(&error, SyncCacheError::ServerMismatch),
        "{error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_SERVER_MISMATCH);

    // Even when the envelope's user id also disagrees with the parsed body,
    // the server check still wins before either account comparison runs.
    let inconsistent = SyncCache {
        user_id: "envelope-user".to_string(),
        ..cache
    };
    let error = validate(&inconsistent, "user-2", "https://other.example.com").unwrap_err();
    assert!(
        matches!(&error, SyncCacheError::ServerMismatch),
        "{error:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn simultaneous_server_and_user_mismatch_prefers_server_on_restore() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    save_default(&SyncCache::from_body(body(), "https://vault.example.com").unwrap()).unwrap();

    let error = cached_sync_for_detailed("https://other.example.com", "user-2").unwrap_err();
    assert!(
        matches!(&error, SyncCacheError::ServerMismatch),
        "{error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_SERVER_MISMATCH);
    assert!(cached_sync_for("https://other.example.com", "user-2").is_none());

    // The other arm stays reachable: with the server matching, the wrong
    // account still reports UserMismatch.
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-2"),
        Err(SyncCacheError::UserMismatch)
    ));
}

#[test]
fn save_at_max_body_size_documents_the_pretty_expansion_limit() {
    // Size-limit consistency (documented on MAX_CACHE_BYTES in cache.rs):
    // `save` accepts a body of exactly MAX_CACHE_BODY_BYTES, but it serializes
    // `body: Vec<u8>` with `to_vec_pretty`, which emits one indented number per
    // byte (~8 bytes per byte). The resulting file exceeds MAX_CACHE_BYTES, so
    // `load_detailed` refuses the very file `save` just wrote. Build the body
    // from a padded JSON string: the redaction pass reparses/re-serializes it
    // compactly without shrinking it, so the stored body stays at the cap.
    const TEMPLATE: &str = r#"{"pad":""}"#;
    let body = format!(
        r#"{{"pad":"{}"}}"#,
        "A".repeat(MAX_CACHE_BODY_BYTES - TEMPLATE.len())
    )
    .into_bytes();
    assert_eq!(body.len(), MAX_CACHE_BODY_BYTES);
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).is_ok(),
        "the fixture must be valid JSON for the write-side redactor"
    );
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body,
        created_at: None,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("max-body-pretty.json");
    save(&path, &cache).expect("the write-side body cap is inclusive");

    let disk_len = std::fs::metadata(&path).unwrap().len();
    assert!(
        disk_len > MAX_CACHE_BYTES,
        "documented pretty-expansion limit: {disk_len} bytes written for a \
         {MAX_CACHE_BODY_BYTES}-byte body (cap {MAX_CACHE_BYTES})"
    );
    // The file-size gate runs before parsing, so the oversized file is refused
    // with the size reason rather than a parse error.
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));
    assert!(load(&path).is_none());

    // Control: the same body inside a compact envelope is under the file cap
    // and loads, proving the failure above is the pretty expansion and not
    // the body cap or a malformed fixture.
    let compact = dir.path().join("max-body-compact.json");
    write_fixture(&compact, &serde_json::to_vec(&cache).unwrap());
    let loaded = load_detailed(&compact).expect("compact envelope stays under the file cap");
    assert_eq!(loaded.body.len(), MAX_CACHE_BODY_BYTES);
    assert_eq!(loaded, cache);
}

#[test]
fn file_exactly_at_max_cache_bytes_is_loaded_and_one_byte_over_is_not() {
    // The file-size gate in `load_detailed` is `metadata.len() > MAX_CACHE_BYTES`
    // (cache.rs:908-913): exactly at the cap must pass, one byte past must not.
    // Trailing spaces are valid JSON whitespace, so they can pad a real cache
    // to the exact boundary without changing its parsed value.
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let mut bytes = serde_json::to_vec(&cache).unwrap();
    assert!((bytes.len() as u64) < MAX_CACHE_BYTES, "fixture premise");
    bytes.resize(MAX_CACHE_BYTES as usize, b' ');
    assert_eq!(bytes.len() as u64, MAX_CACHE_BYTES);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exact-file-size.json");
    write_fixture(&path, &bytes);
    assert_eq!(load_detailed(&path).unwrap(), cache);

    bytes.push(b' ');
    write_fixture(&path, &bytes);
    assert_eq!(bytes.len() as u64, MAX_CACHE_BYTES + 1);
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn restore_guard_priority_puts_identity_checks_before_expiry() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    // One file that is expired AND belongs to another server AND another
    // account. `cached_sync_for_detailed` checks the envelope server first
    // (cache.rs:1066-1078), then the envelope account, then the clock.
    let expired = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: body(),
        created_at: Some(1),
    };
    save_default(&expired).unwrap();

    assert!(matches!(
        cached_sync_for_detailed("https://other.example.com", "user-2"),
        Err(SyncCacheError::ServerMismatch)
    ));
    // Matching server but wrong account still wins over the expiry check.
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-2"),
        Err(SyncCacheError::UserMismatch)
    ));
    // Only once both identity checks pass does the expired marker surface.
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-1"),
        Err(SyncCacheError::CacheExpired)
    ));
    assert!(cached_sync_for("https://vault.example.com", "user-1").is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn restore_guard_priority_puts_expiry_before_body_parse_and_body_user_check() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    let path = default_path().expect("a cache directory from XDG_CACHE_HOME");

    // Expired + a body that no longer parses. `save` refuses a non-JSON body,
    // so write the envelope directly; the clock check (cache.rs:1075-1077)
    // must fire before `cache.sync()` (cache.rs:1079).
    let broken = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: "https://vault.example.com".to_string(),
        body: b"not json".to_vec(),
        created_at: Some(1),
    };
    write_fixture(&path, &serde_json::to_vec(&broken).unwrap());
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-1"),
        Err(SyncCacheError::CacheExpired)
    ));

    // Expired + a parseable body naming a different account. The envelope id
    // matches the caller, so the body-id check (cache.rs:1080-1082) is the only
    // competing guard; expiry still comes first.
    let mismatched = SyncCache {
        body: br#"{"profile":{"id":"body-user"},"folders":[],"ciphers":[]}"#.to_vec(),
        ..broken
    };
    write_fixture(&path, &serde_json::to_vec(&mismatched).unwrap());
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-1"),
        Err(SyncCacheError::CacheExpired)
    ));

    // Control: with a fresh timestamp the very same envelope reaches the
    // body-id check and reports UserMismatch instead.
    let fresh = SyncCache {
        created_at: None,
        ..mismatched
    };
    write_fixture(&path, &serde_json::to_vec(&fresh).unwrap());
    assert!(matches!(
        cached_sync_for_detailed("https://vault.example.com", "user-1"),
        Err(SyncCacheError::UserMismatch)
    ));
}

#[test]
fn wrong_typed_envelope_fields_are_a_parse_failed_cause() {
    // A sibling test pins the "not JSON at all" arm of `load_detailed`. This
    // one pins the same `ParseFailedCause` classification for a syntactically
    // valid envelope whose fields have the wrong JSON types: serde must reject
    // the whole value, the parser text must remain reachable through
    // `Error::source()`, and the status reason must stay "corrupt" rather than
    // being mislabelled as an outdated version or an oversized body.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrong-typed-envelope.json");
    let envelope = br#"{
        "version": "1",
        "user_id": 42,
        "server_url": false,
        "body": "not-an-array",
        "created_at": "yesterday"
    }"#;
    write_fixture(&path, envelope);

    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::ParseFailedCause(_)),
        "{error:?}"
    );
    let source = std::error::Error::source(&error)
        .expect("the serde type error must stay reachable")
        .to_string();
    assert!(!source.is_empty());
    assert_ne!(source, error.message());
    assert_eq!(cache_error_message(error), REASON_CORRUPT);
}

#[test]
fn multiple_ipv6_literals_are_all_removed_before_the_colon_checks() {
    // `without_ipv6_literals` loops over every `[...]` pair (cache.rs:268-281).
    // Removing only the first literal leaves a later address's colons in the
    // text, where they can be mistaken for a `user:password` marker and hide a
    // real credential in a diagnostic URL.
    let text = "user:SECRET@[2001:db8::1]:8443/[fe80::2]?email=a@b";
    assert_eq!(
        super::without_ipv6_literals(text),
        "user:SECRET@:8443/?email=a@b"
    );
    // Three literals, including an adjacent pair and one followed by a port.
    assert_eq!(
        super::without_ipv6_literals("[::1][::2] tail [2001:db8::3]:443 end"),
        " tail :443 end"
    );
    // No literal: the value is copied unchanged.
    let plain = "user:SECRET@vault.example.com:8443?email=a@b";
    assert_eq!(super::without_ipv6_literals(plain), plain);

    // With both literals present, the userinfo is still masked and the query
    // '@' is still left alone; neither address is rewritten by the masker.
    let url = "https://user:SECRET@[2001:db8::1]:8443/[fe80::2]?email=a@b";
    assert_eq!(
        super::mask_url_userinfo(url),
        "https://[redacted]@[2001:db8::1]:8443/[fe80::2]?email=a@b"
    );
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(
        rendered.contains("[redacted]@[2001:db8::1]:8443"),
        "{rendered}"
    );
    assert!(rendered.contains("[fe80::2]"), "{rendered}");
    assert_eq!(cache.server_url, url, "masking is Debug-only");
}

#[test]
fn file_metadata_failure_is_classified_as_read_failed_cause() {
    use crate::error::BoxedCause;

    // `load_detailed` opens the cache file and then calls `File::metadata`
    // (cache.rs:917-927); any error there is mapped to `ReadFailedCause` with
    // the io error retained as the typed cause. There is no injected seam for
    // `fstat` on an already-open fd, so unlike the neighbouring `File::open`
    // ENOTDIR case the OS branch cannot be forced through the public API. Pin
    // the classification applied to such an error instead of implying coverage
    // of the syscall itself.
    let io_error = std::io::Error::other("simulated File::metadata failure");
    let error: CacheLoadError = CacheLoadError::ReadFailedCause(BoxedCause::new(io_error));
    assert!(matches!(&error, CacheLoadError::ReadFailedCause(_)));
    assert_eq!(
        std::error::Error::source(&error)
            .expect("the io cause must stay reachable")
            .to_string(),
        "simulated File::metadata failure"
    );
    assert_eq!(cache_error_message(error.clone()), REASON_UNREADABLE);
    assert_eq!(
        super::cache_restore_status(error),
        Some("同期に失敗しました（キャッシュを読み込めません）")
    );
}

#[test]
fn all_digit_password_with_a_question_or_hash_is_masked() {
    // Regression: `at_is_in_query` treated every colon with an all-digit
    // value as `host:port`, so `12345?` / `12345#` at the end of a password
    // looked like a port followed by a query and the whole credential stayed
    // in the diagnostic URL. A delimiter directly before the '@' has no query
    // text after it and must stay part of the password.
    for (url, expected, secret) in [
        (
            "https://user:12345?@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "12345?",
        ),
        (
            "https://user:12345#@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "12345#",
        ),
        (
            "https://user:9876543210?@vault.example.com:8443",
            "https://[redacted]@vault.example.com:8443",
            "9876543210?",
        ),
        (
            "user:12345?@vault.example.com/path",
            "[redacted]@vault.example.com/path",
            "12345?",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(
            rendered.contains("[redacted]@vault.example.com"),
            "{rendered}"
        );
        // Debug-only masking: the stored URL stays byte-for-byte identical.
        assert_eq!(cache.server_url, url);
    }

    // The real query/fragment after the host is still redacted by the full
    // masker, and a genuine port + query '@' remains untouched (it has query
    // text between the delimiter and the '@').
    let url = "https://user:12345?@vault.example.com/path?token=QUERY_SECRET#code=FRAGMENT_SECRET";
    let masked = super::mask_url_secrets(url);
    assert!(
        masked.contains("[redacted]@vault.example.com/path"),
        "{masked}"
    );
    assert!(masked.contains("token=[redacted]"), "{masked}");
    assert!(masked.contains("code=[redacted]"), "{masked}");
    assert!(!masked.contains("12345?"), "{masked}");
    for url in [
        "https://host:8443?email=a@b",
        "https://vault.example.com:8443#frag@x",
    ] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[test]
fn numeric_only_password_in_a_scheme_less_nested_authority_is_masked() {
    // A nested value `user:12345@host` has none of the `?`, `#` or `//` that
    // normally trigger recursion. The old authority detector rejected every
    // all-digit colon value as a `host:port`, so this credential reached Debug
    // verbatim. Once '@' and a plausible host are present, the digits are a
    // password, not a port (cache.rs:331-354).
    for value in [
        "user:12345@cb.example.com/done",
        "/user:12345@cb.example.com/done",
        "user:9876543210@cb.example.com",
    ] {
        assert!(
            super::nested_authority_with_userinfo(value),
            "must take the nested-authority path: {value}"
        );
    }
    // Controls: without an '@' the digit colon is a port, and without a colon
    // the '@' is harmless. Neither may start the recursive masker.
    assert!(!super::nested_authority_with_userinfo("host:8443/path"));
    assert!(!super::nested_authority_with_userinfo("a@b"));

    let url = "https://vault.example.com/login?next=user:12345@cb.example.com/done";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("12345"), "{masked}");
    assert!(
        masked.contains("next=[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // Percent-encoded and leading-slash spellings reach the same recursion.
    let encoded = "https://vault.example.com/login?next=user%3A12345%40cb.example.com%2Fdone";
    let masked = super::mask_url_secrets(encoded);
    assert!(!masked.contains("12345"), "{masked}");
    assert!(
        masked.contains("[redacted]@cb.example.com/done"),
        "{masked}"
    );

    let slashed = "https://vault.example.com/login?next=/user:12345@cb.example.com/done";
    let masked = super::mask_url_secrets(slashed);
    assert!(!masked.contains("12345"), "{masked}");
    assert!(
        masked.contains("next=/[redacted]@cb.example.com/done"),
        "{masked}"
    );

    // The same path is used by `Debug`; the stored URL stays byte-for-byte
    // identical for the server-mismatch check.
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("12345"), "{rendered}");
    assert!(
        rendered.contains("[redacted]@cb.example.com/done"),
        "{rendered}"
    );
    assert_eq!(cache.server_url, url);
}

#[test]
fn bounded_read_saturates_the_limit_plus_one() {
    // `read_bounded` caps the reader at `limit.saturating_add(1)` bytes
    // (cache.rs:905-915). A plain `limit + 1` would overflow at `u64::MAX`;
    // the saturating form must still read a short reader in full.
    let mut reader = std::io::Cursor::new(vec![b'x'; 8]);
    let contents = super::read_bounded(&mut reader, u64::MAX).unwrap();
    assert_eq!(contents, vec![b'x'; 8]);
    assert_eq!(reader.position(), 8);
}

#[test]
fn save_preserves_the_capture_time_instead_of_refreshing_it() {
    // Documented `created_at` contract on `save`: the sanitized copy keeps the
    // caller's timestamp, so writing an old cache cannot extend its offline
    // window. Only `from_body` stamps a fresh capture time.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync-cache.json");
    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    cache.created_at = Some(1);
    save(&path, &cache).unwrap();
    assert_eq!(load_detailed(&path).unwrap().created_at, Some(1));
    assert_eq!(cache.created_at, Some(1), "the caller's value is untouched");

    // A legacy cache without a timestamp keeps it absent on the round trip.
    cache.created_at = None;
    save(&path, &cache).unwrap();
    assert_eq!(load_detailed(&path).unwrap().created_at, None);
}

#[test]
fn pair_start_zero_without_an_equals_sign_masks_the_whole_authority() {
    // With no `?`/`#`/`/` before the '@' the pre-pass takes `pair_start == 0`.
    // When there is no '=' either, `prefix_end` falls back to 0 (cache.rs:
    // 496-503), so the whole `user:secret` text is treated as userinfo.
    for pairs in [
        "user:P&SS@cb.example.com/done",
        "user:P;SS@cb.example.com/done",
    ] {
        assert_eq!(
            super::mask_nested_userinfo_in_pairs(pairs),
            "[redacted]@cb.example.com/done",
            "{pairs}"
        );
    }
    // A harmless '@' without a `user:secret` marker is still copied verbatim.
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("state=a@b&flag=1"),
        "state=a@b&flag=1"
    );

    let url = "https://vault.example.com/p?user:P&SS@cb.example.com/done";
    let masked = super::mask_url_secrets(url);
    assert!(!masked.contains("P&SS"), "{masked}");
    assert!(
        masked.contains("[redacted]@cb.example.com/done"),
        "{masked}"
    );
}

#[test]
fn numeric_password_question_and_nonempty_text_before_at_is_masked() {
    // A colon followed only by digits is a port *only* when the text after the
    // '?' looks like a query parameter. `user:12345?text@host` is userinfo with
    // a numeric password; treating the '?' as a query delimiter hid the '@'
    // and leaked the credential (cache.rs:236-290).
    for (url, expected, secret) in [
        (
            "https://user:12345?text@host",
            "https://[redacted]@host",
            "12345?text",
        ),
        (
            "https://user:12345?text@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "12345?text",
        ),
        (
            "https://user:0000#frag@host:8443/p",
            "https://[redacted]@host:8443/p",
            "0000#frag",
        ),
        ("user:12345?text@host/p", "[redacted]@host/p", "12345?text"),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        assert!(!super::mask_url_secrets(url).contains(secret), "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(rendered.contains("[redacted]@"), "{rendered}");
        // Debug-only masking: the stored URL stays byte-for-byte identical.
        assert_eq!(cache.server_url, url);
    }

    // A real `host:port` followed by a `key=value` query '@' stays untouched.
    for url in ["https://host:8443?email=a@b", "https://host?email=a@b"] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[cfg(unix)]
#[test]
fn permission_gate_is_checked_before_the_version_gate() {
    use std::os::unix::fs::PermissionsExt;

    // `load_detailed` applies the private-file permission gate before parsing
    // and before the version check (cache.rs:938-980). A file that is both
    // world-readable and stamped with an unknown version must be classified as
    // unreadable, never as a version mismatch.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wide-and-outdated.json");
    let mut cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    cache.version += 1;
    save(&path, &cache).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::CacheInsecureMode { .. }),
        "permission gate must win over version mismatch: {error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);
}

#[cfg(unix)]
#[test]
fn permission_gate_wins_over_the_post_parse_body_size_gate() {
    use std::os::unix::fs::PermissionsExt;

    // `load_detailed` checks the private-file mode before parsing the envelope
    // (cache.rs:1175-1186), while the body-size cap is checked *after* parsing
    // (cache.rs:1192-1194). A world-readable cache whose body is also over
    // MAX_CACHE_BODY_BYTES must therefore be classified as unreadable; the
    // post-parse size gate never gets a chance. This is the missing pair in the
    // gate-priority matrix: the pre-parse metadata gate wins over permission
    // (`oversized_world_readable_file_keeps_its_size_classification`) and the
    // permission gate wins over the version gate
    // (`permission_gate_is_checked_before_the_version_gate`).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wide-and-oversized-body.json");

    // `save` refuses an over-large body, so build the envelope directly. Take
    // the version from `SyncCache::VERSION` rather than a literal so a schema
    // bump keeps this gate-priority fixture current. A compact array of `0`
    // bytes keeps the file below MAX_CACHE_BYTES: the earlier metadata size gate
    // must not classify this fixture instead.
    let mut envelope = format!(
        r#"{{"version":{},"user_id":"user-1","server_url":"https://vault.example.com","body":["#,
        SyncCache::VERSION
    )
    .into_bytes();
    for index in 0..=MAX_CACHE_BODY_BYTES {
        if index > 0 {
            envelope.push(b',');
        }
        envelope.push(b'0');
    }
    envelope.extend_from_slice(br#"],"created_at":null}"#);
    assert!(
        (envelope.len() as u64) <= MAX_CACHE_BYTES,
        "fixture must fit the pre-parse file cap"
    );
    write_fixture(&path, &envelope);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o066,
        0,
        "premise: write_fixture created an owner-only file"
    );

    // Control at the same owner-only mode: the post-parse body gate really does
    // fire, so the assertion below is about priority, not a disabled check.
    assert!(matches!(
        load_detailed(&path),
        Err(CacheLoadError::CacheTooLarge)
    ));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::CacheInsecureMode { .. }),
        "permission gate must win over the post-parse body cap: {error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);
    assert!(load(&path).is_none());
}

#[cfg(unix)]
#[test]
fn permission_gate_wins_over_json_parse_failure() {
    use std::os::unix::fs::PermissionsExt;

    // The private-file mode gate runs after `metadata` but before the bounded
    // read and `serde_json::from_slice` (cache.rs:1232-1252). A file that is
    // both world-readable and syntactically broken must therefore be reported
    // as unreadable with the permission cause, never as a JSON parse failure.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wide-and-broken.json");
    write_fixture(&path, b"not json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o066,
        0,
        "premise: write_fixture created an owner-only file"
    );

    // Control at the safe mode: the same bytes really do reach the parser, so
    // the assertion below is about priority rather than a disabled gate.
    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::ParseFailedCause(_)),
        "control: broken JSON at mode 0600 must be a parse failure: {error:?}"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the serde error must stay reachable through the cause chain"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = load_detailed(&path).unwrap_err();
    assert!(
        matches!(&error, CacheLoadError::CacheInsecureMode { .. }),
        "permission gate must win over the JSON parse failure: {error:?}"
    );
    assert_eq!(cache_error_message(error), REASON_UNREADABLE);
    assert!(load(&path).is_none());
}

#[test]
fn server_mismatch_is_reported_before_the_body_is_parsed() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    let mut corrupt = cache.clone();
    corrupt.body = b"not json".to_vec();

    // `validate` compares the server before parsing the body (cache.rs:1167-1179),
    // so a wrong server wins even when the body is corrupt too.
    assert_eq!(
        validate(&corrupt, "user-1", "https://other.example.com"),
        Err(SyncCacheError::ServerMismatch)
    );
    // Premise: with the server matching, the same body is a parse failure.
    assert!(matches!(
        validate(&corrupt, "user-1", "https://vault.example.com"),
        Err(SyncCacheError::CacheParse(_))
    ));
}

#[test]
fn numeric_password_under_an_arbitrary_username_is_masked() {
    // `at_is_in_query` used to recognize only the literal `user:` prefix, so a
    // numeric password under any other username was dismissed as a
    // `host:port` plus query text and leaked through Debug (cache.rs:257+).
    for (url, expected, secret) in [
        (
            "https://alice:12345?text@host",
            "https://[redacted]@host",
            "12345?text",
        ),
        (
            "alice:9876543210#frag@host:8443/p",
            "[redacted]@host:8443/p",
            "9876543210#frag",
        ),
        (
            "https://bob:0000?text@host/path",
            "https://[redacted]@host/path",
            "0000?text",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        assert!(!super::mask_url_secrets(url).contains(secret), "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(rendered.contains("[redacted]@"), "{rendered}");
        // Debug-only masking: the stored URL stays byte-for-byte identical.
        assert_eq!(cache.server_url, url);
    }

    // Canonical host:port spellings keep their query/fragment classification.
    for url in [
        "https://host:8443#frag@x",
        "https://vault.example.com:8443#frag@x",
    ] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[test]
fn trailing_equals_in_a_numeric_password_is_not_a_query_assignment() {
    // A '=' directly before the '@' has no parameter name and no value: it is
    // password decoration, not a `key=value` query. Treating it as a genuine
    // assignment left the whole numeric credential visible in Debug output.
    let scan = "alice:12345?=@host";
    let at = scan.rfind('@').expect("an '@' after the trailing '='");
    assert!(!super::at_is_in_query(scan, at));

    for (url, expected, secret) in [
        (
            "https://alice:12345?=@host",
            "https://[redacted]@host",
            "12345?=",
        ),
        (
            "https://alice:12345?==@host/path",
            "https://[redacted]@host/path",
            "12345?==",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert_eq!(cache.server_url, url);
    }

    // A real `key=value` assignment after the '?' still wins: the '@' belongs
    // to the query and the URL is copied through unchanged.
    for url in ["https://host:8443?email=a@b", "https://host?x=1@host"] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[test]
fn server_url_credentials_are_persisted_verbatim_in_the_cache_envelope() {
    // Documented on `SyncCache::server_url` and `save`: Debug masks the URL,
    // but the envelope on disk keeps the credential-bearing string as-is.
    let url = "https://alice:ON_DISK_SECRET@vault.example.com:8443/path?token=ON_DISK_TOKEN";
    let cache = SyncCache::from_body(body(), url).unwrap();
    assert_eq!(cache.server_url, url);
    assert!(!format!("{cache:?}").contains("ON_DISK_SECRET"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credential-url-cache.json");
    save(&path, &cache).unwrap();
    let on_disk = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(on_disk.contains("ON_DISK_SECRET"), "{on_disk}");
    assert!(on_disk.contains("ON_DISK_TOKEN"), "{on_disk}");
    assert_eq!(load_detailed(&path).unwrap().server_url, url);
}

#[test]
fn numeric_password_with_a_key_value_query_and_at_sign_is_masked() {
    // `at_is_in_query` used to return "in query" as soon as a `?key=value`
    // assignment appeared before the '@', even when the leading authority was
    // a non-canonical numeric password. The whole credential then reached
    // `Debug` unmasked. The numeric-password check now runs first, so a
    // `user:<digits>?key=value@host` authority keeps its userinfo separator
    // (cache.rs:298+).
    for (url, expected, secret) in [
        (
            "https://user:12345?key=value@host",
            "https://[redacted]@host",
            "12345?key=value",
        ),
        (
            "user:98765?token=abc@host:8443/p",
            "[redacted]@host:8443/p",
            "98765?token=abc",
        ),
        (
            "https://bob:01234?state=ok@host/path?note=keep",
            "https://[redacted]@host/path?note=keep",
            "01234?state=ok",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let masked = super::mask_url_secrets(url);
        assert!(!masked.contains(secret), "leaked {secret}: {masked}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(rendered.contains("[redacted]@"), "{rendered}");
        // Debug-only masking: the stored URL stays byte-for-byte identical.
        assert_eq!(cache.server_url, url);
    }

    // A canonical port plus a real query still keeps its '@' in the query and
    // is copied through unchanged; only non-canonical digit runs are passwords.
    for url in ["https://host:8443?email=a@b", "https://host?x=1@host"] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[test]
fn raw_control_characters_in_the_server_url_are_masked_and_escaped_on_disk() {
    // These are literal control bytes, not `%XX` escapes, so the
    // `percent_decode` control-escape rule does not apply. `Debug` must drop
    // the whole userinfo: a newline or NUL inside a password must not split a
    // log line or expose its tail. The envelope still stores the exact string.
    let url = "https://alice:RAW\nSECRET\rWITH\0NUL@vault.example.com/path?state=ok";
    let cache = SyncCache::from_body(body(), url).unwrap();
    assert_eq!(cache.server_url, url);

    let rendered = format!("{cache:?}");
    for secret in ["RAW", "SECRET", "WITH", "NUL"] {
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
    }
    assert!(!rendered.contains('\n'), "{rendered:?}");
    assert!(!rendered.contains('\r'), "{rendered:?}");
    assert!(!rendered.contains('\0'), "{rendered:?}");
    assert!(
        rendered.contains("[redacted]@vault.example.com/path?state=ok"),
        "{rendered}"
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control-url-cache.json");
    save(&path, &cache).unwrap();
    let on_disk = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    // serde escapes the raw control bytes in the JSON string, so the
    // credential text is still present (escaped) on disk; masking never
    // rewrites the stored field.
    assert!(
        on_disk.contains("RAW\\nSECRET\\rWITH\\u0000NUL"),
        "{on_disk:?}"
    );
    assert!(!on_disk.contains("RAW\nSECRET"), "{on_disk:?}");
    assert_eq!(load_detailed(&path).unwrap().server_url, url);
}

#[test]
fn numeric_password_with_an_unescaped_slash_is_masked_before_the_path_boundary() {
    // An all-digit colon value used to be dismissed as a `host:port`, so the
    // first '/' closed the authority and the '@' after the numeric password was
    // never scanned: `Debug` leaked the credential. `has_userinfo_colon` now
    // recognizes a non-canonical digit run (5+ digits or a leading zero)
    // *before* the slash is treated as a path separator (cache.rs:157-167,
    // 197-204).
    for (url, expected, secret) in [
        (
            "https://user:12345/secret@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "12345/secret",
        ),
        (
            "https://alice:9876543210/a/b@vault.example.com:8443/path?state=ok",
            "https://[redacted]@vault.example.com:8443/path?state=ok",
            "9876543210/a/b",
        ),
        (
            "https://bob:01234/secret@vault.example.com/path",
            "https://[redacted]@vault.example.com/path",
            "01234/secret",
        ),
        (
            "user:12345/secret@vault.example.com",
            "[redacted]@vault.example.com",
            "12345/secret",
        ),
    ] {
        assert_eq!(super::mask_url_userinfo(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(
            rendered.contains("[redacted]@vault.example.com"),
            "{rendered}"
        );
        assert_eq!(cache.server_url, url, "masking is Debug-only");
    }

    // Boundary of the same heuristic: a canonical 1..=4 digit port before the
    // '/' stays a port, so its query '@' is still query text and the URL is
    // copied through verbatim. A five-digit run is deliberately read as a
    // numeric password (the documented `numeric_password_colon` policy) and is
    // therefore masked even though 10000 is a representable TCP port. Pin both
    // sides of the 4/5-digit boundary so the misjudgment cannot drift silently.
    let port_ok = "https://vault.example.com:8443/path?email=a@b";
    assert_eq!(super::mask_url_userinfo(port_ok), port_ok, "{port_ok}");
    assert_eq!(
        super::mask_url_userinfo("https://vault.example.com:10000/path?email=a@b"),
        "https://[redacted]@b"
    );
    assert!(!super::numeric_password_colon("user:9999"));
    assert!(super::numeric_password_colon("user:10000"));
    assert!(super::numeric_password_colon("user:0123"));
}

#[test]
fn hex_value_accepts_lowercase_b_to_f_and_uppercase_b_c_e() {
    // Every hex digit must decode in both cases; a missing arm would leave a
    // `%62` / `%42` escape literal and could hide the name of a secret key
    // from `is_sensitive_param_key` (cache.rs:482-490).
    for (byte, expected) in [
        (b'a', 10),
        (b'b', 11),
        (b'c', 12),
        (b'd', 13),
        (b'e', 14),
        (b'f', 15),
        (b'A', 10),
        (b'B', 11),
        (b'C', 12),
        (b'E', 14),
    ] {
        assert_eq!(super::hex_value(byte), Some(expected), "0x{byte:02X}");
    }
    // Controls: digits and the remaining uppercase letters still decode, and
    // non-hex bytes are rejected rather than mapped to zero.
    assert_eq!(super::hex_value(b'0'), Some(0));
    assert_eq!(super::hex_value(b'9'), Some(9));
    assert_eq!(super::hex_value(b'D'), Some(13));
    assert_eq!(super::hex_value(b'F'), Some(15));
    for byte in [b'g', b'G', b'@', 0x80] {
        assert_eq!(super::hex_value(byte), None, "0x{byte:02X}");
    }
    // End-to-end through `percent_decode`: lowercase and uppercase digits in
    // the same value decode to their ASCII characters.
    assert_eq!(super::percent_decode("%62%42%63%43"), "bBcC");
}

#[test]
fn query_delimiter_without_an_assignment_is_still_in_query() {
    // The last classifier arm used to be `has_assignment || !numeric_password`.
    // The numeric-password branch above already returned, so `!numeric_password`
    // was always true and the assignment test was dead. With the credential
    // shapes ruled out, a bare host or a canonical `host:8443` port keeps its
    // `?`/`#` as a genuine delimiter even without a `key=value` tail
    // (cache.rs:321-335).
    for scan in ["host#frag@x", "host:8443#frag@x", "host?text@x"] {
        let at = scan.rfind('@').expect("an '@' after the delimiter");
        assert!(super::at_is_in_query(scan, at), "{scan}");
    }
    // Control: a real assignment is classified the same way, so the assertions
    // above pin the no-assignment case rather than a blanket "always query".
    let with_assignment = "host:8443?email=a@b";
    assert!(super::at_is_in_query(
        with_assignment,
        with_assignment.rfind('@').unwrap()
    ));
    for url in ["https://host#frag@x", "https://host:8443#frag@x"] {
        assert_eq!(super::mask_url_userinfo(url), url, "{url}");
    }
}

#[test]
fn from_body_stores_empty_and_malformed_server_urls_verbatim() {
    // `SyncCache::from_body` (cache.rs:793-808) copies `server_url` verbatim: it
    // validates neither syntax nor the SSRF policy. An empty or malformed URL
    // is therefore a stored-value property, not a constructor error, and
    // `validate` keeps comparing it byte-for-byte (cache.rs:1256-1268).
    for url in [
        "",
        "   ",
        "not a url",
        "http://169.254.169.254",
        "ftp://vault.example.com",
    ] {
        let cache = SyncCache::from_body(body(), url).unwrap();
        assert_eq!(cache.server_url, url, "the URL must not be rewritten");
        assert!(cache.sync().is_ok());
        assert_eq!(validate(&cache, "user-1", url), Ok(()));
        assert_eq!(
            validate(&cache, "user-1", "https://other.example.com"),
            Err(SyncCacheError::ServerMismatch)
        );
    }
}

#[test]
fn empty_account_ids_fail_closed_on_validate() {
    let url = "https://vault.example.com";
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: String::new(),
        server_url: url.to_string(),
        body: br#"{"profile":{"id":""},"folders":[],"ciphers":[]}"#.to_vec(),
        created_at: None,
    };
    // Premise: an empty id is a present `String`, so parsing succeeds and the
    // only possible guard is the account comparison (not a parse failure).
    assert_eq!(cache.sync().unwrap().user_id(), "");

    // Two blanks used to compare equal and let the cache through (fail-open).
    assert_eq!(validate(&cache, "", url), Err(SyncCacheError::UserMismatch));
    // A trusted caller cannot unlock an anonymous cache either.
    assert_eq!(
        validate(&cache, "user-1", url),
        Err(SyncCacheError::UserMismatch)
    );

    // Direct helper contract: empty on either side never matches, even when
    // both sides are blank. The server is checked before this guard, so a
    // mismatch there still wins (pinned by the sibling priority tests).
    assert!(super::account_ids_match("user-1", "user-1"));
    assert!(!super::account_ids_match("", ""));
    assert!(!super::account_ids_match("", "user-1"));
    assert!(!super::account_ids_match("user-1", ""));
}

#[cfg(target_os = "linux")]
#[test]
fn empty_account_ids_fail_closed_on_the_restore_path() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    let url = "https://vault.example.com";

    save_default(&SyncCache {
        version: SyncCache::VERSION,
        user_id: String::new(),
        server_url: url.to_string(),
        body: br#"{"profile":{"id":""},"folders":[],"ciphers":[]}"#.to_vec(),
        created_at: None,
    })
    .unwrap();

    assert!(matches!(
        cached_sync_for_detailed(url, ""),
        Err(SyncCacheError::UserMismatch)
    ));
    assert!(cached_sync_for(url, "").is_none());
    assert!(matches!(
        cached_sync_for_detailed(url, "user-1"),
        Err(SyncCacheError::UserMismatch)
    ));
    // The server check still runs first and keeps its own classification.
    assert!(matches!(
        cached_sync_for_detailed("https://other.example.com", ""),
        Err(SyncCacheError::ServerMismatch)
    ));
}

// --- R2-CORE-121: write-side permissions and i64::MIN capture time ---

#[cfg(unix)]
#[test]
fn save_writes_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    let path = nested.join("sync-cache.json");
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();

    save(&path, &cache).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "file mode {mode:04o}");
    assert_eq!(mode & 0o066, 0, "group/other bits must be clear");
    let parent_mode = std::fs::metadata(&nested).unwrap().permissions().mode();
    assert_eq!(parent_mode & 0o777, 0o700, "parent mode {parent_mode:04o}");

    // Replacing an existing world-readable file must tighten it again.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    save(&path, &cache).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "replacement mode {mode:04o}");
}

#[cfg(target_os = "linux")]
#[cfg(unix)]
#[test]
fn save_default_writes_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let cache_home = root.path().join("xdg-cache-home");
    let _env = EnvGuard::set("XDG_CACHE_HOME", &cache_home);

    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save_default(&cache).unwrap();
    let path = default_path().expect("cache path");
    assert!(path.is_file(), "save_default must create the cache file");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "file mode {mode:04o}");
    assert_eq!(mode & 0o066, 0, "group/other bits must be clear");
}

#[test]
fn minimum_i64_capture_time_is_expired() {
    let now = 1_800_000_000_i64;
    // Premise: the direct subtraction overflows, so `is_cache_expired` must
    // take the saturating arm of the match (cache.rs:832-838).
    assert_eq!(now.checked_sub(i64::MIN), None);
    assert_eq!(now.saturating_sub(i64::MIN), i64::MAX);
    const {
        assert!(i64::MAX > MAX_CACHE_AGE_SECS);
    }
    assert!(is_cache_expired(Some(i64::MIN), now));
    assert!(is_cache_expired(Some(i64::MIN), 0));
    // The verdict is about the extreme capture time, not a blanket rejection
    // of old-but-representable timestamps.
    assert!(!is_cache_expired(Some(now), now));

    // The sentinel also survives a serde round-trip as an expired timestamp.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("min-created-at.json");
    let envelope = serde_json::json!({
        "version": SyncCache::VERSION,
        "user_id": "user-1",
        "server_url": "https://vault.example.com",
        "body": body(),
        "created_at": i64::MIN,
    });
    write_fixture(&path, &serde_json::to_vec(&envelope).unwrap());
    let loaded = load_detailed(&path).unwrap();
    assert_eq!(loaded.created_at, Some(i64::MIN));
    assert!(is_cache_expired(loaded.created_at, now));
}

#[test]
fn scheme_less_userinfo_without_key_prefix_is_masked_in_query_and_fragment() {
    // `mask_param_pairs` copies pairs without '=' verbatim, so a scheme-less
    // `user:secret@host` needs the pre-pass in
    // `mask_nested_userinfo_in_pairs` (cache.rs:555-625). With no `key=` prefix
    // the candidate starts at byte zero -- the `pair_start == 0` branch -- and
    // the userinfo itself must be replaced, not a value after '='.
    let query = "https://vault.example.com/cb?user:P&SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(query);
    assert!(!masked.contains("P&SS"), "{masked}");
    assert!(
        masked.contains("?[redacted]@cb.example.com/done&state=ok"),
        "{masked}"
    );

    // A ';' in the password is both a legal credential character and a pair
    // separator. In a fragment it must not cut the authority in two either.
    let fragment = "https://vault.example.com/cb#user:P;SS@cb.example.com/done&state=ok";
    let masked = super::mask_url_secrets(fragment);
    assert!(!masked.contains("P;SS"), "{masked}");
    assert!(
        masked.contains("#[redacted]@cb.example.com/done&state=ok"),
        "{masked}"
    );

    // Direct check of the no-'=' branch: there is no `key=` prefix to keep.
    assert_eq!(
        super::mask_nested_userinfo_in_pairs("user:P&SS@cb.example.com/done"),
        "[redacted]@cb.example.com/done"
    );
    // A harmless '@' without a `user:secret` marker stays untouched.
    let harmless = "a@b;state=ok";
    assert_eq!(super::mask_nested_userinfo_in_pairs(harmless), harmless);

    // Debug reaches the same redactor through the stored server URL; the
    // stored value itself remains byte-for-byte the one used for comparisons.
    let cache = SyncCache::from_body(body(), query).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("P&SS"), "{rendered}");
    assert_eq!(cache.server_url, query);
}

#[test]
fn scheme_less_userinfo_without_an_assignment_is_masked() {
    for url in [
        "https://vault.example.com/cb?user:SECRET@cb.example.com",
        "https://vault.example.com/cb#user:SECRET@cb.example.com",
    ] {
        let masked = super::mask_url_secrets(url);
        assert!(!masked.contains("SECRET"), "{url} -> {masked}");
        assert!(masked.contains("[redacted]@cb.example.com"), "{masked}");
    }
    // A harmless `key@host` value with no colon is left alone.
    let plain = "https://vault.example.com/cb?state=ok@cb.example.com";
    assert_eq!(super::mask_url_secrets(plain), plain);
}

#[test]
fn sensitive_param_key_substring_match_masks_innocent_names() {
    // `is_sensitive_param_key` (cache.rs:463-482) is a case-insensitive
    // *substring* test, not a token-boundary test. Harmless names that merely
    // contain a needle (`key`, `code`) are therefore classified as secret too.
    // Pin this over-match so changing it becomes a deliberate contract change.
    for key in [
        "monkey",   // ends with "key"
        "turkey",   // ends with "key"
        "keyboard", // starts with "key"
        "encode",   // contains "code"
        "decode",   // contains "code"
        "encoder",  // contains "code"
        "MonKey",   // case-insensitive "key"
        "ENCODE",   // case-insensitive "code"
    ] {
        assert!(
            super::is_sensitive_param_key(key),
            "substring match must flag: {key}"
        );
    }

    // The masker applies that classification to rendered diagnostic URLs: the
    // innocent key's spelling is kept, but its value is redacted. A neighbour
    // with no sensitive substring is preserved verbatim.
    assert_eq!(
        super::mask_url_secrets("https://vault.example.com/x?monkey=A&encode=B&state=ok"),
        "https://vault.example.com/x?monkey=[redacted]&encode=[redacted]&state=ok"
    );
    assert!(!super::is_sensitive_param_key("state"));
}

#[test]
fn save_accepts_valid_json_but_non_sync_body() {
    // `save` (cache.rs:1221-1241) only runs `redact_profile_keys`, which parses
    // the body as *any* JSON value; it never calls `parse_sync`. A hand-built
    // cache whose body is valid JSON but not a sync response is therefore
    // written and loaded successfully, while the very same bytes are refused
    // by `SyncCache::from_body` (cache.rs:860-875). Pin the boundary between
    // the write path's JSON-shape check and the constructor's sync-shape check.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("non-sync.json");
    for body in [
        br#"{"not":"a sync response"}"#.to_vec(),
        br#"[]"#.to_vec(),
        br#"42"#.to_vec(),
    ] {
        let cache = SyncCache {
            version: SyncCache::VERSION,
            user_id: "user-1".into(),
            server_url: "https://vault.example.com".into(),
            body: body.clone(),
            created_at: Some(1_700_000_000),
        };
        save(&path, &cache).unwrap_or_else(|error| panic!("{body:?}: {error}"));

        let loaded = load(&path).expect("a valid JSON body must be written and reloaded");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&loaded.body).unwrap(),
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        );
        assert!(
            loaded.sync().is_err(),
            "the body is not a sync response: {body:?}"
        );
        assert!(
            matches!(
                SyncCache::from_body(body.clone(), "https://vault.example.com"),
                Err(SyncCacheError::CacheParse(_))
            ),
            "the constructor must reject what save accepted: {body:?}"
        );
    }
}

#[test]
fn hand_built_cache_server_url_credentials_are_plaintext_on_disk() {
    // Documented on `SyncCache::server_url` and `save`: masking is a Debug-only
    // concern. A caller that builds the envelope by hand (there is no
    // production writer) bypasses `from_body` entirely, yet `save` still
    // serializes its `server_url` verbatim -- userinfo and secret query
    // parameters included -- while redacting key material in the body.
    let url =
        "https://svc:HAND_BUILT_SECRET@vault.example.com:8443/sync?token=HAND_BUILT_TOKEN&state=ok";
    let cache = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: url.to_string(),
        body: body(),
        created_at: None,
    };
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("HAND_BUILT_SECRET"), "{rendered}");
    assert!(!rendered.contains("HAND_BUILT_TOKEN"), "{rendered}");
    assert!(rendered.contains("vault.example.com:8443"), "{rendered}");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hand-built-credential-url.json");
    save(&path, &cache).unwrap();
    let on_disk = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    assert!(on_disk.contains("HAND_BUILT_SECRET"), "{on_disk}");
    assert!(on_disk.contains("HAND_BUILT_TOKEN"), "{on_disk}");
    // The plaintext value is what the server-mismatch check later compares.
    assert_eq!(load_detailed(&path).unwrap().server_url, url);
}

#[cfg(target_os = "linux")]
#[test]
fn non_string_profile_id_fails_closed_on_both_validation_paths() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));
    let url = "https://vault.example.com";

    // `profile.id` is a string on the sync wire. A hand-built envelope may carry
    // a number / bool / null there: unlike a missing or empty id, the body is
    // valid JSON but not a sync response. Both the held-object `validate` path
    // and the on-disk restore path must fail at `cache.sync()` with CacheParse,
    // even though server, account and freshness all check out.
    for raw in [
        br#"{"profile":{"id":42},"folders":[],"ciphers":[]}"#.as_slice(),
        br#"{"profile":{"id":null},"folders":[],"ciphers":[]}"#.as_slice(),
        br#"{"profile":{"id":true},"folders":[],"ciphers":[]}"#.as_slice(),
        br#"{"Profile":{"Id":42},"Ciphers":[]}"#.as_slice(),
    ] {
        let cache = SyncCache {
            version: SyncCache::VERSION,
            user_id: "user-1".to_string(),
            server_url: url.to_string(),
            body: raw.to_vec(),
            created_at: None,
        };

        assert!(
            matches!(cache.sync(), Err(SyncCacheError::CacheParse(_))),
            "{raw:?}"
        );
        assert!(
            matches!(
                validate(&cache, "user-1", url),
                Err(SyncCacheError::CacheParse(_))
            ),
            "{raw:?}"
        );

        save_default(&cache).unwrap();
        assert!(
            matches!(
                cached_sync_for_detailed(url, "user-1"),
                Err(SyncCacheError::CacheParse(_))
            ),
            "{raw:?}"
        );
        assert!(cached_sync_for(url, "user-1").is_none(), "{raw:?}");
    }

    // Control: the same hand-built envelope with a string id parses, validates
    // and restores, so the failures above are about the id's JSON type.
    let ok = SyncCache {
        version: SyncCache::VERSION,
        user_id: "user-1".to_string(),
        server_url: url.to_string(),
        body: br#"{"profile":{"id":"user-1"},"folders":[],"ciphers":[]}"#.to_vec(),
        created_at: None,
    };
    assert_eq!(ok.sync().unwrap().user_id(), "user-1");
    assert!(validate(&ok, "user-1", url).is_ok());
    save_default(&ok).unwrap();
    assert!(cached_sync_for_detailed(url, "user-1").is_ok());
}

#[test]
fn raw_non_ascii_multibyte_characters_pass_through_the_url_redactor() {
    // The redactor slices URLs at byte offsets found for ASCII delimiters and
    // advances over non-'%' characters with `len_utf8()` (cache.rs:525-545,
    // 662-740). Raw multibyte scalars must therefore survive unchanged and
    // must never trigger a mid-scalar slice panic, while ASCII secret keys are
    // still redacted in both the query and the fragment.
    let url = "https://vault.example.com/パス?token=SECRET🔑&state=あい#code=FRAGMENT秘密";
    let masked = super::mask_url_secrets(url);
    assert_eq!(
        masked, "https://vault.example.com/パス?token=[redacted]&state=あい#code=[redacted]",
        "{masked}"
    );
    assert!(!masked.contains("SECRET"), "{masked}");
    assert!(!masked.contains("FRAGMENT"), "{masked}");
    assert!(masked.contains("パス"), "{masked}");
    assert!(masked.contains("あい"), "{masked}");

    // A raw multibyte password in userinfo is masked as a whole; the host and
    // the non-ASCII path stay traceable for diagnostics.
    let with_userinfo = "https://user:秘密🔑@vault.example.com/パス?state=あい";
    assert_eq!(
        super::mask_url_userinfo(with_userinfo),
        "https://[redacted]@vault.example.com/パス?state=あい",
    );
    assert_eq!(
        super::mask_url_secrets(with_userinfo),
        "https://[redacted]@vault.example.com/パス?state=あい",
    );

    // The same URL reaches Debug through `SyncCache`: no secret leaks, the
    // non-ASCII text is preserved, and the stored URL stays byte-for-byte
    // identical for the server-mismatch check.
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    assert!(!rendered.contains("FRAGMENT"), "{rendered}");
    assert!(rendered.contains("vault.example.com/パス"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn bare_authority_numeric_password_with_equals_is_masked() {
    // `mask_param_pairs` reads the first '=' as a key/value separator. For a
    // scheme-less bare authority such as `user:12345=x@host` that '=' belongs
    // to the password, so the would-be key `user:12345` has an all-digit value.
    // The `bare_authority_with_equals` guard used to reject that shape and copy
    // the pair verbatim, leaking the numeric credential (cache.rs:710+).
    let pairs = "user:12345=x@cb.example.com/done";
    assert_eq!(
        super::mask_param_pairs(pairs, 0),
        "[redacted]@cb.example.com/done"
    );

    for (url, expected, secret) in [
        (
            "https://vault.example.com/login?user:12345=x@cb.example.com/done",
            "https://vault.example.com/login?[redacted]@cb.example.com/done",
            "12345=x",
        ),
        (
            "https://vault.example.com/login?user:01234=x@cb.example.com/done",
            "https://vault.example.com/login?[redacted]@cb.example.com/done",
            "01234=x",
        ),
        (
            "https://vault.example.com/login?user:9876543210=x@cb.example.com:8443/p",
            "https://vault.example.com/login?[redacted]@cb.example.com:8443/p",
            "9876543210=x",
        ),
    ] {
        assert_eq!(super::mask_url_secrets(url), expected, "{url}");
        let cache = SyncCache::from_body(body(), url).unwrap();
        let rendered = format!("{cache:?}");
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        assert!(rendered.contains("[redacted]@cb.example.com"), "{rendered}");
        // Debug-only masking: the stored URL stays byte-for-byte identical.
        assert_eq!(cache.server_url, url);
    }

    // A second query behind the authority is still descended into and redacted.
    let two_queries = "user:12345=x@cb.example.com/done?token=SECOND_QUERY_SECRET&state=ok";
    assert_eq!(
        super::mask_param_pairs(two_queries, 0),
        "[redacted]@cb.example.com/done?token=[redacted]&state=ok"
    );
    let url = format!("https://vault.example.com/login?{two_queries}");
    let masked = super::mask_url_secrets(&url);
    assert!(!masked.contains("12345=x"), "{masked}");
    assert!(!masked.contains("SECOND_QUERY_SECRET"), "{masked}");
    assert!(masked.contains("token=[redacted]"), "{masked}");
}

#[test]
fn numeric_password_colon_guards_reject_invalid_users_and_values() {
    // `numeric_password_colon` (cache.rs:382+) requires a non-empty user with
    // no authority delimiter, and a non-empty all-digit value that is either
    // leading-zero or at least five digits long. Each guard is pinned so the
    // new bare-authority-with-'=' branch cannot start treating a `host:port`
    // authority as a numeric password.
    for authority in [
        ":12345",       // empty user
        "user:",        // empty value
        "u@ser:12345",  // '@' in user
        "u?ser:12345",  // '?' in user
        "u#ser:12345",  // '#' in user
        "u/ser:12345",  // '/' is a path split before the colon check
        "user:9999",    // canonical port length
        "user:1234a",   // not all digits
        "user:12345=x", // '=' is not part of the digit run
        "no-colon",     // no userinfo marker at all
    ] {
        assert!(
            !super::numeric_password_colon(authority),
            "must not be a numeric password: {authority}"
        );
    }
    for authority in ["user:12345", "user:10000", "user:0123", "alice:9876543210"] {
        assert!(
            super::numeric_password_colon(authority),
            "must be a numeric password: {authority}"
        );
    }
}

// --- R2-CORE-149: validate's check priority ---

#[test]
fn validate_prioritizes_server_then_account_then_body_parse() {
    // `validate` checks the cheap metadata first and only then parses the held
    // body (cache.rs:1455-1467). Pin the ordering with caches where several
    // checks fail at once: the first failing gate must decide the error.
    const SERVER: &str = "https://vault.example.com";
    let original = SyncCache::from_body(body(), SERVER).unwrap();
    let corrupt = |cache: &SyncCache| SyncCache {
        body: b"not json".to_vec(),
        ..cache.clone()
    };

    // Server mismatch wins over a wrong account and an unparsable body.
    let both = corrupt(&SyncCache {
        user_id: "other".to_string(),
        ..original.clone()
    });
    assert_eq!(
        validate(&both, "user-1", "https://other.example.com"),
        Err(SyncCacheError::ServerMismatch)
    );

    // With the server matching, the envelope account check wins over parsing.
    let wrong_account = corrupt(&SyncCache {
        user_id: "other".to_string(),
        ..original.clone()
    });
    assert_eq!(
        validate(&wrong_account, "user-1", SERVER),
        Err(SyncCacheError::UserMismatch)
    );

    // Only once both metadata checks pass does the body parse failure surface.
    assert!(matches!(
        validate(&corrupt(&original), "user-1", SERVER),
        Err(SyncCacheError::CacheParse(_))
    ));

    // A parseable body whose Profile.Id differs from the envelope is a
    // UserMismatch, not a CacheParse.
    let foreign = br#"{"profile":{"id":"someone-else"},"folders":[],"ciphers":[]}"#;
    let mismatch = SyncCache {
        body: foreign.to_vec(),
        ..original.clone()
    };
    assert_eq!(
        validate(&mismatch, "user-1", SERVER),
        Err(SyncCacheError::UserMismatch)
    );

    // Two blank ids never match, even though a blank equals a blank.
    let blank = SyncCache {
        user_id: String::new(),
        ..original.clone()
    };
    assert_eq!(
        validate(&blank, "", SERVER),
        Err(SyncCacheError::UserMismatch)
    );

    // Control: the unmodified cache still validates.
    assert_eq!(validate(&original, "user-1", SERVER), Ok(()));
}

#[test]
fn every_nested_authority_is_masked_by_the_pair_prepass() {
    // `mask_nested_userinfo_in_pairs` (cache.rs:594-672) loops over every '@'
    // in the pair string; it must not stop after rewriting the first nested
    // authority. Each password below contains a pair separator, so both are
    // rewrites this pre-pass owns rather than ordinary `key=value` pairs.
    let pairs =
        "next=user:P&SS@cb1.example.com/done&also=user:Q;TT@cb2.example.com/finish&state=ok";
    // The second rewrite starts at the '/' after the first host, so the text
    // `done&also=` is part of the second authority candidate and is replaced
    // together with its password.
    let expected = "next=[redacted]@cb1.example.com/[redacted]@cb2.example.com/finish&state=ok";
    assert_eq!(super::mask_nested_userinfo_in_pairs(pairs), expected);

    // The same loop runs inside `mask_url_secrets`: neither secret reaches the
    // rendered diagnostic URL, and the harmless `state` pair survives.
    let url = format!("https://vault.example.com/login?{pairs}");
    let masked = super::mask_url_secrets(&url);
    assert!(!masked.contains("P&SS"), "{masked}");
    assert!(!masked.contains("Q;TT"), "{masked}");
    assert_eq!(
        masked,
        format!("https://vault.example.com/login?{expected}")
    );
    assert!(masked.contains("state=ok"), "{masked}");

    // Debug uses the same masker; the stored URL stays byte-for-byte intact.
    let cache = SyncCache::from_body(body(), &url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("P&SS"), "{rendered}");
    assert!(!rendered.contains("Q;TT"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn hash_continues_nested_password_scans_every_query_pair() {
    let tail = "frag@cb.example.com/done";
    // The `user:secret` marker sits in a later pair. The `any()` scan over
    // `&`/`;`-separated pairs (cache.rs:822-830) must not stop at the first
    // pair, or the literal '#' would be mistaken for a real fragment delimiter.
    for head in [
        "https://vault.example.com/login?state=ok&nonce=abc&next=user:NESTED_SECRET&flag=1",
        "https://vault.example.com/login?state=ok;nonce=abc;next=user:NESTED_SECRET",
        "https://vault.example.com/login?state=ok;nonce=abc&next=user:NESTED_SECRET&flag=1",
    ] {
        assert!(
            super::hash_continues_nested_password(head, tail),
            "later query pair was not scanned: {head}"
        );
    }

    // A decoy pair with an empty secret is not a marker, but must not hide a
    // valid marker that follows it.
    let decoy = "https://vault.example.com/login?note=user:&next=user:NESTED_SECRET";
    assert!(super::hash_continues_nested_password(decoy, tail));

    // Control: when no pair carries a usable marker, an '@' in the tail stays
    // a genuine fragment and the delimiter is left alone.
    for clean in [
        "https://vault.example.com/login?state=ok&nonce=abc&next=done",
        "https://vault.example.com/login?note=user:&state=ok",
    ] {
        assert!(
            !super::hash_continues_nested_password(clean, tail),
            "no marker in {clean}"
        );
    }

    // End to end: the marker is the *second* query pair, so the re-encode and
    // the recursive masker must see it through the pair scan. The whole tail
    // behind the first pair's '=' is redacted, but no secret text survives.
    let url = "https://vault.example.com/login?state=ok&next=user:p#NESTED_HASH_SECRET@cb.example.com/done";
    assert_eq!(
        super::mask_url_secrets(url),
        "https://vault.example.com/login?state=[redacted]@cb.example.com/done"
    );
    let cache = SyncCache::from_body(body(), url).unwrap();
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("NESTED_HASH_SECRET"), "{rendered}");
    assert!(!rendered.contains("user:p"), "{rendered}");
    assert_eq!(cache.server_url, url);
}

#[test]
fn bounded_read_with_a_zero_limit_accepts_empty_and_rejects_one_byte() {
    // `read_bounded` (cache.rs:1183-1192) reads `limit.saturating_add(1)` bytes
    // and then compares the length with `limit`. At limit=0 the single probing
    // byte is still read, so an empty reader succeeds and a one-byte reader is
    // rejected as CacheTooLarge rather than silently accepted.
    let mut empty = std::io::Cursor::new(Vec::<u8>::new());
    assert_eq!(
        super::read_bounded(&mut empty, 0).unwrap(),
        Vec::<u8>::new()
    );

    let mut one_byte = std::io::Cursor::new(vec![b'x']);
    assert_eq!(
        super::read_bounded(&mut one_byte, 0),
        Err(CacheLoadError::CacheTooLarge)
    );
    assert_eq!(one_byte.position(), 1, "the probing byte is consumed");
}

#[cfg(unix)]
#[test]
fn insecure_mode_error_keeps_fixed_status_and_exposes_both_modes() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    let cache = SyncCache::from_body(body(), "https://vault.example.com").unwrap();
    save(&path, &cache).unwrap();

    for (mode, expected_detail) in [
        (
            0o644u32,
            "同期に失敗しました（キャッシュを読み込めません（mode 0644、期待 0600））",
        ),
        (
            0o660u32,
            "同期に失敗しました（キャッシュを読み込めません（mode 0660、期待 0600））",
        ),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = load_detailed(&path).unwrap_err();
        assert!(matches!(
            &error,
            CacheLoadError::CacheInsecureMode {
                actual_mode,
                expected_mode: 0o600,
            } if *actual_mode == mode
        ));

        // Callers limited to a `&'static str` keep the exact old wording.
        assert_eq!(cache_error_message(error.clone()), REASON_UNREADABLE);
        assert_eq!(
            super::cache_restore_status(error.clone()),
            Some("同期に失敗しました（キャッシュを読み込めません）")
        );

        // Callers able to carry an owned string can now show the real mode.
        assert_eq!(
            CacheReadFailureKind::classify(&error),
            CacheReadFailureKind::InsecurePermissions { actual_mode: mode }
        );
        assert_eq!(
            CacheReadFailureKind::classify(&error).detail(),
            Some(format!("mode {mode:04o}、期待 0600"))
        );
        assert_eq!(cache_error_status_with_detail(&error), expected_detail);
    }
}

#[cfg(unix)]
#[test]
fn permission_detail_survives_clone_and_carries_no_path_or_secret() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-cache.json");
    let secret_url = "https://user:TOP_SECRET@host.example.com/vault";
    let cache = SyncCache::from_body(body(), secret_url).unwrap();
    save(&path, &cache).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606)).unwrap();

    // The modes are structured fields now, so `AppError::clone()` keeps the
    // type instead of flattening a cause into parsed text. The legacy text
    // fallback below is exercised separately by the octal-normalization test.
    let error = load_detailed(&path).unwrap_err().clone();
    assert!(matches!(&error, CacheLoadError::CacheInsecureMode { .. }));
    assert_eq!(
        CacheReadFailureKind::classify(&error),
        CacheReadFailureKind::InsecurePermissions { actual_mode: 0o606 }
    );
    let detail = cache_error_status_with_detail(&error);
    assert_eq!(
        detail,
        "同期に失敗しました（キャッシュを読み込めません（mode 0606、期待 0600））"
    );
    assert!(!detail.contains("TOP_SECRET"), "{detail}");
    assert!(!detail.contains("host.example.com"), "{detail}");
    assert!(
        !detail.contains(dir.path().to_string_lossy().as_ref()),
        "{detail}"
    );
    assert!(!detail.contains("private-cache.json"), "{detail}");
}

#[test]
fn unrelated_cache_errors_are_not_mislabelled_as_permission_denied() {
    use crate::error::BoxedCause;

    let cases: Vec<SyncCacheError> = vec![
        SyncCacheError::ReadFailedCause(BoxedCause::new(std::io::Error::other("denied"))),
        // A cause that merely mentions `mode` without the module's marker must
        // not be classified as a permission violation.
        SyncCacheError::ReadFailedCause(BoxedCause::text("mode 0644")),
        SyncCacheError::CacheParse(BoxedCause::text("bad json")),
        SyncCacheError::NotFound,
    ];
    for error in cases {
        let kind = CacheReadFailureKind::classify(&error);
        assert_eq!(kind, CacheReadFailureKind::Other, "{error:?}");
        assert_eq!(kind.detail(), None);
        assert_eq!(
            cache_error_status_with_detail(&error),
            cache_error_message(error)
        );
    }
}

#[test]
fn typed_permission_error_classifies_without_parsing_status_text() {
    let error = SyncCacheError::CacheInsecureMode {
        actual_mode: 0o644,
        expected_mode: 0o600,
    };
    // This variant has no cause string at all: classification comes from the
    // discriminant and its mode fields, so rewording a Japanese status message
    // cannot silently downgrade it to `Other`.
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(
        CacheReadFailureKind::classify(&error),
        CacheReadFailureKind::InsecurePermissions { actual_mode: 0o644 }
    );
    assert_eq!(
        CacheReadFailureKind::classify(&error).detail(),
        Some("mode 0644、期待 0600".to_string())
    );

    // Every status surface keeps the exact previously shipped wording.
    assert_eq!(cache_error_message(error.clone()), REASON_UNREADABLE);
    assert_eq!(
        super::cache_restore_status(error.clone()),
        Some("同期に失敗しました（キャッシュを読み込めません）")
    );
    assert_eq!(
        cache_error_status_with_detail(&error),
        "同期に失敗しました（キャッシュを読み込めません（mode 0644、期待 0600））"
    );

    // A clone keeps the typed fields, and two different observed modes remain
    // distinct failures even though they share one static family label.
    assert_eq!(
        CacheReadFailureKind::classify(&error.clone()),
        CacheReadFailureKind::InsecurePermissions { actual_mode: 0o644 }
    );
    assert_ne!(
        error,
        SyncCacheError::CacheInsecureMode {
            actual_mode: 0o640,
            expected_mode: 0o600,
        }
    );
}

#[test]
fn server_urls_match_normalizes_only_equivalent_server_spellings() {
    let stored = "https://vault.example.com";

    // `url::Url` lowercases the host and drops a scheme-default port; a
    // trailing slash is ignored here as well (cache.rs server_urls_match).
    for equivalent in [
        "https://vault.example.com/",
        "https://VAULT.example.com",
        "https://VAULT.EXAMPLE.COM:443/",
        "https://vault.example.com:443",
    ] {
        assert!(
            super::server_urls_match(stored, equivalent),
            "{equivalent} must name the stored server"
        );
        assert!(
            super::server_urls_match(equivalent, stored),
            "the comparison must be symmetric: {equivalent}"
        );
    }

    // Everything else stays significant: a different scheme, port, path,
    // userinfo, query or an unparseable URL must not match the same server.
    for different in [
        "https://other.example.com",
        "http://vault.example.com",
        "https://vault.example.com:8443",
        "https://vault.example.com/path",
        "https://user:pass@vault.example.com",
        "https://vault.example.com/?token=SECRET",
        "",
    ] {
        assert!(
            !super::server_urls_match(stored, different),
            "{different} must be refused"
        );
    }
}

#[test]
fn server_urls_match_keeps_path_query_and_fragment_trailing_slashes_significant() {
    // A trailing slash inside the path, query or fragment is data, not an
    // equivalent spelling of the same server. The old whole-string
    // `trim_end_matches('/')` erased it, so a cache written for one endpoint
    // could be restored for another (e.g. `?next=/` vs `?next=`).
    for (stored, supplied) in [
        (
            "https://vault.example.com/path/",
            "https://vault.example.com/path",
        ),
        (
            "https://vault.example.com/?next=/",
            "https://vault.example.com/?next=",
        ),
        (
            "https://vault.example.com/path?next=/",
            "https://vault.example.com/path?next=",
        ),
        (
            "https://vault.example.com/#frag/",
            "https://vault.example.com/#frag",
        ),
    ] {
        assert!(
            !super::server_urls_match(stored, supplied),
            "{stored} and {supplied} must be different servers"
        );
        assert!(
            !super::server_urls_match(supplied, stored),
            "the comparison must be symmetric: {stored} vs {supplied}"
        );
    }
}

#[test]
fn server_urls_match_accepts_only_host_case_and_root_slash_differences() {
    let stored = "https://vault.example.com";

    // Host casing, an explicit scheme-default port and the root slash added
    // by the parser are the only accepted spelling differences.
    for equivalent in [
        "https://vault.example.com/",
        "https://VAULT.example.com",
        "https://VAULT.EXAMPLE.COM:443/",
        "https://vault.example.com:443",
    ] {
        assert!(
            super::server_urls_match(stored, equivalent),
            "{equivalent} must name the stored server"
        );
        assert!(
            super::server_urls_match(equivalent, stored),
            "the comparison must be symmetric: {equivalent}"
        );
    }
    assert!(super::server_urls_match(
        "https://vault.example.com/",
        "https://VAULT.EXAMPLE.COM:443"
    ));

    // An extra slash beyond the root is a path difference, not a spelling
    // difference, and must stay significant.
    assert!(!super::server_urls_match(
        "https://vault.example.com//",
        "https://vault.example.com/"
    ));
}

#[test]
fn validate_rejects_a_cache_with_a_different_query_or_path_trailing_slash() {
    let cache = SyncCache::from_body(body(), "https://vault.example.com/path/?next=/").unwrap();

    assert!(validate(&cache, "user-1", "https://vault.example.com/path/?next=/").is_ok());
    assert!(matches!(
        validate(&cache, "user-1", "https://vault.example.com/path?next=/"),
        Err(SyncCacheError::ServerMismatch)
    ));
    assert!(matches!(
        validate(&cache, "user-1", "https://vault.example.com/path/?next="),
        Err(SyncCacheError::ServerMismatch)
    ));
    // Equivalent authority spellings are still accepted by the same gate.
    assert!(validate(
        &cache,
        "user-1",
        "https://VAULT.EXAMPLE.COM:443/path/?next=/"
    )
    .is_ok());
}

#[test]
fn validate_accepts_the_same_normalized_server_as_the_restore_path() {
    let cache = SyncCache::from_body(body(), "https://VAULT.example.com:443/").unwrap();
    assert!(validate(&cache, "user-1", "https://vault.example.com").is_ok());
    assert!(matches!(
        validate(&cache, "user-1", "https://other.example.com"),
        Err(SyncCacheError::ServerMismatch)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn cached_sync_for_detailed_accepts_equivalent_server_urls() {
    let _lock = env_lock();
    let root = tempfile::tempdir().unwrap();
    let _cache_env = EnvGuard::set("XDG_CACHE_HOME", &root.path().join("xdg-cache-home"));
    let _config_env = EnvGuard::set("XDG_CONFIG_HOME", &root.path().join("xdg-config-home"));

    save_default(&SyncCache::from_body(body(), "https://vault.example.com").unwrap()).unwrap();

    // Stored without a trailing slash; each of these still names that server.
    for equivalent in [
        "https://vault.example.com/",
        "https://VAULT.example.com",
        "https://VAULT.EXAMPLE.COM:443/",
    ] {
        assert!(
            cached_sync_for_detailed(equivalent, "user-1").is_ok(),
            "{equivalent} must restore the cache"
        );
    }
    // A genuinely different server is still refused.
    assert!(matches!(
        cached_sync_for_detailed("https://other.example.com", "user-1"),
        Err(SyncCacheError::ServerMismatch)
    ));
}

#[cfg(unix)]
#[test]
fn cache_error_status_with_detail_uses_the_sync_family_heading() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-cache.json");
    save(
        &path,
        &SyncCache::from_body(body(), "https://vault.example.com").unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = load_detailed(&path).unwrap_err();

    // Exact wording: the owned-detail branch keeps the sync family heading
    // used by every `cache_restore_status` branch, plus the observed mode.
    assert_eq!(
        cache_error_status_with_detail(&error),
        "同期に失敗しました（キャッシュを読み込めません（mode 0644、期待 0600））"
    );
    assert_eq!(
        cache_restore_status(error.clone()),
        Some("同期に失敗しました（キャッシュを読み込めません）")
    );
}

#[test]
fn permission_classification_normalizes_file_type_bits_and_rejects_bad_octal() {
    use crate::error::BoxedCause;

    let cause = |octal: &str| {
        SyncCacheError::ReadFailedCause(BoxedCause::text(format!(
            "{}（mode {octal}、期待 0600）",
            super::INSECURE_MODE_CAUSE_PREFIX
        )))
    };

    // Older cause text may include the Unix regular-file type bits. Only the
    // 0o7777 permission bits are kept, so 100644 and 0644 classify alike.
    assert_eq!(
        CacheReadFailureKind::classify(&cause("100644")),
        CacheReadFailureKind::InsecurePermissions { actual_mode: 0o644 }
    );
    assert_eq!(
        CacheReadFailureKind::classify(&cause("100606")),
        CacheReadFailureKind::InsecurePermissions { actual_mode: 0o606 }
    );

    // Malformed or out-of-range octal text fails closed as `Other` instead of
    // being guessed at or mislabelled as a permission violation.
    for bad in ["8", "", "999999999999999999999999999999999"] {
        let error = cause(bad);
        assert_eq!(
            CacheReadFailureKind::classify(&error),
            CacheReadFailureKind::Other,
            "{error:?}"
        );
        assert_eq!(
            cache_error_status_with_detail(&error),
            cache_error_message(error)
        );
    }
}
