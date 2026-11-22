#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::settings::*;

#[test]
fn defaults_are_sensible() {
    let settings = Settings::default();
    assert!(settings.server_url.contains("bitwarden"));
    assert!(settings.email.is_empty());
    assert_eq!(settings.idle_lock_seconds, DEFAULT_IDLE_LOCK_SECONDS);
    assert_eq!(
        settings.login_timeout_seconds,
        crate::limits::DEFAULT_LOGIN_TIMEOUT.as_secs()
    );
    assert_eq!(
        settings.clipboard_restore_seconds,
        DEFAULT_CLIPBOARD_RESTORE_SECONDS
    );
}

#[test]
fn round_trip_through_temp_file() {
    let dir = std::env::temp_dir().join("bitwarden-gpui-poc-test");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("settings.json");

    let settings = Settings {
        email: "alice@example.com".to_string(),
        server_url: "https://vault.example.com".to_string(),
        thresholds: crate::health::Thresholds {
            weak_bits: 60,
            ..Default::default()
        },
        idle_lock_seconds: 600,
        login_timeout_seconds: 45,
        clipboard_restore_seconds: 60,
        ..Default::default()
    };
    settings.save(&path).expect("failed to save settings");

    let loaded = Settings::load(&path);
    assert_eq!(loaded, settings);
}

#[test]
fn debug_masks_email_and_server_url() {
    let settings = Settings {
        email: "alice@example.com".into(),
        ..Default::default()
    };
    let debug = format!("{settings:?}");
    assert!(!debug.contains("alice@example.com"), "{debug}");
    assert!(debug.contains("[redacted]"), "{debug}");
    // The default URL used to be printed verbatim; it is now masked like the
    // email, so no URL (plain or credential-bearing) reaches a log line.
    assert!(!debug.contains("vault.bitwarden.com"), "{debug}");
    assert!(debug.contains("server_url: \"[redacted]\""), "{debug}");
    // Non-secret fields stay diagnostic: the device id is an identifier.
    assert!(debug.contains("device_id:"), "{debug}");
}

#[test]
fn debug_masks_server_url_embedded_credentials_without_mutating_settings() {
    // Same policy as the cache layer's `mask_url_secrets`: userinfo and query
    // credentials must never be rendered. Settings masks the whole value, so
    // neither the host nor the secrets survive in `Debug`.
    let url = "https://user:SECRET-PASS@vault.example.com:8443/path?token=SECRET-TOKEN";
    let settings = Settings {
        server_url: url.into(),
        ..Default::default()
    };
    let debug = format!("{settings:?}");
    for secret in ["SECRET-PASS", "SECRET-TOKEN", "vault.example.com"] {
        assert!(!debug.contains(secret), "leaked {secret}: {debug}");
    }
    assert!(debug.contains("server_url: \"[redacted]\""), "{debug}");
    // Masking is Debug-only; the stored URL stays byte-for-byte identical.
    assert_eq!(settings.server_url, url);

    // An empty URL is rendered as an empty string, never as a redaction marker.
    let empty = Settings {
        server_url: String::new(),
        ..Default::default()
    };
    assert!(format!("{empty:?}").contains("server_url: \"\""));
}

#[test]
fn sanitized_clamps_editable_fields() {
    let settings = Settings {
        idle_lock_seconds: 0,
        login_timeout_seconds: 0,
        clipboard_restore_seconds: 10_000,
        password_generator: crate::generator::PasswordSettings {
            length: 5000,
            ..Default::default()
        },
        passphrase_generator: crate::generator::PassphraseSettings {
            words: 100,
            ..Default::default()
        },
        thresholds: crate::health::Thresholds {
            weak_bits: u32::MAX,
            stale_days: -1,
        },
        ..Default::default()
    };
    let safe = settings.sanitized();
    assert_eq!(safe.idle_lock_seconds, 60);
    assert_eq!(safe.login_timeout_seconds, 1);
    assert_eq!(safe.clipboard_restore_seconds, 3600);
    assert_eq!(safe.password_generator.length, 128);
    assert_eq!(safe.passphrase_generator.words, 20);
    assert_eq!(safe.thresholds.weak_bits, 200);
    assert_eq!(safe.thresholds.stale_days, 1);
    assert_eq!(settings.idle_lock_seconds, 0, "sanitized must not mutate");
    assert_eq!(settings.thresholds.weak_bits, u32::MAX);
}

#[test]
fn sanitized_clamps_the_remaining_threshold_bounds() {
    use crate::limits::{MAX_STALE_DAYS, MIN_WEAK_BITS};

    // The opposite ends from `sanitized_clamps_editable_fields`: a too-small
    // weak_bits and an over-large stale_days (settings.rs:606-613).
    let settings = Settings {
        thresholds: crate::health::Thresholds {
            weak_bits: 0,
            stale_days: i64::MAX,
        },
        ..Default::default()
    };
    let safe = settings.sanitized();
    assert_eq!(safe.thresholds.weak_bits, MIN_WEAK_BITS);
    assert_eq!(safe.thresholds.stale_days, MAX_STALE_DAYS);
    // sanitized() is a pure clone-based operation.
    assert_eq!(settings.thresholds.weak_bits, 0);
    assert_eq!(settings.thresholds.stale_days, i64::MAX);

    // The same bounds apply when the values come from a hand-edited file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{"thresholds":{"weak_bits":0,"stale_days":9223372036854775807}}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.thresholds.weak_bits, MIN_WEAK_BITS);
    assert_eq!(loaded.thresholds.stale_days, MAX_STALE_DAYS);
}

#[test]
fn load_sanitizes_hand_edited_values() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-sanitize.json");
    std::fs::write(
        &path,
        br#"{"idle_lock_seconds":0,"login_timeout_seconds":0,"clipboard_restore_seconds":99999,
             "thresholds":{"weak_bits":4294967295,"stale_days":-1}}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.idle_lock_seconds, 60);
    assert_eq!(loaded.login_timeout_seconds, 1);
    assert_eq!(loaded.clipboard_restore_seconds, 3600);
    assert_eq!(loaded.thresholds.weak_bits, 200);
    assert_eq!(loaded.thresholds.stale_days, 1);
}

#[test]
fn missing_file_falls_back_to_defaults() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-does-not-exist.json");
    let settings = Settings::load(&path);
    assert_eq!(settings, Settings::default());
}

#[test]
fn load_detailed_distinguishes_missing_and_malformed() {
    let missing = std::env::temp_dir().join("bitwarden-gpui-poc-load-missing.json");
    let _ = std::fs::remove_file(&missing);
    assert_eq!(
        Settings::load_detailed(&missing).err(),
        Some(SettingsLoadError::NotFound)
    );

    let broken = std::env::temp_dir().join("bitwarden-gpui-poc-load-broken.json");
    std::fs::write(&broken, b"not json").unwrap();
    assert_eq!(
        Settings::load_detailed(&broken).err(),
        Some(SettingsLoadError::ParseFailed)
    );

    // Reading a directory as a file fails (EISDIR on Unix).
    let directory = std::env::temp_dir().join("bitwarden-gpui-poc-load-dir");
    std::fs::create_dir_all(&directory).unwrap();
    assert_eq!(
        Settings::load_detailed(&directory).err(),
        Some(SettingsLoadError::ReadFailed)
    );

    for error in [
        SettingsLoadError::NotFound,
        SettingsLoadError::ReadFailed,
        SettingsLoadError::ParseFailed,
        SettingsLoadError::TooLarge,
    ] {
        assert!(!error.message().is_empty());
    }
}

#[test]
fn invalid_utf8_is_a_read_failure_not_a_parse_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // `read_to_string` rejects an invalid UTF-8 sequence with an io error
    // (settings.rs:733-738), so the file is unreadable rather than bad JSON.
    // The classification must stay ReadFailed all the way to the UI enum.
    std::fs::write(&path, b"{\"email\":\"\xff\"}").unwrap();
    let error = Settings::load_detailed(&path).unwrap_err();
    assert!(matches!(error, SettingsLoadError::ReadFailed), "{error:?}");
    assert_eq!(error, SettingsLoadError::ReadFailed);
    assert_eq!(Settings::load(&path), Settings::default());
}

// --- Robustness regressions: nested defaults, per-field fallback, size cap ---

#[test]
fn missing_nested_objects_keep_top_level_fields() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-nested-missing.json");
    std::fs::write(
        &path,
        br#"{"email":"bob@example.com","idle_lock_seconds":120}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.email, "bob@example.com");
    assert_eq!(loaded.idle_lock_seconds, 120);
    assert_eq!(loaded.server_url, defaults.server_url);
    assert_eq!(loaded.password_generator, defaults.password_generator);
    assert_eq!(loaded.passphrase_generator, defaults.passphrase_generator);
    assert_eq!(loaded.thresholds, defaults.thresholds);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn partial_nested_objects_fill_only_missing_fields() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-nested-partial.json");
    std::fs::write(
        &path,
        br#"{"server_url":"https://custom.example",
             "password_generator":{"length":32},
             "passphrase_generator":{"words":6},
             "thresholds":{"stale_days":30},
             "idle_lock_seconds":600}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.server_url, "https://custom.example");
    assert_eq!(loaded.email, "");
    assert_eq!(loaded.idle_lock_seconds, 600);
    assert_eq!(loaded.password_generator.length, 32);
    assert!(
        loaded.password_generator.lowercase,
        "sibling uses its default"
    );
    assert_eq!(loaded.passphrase_generator.words, 6);
    assert_eq!(loaded.passphrase_generator.separator, "-");
    assert_eq!(loaded.thresholds.stale_days, 30);
    assert_eq!(loaded.thresholds.weak_bits, defaults.thresholds.weak_bits);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_typed_fields_fall_back_without_discarding_siblings() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-type-mixed.json");
    std::fs::write(
        &path,
        br#"{"server_url":"https://typed.example",
             "email":42,
             "password_generator":{"length":"long","lowercase":false,"symbols":true},
             "passphrase_generator":{"words":6,"separator":7},
             "thresholds":{"weak_bits":"oops","stale_days":90},
             "idle_lock_seconds":600}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.server_url, "https://typed.example");
    assert_eq!(loaded.email, "", "wrong top-level type falls back");
    assert_eq!(
        loaded.password_generator.length,
        defaults.password_generator.length
    );
    assert!(
        !loaded.password_generator.lowercase,
        "valid sibling survives"
    );
    assert!(loaded.password_generator.symbols, "valid sibling survives");
    assert!(
        loaded.password_generator.uppercase,
        "missing field uses default"
    );
    assert_eq!(loaded.passphrase_generator.words, 6);
    assert_eq!(loaded.passphrase_generator.separator, "-");
    assert!(loaded.passphrase_generator.capitalize);
    assert_eq!(loaded.thresholds.weak_bits, defaults.thresholds.weak_bits);
    assert_eq!(loaded.thresholds.stale_days, 90);
    assert_eq!(loaded.idle_lock_seconds, 600);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn out_of_range_numbers_fall_back_per_field() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-range-mixed.json");
    std::fs::write(
        &path,
        br#"{"server_url":"https://range.example",
             "password_generator":{"length":20.5,"lowercase":false},
             "thresholds":{"weak_bits":-1,"stale_days":120}}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.server_url, "https://range.example");
    assert_eq!(
        loaded.password_generator.length,
        defaults.password_generator.length
    );
    assert!(!loaded.password_generator.lowercase);
    assert_eq!(loaded.thresholds.weak_bits, defaults.thresholds.weak_bits);
    assert_eq!(loaded.thresholds.stale_days, 120);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn oversized_file_is_rejected() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-oversized.json");
    let payload = vec![b' '; MAX_SETTINGS_BYTES as usize + 1];
    std::fs::write(&path, &payload).unwrap();

    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::TooLarge)
    );
    assert_eq!(Settings::load(&path), Settings::default());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_exactly_at_size_limit_is_parsed() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-at-limit.json");
    let mut payload = br#"{"email":"limit@example.com"}"#.to_vec();
    payload.resize(MAX_SETTINGS_BYTES as usize, b' ');
    std::fs::write(&path, &payload).unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "limit@example.com");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn tolerance_stops_at_syntax_and_root_shape() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-bad-root.json");
    // Per-field recovery only applies to object-shaped settings; an array
    // root or invalid JSON still fails the whole file.
    std::fs::write(&path, b"[]").unwrap();
    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::ParseFailed)
    );
    std::fs::write(&path, b"not json").unwrap();
    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::ParseFailed)
    );
    let _ = std::fs::remove_file(&path);
}

// --- Schema version regressions: current marker, legacy files, future rejection ---

#[test]
fn default_carries_current_schema_version() {
    const { assert!(CURRENT_SCHEMA_VERSION > 0) };
    assert_eq!(Settings::default().schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn legacy_file_without_schema_version_is_compatible() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-schema-legacy.json");
    // No schema_version key: an old settings file must still load, but it is
    // reported as legacy instead of being silently promoted to the current
    // version. Every known field is still honoured.
    std::fs::write(
        &path,
        br#"{"email":"legacy@example.com","idle_lock_seconds":120}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION);
    assert_ne!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.email, "legacy@example.com");
    assert_eq!(loaded.idle_lock_seconds, 120);
    assert_eq!(loaded.server_url, defaults.server_url);
    assert_eq!(loaded.password_generator, defaults.password_generator);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn current_and_older_schema_versions_are_accepted() {
    let defaults = Settings::default();
    for version in [0, CURRENT_SCHEMA_VERSION] {
        let path = std::env::temp_dir().join(format!("bitwarden-gpui-poc-schema-v{version}.json"));
        std::fs::write(
            &path,
            format!(r#"{{"schema_version":{version},"email":"v{version}@example.com"}}"#),
        )
        .unwrap();
        let loaded = Settings::load_detailed(&path).unwrap();

        assert_eq!(loaded.email, format!("v{version}@example.com"));
        assert_eq!(loaded.server_url, defaults.server_url);
        assert_eq!(loaded.schema_version, version);
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn unknown_future_schema_version_falls_back_to_defaults() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-schema-future.json");
    let future = CURRENT_SCHEMA_VERSION + 1;
    // A newer writer may have changed what these familiar keys mean, so none
    // of them may survive: the file is rejected wholesale, not field by field.
    std::fs::write(
        &path,
        format!(
            r#"{{"schema_version":{future},"email":"future@example.com",
                 "server_url":"https://future.example","idle_lock_seconds":42}}"#
        ),
    )
    .unwrap();

    assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
    assert_eq!(Settings::load(&path), Settings::default());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn extremely_large_schema_version_is_rejected_too() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-schema-huge.json");
    // u64::MAX no longer fits the u32 field: the raw JSON check must catch it
    // before the tolerance pass can silently replace it with the default.
    std::fs::write(
        &path,
        br#"{"schema_version":18446744073709551615,"email":"huge@example.com"}"#,
    )
    .unwrap();

    assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_typed_schema_version_cannot_claim_a_future_version() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-schema-wrong-type.json");
    std::fs::write(
        &path,
        br#"{"schema_version":{"major":9999},"email":"typed@example.com","idle_lock_seconds":180}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();

    assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION);
    assert_eq!(loaded.email, "typed@example.com", "siblings survive");
    assert_eq!(loaded.idle_lock_seconds, 180);
    let _ = std::fs::remove_file(&path);

    // A numeric string still encodes a future version and must be rejected
    // wholesale, not downgraded to a "compatible" current file.
    std::fs::write(
        &path,
        br#"{"schema_version":"9999","email":"future@example.com"}"#,
    )
    .unwrap();
    assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn save_stamps_current_schema_version() {
    let dir = std::env::temp_dir().join("bitwarden-gpui-poc-schema-save");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("settings.json");

    // Even an in-memory struct still carrying a legacy marker must be
    // upgraded when written; the original value is left untouched.
    let legacy = Settings {
        schema_version: 0,
        email: "save@example.com".to_string(),
        ..Default::default()
    };
    legacy.save(&path).unwrap();
    assert_eq!(legacy.schema_version, 0, "save must not mutate self");

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        raw["schema_version"],
        serde_json::json!(CURRENT_SCHEMA_VERSION)
    );

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.email, "save@example.com");
    let _ = std::fs::remove_dir_all(&dir);
}

// --- Stable device identifier: CSPRNG generation, persistence, resync reuse ---

#[test]
fn generated_device_id_is_a_canonical_v4_uuid() {
    let first = generate_device_id().expect("CSPRNG should be available");
    let second = generate_device_id().expect("CSPRNG should be available");

    for id in [&first, &second] {
        assert!(is_valid_device_id(id), "invalid UUID: {id}");
        assert_eq!(id.len(), 36);
        for (index, ch) in id.chars().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                assert_eq!(ch, '-', "bad hyphen position in {id}");
            } else {
                assert!(ch.is_ascii_hexdigit(), "bad hex digit in {id}");
                assert!(!ch.is_ascii_uppercase(), "UUID must be lowercase: {id}");
            }
        }
        // Version 4 nibble and RFC 4122 variant nibble.
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }
    assert_ne!(first, second, "two independent draws must not collide");
}

#[test]
fn uppercase_hex_device_ids_are_accepted() {
    // `is_valid_device_id` is case-insensitive for hex digits and for the
    // RFC 4122 variant nibble (8/9/a/b), while the version nibble stays `4`.
    // A canonical lowercase id from the CSPRNG is not the only accepted form:
    // an operator-supplied uppercase UUID must be reused instead of replaced.
    let valid = generate_device_id().unwrap();
    let uppercase = valid.to_ascii_uppercase();
    assert!(is_valid_device_id(&uppercase), "{uppercase}");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        format!(r#"{{"device_id":"{uppercase}"}}"#).as_bytes(),
    )
    .unwrap();
    let loaded = Settings::load(&path);
    assert_eq!(
        loaded.device_id, uppercase,
        "uppercase id must survive load"
    );

    let mut wrong_version = uppercase.clone().into_bytes();
    wrong_version[14] = b'5';
    assert!(!is_valid_device_id(
        std::str::from_utf8(&wrong_version).unwrap()
    ));
}

#[test]
fn malformed_device_ids_are_not_reused() {
    let valid = generate_device_id().unwrap();
    assert!(!is_valid_device_id(""));
    assert!(!is_valid_device_id("bitwarden-gpui-poc-install"));
    assert!(!is_valid_device_id(&valid.replace('-', "")));
    assert!(!is_valid_device_id(&valid[..35]));

    let mut wrong_version = valid.clone().into_bytes();
    wrong_version[14] = b'5';
    assert!(!is_valid_device_id(
        std::str::from_utf8(&wrong_version).unwrap()
    ));

    let mut wrong_variant = valid.into_bytes();
    wrong_variant[19] = b'c';
    assert!(!is_valid_device_id(
        std::str::from_utf8(&wrong_variant).unwrap()
    ));
}

#[test]
fn device_id_is_generated_once_and_reused_on_resync() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let mut settings = Settings::default();
    assert!(settings.device_id.is_empty());

    // First sync: generate and persist.
    let first = settings.ensure_device_id(Some(&path)).unwrap().to_string();
    assert!(is_valid_device_id(&first));
    assert_eq!(Settings::load(&path).device_id, first);

    // Resync in the same session must not rotate the identifier.
    let again = settings.ensure_device_id(Some(&path)).unwrap().to_string();
    assert_eq!(again, first);

    // Resync after a restart loads the persisted value and keeps it.
    let mut restarted = Settings::load(&path);
    let after_restart = restarted.ensure_device_id(Some(&path)).unwrap().to_string();
    assert_eq!(after_restart, first);
    assert_eq!(Settings::load(&path).device_id, first);
}

#[test]
fn malformed_stored_device_id_is_replaced_on_next_sync() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let legacy = Settings {
        device_id: "bitwarden-gpui-poc-install".to_string(),
        ..Default::default()
    };
    legacy.save(&path).unwrap();

    let mut loaded = Settings::load(&path);
    assert!(
        loaded.device_id.is_empty(),
        "sanitized() must clear the old hardcoded value"
    );
    let fresh = loaded.ensure_device_id(Some(&path)).unwrap().to_string();
    assert!(is_valid_device_id(&fresh));
    assert_ne!(fresh, "bitwarden-gpui-poc-install");
    assert_eq!(Settings::load(&path).device_id, fresh);
}

#[test]
fn device_id_is_not_a_secret_but_is_serialized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let mut settings = Settings::default();
    let id = settings.ensure_device_id(Some(&path)).unwrap().to_string();

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(raw["device_id"], serde_json::json!(id));
    assert!(
        format!("{settings:?}").contains(&id),
        "device id is an identifier, not a credential"
    );
}

#[test]
fn device_id_save_failure_is_reported_and_retried() {
    let dir = tempfile::tempdir().unwrap();
    let mut settings = Settings::default();

    // A directory path cannot be replaced by the settings file.
    let error = settings.ensure_device_id(Some(dir.path())).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("デバイス ID を保存できませんでした"),
        "{error}"
    );
    assert!(
        settings.device_id.is_empty(),
        "an identifier that was never persisted must not be reused"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the original io error must stay reachable through the cause chain"
    );

    // Once the target is writable the next call generates and persists a new id.
    let path = dir.path().join("settings.json");
    let id = settings.ensure_device_id(Some(&path)).unwrap().to_string();
    assert!(is_valid_device_id(&id));
    assert_eq!(Settings::load(&path).device_id, id);
}

#[test]
fn shared_field_edits_are_owned_by_settings() {
    use crate::settings::SharedSettingsField;
    let mut settings = Settings::default();
    settings.server_url.clear();
    settings.email.clear();
    settings.push_shared_text(SharedSettingsField::ServerUrl, "https://example.com");
    settings.push_shared_text(SharedSettingsField::Email, "a@b.example");
    assert_eq!(settings.server_url, "https://example.com");
    assert_eq!(settings.email, "a@b.example");

    settings.pop_shared_char(SharedSettingsField::ServerUrl);
    settings.pop_shared_char(SharedSettingsField::Email);
    assert_eq!(settings.server_url, "https://example.co");
    assert_eq!(settings.email, "a@b.exampl");
}

#[test]
fn settings_error_round_trip_keeps_status_text() {
    use crate::error::OTHER_ERROR_MESSAGE;
    let settings = SettingsLoadError::Other("設定固有の失敗");
    assert_eq!(AppError::from(settings).message(), "設定固有の失敗");
    let unexpected = AppError::RandomUnavailable;
    assert_eq!(
        SettingsLoadError::from(unexpected).message(),
        OTHER_ERROR_MESSAGE
    );
}

#[test]
fn shared_field_edits_respect_the_auth_caps() {
    use crate::limits::{MAX_EMAIL_LEN, MAX_SERVER_URL_LEN};
    use crate::settings::SharedSettingsField;

    let mut settings = Settings::default();
    settings.server_url.clear();
    settings.email.clear();
    settings.push_shared_text(
        SharedSettingsField::ServerUrl,
        &format!("https://u.example/{}", "s".repeat(MAX_SERVER_URL_LEN)),
    );
    settings.push_shared_text(
        SharedSettingsField::Email,
        &format!("{}@example.com", "a".repeat(MAX_EMAIL_LEN)),
    );
    assert_eq!(settings.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(settings.email.chars().count(), MAX_EMAIL_LEN);

    // The caps are applied on every append, not only on save.
    settings.push_shared_text(SharedSettingsField::Email, "EXTRA");
    assert_eq!(settings.email.chars().count(), MAX_EMAIL_LEN);
    assert!(!settings.email.contains("EXTRA"));
}

#[test]
fn format_characters_are_dropped_from_pushed_email_text() {
    use crate::settings::SharedSettingsField;

    let mut settings = Settings::default();
    settings.email.clear();
    settings.push_shared_text(SharedSettingsField::Email, "alice");
    // Zero-width space (Cf) between the local part and the domain: accepting
    // it would persist an address that `valid_email` later rejects.
    settings.push_shared_text(SharedSettingsField::Email, "\u{200b}@example.com");
    assert_eq!(settings.email, "alice@example.com");
    assert!(!crate::limits::has_format_character(&settings.email));
    assert!(crate::auth::valid_email(&settings.email));

    // Bidi override and soft hyphen are Cf too; a whole pasted chunk is
    // rejected as one input, and later clean input still works.
    settings.push_shared_text(SharedSettingsField::Email, "\u{202e}evil");
    settings.push_shared_text(SharedSettingsField::Email, "\u{ad}");
    assert_eq!(settings.email, "alice@example.com");
    settings.push_shared_text(SharedSettingsField::Email, "+tag");
    assert_eq!(settings.email, "alice@example.com+tag");

    // The URL field keeps the legacy behaviour: only the length cap applies.
    settings.server_url.clear();
    settings.push_shared_text(
        SharedSettingsField::ServerUrl,
        "https://ex\u{200b}ample.com",
    );
    assert!(settings.server_url.contains('\u{200b}'));
}

#[test]
fn sanitized_clamps_length_and_words_at_both_ends() {
    use crate::limits::{MIN_PASSPHRASE_WORDS, MIN_PASSWORD_LENGTH};

    let settings = Settings {
        password_generator: crate::generator::PasswordSettings {
            length: 0,
            ..Default::default()
        },
        passphrase_generator: crate::generator::PassphraseSettings {
            words: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let safe = settings.sanitized();
    assert_eq!(safe.password_generator.length, MIN_PASSWORD_LENGTH);
    assert_eq!(safe.passphrase_generator.words, MIN_PASSPHRASE_WORDS);
    // The original remains untouched (regression guard for the clone-based
    // implementation).
    assert_eq!(settings.password_generator.length, 0);
    assert_eq!(settings.passphrase_generator.words, 0);
}

#[test]
fn infinite_and_huge_schema_markers_are_future_versions() {
    // `version_from_float` maps positive infinity to u64::MAX so a crafted
    // marker cannot be mistaken for a legacy/current schema; negative
    // infinity stays on the legacy side (settings.rs:323-331).
    assert_eq!(super::version_from_float(f64::INFINITY), Some(u64::MAX));
    assert_eq!(super::version_from_float(f64::NEG_INFINITY), None);
    assert_eq!(super::version_from_float(f64::NAN), None);
    assert_eq!(super::version_from_float(2.0), Some(2));
    assert_eq!(super::version_from_float(2.5), None);

    for raw in [
        serde_json::json!(f64::INFINITY),
        serde_json::json!(f64::NEG_INFINITY),
    ] {
        // serde_json serializes non-finite floats as null, so exercise the
        // float helper directly above; numeric strings still reach it via the
        // string branch of `schema_version_of` when they parse as floats.
        assert_eq!(super::schema_version_of(Some(&raw)), None, "{raw}");
    }
    assert_eq!(
        super::schema_version_of(Some(&serde_json::json!("18446744073709551616"))),
        Some(u64::MAX)
    );
}

#[test]
fn sanitized_clamps_shared_text_fields() {
    use crate::limits::{MAX_EMAIL_LEN, MAX_SERVER_URL_LEN};

    let settings = Settings {
        server_url: "s".repeat(MAX_SERVER_URL_LEN + 10),
        email: "e".repeat(MAX_EMAIL_LEN + 10),
        ..Default::default()
    };
    let safe = settings.sanitized();
    assert_eq!(safe.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(safe.email.chars().count(), MAX_EMAIL_LEN);
    // sanitized() must remain a pure clone-based operation.
    assert_eq!(settings.server_url.chars().count(), MAX_SERVER_URL_LEN + 10);
    assert_eq!(settings.email.chars().count(), MAX_EMAIL_LEN + 10);
}

#[test]
fn save_persists_the_sanitized_values_without_mutating_self() {
    // Settings must not depend on the network-oriented auth module just for
    // two neutral text caps; `limits` is the shared source of truth.
    use crate::limits::{MAX_EMAIL_LEN, MAX_SERVER_URL_LEN};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let settings = Settings {
        server_url: "s".repeat(MAX_SERVER_URL_LEN + 5),
        email: "e".repeat(MAX_EMAIL_LEN + 5),
        ..Default::default()
    };
    settings.save(&path).unwrap();

    assert_eq!(settings.server_url.chars().count(), MAX_SERVER_URL_LEN + 5);
    let loaded = Settings::load(&path);
    assert_eq!(loaded.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(loaded.email.chars().count(), MAX_EMAIL_LEN);
}

#[test]
fn future_schema_keeps_a_valid_device_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let valid = generate_device_id().unwrap();
    let future = CURRENT_SCHEMA_VERSION + 1;
    std::fs::write(
        &path,
        format!(
            r#"{{"schema_version":{future},"email":"future@example.com","device_id":"{valid}"}}"#
        ),
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, valid, "opaque id survives a future file");
    assert_eq!(loaded.email, "", "schema-governed fields still fall back");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);

    // A malformed id is still discarded.
    std::fs::write(
        &path,
        format!(r#"{{"schema_version":{future},"device_id":"not-a-uuid"}}"#),
    )
    .unwrap();
    assert!(Settings::load_detailed(&path).unwrap().device_id.is_empty());
}

#[test]
fn save_device_id_only_preserves_other_on_disk_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // A legacy file (no schema marker) exercises both preservation of its
    // fields and the current-version stamping done by the id-only path.
    std::fs::write(
        &path,
        br#"{"email":"keep@example.com","server_url":"https://vault.example.com"}"#,
    )
    .unwrap();

    let id = generate_device_id().unwrap();
    Settings::save_device_id_only(&path, &id).unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, id);
    assert_eq!(loaded.email, "keep@example.com");
    assert_eq!(loaded.server_url, "https://vault.example.com");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn save_device_id_only_preserves_nested_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // The id-only path re-reads the file and stamps the schema before writing
    // (settings.rs:639-677). Nested objects must survive that read-modify-write
    // just like the flat fields; only `device_id` and `schema_version` change.
    std::fs::write(
        &path,
        br#"{
            "email": "keep@example.com",
            "password_generator": {
                "length": 42, "lowercase": true, "uppercase": false,
                "digits": true, "symbols": false, "avoid_ambiguous": true
            },
            "passphrase_generator": {
                "words": 6, "separator": "_", "capitalize": false, "include_number": true
            },
            "thresholds": {"weak_bits": 70, "stale_days": 30},
            "idle_lock_seconds": 123
        }"#,
    )
    .unwrap();

    let id = generate_device_id().unwrap();
    Settings::save_device_id_only(&path, &id).unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, id);
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.password_generator.length, 42);
    assert!(!loaded.password_generator.uppercase);
    assert!(loaded.password_generator.avoid_ambiguous);
    assert_eq!(loaded.passphrase_generator.words, 6);
    assert_eq!(loaded.passphrase_generator.separator, "_");
    assert!(!loaded.passphrase_generator.capitalize);
    assert!(loaded.passphrase_generator.include_number);
    assert_eq!(loaded.thresholds.weak_bits, 70);
    assert_eq!(loaded.thresholds.stale_days, 30);
    assert_eq!(loaded.idle_lock_seconds, 123);
}

#[test]
fn save_device_id_only_creates_a_file_when_none_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let id = generate_device_id().unwrap();

    Settings::save_device_id_only(&path, &id).unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, id);
    assert_eq!(loaded.email, "");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn save_device_id_only_aborts_on_a_malformed_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = b"not json".to_vec();
    std::fs::write(&path, &original).unwrap();

    let id = generate_device_id().unwrap();
    let error = Settings::save_device_id_only(&path, &id).unwrap_err();

    assert!(
        error.to_string().contains("中止") && error.to_string().contains("ParseFailed"),
        "the abort reason must reach the caller: {error}"
    );
    assert!(!error.to_string().contains("既定値"), "{error}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original,
        "a broken file must never be overwritten with defaults"
    );
}

#[test]
fn save_device_id_only_aborts_on_an_oversized_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = vec![b' '; MAX_SETTINGS_BYTES as usize + 1];
    std::fs::write(&path, &original).unwrap();

    let id = generate_device_id().unwrap();
    assert!(Settings::save_device_id_only(&path, &id).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn ensure_device_id_keeps_its_save_error_classification_on_a_broken_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = b"not json".to_vec();
    std::fs::write(&path, &original).unwrap();

    let mut settings = Settings::default();
    let error = settings.ensure_device_id(Some(&path)).unwrap_err();

    // A failed pre-read is still reported through the same save variant, with
    // the io error in the cause chain, and the id is never accepted in memory.
    assert!(matches!(
        &error,
        crate::error::AppError::SettingsSaveCause(_, _)
    ));
    assert!(error
        .to_string()
        .contains("デバイス ID を保存できませんでした"));
    assert!(std::error::Error::source(&error).is_some());
    assert!(settings.device_id.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn integral_float_schema_version_is_rejected_as_future() {
    let dir = std::env::temp_dir().join("bitwarden-gpui-poc-float-schema");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    std::fs::write(
        &path,
        br#"{"schema_version":2.0,"email":"future@example.com"}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_ne!(loaded.email, "future@example.com");
}

#[test]
fn load_advisories_reports_future_version_and_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{"schema_version":99,"email":"e@example.com","mystery_key":1}"#,
    )
    .unwrap();
    let notices = load_advisories(&path);
    assert!(
        notices.iter().any(|n| n.contains("バージョン 99")),
        "{notices:?}"
    );
    assert!(
        notices.iter().any(|n| n.contains("mystery_key")),
        "{notices:?}"
    );
}

#[test]
fn every_serialized_settings_field_is_in_the_known_key_list() {
    // `KNOWN` in `load_advisories` is maintained by hand next to `Settings`'s
    // serde fields (settings.rs:331-365). A new field missing from that list
    // would be reported as an unknown key on every load, so pin the subset
    // relation through the public advisory output.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let value = serde_json::to_value(Settings::default()).unwrap();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

    let notices = load_advisories(&path);
    assert!(notices.is_empty(), "{notices:?}");
}

#[test]
fn load_advisories_is_empty_for_valid_or_oversized_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(&path, br#"{"schema_version":1,"email":"e@example.com"}"#).unwrap();
    assert!(load_advisories(&path).is_empty());
    let oversized = usize::try_from(MAX_SETTINGS_BYTES + 2).unwrap();
    std::fs::write(&path, vec![b' '; oversized]).unwrap();
    assert!(
        load_advisories(&path).is_empty(),
        "oversized files are skipped"
    );
}

#[test]
fn save_device_id_only_aborts_on_future_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = br#"{"schema_version":999,"email":"future@example.com"}"#.to_vec();
    std::fs::write(&path, &original).unwrap();
    let id = generate_device_id().unwrap();
    let error = Settings::save_device_id_only(&path, &id).unwrap_err();
    assert!(error.to_string().contains("未対応"), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn save_device_id_only_aborts_on_string_and_float_future_schema() {
    for body in [
        br#"{"schema_version":"999","email":"future@example.com"}"#.as_slice(),
        br#"{"schema_version":99.0,"email":"future@example.com"}"#.as_slice(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = body.to_vec();
        std::fs::write(&path, &original).unwrap();
        let id = generate_device_id().unwrap();
        let error = Settings::save_device_id_only(&path, &id).unwrap_err();
        assert!(error.to_string().contains("未対応"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[test]
fn save_aborts_on_a_future_schema_file() {
    // `save` must honour the same guard as `save_device_id_only`, regardless
    // of how the future writer encoded the marker.
    for body in [
        br#"{"schema_version":999,"email":"future@example.com"}"#.as_slice(),
        br#"{"schema_version":"999","email":"future@example.com"}"#.as_slice(),
        br#"{"schema_version":99.0,"email":"future@example.com"}"#.as_slice(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = body.to_vec();
        std::fs::write(&path, &original).unwrap();

        let error = Settings::default().save(&path).unwrap_err();
        assert!(error.to_string().contains("未対応"), "{error}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "a future file must never be overwritten"
        );
    }
}

#[test]
fn save_still_replaces_current_and_legacy_schema_files() {
    // The guard only rejects future markers; a legacy file is still upgraded
    // by the normal stamped write.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(&path, br#"{"schema_version":0,"email":"old@example.com"}"#).unwrap();

    Settings {
        email: "new@example.com".to_string(),
        ..Default::default()
    }
    .save(&path)
    .unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "new@example.com");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn schema_version_beyond_u64_is_treated_as_future() {
    const BEYOND_U64: &str = "18446744073709551616";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // `parse::<u64>()` fails, but this is plainly a future version and must
    // not be downgraded to a compatible legacy file by any write path.
    let original = format!(r#"{{"schema_version":"{BEYOND_U64}","email":"future@example.com"}}"#);
    std::fs::write(&path, &original).unwrap();

    assert_eq!(super::file_schema_version(&path), Some(u64::MAX));
    assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
    assert!(Settings::default().save(&path).is_err());
    let id = generate_device_id().unwrap();
    assert!(Settings::save_device_id_only(&path, &id).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn file_schema_version_reads_only_the_marker_without_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

    std::fs::write(&path, br#"{"schema_version":7,"email":"x@example.com"}"#).unwrap();
    assert_eq!(super::file_schema_version(&path), Some(7));
    std::fs::write(&path, br#"{"email":"x@example.com"}"#).unwrap();
    assert_eq!(super::file_schema_version(&path), None);
    std::fs::write(&path, b"not json").unwrap();
    assert_eq!(super::file_schema_version(&path), None);
}

#[test]
fn file_schema_version_ignores_oversized_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // The cap must be applied before parsing so a hostile file cannot force a
    // full read just to inspect one number.
    let mut body = br#"{"schema_version":999}"#.to_vec();
    body.resize(MAX_SETTINGS_BYTES as usize + 1, b' ');
    std::fs::write(&path, &body).unwrap();

    assert_eq!(super::file_schema_version(&path), None);
}

#[test]
fn save_replaces_a_corrupt_or_oversized_file() {
    // `save` refuses only a *future* schema. Missing, unreadable, oversized and
    // malformed files are all replaced with the sanitized struct, matching the
    // load fallbacks (settings.rs:692-721).
    for original in [
        b"not json".to_vec(),
        vec![b' '; MAX_SETTINGS_BYTES as usize + 2],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, &original).unwrap();

        Settings {
            email: "new@example.com".to_string(),
            ..Default::default()
        }
        .save(&path)
        .expect("a broken file must be replaced by save");

        let loaded = Settings::load_detailed(&path).unwrap();
        assert_eq!(loaded.email, "new@example.com");
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    }
}

#[test]
fn load_advisories_warns_about_string_and_float_future_versions() {
    for (body, expected_version) in [
        (
            br#"{"schema_version":"999","email":"e@example.com"}"#.as_slice(),
            "999",
        ),
        (
            br#"{"schema_version":99.0,"email":"e@example.com"}"#.as_slice(),
            "99",
        ),
        (
            br#"{"schema_version":2e3,"email":"e@example.com"}"#.as_slice(),
            "2000",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, body).unwrap();

        // The advisory must agree with `load_detailed`, which discards all
        // schema-governed fields for such a file.
        assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
        let notices = load_advisories(&path);
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("未対応") && notice.contains(expected_version)),
            "{body:?}: {notices:?}"
        );
    }
}

#[test]
fn load_advisories_skips_an_oversized_file_even_with_a_future_marker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // The marker is right at the start, but the file is one byte past the cap:
    // the advisory pass must not parse it (settings.rs:238-250).
    let mut body = br#"{"schema_version":999,"email":"e@example.com"}"#.to_vec();
    body.resize(MAX_SETTINGS_BYTES as usize + 1, b' ');
    std::fs::write(&path, &body).unwrap();

    assert!(load_advisories(&path).is_empty());
}

#[test]
fn negative_fractional_and_non_numeric_schema_versions_are_legacy() {
    // `version_from_float` must classify these as "not a version marker", so
    // `parse_settings` reports LEGACY instead of treating them as future (which
    // would discard every field) or silently promoting them to current.
    for body in [
        r#"{"schema_version":-1,"email":"neg@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":-2.5,"email":"frac@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":1.5,"email":"frac@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":" -1 ","email":"neg@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":"1.5","email":"frac@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":"NaN","email":"nan@example.com","idle_lock_seconds":123}"#,
    ] {
        let loaded = Settings::parse_settings(body).unwrap();
        assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION, "{body}");
        assert_eq!(loaded.idle_lock_seconds, 123, "{body}");
        // A legacy marker stays compatible: known fields are still honoured.
        assert_eq!(loaded.server_url, Settings::default().server_url, "{body}");
    }

    for raw in [
        serde_json::json!(-1),
        serde_json::json!(-0.5),
        serde_json::json!(1.5),
        serde_json::json!("NaN"),
        serde_json::json!(" -1 "),
    ] {
        assert_eq!(super::schema_version_of(Some(&raw)), None, "{raw}");
    }
    // Integral floats stay on the future side of the guard (regression guard
    // for the adjacent branch).
    assert_eq!(
        super::schema_version_of(Some(&serde_json::json!(2.0))),
        Some(2)
    );
}

#[test]
fn settings_load_error_to_app_error_matrix() {
    let cases = [
        (SettingsLoadError::NotFound, AppError::NotFound),
        (SettingsLoadError::ReadFailed, AppError::ReadFailed),
        (SettingsLoadError::ParseFailed, AppError::ParseFailed),
        (SettingsLoadError::TooLarge, AppError::TooLarge),
        (
            SettingsLoadError::Other("固有の失敗"),
            AppError::Other("固有の失敗".to_string()),
        ),
    ];
    for (source, expected) in cases {
        let converted = AppError::from(source);
        assert_eq!(converted.message(), expected.message());
        assert_eq!(converted.to_string(), expected.to_string());
    }
}

#[test]
fn app_error_to_settings_load_error_matrix() {
    use crate::error::{BoxedCause, OTHER_ERROR_MESSAGE};

    let plain = [
        (AppError::NotFound, SettingsLoadError::NotFound),
        (AppError::ReadFailed, SettingsLoadError::ReadFailed),
        (AppError::ParseFailed, SettingsLoadError::ParseFailed),
        (AppError::TooLarge, SettingsLoadError::TooLarge),
    ];
    for (source, expected) in plain {
        assert_eq!(SettingsLoadError::from(source), expected);
    }
    // Cause-carrying variants collapse to their plain sibling.
    assert_eq!(
        SettingsLoadError::from(AppError::ReadFailedCause(BoxedCause::text("io"))),
        SettingsLoadError::ReadFailed
    );
    assert_eq!(
        SettingsLoadError::from(AppError::ParseFailedCause(BoxedCause::text("json"))),
        SettingsLoadError::ParseFailed
    );
    // Every other AppError variant lands in the catch-all; the text is
    // intentionally not preserved by this direction of the conversion.
    for source in [
        AppError::Other("custom".to_string()),
        AppError::Timeout,
        AppError::RandomUnavailable,
        AppError::InvalidLogin("bad".to_string()),
    ] {
        assert_eq!(
            SettingsLoadError::from(source),
            SettingsLoadError::Other(OTHER_ERROR_MESSAGE)
        );
    }
}

#[test]
fn sanitized_uses_the_ui_email_format_policy() {
    use crate::limits::has_format_character;

    // The UI path (push_shared_text) strips a leading ZWSP run and rejects any
    // other `Cf` wholesale. sanitized() must agree, otherwise load() can store
    // an address the login form rejects forever (settings.rs:537,143-158).
    let leading = Settings {
        email: "\u{200b}\u{200c}alice@example.com".into(),
        ..Default::default()
    };
    let safe = leading.sanitized();
    assert_eq!(safe.email, "alice@example.com");
    assert!(!has_format_character(&safe.email));
    assert!(crate::auth::valid_email(&safe.email));

    // Bidi override and an interior zero-width character are rejected whole.
    for raw in [
        "alice\u{202e}@example.com",
        "al\u{200b}ice@example.com",
        "\u{ad}alice@example.com",
    ] {
        let settings = Settings {
            email: raw.into(),
            ..Default::default()
        };
        let safe = settings.sanitized();
        assert!(
            safe.email.is_empty(),
            "a hand-edited address with an unexpected Cf must be cleared: {raw:?}"
        );
        // sanitized() stays a pure clone-based operation.
        assert_eq!(settings.email, raw);
    }

    // The URL field is not subject to the email structural policy.
    let urls = Settings {
        server_url: "https://ex\u{200b}ample.com".into(),
        ..Default::default()
    };
    assert_eq!(urls.sanitized().server_url, urls.server_url);
}

#[test]
fn sanitized_clips_clipboard_delay_to_the_lower_bound() {
    use crate::limits::{MAX_CLIPBOARD_RESTORE_SECONDS, MIN_CLIPBOARD_RESTORE_SECONDS};

    for (input, expected) in [
        (0, MIN_CLIPBOARD_RESTORE_SECONDS),
        (10_000, MAX_CLIPBOARD_RESTORE_SECONDS),
    ] {
        let settings = Settings {
            clipboard_restore_seconds: input,
            ..Default::default()
        };
        assert_eq!(settings.sanitized().clipboard_restore_seconds, expected);
    }
}

#[test]
fn ensure_device_id_without_a_path_only_uses_memory() {
    let mut settings = Settings::default();
    let generated = settings.ensure_device_id(None).unwrap().to_string();
    assert!(is_valid_device_id(&generated));
    assert_eq!(settings.device_id, generated);

    // A second call must reuse the in-memory value; no file is involved.
    assert_eq!(settings.ensure_device_id(None).unwrap(), generated);
}

#[test]
fn deterministic_uppercase_device_id_variant_is_accepted_and_reused() {
    // A fixed literal keeps this branch deterministic: no CSPRNG draw is
    // needed to build an uppercase variant (settings.rs:514-530).
    const UPPER: &str = "A1B2C3D4-1234-4ABC-8DEF-0123456789AB";
    assert_eq!(UPPER.len(), 36);
    assert_eq!(UPPER.as_bytes()[14], b'4');
    assert_eq!(UPPER.as_bytes()[19], b'8');
    assert!(is_valid_device_id(UPPER), "{UPPER}");
    assert!(is_valid_device_id(&UPPER.to_ascii_lowercase()));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(&path, format!(r#"{{"device_id":"{UPPER}"}}"#).as_bytes()).unwrap();
    let loaded = Settings::load(&path);
    assert_eq!(
        loaded.device_id, UPPER,
        "uppercase id must be reused verbatim"
    );

    // A variant nibble outside 8/9/a/b/A/B is still rejected.
    let mut bad = UPPER.as_bytes().to_vec();
    bad[19] = b'C';
    assert!(!is_valid_device_id(std::str::from_utf8(&bad).unwrap()));
}

#[test]
fn uppercase_variant_nibbles_a_and_b_are_accepted_deterministically() {
    // Fixed literals keep the A/B variant branch deterministic: no CSPRNG
    // draw can be relied on to produce those nibbles (settings.rs:519-535).
    const UPPER_A: &str = "A1B2C3D4-1234-4ABC-ADEF-0123456789AB";
    const UPPER_B: &str = "A1B2C3D4-1234-4ABC-BDEF-0123456789AB";
    for id in [UPPER_A, UPPER_B] {
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'A' | b'B'), "{id}");
        assert!(is_valid_device_id(id), "{id}");
        assert!(is_valid_device_id(&id.to_ascii_lowercase()));

        // A valid uppercase id must survive both sanitizing and a load from
        // a hand-edited settings file instead of being regenerated.
        let settings = Settings {
            device_id: id.to_string(),
            ..Default::default()
        };
        assert_eq!(settings.sanitized().device_id, id);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, format!(r#"{{"device_id":"{id}"}}"#).as_bytes()).unwrap();
        assert_eq!(Settings::load(&path).device_id, id);
    }

    // Other variant nibbles stay invalid even when written in upper case.
    for variant in *b"CDF" {
        let mut bytes = UPPER_A.as_bytes().to_vec();
        bytes[19] = variant;
        let invalid = std::str::from_utf8(&bytes).unwrap();
        assert!(!is_valid_device_id(invalid), "{invalid}");
    }
}

#[test]
fn every_leading_200b_to_200f_character_is_stripped_from_email() {
    use crate::limits::has_format_character;
    use crate::settings::SharedSettingsField;

    // U+200C (ZWNJ) used to be rejected unless U+200B came first; the doc
    // promises the whole U+200B..U+200F run is tolerated at the start
    // (settings.rs:116-139).
    for prefix in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}'] {
        let mut settings = Settings::default();
        settings.email.clear();
        settings.push_shared_text(
            SharedSettingsField::Email,
            &format!("{prefix}alice@example.com"),
        );
        assert_eq!(
            settings.email, "alice@example.com",
            "prefix U+{:04X}",
            prefix as u32
        );

        let from_file = Settings {
            email: format!("{prefix}alice@example.com"),
            ..Default::default()
        }
        .sanitized();
        assert_eq!(from_file.email, "alice@example.com");
        assert!(!has_format_character(&from_file.email));
        assert!(crate::auth::valid_email(&from_file.email));
    }

    // A zero-width character after the first visible character is still
    // rejected wholesale, not filtered in place.
    let interior = Settings {
        email: "al\u{200c}ice@example.com".into(),
        ..Default::default()
    };
    assert!(interior.sanitized().email.is_empty());
}

#[test]
fn leading_zero_width_run_followed_by_another_cf_is_rejected_wholesale() {
    use crate::settings::SharedSettingsField;

    // Only a leading U+200B..U+200F run is tolerated (settings.rs:116-144).
    // A different format character after that run, or a zero-width one after
    // the first visible character, rejects the whole value instead of
    // filtering characters in place — both on the UI input path and on load.
    for raw in [
        "\u{200b}\u{200c}\u{202e}alice@example.com",
        "\u{200b}\u{200f}\u{ad}alice@example.com",
        "\u{200c}\u{200d}\u{200b}al\u{200b}ice@example.com",
    ] {
        let mut pushed = Settings::default();
        pushed.push_shared_text(SharedSettingsField::Email, raw);
        assert!(pushed.email.is_empty(), "pushed {raw:?}");

        let original = Settings {
            email: raw.to_string(),
            ..Default::default()
        };
        assert!(original.sanitized().email.is_empty(), "loaded {raw:?}");
        assert_eq!(original.email, raw, "sanitized() must be a pure clone");
    }

    // A consecutive leading run with no other Cf is stripped completely.
    let clean = Settings {
        email: "\u{200b}\u{200c}\u{200d}alice@example.com".into(),
        ..Default::default()
    }
    .sanitized();
    assert_eq!(clean.email, "alice@example.com");
    assert!(crate::auth::valid_email(&clean.email));
}
