#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::settings::*;

/// Serializes tests that mutate process-global environment variables.
///
/// The `EnvGuard` in `default_path_is_unchanged_after_the_config_environment_changes`
/// restores the previous value on drop, but that alone does not stop two tests
/// from changing `XDG_CONFIG_HOME` at the same time. Every env-touching test
/// must hold this lock for its whole body.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

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
fn generator_boolean_fields_survive_load_sanitize_and_round_trip() {
    // `digits`, `symbols` and `avoid_ambiguous` (password) plus `include_number`
    // (passphrase) are persisted booleans. `sanitized()` only clamps numeric
    // bounds, so a hand-edited file must keep every valid boolean spelling,
    // including `false` for flags whose default is `true`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{
            "password_generator": {
                "length": 16,
                "lowercase": true,
                "uppercase": true,
                "digits": false,
                "symbols": false,
                "avoid_ambiguous": true
            },
            "passphrase_generator": {
                "words": 5,
                "separator": "_",
                "capitalize": false,
                "include_number": true
            }
        }"#,
    )
    .unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert!(!loaded.password_generator.digits);
    assert!(!loaded.password_generator.symbols);
    assert!(loaded.password_generator.avoid_ambiguous);
    assert!(loaded.passphrase_generator.include_number);
    // Siblings omitted from the file keep their defaults.
    assert!(loaded.password_generator.lowercase);
    assert!(loaded.password_generator.uppercase);
    // The defaults differ from the hand-edited values, so the assertions above
    // are not vacuous.
    let defaults = Settings::default();
    assert!(defaults.password_generator.digits);
    assert!(defaults.password_generator.symbols);
    assert!(!defaults.password_generator.avoid_ambiguous);
    assert!(!defaults.passphrase_generator.include_number);

    // `sanitized()` preserves booleans; it only clamps numeric fields.
    let safe = loaded.sanitized();
    assert!(!safe.password_generator.digits);
    assert!(!safe.password_generator.symbols);
    assert!(safe.password_generator.avoid_ambiguous);
    assert!(safe.passphrase_generator.include_number);

    // `save` writes the same booleans back; the round trip is lossless.
    safe.save(&path).unwrap();
    let reloaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(reloaded.password_generator, safe.password_generator);
    assert_eq!(reloaded.passphrase_generator, safe.passphrase_generator);

    // A wrong JSON type falls back per field without discarding valid flags.
    std::fs::write(
        &path,
        br#"{
            "password_generator": {"digits": "no", "symbols": true, "avoid_ambiguous": 1},
            "passphrase_generator": {"include_number": "yes", "capitalize": false}
        }"#,
    )
    .unwrap();
    let tolerant = Settings::load_detailed(&path).unwrap();
    assert!(
        tolerant.password_generator.digits,
        "a wrong-typed boolean uses the default"
    );
    assert!(
        tolerant.password_generator.symbols,
        "a valid sibling survives"
    );
    assert!(
        !tolerant.password_generator.avoid_ambiguous,
        "a wrong-typed boolean uses the default"
    );
    assert!(
        !tolerant.passphrase_generator.include_number,
        "a wrong-typed boolean uses the default"
    );
    assert!(
        !tolerant.passphrase_generator.capitalize,
        "a valid sibling survives"
    );
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

    // An empty email is rendered as an empty string, not as the redaction
    // marker: the guard in `Settings`'s Debug is on `email.is_empty()`
    // (settings.rs:349-356), matching the empty-URL branch above.
    let empty_email = Settings {
        email: String::new(),
        ..Default::default()
    };
    let empty_debug = format!("{empty_email:?}");
    assert!(empty_debug.contains("email: \"\""), "{empty_debug}");
    assert!(
        !empty_debug.contains("email: \"[redacted]\""),
        "{empty_debug}"
    );
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
    use crate::limits::{
        MAX_CLIPBOARD_RESTORE_SECONDS, MAX_PASSPHRASE_WORDS, MAX_PASSWORD_LENGTH, MAX_WEAK_BITS,
        MIN_IDLE_LOCK_SECONDS, MIN_LOGIN_TIMEOUT_SECONDS, MIN_STALE_DAYS,
    };

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
    // The clamp bounds live in `crate::limits`, shared with the UI adjusters
    // and the auth layer; no duplicated magic numbers in this expectation.
    assert_eq!(safe.idle_lock_seconds, MIN_IDLE_LOCK_SECONDS);
    assert_eq!(safe.login_timeout_seconds, MIN_LOGIN_TIMEOUT_SECONDS);
    assert_eq!(
        safe.clipboard_restore_seconds,
        MAX_CLIPBOARD_RESTORE_SECONDS
    );
    assert_eq!(safe.password_generator.length, MAX_PASSWORD_LENGTH);
    assert_eq!(safe.passphrase_generator.words, MAX_PASSPHRASE_WORDS);
    assert_eq!(safe.thresholds.weak_bits, MAX_WEAK_BITS);
    assert_eq!(safe.thresholds.stale_days, MIN_STALE_DAYS);
    assert_eq!(settings.idle_lock_seconds, 0, "sanitized must not mutate");
    assert_eq!(settings.thresholds.weak_bits, u32::MAX);
}

#[test]
fn sanitized_clamps_the_remaining_threshold_bounds() {
    use crate::limits::{MAX_STALE_DAYS, MIN_WEAK_BITS};

    // The opposite ends from `sanitized_clamps_editable_fields`: a too-small
    // weak_bits and an over-large stale_days (settings.rs:706-713).
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
    use crate::limits::{
        MAX_CLIPBOARD_RESTORE_SECONDS, MAX_WEAK_BITS, MIN_IDLE_LOCK_SECONDS,
        MIN_LOGIN_TIMEOUT_SECONDS, MIN_STALE_DAYS,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{"idle_lock_seconds":0,"login_timeout_seconds":0,"clipboard_restore_seconds":99999,
             "thresholds":{"weak_bits":4294967295,"stale_days":-1}}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    // Expectations come from the shared `limits` module, the same source of
    // truth `Settings::sanitized()` clamps against; no duplicated magic numbers
    // that could drift when a UI bound is revised.
    assert_eq!(loaded.idle_lock_seconds, MIN_IDLE_LOCK_SECONDS);
    assert_eq!(loaded.login_timeout_seconds, MIN_LOGIN_TIMEOUT_SECONDS);
    assert_eq!(
        loaded.clipboard_restore_seconds,
        MAX_CLIPBOARD_RESTORE_SECONDS
    );
    assert_eq!(loaded.thresholds.weak_bits, MAX_WEAK_BITS);
    assert_eq!(loaded.thresholds.stale_days, MIN_STALE_DAYS);
}

#[test]
fn missing_file_falls_back_to_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let settings = Settings::load(&path);
    assert_eq!(settings, Settings::default());
}

#[test]
fn load_detailed_distinguishes_missing_and_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.json");
    assert_eq!(
        Settings::load_detailed(&missing).err(),
        Some(SettingsLoadError::NotFound)
    );

    let broken = dir.path().join("broken.json");
    std::fs::write(&broken, b"not json").unwrap();
    assert_eq!(
        Settings::load_detailed(&broken).err(),
        Some(SettingsLoadError::ParseFailed)
    );

    // Reading a directory as a file fails (EISDIR on Unix).
    let directory = dir.path().join("directory");
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
    // (settings.rs:391-396), so the file is unreadable rather than bad JSON.
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
fn server_url_type_mismatch_falls_back_per_field_without_discarding_siblings() {
    use serde_json::json;

    // `wrong_typed_fields_fall_back_without_discarding_siblings` pins the
    // reverse case (a bad `email` beside a good URL). Here the URL itself has
    // the wrong JSON type: `tolerant_struct` (settings.rs:564-605) must replace
    // only that field with `Settings::default().server_url` and keep every
    // correctly typed sibling. Each JSON tag is covered, including a number
    // that no serde coercion can turn into a `String`.
    let defaults = Settings::default();
    for bad in [
        json!(null),
        json!(42),
        json!(1.5),
        json!(true),
        json!(["https://array.example"]),
        json!({"url": "https://object.example"}),
    ] {
        let input = json!({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "server_url": bad,
            "email": "keep@example.com",
            "idle_lock_seconds": 600,
            "login_timeout_seconds": 45,
            "password_generator": {"length": 32},
            "thresholds": {"weak_bits": 60, "stale_days": 30},
        });
        let loaded = Settings::parse_settings(&input.to_string()).unwrap();
        assert_eq!(loaded.server_url, defaults.server_url, "bad url: {bad}");
        assert_eq!(loaded.email, "keep@example.com", "bad url: {bad}");
        assert_eq!(loaded.idle_lock_seconds, 600, "bad url: {bad}");
        assert_eq!(loaded.login_timeout_seconds, 45, "bad url: {bad}");
        assert_eq!(loaded.password_generator.length, 32, "bad url: {bad}");
        assert!(loaded.password_generator.lowercase, "bad url: {bad}");
        assert_eq!(loaded.thresholds.weak_bits, 60, "bad url: {bad}");
        assert_eq!(loaded.thresholds.stale_days, 30, "bad url: {bad}");
        assert_eq!(
            loaded.schema_version, CURRENT_SCHEMA_VERSION,
            "bad url: {bad}"
        );
    }

    // The same fallback holds on the real file-load path, after `sanitized()`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{"schema_version":1,"server_url":123,"email":"file@example.com","thresholds":{"stale_days":90}}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.server_url, defaults.server_url);
    assert_eq!(loaded.email, "file@example.com");
    assert_eq!(loaded.thresholds.stale_days, 90);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn out_of_range_numbers_fall_back_per_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let mut payload = br#"{"email":"limit@example.com"}"#.to_vec();
    payload.resize(MAX_SETTINGS_BYTES as usize, b' ');
    std::fs::write(&path, &payload).unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "limit@example.com");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn tolerance_stops_at_syntax_and_root_shape() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    // Every scalar root fails the same shape check (not only arrays).
    for scalar in [b"42".as_slice(), b"\"settings\"", b"true", b"null"] {
        std::fs::write(&path, scalar).unwrap();
        assert!(
            matches!(
                Settings::load_detailed(&path).err(),
                Some(SettingsLoadError::ParseFailed)
            ),
            "scalar root {scalar:?} must be rejected by shape"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn current_schema_drops_non_string_device_ids_per_field() {
    const A1B2C3D4: &str = "A1B2C3D4-1234-4ABC-8DEF-0123456789AB";
    // A current-schema file uses per-field tolerance instead of the future
    // rescue path: a non-string `device_id` is dropped while siblings survive.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    for device_id in [
        serde_json::json!(42),
        serde_json::json!([A1B2C3D4]),
        serde_json::json!({ "uuid": A1B2C3D4 }),
        serde_json::json!(true),
    ] {
        let body = serde_json::json!({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "email": "keep@example.com",
            "device_id": device_id,
        });
        std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
        let loaded = Settings::load_detailed(&path).unwrap();
        assert_eq!(loaded.device_id, "");
        assert_eq!(loaded.email, "keep@example.com");
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    }
}

// --- Schema version regressions: current marker, legacy files, future rejection ---

#[test]
fn default_carries_current_schema_version() {
    const { assert!(CURRENT_SCHEMA_VERSION > 0) };
    assert_eq!(Settings::default().schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn legacy_file_without_schema_version_is_compatible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

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
    // Write the legacy value as raw JSON: `Settings::save` calls `sanitized()`
    // (settings.rs:930-943) and would clear the id *before* writing, so it
    // cannot exercise the read-time sanitization under test here. Every other
    // field falls back to its serde default, which is exactly the shape of a
    // hand-edited or older settings file.
    let raw = br#"{"schema_version":1,"device_id":"bitwarden-gpui-poc-install"}"#;
    std::fs::write(&path, raw).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("bitwarden-gpui-poc-install"),
        "the malformed value must really be on disk before load"
    );

    let mut loaded = Settings::load(&path);
    assert!(
        loaded.device_id.is_empty(),
        "sanitized() must clear the old hardcoded value on load"
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
fn settings_load_error_messages_are_pinned() {
    // These four strings are shown verbatim in the status bar; changing one
    // silently would break the UI wording contract (settings.rs:286-297).
    assert_eq!(
        SettingsLoadError::NotFound.message(),
        "設定ファイルが未作成です（既定値を使用）"
    );
    assert_eq!(
        SettingsLoadError::ReadFailed.message(),
        "設定ファイルを読み込めません（既定値を使用）"
    );
    assert_eq!(
        SettingsLoadError::ParseFailed.message(),
        "設定ファイルが破損しています（既定値を使用）"
    );
    assert_eq!(
        SettingsLoadError::TooLarge.message(),
        "設定ファイルがサイズ上限（1 MiB）を超えています（既定値を使用）"
    );

    for error in [
        SettingsLoadError::NotFound,
        SettingsLoadError::ReadFailed,
        SettingsLoadError::ParseFailed,
        SettingsLoadError::TooLarge,
    ] {
        let expected = error.message();
        assert_eq!(error.to_string(), expected);
        assert_eq!(AppError::from(error).message(), expected);
    }
}

#[test]
fn save_device_id_only_aborts_on_a_read_failed_file() {
    let dir = tempfile::tempdir().unwrap();
    // A directory cannot be read as a settings file: File::open succeeds but
    // read_to_string fails with EISDIR, which `read_bounded_settings_text`
    // classifies as ReadFailed (settings.rs:383-401). No other load failure
    // (malformed / oversized) is accepted on the id-only write path.
    let path = dir.path();
    let id = generate_device_id().unwrap();
    let error = Settings::save_device_id_only(path, &id).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("中止"), "{text}");
    assert!(text.contains("ReadFailed"), "{text}");
    // The id-only path aborts instead of falling back to defaults, so the
    // promise of "default values" must not appear in its error text.
    assert!(!text.contains("既定値"), "{text}");
    assert_eq!(
        std::fs::read_dir(path).unwrap().count(),
        0,
        "nothing was written"
    );
}

#[test]
#[cfg(unix)]
fn save_device_id_only_reports_a_failed_final_write() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = br#"{"schema_version":1,"email":"keep@example.com"}"#;
    std::fs::write(&path, original).unwrap();

    // Reading and parsing still succeed; a read-only parent stops the final
    // `write_private` (settings.rs:798) before it can create its temporary
    // file (private_file.rs:47). This isolates the write failure from the
    // read/parse abort cases above.
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(dir.path(), perms).unwrap();

    let id = generate_device_id().unwrap();
    let error = Settings::save_device_id_only(&path, &id).unwrap_err();

    // Restore write access before asserting so TempDir can clean up.
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(dir.path(), perms).unwrap();

    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original.as_slice(),
        "a failed write must leave the existing file byte-for-byte intact"
    );
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
    // infinity stays on the legacy side (settings.rs:478-486).
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
fn infinity_spelled_as_a_schema_string_saturates_but_negative_is_legacy() {
    use serde_json::json;

    // `schema_version_of` (settings.rs:521-535) tries u64 first, then f64.
    // `serde_json` serializes a non-finite JSON number as null, so the sibling
    // test can only reach `version_from_float` directly; a hand-edited file
    // can still carry the literal strings "Infinity"/"-Infinity", which
    // Rust's f64 parser accepts. The positive spelling must saturate to
    // u64::MAX (a future marker), the negative one must stay legacy (None).
    for marker in ["Infinity", "infinity", "inf"] {
        assert_eq!(
            super::schema_version_of(Some(&json!(marker))),
            Some(u64::MAX),
            "{marker}"
        );
    }
    for marker in ["-Infinity", "-infinity", "-inf"] {
        assert_eq!(
            super::schema_version_of(Some(&json!(marker))),
            None,
            "{marker}"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

    // Positive Infinity on disk: whole-file future fallback, raw marker still
    // readable for the advisory.
    let future =
        r#"{"schema_version":"Infinity","email":"future@example.com","idle_lock_seconds":123}"#;
    std::fs::write(&path, future).unwrap();
    assert_eq!(
        super::file_schema_version(&path),
        Some(u64::MAX),
        "{future}"
    );
    assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
    assert_eq!(Settings::load(&path), Settings::default());
    assert!(
        load_advisories(&path)
            .iter()
            .any(|notice| notice.contains("18446744073709551615")),
        "{:?}",
        load_advisories(&path)
    );

    // Negative Infinity on disk: legacy marker, so every known field survives.
    let legacy =
        r#"{"schema_version":"-Infinity","email":"legacy@example.com","idle_lock_seconds":123}"#;
    std::fs::write(&path, legacy).unwrap();
    assert_eq!(super::file_schema_version(&path), None, "{legacy}");
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION, "{legacy}");
    assert_eq!(loaded.email, "legacy@example.com", "{legacy}");
    assert_eq!(loaded.idle_lock_seconds, 123, "{legacy}");
    assert!(load_advisories(&path).is_empty(), "{legacy}");
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
fn settings_load_rescues_a_valid_device_id_from_a_future_schema_file() {
    // The sibling test exercises `load_detailed`; the public `Settings::load`
    // wrapper is what the UI actually calls. It must expose the same device-id
    // rescue: an opaque local UUID survives the wholesale future-schema
    // fallback while every schema-governed field falls back to defaults.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let valid = generate_device_id().unwrap();
    let future = CURRENT_SCHEMA_VERSION + 1;
    std::fs::write(
        &path,
        format!(
            r#"{{"schema_version":{future},"email":"future@example.com","server_url":"https://future.example","device_id":"{valid}"}}"#
        ),
    )
    .unwrap();

    let loaded = Settings::load(&path);
    assert_eq!(loaded.device_id, valid, "opaque id must survive via load()");
    assert_eq!(loaded.email, "", "schema-governed fields still fall back");
    assert_eq!(loaded.server_url, Settings::default().server_url);
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);

    // A malformed id is dropped on the same public path, so no invalid value
    // can be reused by `ensure_device_id` after a future-schema load.
    std::fs::write(
        &path,
        format!(r#"{{"schema_version":{future},"device_id":"not-a-uuid"}}"#),
    )
    .unwrap();
    assert!(Settings::load(&path).device_id.is_empty());
}

#[test]
fn numeric_string_schema_markers_are_trimmed_before_classification() {
    // `schema_version_of` (settings.rs:502-508) trims a string marker before
    // parsing it. A future version written with surrounding whitespace must
    // still be classified as future, not downgraded to a legacy/current file.
    let future = CURRENT_SCHEMA_VERSION + 1;
    for marker in [format!("  {future}  "), format!("\t{future}\n")] {
        assert_eq!(
            super::schema_version_of(Some(&serde_json::json!(marker))),
            Some(u64::from(future)),
            "{marker:?}"
        );
    }

    // Through the file loader the same padded marker reaches the future-version
    // guard: schema-governed fields are discarded, but the opaque device id is
    // rescued exactly as for an unpadded numeric marker.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let valid = generate_device_id().unwrap();
    let padded = format!("\t{future}\n");
    let body = serde_json::json!({
        "schema_version": padded,
        "email": "padded@example.com",
        "device_id": valid,
    });
    std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();

    assert_eq!(super::file_schema_version(&path), Some(u64::from(future)));
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, valid);
    assert_eq!(loaded.email, "");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    // The public wrapper agrees, since it delegates to the same parser.
    assert_eq!(Settings::load(&path).device_id, valid);
}

#[test]
fn future_schema_drops_non_string_device_ids() {
    // A future file can carry a valid `device_id` through the wholesale
    // fallback (settings.rs:860-871), but the rescue accepts only a JSON
    // string. Numbers, arrays and objects are not opaque UUIDs: stringifying
    // them would send a malformed identifier to the server, so each must yield
    // the empty id that triggers `ensure_device_id`'s regeneration.
    const VALID: &str = "A1B2C3D4-1234-4ABC-8DEF-0123456789AB";
    let future = CURRENT_SCHEMA_VERSION + 1;
    for device_id in [
        serde_json::json!(42),
        serde_json::json!([VALID]),
        serde_json::json!({ "uuid": VALID }),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let body = serde_json::json!({
            "schema_version": future,
            "device_id": device_id,
            "email": "future@example.com",
        });
        std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();

        let loaded = Settings::load_detailed(&path).unwrap();
        assert!(
            loaded.device_id.is_empty(),
            "must drop the non-string id {device_id}: {loaded:?}"
        );
        assert_eq!(loaded.email, "", "schema-governed fields still fall back");
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    }
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
    // (settings.rs:775-799). Nested objects must survive that read-modify-write
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
fn save_device_id_only_stores_an_invalid_id_verbatim() {
    // Known constraint pinned by this test: the id-only writer does not call
    // `is_valid_device_id` (settings.rs:775-799). Only the reuse/sanitize paths
    // reject a malformed value, so a direct caller can persist one unchanged.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let invalid = "not-a-canonical-v4-uuid";

    assert!(!is_valid_device_id(invalid), "the fixture must be invalid");
    Settings::save_device_id_only(&path, invalid).unwrap();

    // The writer stores the id verbatim; the *reader* sanitizes it, so the
    // raw JSON is the place to observe the writer's contract.
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains(invalid), "the raw value is persisted: {raw}");
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, "", "load sanitizes invalid ids");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    // The guard still applies before the id reaches the server.
    assert!(loaded.sanitized().device_id.is_empty());
    let mut reused = loaded;
    let replacement = reused.ensure_device_id(None).unwrap();
    assert_ne!(replacement, invalid);
    assert!(is_valid_device_id(replacement));
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
    let error = Settings::save_device_id_only(&path, &id).unwrap_err();
    // The abort arm formats the SettingsLoadError with `{:?}`, so the reason
    // is the variant name -- not the load message promising default values.
    assert_eq!(
        error.to_string(),
        "保存済みの設定を読み込めないため上書きを中止しました（TooLarge）",
        "{error}"
    );
    assert!(error.to_string().contains("中止"), "{error}");
    assert!(error.to_string().contains("TooLarge"), "{error}");
    assert!(!error.to_string().contains("既定値"), "{error}");
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
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
    // serde fields (settings.rs:129-161, 424-435). A new field missing from that list
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
fn load_advisories_is_empty_when_the_file_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();

    // `File::open` on a directory succeeds but `read_to_string` fails with
    // EISDIR, which `read_bounded_settings_text` classifies as ReadFailed.
    // The advisory scan shares that reader and collapses the failure to
    // "no metadata" (settings.rs:409-412).
    assert!(load_advisories(dir.path()).is_empty());
    assert_eq!(super::file_schema_version(dir.path()), None);

    // Invalid UTF-8 is another ReadFailed path, not a parse failure. A file
    // that cannot be decoded cannot yield top-level keys to warn about.
    let path = dir.path().join("settings.json");
    std::fs::write(&path, b"{\"email\":\"\xff\"}").unwrap();
    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::ReadFailed)
    );
    assert!(load_advisories(&path).is_empty());
    assert_eq!(super::file_schema_version(&path), None);
}

#[test]
fn load_advisories_is_empty_for_syntactically_invalid_json() {
    // Valid UTF-8 but broken JSON is a ParseFailed for the full loader. The
    // advisory reader shares `read_settings_json` (settings.rs:433-436), so the
    // parse error collapses to "no metadata": no future-version or unknown-key
    // notice may be fabricated from a file that never parsed.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    for body in [
        br#"{"schema_version":99,"mystery_key":"#.as_slice(),
        br#"{"schema_version":99,}"#.as_slice(),
        br#"{"email":"e@example.com" "#.as_slice(),
    ] {
        std::fs::write(&path, body).unwrap();
        assert_eq!(
            Settings::load_detailed(&path).err(),
            Some(SettingsLoadError::ParseFailed),
            "body {body:?} must be classified as a parse failure"
        );
        assert!(load_advisories(&path).is_empty(), "body {body:?}");
        assert_eq!(super::file_schema_version(&path), None, "body {body:?}");
    }
}

#[test]
fn wrong_typed_nested_leaf_recovers_without_a_nested_advisory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // One bad leaf in each nested object must fall back to that field's
    // default while its correctly typed siblings survive
    // (settings.rs:547-581, 872-889). Advisory scanning only inspects
    // top-level keys, so the recovery stays silent.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "email": "nested@example.com",
            "password_generator": {"length": "long", "lowercase": false, "uppercase": true},
            "passphrase_generator": {"words": 6, "separator": 7, "capitalize": false},
            "thresholds": {"weak_bits": "oops", "stale_days": 90}
        }"#,
    )
    .unwrap();

    let defaults = Settings::default();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.email, "nested@example.com");

    assert_eq!(
        loaded.password_generator.length,
        defaults.password_generator.length
    );
    assert!(
        !loaded.password_generator.lowercase,
        "valid sibling survives"
    );
    assert!(
        loaded.password_generator.uppercase,
        "valid sibling survives"
    );

    assert_eq!(loaded.passphrase_generator.words, 6);
    assert_eq!(
        loaded.passphrase_generator.separator,
        defaults.passphrase_generator.separator
    );
    assert!(!loaded.passphrase_generator.capitalize);

    assert_eq!(loaded.thresholds.weak_bits, defaults.thresholds.weak_bits);
    assert_eq!(loaded.thresholds.stale_days, 90);
    assert!(
        load_advisories(&path).is_empty(),
        "{:?}",
        load_advisories(&path)
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
fn padded_future_schema_string_blocks_both_write_paths() {
    // `schema_version_of` trims numeric strings before classifying them, so a
    // padded future marker is still a future version. Both write guards must
    // refuse to overwrite such a file: a future writer may have changed the
    // meaning of otherwise familiar keys (settings.rs:775-782, 930-938).
    let future = CURRENT_SCHEMA_VERSION + 1;
    for marker in [format!("  {future}  "), format!("\t{future}\n")] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = serde_json::json!({
            "schema_version": marker,
            "email": "future@example.com",
        })
        .to_string();
        std::fs::write(&path, &original).unwrap();

        assert_eq!(
            super::file_schema_version(&path),
            Some(u64::from(future)),
            "{marker:?}"
        );
        // The read path falls back to defaults, but neither writer may stamp
        // over the file with a schema this build claims to understand.
        assert_eq!(Settings::load(&path), Settings::default());
        let error = Settings::default().save(&path).unwrap_err();
        assert!(error.to_string().contains("未対応"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        let id = generate_device_id().unwrap();
        let error = Settings::save_device_id_only(&path, &id).unwrap_err();
        assert!(error.to_string().contains("未対応"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    // Control: a padded *current* marker is a legacy/non-future file and is
    // still upgraded by `save`, so the guard above is about the version.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let current = CURRENT_SCHEMA_VERSION;
    std::fs::write(
        &path,
        format!(r#"{{"schema_version":"  {current}  ","email":"old@example.com"}}"#),
    )
    .unwrap();
    Settings::default().save(&path).unwrap();
    assert_eq!(
        Settings::load_detailed(&path).unwrap().schema_version,
        CURRENT_SCHEMA_VERSION
    );
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

    // Control: a file already stamped with the *current* schema is replaced
    // too; only a version newer than this build's marker is refused. Without
    // this case the legacy assertion above cannot tell an "accepted current
    // marker" from a "silently ignored marker" on the write path.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        format!(r#"{{"schema_version":{CURRENT_SCHEMA_VERSION},"email":"old@example.com"}}"#),
    )
    .unwrap();

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
    // load fallbacks (settings.rs:822-827).
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
    // the advisory pass must not parse it (settings.rs:383-401).
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
    // an address the login form rejects forever (settings.rs:191-216, 683-687).
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
fn sanitized_email_cc_is_kept_but_valid_email_rejects_it() {
    // Documented asymmetry: `normalize_email_text` (settings.rs:201-216) only
    // knows about Unicode `Cf`, so a Cc control (NUL, DEL, C1) survives
    // `sanitized()` unchanged. `auth::valid_email` rejects Cc explicitly
    // (auth.rs:449-454), so such a stored address cannot be used to log in.
    // Pin both halves; the boundary is a settings-layer constraint, not
    // evidence that Cc is an acceptable email character.
    for control in ['\u{0}', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}'] {
        let raw = format!("alice{control}@example.com");
        let settings = Settings {
            email: raw.clone(),
            ..Default::default()
        };
        let safe = settings.sanitized();
        assert_eq!(safe.email, raw, "Cc U+{:04X} is not a Cf", control as u32);
        assert_eq!(settings.email, raw, "sanitized() must stay a pure clone");
        assert!(
            !crate::auth::valid_email(&safe.email),
            "auth must reject the Cc the settings layer kept: {raw:?}"
        );
    }

    // The Cf mirror image: a leading zero-width run is stripped and the
    // remainder is accepted, while an interior Cf clears the whole address.
    let leading = Settings {
        email: "\u{200b}alice@example.com".into(),
        ..Default::default()
    };
    let safe = leading.sanitized();
    assert_eq!(safe.email, "alice@example.com");
    assert!(crate::auth::valid_email(&safe.email));
    let interior = Settings {
        email: "al\u{200b}ice@example.com".into(),
        ..Default::default()
    };
    assert!(interior.sanitized().email.is_empty());

    // Embedded credentials in the server URL are presentation-redacted, not
    // rewritten: sanitized() keeps the string (only its length is clamped).
    // A Cf/Cc inside that userinfo is preserved too, so Debug's `[redacted]`
    // must not be mistaken for a storage guarantee.
    let raw = "https://user\u{200b}:\u{0}pass@vault.example.com/p";
    let settings = Settings {
        server_url: raw.into(),
        ..Default::default()
    };
    assert_eq!(settings.sanitized().server_url, raw);
    let debug = format!("{settings:?}");
    assert!(debug.contains("server_url: \"[redacted]\""), "{debug}");
    assert!(!debug.contains("pass@vault.example.com"), "{debug}");
}

#[test]
fn normalize_email_text_treats_a_zero_width_only_input_as_empty() {
    // `normalize_email_text` (settings.rs:225-240) distinguishes a leading
    // zero-width run from other `Cf` characters: when the whole input is
    // U+200B..=U+200F, `only_leading_zero_width` is true even though the skip
    // leaves nothing, so the value is accepted and every `Cf` is filtered out
    // into `Some("")` instead of being rejected wholesale with `None`.
    for zero_width in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}'] {
        let single = zero_width.to_string();
        assert_eq!(
            super::normalize_email_text(&single),
            Some(String::new()),
            "U+{:04X} alone must normalize to empty: {single:?}",
            zero_width as u32
        );
        let repeated = format!("{zero_width}{zero_width}{zero_width}");
        assert_eq!(
            super::normalize_email_text(&repeated),
            Some(String::new()),
            "a run of U+{:04X} must normalize to empty",
            zero_width as u32
        );
    }
    let mixed = "\u{200b}\u{200d}\u{200f}\u{200c}\u{200e}\u{200b}";
    assert_eq!(
        super::normalize_email_text(mixed),
        Some(String::new()),
        "a mixed zero-width-only run is still one removable prefix"
    );

    // Neighbouring branches stay distinct: plain text is untouched, and a
    // bidi override or a zero-width character after visible text is rejected.
    assert_eq!(
        super::normalize_email_text("alice@example.com"),
        Some("alice@example.com".to_string())
    );
    assert_eq!(super::normalize_email_text(""), Some(String::new()));
    assert_eq!(super::normalize_email_text("\u{202e}"), None);
    assert_eq!(
        super::normalize_email_text("al\u{200b}ice@example.com"),
        None
    );

    // Both public entry points inherit the same branch.
    let stored = Settings {
        email: mixed.to_string(),
        ..Default::default()
    };
    assert_eq!(stored.sanitized().email, "");
    assert_eq!(stored.email, mixed, "sanitized() must stay a pure clone");
    let mut pushed = Settings::default();
    pushed.push_shared_text(SharedSettingsField::Email, mixed);
    assert_eq!(pushed.email, "", "a zero-width-only paste appends nothing");
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
    // needed to build an uppercase variant (settings.rs:632-648).
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
    // draw can be relied on to produce those nibbles (settings.rs:632-648).
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
    // (settings.rs:95-107, 191-200).
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
fn sanitized_clamps_idle_and_login_timeouts_at_the_upper_bound() {
    use crate::limits::{MAX_IDLE_LOCK_SECONDS, MAX_LOGIN_TIMEOUT_SECONDS};

    // The sibling test pins the lower ends; these two `.clamp()` calls
    // (settings.rs:689-694) must also reject values above the UI maxima.
    let settings = Settings {
        idle_lock_seconds: MAX_IDLE_LOCK_SECONDS + 1,
        login_timeout_seconds: MAX_LOGIN_TIMEOUT_SECONDS + 1,
        ..Default::default()
    };
    let safe = settings.sanitized();
    assert_eq!(safe.idle_lock_seconds, MAX_IDLE_LOCK_SECONDS);
    assert_eq!(safe.login_timeout_seconds, MAX_LOGIN_TIMEOUT_SECONDS);
    // sanitized() stays a pure clone-based operation.
    assert_eq!(settings.idle_lock_seconds, MAX_IDLE_LOCK_SECONDS + 1);
    assert_eq!(
        settings.login_timeout_seconds,
        MAX_LOGIN_TIMEOUT_SECONDS + 1
    );

    // The extremes cannot overflow the clamp or wrap around.
    let extreme = Settings {
        idle_lock_seconds: u64::MAX,
        login_timeout_seconds: u64::MAX,
        ..Default::default()
    };
    let safe = extreme.sanitized();
    assert_eq!(safe.idle_lock_seconds, MAX_IDLE_LOCK_SECONDS);
    assert_eq!(safe.login_timeout_seconds, MAX_LOGIN_TIMEOUT_SECONDS);
}

#[test]
fn default_path_is_a_stable_settings_json_under_the_config_directory() {
    // `default_path` caches its result in a OnceLock (settings.rs:805-811), so
    // every UI call site in one process observes the same location.
    let first = Settings::default_path();
    assert_eq!(first, Settings::default_path(), "path must be cached");

    if let Some(path) = first {
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("settings.json")
        );
        assert!(
            path.to_string_lossy().contains("bitwarden-gpui-poc"),
            "{path:?}"
        );
        // The file lives in the app's subdirectory, not the bare config root.
        assert_eq!(
            path.parent()
                .and_then(|dir| dir.file_name())
                .and_then(|name| name.to_str()),
            Some("bitwarden-gpui-poc")
        );
    }
    // `dirs::config_dir()` can be None on an unusual host; the stability
    // assertion above holds for both the Some and None cases.
}

#[test]
fn leading_zero_width_run_followed_by_another_cf_is_rejected_wholesale() {
    use crate::settings::SharedSettingsField;

    // Only a leading U+200B..U+200F run is tolerated (settings.rs:95-107, 201-216).
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

#[test]
fn tolerant_struct_returns_defaults_for_non_object_input() {
    // The per-field fallback only makes sense for a JSON object. If the
    // initial deserialization fails because the value is a scalar or an array,
    // `tolerant_struct` returns T::default() without attempting a field walk
    // (settings.rs:547-556).
    for input in [
        serde_json::Value::Null,
        serde_json::Value::Bool(true),
        serde_json::Value::Number(serde_json::Number::from(42)),
        serde_json::Value::String("email".to_string()),
        serde_json::Value::Array(Vec::new()),
        serde_json::Value::Array(vec![serde_json::json!({"email": "a@example.com"})]),
    ] {
        let restored: Settings = super::tolerant_struct(input.clone());
        assert_eq!(restored, Settings::default(), "input {input:?}");
    }
}

#[test]
fn load_advisories_ignores_unknown_keys_nested_in_known_objects() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // Only top-level keys are inspected (settings.rs:440-448): an
    // unknown key inside a known object is left to the per-field tolerance.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "password_generator": {"length": 20, "nested_unknown": true},
            "thresholds": {"weak_bits": 80, "mystery_nested": "x"}
        }"#,
    )
    .unwrap();
    let notices = load_advisories(&path);
    assert!(notices.is_empty(), "nested keys must not warn: {notices:?}");
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.password_generator.length, 20);
    assert_eq!(loaded.thresholds.weak_bits, 80);

    // A top-level unknown key is still reported, so nested tolerance is a
    // deliberate boundary rather than a blanket silence.
    std::fs::write(
        &path,
        br#"{"thresholds": {"mystery_nested": 1}, "top_unknown": 2}"#,
    )
    .unwrap();
    let notices = load_advisories(&path);
    assert!(
        notices.iter().any(|notice| notice.contains("top_unknown")),
        "{notices:?}"
    );
    assert!(
        !notices
            .iter()
            .any(|notice| notice.contains("mystery_nested")),
        "{notices:?}"
    );
}

#[test]
fn load_advisories_is_empty_for_non_object_and_missing_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

    // A missing file has no metadata to report; `read_bounded_settings_text`
    // maps NotFound to a plain `None` for the advisory/marker readers.
    assert!(load_advisories(&path).is_empty());
    assert_eq!(super::file_schema_version(&path), None);

    // A JSON document that is not an object has no top-level keys at all, so
    // neither the version nor the unknown-key check can fire.
    for body in [
        br#"[]"#.as_slice(),
        br#""just a string""#.as_slice(),
        br#"null"#.as_slice(),
        br#"42"#.as_slice(),
        br#"true"#.as_slice(),
    ] {
        std::fs::write(&path, body).unwrap();
        assert!(load_advisories(&path).is_empty(), "body {body:?}");
        assert_eq!(super::file_schema_version(&path), None, "body {body:?}");
    }

    // An empty object parses, but with no schema_version marker it carries no
    // advisory either; the full loader still accepts it as a legacy file.
    std::fs::write(&path, br#"{}"#).unwrap();
    assert!(load_advisories(&path).is_empty());
    assert_eq!(
        Settings::load_detailed(&path).unwrap().schema_version,
        LEGACY_SCHEMA_VERSION
    );
}

#[test]
fn current_version_as_a_numeric_string_is_not_legacy_or_future() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // Some writers emit the marker as a string. A non-number type is treated
    // as legacy (0) by design: the fields stay compatible and the file is not
    // rejected as a future version, but the marker itself is not trusted.
    let current = CURRENT_SCHEMA_VERSION.to_string();
    let body = format!(
        r#"{{"schema_version":"{current}","email":"string-version@example.com","idle_lock_seconds":120}}"#
    );
    std::fs::write(&path, &body).unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION);
    assert_eq!(loaded.email, "string-version@example.com");
    assert_eq!(loaded.idle_lock_seconds, 120);
    assert_eq!(
        super::schema_version_of(Some(&serde_json::json!(current))),
        Some(u64::from(CURRENT_SCHEMA_VERSION))
    );
    assert_eq!(
        super::file_schema_version(&path),
        Some(u64::from(CURRENT_SCHEMA_VERSION))
    );
    assert!(load_advisories(&path).is_empty());

    // Save must not treat the string marker as an unknown writer and refuse to
    // overwrite the file.
    loaded.save(&path).unwrap();
    // A legacy file is upgraded to the current marker on save.
    let saved = Settings::load_detailed(&path).unwrap();
    assert_eq!(saved.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(saved.email, loaded.email);
    assert_eq!(saved.idle_lock_seconds, loaded.idle_lock_seconds);
}

#[test]
fn integral_float_zero_is_the_legacy_marker_not_current() {
    use serde_json::json;

    // Decision: `0.0` is an explicit legacy marker (0), never a claim to be
    // the current schema. serde cannot coerce a JSON float into the u32
    // field, so without the raw-marker fallback `tolerant_struct` would leave
    // the default (1) and silently promote the file (settings.rs:894-905).
    assert_eq!(super::schema_version_of(Some(&json!(0.0))), Some(0));
    let loaded = Settings::parse_settings(
        r#"{"schema_version":0.0,"email":"zero@example.com","idle_lock_seconds":123}"#,
    )
    .unwrap();
    assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION);
    assert_ne!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.email, "zero@example.com");
    assert_eq!(loaded.idle_lock_seconds, 123);
    assert_eq!(loaded.server_url, Settings::default().server_url);

    // A float marker of 1.0 stays current (it already matched the default,
    // but the raw-marker assignment must not turn it into legacy).
    assert_eq!(
        Settings::parse_settings(r#"{"schema_version":1.0,"email":"one@example.com"}"#)
            .unwrap()
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn negative_zero_and_finite_string_schema_markers_are_classified_by_value() {
    use serde_json::json;

    // IEEE 754: `-0.0 < 0.0` is false and `-0.0.fract() == 0.0`, so the float
    // helper maps negative zero to the legacy marker 0 -- neither "no marker"
    // nor the current version (settings.rs:502-510).
    assert_eq!(super::version_from_float(-0.0), Some(0));
    assert_eq!(super::version_from_float(0.0), Some(0));
    for marker in [json!(-0.0), json!("-0.0"), json!("  -0.0  ")] {
        assert_eq!(super::schema_version_of(Some(&marker)), Some(0), "{marker}");
    }

    // Finite decimal/exponent spellings are parsed as floats after the u64
    // parse fails; in-range values keep their exact version (settings.rs:521-535).
    for (marker, expected) in [
        ("0.0", 0),
        ("0e0", 0),
        ("1.0", 1),
        ("1e0", 1),
        ("1E+0", 1),
        ("2.0", 2),
        ("2e0", 2),
        ("1e1", 10),
    ] {
        assert_eq!(
            super::schema_version_of(Some(&json!(marker))),
            Some(expected),
            "{marker}"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // A JSON -0.0 or a "-0.0"/"0.0" string is a legacy marker on disk: fields
    // stay compatible and the read paths report legacy, never current.
    for body in [
        r#"{"schema_version":-0.0,"email":"negzero@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":"-0.0","email":"negzero@example.com","idle_lock_seconds":123}"#,
        r#"{"schema_version":"0.0","email":"negzero@example.com","idle_lock_seconds":123}"#,
    ] {
        std::fs::write(&path, body).unwrap();
        let loaded = Settings::parse_settings(body).unwrap();
        assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION, "{body}");
        assert_eq!(loaded.email, "negzero@example.com", "{body}");
        assert_eq!(loaded.idle_lock_seconds, 123, "{body}");
        assert_eq!(super::file_schema_version(&path), Some(0), "{body}");
        assert!(load_advisories(&path).is_empty(), "{body}");
    }

    // A finite in-range marker of 1 is compatible. The string spelling is
    // reported as legacy because only a JSON number is trusted as the marker,
    // but the raw value is still 1, so no write guard refuses the file.
    for marker in ["1.0", "1e0"] {
        let body = format!(
            r#"{{"schema_version":"{marker}","email":"one@example.com","idle_lock_seconds":123}}"#
        );
        std::fs::write(&path, &body).unwrap();
        let loaded = Settings::load_detailed(&path).unwrap();
        assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION, "{body}");
        assert_eq!(loaded.email, "one@example.com", "{body}");
        assert_eq!(loaded.idle_lock_seconds, 123, "{body}");
        assert_eq!(super::file_schema_version(&path), Some(1), "{body}");
        assert!(load_advisories(&path).is_empty(), "{body}");
    }

    // The same finite spellings above the current version stay future markers:
    // the whole file falls back to defaults while the raw marker is still read.
    for (marker, version) in [("2.0", 2), ("2e0", 2), ("1e1", 10)] {
        let body = format!(
            r#"{{"schema_version":"{marker}","email":"future@example.com","idle_lock_seconds":123}}"#
        );
        std::fs::write(&path, &body).unwrap();
        assert_eq!(
            Settings::load_detailed(&path).unwrap(),
            Settings::default(),
            "{body}"
        );
        assert_eq!(super::file_schema_version(&path), Some(version), "{body}");
        assert_eq!(Settings::load(&path), Settings::default(), "{body}");
    }
}

#[test]
fn string_and_float_future_schemas_still_rescue_a_valid_device_id() {
    use serde_json::json;

    let valid = generate_device_id().unwrap();
    let bodies = [
        format!(
            r#"{{"schema_version":"9999","email":"future@example.com","device_id":"{valid}"}}"#
        ),
        format!(r#"{{"schema_version":2.0,"email":"future@example.com","device_id":"{valid}"}}"#),
    ];
    for body in bodies {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, body.as_bytes()).unwrap();
        let loaded = Settings::load_detailed(&path).unwrap();
        assert_eq!(loaded.device_id, valid, "opaque id survives {body}");
        assert_eq!(loaded.email, "", "schema-governed fields fall back");
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    }
    // The numeric-string spelling is also accepted by the raw helper, and a
    // malformed id is still dropped on the same future-version path.
    assert_eq!(super::schema_version_of(Some(&json!("9999"))), Some(9999));
    assert_eq!(super::schema_version_of(Some(&json!(2.0))), Some(2));
    assert_eq!(
        Settings::parse_settings(r#"{"schema_version":2.0,"device_id":"not-a-uuid"}"#)
            .unwrap()
            .device_id,
        ""
    );
}

#[test]
fn non_hex_characters_are_rejected_in_device_ids() {
    let valid = generate_device_id().unwrap();
    let mut bad_ascii = valid.clone().into_bytes();
    bad_ascii[2] = b'g'; // outside 0-9 / a-f / A-F
    let bad_ascii = std::str::from_utf8(&bad_ascii).unwrap();
    assert!(!bad_ascii.as_bytes()[2].is_ascii_hexdigit());
    assert!(!is_valid_device_id(bad_ascii), "{bad_ascii}");

    // Uppercase hex is accepted (sibling test), but a Unicode lookalike is
    // not: the byte-wise validator rejects the extra bytes and the non-ASCII
    // code point.
    let wide = valid.replacen(&valid[2..3], "ａ", 1);
    assert_eq!(wide.len(), valid.len() + 2);
    assert!(!is_valid_device_id(&wide), "{wide}");
    let emoji = valid.replacen(&valid[2..3], "🔑", 1);
    assert!(!is_valid_device_id(&emoji), "{emoji}");

    // The rejected value is cleared by sanitize(), just like any other
    // malformed identifier, so it can never reach the login request.
    let safe = Settings {
        device_id: bad_ascii.to_string(),
        ..Settings::default()
    }
    .sanitized();
    assert!(safe.device_id.is_empty());
}

#[test]
fn ui_clamp_bounds_come_from_the_shared_limits_module() {
    use crate::limits::{
        MAX_CLIPBOARD_RESTORE_SECONDS, MAX_IDLE_LOCK_MINUTES, MAX_IDLE_LOCK_SECONDS,
        MAX_LOGIN_TIMEOUT_SECONDS, MIN_CLIPBOARD_RESTORE_SECONDS, MIN_IDLE_LOCK_MINUTES,
        MIN_IDLE_LOCK_SECONDS, MIN_LOGIN_TIMEOUT_SECONDS,
    };

    // The UI adjusts idle lock in whole minutes and the other delays in
    // seconds. Both spellings are defined once, in `crate::limits`, so a UI
    // tweak and `Settings::sanitized()` cannot silently disagree.
    assert_eq!(MIN_IDLE_LOCK_MINUTES * 60, MIN_IDLE_LOCK_SECONDS);
    assert_eq!(MAX_IDLE_LOCK_MINUTES * 60, MAX_IDLE_LOCK_SECONDS);
    assert_eq!(MIN_LOGIN_TIMEOUT_SECONDS, MIN_CLIPBOARD_RESTORE_SECONDS);
    assert_eq!(MAX_LOGIN_TIMEOUT_SECONDS, MAX_CLIPBOARD_RESTORE_SECONDS);
}

#[test]
fn save_reports_an_io_failure_without_touching_the_destination() {
    // `Settings::save` delegates the final write to `write_private`, whose
    // atomic persist must fail when the destination is a directory. The error
    // has to reach the caller instead of being swallowed after serialization.
    let dir = tempfile::tempdir().unwrap();
    let error = Settings::default().save(dir.path()).unwrap_err();
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(!error.to_string().is_empty());
    assert!(dir.path().is_dir(), "the directory must remain intact");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    // A path whose parent is a regular file fails even earlier (mkdir), and
    // still surfaces as an io error rather than a successful save.
    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, b"x").unwrap();
    let nested = file.join("settings.json");
    let error = Settings::default().save(&nested).unwrap_err();
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(std::fs::read(&file).unwrap(), b"x");
}

#[test]
fn load_advisories_messages_match_exactly() {
    // The two advisory strings are user-facing status text (settings.rs:449-468).
    // Pin them verbatim: a `contains` check would let a wording regression or
    // a missing key list slip through unnoticed.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{"schema_version":99,"mystery_key":1,"another_key":2}"#,
    )
    .unwrap();

    assert_eq!(
        load_advisories(&path),
        vec![
            "設定ファイルのバージョン 99 は未対応です。既定値で起動します".to_string(),
            "未知の設定キーは無視されます: mystery_key, another_key".to_string(),
        ]
    );

    // A current file with only known keys produces no notice at all.
    std::fs::write(&path, br#"{"schema_version":1,"email":"e@example.com"}"#).unwrap();
    assert_eq!(load_advisories(&path), Vec::<String>::new());
}

#[test]
fn multibyte_utf8_at_the_read_limit_is_classified_by_char_boundaries() {
    // `read_bounded_settings_text` takes MAX_SETTINGS_BYTES + 1 bytes and then
    // compares the decoded string's length (settings.rs:392-399). A multibyte
    // character straddling that *take* boundary leaves an incomplete UTF-8
    // sequence, so `read_to_string` fails and the file is ReadFailed. When the
    // boundary falls between characters, MAX+1 decodable bytes are read and
    // the file is TooLarge. Every file below is valid UTF-8 in full; only the
    // truncation distinguishes the two classifications.
    const MAX: usize = MAX_SETTINGS_BYTES as usize;

    fn content(char_start: usize, total: usize) -> Vec<u8> {
        let prefix = br#"{"email":""#;
        let suffix = br#""}"#;
        assert!(char_start >= prefix.len());
        // Leading/trailing spaces stay outside the JSON string, so the field
        // itself is exactly one multibyte character in every variant.
        let mut bytes = vec![b' '; char_start - prefix.len()];
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice("あ".as_bytes()); // 3 bytes: E3 81 82
        bytes.extend_from_slice(suffix);
        bytes.resize(total, b' ');
        bytes
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

    // (1) The character is fully inside the cap: the whole file is read and
    //     parsed, even though the final character is multibyte.
    let at_limit = content(MAX - 5, MAX);
    assert_eq!(at_limit.len(), MAX);
    assert!(std::str::from_utf8(&at_limit).is_ok());
    std::fs::write(&path, &at_limit).unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "あ");
    assert_eq!(loaded.email.encode_utf16().count(), 1);

    // (2) One byte over the cap, with the whole character still inside the
    //     take window: MAX+1 decodable bytes -> TooLarge, not ReadFailed.
    let one_over = content(MAX - 4, MAX + 1);
    assert_eq!(one_over.len(), MAX + 1);
    assert!(std::str::from_utf8(&one_over).is_ok());
    std::fs::write(&path, &one_over).unwrap();
    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::TooLarge)
    );

    // (3) Same content, but the character starts one byte later, so the
    //     take boundary cuts through its 3-byte sequence. The file itself is
    //     valid UTF-8; only its first MAX+1 bytes are not.
    let split = content(MAX - 1, MAX + 4);
    assert_eq!(split.len(), MAX + 4);
    assert!(
        std::str::from_utf8(&split).is_ok(),
        "file must be valid UTF-8"
    );
    assert!(
        std::str::from_utf8(&split[..MAX + 1]).is_err(),
        "take(MAX+1) must end mid-character"
    );
    std::fs::write(&path, &split).unwrap();
    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::ReadFailed)
    );
    assert_eq!(Settings::load(&path), Settings::default());
}

#[test]
fn load_detailed_ignores_unknown_top_level_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // `tolerant_struct` skips keys absent from the default struct
    // (settings.rs:564-570). `load_advisories` still warns about them, but the
    // loader itself must keep the known fields and never fail on the extra key.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "email": "known@example.com",
            "future_field": {"nested": [1, 2, 3]},
            "totally_unknown": null
        }"#,
    )
    .unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "known@example.com");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.server_url, Settings::default().server_url);
    let notices = load_advisories(&path);
    assert!(
        notices.iter().any(|notice| notice.contains("future_field")),
        "{notices:?}"
    );
    assert!(
        notices
            .iter()
            .any(|notice| notice.contains("totally_unknown")),
        "{notices:?}"
    );

    // An unknown key with a scalar value is ignored by the same branch, not
    // mistaken for a bad value of a known field.
    std::fs::write(&path, br#"{"email":"still@example.com","future_field":42}"#).unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "still@example.com");
    assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION);
}

#[test]
fn hand_edited_generator_bounds_are_clamped_to_the_limits_constants() {
    use crate::limits::{
        MAX_PASSPHRASE_WORDS, MAX_PASSWORD_LENGTH, MIN_PASSPHRASE_WORDS, MIN_PASSWORD_LENGTH,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // Both values are well-typed `usize` in the JSON, so per-field tolerance
    // keeps them and `sanitized()` (settings.rs:698-705) clamps them on load.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "password_generator": {"length": 100000},
            "passphrase_generator": {"words": 100000}
        }"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.password_generator.length, MAX_PASSWORD_LENGTH);
    assert_eq!(loaded.passphrase_generator.words, MAX_PASSPHRASE_WORDS);

    // The lower ends use the same constants, again from a hand-edited file
    // rather than from an in-memory struct.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "password_generator": {"length": 0},
            "passphrase_generator": {"words": 0}
        }"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.password_generator.length, MIN_PASSWORD_LENGTH);
    assert_eq!(loaded.passphrase_generator.words, MIN_PASSPHRASE_WORDS);
}

#[test]
fn every_known_key_maps_to_a_real_settings_field() {
    // The reverse of `every_serialized_settings_field_is_in_the_known_key_list`:
    // KNOWN is pub(crate) (settings.rs:414-435), so read the live list instead
    // of a hand-copied mirror that could drift from the production constant.
    // Otherwise a hand-written file containing only valid fields would produce
    // a spurious "unknown key" advisory.
    let defaults = serde_json::to_value(Settings::default()).unwrap();
    let defaults = defaults
        .as_object()
        .expect("Settings serializes to a JSON object");
    let mut object = serde_json::Map::new();
    for key in KNOWN {
        let key = *key;
        assert!(
            defaults.contains_key(key),
            "KNOWN entry is not a Settings field: {key}"
        );
        object.insert(
            key.to_string(),
            defaults.get(key).expect("checked above").clone(),
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::Value::Object(object)).unwrap(),
    )
    .unwrap();
    assert!(
        load_advisories(&path).is_empty(),
        "{:?}",
        load_advisories(&path)
    );

    // A key outside the list still gets the advisory, so the clean result
    // above comes from membership in KNOWN, not from a silent scanner.
    let mut with_unknown = serde_json::to_value(Settings::default()).unwrap();
    with_unknown["not_a_settings_field"] = serde_json::json!(1);
    std::fs::write(&path, serde_json::to_vec(&with_unknown).unwrap()).unwrap();
    assert!(load_advisories(&path)
        .iter()
        .any(|notice| notice.contains("not_a_settings_field")));
}

#[test]
fn push_shared_text_truncates_multibyte_input_on_a_utf8_boundary() {
    use crate::limits::{MAX_EMAIL_LEN, MAX_SERVER_URL_LEN};
    use crate::settings::SharedSettingsField;

    // `truncate_to_limit` counts characters, not bytes (limits.rs:107-118).
    // A 3-byte character straddling the cap must be dropped whole, leaving a
    // valid UTF-8 string of exactly the capped character count.
    let mut settings = Settings::default();
    settings.email.clear();
    settings.push_shared_text(SharedSettingsField::Email, &"あ".repeat(MAX_EMAIL_LEN + 3));
    assert_eq!(settings.email.chars().count(), MAX_EMAIL_LEN);
    assert_eq!(settings.email, "あ".repeat(MAX_EMAIL_LEN));
    // `String::as_bytes()` is valid UTF-8 by construction, so re-decoding it
    // proves nothing. The meaningful check is that truncation dropped whole
    // characters: three bytes per 'あ' leaves no half scalar at the cap.
    assert_eq!(settings.email.len(), MAX_EMAIL_LEN * 'あ'.len_utf8());
    assert!(settings.email.chars().all(|ch| ch == 'あ'));

    settings.server_url.clear();
    settings.push_shared_text(
        SharedSettingsField::ServerUrl,
        &"あ".repeat(MAX_SERVER_URL_LEN + 3),
    );
    assert_eq!(settings.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(settings.server_url, "あ".repeat(MAX_SERVER_URL_LEN));
    // Same whole-character check as the email field above.
    assert_eq!(
        settings.server_url.len(),
        MAX_SERVER_URL_LEN * 'あ'.len_utf8()
    );
    assert!(settings.server_url.chars().all(|ch| ch == 'あ'));

    // Crossing the boundary on a later append keeps the already-stored text
    // and admits only the characters that still fit.
    settings.email.clear();
    settings.push_shared_text(SharedSettingsField::Email, &"a".repeat(MAX_EMAIL_LEN - 1));
    settings.push_shared_text(SharedSettingsField::Email, "あい");
    assert_eq!(settings.email.chars().count(), MAX_EMAIL_LEN);
    assert!(settings.email.ends_with('あ'));
    assert!(!settings.email.ends_with('い'));
    assert_eq!(
        settings.email,
        format!("{}あ", "a".repeat(MAX_EMAIL_LEN - 1))
    );
}

#[test]
fn save_writes_a_sanitized_device_id_without_mutating_self() {
    // `save` clones through `sanitized()` (settings.rs:930-943), so a malformed
    // stored id must be cleared on disk even though the in-memory value stays.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let settings = Settings {
        device_id: "not-a-uuid".to_string(),
        ..Default::default()
    };
    settings.save(&path).unwrap();

    assert_eq!(
        settings.device_id, "not-a-uuid",
        "save must not mutate self"
    );
    let loaded = Settings::load(&path);
    assert!(loaded.device_id.is_empty(), "{loaded:?}");
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["device_id"], serde_json::json!(""));
    assert_eq!(
        raw["schema_version"],
        serde_json::json!(CURRENT_SCHEMA_VERSION)
    );
}

#[test]
fn non_object_nested_values_fall_back_per_field_without_discarding_siblings() {
    // `parse_settings` offers each nested field to `tolerant_struct`, which
    // returns `T::default()` when the value is not a JSON object
    // (settings.rs:547-556). That repair is per field: correctly typed
    // top-level siblings must still survive alongside the three defaults.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "email": "shape@example.com",
            "server_url": "https://shape.example",
            "password_generator": 42,
            "passphrase_generator": ["not", "an", "object"],
            "thresholds": "oops",
            "idle_lock_seconds": 600
        }"#,
    )
    .unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.email, "shape@example.com");
    assert_eq!(loaded.server_url, "https://shape.example");
    assert_eq!(loaded.idle_lock_seconds, 600);

    assert_eq!(loaded.password_generator, defaults.password_generator);
    assert_eq!(loaded.passphrase_generator, defaults.passphrase_generator);
    assert_eq!(loaded.thresholds, defaults.thresholds);

    // The sibling test on a *bad leaf inside* an object must keep working: a
    // non-object field replaces only that nested struct, not the whole file.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "email": "leaf@example.com",
            "password_generator": {"length": 24, "lowercase": false},
            "thresholds": "oops"
        }"#,
    )
    .unwrap();
    let mixed = Settings::load_detailed(&path).unwrap();
    assert_eq!(mixed.email, "leaf@example.com");
    assert_eq!(mixed.password_generator.length, 24);
    assert!(!mixed.password_generator.lowercase);
    assert_eq!(mixed.thresholds, defaults.thresholds);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn save_creates_missing_parent_directories() {
    // `Settings::save` documents that it creates parent directories when
    // needed (settings.rs:914). It delegates the final write to
    // `write_private`, whose recursive mkdir must let a caller save several
    // levels below an existing root without any prior setup.
    let root = tempfile::tempdir().unwrap();
    let parent = root
        .path()
        .join("config")
        .join("bitwarden-gpui-poc")
        .join("nested");
    let path = parent.join("settings.json");
    assert!(!parent.exists(), "the fixture must start without parents");

    let settings = Settings {
        email: "alice@example.com".to_string(),
        ..Default::default()
    };
    settings
        .save(&path)
        .expect("save must create the parent dirs");

    assert!(parent.is_dir(), "all intermediate dirs must exist");
    assert!(path.is_file(), "the settings file must be written");
    assert_eq!(Settings::load(&path), settings);
    assert!(
        !std::fs::read(&path).unwrap().is_empty(),
        "the file must contain the serialized settings"
    );

    // write_private creates directories with restrictive permissions, so the
    // newly created parent must not be group/world accessible on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "parent dir is not private: {mode:04o}");
    }
}

#[cfg(unix)]
#[test]
fn non_not_found_open_errors_are_classified_as_read_failed() {
    // `read_bounded_settings_text` maps only `ErrorKind::NotFound` to the
    // silent missing case; every other `File::open` error becomes
    // `ReadFailedCause` and then `SettingsLoadError::ReadFailed`
    // (settings.rs:383-401). The existing directory test exercises a failing
    // `read_to_string` *after* a successful open, so it does not cover this
    // arm. Using a regular file as an intermediate path component makes
    // `open(2)` fail with ENOTDIR, which is distinct from ENOENT/NotFound.
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"x").unwrap();
    let path = blocker.join("settings.json");

    let error = Settings::load_detailed(&path).unwrap_err();
    assert_eq!(error, SettingsLoadError::ReadFailed, "{error:?}");
    assert_eq!(
        error.message(),
        "設定ファイルを読み込めません（既定値を使用）"
    );
    // Every public reader shares the bounded reader, so all three collapse
    // this open error the same way instead of reporting a parse failure.
    assert_eq!(Settings::load(&path), Settings::default());
    assert_eq!(super::file_schema_version(&path), None);
    assert!(load_advisories(&path).is_empty());

    // Control: a genuinely absent path still takes the NotFound arm of the
    // very same match, so the assertions above are about the error kind.
    let missing = dir.path().join("missing.json");
    assert_eq!(
        Settings::load_detailed(&missing).err(),
        Some(SettingsLoadError::NotFound)
    );
}

#[test]
fn default_server_url_is_pinned_to_the_bitwarden_cloud_endpoint() {
    // A missing or hand-edited file falls back to this exact endpoint. Pin the
    // literal rather than just `contains("bitwarden")` so a silent default
    // change is an explicit, reviewed edit (settings.rs:163-179).
    const EXPECTED: &str = "https://vault.bitwarden.com";
    assert_eq!(Settings::default().server_url, EXPECTED);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    assert_eq!(Settings::load(&path).server_url, EXPECTED);
    assert_eq!(
        Settings::parse_settings(r#"{"email":"a@example.com"}"#)
            .unwrap()
            .server_url,
        EXPECTED
    );
    // A saved-and-reloaded default stays on the same endpoint.
    Settings::default().save(&path).unwrap();
    assert_eq!(Settings::load(&path).server_url, EXPECTED);
}

#[test]
fn finite_huge_float_schema_version_saturates_to_u64_max() {
    use serde_json::json;

    // `version_from_float` casts integral finite floats with `as u64`, which
    // saturates at u64::MAX (settings.rs:478-486). A very large but finite
    // marker must therefore stay on the future side of every guard, just like
    // infinity, instead of wrapping into a "compatible" small version.
    let huge = 1e300_f64;
    assert!(huge.is_finite());
    assert_eq!(super::version_from_float(huge), Some(u64::MAX));
    assert_eq!(super::schema_version_of(Some(&json!(huge))), Some(u64::MAX));
    // The string spelling reaches the same float helper after `parse::<u64>`
    // fails (settings.rs:497-511).
    assert_eq!(
        super::schema_version_of(Some(&json!("1e300"))),
        Some(u64::MAX)
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = br#"{"schema_version":1e300,"email":"huge@example.com"}"#.to_vec();
    std::fs::write(&path, &original).unwrap();

    assert_eq!(super::file_schema_version(&path), Some(u64::MAX));
    assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
    // Both write paths refuse to replace a file whose marker they cannot
    // understand, so the saturated sentinel protects the original bytes.
    assert!(Settings::default().save(&path).is_err());
    let id = generate_device_id().unwrap();
    assert!(Settings::save_device_id_only(&path, &id).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn save_replaces_an_unreadable_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // Invalid UTF-8 makes `read_bounded_settings_text` fail with ReadFailed
    // (settings.rs:383-401). `file_schema_version` deliberately collapses that
    // to "no marker", and `save` refuses only *future* markers, so an
    // unreadable file must be replaced with the sanitized struct rather than
    // being preserved like a future-version file.
    let broken = b"{\"schema_version\":1,\"email\":\"\xff\"}".to_vec();
    std::fs::write(&path, &broken).unwrap();
    assert_eq!(
        Settings::load_detailed(&path).err(),
        Some(SettingsLoadError::ReadFailed)
    );
    assert_eq!(super::file_schema_version(&path), None);

    Settings {
        email: "new@example.com".to_string(),
        ..Default::default()
    }
    .save(&path)
    .expect("save must replace an unreadable file");

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "new@example.com");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_ne!(std::fs::read(&path).unwrap(), broken);
}

#[test]
fn same_json_type_covers_all_six_tags_and_rejects_cross_tag_pairs() {
    use serde_json::json;

    // `same_json_type` (settings.rs:528-538) guards the per-field fallback in
    // `tolerant_struct`: only a value sharing its default's JSON tag may be
    // trial-parsed. Pin all six positive arms, including two numbers of
    // different widths (they share the tag; the trial parse rejects overflow).
    let same_tag = [
        (json!(null), json!(null)),
        (json!(true), json!(false)),
        (json!(1), json!(2)),
        (json!(1.5), json!(4_000_000_000u64)),
        (json!("left"), json!("right")),
        (json!([1]), json!(["two"])),
        (json!({"a": 1}), json!({"b": "two"})),
    ];
    for (left, right) in &same_tag {
        assert!(super::same_json_type(left, right), "{left} vs {right}");
    }

    // One representative per tag: every mismatched pair must be rejected.
    // The tags are distinct, so agreement is exactly the diagonal.
    let representatives = [
        json!(null),
        json!(true),
        json!(42),
        json!("text"),
        json!([]),
        json!({}),
    ];
    for (left_index, left) in representatives.iter().enumerate() {
        for (right_index, right) in representatives.iter().enumerate() {
            assert_eq!(
                super::same_json_type(left, right),
                left_index == right_index,
                "{left} vs {right}"
            );
        }
    }
}

#[test]
fn pop_shared_char_is_a_no_op_on_empty_and_pops_consecutive_characters() {
    use crate::settings::SharedSettingsField;

    let mut settings = Settings::default();
    settings.server_url.clear();
    settings.email.clear();

    // An empty field stays empty; `String::pop` returns None and does nothing.
    settings.pop_shared_char(SharedSettingsField::ServerUrl);
    settings.pop_shared_char(SharedSettingsField::Email);
    assert_eq!(settings.server_url, "");
    assert_eq!(settings.email, "");

    // Consecutive pops remove one scalar value each, including a multibyte
    // character (settings.rs:253-262), and never split a UTF-8 sequence.
    settings.push_shared_text(SharedSettingsField::ServerUrl, "xyz");
    settings.push_shared_text(SharedSettingsField::Email, "あい");
    settings.pop_shared_char(SharedSettingsField::ServerUrl);
    settings.pop_shared_char(SharedSettingsField::Email);
    assert_eq!(settings.server_url, "xy");
    assert_eq!(settings.email, "あ");
    settings.pop_shared_char(SharedSettingsField::ServerUrl);
    settings.pop_shared_char(SharedSettingsField::Email);
    assert_eq!(settings.server_url, "x");
    assert_eq!(settings.email, "");

    // Popping past the end is a no-op, and the two fields are independent.
    settings.pop_shared_char(SharedSettingsField::ServerUrl);
    settings.pop_shared_char(SharedSettingsField::Email);
    assert_eq!(settings.server_url, "");
    assert_eq!(settings.email, "");
    settings.push_shared_text(SharedSettingsField::ServerUrl, "keep");
    settings.pop_shared_char(SharedSettingsField::Email);
    assert_eq!(settings.server_url, "keep");
    assert_eq!(settings.email, "");
}

#[test]
fn save_guard_distinguishes_oversized_files_from_future_schema_files() {
    // `Settings::save` (settings.rs:930-943) guards only on `file_schema_version`.
    // An oversized file yields no marker, so it is replaced with the sanitized
    // struct; a future marker aborts with a distinct wording and leaves the
    // file byte-for-byte intact.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let oversized = vec![b' '; MAX_SETTINGS_BYTES as usize + 1];
    std::fs::write(&path, &oversized).unwrap();
    assert_eq!(super::file_schema_version(&path), None);

    Settings {
        email: "replace@example.com".into(),
        ..Default::default()
    }
    .save(&path)
    .expect("an oversized file has no future marker and must be replaced");
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "replace@example.com");
    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);

    let future = br#"{"schema_version":999,"email":"keep@example.com"}"#.to_vec();
    std::fs::write(&path, &future).unwrap();
    assert_eq!(super::file_schema_version(&path), Some(999));
    let error = Settings::default().save(&path).unwrap_err();
    assert_eq!(
        error.to_string(),
        "設定ファイルのバージョン 999 は未対応のため上書きを中止しました",
        "{error}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), future);
}

#[test]
fn valid_device_id_survives_a_save_and_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");

    // Both accepted hex spellings must make the full Settings -> save -> load
    // round trip without being cleared by `sanitized()` (settings.rs:670-676).
    for id in [
        generate_device_id().unwrap(),
        generate_device_id().unwrap().to_ascii_uppercase(),
    ] {
        assert!(is_valid_device_id(&id), "fixture id: {id}");
        let settings = Settings {
            device_id: id.clone(),
            email: "alice@example.com".into(),
            ..Default::default()
        };
        settings.save(&path).unwrap();

        let loaded = Settings::load_detailed(&path).unwrap();
        assert_eq!(loaded, settings, "the whole struct must round-trip: {id}");
        assert_eq!(loaded.device_id, id);
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
        // A valid stored id is reused on the next sync: no regeneration, no
        // extra write, so the on-disk bytes are unchanged by ensure_device_id.
        let before = std::fs::read(&path).unwrap();
        let mut reused = loaded;
        assert_eq!(reused.ensure_device_id(Some(&path)).unwrap(), id.as_str());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn sanitized_truncates_shared_text_fields_on_multibyte_char_boundaries() {
    use crate::limits::{MAX_EMAIL_LEN, MAX_SERVER_URL_LEN};

    // `sanitized()` applies the same `truncate_to_limit` used by
    // `push_shared_text` (settings.rs:677-688, limits.rs:107-118): the cap
    // counts characters and a 3-byte scalar straddling it is dropped whole.
    let settings = Settings {
        server_url: format!("{}{}", "a".repeat(MAX_SERVER_URL_LEN - 1), "あい"),
        email: format!("{}{}", "a".repeat(MAX_EMAIL_LEN - 1), "あい"),
        ..Default::default()
    };
    let safe = settings.sanitized();

    assert_eq!(safe.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(
        safe.server_url,
        format!("{}あ", "a".repeat(MAX_SERVER_URL_LEN - 1))
    );
    assert_eq!(
        safe.server_url.len(),
        (MAX_SERVER_URL_LEN - 1) + 'あ'.len_utf8()
    );
    assert_eq!(safe.email.chars().count(), MAX_EMAIL_LEN);
    assert_eq!(safe.email, format!("{}あ", "a".repeat(MAX_EMAIL_LEN - 1)));
    assert_eq!(safe.email.len(), (MAX_EMAIL_LEN - 1) + 'あ'.len_utf8());
    // The last admitted scalar is complete; the following one was dropped.
    assert!(safe.email.ends_with('あ'));
    assert!(!safe.email.contains('い'));

    // The email format policy runs before the cap: a leading zero-width run
    // is stripped and may not push a multibyte tail past the boundary.
    let zero_width = Settings {
        email: format!("\u{200b}\u{200d}あ{}", "い".repeat(MAX_EMAIL_LEN)),
        ..Default::default()
    }
    .sanitized();
    assert_eq!(zero_width.email.chars().count(), MAX_EMAIL_LEN);
    assert!(zero_width.email.starts_with('あ'));
    // `s.is_char_boundary(s.len())` is true for every String, so that
    // assertion could never fail. Check the observable truncation result
    // instead: the retained tail is a complete scalar, the byte length is
    // exactly the leading 3-byte 'あ' plus the remaining full-width 'い'
    // scalars, and the stripped Cf characters are gone.
    assert!(zero_width.email.ends_with('い'));
    assert_eq!(
        zero_width.email.len(),
        'あ'.len_utf8() + (MAX_EMAIL_LEN - 1) * 'い'.len_utf8()
    );
    assert!(!zero_width.email.contains('\u{200b}'));
    assert!(!zero_width.email.contains('\u{200d}'));

    // sanitized() stays a pure clone-based operation.
    assert_eq!(settings.server_url.chars().count(), MAX_SERVER_URL_LEN + 1);
    assert_eq!(settings.email.chars().count(), MAX_EMAIL_LEN + 1);
}

#[test]
fn top_level_u64_fields_fall_back_per_field_on_type_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // `idle_lock_seconds`, `login_timeout_seconds` and
    // `clipboard_restore_seconds` are u64. One wrong JSON type used to make
    // serde reject the whole struct; `tolerant_struct` must keep each bad
    // field's default while correctly typed siblings survive
    // (settings.rs:540-581, 889-906).
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "email": "u64@example.com",
            "server_url": "https://u64.example",
            "idle_lock_seconds": "600",
            "login_timeout_seconds": true,
            "clipboard_restore_seconds": null,
            "thresholds": {"weak_bits": 90, "stale_days": 30}
        }"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    let defaults = Settings::default();

    assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.email, "u64@example.com");
    assert_eq!(loaded.server_url, "https://u64.example");
    assert_eq!(loaded.idle_lock_seconds, defaults.idle_lock_seconds);
    assert_eq!(loaded.login_timeout_seconds, defaults.login_timeout_seconds);
    assert_eq!(
        loaded.clipboard_restore_seconds,
        defaults.clipboard_restore_seconds
    );
    // Siblings of a different type tag are kept, both nested and top level.
    assert_eq!(loaded.thresholds.weak_bits, 90);
    assert_eq!(loaded.thresholds.stale_days, 30);
}

#[test]
fn top_level_u64_fields_keep_valid_siblings_and_reject_fractional_numbers() {
    let defaults = Settings::default();

    // One valid u64, one fractional number (same JSON number tag but not a
    // u64, rejected by the trial parse) and one u64::MAX that serde accepts
    // but `sanitized()` clamps. The mismatch must not discard the good field.
    let parsed = Settings::parse_settings(
        r#"{
            "schema_version": 1,
            "email": "mixed@example.com",
            "idle_lock_seconds": 600,
            "login_timeout_seconds": 12.5,
            "clipboard_restore_seconds": 18446744073709551615
        }"#,
    )
    .unwrap();
    assert_eq!(parsed.email, "mixed@example.com");
    assert_eq!(parsed.idle_lock_seconds, 600);
    assert_eq!(parsed.login_timeout_seconds, defaults.login_timeout_seconds);
    // u64::MAX is a valid u64, so tolerance keeps it; the clamp is a later,
    // separate step that runs on load(), not inside parse_settings().
    assert_eq!(parsed.clipboard_restore_seconds, u64::MAX);
    assert_eq!(
        parsed.sanitized().clipboard_restore_seconds,
        crate::limits::MAX_CLIPBOARD_RESTORE_SECONDS
    );
}

#[test]
fn bool_and_null_schema_markers_are_legacy() {
    use serde_json::json;

    // `schema_version_of` (settings.rs:497-511) has no arm for JSON booleans
    // or null, so both are "not a version marker" (None), never a future one.
    for raw in [json!(true), json!(false), json!(null)] {
        assert_eq!(super::schema_version_of(Some(&raw)), None, "{raw}");
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    for marker in ["true", "false", "null"] {
        std::fs::write(
            &path,
            format!(r#"{{"schema_version":{marker},"email":"marker@example.com","idle_lock_seconds":123}}"#),
        )
        .unwrap();

        // `well_typed` is false for a non-Number marker, so parse_settings
        // rewrites serde's default (CURRENT) to LEGACY (settings.rs:857-905).
        let loaded = Settings::load_detailed(&path).unwrap();
        assert_eq!(loaded.schema_version, LEGACY_SCHEMA_VERSION, "{marker}");
        assert_ne!(loaded.schema_version, CURRENT_SCHEMA_VERSION, "{marker}");
        // A legacy marker stays compatible: known fields are still honoured.
        assert_eq!(loaded.email, "marker@example.com", "{marker}");
        assert_eq!(loaded.idle_lock_seconds, 123, "{marker}");

        // No future-version advisory is raised for a bool/null marker, and
        // the write paths must not treat it as an unknown writer either.
        assert!(load_advisories(&path).is_empty(), "{marker}");
        assert_eq!(super::file_schema_version(&path), None, "{marker}");
        loaded.save(&path).unwrap();
        assert_eq!(
            Settings::load_detailed(&path).unwrap().schema_version,
            CURRENT_SCHEMA_VERSION,
            "{marker}"
        );
        let id = generate_device_id().unwrap();
        Settings::save_device_id_only(&path, &id).unwrap();
    }
}

#[test]
fn ensure_device_id_refuses_to_write_through_a_future_schema_file() {
    // `ensure_device_id` generates an id and immediately calls
    // `save_device_id_only`, which checks `file_schema_version` before touching
    // the file (settings.rs:735-799). A future writer may have changed the
    // meaning of otherwise familiar keys, so the id-only write must abort no
    // matter how the marker was encoded, and the rejected id must never be
    // accepted in memory.
    for original in [
        br#"{"schema_version":999,"email":"future@example.com"}"#.as_slice(),
        br#"{"schema_version":"999","email":"future@example.com"}"#.as_slice(),
        br#"{"schema_version":2.0,"email":"future@example.com"}"#.as_slice(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, original).unwrap();

        let mut settings = Settings::default();
        let error = settings.ensure_device_id(Some(&path)).unwrap_err();
        assert!(
            matches!(&error, crate::error::AppError::SettingsSaveCause(_, _)),
            "{error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("デバイス ID を保存できませんでした"));
        assert!(text.contains("未対応"), "{text}");
        assert!(
            std::error::Error::source(&error).is_some(),
            "the underlying io error must stay reachable"
        );
        assert!(
            settings.device_id.is_empty(),
            "an id that was not persisted must not be reused"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original.to_vec(),
            "a future file must never be overwritten"
        );
    }
}

#[test]
fn save_persists_clamped_numeric_fields_and_leaves_self_untouched() {
    use crate::limits::{
        MAX_CLIPBOARD_RESTORE_SECONDS, MAX_PASSWORD_LENGTH, MAX_WEAK_BITS, MIN_IDLE_LOCK_SECONDS,
        MIN_LOGIN_TIMEOUT_SECONDS, MIN_PASSPHRASE_WORDS, MIN_STALE_DAYS,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let settings = Settings {
        idle_lock_seconds: 0,
        login_timeout_seconds: 0,
        clipboard_restore_seconds: u64::MAX,
        password_generator: crate::generator::PasswordSettings {
            length: 10_000,
            ..Default::default()
        },
        passphrase_generator: crate::generator::PassphraseSettings {
            words: 0,
            ..Default::default()
        },
        thresholds: crate::health::Thresholds {
            weak_bits: u32::MAX,
            stale_days: -1,
        },
        ..Default::default()
    };

    settings.save(&path).unwrap();

    // `save` writes `sanitized()`, so the clamp must be visible in the raw
    // JSON on disk, not only through a later load-time clamp.
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (key, expected) in [
        (
            "idle_lock_seconds",
            serde_json::json!(MIN_IDLE_LOCK_SECONDS),
        ),
        (
            "login_timeout_seconds",
            serde_json::json!(MIN_LOGIN_TIMEOUT_SECONDS),
        ),
        (
            "clipboard_restore_seconds",
            serde_json::json!(MAX_CLIPBOARD_RESTORE_SECONDS),
        ),
    ] {
        assert_eq!(raw[key], expected, "{key} was not clamped on disk");
    }
    assert_eq!(
        raw["password_generator"]["length"],
        serde_json::json!(MAX_PASSWORD_LENGTH)
    );
    assert_eq!(
        raw["passphrase_generator"]["words"],
        serde_json::json!(MIN_PASSPHRASE_WORDS)
    );
    assert_eq!(
        raw["thresholds"]["weak_bits"],
        serde_json::json!(MAX_WEAK_BITS)
    );
    assert_eq!(
        raw["thresholds"]["stale_days"],
        serde_json::json!(MIN_STALE_DAYS)
    );

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.idle_lock_seconds, MIN_IDLE_LOCK_SECONDS);
    assert_eq!(loaded.login_timeout_seconds, MIN_LOGIN_TIMEOUT_SECONDS);
    assert_eq!(
        loaded.clipboard_restore_seconds,
        MAX_CLIPBOARD_RESTORE_SECONDS
    );
    assert_eq!(loaded.password_generator.length, MAX_PASSWORD_LENGTH);
    // The lower generator bound is pinned by the sibling sanitize tests; here
    // `words: 0` demonstrates that the persisted file carries the clamp too.
    assert_eq!(loaded.passphrase_generator.words, MIN_PASSPHRASE_WORDS);
    assert_eq!(loaded.thresholds.weak_bits, MAX_WEAK_BITS);
    assert_eq!(loaded.thresholds.stale_days, MIN_STALE_DAYS);
    assert_eq!(loaded, settings.sanitized());

    // The caller's struct is never mutated by save().
    assert_eq!(settings.idle_lock_seconds, 0);
    assert_eq!(settings.login_timeout_seconds, 0);
    assert_eq!(settings.clipboard_restore_seconds, u64::MAX);
    assert_eq!(settings.password_generator.length, 10_000);
    assert_eq!(settings.passphrase_generator.words, 0);
    assert_eq!(settings.thresholds.weak_bits, u32::MAX);
    assert_eq!(settings.thresholds.stale_days, -1);
}

#[test]
fn default_path_is_unchanged_after_the_config_environment_changes() {
    // XDG_CONFIG_HOME is process-global: hold ENV_LOCK so no other test can
    // observe or overwrite the value while this one swaps it.
    let _env = ENV_LOCK.lock().unwrap();
    // `Settings::default_path` resolves once into a OnceLock (settings.rs), so
    // every later call must return that same path even if XDG_CONFIG_HOME is
    // changed or removed. The environment is process-global; the guard below
    // restores the original value on every exit so parallel tests are not
    // left with a modified environment. The set/remove APIs are safe on this
    // crate's edition (2021).
    struct EnvGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let original = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, original }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    let root = tempfile::tempdir().unwrap();
    let first_root = root.path().join("first-config");
    let _first = EnvGuard::set("XDG_CONFIG_HOME", &first_root);
    // Initialize the OnceLock before changing the environment, so the test is
    // independent of whether another test called default_path() first.
    let before = Settings::default_path();
    assert_eq!(Settings::default_path(), before, "stable before the change");

    let second_root = root.path().join("second-config");
    let _second = EnvGuard::set("XDG_CONFIG_HOME", &second_root);
    assert_ne!(
        first_root, second_root,
        "the fixture really changed the env"
    );
    assert_eq!(
        Settings::default_path(),
        before,
        "a later XDG_CONFIG_HOME change must not move the cached path"
    );

    std::env::remove_var("XDG_CONFIG_HOME");
    assert_eq!(
        Settings::default_path(),
        before,
        "unsetting the variable must not move the cached path either"
    );

    if let Some(path) = before {
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("settings.json")
        );
    }
}

#[test]
fn settings_load_error_other_carries_its_message_and_display() {
    // `message()` returns the carried `&'static str` verbatim for `Other`
    // (settings.rs:286-303), and `Display` forwards to `message()`. Unlike the
    // four fixed variants, it must not promise default values or add a prefix.
    const DETAIL: &str = "設定固有の失敗（詳細）";
    let error = SettingsLoadError::Other(DETAIL);
    assert_eq!(error.message(), DETAIL);
    assert_eq!(error.to_string(), DETAIL);
    assert_eq!(format!("{error}"), DETAIL);
    // Debug still names the variant so diagnostics can distinguish it.
    let debug = format!("{error:?}");
    assert!(debug.contains("Other"), "{debug}");
    assert!(debug.contains(DETAIL), "{debug}");

    // The catch-all conversion from an unrelated AppError goes through the
    // same message/Display pair with the shared generic text.
    let generic = SettingsLoadError::from(crate::error::AppError::RandomUnavailable);
    assert_eq!(generic.message(), crate::error::OTHER_ERROR_MESSAGE);
    assert_eq!(generic.to_string(), crate::error::OTHER_ERROR_MESSAGE);
    assert_eq!(generic.message(), generic.to_string());
    assert_ne!(generic.message(), SettingsLoadError::ReadFailed.message());
}

#[test]
fn default_path_mirrors_config_dir_including_the_none_branch() {
    let _env = ENV_LOCK.lock().unwrap();
    // `default_path()` caches `dirs::config_dir().map(|dir| ...)` in a OnceLock
    // (settings.rs:805-811). The `Option` is mapped, not unwrapped: when no
    // config directory can be resolved the result stays None instead of a
    // fabricated relative path. Compare with the live resolver under the same
    // environment; the dedicated caching test pins that later env changes
    // cannot move the value once it has been resolved.
    let resolver = dirs::config_dir();
    let cached = Settings::default_path();
    assert_eq!(
        cached.is_some(),
        resolver.is_some(),
        "default_path must mirror config_dir's Option"
    );
    match (resolver, cached) {
        (None, None) => {
            // The config_dir None branch: no path is produced, and repeated
            // calls keep returning None from the same cached cell.
            assert_eq!(Settings::default_path(), None);
        }
        (Some(_), Some(path)) => {
            assert_eq!(
                path.file_name().and_then(|name| name.to_str()),
                Some("settings.json")
            );
        }
        other => unreachable!("the is_some correspondence rules this out: {other:?}"),
    }
}

#[test]
fn default_path_maps_config_dir_to_the_app_settings_json() {
    let _env = ENV_LOCK.lock().unwrap();
    // `default_path` maps `dirs::config_dir()` through
    // `.join("bitwarden-gpui-poc").join("settings.json")` and caches the
    // Option in a OnceLock (settings.rs:825-835). An env-touching test in the
    // same process may have initialized that cell under a different
    // XDG_CONFIG_HOME, so compare the mapping's shape instead of the absolute
    // value; the caching test pins stability across later env changes.
    let mapped = dirs::config_dir().map(|dir| dir.join("bitwarden-gpui-poc").join("settings.json"));
    let cached = Settings::default_path();
    assert_eq!(cached.is_some(), mapped.is_some());
    if let (Some(mapped), Some(cached)) = (mapped, cached) {
        assert_eq!(cached.file_name(), mapped.file_name());
        assert_eq!(
            cached.parent().and_then(|dir| dir.file_name()),
            mapped.parent().and_then(|dir| dir.file_name())
        );
        assert!(cached.is_absolute(), "{cached:?}");
        assert_eq!(
            cached.file_name().and_then(|name| name.to_str()),
            Some("settings.json")
        );
        assert_eq!(
            cached
                .parent()
                .and_then(|dir| dir.file_name())
                .and_then(|name| name.to_str()),
            Some("bitwarden-gpui-poc")
        );
    }
}

#[test]
fn settings_load_error_never_carries_a_source() {
    use crate::error::{AppError, BoxedCause};

    // `SettingsLoadError` has no `source()` chain at all: even `Other` renders
    // only its `&'static str` message (settings.rs:265-305).
    for error in [
        SettingsLoadError::NotFound,
        SettingsLoadError::ReadFailed,
        SettingsLoadError::ParseFailed,
        SettingsLoadError::TooLarge,
        SettingsLoadError::Other("detail"),
    ] {
        assert!(std::error::Error::source(&error).is_none(), "{error:?}");
    }

    // Cause-carrying `AppError`s do have a typed source before the boundary;
    // converting to the small UI enum drops it, keeping only the category.
    for app in [
        AppError::ReadFailedCause(BoxedCause::text("io failure")),
        AppError::ParseFailedCause(BoxedCause::text("json failure")),
        AppError::SettingsSaveCause("save detail".into(), BoxedCause::text("io failure")),
    ] {
        assert!(
            std::error::Error::source(&app).is_some(),
            "premise: typed cause"
        );
        let small = SettingsLoadError::from(app);
        assert!(std::error::Error::source(&small).is_none(), "{small:?}");
    }

    // The forward direction never invents a cause either.
    for error in [
        SettingsLoadError::NotFound,
        SettingsLoadError::ReadFailed,
        SettingsLoadError::ParseFailed,
        SettingsLoadError::TooLarge,
        SettingsLoadError::Other("固有の失敗"),
    ] {
        let app = AppError::from(error);
        assert!(std::error::Error::source(&app).is_none(), "{app:?}");
    }
}

#[test]
fn hyphen_positions_outside_the_uuid_template_are_rejected() {
    // `is_valid_device_id` checks bytes 8/13/18/23 (settings.rs:632-648).
    // Moving a hyphen to any other index keeps the length and the hex digits
    // intact, so only the position rule can reject the value. Every shifted
    // spelling must be cleared by `sanitized()` instead of being reused.
    const VALID: &str = "A1B2C3D4-1234-4ABC-8DEF-0123456789AB";
    const POSITIONS: [usize; 4] = [8, 13, 18, 23];
    assert!(is_valid_device_id(VALID), "fixture must be valid");

    for &source in &POSITIONS {
        for target in [0usize, 1, 7, 9, 12, 14, 19, 24, 35] {
            if POSITIONS.contains(&target) {
                continue;
            }
            let mut bytes = VALID.as_bytes().to_vec();
            bytes.swap(source, target);
            let shifted = std::str::from_utf8(&bytes).unwrap();
            assert!(
                !is_valid_device_id(shifted),
                "hyphen {source} -> {target}: {shifted}"
            );
            let safe = Settings {
                device_id: shifted.to_string(),
                ..Default::default()
            }
            .sanitized();
            assert!(safe.device_id.is_empty(), "sanitize must drop {shifted}");
        }
    }

    // Control: the untouched canonical spelling stays reusable.
    let valid = Settings {
        device_id: VALID.to_string(),
        ..Default::default()
    };
    assert_eq!(valid.sanitized().device_id, VALID);
}

#[test]
fn positive_schema_markers_beyond_u32_width_are_future_versions() {
    // `schema_version` is a u32 (settings.rs:120), but `schema_version_of`
    // reads the raw marker as u64/f64 (settings.rs:471-511). A positive
    // integer wider than u32 must therefore be classified as a future version
    // on every path, never downgraded to a "compatible" legacy marker.
    const BEYOND_U32: &str = "4294967296"; // u32::MAX + 1
    assert_eq!(
        super::schema_version_of(Some(&serde_json::json!(4_294_967_296u64))),
        Some(4_294_967_296)
    );
    assert_eq!(
        super::schema_version_of(Some(&serde_json::json!(BEYOND_U32))),
        Some(4_294_967_296)
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    for marker in [BEYOND_U32, "18446744073709551615"] {
        let original = format!(
            r#"{{"schema_version":{marker},"email":"wide@example.com","idle_lock_seconds":123}}"#
        );
        std::fs::write(&path, &original).unwrap();
        assert!(super::file_schema_version(&path).is_some());
        assert_eq!(Settings::load_detailed(&path).unwrap(), Settings::default());
        assert!(load_advisories(&path)
            .iter()
            .any(|notice| notice.contains("未対応")));
        assert!(Settings::default().save(&path).is_err());
        let id = generate_device_id().unwrap();
        assert!(Settings::save_device_id_only(&path, &id).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    // A float wider than u32 but finite still saturates on the same side.
    assert_eq!(
        super::version_from_float(4_294_967_296.0),
        Some(4_294_967_296)
    );
}

#[test]
fn ensure_device_id_with_a_valid_id_and_a_path_does_not_create_a_file() {
    // `ensure_device_id` (settings.rs:759-774) only generates and persists when
    // the in-memory value fails `is_valid_device_id`. With an already valid id
    // and `Some(path)` it takes the early return: the id is reused verbatim and
    // no settings file is created. This is the "valid id + Some(path) + no
    // file" branch, distinct from the generation/persist path (which writes)
    // and from the `None` path (which only touches memory).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    const VALID: &str = "a1b2c3d4-1234-4abc-8def-0123456789ab";
    assert!(is_valid_device_id(VALID), "fixture premise: {VALID}");
    assert!(!path.exists(), "fixture premise: no file yet");

    let mut settings = Settings {
        device_id: VALID.to_string(),
        ..Default::default()
    };
    assert_eq!(settings.ensure_device_id(Some(&path)).unwrap(), VALID);
    assert!(
        !path.exists(),
        "a valid in-memory id must not trigger a write"
    );
    assert_eq!(settings.device_id, VALID);

    // Repeating the call keeps the same early-return behaviour.
    assert_eq!(settings.ensure_device_id(Some(&path)).unwrap(), VALID);
    assert!(!path.exists());
}

#[test]
fn ensure_device_id_with_an_invalid_in_memory_id_and_a_path_generates_and_persists_it() {
    // The mirror of the test above: an in-memory id that fails
    // `is_valid_device_id` takes the generation/persist arm of
    // `ensure_device_id` (settings.rs:759-774). A fresh id replaces the bad
    // value in memory and is written through `save_device_id_only`, so the
    // name's "generates and persists" matches every assertion below (a
    // "does not create a file" name/assertion pair would contradict the
    // behaviour of this branch).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    const INVALID: &str = "not-a-canonical-v4-uuid";
    assert!(!is_valid_device_id(INVALID), "fixture premise: {INVALID}");
    assert!(!path.exists(), "fixture premise: no file yet");

    let mut settings = Settings {
        device_id: INVALID.to_string(),
        ..Default::default()
    };
    let generated = settings.ensure_device_id(Some(&path)).unwrap().to_string();
    assert!(is_valid_device_id(&generated), "{generated}");
    assert_ne!(generated, INVALID, "a malformed id must never be reused");
    assert_eq!(settings.device_id, generated);
    assert!(path.exists(), "this branch must persist the generated id");
    assert_eq!(Settings::load(&path).device_id, generated);

    // Once the valid id is in memory the call rejoins the early-return path:
    // the same id is returned and the file is not rewritten.
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        settings.ensure_device_id(Some(&path)).unwrap(),
        generated.as_str()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn save_device_id_only_resanitizes_the_fields_it_reads_back() {
    use crate::limits::{MAX_SERVER_URL_LEN, MAX_STALE_DAYS, MIN_WEAK_BITS};

    // The id-only writer re-reads through `load_detailed`, which applies
    // `sanitized()` before `device_id` is replaced. Hand-edited values in the
    // old file are therefore clamped/cleaned on write even though this path
    // never calls `save` and never mutates a caller's struct.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let original = serde_json::json!({
        "schema_version": CURRENT_SCHEMA_VERSION,
        "email": "\u{202e}evil@example.com",
        "server_url": "s".repeat(MAX_SERVER_URL_LEN + 5),
        "thresholds": {"weak_bits": 0, "stale_days": i64::MAX},
        "device_id": "legacy-hardcoded-value",
    });
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();

    let id = generate_device_id().unwrap();
    Settings::save_device_id_only(&path, &id).unwrap();

    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["device_id"], serde_json::json!(id));
    assert_eq!(
        raw["schema_version"],
        serde_json::json!(CURRENT_SCHEMA_VERSION)
    );
    // A bidi override is not a leading U+200B..U+200F run, so the whole
    // hand-edited address is cleared rather than filtered in place.
    assert_eq!(raw["email"], serde_json::json!(""));
    assert_eq!(
        raw["server_url"].as_str().unwrap().chars().count(),
        MAX_SERVER_URL_LEN
    );
    assert_eq!(
        raw["thresholds"]["weak_bits"],
        serde_json::json!(MIN_WEAK_BITS)
    );
    assert_eq!(
        raw["thresholds"]["stale_days"],
        serde_json::json!(MAX_STALE_DAYS)
    );

    // The reader observes the same sanitized values, and the id is a real one
    // that survives a reload instead of being regenerated on the next sync.
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.device_id, id);
    assert!(is_valid_device_id(&loaded.device_id));
    assert_eq!(loaded.email, "");
    assert_eq!(loaded.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(loaded.thresholds.weak_bits, MIN_WEAK_BITS);
    assert_eq!(loaded.thresholds.stale_days, MAX_STALE_DAYS);
}

// --- R2-CORE-121: variant nibbles and future-schema uppercase UUID rescue ---

#[test]
fn device_id_variant_nibbles_9_a_b_are_accepted() {
    // RFC 4122 encodes the variant as the `10xx` bit pattern, whose low nibble
    // is 8/9/a/b. `is_valid_device_id` must accept every one of those spellings
    // (settings.rs:670-671), including the uppercase form of a/b, and reject
    // every non-variant nibble. Position 14 stays the version-4 marker.
    let base = generate_device_id().unwrap();
    assert_eq!(base.as_bytes()[14], b'4');

    for variant in *b"89abAB" {
        let mut id = base.clone().into_bytes();
        id[19] = variant;
        let id = std::str::from_utf8(&id).unwrap();
        assert!(is_valid_device_id(id), "variant {variant}: {id}");
    }
    for variant in *b"07cCdfgz" {
        let mut id = base.clone().into_bytes();
        id[19] = variant;
        let id = std::str::from_utf8(&id).unwrap();
        assert!(!is_valid_device_id(id), "variant {variant}: {id}");
    }

    // Uppercase hex anywhere else is accepted too; only the version nibble and
    // the variant nibble carry semantic meaning.
    let uppercase = base.to_ascii_uppercase();
    assert!(is_valid_device_id(&uppercase), "{uppercase}");
    let mut wrong_version = uppercase.clone().into_bytes();
    wrong_version[14] = b'5';
    assert!(!is_valid_device_id(
        std::str::from_utf8(&wrong_version).unwrap()
    ));
}

#[test]
fn future_schema_rescues_uppercase_uuid_device_ids() {
    // A future writer may spell the opaque id in uppercase hex. The rescue in
    // `parse_settings` (settings.rs:884-895) calls `is_valid_device_id`, so the
    // uppercase form with each variant nibble must survive both the detailed
    // and the public loader while schema-governed fields still fall back.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let future = CURRENT_SCHEMA_VERSION + 1;

    for variant in *b"9abAB" {
        let mut bytes = generate_device_id().unwrap().into_bytes();
        bytes[19] = variant;
        let id = std::str::from_utf8(&bytes).unwrap().to_ascii_uppercase();
        assert!(is_valid_device_id(&id), "variant {variant}: {id}");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version":{future},"email":"future@example.com","server_url":"https://future.example","device_id":"{id}"}}"#
            ),
        )
        .unwrap();

        let detailed = Settings::load_detailed(&path).unwrap();
        assert_eq!(detailed.device_id, id, "detailed must rescue {id}");
        assert_eq!(detailed.email, "", "schema-governed fields still fall back");
        assert_eq!(detailed.server_url, Settings::default().server_url);
        assert_eq!(detailed.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(Settings::load(&path).device_id, id, "load must rescue {id}");
    }

    // An uppercase id with a non-variant nibble is still rejected on both paths.
    let mut bytes = generate_device_id().unwrap().into_bytes();
    bytes[19] = b'C';
    let invalid = std::str::from_utf8(&bytes).unwrap().to_ascii_uppercase();
    assert!(!is_valid_device_id(&invalid), "{invalid}");
    std::fs::write(
        &path,
        format!(r#"{{"schema_version":{future},"device_id":"{invalid}"}}"#),
    )
    .unwrap();
    assert!(Settings::load_detailed(&path).unwrap().device_id.is_empty());
    assert!(Settings::load(&path).device_id.is_empty());
}

#[cfg(unix)]
#[test]
fn save_writes_settings_json_itself_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();

    // A brand-new file created by `save` must be 0600, not merely its parent:
    // `write_private` persists a 0600 temporary file (private_file.rs:47-56).
    let fresh = dir.path().join("fresh-settings.json");
    Settings::default().save(&fresh).unwrap();
    let fresh_mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
    assert_eq!(fresh_mode, 0o600, "a new settings.json must be owner-only");

    // An existing world-readable file is replaced, and the replacement must
    // correct the mode instead of inheriting the old one.
    let path = dir.path().join("settings.json");
    std::fs::write(&path, br#"{"email":"old@example.com"}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "the fixture must really be world-readable before save"
    );

    Settings {
        email: "new@example.com".to_string(),
        ..Default::default()
    }
    .save(&path)
    .unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "settings.json itself must be 0600 after save");
    assert_eq!(Settings::load(&path).email, "new@example.com");
}

#[test]
fn save_discards_unknown_top_level_and_nested_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    // The loader only warns about unknown keys (`load_advisories`); `save`
    // serializes the typed `Settings` struct, so none of them may be written
    // back -- at the top level or inside a known nested object.
    std::fs::write(
        &path,
        br#"{
            "schema_version": 1,
            "email": "keep@example.com",
            "unknown_top": "DROP_TOP_VALUE",
            "password_generator": {"length": 24, "unknown_nested": "DROP_NESTED_VALUE"},
            "thresholds": {"weak_bits": 70, "mystery_nested": "DROP_MYSTERY_VALUE"}
        }"#,
    )
    .unwrap();

    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.email, "keep@example.com");
    assert!(load_advisories(&path)
        .iter()
        .any(|notice| notice.contains("unknown_top")));
    loaded.save(&path).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    for dropped in [
        "unknown_top",
        "DROP_TOP_VALUE",
        "unknown_nested",
        "DROP_NESTED_VALUE",
        "mystery_nested",
        "DROP_MYSTERY_VALUE",
    ] {
        assert!(
            !raw.contains(dropped),
            "unknown key survived save: {dropped}: {raw}"
        );
    }
    // The advisory pass is silent after the rewrite, and known values survive.
    assert!(
        load_advisories(&path).is_empty(),
        "{:?}",
        load_advisories(&path)
    );
    let reloaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(reloaded.email, "keep@example.com");
    assert_eq!(reloaded.password_generator.length, 24);
    assert_eq!(reloaded.thresholds.weak_bits, 70);
    assert_eq!(reloaded.schema_version, CURRENT_SCHEMA_VERSION);
}

#[test]
fn load_advisories_warns_about_padded_numeric_string_future_versions() {
    // `schema_version_of` trims a string marker before parsing it
    // (settings.rs:526-534), so a future version padded with whitespace must
    // still produce the advisory -- with the trimmed number rendered -- rather
    // than being silently treated as a legacy/current file. Serialize through
    // serde_json so the tab/newline cases are valid JSON string escapes.
    let future = CURRENT_SCHEMA_VERSION + 1;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    for marker in [format!("  {future}  "), format!("\t{future}\n")] {
        let body = serde_json::json!({
            "schema_version": marker,
            "email": "e@example.com",
        });
        std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(
            load_advisories(&path),
            vec![format!(
                "設定ファイルのバージョン {future} は未対応です。既定値で起動します"
            )],
            "{marker:?}"
        );
    }

    // A padded current version is not future: no advisory is emitted.
    let current = format!("  {CURRENT_SCHEMA_VERSION}  ");
    let body = serde_json::json!({
        "schema_version": current,
        "email": "e@example.com",
    });
    std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
    assert!(load_advisories(&path).is_empty(), "{current:?}");
}
