#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::settings::*;

#[test]
fn defaults_are_sensible() {
    let settings = Settings::default();
    assert!(settings.server_url.contains("bitwarden"));
    assert!(settings.email.is_empty());
    assert_eq!(settings.idle_lock_seconds, 300);
    assert_eq!(settings.login_timeout_seconds, 30);
    assert_eq!(settings.clipboard_restore_seconds, 30);
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

#[::core::prelude::v1::test]
fn debug_masks_email() {
    let settings = Settings {
        email: "alice@example.com".into(),
        ..Default::default()
    };
    let debug = format!("{settings:?}");
    assert!(!debug.contains("alice@example.com"), "{debug}");
    assert!(debug.contains("[redacted]"), "{debug}");
    assert!(debug.contains("vault.bitwarden.com"), "{debug}");
}

#[::core::prelude::v1::test]
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

#[::core::prelude::v1::test]
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
