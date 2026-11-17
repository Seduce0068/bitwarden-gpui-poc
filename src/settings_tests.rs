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
        ..Default::default()
    };
    let safe = settings.sanitized();
    assert_eq!(safe.idle_lock_seconds, 60);
    assert_eq!(safe.login_timeout_seconds, 1);
    assert_eq!(safe.clipboard_restore_seconds, 3600);
    assert_eq!(safe.password_generator.length, 128);
    assert_eq!(safe.passphrase_generator.words, 20);
    assert_eq!(settings.idle_lock_seconds, 0, "sanitized must not mutate");
}

#[::core::prelude::v1::test]
fn load_sanitizes_hand_edited_values() {
    let path = std::env::temp_dir().join("bitwarden-gpui-poc-sanitize.json");
    std::fs::write(
        &path,
        br#"{"idle_lock_seconds":0,"login_timeout_seconds":0,"clipboard_restore_seconds":99999}"#,
    )
    .unwrap();
    let loaded = Settings::load_detailed(&path).unwrap();
    assert_eq!(loaded.idle_lock_seconds, 60);
    assert_eq!(loaded.login_timeout_seconds, 1);
    assert_eq!(loaded.clipboard_restore_seconds, 3600);
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

    for error in [
        SettingsLoadError::NotFound,
        SettingsLoadError::ReadFailed,
        SettingsLoadError::ParseFailed,
    ] {
        assert!(!error.message().is_empty());
    }
}
