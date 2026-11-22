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

#[test]
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
    use crate::auth::{MAX_EMAIL_LEN, MAX_SERVER_URL_LEN};

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
