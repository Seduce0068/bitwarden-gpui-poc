#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::vault_sync::*;

const REAL_PASSWORD: &str = "vT7#kQm2!zR9wP4$xL8@";
const REAL_TOTP: &str =
    "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example";
const TOTP_AT: u64 = 1_700_000_000;

#[test]
fn sync_body_with_empty_profile_and_folders_parses() {
    let body = br#"{
        "profile": {"id": "user-1"},
        "folders": [{"id": "f1", "name": "2.work"}],
        "ciphers": []
    }"#;
    let sync = parse_sync(body).expect("sync JSON should parse");
    assert_eq!(sync.user_id(), "user-1");
}

#[test]
fn malformed_sync_body_is_reported() {
    assert!(parse_sync(b"not json").is_err());
    // profile.id is required by openwarden's sync wire format.
    assert!(parse_sync(br#"{"folders": [], "ciphers": []}"#).is_err());
    assert!(parse_sync(br#"{"profile": {}}"#).is_err());
}

#[test]
fn revision_dates_convert_to_unix_seconds() {
    assert_eq!(parse_revision(Some("1970-01-01T00:00:00Z")), Some(0));
    // The time-of-day is now part of the epoch value.
    assert_eq!(
        parse_revision(Some("2023-11-14T22:13:20Z")),
        Some(1_700_000_000)
    );
    assert_eq!(parse_revision(Some("not-a-date")), None);
    assert_eq!(parse_revision(None), None);
    // Out-of-range month/day and too-short strings are rejected.
    assert_eq!(parse_revision(Some("2023-13-01T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2023-01-32T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2023-1-01")), None);
}

#[test]
fn revision_dates_validate_days_in_month_and_leap_years() {
    // Leap-day rules: divisible by 4, except centuries not divisible by 400.
    assert_eq!(
        parse_revision(Some("2024-02-29T00:00:00Z")),
        Some(1_709_164_800)
    );
    assert_eq!(parse_revision(Some("2024-02-30T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2023-02-29T00:00:00Z")), None);
    assert_eq!(
        parse_revision(Some("2000-02-29T00:00:00Z")),
        Some(951_782_400)
    );
    assert_eq!(parse_revision(Some("1900-02-29T00:00:00Z")), None);

    // 30-day months and the boundaries of every month length.
    assert_eq!(parse_revision(Some("2024-04-31T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2024-06-31T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2024-09-31T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2024-11-31T00:00:00Z")), None);
    assert_eq!(
        parse_revision(Some("2024-01-31T00:00:00Z")),
        Some(1_706_659_200)
    );
    assert_eq!(
        parse_revision(Some("2024-04-30T00:00:00Z")),
        Some(1_714_435_200)
    );
    assert_eq!(parse_revision(Some("2024-00-01T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2024-01-00T00:00:00Z")), None);
}

#[test]
fn revision_dates_apply_rfc3339_offsets() {
    // Z / z and lower-case t are all valid RFC 3339 spellings.
    assert_eq!(parse_revision(Some("1970-01-01t00:00:00z")), Some(0));
    // 09:00 at +09:00 and 19:00 on the previous day at -05:00 are both UTC
    // midnight, i.e. epoch 0.
    assert_eq!(parse_revision(Some("1970-01-01T09:00:00+09:00")), Some(0));
    assert_eq!(parse_revision(Some("1969-12-31T19:00:00-05:00")), Some(0));
    // All three spellings below denote the same instant.
    let expected = Some(1_700_000_000);
    for value in [
        "2023-11-14T22:13:20Z",
        "2023-11-15T07:13:20+09:00",
        "2023-11-14T17:13:20-05:00",
        "2023-11-14T22:13:20.999Z",
        "2023-11-14T22:13:20,999Z",
    ] {
        assert_eq!(parse_revision(Some(value)), expected, "{value}");
    }
    // Offsets take the date across a month/year boundary.
    assert_eq!(
        parse_revision(Some("2024-01-01T01:00:00+09:00")),
        parse_revision(Some("2023-12-31T16:00:00Z"))
    );
}

#[test]
fn revision_dates_reject_malformed_timestamps() {
    for value in [
        "2023-11-14",                 // no time or offset
        "2023-11-14 22:13:20Z",       // space instead of T
        "2023-11-14T22:13:20",        // no offset
        "2023-11-14T22:13:20+0900",   // offset without colon
        "2023-11-14T22:13:20+24:00",  // offset hour out of range
        "2023-11-14T22:13:20+09:60",  // offset minute out of range
        "2023-11-14T22:13:20.Z",      // empty fractional part
        "2023-11-14T24:00:00Z",       // hour out of range
        "2023-11-14T22:60:00Z",       // minute out of range
        "2023-11-14T22:13:60Z",       // second out of range
        "2023-11-14T22:13:20Zjunk",   // trailing bytes
        "2023-11-14T22:13:20+09:00x", // trailing bytes after offset
    ] {
        assert_eq!(parse_revision(Some(value)), None, "{value}");
    }
}

#[test]
fn days_from_civil_matches_known_dates() {
    assert_eq!(days_from_civil(1970, 1, 1), Some(0));
    assert_eq!(days_from_civil(2000, 2, 29), Some(11_016));
    assert_eq!(days_from_civil(2023, 11, 14), Some(19_675));
    // Checked arithmetic must fail instead of wrapping on extreme inputs.
    assert_eq!(days_from_civil(i64::MAX, 1, 1), None);
    assert_eq!(days_from_civil(i64::MIN, 1, 1), None);
}

#[test]
fn error_messages_are_present() {
    assert!(!SyncError::Locked.message().is_empty());
    assert!(!SyncError::InvalidLogin("x".into()).message().is_empty());
}

/// Minimal personal login cipher: no encrypted fields, so a zero test key
/// is enough for the metadata-only import path.
fn cipher(id: &str, revision: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": 1,
        "name": null,
        "login": { "uris": [] },
        "revisionDate": revision,
    })
}

fn unlocked_vault(ciphers: &[serde_json::Value]) -> openwarden::Vault {
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    let body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [],
        "ciphers": ciphers,
    })
    .to_string();
    let sync = parse_sync(body.as_bytes()).expect("sync JSON should parse");
    vault.apply_sync(sync).expect("sync should apply");
    vault
}

#[test]
fn duplicate_ids_are_collapsed_before_remove() {
    let id = "dup-1";
    let vault = unlocked_vault(&[
        cipher(id, "2024-01-01T00:00:00Z"),
        cipher(id, "2024-01-02T00:00:00Z"),
    ]);
    let (mut model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    // Without dedup the same id would occupy two slots and a single remove
    // would wipe both at once.
    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].id, id);
    assert!(audit.contains(&ImportAudit::Updated {
        id: id.to_string(),
        old_revision: parse_revision(Some("2024-01-01T00:00:00Z")).unwrap(),
        new_revision: parse_revision(Some("2024-01-02T00:00:00Z")).unwrap(),
    }));

    assert!(model.remove(id));
    assert!(model.items.is_empty());
}

#[test]
fn regressed_revision_is_clipped_and_recorded() {
    let id = "rev-1";
    let kept = parse_revision(Some("2024-02-01T00:00:00Z")).unwrap();
    let dropped = parse_revision(Some("2024-01-01T00:00:00Z")).unwrap();
    let vault = unlocked_vault(&[
        cipher(id, "2024-02-01T00:00:00Z"),
        cipher(id, "2024-01-01T00:00:00Z"),
    ]);
    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].revision_date, kept);
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: id.to_string(),
                revision: kept,
            },
            ImportAudit::Clipped {
                id: id.to_string(),
                old_revision: kept,
                new_revision: dropped,
            },
        ]
    );
}

#[test]
fn newer_duplicate_replaces_the_older_revision() {
    let id = "rev-2";
    let old = parse_revision(Some("2024-01-01T00:00:00Z")).unwrap();
    let new = parse_revision(Some("2024-03-01T00:00:00Z")).unwrap();
    let vault = unlocked_vault(&[
        cipher(id, "2024-01-01T00:00:00Z"),
        cipher(id, "2024-03-01T00:00:00Z"),
    ]);
    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].revision_date, new);
    assert!(audit.contains(&ImportAudit::Updated {
        id: id.to_string(),
        old_revision: old,
        new_revision: new,
    }));
}

#[test]
fn duplicate_with_same_revision_is_ignored() {
    let id = "rev-3";
    let revision = parse_revision(Some("2024-01-01T00:00:00Z")).unwrap();
    let vault = unlocked_vault(&[
        cipher(id, "2024-01-01T00:00:00Z"),
        cipher(id, "2024-01-01T00:00:00Z"),
    ]);
    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: id.to_string(),
                revision,
            },
            ImportAudit::Ignored {
                id: id.to_string(),
                revision,
            },
        ]
    );
}

#[test]
fn audit_log_never_contains_secrets() {
    let id = "secret-1";
    let marker = "SHOULD_NOT_APPEAR_IN_AUDIT";
    let mut secret_cipher = cipher(id, "2024-01-01T00:00:00Z");
    secret_cipher["name"] = serde_json::json!(marker);
    secret_cipher["login"]["username"] = serde_json::json!(marker);
    secret_cipher["login"]["password"] = serde_json::json!(marker);
    secret_cipher["login"]["totp"] = serde_json::json!(marker);
    let vault = unlocked_vault(&[secret_cipher, cipher(id, "2024-01-02T00:00:00Z")]);
    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
    let rendered = format!("{audit:?}");
    assert!(
        !rendered.contains(marker),
        "audit log leaked a secret field"
    );
    assert!(rendered.contains(id));
}

#[test]
fn plain_import_still_skips_duplicates_and_reports_locked_vault() {
    let id = "plain-1";
    let vault = unlocked_vault(&[
        cipher(id, "2024-01-01T00:00:00Z"),
        cipher(id, "2024-01-02T00:00:00Z"),
    ]);
    let model = import_logins(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 1);

    let mut locked = unlocked_vault(&[]);
    locked.lock();
    assert!(matches!(
        import_logins_with_audit(&locked),
        Err(SyncError::Locked)
    ));
    assert!(matches!(folders_from(&locked), Err(SyncError::Locked)));
}

/// A folder whose `name` is not a valid `EncString` is stored as `None` by
/// `SyncData::from_json`, which makes `folder_name` fail at read time with
/// `MalformedEncString`.
fn vault_with_folders(
    folders: &[serde_json::Value],
    ciphers: &[serde_json::Value],
) -> openwarden::Vault {
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    let body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": folders,
        "ciphers": ciphers,
    })
    .to_string();
    let sync = parse_sync(body.as_bytes()).expect("sync JSON should parse");
    vault.apply_sync(sync).expect("sync should apply");
    vault
}

#[test]
fn undecryptable_folder_name_is_placeholdered_without_discarding_vault() {
    let symmetric = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).unwrap();
    let good_name = openwarden::EncString::encrypt(&symmetric, b"Work")
        .unwrap()
        .to_string();
    let vault = vault_with_folders(
        &[
            serde_json::json!({ "id": "f-good", "name": good_name }),
            serde_json::json!({ "id": "f-bad", "name": "not-an-enc-string" }),
        ],
        &[cipher("login-1", "2024-01-01T00:00:00Z")],
    );

    // Before the fix, the single bad name aborted the whole import.
    let model = import_logins(&vault).expect("a bad folder name must not abort the import");
    assert_eq!(model.items.len(), 1, "login items must survive");
    assert_eq!(model.folders.len(), 2, "both folders must be kept");

    let good = model
        .folders
        .iter()
        .find(|folder| folder.id == "f-good")
        .unwrap();
    assert_eq!(good.name, "Work");
    let bad = model
        .folders
        .iter()
        .find(|folder| folder.id == "f-bad")
        .unwrap();
    assert_eq!(bad.name, "フォルダ (f-bad)");
}

/// A personal login whose fields are real `EncString` ciphertexts, matching
/// what `/api/sync` returns after an actual unlock. The zero user key from
/// `unlocked_vault` is also the item key when the cipher has no own `key`.
fn encrypted_login(id: &str, password: &str, totp: &str) -> serde_json::Value {
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let enc = |plain: &[u8]| {
        serde_json::json!(openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string())
    };
    serde_json::json!({
        "id": id,
        "type": 1,
        "name": enc(b"Example Login"),
        "login": {
            "username": enc(b"alice@example.com"),
            "password": enc(password.as_bytes()),
            "totp": enc(totp.as_bytes()),
            "uris": [{ "uri": enc(b"https://example.com") }],
        },
        "revisionDate": "2024-01-01T00:00:00Z",
    })
}

#[test]
fn real_login_decrypts_secrets_and_enables_totp_copy() {
    let vault = unlocked_vault(&[encrypted_login("login-real", REAL_PASSWORD, REAL_TOTP)]);
    let id = vault.logins()[0].id.clone();
    let model = import_logins(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
    let item = &model.items[0];
    assert_eq!(item.password(), Some(REAL_PASSWORD));
    assert_eq!(item.totp_secret(), Some(REAL_TOTP));
    assert_ne!(item.totp_secret(), Some("available"));

    // The UI's copy action calls `code_at` with the model's TOTP field. The
    // code must match the one openwarden derives from the same ciphertext.
    let copied = crate::totp::code_at(item.totp_secret().unwrap(), TOTP_AT)
        .expect("the model's real TOTP secret must generate a code");
    let direct = vault
        .totp(&id, TOTP_AT)
        .expect("vault TOTP should succeed")
        .expect("the login has a TOTP field");
    assert_eq!(copied.code(), direct.code.expose_secret());
    assert_eq!(copied.code().len(), 6);
}

#[test]
fn undecryptable_password_keeps_the_vault_and_is_excluded_from_audit() {
    let mut bad = cipher("login-bad", "2024-01-02T00:00:00Z");
    bad["name"] = serde_json::json!("plain name");
    bad["login"]["username"] = serde_json::json!("plain-user");
    bad["login"]["password"] = serde_json::json!("NEVER_IN_THE_MODEL");
    bad["login"]["totp"] = serde_json::json!("NEVER_IN_THE_MODEL_TOTP");
    let vault = unlocked_vault(&[encrypted_login("login-good", REAL_PASSWORD, REAL_TOTP), bad]);
    let (model, audit) = import_logins_with_audit(&vault).expect("one bad field must not abort");

    assert_eq!(model.items.len(), 2);
    assert_eq!(audit.len(), 2);
    let good = model
        .items
        .iter()
        .find(|item| item.id == "login-good")
        .unwrap();
    let bad = model
        .items
        .iter()
        .find(|item| item.id == "login-bad")
        .unwrap();
    assert_eq!(good.password(), Some(REAL_PASSWORD));
    assert_eq!(good.totp_secret(), Some(REAL_TOTP));
    assert!(crate::totp::code_at(good.totp_secret().unwrap(), TOTP_AT).is_ok());

    assert_eq!(bad.password(), Some(UNDECRYPTABLE_PASSWORD));
    assert_eq!(bad.totp_secret(), Some(""));
    assert!(crate::totp::code_at(bad.totp_secret().unwrap(), TOTP_AT).is_err());

    // No ciphertext plaintext lands in the model, the audit, or their
    // debug/serde renderings.
    let rendered = format!(
        "{model:?} {audit:?} {}",
        serde_json::to_string(&model.items).unwrap()
    );
    assert!(!rendered.contains("NEVER_IN_THE_MODEL"), "{rendered}");

    // End to end: the health report names exactly the undecryptable login.
    let report = crate::health::audit(
        &model,
        crate::health::Thresholds::default(),
        i64::try_from(TOTP_AT).unwrap(),
    );
    assert_eq!(report.password_uninspectable(), 1);
    assert_eq!(report.with_totp, 1);
    assert_eq!(report.logins, 2);
    assert!(report.summary().contains("パスワード検査対象外: 1 件"));
}

#[test]
fn missing_totp_is_empty_instead_of_an_available_marker() {
    let vault = unlocked_vault(&[cipher("no-totp", "2024-01-01T00:00:00Z")]);
    let model = import_logins(&vault).expect("import should succeed");
    assert_eq!(model.items[0].totp_secret(), Some(""));
    assert!(crate::totp::code_at(model.items[0].totp_secret().unwrap(), TOTP_AT).is_err());
}
