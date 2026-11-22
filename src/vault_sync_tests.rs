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

/// Build a vault that keeps duplicate ciphers, bypassing `parse_sync`'s
/// pre-sync dedup. The import layer's `ImportAudit` contract is defined for
/// duplicates handed directly to `import_logins_with_audit`, so those tests
/// construct their vault this way instead of going through `parse_sync`.
fn unlocked_vault_raw(ciphers: &[serde_json::Value]) -> openwarden::Vault {
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
    let sync = openwarden::SyncData::from_json(body.as_bytes()).expect("sync JSON should parse");
    vault.apply_sync(sync).expect("sync should apply");
    vault
}

fn vault_from_body(body: &[u8]) -> openwarden::Vault {
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    let sync = parse_sync(body).expect("sync JSON should parse");
    vault.apply_sync(sync).expect("sync should apply");
    vault
}

/// Uppercase the first ASCII letter of every JSON key, recursively, to mimic
/// a Vaultwarden server that returns PascalCase wire keys.
fn pascalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, mut child) in std::mem::take(map) {
                pascalize(&mut child);
                let mut chars = key.chars();
                let pascal = match chars.next() {
                    Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                };
                map.insert(pascal, child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                pascalize(item);
            }
        }
        _ => {}
    }
}

#[test]
fn duplicate_ids_are_collapsed_before_remove() {
    let id = "dup-1";
    let vault = unlocked_vault_raw(&[
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
    let vault = unlocked_vault_raw(&[
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
    let vault = unlocked_vault_raw(&[
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
    let vault = unlocked_vault_raw(&[
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
fn duplicate_ciphers_use_the_latest_revisions_decrypted_content() {
    // Regression: `openwarden::Vault::cipher(id)` returns the first matching
    // row, so a newer `LoginInfo` used to be paired with the older cipher's
    // decrypted password. Pre-sync dedup keeps metadata and fields consistent.
    let id = "dup-content";
    let mut old = encrypted_login(id, "OLD_PASSWORD_VALUE", REAL_TOTP);
    old["revisionDate"] = serde_json::json!("2024-01-01T00:00:00Z");
    let mut newest = encrypted_login(id, "NEW_PASSWORD_VALUE", REAL_TOTP);
    newest["revisionDate"] = serde_json::json!("2024-03-01T00:00:00Z");
    // A unique id must survive alongside the collapsed duplicate.
    let other = encrypted_login("unique-1", "UNIQUE_PASSWORD_VALUE", REAL_TOTP);
    let vault = unlocked_vault(&[old, newest, other]);
    let model = import_logins(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 2, "duplicate collapsed, unique kept");
    let item = model.item(id).expect("the duplicate id must survive");
    assert_eq!(
        item.revision_date,
        parse_revision(Some("2024-03-01T00:00:00Z")).unwrap()
    );
    assert_eq!(item.password(), Some("NEW_PASSWORD_VALUE"));
    assert_eq!(item.totp_secret(), Some(REAL_TOTP));
    assert_eq!(
        model.item("unique-1").unwrap().password(),
        Some("UNIQUE_PASSWORD_VALUE")
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
    let vault = unlocked_vault_raw(&[secret_cipher, cipher(id, "2024-01-02T00:00:00Z")]);
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
    let vault = unlocked_vault_raw(&[
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
    // The placeholder must not expose the internal folder id (vault_sync.rs:237).
    assert_eq!(bad.name, "(復号できませんでした)");
    assert!(!bad.name.contains("f-bad"), "{:?}", bad.name);
    // The id is still available for filtering and lookup.
    assert_eq!(bad.id, "f-bad");
}

#[test]
fn undecryptable_login_name_is_placeholdered_without_the_internal_id() {
    // G07: the login-name fallback must not expose the internal cipher id;
    // the id stays on `VaultItem::id` for lookup and filtering
    // (vault_sync.rs:271-286).
    let mut bad = cipher("login-secret-id", "2024-01-01T00:00:00Z");
    bad["name"] = serde_json::json!("not-an-enc-string");
    bad["login"]["username"] = serde_json::json!("USERNAME_SHOULD_NOT_LEAK");
    let vault = unlocked_vault(&[bad]);
    let model = import_logins(&vault).expect("a bad name must not abort the import");

    assert_eq!(model.items.len(), 1);
    let item = &model.items[0];
    assert_eq!(item.id, "login-secret-id");
    assert_eq!(item.name, "(復号できませんでした)");
    assert!(!item.name.contains("login-secret-id"), "{:?}", item.name);
    let rendered = format!("{item:?} {}", serde_json::to_string(item).unwrap());
    assert!(!rendered.contains("not-an-enc-string"), "{rendered}");
    assert!(!rendered.contains("USERNAME_SHOULD_NOT_LEAK"), "{rendered}");
}

#[test]
fn undecryptable_username_currently_folds_into_an_empty_string() {
    // Documented current behaviour (login_item docs): a broken username
    // ciphertext is folded into an empty string just like an absent field;
    // there is no `UNDECRYPTABLE_USERNAME` marker. The raw ciphertext never
    // enters the model, its Debug output or its serde form.
    let mut bad = cipher("username-bad", "2024-01-01T00:00:00Z");
    bad["login"]["username"] = serde_json::json!("NEVER_IN_THE_MODEL_USERNAME");
    let vault = unlocked_vault(&[bad]);
    let model = import_logins(&vault).expect("a bad username must not abort the import");

    let item = model.item("username-bad").unwrap();
    assert_eq!(item.login().unwrap().0, "");
    let rendered = format!("{item:?} {}", serde_json::to_string(item).unwrap());
    assert!(
        !rendered.contains("NEVER_IN_THE_MODEL_USERNAME"),
        "{rendered}"
    );
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
    // The decrypted name/username from `encrypted_login` must survive the
    // openwarden -> model path, not just the password/TOTP fields
    // (vault_sync.rs:272-282).
    assert_eq!(item.name, "Example Login");
    let (username, password, totp, uris) = item.login().expect("the item is a login");
    assert_eq!(username, "alice@example.com");
    assert_eq!(password, REAL_PASSWORD);
    assert_eq!(totp, REAL_TOTP);
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, "https://example.com");
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
    // A broken TOTP ciphertext keeps the "2FA configured" information instead
    // of being collapsed into "no TOTP".
    assert_eq!(bad.totp_secret(), Some(UNDECRYPTABLE_TOTP));
    assert!(is_undecryptable_totp(bad.totp_secret().unwrap()));
    assert!(crate::health::has_totp_field(bad));
    assert!(!crate::health::has_usable_totp(bad));
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

#[test]
fn undecryptable_totp_keeps_the_has_totp_information() {
    let mut bad = cipher("totp-bad", "2024-01-01T00:00:00Z");
    bad["login"]["totp"] = serde_json::json!("NEVER_IN_THE_MODEL_TOTP");
    let unset = cipher("totp-unset", "2024-01-01T00:00:00Z");
    let vault = unlocked_vault(&[bad, unset]);
    let model = import_logins(&vault).expect("import should succeed");

    let bad_item = model.item("totp-bad").unwrap();
    let unset_item = model.item("totp-unset").unwrap();
    assert_eq!(bad_item.totp_secret(), Some(UNDECRYPTABLE_TOTP));
    assert_eq!(unset_item.totp_secret(), Some(""));
    // The audit/UI can still tell that the first login is 2FA-enabled.
    assert!(crate::health::has_totp_field(bad_item));
    assert!(!crate::health::has_totp_field(unset_item));
    assert!(!crate::health::has_usable_totp(bad_item));

    let report = crate::health::audit(
        &model,
        crate::health::Thresholds::default(),
        i64::try_from(TOTP_AT).unwrap(),
    );
    let bad_report = report
        .items
        .iter()
        .find(|item| item.id == "totp-bad")
        .unwrap();
    assert!(bad_report
        .findings
        .contains(&crate::health::Finding::TotpUninspectable));
    assert!(!bad_report
        .findings
        .contains(&crate::health::Finding::NoTotp));
    let unset_report = report
        .items
        .iter()
        .find(|item| item.id == "totp-unset")
        .unwrap();
    assert!(unset_report
        .findings
        .contains(&crate::health::Finding::NoTotp));
    assert_eq!(report.with_totp, 0);
}

#[test]
fn undecryptable_uri_becomes_a_marker_and_is_audited_as_uninspectable() {
    let mut bad = cipher("login-bad-uri", "2024-01-02T00:00:00Z");
    bad["name"] = serde_json::json!("plain name");
    bad["login"]["username"] = serde_json::json!("plain-user");
    bad["login"]["password"] = serde_json::json!("NEVER_IN_THE_MODEL");
    bad["login"]["totp"] = serde_json::json!("NEVER_IN_THE_MODEL_TOTP");
    bad["login"]["uris"] = serde_json::json!([{ "uri": "NEVER_IN_THE_MODEL_URI" }]);
    let vault = unlocked_vault(&[bad]);
    let (model, _audit) = import_logins_with_audit(&vault).expect("one bad field must not abort");

    assert_eq!(model.items.len(), 1);
    let uris = model.items[0].uris();
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, UNDECRYPTABLE_URI);

    let report = crate::health::audit(
        &model,
        crate::health::Thresholds::default(),
        i64::try_from(TOTP_AT).unwrap(),
    );
    assert!(report.items[0]
        .findings
        .contains(&crate::health::Finding::UriUninspectable));

    let rendered = format!("{model:?} {}", serde_json::to_string(&model.items).unwrap());
    assert!(!rendered.contains("NEVER_IN_THE_MODEL_URI"), "{rendered}");
}

#[test]
fn undecryptable_uri_marker_and_real_match_types_are_distinguished() {
    assert!(is_undecryptable_uri(UNDECRYPTABLE_URI));
    assert!(!is_undecryptable_uri("https://example.com"));
    assert!(!is_undecryptable_uri(UNDECRYPTABLE_PASSWORD));
    assert!(!is_undecryptable_uri(""));
    // Only the exact NUL-prefixed marker counts; a lookalike does not.
    assert!(!is_undecryptable_uri("\0openwarden:uri-undecryptable-x"));
    assert_eq!(UNDECRYPTABLE_URI, "\u{0}openwarden:uri-undecryptable");

    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let enc = |plain: &[u8]| {
        openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string()
    };
    let mut with_matches = encrypted_login("uri-matches", REAL_PASSWORD, REAL_TOTP);
    with_matches["login"]["uris"] = serde_json::json!([
        { "uri": enc(b"https://one.example.com"), "match": 1 },
        { "uri": enc(b"https://two.example.com"), "match": 3 },
        { "uri": enc(b"https://three.example.com"), "match": 5 },
        { "uri": enc(b"https://four.example.com"), "match": null }
    ]);
    let vault = unlocked_vault(&[with_matches]);
    let model = import_logins(&vault).expect("import should succeed");
    let uris = model.item("uri-matches").unwrap().uris();
    assert_eq!(uris.len(), 4);
    // `to_wire()` numbers survive the real sync -> openwarden -> model path.
    assert_eq!(uris[0].match_type, Some(1));
    assert_eq!(uris[1].match_type, Some(3));
    assert_eq!(uris[2].match_type, Some(5));
    assert_eq!(uris[3].match_type, None);
    for uri in uris {
        assert!(!is_undecryptable_uri(&uri.uri));
    }
}

#[test]
fn pascal_case_sync_body_is_normalized_for_openwarden() {
    let body = br#"{
        "Profile": {"Id": "user-1", "Key": "2.encrypted"},
        "Folders": [{"Id": "f1", "Name": "2.folder"}],
        "Ciphers": [],
        "Object": "sync"
    }"#;
    let data = parse_sync(body).expect("PascalCase keys must be accepted");
    assert_eq!(data.user_id(), "user-1");
    assert!(data.protected_key().is_some());

    // Values (including encrypted strings) must survive unchanged.
    assert_eq!(data.protected_key(), Some("2.encrypted"));
}

#[test]
fn camel_case_keys_and_values_are_left_unchanged() {
    let key = camel_case_key("RevisionDate");
    assert_eq!(key, "revisionDate");
    assert_eq!(camel_case_key("privateKey"), "privateKey");
    assert_eq!(camel_case_key(""), "");
}

#[test]
fn pascal_case_cipher_fields_are_normalized_end_to_end() {
    // Build a real encrypted login, then rewrite every JSON key to PascalCase.
    // Unlike a duplicate `user_id` assertion, importing the result proves that
    // the nested cipher/login/URI keys were actually recognized: a missed key
    // would leave the password, TOTP, folder or revision at their defaults.
    let mut encrypted = encrypted_login("cipher-1", REAL_PASSWORD, REAL_TOTP);
    encrypted["folderId"] = serde_json::json!("f1");
    let mut body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [],
        "ciphers": [encrypted],
    });
    pascalize(&mut body);
    let vault = vault_from_body(body.to_string().as_bytes());
    let model = import_logins(&vault).expect("nested PascalCase keys must be normalized");

    assert_eq!(model.items.len(), 1);
    let item = &model.items[0];
    assert_eq!(item.id, "cipher-1");
    assert_eq!(item.password(), Some(REAL_PASSWORD));
    assert_eq!(item.totp_secret(), Some(REAL_TOTP));
    assert_eq!(
        item.revision_date,
        parse_revision(Some("2024-01-01T00:00:00Z")).unwrap()
    );
    assert_eq!(item.folder_id.as_deref(), Some("f1"));
    assert_eq!(item.uris().len(), 1);
    assert_eq!(item.uris()[0].uri, "https://example.com");
}

#[test]
fn mixed_case_key_collision_is_rejected() {
    let body = br#"{
        "Profile": {"Id": "user-1", "Key": "2.a", "key": "2.b"},
        "Ciphers": []
    }"#;
    assert!(parse_sync(body).is_err());
}

#[test]
fn dedup_counts_missing_and_invalid_revisions_as_unknown_and_keeps_first_on_ties() {
    // `dedup_ciphers_by_revision` (vault_sync.rs:168-198) must not let a
    // malformed timestamp outrank a real one, and equal revisions must keep
    // the first row so normalization stays deterministic.
    let mut value = serde_json::json!({
        "ciphers": [
            {"id": "missing", "revisionDate": null},
            {"id": "missing", "revisionDate": "2024-01-02T00:00:00Z"},
            {"id": "invalid", "revisionDate": "not-a-date"},
            {"id": "invalid", "revisionDate": null},
            {"id": "tie", "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "tie", "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "no-date"},
            {"id": "no-date", "revisionDate": 12345},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    let ids: Vec<&str> = kept.iter().map(|row| row["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["missing", "invalid", "tie", "no-date"]);
    assert_eq!(
        kept[0]["revisionDate"],
        serde_json::json!("2024-01-02T00:00:00Z"),
        "a real revision beats a missing one"
    );
    assert_eq!(
        kept[1]["revisionDate"],
        serde_json::json!("not-a-date"),
        "an unparsable revision is UNKNOWN_REVISION, tying with null: first wins"
    );
    assert_eq!(
        kept[2]["revisionDate"],
        serde_json::json!("2024-01-01T00:00:00Z")
    );
    assert!(
        kept[3].get("revisionDate").is_none(),
        "a non-string revision is unknown and ties with a missing one"
    );
}

#[test]
fn dedup_skips_rows_without_a_string_id() {
    // Rows whose `id` is missing, null or a number are left untouched rather
    // than being keyed under a fabricated id or aborting the dedup pass
    // (vault_sync.rs:180-183). Valid duplicate ids still collapse normally.
    let mut value = serde_json::json!({
        "ciphers": [
            {"name": "no-id"},
            {"id": null, "name": "null-id"},
            {"id": 42, "name": "numeric-id"},
            {"id": "dup", "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "dup", "revisionDate": "2024-02-01T00:00:00Z"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 4, "only the older duplicate is dropped");
    assert_eq!(kept[0]["name"], "no-id");
    assert_eq!(kept[1]["name"], "null-id");
    assert_eq!(kept[2]["name"], "numeric-id");
    assert_eq!(kept[3]["id"], "dup");
    assert_eq!(
        kept[3]["revisionDate"], "2024-02-01T00:00:00Z",
        "the newest revision of the valid id wins"
    );
}

#[test]
fn key_conflicts_inside_array_objects_are_rejected() {
    // `normalize_sync_keys` recurses into arrays (vault_sync.rs:148-151): a
    // collision between `Key` and `key` inside any array element must be
    // reported, not silently overwritten by whichever key iterates last.
    let mut value = serde_json::json!({
        "ciphers": [
            {"id": "ok", "login": {"Username": "u"}},
            {"Id": "bad", "Key": "2.a", "key": "2.b"}
        ]
    });
    let error = super::normalize_sync_keys(&mut value).unwrap_err();
    assert!(error.contains("conflicting keys"), "{error}");
    assert!(error.contains("key"), "{error}");
    // The server controls the raw key names; they must not be echoed into a
    // detail string that may reach diagnostics (vault_sync.rs:139-143).
    assert!(!error.contains("`Key`"), "{error}");
    assert!(!error.contains("`key`"), "{error}");

    // A single spelling per object remains valid.
    let mut clean = serde_json::json!({
        "ciphers": [{"Id": "ok", "Key": "2.a"}]
    });
    assert!(super::normalize_sync_keys(&mut clean).is_ok());
    assert_eq!(clean["ciphers"][0]["id"], "ok");
}

#[test]
fn plain_import_discards_the_audit_the_with_audit_variant_exposes() {
    let id = "audit-discard";
    let vault = unlocked_vault_raw(&[
        cipher(id, "2024-01-01T00:00:00Z"),
        cipher(id, "2024-01-02T00:00:00Z"),
    ]);
    let from_plain = import_logins(&vault).expect("import should succeed");
    let (from_audit, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    // Both entry points build the same model, but only the `*_with_audit`
    // variant returns the duplicate decision; the production path drops it.
    assert_eq!(from_plain.items, from_audit.items);
    assert_eq!(from_plain.folders, from_audit.folders);
    assert!(
        audit
            .iter()
            .any(|entry| matches!(entry, ImportAudit::Updated { .. })),
        "the change log exists but `import_logins` discards it: {audit:?}"
    );
}

#[test]
fn updated_branch_keeps_first_rows_decrypted_content_for_raw_duplicates() {
    // `import_logins_with_audit` reads fields from a concrete
    // `openwarden::Vault` by id. With duplicates that bypass `parse_sync`, the
    // field readers see the first row, so the `Updated` replacement can refresh
    // revision metadata but not the decrypted password. Production avoids this
    // by deduplicating before `apply_sync` (covered by the sibling test using
    // `unlocked_vault`).
    let id = "updated-content";
    let mut old = encrypted_login(id, "OLD_UPDATED_PASSWORD", REAL_TOTP);
    old["revisionDate"] = serde_json::json!("2024-01-01T00:00:00Z");
    let mut newest = encrypted_login(id, "NEW_UPDATED_PASSWORD", REAL_TOTP);
    newest["revisionDate"] = serde_json::json!("2024-03-01T00:00:00Z");
    let vault = unlocked_vault_raw(&[old.clone(), newest.clone()]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].id, id);
    assert_eq!(
        model.items[0].revision_date,
        parse_revision(Some("2024-03-01T00:00:00Z")).unwrap(),
        "the newer LoginInfo's revision must win"
    );
    assert_eq!(
        model.items[0].password(),
        Some("OLD_UPDATED_PASSWORD"),
        "field decryption resolves by id to the first raw duplicate"
    );
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: id.to_string(),
                revision: parse_revision(Some("2024-01-01T00:00:00Z")).unwrap(),
            },
            ImportAudit::Updated {
                id: id.to_string(),
                old_revision: parse_revision(Some("2024-01-01T00:00:00Z")).unwrap(),
                new_revision: parse_revision(Some("2024-03-01T00:00:00Z")).unwrap(),
            },
        ]
    );

    // The production path (parse_sync pre-dedup) pairs the newer revision with
    // its own ciphertext, so the newest password really is imported there.
    let deduped = unlocked_vault(&[old, newest]);
    let (model, _) = import_logins_with_audit(&deduped).expect("import should succeed");
    assert_eq!(model.items[0].password(), Some("NEW_UPDATED_PASSWORD"));
}

#[test]
fn parse_sync_retains_the_original_failure_as_a_source() {
    use std::error::Error as _;

    for body in [
        &b"not json"[..],
        &br#"{"profile":{"id":"u"},"Key":1,"key":2}"#[..],
        &br#"{"folders":[],"ciphers":[]}"#[..],
    ] {
        let error = parse_sync(body).unwrap_err();
        assert!(
            matches!(error, SyncError::InvalidLoginCause(_, _)),
            "{error:?}"
        );
        let source = error
            .source()
            .expect("every parse_sync failure must carry a typed cause");
        assert!(!source.to_string().is_empty(), "{error:?}");
        // AppError::InvalidLoginCause keeps the family message in `message()`
        // and the original serde/openwarden text in `source()`; the latter is
        // only available before conversion to the small UI error enum.
        assert_eq!(error.message(), "ログイン項目を読み取れませんでした");
        assert!(!source
            .to_string()
            .contains("ログイン項目を読み取れませんでした"));
    }
}

#[test]
fn pascal_case_folder_names_and_duplicate_ids_survive_end_to_end() {
    // A real Vaultwarden body can use PascalCase everywhere and repeat a
    // cipher id. Normalization must decrypt the folder names and dedup must
    // keep the newest cipher before `apply_sync` sees the rows.
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let enc = |plain: &[u8]| {
        openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string()
    };
    let mut old = encrypted_login("dup-folder", "OLD_PASSWORD_VALUE", REAL_TOTP);
    old["revisionDate"] = serde_json::json!("2024-01-01T00:00:00Z");
    old["folderId"] = serde_json::json!("f-work");
    let mut newer = encrypted_login("dup-folder", "NEW_PASSWORD_VALUE", REAL_TOTP);
    newer["revisionDate"] = serde_json::json!("2024-03-01T00:00:00Z");
    newer["folderId"] = serde_json::json!("f-work");
    let mut body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [
            { "id": "f-work", "name": enc(b"Work") },
            { "id": "f-private", "name": enc(b"Private") },
        ],
        "ciphers": [old, newer],
    });
    pascalize(&mut body);
    let vault = vault_from_body(body.to_string().as_bytes());
    let model = import_logins(&vault).expect("PascalCase folders and duplicates must import");

    assert_eq!(model.folders.len(), 2);
    assert_eq!(model.folder_name("f-work"), Some("Work"));
    assert_eq!(model.folder_name("f-private"), Some("Private"));
    assert_eq!(model.items.len(), 1, "the duplicate id must be collapsed");
    let item = model.item("dup-folder").expect("the id must survive");
    assert_eq!(item.password(), Some("NEW_PASSWORD_VALUE"));
    assert_eq!(item.totp_secret(), Some(REAL_TOTP));
    assert_eq!(item.folder_id.as_deref(), Some("f-work"));
    assert_eq!(
        item.revision_date,
        parse_revision(Some("2024-03-01T00:00:00Z")).unwrap()
    );
}

#[test]
fn per_item_key_ciphers_decrypt_with_a_nonzero_user_key() {
    // Unlike the shared helpers, this fixture uses a different user key and
    // gives the cipher its own item key: fields are encrypted under the item
    // key, and that key is encrypted under the user key. A path that ignored
    // `cipher.key` or hard-coded the shared zero key would fail here.
    let user_bytes = [0x42u8; 64];
    let user_key = openwarden::UserKey::from_bytes(&user_bytes).expect("a 64-byte user key");
    let user_symmetric =
        openwarden::SymmetricKey::from_bytes(&user_bytes).expect("a 64-byte user symmetric key");
    let item_bytes = [0x43u8; 64];
    let item_symmetric =
        openwarden::SymmetricKey::from_bytes(&item_bytes).expect("a 64-byte item key");
    let encrypted_item_key = openwarden::EncString::encrypt(&user_symmetric, &item_bytes)
        .expect("the item key should encrypt under the user key")
        .to_string();
    let enc = |plain: &[u8]| {
        openwarden::EncString::encrypt(&item_symmetric, plain)
            .expect("field should encrypt under the item key")
            .to_string()
    };
    let folder_name = openwarden::EncString::encrypt(&user_symmetric, b"Work")
        .expect("folder name should encrypt under the user key")
        .to_string();
    let body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [{ "id": "f1", "name": folder_name }],
        "ciphers": [{
            "id": "item-key-1",
            "type": 1,
            "key": encrypted_item_key,
            "name": enc(b"Item-key Login"),
            "login": {
                "username": enc(b"alice@example.com"),
                "password": enc(REAL_PASSWORD.as_bytes()),
                "totp": enc(REAL_TOTP.as_bytes()),
                "uris": [{ "uri": enc(b"https://example.com") }],
            },
            "revisionDate": "2024-01-01T00:00:00Z",
        }],
    })
    .to_string();
    let sync = parse_sync(body.as_bytes()).expect("sync JSON should parse");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(user_key, state);
    vault.apply_sync(sync).expect("sync should apply");
    let model = import_logins(&vault).expect("per-item key fields must decrypt");

    assert_eq!(model.folder_name("f1"), Some("Work"));
    assert_eq!(model.items.len(), 1);
    let item = &model.items[0];
    assert_eq!(item.name, "Item-key Login");
    let (username, password, totp, uris) = item.login().expect("the item is a login");
    assert_eq!(username, "alice@example.com");
    assert_eq!(password, REAL_PASSWORD);
    assert_eq!(totp, REAL_TOTP);
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, "https://example.com");
}

#[test]
fn absent_password_is_empty_and_markers_are_exact() {
    // `vault.password()` returns `Ok(None)` when the field is absent. The
    // importer must map that to a genuinely empty password (vault_sync.rs:
    // 295-303), not to the undecryptable marker or a pseudo-marker.
    let vault = unlocked_vault(&[cipher("no-password", "2024-01-01T00:00:00Z")]);
    let (model, _audit) = import_logins_with_audit(&vault).expect("import should succeed");
    let item = model
        .items
        .iter()
        .find(|item| item.id == "no-password")
        .unwrap();
    assert_eq!(item.password(), Some(""));
    assert!(!is_undecryptable_password(item.password().unwrap()));
    assert!(!is_undecryptable_totp(item.totp_secret().unwrap_or("")));

    // The marker helpers use exact equality (vault_sync.rs:39-52): a lookalike
    // must never be mistaken for "ciphertext could not be decrypted".
    assert!(is_undecryptable_password(UNDECRYPTABLE_PASSWORD));
    assert!(is_undecryptable_totp(UNDECRYPTABLE_TOTP));
    for impostor in [
        "",
        "openwarden:password-undecryptable",
        "\u{0}openwarden:password-undecryptable ",
        "\u{0}openwarden:totp-undecryptable ",
        "\u{0}OPENWARDEN:PASSWORD-UNDECRYPTABLE",
        "\u{0}openwarden:password-undecryptable\u{0}",
    ] {
        assert!(
            !is_undecryptable_password(impostor),
            "pseudo-marker accepted as a password marker: {impostor:?}"
        );
        assert!(
            !is_undecryptable_totp(impostor),
            "pseudo-marker accepted as a TOTP marker: {impostor:?}"
        );
    }
}
