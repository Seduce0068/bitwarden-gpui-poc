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
fn non_object_sync_bodies_are_classified_as_invalid_login() {
    use std::error::Error as _;

    // A JSON scalar or array is syntactically valid, so it passes the serde
    // step; normalization and cipher dedup are no-ops for non-objects, and
    // openwarden rejects it because the required `profile` object is missing
    // (`SyncWire` in openwarden 0.1.1). Every shape must land in the same
    // `InvalidLoginCause` class as a malformed object, with a typed cause and
    // the same family message - never a different variant or a panic.
    for body in [
        &br#"[]"#[..],
        &br#"[{"profile":{"id":"u"}}]"#[..],
        &b"42"[..],
        &br#""sync""#[..],
        &b"null"[..],
    ] {
        let error = parse_sync(body).unwrap_err();
        assert!(
            matches!(error, SyncError::InvalidLoginCause(_, _)),
            "body {body:?}: {error:?}"
        );
        assert_eq!(error.message(), "ログイン項目を読み取れませんでした");
        let source = error
            .source()
            .expect("a non-object body must keep a typed cause")
            .to_string();
        assert!(!source.is_empty(), "body {body:?}");
        assert!(
            !source.contains("ログイン項目を読み取れませんでした"),
            "body {body:?}: the family message must stay in message()"
        );
    }
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
fn pre_1970_timestamps_produce_negative_epoch_seconds() {
    // The checked day arithmetic in `days_from_civil` (vault_sync.rs:481-500)
    // must stay signed: a revision before the Unix epoch is a negative i64,
    // not UNKNOWN_REVISION (0) and not a wrapped positive value.
    assert_eq!(parse_revision(Some("1969-12-31T23:59:59Z")), Some(-1));
    assert_eq!(parse_revision(Some("1969-12-31T00:00:00Z")), Some(-86_400));
    // A positive offset subtracts from the local instant: 23:00 on the last
    // day of 1969 at +09:00 is 14:00 UTC, i.e. -36000 seconds.
    assert_eq!(
        parse_revision(Some("1969-12-31T23:00:00+09:00")),
        Some(-36_000)
    );
    // The same local clock time at UTC is also negative.
    assert_eq!(parse_revision(Some("1969-12-31T23:00:00Z")), Some(-3_600));
    let older = parse_revision(Some("1960-01-01T00:00:00Z")).unwrap();
    assert!(older < 0, "{older}");
    assert_ne!(older, crate::model::UNKNOWN_REVISION);
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
fn revision_dates_accept_the_maximum_numeric_utc_offsets() {
    // parse_revision validates the offset with `offset_hour > 23` and
    // `offset_minute > 59` (vault_sync.rs:411-418), so +23:59 and -23:59 are
    // the last accepted spellings on either side of UTC.
    let utc = parse_revision(Some("2024-01-01T00:00:00Z")).unwrap();
    let plus = parse_revision(Some("2024-01-01T00:00:00+23:59"));
    let minus = parse_revision(Some("2024-01-01T00:00:00-23:59"));

    // 23 * 3600 + 59 * 60 = 86_340 seconds.
    assert_eq!(plus, Some(utc - 86_340));
    assert_eq!(minus, Some(utc + 86_340));
    // Cross-check against the equivalent UTC calendar spellings.
    assert_eq!(plus, parse_revision(Some("2023-12-31T00:01:00Z")));
    assert_eq!(minus, parse_revision(Some("2024-01-01T23:59:00Z")));
    let plus = plus.unwrap();
    let minus = minus.unwrap();
    assert!(plus < utc && utc < minus, "{plus} < {utc} < {minus}");

    // One minute/hour past either boundary is still rejected.
    for value in [
        "2024-01-01T00:00:00+24:00",
        "2024-01-01T00:00:00-24:00",
        "2024-01-01T00:00:00+23:60",
        "2024-01-01T00:00:00-23:60",
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
fn missing_and_invalid_revision_dates_fall_back_to_unknown_revision() {
    // Both the import item (vault_sync.rs:343-344) and the audit entry
    // (vault_sync.rs:548-549) use the same fallback when `revisionDate` is
    // absent or unparsable. `unlocked_vault_raw` keeps the rows as supplied.
    let mut missing = cipher("no-revision", "2024-01-01T00:00:00Z");
    missing
        .as_object_mut()
        .expect("cipher is an object")
        .remove("revisionDate");
    let invalid = cipher("bad-revision", "not-a-date");
    let vault = unlocked_vault_raw(&[missing, invalid]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 2);
    for id in ["no-revision", "bad-revision"] {
        assert_eq!(
            model.item(id).expect("imported item").revision_date,
            crate::model::UNKNOWN_REVISION,
            "{id}"
        );
    }
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: "no-revision".to_string(),
                revision: crate::model::UNKNOWN_REVISION,
            },
            ImportAudit::Added {
                id: "bad-revision".to_string(),
                revision: crate::model::UNKNOWN_REVISION,
            },
        ]
    );
}

#[test]
fn three_duplicate_rows_chain_a_clipped_then_an_updated_decision() {
    // A clipped row must not overwrite the accepted revision in the tracking
    // map: the following newer row has to compare against the *kept* rev and
    // emit `Updated { old_revision: kept, .. }` (vault_sync.rs:551-585).
    let id = "chain-1";
    let kept = parse_revision(Some("2024-02-01T00:00:00Z")).unwrap();
    let regressed = parse_revision(Some("2024-01-01T00:00:00Z")).unwrap();
    let newest = parse_revision(Some("2024-03-01T00:00:00Z")).unwrap();
    let vault = unlocked_vault_raw(&[
        cipher(id, "2024-02-01T00:00:00Z"),
        cipher(id, "2024-01-01T00:00:00Z"),
        cipher(id, "2024-03-01T00:00:00Z"),
    ]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 1, "all three rows collapse to one item");
    assert_eq!(model.items[0].revision_date, newest);
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
                new_revision: regressed,
            },
            ImportAudit::Updated {
                id: id.to_string(),
                old_revision: kept,
                new_revision: newest,
            },
        ]
    );
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
fn folder_name_text_covers_ok_none_placeholder_and_the_reachable_branches() {
    // `folder_name_text` (vault_sync.rs:283-302) maps the otherwise unreachable
    // `Ok(None)` result to the "(名前なし)" placeholder. The helper exists so
    // this defensive arm can be pinned without a fake `openwarden::Vault`.
    assert_eq!(
        super::folder_name_text(Ok(None)),
        "(名前なし)",
        "a missing folder name must not be reported as a decryption failure"
    );
    assert_eq!(
        super::folder_name_text(Err(openwarden::Error::MalformedEncString)),
        "(復号できませんでした)"
    );
    let decrypted = openwarden::SecretString::from("Work".to_string());
    assert_eq!(super::folder_name_text(Ok(Some(decrypted))), "Work");

    // None of the placeholders may expose the internal folder id.
    for placeholder in ["(名前なし)", "(復号できませんでした)"] {
        assert!(!placeholder.contains("f-bad"), "{placeholder}");
    }
}

#[test]
fn dedup_folders_returns_early_when_folders_are_missing_or_not_an_array() {
    // `dedup_folders_by_id` (vault_sync.rs:267-273) is a no-op when the key is
    // absent or the value is not an array; openwarden's parser, not the dedup
    // pass, is responsible for rejecting such a sync body.
    let mut missing = serde_json::json!({"ciphers": []});
    let before = missing.clone();
    super::dedup_folders_by_id(&mut missing);
    assert_eq!(missing, before);

    let mut object = serde_json::json!({"folders": {"id": "f1"}});
    let before = object.clone();
    super::dedup_folders_by_id(&mut object);
    assert_eq!(object, before);

    let mut scalar = serde_json::json!({"folders": 7});
    let before = scalar.clone();
    super::dedup_folders_by_id(&mut scalar);
    assert_eq!(scalar, before);

    // Control: a real array still dedups by string id (first row wins), while
    // rows without one are left for openwarden to handle as usual. Without
    // this, the three assertions above would pass for a stub that does nothing.
    let mut array = serde_json::json!({
        "folders": [
            {"id": "f1", "name": "first"},
            {"id": "f1", "name": "second"},
            {"name": "no-id"},
            {"id": 42}
        ]
    });
    super::dedup_folders_by_id(&mut array);
    let kept = array["folders"].as_array().unwrap();
    assert_eq!(kept.len(), 3);
    assert_eq!(kept[0]["name"], "first");
    assert_eq!(kept[1]["name"], "no-id");
    assert_eq!(kept[2]["id"], serde_json::json!(42));
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
    // A failed URI decryption has no wire `match` value to carry, so the
    // marker is emitted with `match_type: None` (vault_sync.rs:313-318).
    assert_eq!(uris[0].match_type, None);

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
fn uri_marker_rejects_pseudo_markers() {
    // `is_undecryptable_uri` (vault_sync.rs:38-41) is exact equality, like its
    // password/TOTP siblings. A lookalike must never trigger the
    // "UriUninspectable" classification.
    assert!(is_undecryptable_uri(UNDECRYPTABLE_URI));
    for impostor in [
        "",
        "openwarden:uri-undecryptable",
        "\u{0}openwarden:uri-undecryptable ",
        "\u{0}OPENWARDEN:URI-UNDECRYPTABLE",
        "\u{0}openwarden:uri-undecryptable\u{0}",
        UNDECRYPTABLE_PASSWORD,
        UNDECRYPTABLE_TOTP,
    ] {
        assert!(
            !is_undecryptable_uri(impostor),
            "pseudo-marker accepted as a URI marker: {impostor:?}"
        );
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
fn camel_case_key_lowercases_only_the_leading_ascii_uppercase() {
    let key = camel_case_key("RevisionDate");
    assert_eq!(key, "revisionDate");
    assert_eq!(camel_case_key("privateKey"), "privateKey");
    assert_eq!(camel_case_key(""), "");
}

#[test]
fn non_ascii_leading_keys_are_passed_through_verbatim() {
    // `camel_case_key` only folds a leading *ASCII* uppercase letter
    // (vault_sync.rs:122-133). A non-ASCII initial code point must survive
    // unchanged: applying a Unicode lowercase mapping there would invent a
    // wire key openwarden never sees, and could collide with a real field.
    for key in ["État", "Äpfel", "Ωmega", "étagère", "日本"] {
        assert_eq!(camel_case_key(key), key, "{key}");
    }
    let lower = camel_case_key("État").to_lowercase();
    assert_ne!(camel_case_key("État"), lower, "no Unicode case folding");

    // The recursive normalizer reaches the same conclusion: only the nested
    // ASCII key changes, the non-ASCII parent key keeps its spelling.
    let mut body = serde_json::json!({
        "État": {"RevisionDate": "2024-01-01T00:00:00Z"},
        "Ciphers": []
    });
    super::normalize_sync_keys(&mut body).unwrap();
    assert_eq!(body["État"]["revisionDate"], "2024-01-01T00:00:00Z");
    assert!(body.get("état").is_none());
}

#[test]
fn an_empty_vault_imports_as_an_empty_model_and_audit() {
    // Importing an unlocked vault with no folders and no ciphers must succeed:
    // the empty collections are a valid contract, not a lock or parse error
    // (vault_sync.rs:552-613). Both public entry points agree.
    let vault = unlocked_vault(&[]);
    let (model, audit) = import_logins_with_audit(&vault).expect("empty vault import");
    assert!(model.items.is_empty());
    assert!(model.folders.is_empty());
    assert!(model.is_empty());
    assert_eq!(model.len(), 0);
    assert!(audit.is_empty(), "no rows means no import decisions");

    let plain = import_logins(&vault).expect("plain empty vault import");
    assert!(plain.items.is_empty());
    assert!(plain.folders.is_empty());
    assert!(folders_from(&vault).expect("empty folders").is_empty());
}

#[test]
fn revision_dates_combine_fractional_seconds_with_numeric_offsets() {
    // `parse_revision` reads the optional fraction before the numeric offset
    // (vault_sync.rs:392-430). A fraction must not hide the offset, and the
    // offset must still be subtracted from the local wall-clock time.
    let utc = Some(1_700_000_000);
    for value in [
        "2023-11-15T07:13:20.000+09:00",
        "2023-11-15T07:13:20,123456+09:00",
        "2023-11-14T17:13:20.999-05:00",
        "2023-11-14T17:13:20,1-05:00",
    ] {
        assert_eq!(parse_revision(Some(value)), utc, "{value}");
    }
    // A valid fraction cannot rescue an out-of-range offset.
    assert_eq!(parse_revision(Some("2023-11-15T07:13:20.5+24:00")), None);
    assert_eq!(parse_revision(Some("2023-11-15T07:13:20.5+09:60")), None);
    // Nor can a valid offset rescue an empty fraction or trailing bytes.
    assert_eq!(parse_revision(Some("2023-11-15T07:13:20.+09:00")), None);
    assert_eq!(parse_revision(Some("2023-11-15T07:13:20.1+09:00x")), None);
}

#[test]
fn login_without_a_folder_id_imports_with_none() {
    // `login_item` maps an absent `folderId` to `None`; the import must not
    // fabricate a folder or discard the login (vault_sync.rs:347-350).
    let vault = unlocked_vault(&[cipher("no-folder", "2024-01-01T00:00:00Z")]);
    let model = import_logins(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].id, "no-folder");
    assert_eq!(model.items[0].folder_id, None);
    // A sibling row with an explicit folder keeps its assignment, so the
    // assertion above is not just an all-None import.
    let mut with_folder = cipher("with-folder", "2024-01-01T00:00:00Z");
    with_folder["folderId"] = serde_json::json!("f1");
    let vault = unlocked_vault(&[with_folder]);
    let model = import_logins(&vault).expect("import should succeed");
    assert_eq!(model.items[0].folder_id.as_deref(), Some("f1"));
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

#[test]
fn absent_username_field_is_empty_without_a_marker() {
    // `cipher()` has no `login.username`, so `vault.username()` returns
    // `Ok(None)`. `login_item` folds that into an empty string with the same
    // `unwrap_or_default()` used for `Err(_)` (vault_sync.rs:299-304).
    // The existing sibling test covers the Err(_) half of the fold; this one
    // pins the Ok(None) half through the real, uninjected openwarden vault.
    let vault = unlocked_vault(&[cipher("no-username", "2024-01-01T00:00:00Z")]);
    let model = import_logins(&vault).expect("a missing username must not abort the import");
    let item = model.item("no-username").unwrap();
    assert_eq!(item.login().unwrap().0, "");
    // No sentinel is introduced for usernames: the raw JSON field never
    // enters the model, even when it is absent rather than undecryptable.
    assert!(!item.login().unwrap().0.contains("openwarden"));
}

#[test]
fn dedup_is_a_no_op_when_ciphers_is_missing_or_not_an_array() {
    // `dedup_ciphers_by_revision` returns early when `ciphers` is absent or
    // not an array (vault_sync.rs:181-186). It must neither panic nor rewrite
    // the remaining document; `parse_sync` may be handed such a body.
    let mut missing = serde_json::json!({"profile": {"id": "user-1"}, "folders": []});
    let before = missing.clone();
    super::dedup_ciphers_by_revision(&mut missing);
    assert_eq!(missing, before);
    assert!(missing.get("ciphers").is_none());

    for wrong in [
        serde_json::json!(null),
        serde_json::json!("ciphers"),
        serde_json::json!({"0": "row"}),
        serde_json::json!(42),
    ] {
        let mut value = serde_json::json!({"ciphers": wrong.clone()});
        super::dedup_ciphers_by_revision(&mut value);
        assert_eq!(value["ciphers"], wrong, "{wrong}");
    }
}

#[test]
fn dedup_prefers_unknown_revision_over_a_negative_one() {
    // Pre-epoch timestamps parse to negative i64 seconds, while a missing or
    // unparsable date becomes UNKNOWN_REVISION (0). The comparison at
    // vault_sync.rs:194-198 must therefore let 0 outrank a negative revision.
    let negative = "1969-12-31T23:59:59Z";
    assert!(parse_revision(Some(negative)).unwrap() < crate::model::UNKNOWN_REVISION);

    let mut value = serde_json::json!({
        "ciphers": [
            {"id": "dup", "revisionDate": negative, "name": "negative"},
            {"id": "dup", "revisionDate": null, "name": "unknown"},
            {"id": "invalid", "revisionDate": negative, "name": "negative"},
            {"id": "invalid", "revisionDate": "not-a-date", "name": "unknown"},
            {"id": "future", "revisionDate": negative, "name": "negative"},
            {"id": "future", "revisionDate": "2024-01-01T00:00:00Z", "name": "positive"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    let names: Vec<&str> = kept
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["unknown", "unknown", "positive"]);
}

#[test]
fn login_without_a_name_keeps_an_empty_name_without_leaking_the_id() {
    // `cipher()` stores "name": null; removing the key exercises the same
    // result through serde's default. openwarden's `Vault::name` maps a
    // missing name to an empty SecretString, so `.ok().map(...)` yields
    // Some("") and the placeholder arm at vault_sync.rs:294-298 is reserved
    // for a decryption failure. Pin the real outcome: no id in the name, no
    // invented placeholder.
    let mut row = cipher("nameless-secret-id", "2024-01-01T00:00:00Z");
    row.as_object_mut()
        .expect("cipher fixture must be an object")
        .remove("name");
    let vault = unlocked_vault(&[row]);
    let model = import_logins(&vault).expect("a missing name must not abort the import");
    let item = model.item("nameless-secret-id").unwrap();
    assert_eq!(item.name, "");
    assert!(!item.name.contains("nameless-secret-id"));
}

#[test]
fn same_revision_duplicate_keeps_the_first_rows_decrypted_fields() {
    // The `Ignored` audit entry alone cannot show *which* row survived: both
    // rows must carry a distinguishing field. Raw duplicates (bypassing
    // `parse_sync`) reach the `revision == old_revision` branch, which keeps
    // the already pushed item untouched (vault_sync.rs:569-585).
    let id = "rev-tie-fields";
    let revision = parse_revision(Some("2024-05-01T00:00:00Z")).unwrap();
    let mut first = encrypted_login(id, "FIRST_PASSWORD_VALUE", REAL_TOTP);
    first["revisionDate"] = serde_json::json!("2024-05-01T00:00:00Z");
    let mut second = encrypted_login(id, "SECOND_PASSWORD_VALUE", REAL_TOTP);
    second["revisionDate"] = serde_json::json!("2024-05-01T00:00:00Z");
    let vault = unlocked_vault_raw(&[first, second]);

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
    let item = model.item(id).expect("the duplicate id must survive");
    assert_eq!(item.revision_date, revision);
    assert_eq!(item.password(), Some("FIRST_PASSWORD_VALUE"));
    assert_ne!(item.password(), Some("SECOND_PASSWORD_VALUE"));
}

#[test]
fn plain_import_propagates_a_locked_vault() {
    // `import_logins` is the production seam used by auth; it must forward the
    // `Locked` error from `import_logins_with_audit` instead of returning an
    // empty vault. All three public importers share the same guard.
    let mut locked = unlocked_vault(&[encrypted_login("locked-1", REAL_PASSWORD, REAL_TOTP)]);
    locked.lock();

    assert!(matches!(import_logins(&locked), Err(SyncError::Locked)));
    assert!(matches!(
        import_logins_with_audit(&locked),
        Err(SyncError::Locked)
    ));
    assert!(matches!(folders_from(&locked), Err(SyncError::Locked)));
}

#[test]
fn non_login_ciphers_are_excluded_from_import_and_audit() {
    // `openwarden::Vault::logins()` keeps only personal, live ciphers of
    // `type: 1`. A secure note or card must not become a model login, and
    // must not produce an `ImportAudit` entry.
    let note = serde_json::json!({
        "id": "note-1",
        "type": 2,
        "name": "Recovery codes",
        "notes": "not importable",
        "revisionDate": "2024-01-01T00:00:00Z",
    });
    let card = serde_json::json!({
        "id": "card-1",
        "type": 3,
        "name": "Visa",
        "revisionDate": "2024-01-01T00:00:00Z",
    });
    // `type: 1` alone is not enough: openwarden's `StoredCipher::parse` drops
    // any cipher that is owned by an organization or soft-deleted. Both carry
    // a full login object here so only that account field can exclude them.
    let org_login = serde_json::json!({
        "id": "org-1",
        "type": 1,
        "organizationId": "org-abc",
        "name": "Org login",
        "login": { "uris": [] },
        "revisionDate": "2024-01-01T00:00:00Z",
    });
    let deleted_login = serde_json::json!({
        "id": "deleted-1",
        "type": 1,
        "deletedDate": "2024-01-02T00:00:00Z",
        "name": "Deleted login",
        "login": { "uris": [] },
        "revisionDate": "2024-01-01T00:00:00Z",
    });
    let vault = unlocked_vault(&[
        note,
        card,
        org_login,
        deleted_login,
        cipher("login-1", "2024-01-01T00:00:00Z"),
    ]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    assert_eq!(
        model.items.len(),
        1,
        "only the personal live login is imported"
    );
    assert_eq!(model.items[0].id, "login-1");
    for excluded in ["note-1", "card-1", "org-1", "deleted-1"] {
        assert!(
            model.item(excluded).is_none(),
            "{excluded} must be excluded"
        );
    }
    assert_eq!(
        audit,
        vec![ImportAudit::Added {
            id: "login-1".to_string(),
            revision: parse_revision(Some("2024-01-01T00:00:00Z")).unwrap(),
        }]
    );
}

#[test]
fn favorite_and_notes_keep_their_defaults_when_imported_from_sync() {
    // vault_sync.rs:272-277: openwarden 0.1.1's `LoginInfo` and `Vault` public
    // readers expose neither the favorite flag nor free-form notes, so even a
    // wire body that carries both must leave the model defaults untouched.
    // Pin that on the production importer and on the audit sibling, which
    // share the same `login_item` conversion.
    let mut wire_cipher = cipher("fav-notes-1", "2024-01-01T00:00:00Z");
    wire_cipher["favorite"] = serde_json::json!(true);
    wire_cipher["notes"] = serde_json::json!("WIRE-NOTES-MUST-NOT-BE-IMPORTED");
    let vault = unlocked_vault(&[wire_cipher]);

    let model = import_logins(&vault).expect("import should succeed");
    let item = model.item("fav-notes-1").expect("the login was imported");
    assert!(!item.favorite, "a wire favorite must not reach the model");
    assert!(
        item.notes.is_empty(),
        "wire notes must not reach the model: {:?}",
        item.notes
    );
    // The source vault did contain the login; only the importer dropped the
    // two unsupported fields.
    assert!(vault
        .logins()
        .iter()
        .any(|info| info.id.as_str() == "fav-notes-1"));

    let (audited, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    let audited_item = audited
        .item("fav-notes-1")
        .expect("the login was imported with audit");
    assert!(!audited_item.favorite);
    assert!(audited_item.notes.is_empty());
    assert_eq!(audit.len(), 1);
}

#[test]
fn password_and_totp_markers_reject_the_other_status_markers() {
    // Each helper is an exact-equality check against its own sentinel
    // (vault_sync.rs:34-60). Treating a sibling marker as "undecryptable
    // password/TOTP" would hide the real classification in the health audit.
    assert!(is_undecryptable_password(UNDECRYPTABLE_PASSWORD));
    assert!(is_undecryptable_totp(UNDECRYPTABLE_TOTP));
    assert!(!is_undecryptable_password(UNDECRYPTABLE_TOTP));
    assert!(!is_undecryptable_totp(UNDECRYPTABLE_PASSWORD));
    assert!(!is_undecryptable_password(UNDECRYPTABLE_URI));
    assert!(!is_undecryptable_totp(UNDECRYPTABLE_URI));
    assert!(!is_undecryptable_uri(UNDECRYPTABLE_PASSWORD));
    assert!(!is_undecryptable_uri(UNDECRYPTABLE_TOTP));

    // A marker with a suffix is a different string and must not be accepted.
    for marker in [
        UNDECRYPTABLE_PASSWORD,
        UNDECRYPTABLE_TOTP,
        UNDECRYPTABLE_URI,
    ] {
        let extended = format!("{marker}-x");
        assert!(
            !is_undecryptable_password(&extended),
            "password marker accepted {extended:?}"
        );
        assert!(
            !is_undecryptable_totp(&extended),
            "TOTP marker accepted {extended:?}"
        );
    }
}

#[test]
fn undecryptable_markers_begin_with_a_nul_literal() {
    // The NUL prefix (vault_sync.rs:28-55) is what makes a marker practically
    // impossible to collide with a real password or TOTP value. Assert the
    // literal itself, not just a helper's verdict, so dropping or changing the
    // prefix is caught even if the recognisers are updated in lockstep.
    assert_eq!(UNDECRYPTABLE_PASSWORD, "\0openwarden:undecryptable");
    assert_eq!(UNDECRYPTABLE_TOTP, "\0openwarden:totp-undecryptable");
    assert_eq!(UNDECRYPTABLE_URI, "\0openwarden:uri-undecryptable");
    assert!(UNDECRYPTABLE_PASSWORD.starts_with('\0'));
    assert!(UNDECRYPTABLE_TOTP.starts_with('\0'));
    assert!(UNDECRYPTABLE_URI.starts_with('\0'));
    // A lookalike without the leading NUL is not a marker.
    assert!(!is_undecryptable_password("openwarden:undecryptable"));
    assert!(!is_undecryptable_totp("openwarden:totp-undecryptable"));
}

#[test]
fn an_empty_uri_list_imports_as_empty_without_the_undecryptable_marker() {
    // `openwarden::Vault::uris` returns `Ok(vec![])` for a login whose `uris`
    // array is empty. The Ok arm of `login_item` (vault_sync.rs:305-319) must
    // map that to an empty model list; the marker is reserved for the Err arm.
    let vault = unlocked_vault(&[cipher("empty-uris", "2024-01-01T00:00:00Z")]);
    let model = import_logins(&vault).expect("an empty URI list must not abort");
    let item = model
        .item("empty-uris")
        .expect("the login must be imported");
    assert!(item.uris().is_empty(), "{:?}", item.uris());
    assert!(
        !item.uris().iter().any(|uri| is_undecryptable_uri(&uri.uri)),
        "an empty list is not a decryption failure"
    );

    // A sibling with one real encrypted URI proves this is the empty-list
    // branch and not a fixture that drops URIs for every login.
    let with_uri = encrypted_login("one-uri", REAL_PASSWORD, REAL_TOTP);
    let vault = unlocked_vault(&[with_uri]);
    let model = import_logins(&vault).expect("import should succeed");
    let item = model.item("one-uri").unwrap();
    assert_eq!(item.uris().len(), 1);
    assert_eq!(item.uris()[0].uri, "https://example.com");
}

#[test]
fn uri_wire_matches_zero_two_four_survive_the_sync_to_model_round_trip() {
    // The sibling test pins wire 1/3/5 and `null`. Wire 0/2/4 are the remaining
    // accepted values; `login_item` forwards openwarden's `to_wire()` verbatim
    // (vault_sync.rs:305-312), so each must reach the model unchanged and map
    // back to its own `UriMatch` through `LoginUri::match_enum()`.
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let enc = |plain: &[u8]| {
        openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string()
    };
    let mut cipher = encrypted_login("uri-wire-024", REAL_PASSWORD, REAL_TOTP);
    cipher["login"]["uris"] = serde_json::json!([
        { "uri": enc(b"https://domain.example.com"), "match": 0 },
        { "uri": enc(b"https://prefix.example.com"), "match": 2 },
        { "uri": enc(b"https://regex.example.com"), "match": 4 }
    ]);

    let vault = unlocked_vault(&[cipher]);
    let model = import_logins(&vault).expect("import should succeed");
    let uris = model
        .item("uri-wire-024")
        .expect("the login must be imported")
        .uris();
    assert_eq!(uris.len(), 3, "{uris:?}");

    let cases = [
        (
            0u8,
            "https://domain.example.com",
            openwarden::UriMatch::Domain,
        ),
        (
            2,
            "https://prefix.example.com",
            openwarden::UriMatch::StartsWith,
        ),
        (
            4,
            "https://regex.example.com",
            openwarden::UriMatch::RegularExpression,
        ),
    ];
    for (uri, (wire, expected_uri, expected_enum)) in uris.iter().zip(cases.iter()) {
        assert_eq!(uri.uri, *expected_uri);
        assert_eq!(uri.match_type, Some(*wire), "wire {wire}");
        assert_eq!(uri.match_enum(), Some(*expected_enum), "wire {wire}");
        assert_eq!(expected_enum.to_wire(), *wire);
        assert!(!is_undecryptable_uri(&uri.uri));
    }

    // The model's serde round trip keeps the wire number as well.
    let json = serde_json::to_string(uris).unwrap();
    let restored: Vec<crate::model::LoginUri> = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.as_slice(), uris);
}

#[test]
fn one_undecryptable_uri_replaces_the_whole_list_with_the_marker() {
    // vault_sync.rs:312-326: `Vault::uris` decrypts the list as one operation.
    // A single bad ciphertext makes that call fail, so `login_item` substitutes
    // one marker for the *entire* list. Valid siblings are not kept.
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let enc = |plain: &[u8]| {
        serde_json::json!(openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string())
    };
    let mut mixed = encrypted_login("uri-mixed", REAL_PASSWORD, REAL_TOTP);
    mixed["login"]["uris"] = serde_json::json!([
        { "uri": enc(b"https://valid.example.com"), "match": 1 },
        { "uri": "NEVER_IN_THE_MODEL_URI" },
        { "uri": enc(b"https://also-valid.example.com"), "match": 3 },
    ]);
    let vault = unlocked_vault(&[mixed]);
    let model = import_logins(&vault).expect("one bad URI must not abort the import");
    let uris = model.item("uri-mixed").expect("the login survives").uris();
    assert_eq!(uris.len(), 1, "the whole list is replaced, not one field");
    assert_eq!(uris[0].uri, UNDECRYPTABLE_URI);
    assert_eq!(uris[0].match_type, None);

    let rendered = format!("{model:?} {}", serde_json::to_string(&model.items).unwrap());
    for leaked in [
        "https://valid.example.com",
        "https://also-valid.example.com",
        "NEVER_IN_THE_MODEL_URI",
    ] {
        assert!(!rendered.contains(leaked), "leaked {leaked}: {rendered}");
    }

    let report = crate::health::audit(
        &model,
        crate::health::Thresholds::default(),
        i64::try_from(TOTP_AT).unwrap(),
    );
    assert!(report.items[0]
        .findings
        .contains(&crate::health::Finding::UriUninspectable));
    assert!(!report.items[0]
        .findings
        .contains(&crate::health::Finding::NoUri));
}

#[test]
fn dedup_never_lets_an_excluded_row_win_over_an_eligible_one() {
    // openwarden's StoredCipher::parse drops organization-owned and
    // soft-deleted rows (vault.rs:344-350). If such a row wins the id dedup,
    // the older eligible row is dropped too and the item vanishes entirely.
    let mut value = serde_json::json!({
        "ciphers": [
            {"id": "org", "revisionDate": "2024-01-01T00:00:00Z", "type": 1},
            {"id": "org", "revisionDate": "2024-06-01T00:00:00Z",
             "organizationId": "org-1", "type": 1},
            {"id": "deleted", "revisionDate": "2024-06-01T00:00:00Z",
             "deletedDate": "2024-07-01T00:00:00Z", "type": 1},
            {"id": "deleted", "revisionDate": "2024-01-01T00:00:00Z", "type": 1},
            {"id": "nulls", "revisionDate": "2024-01-01T00:00:00Z",
             "organizationId": null, "deletedDate": null, "type": 1},
            {"id": "nulls", "revisionDate": "2024-06-01T00:00:00Z", "type": 1},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 3, "one row per id");
    for row in kept {
        assert!(row.get("organizationId").is_none());
        assert!(row.get("deletedDate").is_none());
    }
    assert_eq!(kept[0]["id"], "org");
    assert_eq!(kept[0]["revisionDate"], "2024-01-01T00:00:00Z");
    assert_eq!(kept[1]["id"], "deleted");
    assert_eq!(kept[1]["revisionDate"], "2024-01-01T00:00:00Z");
    assert_eq!(kept[2]["id"], "nulls");
    assert_eq!(
        kept[2]["revisionDate"], "2024-06-01T00:00:00Z",
        "null organizationId/deletedDate are not exclusions"
    );

    // When every duplicate is excluded, the ordinary newest-revision rule
    // still applies (openwarden drops the single survivor as before).
    let mut all_excluded = serde_json::json!({
        "ciphers": [
            {"id": "x", "revisionDate": "2024-01-01T00:00:00Z", "organizationId": "o"},
            {"id": "x", "revisionDate": "2024-02-01T00:00:00Z", "organizationId": "o"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut all_excluded);
    let kept = all_excluded["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["revisionDate"], "2024-02-01T00:00:00Z");
}

#[test]
fn parse_sync_keeps_an_item_when_an_excluded_duplicate_is_newer() {
    // End-to-end regression: before the fix, the organization-owned row won
    // the dedup, openwarden dropped it and `vault.logins()` was empty.
    let body = br#"{
        "profile": {"id": "user-1"},
        "folders": [],
        "ciphers": [
            {"id": "c1", "type": 1, "name": "Live", "login": {"uris": []},
             "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "c1", "type": 1, "name": "Org", "organizationId": "org-1",
             "login": {"uris": []}, "revisionDate": "2024-06-01T00:00:00Z"}
        ]
    }"#;
    let sync = parse_sync(body).expect("the sync body must parse");
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    vault.apply_sync(sync).expect("apply_sync must succeed");
    let logins = vault.logins();
    let ids: Vec<&str> = logins.iter().map(|info| info.id.as_str()).collect();
    assert_eq!(ids, vec!["c1"], "the eligible row must survive");
}

#[test]
fn dedup_never_lets_a_non_login_type_win_over_a_login() {
    // openwarden's `Vault::logins()` only yields `type: 1` rows. A note/card
    // sharing an id with a login must not win the dedup, otherwise openwarden
    // drops the survivor and the item disappears entirely.
    let mut value = serde_json::json!({
        "ciphers": [
            {"id": "login", "type": 1, "revisionDate": "2024-01-01T00:00:00Z", "name": "login-row"},
            {"id": "login", "type": 2, "revisionDate": "2024-06-01T00:00:00Z", "name": "note-row"},
            {"id": "card", "type": 3, "revisionDate": "2024-06-01T00:00:00Z", "name": "card-row"},
            {"id": "card", "type": 1, "revisionDate": "2024-01-01T00:00:00Z", "name": "login-row"},
            {"id": "untyped", "revisionDate": "2024-06-01T00:00:00Z", "name": "no-type-row"},
            {"id": "untyped", "type": 1, "revisionDate": "2024-01-01T00:00:00Z", "name": "login-row"},
            {"id": "all-notes", "type": 2, "revisionDate": "2024-01-01T00:00:00Z", "name": "first"},
            {"id": "all-notes", "type": 3, "revisionDate": "2024-02-01T00:00:00Z", "name": "second"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 4, "one row per id");
    for (index, id) in ["login", "card", "untyped", "all-notes"].iter().enumerate() {
        assert_eq!(kept[index]["id"], serde_json::json!(id));
    }
    // The eligible type-1 row wins regardless of its older revision, even when
    // the excluded duplicate has a newer one.
    for row in kept.iter().take(3) {
        assert_eq!(row["name"], "login-row");
        assert_eq!(row["revisionDate"], "2024-01-01T00:00:00Z");
    }
    // With every duplicate excluded the ordinary newest-revision rule applies.
    assert_eq!(kept[3]["name"], "second");
    assert_eq!(kept[3]["revisionDate"], "2024-02-01T00:00:00Z");
}

#[test]
fn parse_sync_keeps_an_item_when_a_non_login_duplicate_is_newer() {
    // End-to-end regression: a secure note with the same id and a newer
    // revision used to win the dedup, get dropped by openwarden and leave
    // `vault.logins()` empty.
    let body = br#"{
        "profile": {"id": "user-1"},
        "folders": [],
        "ciphers": [
            {"id": "c1", "type": 1, "name": "Live", "login": {"uris": []},
             "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "c1", "type": 2, "name": "Note", "notes": "x",
             "revisionDate": "2024-06-01T00:00:00Z"}
        ]
    }"#;
    let sync = parse_sync(body).expect("the sync body must parse");
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    vault.apply_sync(sync).expect("apply_sync must succeed");
    let logins = vault.logins();
    let ids: Vec<&str> = logins.iter().map(|info| info.id.as_str()).collect();
    assert_eq!(ids, vec!["c1"], "the type-1 row must survive");
}

#[test]
fn duplicate_folder_ids_are_collapsed_before_apply_sync() {
    let mut value = serde_json::json!({
        "folders": [
            {"id": "f1", "name": "first"},
            {"id": "f1", "name": "second"},
            {"name": "no-id"},
            {"id": 42, "name": "numeric-id"},
            {"id": "f2", "name": "other"},
            {"id": "f2", "name": "again"},
        ]
    });
    super::dedup_folders_by_id(&mut value);
    let kept = value["folders"].as_array().unwrap();
    let names: Vec<&str> = kept
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["first", "no-id", "numeric-id", "other"]);
    // Compare the *value* before and after: asserting that the function's
    // `()` return equals `()` would be true for any behaviour, including one
    // that scrambled the empty list.
    let mut empty = serde_json::json!({"folders": []});
    let before = empty.clone();
    super::dedup_folders_by_id(&mut empty);
    assert_eq!(empty, before, "an empty folder list is a no-op");
    assert!(
        empty["folders"]
            .as_array()
            .expect("folders stays an array")
            .is_empty(),
        "the empty list must still be empty"
    );
}

#[test]
fn parse_sync_removes_duplicate_folder_ids_end_to_end() {
    // `Vault::folder_name(id)` reads the first matching folder, so a duplicate
    // id would otherwise shadow the later row and yield duplicate model ids.
    let body = br#"{
        "profile": {"id": "user-1"},
        "folders": [
            {"id": "f1", "name": "first"},
            {"id": "f1", "name": "second"},
            {"id": "f2", "name": "other"}
        ],
        "ciphers": []
    }"#;
    let sync = parse_sync(body).expect("the sync body must parse");
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    vault.apply_sync(sync).expect("apply_sync must succeed");
    let folders = vault.folders();
    let mut ids: Vec<&str> = folders.iter().map(|id| id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec!["f1", "f2"]);
}

#[test]
fn pascal_case_duplicate_folder_ids_are_removed_before_apply_sync() {
    // A PascalCase wire body can repeat a folder id. `parse_sync` must
    // normalize `Folders`/`Id`/`Name` first, then `dedup_folders_by_id`
    // collapses the duplicate before `apply_sync` builds the vault: a
    // leftover row would appear twice in `folders()` and shadow the first
    // name in `folder_name(id)`.
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let enc = |plain: &[u8]| {
        openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string()
    };
    let mut body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [
            { "id": "f-dup", "name": enc(b"First") },
            { "id": "f-dup", "name": enc(b"Second") },
            { "id": "f-other", "name": enc(b"Other") },
        ],
        "ciphers": [],
    });
    pascalize(&mut body);
    let sync = parse_sync(body.to_string().as_bytes())
        .expect("PascalCase duplicate folder ids must parse");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let user_key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let mut vault = openwarden::Vault::open(user_key, state);
    vault.apply_sync(sync).expect("apply_sync must succeed");

    let folder_ids = vault.folders();
    let mut ids: Vec<&str> = folder_ids.iter().map(|id| id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec!["f-dup", "f-other"], "one folder per id");

    let folders = folders_from(&vault).expect("folders must be readable");
    assert_eq!(folders.len(), 2);
    let dup = folders
        .iter()
        .find(|folder| folder.id == "f-dup")
        .expect("the first duplicate row must survive");
    assert_eq!(dup.name, "First", "the first row wins the id");
}

#[test]
fn dedup_leaves_non_object_cipher_and_folder_rows_untouched() {
    // `Value::get("id")` returns None for a non-object, so dedup treats such
    // elements like rows without a string id and leaves them in place. This
    // pins the current split of responsibility: dedup collapses only rows
    // with a real string id; openwarden's parser decides whether the rest
    // of the body is valid.
    let mut value = serde_json::json!({
        "ciphers": [
            7,
            "cipher-as-string",
            null,
            [1, 2],
            {"id": "dup", "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "dup", "revisionDate": "2024-02-01T00:00:00Z"},
        ],
        "folders": [
            9,
            "folder-as-string",
            null,
            [3, 4],
            {"id": "f1", "name": "first"},
            {"id": "f1", "name": "second"},
        ],
    });
    super::dedup_ciphers_by_revision(&mut value);
    super::dedup_folders_by_id(&mut value);

    let ciphers = value["ciphers"].as_array().expect("ciphers is an array");
    assert_eq!(
        ciphers.len(),
        5,
        "only the older duplicate cipher is dropped"
    );
    assert_eq!(ciphers[0], serde_json::json!(7));
    assert_eq!(ciphers[1], serde_json::json!("cipher-as-string"));
    assert_eq!(ciphers[2], serde_json::json!(null));
    assert_eq!(ciphers[3], serde_json::json!([1, 2]));
    assert_eq!(ciphers[4]["id"], "dup");
    assert_eq!(ciphers[4]["revisionDate"], "2024-02-01T00:00:00Z");

    let folders = value["folders"].as_array().expect("folders is an array");
    assert_eq!(folders.len(), 5, "only the duplicate folder id is dropped");
    assert_eq!(folders[0], serde_json::json!(9));
    assert_eq!(folders[1], serde_json::json!("folder-as-string"));
    assert_eq!(folders[2], serde_json::json!(null));
    assert_eq!(folders[3], serde_json::json!([3, 4]));
    assert_eq!(folders[4]["name"], "first");
}

#[test]
fn clipped_revision_does_not_overwrite_the_accepted_items_encrypted_fields() {
    // The `Clipped` branch only records the decision and `continue`s
    // (vault_sync.rs:642-649), so the already accepted item keeps its decrypted
    // fields. Raw duplicates (bypassing `parse_sync`) are required to reach the
    // branch; give every secret-bearing field a distinct ciphertext so a
    // stray replacement would be observable.
    let id = "clipped-fields";
    let kept = parse_revision(Some("2024-05-01T00:00:00Z")).unwrap();
    let dropped = parse_revision(Some("2024-04-01T00:00:00Z")).unwrap();
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).unwrap();
    let enc = |plain: &[u8]| {
        serde_json::json!(openwarden::EncString::encrypt(&key, plain)
            .expect("field should encrypt")
            .to_string())
    };

    let mut accepted = encrypted_login(id, "KEPT_PASSWORD_VALUE", REAL_TOTP);
    accepted["revisionDate"] = serde_json::json!("2024-05-01T00:00:00Z");

    let mut regressed = encrypted_login(id, "CLIPPED_PASSWORD_VALUE", "CLIPPED_TOTP_VALUE");
    regressed["revisionDate"] = serde_json::json!("2024-04-01T00:00:00Z");
    regressed["name"] = enc(b"Clipped Name");
    regressed["login"]["username"] = enc(b"clipped@example.com");
    regressed["login"]["uris"] =
        serde_json::json!([{ "uri": enc(b"https://clipped.example.com") }]);

    let vault = unlocked_vault_raw(&[accepted, regressed]);
    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");

    assert_eq!(model.items.len(), 1);
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
    let item = model.item(id).expect("the accepted item must survive");
    assert_eq!(item.revision_date, kept);
    assert_eq!(item.name, "Example Login");
    assert_eq!(item.login().unwrap().0, "alice@example.com");
    assert_eq!(item.password(), Some("KEPT_PASSWORD_VALUE"));
    assert_eq!(item.totp_secret(), Some(REAL_TOTP));
    assert_eq!(item.uris()[0].uri, "https://example.com");
}

#[test]
fn pascal_case_body_with_excluded_newer_duplicates_keeps_eligible_rows() {
    // A Vaultwarden body can be PascalCase *and* carry excluded duplicates with
    // a newer revision. `normalize_sync_keys` must fold `OrganizationId` /
    // `DeletedDate` to camelCase before `dedup_ciphers_by_revision` checks
    // exclusions; otherwise the excluded row wins, openwarden drops it and the
    // item disappears entirely (vault_sync.rs:151-176, 194-258).
    let mut org_old = encrypted_login("pascal-org", "KEPT_ORG_PASSWORD", REAL_TOTP);
    org_old["revisionDate"] = serde_json::json!("2024-01-01T00:00:00Z");
    let mut org_new = encrypted_login("pascal-org", "ORG_PASSWORD", REAL_TOTP);
    org_new["revisionDate"] = serde_json::json!("2024-06-01T00:00:00Z");
    org_new["organizationId"] = serde_json::json!("org-1");

    let mut deleted_new = encrypted_login("pascal-deleted", "DELETED_PASSWORD", REAL_TOTP);
    deleted_new["revisionDate"] = serde_json::json!("2024-06-01T00:00:00Z");
    deleted_new["deletedDate"] = serde_json::json!("2024-07-01T00:00:00Z");
    let mut deleted_old = encrypted_login("pascal-deleted", "KEPT_DELETED_PASSWORD", REAL_TOTP);
    deleted_old["revisionDate"] = serde_json::json!("2024-01-01T00:00:00Z");

    let mut body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [],
        "ciphers": [org_old, org_new, deleted_new, deleted_old],
    });
    pascalize(&mut body);
    let vault = vault_from_body(body.to_string().as_bytes());
    let (model, audit) = import_logins_with_audit(&vault)
        .expect("PascalCase rows with excluded duplicates must import");

    assert_eq!(model.items.len(), 2, "one eligible row per id survives");
    let kept_revision = parse_revision(Some("2024-01-01T00:00:00Z")).unwrap();
    let org = model.item("pascal-org").expect("eligible row must survive");
    assert_eq!(org.revision_date, kept_revision);
    assert_eq!(org.password(), Some("KEPT_ORG_PASSWORD"));
    let deleted = model
        .item("pascal-deleted")
        .expect("eligible row must survive");
    assert_eq!(deleted.revision_date, kept_revision);
    assert_eq!(deleted.password(), Some("KEPT_DELETED_PASSWORD"));

    assert_eq!(audit.len(), 2, "pre-sync dedup leaves two Added decisions");
    for entry in &audit {
        assert!(matches!(entry, ImportAudit::Added { .. }), "{entry:?}");
    }
}

#[test]
fn revision_dates_accept_zero_utc_offsets_in_both_signs() {
    // RFC 3339 allows both `+00:00` and `-00:00`. The sign is applied to a zero
    // magnitude, so both spellings must produce the exact same epoch value as
    // `Z` (vault_sync.rs:474-498).
    let utc = parse_revision(Some("2023-11-14T22:13:20Z")).unwrap();
    assert_eq!(parse_revision(Some("2023-11-14T22:13:20+00:00")), Some(utc));
    assert_eq!(parse_revision(Some("2023-11-14T22:13:20-00:00")), Some(utc));
    assert_eq!(parse_revision(Some("1970-01-01T00:00:00+00:00")), Some(0));
    assert_eq!(parse_revision(Some("1970-01-01T00:00:00-00:00")), Some(0));
    // A fractional second in front of a zero offset is still the same instant.
    assert_eq!(
        parse_revision(Some("2023-11-14T22:13:20.999-00:00")),
        Some(utc)
    );
}

#[test]
fn updated_audit_records_zero_old_revision_for_an_undated_first_row() {
    // A first row whose `revisionDate` is missing gets UNKNOWN_REVISION (0).
    // A later duplicate with a real revision must therefore emit
    // `Updated { old_revision: 0, .. }` (vault_sync.rs:634-671): the audit
    // reports the sentinel actually stored for the replaced row, not an
    // invented timestamp. The `unwrap_or(UNKNOWN_REVISION)` lookup fallback on
    // that branch stays unreachable because the Added arm always inserts the
    // id into `revisions` first; this test pins the observable zero path.
    let id = "unknown-old-revision";
    let mut undated = cipher(id, "2024-01-01T00:00:00Z");
    undated
        .as_object_mut()
        .expect("cipher fixture must be an object")
        .remove("revisionDate");
    let new_revision = parse_revision(Some("2024-02-01T00:00:00Z")).unwrap();
    let vault = unlocked_vault_raw(&[undated, cipher(id, "2024-02-01T00:00:00Z")]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].revision_date, new_revision);
    assert_eq!(crate::model::UNKNOWN_REVISION, 0);
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: id.to_string(),
                revision: crate::model::UNKNOWN_REVISION,
            },
            ImportAudit::Updated {
                id: id.to_string(),
                old_revision: crate::model::UNKNOWN_REVISION,
                new_revision,
            },
        ]
    );
}

#[test]
fn clipped_audit_records_zero_old_revision_for_an_undated_first_row() {
    // Mirror of the `Updated` zero case: an undated first row stores
    // UNKNOWN_REVISION (0), and a pre-epoch duplicate (negative epoch) is
    // clipped against it. The audit must report old_revision: 0 rather than a
    // fabricated timestamp.
    let id = "unknown-old-revision-clipped";
    let negative = parse_revision(Some("1969-12-31T23:59:59Z")).unwrap();
    assert!(negative < crate::model::UNKNOWN_REVISION);
    let mut undated = cipher(id, "2024-01-01T00:00:00Z");
    undated
        .as_object_mut()
        .expect("cipher fixture must be an object")
        .remove("revisionDate");
    let mut regression = cipher(id, "2024-01-01T00:00:00Z");
    regression["revisionDate"] = serde_json::json!("1969-12-31T23:59:59Z");
    let vault = unlocked_vault_raw(&[undated, regression]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].revision_date, crate::model::UNKNOWN_REVISION);
    assert_eq!(crate::model::UNKNOWN_REVISION, 0);
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: id.to_string(),
                revision: crate::model::UNKNOWN_REVISION,
            },
            ImportAudit::Clipped {
                id: id.to_string(),
                old_revision: crate::model::UNKNOWN_REVISION,
                new_revision: negative,
            },
        ]
    );
}

#[test]
fn ignored_audit_records_zero_revision_when_both_duplicates_are_undated() {
    // `Ignored` has no separate `old_revision`: its `revision` is the accepted
    // row's revision. Two undated duplicates both map to UNKNOWN_REVISION (0),
    // so the ignored decision must pin 0 as well.
    let id = "unknown-revision-ignored";
    let mut first = cipher(id, "2024-01-01T00:00:00Z");
    first
        .as_object_mut()
        .expect("cipher fixture must be an object")
        .remove("revisionDate");
    let mut second = cipher(id, "2024-01-01T00:00:00Z");
    second
        .as_object_mut()
        .expect("cipher fixture must be an object")
        .remove("revisionDate");
    let vault = unlocked_vault_raw(&[first, second]);

    let (model, audit) = import_logins_with_audit(&vault).expect("import should succeed");
    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].revision_date, crate::model::UNKNOWN_REVISION);
    assert_eq!(crate::model::UNKNOWN_REVISION, 0);
    assert_eq!(
        audit,
        vec![
            ImportAudit::Added {
                id: id.to_string(),
                revision: crate::model::UNKNOWN_REVISION,
            },
            ImportAudit::Ignored {
                id: id.to_string(),
                revision: crate::model::UNKNOWN_REVISION,
            },
        ]
    );
}

#[test]
fn dedup_ties_between_excluded_rows_keep_the_first_row() {
    // When both duplicates are excluded (organization-owned / soft-deleted),
    // the ordinary newest-revision rule still applies: a higher revision wins
    // and an equal revision keeps the first row (vault_sync.rs:215-231).
    // openwarden drops the single survivor either way, but the choice must
    // stay deterministic. Distinct `name` values make the winner observable.
    let mut value = serde_json::json!({
        "ciphers": [
            {"id": "org", "revisionDate": "2024-01-01T00:00:00Z",
             "organizationId": "org-1", "name": "first"},
            {"id": "org", "revisionDate": "2024-01-01T00:00:00Z",
             "organizationId": "org-2", "name": "second"},
            {"id": "deleted", "revisionDate": "2024-01-01T00:00:00Z",
             "deletedDate": "2024-02-01T00:00:00Z", "name": "first"},
            {"id": "deleted", "revisionDate": "2024-01-01T00:00:00Z",
             "deletedDate": "2024-03-01T00:00:00Z", "name": "second"},
            // Missing and unparsable dates both become UNKNOWN_REVISION (0),
            // so two excluded rows tying there must also keep the first.
            {"id": "unknown", "organizationId": "org-3", "name": "first"},
            {"id": "unknown", "revisionDate": "not-a-date",
             "organizationId": "org-4", "name": "second"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 3, "one row per id");
    for (index, id) in ["org", "deleted", "unknown"].iter().enumerate() {
        assert_eq!(kept[index]["id"], serde_json::json!(id));
        assert_eq!(kept[index]["name"], "first", "first excluded row wins {id}");
    }

    // Control: with the same excluded status but a strictly newer revision,
    // the newer excluded row still wins rather than the tie rule applying.
    let mut newer = serde_json::json!({
        "ciphers": [
            {"id": "x", "revisionDate": "2024-01-01T00:00:00Z",
             "organizationId": "a", "name": "old"},
            {"id": "x", "revisionDate": "2024-02-01T00:00:00Z",
             "organizationId": "b", "name": "new"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut newer);
    let kept = newer["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["name"], "new");
}

#[test]
fn non_numeric_cipher_types_are_excluded_from_dedup() {
    use serde_json::json;

    // `cipher_row_is_excluded` (vault_sync.rs:260-268) recognizes a login only
    // when `type` is the integer 1 (`as_u64() == Some(1)`). openwarden's wire
    // format has no serde default for `type`, so any other JSON tag fails its
    // deserialization: a string, bool, null or fractional number is never a
    // login and must not win an id dedup over an eligible row.
    let bad_types = [
        ("string", json!("1")),
        ("bool", json!(true)),
        ("null", json!(null)),
        ("decimal", json!(1.0)),
    ];
    for (name, bad_type) in &bad_types {
        let mut row = json!({
            "id": "dup",
            "revisionDate": "2024-06-01T00:00:00Z",
        });
        row["type"] = bad_type.clone();
        assert!(
            super::cipher_row_is_excluded(&row),
            "{name} type must be excluded: {row}"
        );
    }
    assert!(!super::cipher_row_is_excluded(&json!({
        "id": "login",
        "type": 1,
    })));
    // A missing type is excluded by the same `is_some_and` guard.
    assert!(super::cipher_row_is_excluded(&json!({"id": "untyped"})));
    // Exclusion is independent of the organization/deleted-date rules.
    assert!(super::cipher_row_is_excluded(&json!({
        "id": "org",
        "type": "1",
        "organizationId": null,
    })));

    // End-to-end through the dedup: every malformed type loses to an older
    // type-1 row with the same id, so openwarden still sees a login for it.
    for (name, bad_type) in bad_types {
        let mut malformed = json!({
            "id": "dup",
            "revisionDate": "2024-06-01T00:00:00Z",
        });
        malformed["type"] = bad_type;
        let mut value = json!({
            "ciphers": [
                {"id": "dup", "type": 1, "revisionDate": "2024-01-01T00:00:00Z",
                 "name": "login-row"},
                malformed,
            ]
        });
        super::dedup_ciphers_by_revision(&mut value);
        let kept = value["ciphers"].as_array().unwrap();
        assert_eq!(kept.len(), 1, "{name}");
        assert_eq!(kept[0]["name"], "login-row", "{name}");
        assert_eq!(kept[0]["type"], json!(1), "{name}");
    }
}

#[test]
fn dangling_folder_id_is_kept_verbatim_without_creating_a_folder() {
    // openwarden's `CipherWire` stores the raw `folderId` as an opaque
    // `FolderId` (openwarden vault.rs:298, 367) and `login_item` copies it into
    // the model (vault_sync.rs, `login_item`). Neither layer checks it against the
    // folder list, so a cipher pointing at a non-existent id still imports:
    // the id remains on the item and no folder is fabricated. See the module
    // docs for the recorded constraint.
    let key = openwarden::SymmetricKey::from_bytes(&[0u8; 64]).unwrap();
    let folder_name = openwarden::EncString::encrypt(&key, b"Work")
        .unwrap()
        .to_string();
    let mut orphan = cipher("orphan", "2024-01-01T00:00:00Z");
    orphan["folderId"] = serde_json::json!("ghost-folder");
    let vault = vault_with_folders(
        &[serde_json::json!({"id": "f1", "name": folder_name})],
        &[orphan],
    );

    let model = import_logins(&vault).expect("a dangling folder id must not abort the import");
    assert_eq!(model.items.len(), 1);
    assert_eq!(model.items[0].id, "orphan");
    assert_eq!(model.items[0].folder_id.as_deref(), Some("ghost-folder"));
    assert_eq!(model.folders.len(), 1, "no folder is invented for the id");
    assert_eq!(model.folders[0].id, "f1");
    assert_eq!(model.folder_name("ghost-folder"), None);
    // The dangling id is still usable by the raw-id filter, which does not
    // consult `Vault::folders` either.
    assert!(crate::model::Filter::Folder("ghost-folder".into()).accepts(&model.items[0]));
}

#[test]
fn revision_dates_accept_the_four_digit_year_boundaries() {
    // `parse_revision` reads exactly four year digits (vault_sync.rs,
    // `parse_revision`) and applies checked arithmetic, so 0000 and 9999 are
    // the accepted extremes.
    let min = parse_revision(Some("0000-01-01T00:00:00Z")).expect("year 0000 must parse");
    let max = parse_revision(Some("9999-12-31T23:59:59Z")).expect("year 9999 must parse");
    assert!(min < 0, "{min}");
    assert!(max > 0, "{max}");
    assert!(max > min);

    // Both boundary years keep their full calendar range: the first and last
    // instants of each year are distinct and ordered.
    let min_end = parse_revision(Some("0000-12-31T23:59:59Z")).unwrap();
    let max_start = parse_revision(Some("9999-01-01T00:00:00Z")).unwrap();
    assert!(min_end > min);
    assert!(max > max_start);
    // Year 0 is a leap year in the proleptic Gregorian calendar used by
    // `days_from_civil`; year 9999 is not.
    let year_one = parse_revision(Some("0001-01-01T00:00:00Z")).unwrap();
    assert_eq!(year_one - min, 366 * 86_400);
    let year_9998_end = parse_revision(Some("9998-12-31T23:59:59Z")).unwrap();
    assert_eq!(max - year_9998_end, 365 * 86_400);

    // The largest numeric offset still subtracts without overflowing at the
    // upper boundary, and the negative one still adds at the lower boundary.
    assert_eq!(
        max - parse_revision(Some("9999-12-31T23:59:59+23:59")).unwrap(),
        86_340
    );
    assert_eq!(
        parse_revision(Some("0000-01-01T00:00:00-23:59")).unwrap() - min,
        86_340
    );

    // A fifth digit or an explicit sign cannot fit the fixed four-digit field
    // and is rejected rather than silently truncated.
    for value in [
        "10000-01-01T00:00:00Z",
        "09999-12-31T23:59:59Z",
        "-001-01-01T00:00:00Z",
        "+9999-12-31T23:59:59Z",
    ] {
        assert_eq!(parse_revision(Some(value)), None, "{value}");
    }
}

#[test]
fn same_revision_tie_between_excluded_and_eligible_rows_keeps_eligible() {
    // `dedup_ciphers_by_revision` (vault_sync.rs:224-240) compares the exclusion
    // flag *before* the revision: an eligible personal login wins even when the
    // excluded row has the same revision, and regardless of row order. A tie
    // between two eligible rows still keeps the first one (see the sibling
    // `dedup_counts_missing_and_invalid_revisions_as_unknown_and_keeps_first_on_ties`).
    const REVISION: &str = "2024-01-01T00:00:00Z";
    let mut value = serde_json::json!({
        "ciphers": [
            // Excluded first, eligible second.
            {"id": "org", "revisionDate": REVISION, "type": 1,
             "organizationId": "org-1", "name": "Excluded"},
            {"id": "org", "revisionDate": REVISION, "type": 1, "name": "Eligible"},
            // Eligible first, excluded second.
            {"id": "deleted", "revisionDate": REVISION, "type": 1, "name": "Eligible"},
            {"id": "deleted", "revisionDate": REVISION, "type": 1,
             "deletedDate": "2024-02-01T00:00:00Z", "name": "Excluded"},
            // A non-login type is excluded by the same classifier.
            {"id": "note", "revisionDate": REVISION, "type": 2, "name": "Excluded"},
            {"id": "note", "revisionDate": REVISION, "type": 1, "name": "Eligible"},
            // Missing/unparsable dates both become UNKNOWN_REVISION (0): the
            // exclusion rule still decides the tie, not row order. Both rows
            // must be type 1 so only organizationId separates them.
            {"id": "unknown", "type": 1, "organizationId": "org-2", "name": "Excluded"},
            {"id": "unknown", "type": 1, "revisionDate": "not-a-date", "name": "Eligible"},
        ]
    });
    super::dedup_ciphers_by_revision(&mut value);
    let kept = value["ciphers"].as_array().unwrap();
    assert_eq!(kept.len(), 4, "one row per id");
    for (index, id) in ["org", "deleted", "note", "unknown"].iter().enumerate() {
        assert_eq!(kept[index]["id"], serde_json::json!(*id));
        assert_eq!(kept[index]["name"], "Eligible", "id {id}");
        assert!(kept[index].get("organizationId").is_none(), "id {id}");
        assert!(kept[index].get("deletedDate").is_none(), "id {id}");
        assert_eq!(kept[index]["type"], serde_json::json!(1), "id {id}");
    }
}

#[test]
fn parse_sync_keeps_the_eligible_row_when_it_ties_with_an_excluded_row() {
    // End-to-end: the excluded row is listed *first* and has the same revision,
    // so only the exclusion-aware tie-break can keep the login alive. Without
    // it openwarden would drop the organization-owned survivor and logins()
    // would be empty.
    let body = br#"{
        "profile": {"id": "user-1"},
        "folders": [],
        "ciphers": [
            {"id": "tie", "type": 1, "name": "Org", "organizationId": "org-1",
             "login": {"uris": []}, "revisionDate": "2024-01-01T00:00:00Z"},
            {"id": "tie", "type": 1, "name": "Live",
             "login": {"uris": []}, "revisionDate": "2024-01-01T00:00:00Z"}
        ]
    }"#;
    let sync = parse_sync(body).expect("the sync body must parse");
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    vault.apply_sync(sync).expect("apply_sync must succeed");
    let logins = vault.logins();
    let ids: Vec<&str> = logins.iter().map(|info| info.id.as_str()).collect();
    assert_eq!(ids, vec!["tie"], "the eligible row must win the tie");
}

#[test]
fn non_array_ciphers_and_folders_are_classified_as_invalid_login_end_to_end() {
    use std::error::Error as _;

    // `dedup_ciphers_by_revision` / `dedup_folders_by_id` are no-ops for a
    // non-array value (vault_sync.rs:203-209, 285-289). The classification is
    // left to openwarden's `SyncWire` deserializer: every wrong JSON shape must
    // land in `InvalidLoginCause` with a non-empty typed source, never a panic
    // or a success with silently dropped data. A *missing* key is different:
    // serde's `#[serde(default)]` turns it into an empty vector.
    let wrong_shapes = [
        serde_json::json!({"0": {"id": "row"}}),
        serde_json::json!("text"),
        serde_json::json!(42),
        serde_json::json!(null),
    ];
    for field in ["ciphers", "folders"] {
        for wrong in wrong_shapes.iter() {
            let mut document = serde_json::json!({
                "profile": {"id": "user-1"},
                "ciphers": [],
                "folders": [],
            });
            document[field] = wrong.clone();
            let bytes = serde_json::to_vec(&document).unwrap();
            let error = parse_sync(&bytes).unwrap_err();
            assert!(
                matches!(&error, SyncError::InvalidLoginCause(_, _)),
                "{field}={wrong}: {error:?}"
            );
            assert_eq!(error.message(), "ログイン項目を読み取れませんでした");
            let source = error
                .source()
                .expect("a wrong array shape must keep a typed cause")
                .to_string();
            assert!(!source.is_empty(), "{field}={wrong}");
            assert!(
                !source.contains("ログイン項目を読み取れませんでした"),
                "{field}={wrong}: the family message must stay in message()"
            );
        }
    }

    // Controls: arrays still parse, and both omitted keys default to empty.
    let arrays = parse_sync(br#"{"profile":{"id":"user-1"},"ciphers":[],"folders":[]}"#)
        .expect("array-valued keys must parse");
    assert_eq!(arrays.user_id(), "user-1");
    let omitted = parse_sync(br#"{"profile":{"id":"user-1"}}"#)
        .expect("omitted keys are defaulted by openwarden");
    assert_eq!(omitted.user_id(), "user-1");
}
