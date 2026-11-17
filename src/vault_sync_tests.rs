#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::vault_sync::*;

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
    // Only the date part is used: 2023-11-14 00:00:00Z.
    assert_eq!(
        parse_revision(Some("2023-11-14T22:13:20Z")),
        Some(1_699_920_000)
    );
    assert_eq!(parse_revision(Some("not-a-date")), None);
    assert_eq!(parse_revision(None), None);
    // Out-of-range month/day and too-short strings are rejected.
    assert_eq!(parse_revision(Some("2023-13-01T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2023-01-32T00:00:00Z")), None);
    assert_eq!(parse_revision(Some("2023-1-01")), None);
}

#[test]
fn days_from_civil_matches_known_dates() {
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(days_from_civil(2000, 2, 29), 11_016);
    assert_eq!(days_from_civil(2023, 11, 14), 19_675);
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
}
