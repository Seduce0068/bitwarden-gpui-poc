#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::model::*;
use zeroize::Zeroizing;

use super::unicode_normalize::{comparison_key, nfkd};

#[test]
fn debug_never_reveals_item_secrets() {
    let item = VaultItem::new(
        "1",
        "Sample",
        ItemData::Login {
            username: "alice".into(),
            password: Zeroizing::new("super-secret-pw".into()),
            totp: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
            uris: vec![],
        },
    );
    let debug = format!("{item:?}");
    assert!(debug.contains("Sample"));
    assert!(!debug.contains("super-secret-pw"), "{debug}");
    assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "{debug}");

    let card = VaultItem::new(
        "2",
        "Card",
        ItemData::Card(CardData {
            number: "4111111111111234".into(),
            code: "987".into(),
            ..CardData::default()
        }),
    );
    let debug = format!("{card:?}");
    assert!(!debug.contains("4111111111111234"), "{debug}");
    assert!(!debug.contains("987"), "{debug}");

    let ssh = VaultItem::new(
        "3",
        "Key",
        ItemData::SshKey(SshKeyData {
            private_key: "PRIVATE-KEY-MATERIAL".into(),
            ..SshKeyData::default()
        }),
    );
    let debug = format!("{ssh:?}");
    assert!(!debug.contains("PRIVATE-KEY-MATERIAL"), "{debug}");
}

#[test]
fn mask_uri_keeps_scheme_host_and_port_only() {
    assert_eq!(
        mask_uri("https://example.com/login?token=secret"),
        "https://example.com"
    );
    assert_eq!(
        mask_uri("http://user:pass@example.com:8080/a"),
        "http://example.com:8080"
    );
    assert_eq!(mask_uri("not a url"), "(不正な URI)");
}

#[test]
fn mask_uri_handles_ipv6_and_credentials() {
    assert_eq!(mask_uri("https://[::1]:8443/path"), "https://[::1]:8443");
    assert_eq!(
        mask_uri("https://user:token@[2001:db8::1]/secret"),
        "https://[2001:db8::1]"
    );
    assert_eq!(mask_uri("ftp://example.com/x"), "ftp://example.com");
}

fn login(id: &str, name: &str, username: &str, password: &str, uri: &str) -> VaultItem {
    VaultItem::new(
        id,
        name,
        ItemData::Login {
            username: username.to_string(),
            password: Zeroizing::new(password.to_string()),
            totp: Zeroizing::new(String::new()),
            uris: vec![LoginUri::new(uri)],
        },
    )
}

fn sample() -> Vault {
    let mut vault = Vault::new();
    vault.folders.push(Folder {
        id: "f1".into(),
        name: "仕事".into(),
    });
    let mut github = login(
        "1",
        "GitHub",
        "alice",
        "hunter2",
        "https://github.com/login",
    );
    github.folder_id = Some("f1".into());
    github.favorite = true;
    github.revision_date = 100;
    let mut mail = login(
        "2",
        "Mail",
        "alice@example.com",
        "s3cret",
        "https://mail.example.com",
    );
    mail.revision_date = 200;
    let note = VaultItem::new(
        "3",
        "Wi-Fi",
        ItemData::SecureNote {
            text: "guest / guest".into(),
        },
    );
    vault.items = vec![github, mail, note];
    vault
}

#[test]
fn kind_round_trips_through_wire_numbers() {
    for kind in [
        ItemKind::Login,
        ItemKind::SecureNote,
        ItemKind::Card,
        ItemKind::Identity,
        ItemKind::SshKey,
    ] {
        assert_eq!(ItemKind::from_wire(kind.to_wire()), Some(kind));
    }
    assert_eq!(ItemKind::from_wire(0), None);
    assert_eq!(ItemKind::from_wire(6), None);
}

#[test]
fn filter_and_query_narrow_the_view() {
    let vault = sample();
    assert_eq!(vault.view(&Filter::All, "", SortKey::NameAsc).len(), 3);
    assert_eq!(
        vault.view(&Filter::Favorites, "", SortKey::NameAsc).len(),
        1
    );
    assert_eq!(
        vault
            .view(&Filter::Kind(ItemKind::Login), "", SortKey::NameAsc)
            .len(),
        2
    );
    assert_eq!(
        vault
            .view(&Filter::Folder("f1".into()), "", SortKey::NameAsc)
            .len(),
        1
    );
    assert_eq!(vault.view(&Filter::NoFolder, "", SortKey::NameAsc).len(), 2);

    let hits = vault.view(&Filter::All, "ALICE", SortKey::NameAsc);
    assert_eq!(hits.len(), 2);
    let by_uri = vault.view(&Filter::All, "example.com", SortKey::NameAsc);
    assert_eq!(by_uri.len(), 1);
    assert_eq!(by_uri[0].id, "2");
}

#[test]
fn sorting_is_stable_and_deterministic() {
    let vault = sample();
    let asc: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(asc, vec!["1", "2", "3"]);
    let desc: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::NameDesc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(desc, vec!["3", "2", "1"]);
    let recent: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::RecentlyModified)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(recent, vec!["2", "1", "3"]);
}

#[test]
fn page_matching_uses_bitwarden_rules() {
    let vault = sample();
    let opts = openwarden::MatchOptions::default();
    let hits = vault.matches_page("https://github.com/settings", &opts);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "1");
    // A lookalike domain must not match.
    assert!(vault
        .matches_page("https://github.com.evil.net/", &opts)
        .is_empty());
    // http page vs https login, strict scheme: no match.
    assert!(vault.matches_page("http://github.com/", &opts).is_empty());
}

#[test]
fn debug_masks_identity_and_uri_details() {
    let identity = VaultItem::new(
        "1",
        "Person",
        ItemData::Identity(IdentityData {
            first_name: "Alice".into(),
            last_name: "Smith".into(),
            email: "alice@example.com".into(),
            phone: "090-1234-5678".into(),
            address: "1 Main St".into(),
            company: "Acme".into(),
        }),
    );
    let debug = format!("{identity:?}");
    for secret in [
        "Alice",
        "Smith",
        "alice@example.com",
        "090-1234-5678",
        "1 Main St",
    ] {
        assert!(!debug.contains(secret), "{debug}");
    }
    assert!(debug.contains("Acme"), "{debug}");

    let login = VaultItem::new(
        "2",
        "Site",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![LoginUri::new("https://user:token@example.com/secret")],
        },
    );
    let debug = format!("{login:?}");
    assert!(debug.contains("https://example.com"), "{debug}");
    assert!(!debug.contains("token"), "{debug}");
}

#[test]
fn password_and_totp_secrets_are_not_searchable() {
    let item = login(
        "1",
        "Login",
        "alice",
        "super-secret-pw",
        "https://example.com",
    );
    let mut secret_item = item;
    let replaced = if let ItemData::Login { totp, .. } = &mut secret_item.data {
        // Reassignment drops (and zeroizes) the previous secret buffer.
        *totp = Zeroizing::new("JBSWY3DPEHPK3PXP".into());
        true
    } else {
        false
    };
    assert!(replaced, "the test item must be a login with a TOTP field");
    // matches_query is public and normalizes its needle itself, so raw input
    // works even when the caller bypasses Vault::view().
    assert!(secret_item.matches_query("alice"));
    assert!(secret_item.matches_query("ALICE"));
    assert!(!secret_item.matches_query("super-secret-pw"));
    assert!(!secret_item.matches_query("jbswy3dpehpk3pxp"));
}

#[test]
fn card_numbers_are_only_searchable_by_last_four() {
    let mut vault = Vault::new();
    vault.items.push(VaultItem::new(
        "c",
        "Visa",
        ItemData::Card(CardData {
            number: "4111 1111 1111 1234".into(),
            ..CardData::default()
        }),
    ));
    assert_eq!(vault.view(&Filter::All, "1234", SortKey::NameAsc).len(), 1);
    assert_eq!(
        vault
            .view(&Filter::All, "4111 1111", SortKey::NameAsc)
            .len(),
        0
    );
}

#[test]
fn unspaced_card_numbers_are_also_masked_to_last_four() {
    let mut vault = Vault::new();
    vault.items.push(VaultItem::new(
        "c",
        "Visa",
        ItemData::Card(CardData {
            number: "4111111111111234".into(),
            ..CardData::default()
        }),
    ));
    assert_eq!(vault.view(&Filter::All, "1234", SortKey::NameAsc).len(), 1);
    // The full PAN must never be searchable, with or without spaces.
    assert_eq!(
        vault
            .view(&Filter::All, "411111111111", SortKey::NameAsc)
            .len(),
        0
    );
}

#[test]
fn favorites_folders_and_removal_round_trip() {
    let mut vault = sample();
    assert_eq!(vault.toggle_favorite("2"), Some(true));
    assert_eq!(vault.favorite_count(), 2);
    assert_eq!(vault.toggle_favorite("nope"), None);

    assert!(vault.set_folder("3", Some("f1".into())));
    assert!(!vault.set_folder("nope", None));
    assert_eq!(vault.folder_counts(), vec![("f1".to_string(), 2)]);

    assert!(vault.remove("3"));
    assert!(!vault.remove("3"));
    assert_eq!(vault.len(), 2);

    assert_eq!(vault.folder_name("f1"), Some("仕事"));
    assert_eq!(vault.folder_name("nope"), None);
    assert!(vault.item("1").is_some());
    assert!(vault.item("nope").is_none());
}

#[test]
fn upsert_replaces_but_keeps_the_previous_revision() {
    let mut vault = sample();
    let mut edited = login(
        "1",
        "GitHub (work)",
        "alice",
        "newpass",
        "https://github.com",
    );
    edited.revision_date = 0;
    vault.upsert(edited);
    assert_eq!(vault.len(), 3);
    let stored = vault.item("1").unwrap();
    assert_eq!(stored.name, "GitHub (work)");
    assert_eq!(stored.revision_date, 100);
    assert!(stored.folder_id.is_none(), "upsert replaces the whole item");

    let mut fresh = login("9", "New", "bob", "pw", "https://new.example");
    fresh.revision_date = 42;
    vault.upsert(fresh);
    assert_eq!(vault.len(), 4);
    assert_eq!(vault.item("9").unwrap().revision_date, 42);
}

#[test]
fn duplicate_names_group_case_insensitively() {
    let mut vault = sample();
    vault
        .items
        .push(login("4", "github", "bob", "pw", "https://github.com"));
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "github");
    assert_eq!(groups[0].1, vec!["1".to_string(), "4".to_string()]);
}

#[test]
fn nfkd_absorbs_canonical_and_compatibility_differences() {
    // NFC vs NFD (precomposed vs base + combining mark).
    assert_eq!(nfkd("Caf\u{e9}"), nfkd("Cafe\u{301}"));
    // Canonical ordering of combining marks with different combining classes.
    assert_eq!(nfkd("a\u{301}\u{327}"), nfkd("a\u{327}\u{301}"));
    // Full-width ASCII vs ASCII.
    assert_eq!(nfkd("\u{ff21}\u{ff22}\u{ff23}"), "ABC");
    // Ideographic space vs ASCII space.
    assert_eq!(nfkd("\u{3000}"), " ");
    // Half-width katakana (with a half-width voiced mark) vs full-width ガ.
    assert_eq!(nfkd("\u{ff76}\u{ff9e}"), nfkd("\u{30ac}"));
}

#[test]
fn search_absorbs_unicode_form_differences() {
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "Caf\u{e9}", "user", "pw", "https://a.example"));
    // An NFD query must find an NFC name.
    assert_eq!(
        vault
            .view(&Filter::All, "cafe\u{301}", SortKey::NameAsc)
            .len(),
        1
    );
    // The NFC query must find the same item.
    assert_eq!(
        vault
            .view(&Filter::All, "caf\u{e9}", SortKey::NameAsc)
            .len(),
        1
    );

    vault
        .items
        .push(login("2", "GitHub", "user", "pw", "https://b.example"));
    // A full-width query must find the ASCII name.
    assert_eq!(
        vault
            .view(
                &Filter::All,
                "\u{ff47}\u{ff49}\u{ff54}\u{ff48}\u{ff55}\u{ff42}",
                SortKey::NameAsc,
            )
            .len(),
        1
    );
}

#[test]
fn comparison_key_applies_full_case_folding_and_is_idempotent() {
    // `to_lowercase` alone leaves these pairs distinct; the search, duplicate
    // and sort paths all go through this one key so they agree.
    assert_eq!(comparison_key("Straße"), comparison_key("STRASSE"));
    assert_eq!(comparison_key("ß"), comparison_key("ss"));
    assert_eq!(comparison_key("ẞ"), comparison_key("ss"));
    assert_eq!(comparison_key("ς"), comparison_key("σ"));
    assert_eq!(comparison_key("Σ"), comparison_key("σ"));
    assert_eq!(comparison_key("ſ"), comparison_key("s"));
    for value in ["Straße", "STRASSE", "ΟΔΟΣ", "οδος", "ſnail", "Café"] {
        assert_eq!(
            comparison_key(&comparison_key(value)),
            comparison_key(value),
            "{value}"
        );
    }
}

#[test]
fn search_and_duplicates_share_the_folded_key() {
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "Straße", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("2", "STRASSE", "u", "p", "https://b.example"));
    assert_eq!(
        vault.view(&Filter::All, "strasse", SortKey::NameAsc).len(),
        2
    );
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].1, vec!["1".to_string(), "2".to_string()]);
}

#[test]
fn matches_query_normalizes_a_raw_needle() {
    let item = login("1", "Café", "user", "pw", "https://example.com");
    assert!(item.matches_query("café"));
    // NFD spelling plus upper case, without going through Vault::view().
    assert!(item.matches_query("CAFE\u{301}"));
    assert!(!item.matches_query("tea"));
}

#[test]
fn search_absorbs_halfwidth_katakana() {
    let mut vault = Vault::new();
    vault.items.push(login(
        "1",
        "\u{30ab}\u{30bf}\u{30ab}\u{30ca}",
        "user",
        "pw",
        "https://example.com",
    ));
    assert_eq!(
        vault
            .view(
                &Filter::All,
                "\u{ff76}\u{ff80}\u{ff76}\u{ff85}",
                SortKey::NameAsc,
            )
            .len(),
        1
    );
}

#[test]
fn duplicate_names_normalize_forms_and_skip_blanks() {
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "Caf\u{e9}", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("2", "Cafe\u{301}", "u", "p", "https://b.example"));
    vault.items.push(login(
        "3",
        "\u{ff21}\u{ff42}\u{ff43}",
        "u",
        "p",
        "https://c.example",
    ));
    vault
        .items
        .push(login("4", "abc", "u", "p", "https://d.example"));
    // Blank names (empty, ASCII spaces, ideographic space) must not be
    // reported as duplicates of each other.
    vault
        .items
        .push(login("5", "", "u", "p", "https://e.example"));
    vault
        .items
        .push(login("6", "   ", "u", "p", "https://f.example"));
    vault
        .items
        .push(login("7", "\u{3000}", "u", "p", "https://g.example"));

    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 2, "{groups:?}");
    let keys: Vec<&str> = groups.iter().map(|(key, _)| key.as_str()).collect();
    assert!(keys.contains(&"cafe\u{301}"), "{keys:?}");
    assert!(keys.contains(&"abc"), "{keys:?}");
    for (_, ids) in &groups {
        assert_eq!(ids.len(), 2, "{groups:?}");
    }
}

#[test]
fn filter_labels_resolve_folder_names() {
    let vault = sample();
    assert_eq!(Filter::All.label(&vault.folders), "すべてのアイテム");
    assert_eq!(Filter::Kind(ItemKind::Card).label(&vault.folders), "カード");
    assert_eq!(Filter::Folder("f1".into()).label(&vault.folders), "仕事");
    assert_eq!(
        Filter::Folder("gone".into()).label(&vault.folders),
        "(不明なフォルダ)"
    );
    assert_eq!(SortKey::Kind.next(), SortKey::NameAsc);
}

#[test]
fn match_type_numbers_map_to_the_enum() {
    let uri = LoginUri {
        uri: "https://example.com".into(),
        match_type: Some(4),
    };
    assert_eq!(
        uri.match_enum(),
        Some(openwarden::UriMatch::RegularExpression)
    );
    let bad = LoginUri {
        uri: "x".into(),
        match_type: Some(9),
    };
    assert_eq!(bad.match_enum(), None);
    // An unknown match_type falls back to Domain, and "x" parses as
    // "http://x/", whose base domain "x" differs from "example.com", so
    // the page must not match.
    assert!(!bad.matches("https://example.com/", &openwarden::MatchOptions::default()));
}

#[test]
fn kind_counts_covers_every_kind() {
    let vault = sample();
    let counts = vault.kind_counts();
    assert_eq!(counts.len(), 5);
    assert_eq!(counts[0], (ItemKind::Login, 2));
    assert_eq!(counts[1], (ItemKind::SecureNote, 1));
    assert_eq!(counts[4], (ItemKind::SshKey, 0));
}

#[test]
fn login_secret_fields_are_zeroizing_buffers() {
    let mut item = login("1", "Site", "alice", "old-pw", "https://example.com");
    if let ItemData::Login { password, totp, .. } = &mut item.data {
        // Assigning a `Zeroizing<String>` compiles only because both fields
        // now have that exact type; the old buffer is wiped on replacement.
        *password = Zeroizing::new("replacement-pw".to_string());
        *totp = Zeroizing::new("JBSWY3DPEHPK3PXP".to_string());
    }
    assert_eq!(item.password(), Some("replacement-pw"));
    assert_eq!(item.totp_secret(), Some("JBSWY3DPEHPK3PXP"));
    let (username, password, totp, uris) = item.login().unwrap();
    assert_eq!(username, "alice");
    assert_eq!(password, "replacement-pw");
    assert_eq!(totp, "JBSWY3DPEHPK3PXP");
    assert_eq!(uris.len(), 1);
    let debug = format!("{item:?}");
    assert!(!debug.contains("old-pw"), "{debug}");
    assert!(!debug.contains("replacement-pw"), "{debug}");
    assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "{debug}");
}

// Generated with `ssh-keygen -t ed25519`; the expected fingerprint was
// confirmed independently by `ssh-keygen -lf` and Python's hashlib.
const REFERENCE_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVYTn6DgHoRS29obD0RhrnbKgHhM1eqLvmbTWMGwSmR fp-test@example";
const REFERENCE_FINGERPRINT: &str = "SHA256:rU5/Ssu4iQF+Dh5DRCbEpCjexkxaSKWYzYW9pUPi7R0";

fn ssh_key(public_key: &str, fingerprint: &str) -> SshKeyData {
    SshKeyData {
        public_key: public_key.to_string(),
        private_key: String::new(),
        fingerprint: fingerprint.to_string(),
    }
}

#[test]
fn ssh_fingerprint_matches_openssh_reference() {
    let key = ssh_key(REFERENCE_PUBLIC_KEY, REFERENCE_FINGERPRINT);
    assert_eq!(key.verify_fingerprint(), FingerprintVerify::Match);
    assert!(key.fingerprint_matches());
}

#[test]
fn ssh_fingerprint_detects_a_stored_value_mismatch() {
    let key = ssh_key(
        REFERENCE_PUBLIC_KEY,
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    assert_eq!(
        key.verify_fingerprint(),
        FingerprintVerify::Mismatch {
            computed: REFERENCE_FINGERPRINT.to_string(),
        }
    );
    assert!(!key.fingerprint_matches());
}

#[test]
fn ssh_fingerprint_ignores_comment_and_extra_whitespace() {
    let key = ssh_key(
        "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIMVYTn6DgHoRS29obD0RhrnbKgHhM1eqLvmbTWMGwSmR   someone@else  ",
        REFERENCE_FINGERPRINT,
    );
    assert_eq!(key.verify_fingerprint(), FingerprintVerify::Match);
}

#[test]
fn ssh_fingerprint_rejects_unparsable_public_keys() {
    for public_key in [
        "",
        "ssh-ed25519",
        "ssh-ed25519 !!!not-base64!!! comment",
        "ssh-ed25519 A",
    ] {
        let key = ssh_key(public_key, REFERENCE_FINGERPRINT);
        assert_eq!(
            key.verify_fingerprint(),
            FingerprintVerify::InvalidPublicKey,
            "input: {public_key:?}"
        );
        assert!(!key.fingerprint_matches());
    }
}

#[test]
fn login_secret_serde_round_trip_keeps_debug_redacted() {
    let item = VaultItem::new(
        "1",
        "Site",
        ItemData::Login {
            username: "alice".into(),
            password: Zeroizing::new("super-secret-pw".into()),
            totp: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
            uris: vec![LoginUri::new("https://example.com")],
        },
    );
    let json = serde_json::to_string(&item).unwrap();
    // The wire format stays a plain string; deserialization re-wraps it.
    assert!(json.contains("super-secret-pw"), "{json}");
    let restored: VaultItem = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, item);
    assert_eq!(restored.password(), Some("super-secret-pw"));
    assert_eq!(restored.totp_secret(), Some("JBSWY3DPEHPK3PXP"));
    let debug = format!("{restored:?}");
    assert!(!debug.contains("super-secret-pw"), "{debug}");
    assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "{debug}");
}

#[test]
fn name_sort_uses_the_same_nfkd_key_as_search() {
    let mut vault = Vault::new();
    // Full-width "A" and a decomposed "A" must sort like plain "A".
    vault.items.push(VaultItem::new(
        "a-full",
        "Ａ",
        ItemData::SecureNote {
            text: String::new(),
        },
    ));
    vault.items.push(VaultItem::new(
        "a-decomposed",
        "A\u{0301}",
        ItemData::SecureNote {
            text: String::new(),
        },
    ));
    vault.items.push(VaultItem::new(
        "b-plain",
        "B",
        ItemData::SecureNote {
            text: String::new(),
        },
    ));

    let sorted = vault.view(&Filter::All, "", SortKey::NameAsc);
    let ids: Vec<&str> = sorted.iter().map(|item| item.id.as_str()).collect();
    assert_eq!(ids, vec!["a-full", "a-decomposed", "b-plain"]);
}
