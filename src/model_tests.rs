#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::model::*;

#[::core::prelude::v1::test]
fn debug_never_reveals_item_secrets() {
    let item = VaultItem::new(
        "1",
        "Sample",
        ItemData::Login {
            username: "alice".into(),
            password: "super-secret-pw".into(),
            totp: "JBSWY3DPEHPK3PXP".into(),
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
            password: password.to_string(),
            totp: String::new(),
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

#[::core::prelude::v1::test]
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
            password: "p".into(),
            totp: String::new(),
            uris: vec![LoginUri::new("https://user:token@example.com/secret")],
        },
    );
    let debug = format!("{login:?}");
    assert!(debug.contains("https://example.com"), "{debug}");
    assert!(!debug.contains("token"), "{debug}");
}

#[::core::prelude::v1::test]
fn password_and_totp_secrets_are_not_searchable() {
    let item = login(
        "1",
        "Login",
        "alice",
        "super-secret-pw",
        "https://example.com",
    );
    let mut secret_item = item;
    if let ItemData::Login { totp, .. } = &mut secret_item.data {
        *totp = "JBSWY3DPEHPK3PXP".into();
    }
    assert!(!secret_item.matches_query("super-secret-pw"));
    assert!(!secret_item.matches_query("jbswy3dpehpk3pxp"));
    assert!(secret_item.matches_query("alice"));
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
