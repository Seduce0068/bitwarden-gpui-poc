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

#[test]
fn mask_uri_handles_schemes_without_a_host() {
    // `url::Url::parse` accepts opaque, non-hierarchical URLs with no host.
    // The masker must keep the scheme and return an empty authority rather
    // than fabricating a host from the path (model.rs:75-85).
    assert_eq!(mask_uri("mailto:alice@example.com"), "mailto://");
    assert_eq!(mask_uri("data:text/plain,hello"), "data://");
    assert_eq!(mask_uri("about:blank"), "about://");
    // A real host still wins when a `//` authority is present.
    assert_eq!(mask_uri("custom://host/path"), "custom://host");
}

#[test]
fn mask_uri_nul_sentinel_is_not_read_as_a_scheme() {
    use crate::vault_sync::UNDECRYPTABLE_URI;

    assert!(UNDECRYPTABLE_URI.starts_with('\0'));
    assert_eq!(mask_uri(UNDECRYPTABLE_URI), "（復号できませんでした）");
    assert_eq!(
        mask_uri("\0https://example.com/path"),
        "（復号できませんでした）"
    );
    // Already-rendered statuses survive a second pass unchanged: findings may
    // be built from either a raw URI or a previously masked one.
    assert_eq!(
        mask_uri("（復号できませんでした）"),
        "（復号できませんでした）"
    );
    assert_eq!(mask_uri("(不正な URI)"), "(不正な URI)");
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
fn name_sort_id_tiebreak_is_reversed_only_for_name_desc() {
    let vault = Vault {
        items: vec![
            login("a", "Same", "u", "p", "https://a.example"),
            login("b", "Same", "u", "p", "https://b.example"),
        ],
        folders: Vec::new(),
    };
    let ids = |sort| -> Vec<&str> {
        vault
            .view(&Filter::All, "", sort)
            .iter()
            .map(|item| item.id.as_str())
            .collect()
    };

    // `compare` builds `name.cmp().then(id.cmp())` and reverses the whole
    // ordering for NameDesc, so the id tiebreak flips with the name direction.
    assert_eq!(ids(SortKey::NameAsc), vec!["a", "b"]);
    assert_eq!(ids(SortKey::NameDesc), vec!["b", "a"]);
    // Other keys reuse the un-reversed name+id ordering as their tiebreak.
    assert_eq!(ids(SortKey::RecentlyModified), vec!["a", "b"]);
    assert_eq!(ids(SortKey::Kind), vec!["a", "b"]);
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
fn page_matching_orders_multiple_hits_by_favorite_then_revision_then_name() {
    let mut vault = Vault::new();
    let page = "https://example.com/settings";
    let mut plain_old = login("plain-old", "Zeta", "u", "p", page);
    plain_old.revision_date = 10;
    let mut plain_new = login("plain-new", "Alpha", "u", "p", page);
    plain_new.revision_date = 20;
    let mut favorite_old = login("fav-old", "Beta", "u", "p", page);
    favorite_old.favorite = true;
    favorite_old.revision_date = 5;
    let mut favorite_new = login("fav-new", "Omega", "u", "p", page);
    favorite_new.favorite = true;
    favorite_new.revision_date = 30;
    // Same favorite/revision pair: the name is the final tiebreak.
    let mut favorite_tie_a = login("fav-tie-a", "Gamma", "u", "p", page);
    favorite_tie_a.favorite = true;
    favorite_tie_a.revision_date = 30;
    // A non-matching item must never enter the result.
    let other = login("other", "Other", "u", "p", "https://elsewhere.example.net");
    vault.items = vec![
        plain_old,
        plain_new,
        favorite_old,
        favorite_new,
        favorite_tie_a,
        other,
    ];

    let opts = openwarden::MatchOptions::default();
    let hits: Vec<&str> = vault
        .matches_page(page, &opts)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(
        hits,
        vec!["fav-tie-a", "fav-new", "fav-old", "plain-new", "plain-old"]
    );
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
        "Acme",
    ] {
        assert!(!debug.contains(secret), "{debug}");
    }
    assert!(debug.contains("[redacted]"), "{debug}");

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
fn filter_labels_cover_favorites_and_no_folder() {
    let vault = sample();
    // Both sidebar-only filters must have a stable label (model.rs:697-707).
    assert_eq!(Filter::Favorites.label(&vault.folders), "お気に入り");
    assert_eq!(Filter::NoFolder.label(&vault.folders), "フォルダなし");
    // Labels do not depend on folder contents when the filter is not a folder.
    assert_eq!(Filter::Favorites.label(&[]), "お気に入り");
    assert_eq!(Filter::NoFolder.label(&[]), "フォルダなし");
}

#[test]
fn sort_key_next_cycles_through_all_four_variants() {
    // All four branches of `SortKey::next` (model.rs:727-734) must form one
    // closed cycle; a missing branch would leave the UI sort button stuck.
    assert_eq!(SortKey::NameAsc.next(), SortKey::NameDesc);
    assert_eq!(SortKey::NameDesc.next(), SortKey::RecentlyModified);
    assert_eq!(SortKey::RecentlyModified.next(), SortKey::Kind);
    assert_eq!(SortKey::Kind.next(), SortKey::NameAsc);

    let mut key = SortKey::NameAsc;
    for _ in 0..4 {
        key = key.next();
    }
    assert_eq!(key, SortKey::NameAsc);
}

#[test]
fn view_sorting_uses_comparison_keys_for_names() {
    // `compare()` normalizes both names with `comparison_key` before ordering
    // (model.rs:923-926), and `Vault::view` normalizes the query the same way
    // (model.rs:819-826). NFD/uppercase spellings must therefore sort and
    // search identically to their precomposed/lowercase counterparts.
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "cafe\u{301}", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("2", "Café", "u", "p", "https://b.example"));
    assert_eq!(
        vault
            .view(&Filter::All, "CAFE\u{301}", SortKey::NameAsc)
            .len(),
        2
    );
    let ids: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(ids, vec!["1", "2"]);
    let desc: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::NameDesc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(desc, vec!["2", "1"]);
    // The comparison keys themselves remain equal across the two spellings.
    assert_eq!(comparison_key("cafe\u{301}"), comparison_key("Caf\u{e9}"));
}

#[test]
fn sort_key_kind_orders_by_wire_number_then_name_and_has_a_label() {
    let mut vault = Vault::new();
    // Inserted out of kind order; names alone would sort differently.
    vault.items.push(VaultItem::new(
        "card-z",
        "Zebra",
        ItemData::Card(CardData::default()),
    ));
    vault
        .items
        .push(login("login-y", "Yankee", "u", "p", "https://y.example"));
    vault.items.push(VaultItem::new(
        "note-b",
        "Bravo",
        ItemData::SecureNote {
            text: String::new(),
        },
    ));
    vault
        .items
        .push(login("login-a", "Alpha", "u", "p", "https://a.example"));
    vault.items.push(VaultItem::new(
        "identity-m",
        "Mike",
        ItemData::Identity(IdentityData::default()),
    ));
    vault.items.push(VaultItem::new(
        "ssh-s",
        "Sierra",
        ItemData::SshKey(SshKeyData::default()),
    ));

    let ids: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::Kind)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    // Login(1), SecureNote(2), Card(3), Identity(4), SshKey(5); ties by name.
    assert_eq!(
        ids,
        vec![
            "login-a",
            "login-y",
            "note-b",
            "card-z",
            "identity-m",
            "ssh-s"
        ]
    );

    assert_eq!(SortKey::Kind.label(), "種類");
    assert_eq!(SortKey::NameAsc.label(), "名前 ↑");
    assert_eq!(SortKey::NameDesc.label(), "名前 ↓");
    assert_eq!(SortKey::RecentlyModified.label(), "更新が新しい順");
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
fn ssh_fingerprint_rejects_extra_base64_padding() {
    // Padding is optional, but a surplus `=` must not decode to the same blob:
    // otherwise distinct public-key lines would share one fingerprint
    // (model.rs:278-320).
    let canonical = super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQ== fp");
    assert!(canonical.is_some());
    for extra in [
        "ssh-ed25519 A=== fp",
        "ssh-ed25519 AQ=== fp",
        "ssh-ed25519 AQI== fp",
        "ssh-ed25519 AQID= fp",
        "ssh-ed25519 =AQ== fp",
        "ssh-ed25519 A=Q= fp",
    ] {
        assert_eq!(
            super::ssh_fingerprint::sha256_fingerprint(extra),
            None,
            "{extra}"
        );
    }
    // Unpadded and correctly padded forms of the same blob still agree.
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQI fp"),
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQI= fp")
    );
}

#[test]
fn ssh_fingerprint_rejects_non_canonical_base64_padding_bits() {
    // The decoder must verify the unused low bits of the final base64
    // character (model.rs:300-311). `AQ==` is canonical for byte 0x01, while
    // `AR==` decodes to the same 0x01 only if those low bits are ignored.
    // Accepting it would let two different fingerprints map to one key blob.
    let canonical = "ssh-ed25519 AQ== fp";
    let noncanonical = "ssh-ed25519 AR== fp";

    let expected = super::ssh_fingerprint::sha256_fingerprint(canonical);
    assert!(
        expected.is_some(),
        "a one-byte blob is a valid base64 string"
    );
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint(noncanonical),
        None,
        "a nonzero unused bit must be rejected"
    );

    // Two leftover bits: `AQI=` (bytes 01 02) is canonical; the third
    // character's low two bits must be zero, so `AQJ=` is rejected.
    assert!(super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQI= fp").is_some());
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQJ= fp"),
        None
    );

    // Four leftover bits with no `=` padding are impossible; the two-character
    // form above covers that case. A full three-byte group leaves zero bits and
    // must continue to decode normally.
    assert!(super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQID fp").is_some());
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

#[test]
fn notes_are_searchable_even_for_non_login_items() {
    // `haystacks` always includes `notes` (model.rs:582-587), so a free-form
    // note is findable regardless of the item's kind, including text that is
    // absent from the name and kind-specific fields.
    let mut item = VaultItem::new(
        "n-1",
        "Unrelated title",
        ItemData::SecureNote {
            text: "different body".into(),
        },
    );
    item.notes = "recovery-code-7X".into();
    assert!(item.matches_query("recovery-code"));
    assert!(item.matches_query("7X"));
    assert!(!item.matches_query("not-in-this-item"));

    // NFKD/case normalization applies to notes just like other fields.
    assert!(item.matches_query("RECOVERY-CODE"));
}

#[test]
fn upsert_honors_an_explicit_revision_but_preserves_zero() {
    let mut vault = Vault::new();
    let mut original = VaultItem::new(
        "u-1",
        "Original",
        ItemData::SecureNote { text: "old".into() },
    );
    original.revision_date = 1_700_000_000;
    vault.upsert(original.clone());

    let mut explicit = original.clone();
    explicit.name = "Renewed".into();
    explicit.revision_date = 1_800_000_000;
    vault.upsert(explicit);
    assert_eq!(vault.item("u-1").unwrap().name, "Renewed");
    assert_eq!(
        vault.item("u-1").unwrap().revision_date,
        1_800_000_000,
        "an explicit revision overwrites the stored one"
    );

    // A caller that leaves the revision at UNKNOWN_REVISION keeps the old one.
    let mut implicit = original.clone();
    implicit.name = "Metadata only".into();
    implicit.revision_date = UNKNOWN_REVISION;
    vault.upsert(implicit);
    assert_eq!(vault.item("u-1").unwrap().name, "Metadata only");
    assert_eq!(
        vault.item("u-1").unwrap().revision_date,
        1_800_000_000,
        "zero revision must not rewind an explicit one"
    );
}

#[test]
fn page_matching_ties_use_the_folded_name_key_then_the_id() {
    // `matches_page` shares the `compare` tiebreak (model.rs:841,923-926):
    // folded names order first, and identical folded names fall back to the id
    // so the result never depends on insertion order.
    let page = "https://example.com/shared";
    let mut vault = Vault::new();
    let mut nfd = login("b-nfd", "cafe\u{301}", "u", "p", page);
    nfd.favorite = true;
    nfd.revision_date = 10;
    let mut nfc = login("a-nfc", "Café", "u", "p", page);
    nfc.favorite = true;
    nfc.revision_date = 10;
    let mut alpha = login("z-alpha", "Apple", "u", "p", page);
    alpha.favorite = true;
    alpha.revision_date = 10;
    vault.items = vec![nfd, nfc, alpha];

    let opts = openwarden::MatchOptions::default();
    let ids: Vec<&str> = vault
        .matches_page(page, &opts)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(ids, vec!["z-alpha", "a-nfc", "b-nfd"]);
    assert_eq!(comparison_key("cafe\u{301}"), comparison_key("Café"));
}

#[test]
fn cardholder_name_is_redacted_in_debug_but_brand_stays_visible() {
    let card = VaultItem::new(
        "c",
        "Card",
        ItemData::Card(CardData {
            cardholder_name: "Ada Lovelace".into(),
            brand: "Visa".into(),
            number: "4111111111111234".into(),
            code: "987".into(),
            ..CardData::default()
        }),
    );
    let debug = format!("{card:?}");
    assert!(!debug.contains("Ada Lovelace"), "{debug}");
    assert!(!debug.contains("Ada"), "{debug}");
    assert!(!debug.contains("4111111111111234"), "{debug}");
    assert!(!debug.contains("987"), "{debug}");
    assert!(debug.contains("Visa"), "{debug}");
    assert!(debug.contains("[redacted]"), "{debug}");
}

#[test]
fn search_hints_exclude_card_code_and_ssh_private_key() {
    // `haystacks` (model.rs:599-643) lists only non-secret kind-specific
    // fields. The card security code and SSH private key must not be fished
    // out through search even though they live in the same item.
    let card = VaultItem::new(
        "c",
        "Card",
        ItemData::Card(CardData {
            cardholder_name: "Holder".into(),
            number: "4111111111111234".into(),
            code: "987654".into(),
            ..CardData::default()
        }),
    );
    assert!(!card.matches_query("987654"));
    assert!(!card.matches_query("987"));
    assert!(card.matches_query("Holder"));
    assert!(card.matches_query("1234"));

    let ssh = VaultItem::new(
        "s",
        "Key",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: "PRIVATE-KEY-MATERIAL".into(),
            fingerprint: "SHA256:abc".into(),
        }),
    );
    assert!(!ssh.matches_query("PRIVATE-KEY-MATERIAL"));
    assert!(!ssh.matches_query("KEY-MATERIAL"));
    assert!(ssh.matches_query("SHA256:abc"));
}

#[test]
fn login_username_is_redacted_in_debug() {
    // Regression for model.rs:490: the manual `ItemData` Debug prints a
    // placeholder for username, not the actual value.
    let item = login(
        "1",
        "Sample",
        "alice@example.com",
        "super-secret-pw",
        "https://example.com",
    );
    let debug = format!("{item:?}");
    assert!(debug.contains("Sample"), "{debug}");
    assert!(!debug.contains("alice@example.com"), "{debug}");
    assert!(!debug.contains("alice"), "{debug}");
    assert!(!debug.contains("super-secret-pw"), "{debug}");
}

#[test]
fn search_haystacks_cover_kind_specific_fields() {
    let note = VaultItem::new(
        "n",
        "note-title",
        ItemData::SecureNote {
            text: "needle-note".into(),
        },
    );
    assert!(note.matches_query("needle-note"));

    let card = VaultItem::new(
        "c",
        "card-title",
        ItemData::Card(CardData {
            cardholder_name: "Card Holder".into(),
            brand: "Visa".into(),
            number: "1234 5678 9012 3456".into(),
            exp_month: "01".into(),
            exp_year: "30".into(),
            code: "123".into(),
        }),
    );
    assert!(card.matches_query("card holder"));
    assert!(card.matches_query("3456"));
    assert!(
        !card.matches_query("9012"),
        "the full PAN must not be searchable"
    );

    let identity = VaultItem::new(
        "i",
        "id-title",
        ItemData::Identity(IdentityData {
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            email: "ada@example.com".into(),
            phone: "090-1234".into(),
            address: "42 Maple Avenue".into(),
            company: "Analytical".into(),
        }),
    );
    assert!(identity.matches_query("lovelace"));
    assert!(identity.matches_query("analytical"));
    // The address is a searchable identity field too (model.rs:607-613), but
    // it stays redacted in Debug (see `debug_masks_identity_and_uri_details`).
    assert!(identity.matches_query("maple avenue"));
    assert!(identity.matches_query("MAPLE"));

    let ssh = VaultItem::new(
        "s",
        "ssh-title",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: String::new(),
            fingerprint: "SHA256:abc".into(),
        }),
    );
    assert!(ssh.matches_query("SHA256:abc"));
}
