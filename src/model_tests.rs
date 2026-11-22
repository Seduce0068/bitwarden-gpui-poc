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

    // Free-form notes are secret-bearing too. The manual `VaultItem` Debug
    // (model.rs:672-686) masks the whole value, including through `Vault`'s
    // derived Debug, while search and serde still see the plain text.
    const NOTES_SECRET: &str = "NOTES-SECRET-recovery-code-7X";
    let mut noted = VaultItem::new(
        "4",
        "Noted",
        ItemData::SecureNote {
            text: String::new().into(),
        },
    );
    noted.notes = Zeroizing::new(NOTES_SECRET.to_string());
    let debug = format!("{noted:?}");
    assert!(!debug.contains(NOTES_SECRET), "{debug}");
    assert!(debug.contains("notes: \"[redacted]\""), "{debug}");
    let vault_debug = format!(
        "{:?}",
        Vault {
            items: vec![noted.clone()],
            folders: Vec::new(),
        }
    );
    assert!(!vault_debug.contains(NOTES_SECRET), "{vault_debug}");
    assert!(noted.matches_query("recovery-code"), "only Debug is masked");
    assert!(serde_json::to_string(&noted)
        .unwrap()
        .contains(NOTES_SECRET));
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
    // than fabricating a host from the path (model.rs:86-112).
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
fn item_kind_labels_cover_all_five_variants() {
    // `ItemKind::label` (model.rs:155-163) is the sidebar's display text; every
    // wire kind needs one, so the five arms are pinned in a table.
    for (kind, label) in [
        (ItemKind::Login, "ログイン"),
        (ItemKind::SecureNote, "メモ"),
        (ItemKind::Card, "カード"),
        (ItemKind::Identity, "ID"),
        (ItemKind::SshKey, "SSH鍵"),
    ] {
        assert_eq!(kind.label(), label, "{kind:?}");
    }
}

#[test]
fn vault_is_empty_depends_only_on_items() {
    // `Vault::is_empty` (model.rs:922-924) delegates to the item list: folders
    // alone do not make a vault non-empty, and removal restores emptiness.
    let mut vault = Vault::new();
    assert!(vault.is_empty());
    assert_eq!(vault.len(), 0);

    vault.folders.push(Folder {
        id: "f1".into(),
        name: "仕事".into(),
    });
    assert!(vault.is_empty(), "folders are not items");

    vault
        .items
        .push(login("1", "Item", "u", "p", "https://example.com"));
    assert!(!vault.is_empty());
    assert_eq!(vault.len(), 1);

    assert!(vault.remove("1"));
    assert!(vault.is_empty());
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
fn raw_login_uris_stay_in_the_search_haystack() {
    // `haystacks` pushes `uri.uri` verbatim (model.rs:763-765). `mask_uri`
    // protects Debug and reports, but the search index is a separate path: a
    // credential in a URI query can still be found through search hints. This
    // is a documented known constraint, asserted here so it cannot drift
    // silently.
    let item = login(
        "1",
        "Site",
        "alice",
        "pw",
        "https://example.com/cb?token=RAW_URI_SECRET",
    );
    assert!(item.matches_query("token=RAW_URI_SECRET"));
    assert!(item.matches_query("raw_uri_secret"));
    assert!(item.matches_query("example.com"));
    let debug = format!("{item:?}");
    assert!(!debug.contains("RAW_URI_SECRET"), "{debug}");
}

#[test]
fn login_only_accessors_return_none_or_empty_for_non_login_items() {
    // The `_ =>` arms of `login`/`password`/`totp_secret`/`uris`
    // (model.rs:708-742) must not panic or fall through for other kinds.
    let items = [
        VaultItem::new(
            "n",
            "note",
            ItemData::SecureNote {
                text: "text".into(),
            },
        ),
        VaultItem::new("c", "card", ItemData::Card(CardData::default())),
        VaultItem::new("i", "identity", ItemData::Identity(IdentityData::default())),
        VaultItem::new("s", "ssh", ItemData::SshKey(SshKeyData::default())),
    ];
    for item in &items {
        assert!(item.login().is_none(), "{}", item.id);
        assert_eq!(item.password(), None, "{}", item.id);
        assert_eq!(item.totp_secret(), None, "{}", item.id);
        assert!(item.uris().is_empty(), "{}", item.id);
        assert!(!item.matches_page("https://example.com", &openwarden::MatchOptions::default()));
    }
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

    // `None` removes the folder assignment rather than being ignored, and a
    // subsequent assignment is accepted again (model.rs:1020-1028).
    assert!(vault.set_folder("3", None));
    assert_eq!(vault.item("3").unwrap().folder_id, None);
    assert_eq!(vault.folder_counts(), vec![("f1".to_string(), 1)]);
    assert!(vault.set_folder("3", Some("f1".into())));
    assert_eq!(vault.item("3").unwrap().folder_id.as_deref(), Some("f1"));

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
fn comparison_key_folds_the_documented_cases_and_is_idempotent() {
    // `to_lowercase` alone leaves these pairs distinct; the search, duplicate
    // and sort paths all go through this one key so they agree. The doc does
    // not claim a complete Unicode full case fold (model.rs:24-34): only the
    // explicitly listed mappings are guaranteed.
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
fn comparison_key_is_idempotent_for_titlecase_dz_variants() {
    // U+01C4/01C5/01C6 (capital / titlecase / small DZ with caron) all NFKD to
    // D or d + z + combining caron once lowercasing is applied. The fixed-point
    // loop (model.rs:59-69) must leave the folded key unchanged on a second
    // pass; otherwise a normalized needle would drift on the `view()` path.
    let title = comparison_key("\u{01c5}");
    let small = comparison_key("\u{01c6}");
    assert_eq!(title, small);
    assert_eq!(comparison_key("\u{01c4}"), title);
    assert_eq!(comparison_key("dz\u{030c}"), title);
    for key in [&title, &small] {
        assert_eq!(comparison_key(key), *key, "{key:?}");
        assert_eq!(comparison_key(&comparison_key(key)), *key, "{key:?}");
    }
}

#[test]
fn comparison_key_is_idempotent_for_combining_greek_ypogegrammeni() {
    // U+0345 COMBINING GREEK YPOGEGRAMMENI is a combining mark that this
    // Unicode table keeps verbatim. The fixed-point loop must still leave it
    // unchanged, so a normalized search needle does not drift when fed back
    // through `view()`.
    let key = comparison_key("\u{0345}");
    assert_eq!(comparison_key(&key), key, "{key:?}");
    assert_eq!(comparison_key(&comparison_key(&key)), key, "{key:?}");

    // The same must hold when the mark follows a base letter.
    let with_base = comparison_key("Α\u{0345}");
    assert_eq!(comparison_key(&with_base), with_base, "{with_base:?}");
    assert_eq!(
        comparison_key(&comparison_key(&with_base)),
        with_base,
        "{with_base:?}"
    );
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
    // Both sidebar-only filters must have a stable label (model.rs:851-862).
    assert_eq!(Filter::Favorites.label(&vault.folders), "お気に入り");
    assert_eq!(Filter::NoFolder.label(&vault.folders), "フォルダなし");
    // Labels do not depend on folder contents when the filter is not a folder.
    assert_eq!(Filter::Favorites.label(&[]), "お気に入り");
    assert_eq!(Filter::NoFolder.label(&[]), "フォルダなし");
}

#[test]
fn sort_key_next_cycles_through_all_four_variants() {
    // All four branches of `SortKey::next` (model.rs:881-888) must form one
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
    // (model.rs:1084-1087), and `Vault::view` normalizes the query the same way
    // (model.rs:972-978). NFD/uppercase spellings must therefore sort and
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
            text: String::new().into(),
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
fn login_uri_matches_host_starts_with_and_regex_modes() {
    let opts = openwarden::MatchOptions::default();

    // Host (wire 1): host and port must agree; subdomains and a downgraded
    // scheme do not match.
    let host = LoginUri {
        uri: "https://app.example.com:8443/login".into(),
        match_type: Some(1),
    };
    assert_eq!(host.match_enum(), Some(openwarden::UriMatch::Host));
    assert!(host.matches("https://app.example.com:8443/other", &opts));
    assert!(
        !host.matches("https://app.example.com/login", &opts),
        "a different port must not match"
    );
    assert!(!host.matches("https://evil-app.example.com:8443/login", &opts));
    assert!(!host.matches("http://app.example.com:8443/login", &opts));

    // StartsWith (wire 2): the page must begin with the URI at a boundary.
    let prefix = LoginUri {
        uri: "https://bank.example.com".into(),
        match_type: Some(2),
    };
    assert_eq!(prefix.match_enum(), Some(openwarden::UriMatch::StartsWith));
    assert!(prefix.matches("https://bank.example.com/login", &opts));
    assert!(prefix.matches("https://bank.example.com:8443/", &opts));
    assert!(!prefix.matches("https://bank.example.com.evil.net/", &opts));

    // RegularExpression (wire 4): regex is off by default, opt-in and
    // case-insensitive once enabled.
    let regex = LoginUri {
        uri: r"^https://[a-z]+\.example\.com/login$".into(),
        match_type: Some(4),
    };
    assert_eq!(
        regex.match_enum(),
        Some(openwarden::UriMatch::RegularExpression)
    );
    assert!(
        !regex.matches("https://app.example.com/login", &opts),
        "regex must stay inert unless explicitly enabled"
    );
    let regex_opts = openwarden::MatchOptions {
        allow_regex: true,
        ..Default::default()
    };
    assert!(regex.matches("https://app.example.com/login", &regex_opts));
    assert!(regex.matches("https://APP.EXAMPLE.COM/login", &regex_opts));
    assert!(!regex.matches("https://app.example.com/other", &regex_opts));
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
        private_key: String::new().into(),
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
fn ssh_fingerprint_works_without_an_optional_comment_field() {
    // `sha256_fingerprint` reads only the algorithm label and the base64 blob
    // (model.rs:469-476). OpenSSH's trailing comment is optional, so a
    // two-field line must yield the same fingerprint as the commented key.
    let blob = REFERENCE_PUBLIC_KEY.split_whitespace().nth(1).unwrap();
    let two_fields = format!("ssh-ed25519 {blob}");
    for line in [
        two_fields.as_str(),
        "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIMVYTn6DgHoRS29obD0RhrnbKgHhM1eqLvmbTWMGwSmR  ",
    ] {
        assert_eq!(
            super::ssh_fingerprint::sha256_fingerprint(line).as_deref(),
            Some(REFERENCE_FINGERPRINT),
            "line {line:?}"
        );
        let key = ssh_key(line, REFERENCE_FINGERPRINT);
        assert_eq!(
            key.verify_fingerprint(),
            FingerprintVerify::Match,
            "{line:?}"
        );
    }
}

#[test]
fn ssh_fingerprint_rejects_extra_base64_padding() {
    // Padding is optional, but a surplus `=` must not decode to the same blob:
    // otherwise distinct public-key lines would share one fingerprint
    // (model.rs:380-433).
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
    // character (model.rs:410-419). `AQ==` is canonical for byte 0x01, while
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
            text: String::new().into(),
        },
    ));
    vault.items.push(VaultItem::new(
        "a-decomposed",
        "A\u{0301}",
        ItemData::SecureNote {
            text: String::new().into(),
        },
    ));
    vault.items.push(VaultItem::new(
        "b-plain",
        "B",
        ItemData::SecureNote {
            text: String::new().into(),
        },
    ));

    let sorted = vault.view(&Filter::All, "", SortKey::NameAsc);
    let ids: Vec<&str> = sorted.iter().map(|item| item.id.as_str()).collect();
    assert_eq!(ids, vec!["a-full", "a-decomposed", "b-plain"]);
}

#[test]
fn notes_are_searchable_even_for_non_login_items() {
    // `haystacks` always includes `notes` (model.rs:754-759), so a free-form
    // note is findable regardless of the item's kind, including text that is
    // absent from the name and kind-specific fields.
    let mut item = VaultItem::new(
        "n-1",
        "Unrelated title",
        ItemData::SecureNote {
            text: "different body".into(),
        },
    );
    item.notes = Zeroizing::new("recovery-code-7X".to_string());
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
    // `matches_page` shares the `compare` tiebreak (model.rs:985-1005,1084-1087):
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
    // `haystacks` (model.rs:754-797) lists only non-secret kind-specific
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
    // Regression for model.rs:608-632: the manual `ItemData` Debug prints a
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
    // The address is a searchable identity field too (model.rs:779-790), but
    // it stays redacted in Debug (see `debug_masks_identity_and_uri_details`).
    assert!(identity.matches_query("maple avenue"));
    assert!(identity.matches_query("MAPLE"));

    let ssh = VaultItem::new(
        "s",
        "ssh-title",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: String::new().into(),
            fingerprint: "SHA256:abc".into(),
        }),
    );
    assert!(ssh.matches_query("SHA256:abc"));
}

#[test]
fn unset_or_foreign_format_fingerprints_are_reported_as_mismatch() {
    // Current contract: only an unparsable *public key* has a third outcome
    // (`InvalidPublicKey`). An empty or differently formatted stored
    // fingerprint is a string mismatch, with the recomputed SHA256 value
    // returned for diagnostics (model.rs:330-355).
    let expected = FingerprintVerify::Mismatch {
        computed: REFERENCE_FINGERPRINT.to_string(),
    };
    let lowercase_prefix = REFERENCE_FINGERPRINT.replace("SHA256:", "sha256:");
    for stored in ["", "  ", "MD5:aa:bb:cc", lowercase_prefix.as_str()] {
        let key = ssh_key(REFERENCE_PUBLIC_KEY, stored);
        assert_eq!(key.verify_fingerprint(), expected, "{stored:?}");
        assert!(!key.fingerprint_matches());
    }
    // Whitespace around a correct value is tolerated by the comparison.
    let padded = ssh_key(
        REFERENCE_PUBLIC_KEY,
        &format!("  {REFERENCE_FINGERPRINT}  "),
    );
    assert_eq!(padded.verify_fingerprint(), FingerprintVerify::Match);
}

#[test]
fn secure_note_debug_masks_the_note_text() {
    const SECRET: &str = "TOP SECRET NOTE TEXT";
    let item = VaultItem::new(
        "n",
        "Private note",
        ItemData::SecureNote {
            text: SECRET.into(),
        },
    );
    let data_debug = format!("{:?}", item.data);
    let item_debug = format!("{item:?}");
    let vault_debug = format!(
        "{:?}",
        Vault {
            items: vec![item],
            folders: Vec::new(),
        }
    );
    for rendered in [&data_debug, &item_debug, &vault_debug] {
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }
    // Search and serde still see the plain text: only Debug is masked.
    let note = VaultItem::new(
        "n",
        "Private note",
        ItemData::SecureNote {
            text: SECRET.into(),
        },
    );
    assert!(note.matches_query("TOP SECRET"));
    assert!(serde_json::to_string(&note).unwrap().contains(SECRET));
}

#[test]
fn an_item_with_multiple_uris_matches_any_of_them() {
    let item = VaultItem::new(
        "multi",
        "Multi",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![
                LoginUri {
                    uri: "https://one.example.com/login".into(),
                    match_type: Some(3),
                },
                LoginUri {
                    uri: "https://two.example.net/login".into(),
                    match_type: Some(3),
                },
                // `never` must not make the item match its own URI.
                LoginUri {
                    uri: "https://never.example.org/".into(),
                    match_type: Some(5),
                },
            ],
        },
    );
    let opts = openwarden::MatchOptions::default();
    assert!(item.matches_page("https://one.example.com/login", &opts));
    assert!(item.matches_page("https://two.example.net/login", &opts));
    assert!(!item.matches_page("https://never.example.org/", &opts));
    assert!(!item.matches_page("https://elsewhere.example.com/login", &opts));

    // A vault returns a multi-URI item once, not once per matching URI.
    let vault = Vault {
        items: vec![item],
        folders: Vec::new(),
    };
    let hits = vault.matches_page("https://two.example.net/login", &opts);
    assert_eq!(hits.len(), 1, "a matching item must not be duplicated");
    assert_eq!(hits[0].id, "multi");
}

#[test]
fn view_trims_surrounding_whitespace_from_the_query() {
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "Café", "user", "pw", "https://example.com"));

    // `Vault::view` trims the raw query before normalizing it (model.rs:973),
    // so a pasted value with stray whitespace behaves like the bare needle.
    for query in ["Café", "  Café  ", "\tCafé\n", "  CAFE\u{301}  "] {
        assert_eq!(
            vault.view(&Filter::All, query, SortKey::NameAsc).len(),
            1,
            "{query:?}"
        );
    }
    // A whitespace-only query is the empty needle: every item stays visible.
    assert_eq!(vault.view(&Filter::All, "   ", SortKey::NameAsc).len(), 1);
    assert!(vault
        .view(&Filter::All, "   tea   ", SortKey::NameAsc)
        .is_empty());
}

#[test]
fn ssh_fingerprint_rejects_insufficient_base64_padding() {
    // Padding is optional, but when it is present the run of `=` must match
    // the encoded byte count (model.rs:420-431). A partial run must not decode
    // to the same key blob as the canonical form.
    let canonical = super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQ== fp");
    assert!(canonical.is_some());
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQ= fp"),
        None,
        "one '=' for a one-byte blob is insufficient"
    );

    // Fully unpadded `AQ` is deliberately accepted and yields the same blob.
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQ fp"),
        canonical
    );
    // A two-byte blob still needs exactly one '=' when padding is used.
    assert!(super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQI= fp").is_some());
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQI== fp"),
        None
    );
}

#[test]
fn matches_query_trims_a_padded_needle_like_view() {
    let item = login("1", "Café", "user", "pw", "https://example.com");
    // A raw caller may copy a query with padding; `view()` trims it before
    // normalization (model.rs:972-973), so the public method must do the same.
    assert!(item.matches_query("  café \t"));
    assert!(item.matches_query(" \tCAFE\u{301}\n "));
    assert!(!item.matches_query("  tea  "));

    let mut vault = Vault::new();
    vault.items.push(item);
    // The normalized needle that view() passes in must survive a second
    // normalization without regaining the trimmed whitespace.
    assert_eq!(
        vault.view(&Filter::All, "  café  ", SortKey::NameAsc).len(),
        1
    );
}

#[test]
fn empty_and_whitespace_needles_match_every_item() {
    let item = login("1", "Café", "user", "pw", "https://example.com");
    // `matches_query` trims the raw needle before folding it (model.rs:805-810).
    // An empty needle is contained in every haystack, so a public caller that
    // bypasses `Vault::view` still sees every item for blank input.
    for needle in ["", " ", "   ", "\t", "\n", "\u{3000}", " \t\u{3000}\n "] {
        assert!(item.matches_query(needle), "needle {needle:?}");
    }

    let vault = Vault {
        items: vec![item],
        folders: Vec::new(),
    };
    // `Vault::view` short-circuits on the same empty needle instead of calling
    // `matches_query`; both paths must keep every item visible (model.rs:972-982).
    for needle in ["", "   ", "\u{3000}"] {
        assert_eq!(
            vault.view(&Filter::All, needle, SortKey::NameAsc).len(),
            1,
            "needle {needle:?}"
        );
    }
    // A non-blank needle still narrows the result, so this is not a blanket
    // "always true" branch.
    assert!(vault.view(&Filter::All, "tea", SortKey::NameAsc).is_empty());
}

#[test]
fn every_item_data_variant_round_trips_through_serde() {
    // Internally tagged `ItemData` must keep its `type` tag and every field —
    // especially the four non-Login payloads, whose newtype/struct variants
    // share the same wire shape (model.rs:576-606).
    let cases = [
        (
            "login",
            ItemData::Login {
                username: "alice".into(),
                password: Zeroizing::new("pw".into()),
                totp: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
                uris: vec![LoginUri::new("https://example.com")],
            },
        ),
        (
            "secure_note",
            ItemData::SecureNote {
                text: "private note".into(),
            },
        ),
        (
            "card",
            ItemData::Card(CardData {
                cardholder_name: "Alice".into(),
                brand: "Visa".into(),
                number: "4111111111111234".into(),
                exp_month: "12".into(),
                exp_year: "2030".into(),
                code: "987".into(),
            }),
        ),
        (
            "identity",
            ItemData::Identity(IdentityData {
                first_name: "Ada".into(),
                last_name: "Lovelace".into(),
                email: "ada@example.com".into(),
                phone: "090-1234".into(),
                address: "1 Maple Avenue".into(),
                company: "Analytical".into(),
            }),
        ),
        (
            "ssh_key",
            ItemData::SshKey(SshKeyData {
                public_key: "ssh-ed25519 AQ== fp".into(),
                private_key: "private-key-material".into(),
                fingerprint: "SHA256:fp".into(),
            }),
        ),
    ];

    for (expected_tag, data) in cases {
        let item = VaultItem::new("1", "Name", data);
        let json = serde_json::to_string(&item).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["data"]["type"], expected_tag, "{json}");
        let restored: VaultItem = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, item, "{json}");
        assert_eq!(restored.data.kind(), item.data.kind());
        // A second serialization must be stable, not lossy.
        assert_eq!(serde_json::to_string(&restored).unwrap(), json);
    }
}

#[test]
fn login_uri_match_enum_maps_every_wire_value() {
    // Every wire number must reach its own enum variant, not collapse into
    // the low-value defaults; pin each one and its serde form
    // (model.rs:169-189). Wire 3 and 5 are the upper-bound regressions: they
    // are the last two values `from_wire` accepts.
    for (wire, expected) in [
        (0, openwarden::UriMatch::Domain),
        (1, openwarden::UriMatch::Host),
        (2, openwarden::UriMatch::StartsWith),
        (3, openwarden::UriMatch::Exact),
        (4, openwarden::UriMatch::RegularExpression),
        (5, openwarden::UriMatch::Never),
    ] {
        let uri = LoginUri {
            uri: "https://example.com".into(),
            match_type: Some(wire),
        };
        assert_eq!(uri.match_enum(), Some(expected), "wire {wire}");
        assert_eq!(expected.to_wire(), wire);
        let json = serde_json::to_string(&uri).unwrap();
        let restored: LoginUri = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, uri, "{json}");
        assert_eq!(restored.match_enum(), Some(expected));
    }
    for unknown in [6u8, 255] {
        let uri = LoginUri {
            uri: "https://example.com".into(),
            match_type: Some(unknown),
        };
        assert_eq!(uri.match_enum(), None, "wire {unknown}");
    }
    assert_eq!(LoginUri::new("https://example.com").match_enum(), None);
}

#[test]
fn card_and_notes_secrets_keep_their_wire_and_length_shape() {
    // Both layers of redaction must survive the Zeroizing change: the manual
    // `CardData` / `VaultItem` Debug implementations mask the original text,
    // while search, character counts and serde still see it verbatim.
    let mut item = VaultItem::new(
        "zero-1",
        "Card",
        ItemData::Card(CardData {
            number: "4111 1111 1111 1234".into(),
            code: "987".into(),
            ..CardData::default()
        }),
    );
    item.notes = Zeroizing::new("recovery-code-7X".to_string());

    let debug = format!("{item:?}");
    assert!(!debug.contains("4111 1111 1111 1234"), "{debug}");
    assert!(!debug.contains("recovery-code-7X"), "{debug}");
    assert!(debug.contains("notes: \"[redacted]\""), "{debug}");

    let json = serde_json::to_value(&item).unwrap();
    assert_eq!(
        json["data"]["number"],
        serde_json::json!("4111 1111 1111 1234")
    );
    assert_eq!(json["data"]["code"], serde_json::json!("987"));
    assert_eq!(json["notes"], serde_json::json!("recovery-code-7X"));
    let restored: VaultItem = serde_json::from_value(json).unwrap();
    assert_eq!(restored, item);

    // UI consumers count characters and search the same text as before.
    let ItemData::Card(card) = &item.data else {
        panic!("fixture must be a card")
    };
    assert_eq!(card.number.len(), 19);
    assert_eq!(card.code.len(), 3);
    assert_eq!(item.notes.len(), 16);
    assert!(item.matches_query("recovery-code"));
}

#[test]
fn ssh_fingerprint_discards_the_key_type_field() {
    // `sha256_fingerprint` hashes only the decoded blob (the second
    // whitespace-separated field); the algorithm label is read and discarded
    // (model.rs:469-476). Re-labelling the same blob must not change the
    // computed fingerprint, even though OpenSSH itself would reject such a
    // line as inconsistent.
    let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIMVYTn6DgHoRS29obD0RhrnbKgHhM1eqLvmbTWMGwSmR";
    let canonical =
        super::ssh_fingerprint::sha256_fingerprint(&format!("ssh-ed25519 {blob} fp-test@example"));
    assert_eq!(canonical.as_deref(), Some(REFERENCE_FINGERPRINT));

    for key_type in ["ssh-rsa", "ecdsa-sha2-nistp256", "arbitrary-label"] {
        let relabelled =
            super::ssh_fingerprint::sha256_fingerprint(&format!("{key_type} {blob} comment"));
        assert_eq!(relabelled, canonical, "key_type {key_type:?}");
    }

    // Without a second field there is no blob to hash, regardless of label.
    assert_eq!(super::ssh_fingerprint::sha256_fingerprint(blob), None);
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519"),
        None
    );
}

#[test]
fn ssh_private_key_and_note_text_are_zeroized_with_unchanged_wire_and_debug() {
    const KEY_SECRET: &str = "PRIVATE-KEY-CANARY";
    const NOTE_SECRET: &str = "NOTE-TEXT-CANARY";
    let ssh = VaultItem::new(
        "ssh-zero",
        "Key",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: KEY_SECRET.into(),
            fingerprint: "SHA256:abc".into(),
        }),
    );
    let note = VaultItem::new(
        "note-zero",
        "Note",
        ItemData::SecureNote {
            text: NOTE_SECRET.into(),
        },
    );

    // Manual Debug masks both fields at every level; the type's own Debug
    // masks them even when rendered outside a VaultItem.
    for (item, secret) in [(&ssh, KEY_SECRET), (&note, NOTE_SECRET)] {
        let debug = format!("{item:?}");
        assert!(!debug.contains(secret), "{debug}");
        assert!(debug.contains("[redacted]"), "{debug}");
    }
    let ssh_data_debug = format!("{:?}", ssh.data);
    let note_data_debug = format!("{:?}", note.data);
    assert!(!ssh_data_debug.contains(KEY_SECRET), "{ssh_data_debug}");
    assert!(!note_data_debug.contains(NOTE_SECRET), "{note_data_debug}");

    // serde shape remains a plain JSON string, so older saves/fixtures round
    // trip and search still sees the text (only Debug is masked).
    let ssh_json = serde_json::to_value(&ssh).unwrap();
    let note_json = serde_json::to_value(&note).unwrap();
    assert_eq!(
        ssh_json["data"]["private_key"],
        serde_json::json!(KEY_SECRET)
    );
    assert_eq!(note_json["data"]["text"], serde_json::json!(NOTE_SECRET));
    let restored_ssh: VaultItem = serde_json::from_value(ssh_json).unwrap();
    let restored_note: VaultItem = serde_json::from_value(note_json).unwrap();
    assert_eq!(restored_ssh, ssh);
    assert_eq!(restored_note, note);
    assert!(restored_ssh.matches_query("SHA256:abc"));
    assert!(restored_note.matches_query("NOTE-TEXT"));
    assert!(!restored_ssh.matches_query(KEY_SECRET));
}

#[test]
fn card_haystack_needs_four_ascii_digits_and_ignores_fullwidth_digits() {
    let card_item = |number: &str| {
        VaultItem::new(
            "c",
            "Card",
            ItemData::Card(CardData {
                number: number.into(),
                ..CardData::default()
            }),
        )
    };

    // Fewer than four ASCII digits never contributes a searchable tail.
    for number in ["", "12", "1 2 3", "A1B2C3"] {
        assert!(!card_item(number).matches_query("123"), "{number:?}");
    }
    assert!(card_item("A1B2C3D4").matches_query("1234"));

    // Full-width digits are not ASCII digits: the filter skips them, so an
    // NFKD-foldable full-width PAN cannot be fished out through search.
    let wide = card_item("４１１１１１１１１１１１１２３４");
    assert!(
        !wide.matches_query("1234"),
        "a full-width PAN must not expose a searchable last four"
    );
    assert!(!wide.matches_query("４１２３"));

    // A mixed number exposes only the ASCII last four.
    let mixed = card_item("4111 ３３３３ 1234");
    assert!(mixed.matches_query("1234"));
    assert!(
        !mixed.matches_query("3333"),
        "full-width middle stays private"
    );
}

#[test]
fn ssh_base64_codec_handles_plus_and_slash() {
    use super::ssh_fingerprint::{decode, encode};

    // Three bytes whose six-bit groups are 62 ('+') and 63 ('/').
    let raw = [0xfb, 0xff, 0xbf];
    assert_eq!(encode(&raw), "+/+/");
    assert_eq!(decode(b"+/+/"), Some(raw.to_vec()));

    // A padded multi-group value with both characters must round-trip.
    let digest = [0xfb, 0xff, 0xbf, 0x00, 0x10];
    let encoded = encode(&digest);
    assert!(encoded.contains('+') && encoded.contains('/'), "{encoded}");
    assert_eq!(decode(encoded.as_bytes()), Some(digest.to_vec()));

    // The URL-safe alphabet is not a substitute for standard base64.
    assert_eq!(decode(b"-__/"), None);
    assert_eq!(decode(b"+_+/"), None);
}

#[test]
fn ssh_base64_encode_one_byte_remainder_uses_two_chars_and_double_padding() {
    use super::ssh_fingerprint::{decode, encode};

    // model.rs:444-449: a single leftover byte takes the `[a]` arm, emitting
    // two alphabet characters followed by `==`. A wrapping or 3-byte-only
    // implementation would drop the byte or produce the wrong padding.
    assert_eq!(encode(&[]), "");
    assert_eq!(encode(&[0x00]), "AA==");
    assert_eq!(encode(&[0xff]), "/w==");
    for raw in [[0x00u8], [0x01], [0x7f], [0x80], [0xfe], [0xff]] {
        let encoded = encode(&raw);
        assert_eq!(encoded.len(), 4, "{encoded}");
        assert!(encoded.ends_with("=="), "{encoded}");
        assert_eq!(decode(encoded.as_bytes()), Some(raw.to_vec()), "{encoded}");
    }
    // The neighbouring remainder arms stay distinct (two bytes -> one '=',
    // three bytes -> no padding), so the one-byte arm cannot swallow them.
    assert_eq!(encode(&[0x01, 0x02]), "AQI=");
    assert_eq!(encode(&[0x01, 0x02, 0x03]), "AQID");
}

#[test]
fn vault_item_debug_shows_non_secret_metadata_and_masks_notes() {
    // model.rs:672-686 prints every non-secret metadata field verbatim while
    // replacing the secret-bearing notes wholesale. Diagnostics must stay
    // useful (id / folder / favorite / revision) without revealing notes.
    let mut item = VaultItem::new(
        "item-42",
        "Visible Name",
        ItemData::Login {
            username: "alice".into(),
            password: Zeroizing::new("pw-secret".into()),
            totp: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
            uris: vec![],
        },
    );
    item.folder_id = Some("folder-7".into());
    item.favorite = true;
    item.revision_date = 1_700_000_000;
    item.notes = Zeroizing::new("RECOVERY-NOTE-SECRET".into());

    let debug = format!("{item:?}");
    for visible in [
        "VaultItem",
        "item-42",
        "Visible Name",
        "folder-7",
        "favorite: true",
        "revision_date: 1700000000",
        "notes: \"[redacted]\"",
    ] {
        assert!(debug.contains(visible), "missing {visible:?}: {debug}");
    }
    assert!(!debug.contains("RECOVERY-NOTE-SECRET"), "{debug}");
    assert!(!debug.contains("pw-secret"), "{debug}");
    assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "{debug}");
}

#[test]
fn item_kind_uses_snake_case_strings_on_the_wire() {
    // `ItemKind` derives `#[serde(rename_all = "snake_case")]` (model.rs:115-117):
    // its serde form is a string, not the numeric `to_wire()` value.
    for (kind, text) in [
        (ItemKind::Login, "login"),
        (ItemKind::SecureNote, "secure_note"),
        (ItemKind::Card, "card"),
        (ItemKind::Identity, "identity"),
        (ItemKind::SshKey, "ssh_key"),
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, format!("\"{text}\""), "{kind:?}");
        let restored: ItemKind = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, kind);
        assert_eq!(kind.label(), restored.label());
    }
    assert!(serde_json::from_str::<ItemKind>("1").is_err());
    assert!(serde_json::from_str::<ItemKind>("\"Login\"").is_err());
    assert!(serde_json::from_str::<ItemKind>("\"unknown\"").is_err());
}

#[test]
fn debug_distinguishes_an_empty_totp_from_a_populated_one() {
    // The manual `ItemData` Debug (model.rs:608-632) prints an empty string
    // for an unset TOTP and a redaction marker for a set one.
    let mut item = login("1", "Sample", "alice", "pw", "https://example.com");
    assert_eq!(item.totp_secret(), Some(""));
    let empty = format!("{item:?}");
    assert!(empty.contains("totp: \"\""), "{empty}");
    assert!(!empty.contains("totp: \"[redacted]\""), "{empty}");

    if let ItemData::Login { totp, .. } = &mut item.data {
        *totp = Zeroizing::new("JBSWY3DPEHPK3PXP".to_string());
    }
    let populated = format!("{item:?}");
    assert!(populated.contains("totp: \"[redacted]\""), "{populated}");
    assert!(!populated.contains("JBSWY3DPEHPK3PXP"), "{populated}");
    assert!(!populated.contains("totp: \"\""), "{populated}");
}

#[test]
fn an_unknown_folder_id_is_never_counted_but_still_filters() {
    // `folder_counts` walks the declared folders (model.rs:935-947), so a
    // dangling `folder_id` is never materialised as a bucket and its item is
    // counted nowhere. `Filter::Folder`, however, compares the raw id, so the
    // item stays reachable through that filter and the label degrades
    // gracefully (model.rs:851-862).
    let mut vault = Vault::new();
    vault.folders = vec![
        Folder {
            id: "f1".into(),
            name: "仕事".into(),
        },
        Folder {
            id: "f2".into(),
            name: "私用".into(),
        },
    ];
    let mut in_f1 = login("1", "In f1", "a", "pw", "https://one.example.com");
    in_f1.folder_id = Some("f1".into());
    let mut orphan = login("2", "Orphan", "b", "pw", "https://two.example.com");
    orphan.folder_id = Some("ghost".into());
    let loose = login("3", "Loose", "c", "pw", "https://three.example.com");
    vault.items = vec![in_f1, orphan, loose];

    assert_eq!(
        vault.folder_counts(),
        vec![("f1".to_string(), 1), ("f2".to_string(), 0)]
    );
    assert_eq!(vault.folder_name("ghost"), None);
    assert_eq!(vault.len(), 3, "a dangling id must not drop the item");

    let ghost = Filter::Folder("ghost".into());
    assert!(ghost.accepts(vault.item("2").unwrap()));
    assert!(!ghost.accepts(vault.item("3").unwrap()));
    assert!(!Filter::NoFolder.accepts(vault.item("2").unwrap()));
    assert!(Filter::NoFolder.accepts(vault.item("3").unwrap()));
    assert_eq!(ghost.label(&vault.folders), "(不明なフォルダ)");

    let shown = vault.view(&ghost, "", SortKey::NameAsc);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].id, "2");
}

#[test]
fn zeroizing_text_display_prints_the_plain_text_while_debug_masks_it() {
    let secret = ZeroizingText::new("plain-text-secret");
    // Display is the rendering path and deliberately exposes the plaintext;
    // only Debug is masked (model.rs:245-255). The split is pinned so a future
    // "safety" change cannot silently break status/search text.
    assert_eq!(secret.as_str(), "plain-text-secret");
    assert_eq!(secret.to_string(), "plain-text-secret");
    assert_eq!(format!("{secret}"), "plain-text-secret");
    assert_eq!(format!("{secret:?}"), "[redacted]");
    assert_eq!(secret, ZeroizingText::from("plain-text-secret"));

    // A field using the serde adapter keeps the same split: JSON holds the
    // plain string, Debug prints only the marker.
    let note = VaultItem::new(
        "n",
        "Note",
        ItemData::SecureNote {
            text: ZeroizingText::new("NOTE-PLAINTEXT"),
        },
    );
    assert!(!format!("{note:?}").contains("NOTE-PLAINTEXT"));
    assert!(serde_json::to_string(&note)
        .unwrap()
        .contains("NOTE-PLAINTEXT"));
}

#[test]
fn item_data_rejects_an_unknown_or_missing_type_tag() {
    // `ItemData` is internally tagged with `type` (model.rs:576-578), so both
    // an unknown tag and a missing tag must be rejected instead of falling
    // back to a variant with default fields.
    for body in [
        r#"{"type":"unknown","text":"x"}"#,
        r#"{"type":"Login","username":"a","password":"p","totp":"","uris":[]}"#,
        r#"{"text":"x"}"#,
        r#"{}"#,
    ] {
        assert!(
            serde_json::from_str::<ItemData>(body).is_err(),
            "unexpectedly accepted {body}"
        );
    }
    // A known tag with the right payload still loads, so the rejection above
    // is about the tag rather than all deserialization.
    let data: ItemData = serde_json::from_str(r#"{"type":"secure_note","text":"x"}"#)
        .expect("a known tag must load");
    assert_eq!(
        serde_json::to_value(&data).unwrap()["type"],
        serde_json::json!("secure_note")
    );
}

#[test]
fn duplicate_names_ignore_surrounding_whitespace_differences() {
    // `duplicate_names` compares `comparison_key(item.name.trim())`
    // (model.rs:1063-1081), so padding a name with ASCII or Unicode whitespace
    // must not split it into a separate group.
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "  GitHub  ", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("2", "GitHub", "u", "p", "https://b.example"));
    vault.items.push(login(
        "3",
        "\u{3000}github\u{3000}",
        "u",
        "p",
        "https://c.example",
    ));

    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "github");
    assert_eq!(
        groups[0].1,
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    );
}

#[test]
fn ssh_key_debug_keeps_the_public_key_and_fingerprint() {
    // `SshKeyData`'s manual Debug masks only `private_key`; the two public
    // fields stay visible for diagnostics (model.rs:514-522).
    let key = SshKeyData {
        private_key: "PRIVATE-KEY-CANARY".into(),
        ..ssh_key(REFERENCE_PUBLIC_KEY, REFERENCE_FINGERPRINT)
    };
    let debug = format!("{key:?}");
    assert!(debug.contains("SshKeyData"), "{debug}");
    assert!(debug.contains("public_key"), "{debug}");
    assert!(debug.contains(REFERENCE_PUBLIC_KEY), "{debug}");
    assert!(debug.contains("fingerprint"), "{debug}");
    assert!(debug.contains(REFERENCE_FINGERPRINT), "{debug}");
    assert!(debug.contains("private_key: \"[redacted]\""), "{debug}");
    assert!(!debug.contains("PRIVATE-KEY-CANARY"), "{debug}");
}

#[test]
fn zeroizing_text_derefs_and_borrows_as_str() {
    // model.rs:231-243: `Deref<Target = str>` and `AsRef<str>` are the two
    // read paths a caller gets for free; only `Debug` is masked. Pinning them
    // keeps generic helpers that accept `AsRef<str>` working on secret fields.
    let text = ZeroizingText::new("abcあ");
    let via_deref: &str = &text;
    assert_eq!(via_deref, "abcあ");
    assert_eq!(text.chars().count(), 4, "str methods work through Deref");
    assert_eq!(text.len(), 6, "str::len is byte length, not char count");
    let via_as_ref: &str = AsRef::<str>::as_ref(&text);
    assert_eq!(via_as_ref, text.as_str());

    fn char_count<T: AsRef<str>>(value: &T) -> usize {
        value.as_ref().chars().count()
    }
    assert_eq!(char_count(&text), 4);
    assert_eq!(format!("{}", text), text.as_str());
    assert_eq!(format!("{:?}", text), "[redacted]");

    // The same contract holds for the empty default and for `From<String>`.
    let empty = ZeroizingText::default();
    assert_eq!(&*empty, "");
    assert_eq!(AsRef::<str>::as_ref(&empty), "");
    let owned = ZeroizingText::from(String::from("owned"));
    assert_eq!(&*owned, "owned");
    assert_eq!(char_count(&owned), 5);
}

#[test]
fn upsert_replaces_only_the_first_duplicate_id_but_remove_deletes_them_all() {
    // model.rs:1032-1058: `upsert` uses `iter_mut().find(...)`, while `remove`
    // uses `retain(...)`. Pre-existing duplicate ids (possible when a caller
    // pushes directly into `items`) therefore behave asymmetrically.
    let mut vault = Vault::new();
    let first = login("dup", "First", "u", "p1", "https://one.example");
    let mut second = login("dup", "Second", "u", "p2", "https://two.example");
    second.revision_date = 7;
    vault.items.push(first);
    vault.items.push(second);
    assert_eq!(vault.len(), 2);
    assert_eq!(vault.item("dup").unwrap().name, "First");

    let mut replacement = login("dup", "Replacement", "u", "p3", "https://three.example");
    replacement.revision_date = 9;
    vault.upsert(replacement);
    assert_eq!(
        vault.len(),
        2,
        "upsert must not collapse existing duplicates"
    );
    assert_eq!(vault.item("dup").unwrap().name, "Replacement");
    let names: Vec<&str> = vault.items.iter().map(|item| item.name.as_str()).collect();
    assert_eq!(names, vec!["Replacement", "Second"]);
    assert_eq!(vault.items[0].revision_date, 9);
    assert_eq!(
        vault.items[1].revision_date, 7,
        "the second row is untouched"
    );

    // A zero revision on the replacement still keeps the first row's revision,
    // and the duplicate row is still present afterwards.
    let mut metadata_only = login("dup", "Metadata", "u", "p4", "https://four.example");
    metadata_only.revision_date = UNKNOWN_REVISION;
    vault.upsert(metadata_only);
    assert_eq!(vault.items[0].revision_date, 9);
    assert_eq!(vault.len(), 2);

    // `remove` is id-based and removes every matching row in one call.
    assert!(vault.remove("dup"));
    assert!(vault.items.is_empty());
    assert!(vault.item("dup").is_none());
    assert!(!vault.remove("dup"), "a second removal reports no match");
}

#[test]
fn mask_uri_drops_fragment_tokens() {
    // `mask_uri` (model.rs:86-112) keeps only scheme + host + port, so an
    // OAuth token in the fragment cannot reach a report or a Debug line.
    assert_eq!(
        mask_uri("https://example.com/cb#access_token=FRAGMENT_TOKEN&state=ok"),
        "https://example.com"
    );
    assert_eq!(
        mask_uri("https://example.com:8443/cb#code=FRAGMENT_CODE"),
        "https://example.com:8443"
    );
    // A '?' after '#' belongs to the fragment, not to a query.
    assert_eq!(
        mask_uri("https://user:secret@example.com/cb#next=1?token=FRAG_LATE_TOKEN"),
        "https://example.com"
    );

    // Only presentation is masked: the raw URI stays in the search haystack.
    let item = login(
        "1",
        "CB",
        "u",
        "p",
        "https://example.com/cb#token=RAW_FRAGMENT_TOKEN",
    );
    assert!(item.matches_query("RAW_FRAGMENT_TOKEN"));
    assert!(!format!("{item:?}").contains("RAW_FRAGMENT_TOKEN"));
}

#[test]
fn vault_item_kind_follows_the_data_payload() {
    // `VaultItem::kind` (model.rs:702-705) delegates to `ItemData::kind`
    // (model.rs:634-645); both must agree for every payload variant.
    let cases = [
        (
            login("1", "Login", "u", "p", "https://example.com"),
            ItemKind::Login,
        ),
        (
            VaultItem::new(
                "2",
                "Note",
                ItemData::SecureNote {
                    text: "body".into(),
                },
            ),
            ItemKind::SecureNote,
        ),
        (
            VaultItem::new("3", "Card", ItemData::Card(CardData::default())),
            ItemKind::Card,
        ),
        (
            VaultItem::new("4", "Id", ItemData::Identity(IdentityData::default())),
            ItemKind::Identity,
        ),
        (
            VaultItem::new("5", "SSH", ItemData::SshKey(SshKeyData::default())),
            ItemKind::SshKey,
        ),
    ];
    assert_eq!(cases.len(), 5);
    for (item, expected) in cases {
        assert_eq!(item.kind(), expected, "{}", item.id);
        assert_eq!(item.data.kind(), expected, "{}", item.id);
    }
}
