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

/// A vault with one Login, one Card and one Identity (no SecureNote or
/// SshKey), each carrying `alice` in a searchable field, used to pin
/// filter/query intersection and kind counts.
fn mixed_kinds() -> Vault {
    let mut vault = Vault::new();
    vault.items = vec![
        login("l", "Login", "alice", "pw", "https://example.com"),
        VaultItem::new(
            "c",
            "Card",
            ItemData::Card(CardData {
                cardholder_name: "Alice Cardholder".into(),
                number: "4111111111111234".into(),
                ..CardData::default()
            }),
        ),
        VaultItem::new(
            "i",
            "Identity",
            ItemData::Identity(IdentityData {
                first_name: "Alice".into(),
                ..IdentityData::default()
            }),
        ),
    ];
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
fn item_kind_wire_numbers_are_one_through_five() {
    // Bitwarden's `type` field uses 1..=5 (model.rs:198-248). Pin each exact
    // number in both directions; the sibling round-trip test only proves the
    // two functions are inverses, so a simultaneous shift of every value
    // would go unnoticed there.
    for (number, kind) in [
        (1u8, ItemKind::Login),
        (2, ItemKind::SecureNote),
        (3, ItemKind::Card),
        (4, ItemKind::Identity),
        (5, ItemKind::SshKey),
    ] {
        assert_eq!(kind.to_wire(), number, "{kind:?}");
        assert_eq!(ItemKind::from_wire(number), Some(kind), "wire {number}");
    }
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
fn view_ands_the_filter_and_the_query() {
    // `Vault::view` (model.rs:977-987) chains two `.filter()` calls: an item
    // must pass `Filter::accepts` AND match the normalized query. With three
    // different kinds all matching "alice", the kind filter has to do real
    // work on top of the query instead of being ignored.
    let vault = mixed_kinds();
    let ids = |filter: &Filter, query: &str| -> Vec<String> {
        vault
            .view(filter, query, SortKey::NameAsc)
            .iter()
            .map(|item| item.id.clone())
            .collect()
    };

    assert_eq!(ids(&Filter::All, "alice"), vec!["c", "i", "l"]);
    assert_eq!(ids(&Filter::Kind(ItemKind::Login), "alice"), vec!["l"]);
    assert_eq!(ids(&Filter::Kind(ItemKind::Card), "alice"), vec!["c"]);
    assert_eq!(ids(&Filter::Kind(ItemKind::Identity), "alice"), vec!["i"]);
    assert!(ids(&Filter::Kind(ItemKind::SshKey), "alice").is_empty());

    // A query that only the filtered-out kinds can answer must produce no
    // hits: the last four digits are searchable on the card, not the login.
    assert_eq!(ids(&Filter::All, "1234"), vec!["c"]);
    assert!(ids(&Filter::Kind(ItemKind::Login), "1234").is_empty());
    assert!(
        ids(&Filter::Favorites, "alice").is_empty(),
        "no favorites here"
    );

    // The same AND rule holds for the folder and no-folder filters, and the
    // query alone must still be able to find every item.
    let mut folder_vault = mixed_kinds();
    folder_vault.items[0].folder_id = Some("f1".into());
    let ids = |filter: &Filter, query: &str| -> Vec<String> {
        folder_vault
            .view(filter, query, SortKey::NameAsc)
            .iter()
            .map(|item| item.id.clone())
            .collect()
    };
    assert_eq!(ids(&Filter::Folder("f1".into()), "alice"), vec!["l"]);
    assert_eq!(ids(&Filter::NoFolder, "alice"), vec!["c", "i"]);
    assert!(ids(&Filter::Folder("missing".into()), "alice").is_empty());
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
fn recently_modified_breaks_equal_revision_ties_by_name_then_id() {
    // `compare` orders `RecentlyModified` by revision descending, then reuses
    // the un-reversed `name + id` ordering (model.rs:1215-1225). With equal
    // revisions the folded name must win first and the id must break an
    // exactly equal name, regardless of insertion order.
    let mut vault = Vault::new();
    let mut z_alpha = login("z-id", "Alpha", "u", "p", "https://z.example");
    z_alpha.revision_date = 100;
    let mut a_beta = login("a-id", "Beta", "u", "p", "https://a.example");
    a_beta.revision_date = 100;
    let mut m_alpha = login("m-id", "Alpha", "u", "p", "https://m.example");
    m_alpha.revision_date = 100;
    let mut newest = login("n-id", "Zulu", "u", "p", "https://n.example");
    newest.revision_date = 200;
    // Deliberately out of sort order.
    vault.items = vec![z_alpha, a_beta, m_alpha, newest];

    let ids: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::RecentlyModified)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    // The newer revision wins even though its name sorts last; among the
    // three tied items "Alpha" precedes "Beta", and the two "Alpha" rows
    // fall back to ascending ids ("m-id" < "z-id").
    assert_eq!(ids, vec!["n-id", "m-id", "z-id", "a-id"]);
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
fn default_domain_match_covers_subdomains_but_not_lookalikes() {
    // A `LoginUri` without an explicit match type uses
    // `MatchOptions::default_match` (Domain), as in Bitwarden. A login stored
    // for a registrable domain is therefore offered on its subdomains too.
    let uri = LoginUri::new("https://example.com/login");
    assert_eq!(
        uri.match_enum(),
        None,
        "precondition: no explicit match type"
    );
    let opts = openwarden::MatchOptions::default();
    assert_eq!(opts.default_match, openwarden::UriMatch::Domain);

    assert!(uri.matches("https://www.example.com/dashboard", &opts));
    assert!(uri.matches("https://a.b.example.com/other", &opts));
    // The default strict_scheme still refuses an https login on an http page.
    assert!(!uri.matches("http://www.example.com/", &opts));
    // Neither a lookalike nor a sibling registrable domain shares the base.
    assert!(!uri.matches("https://example.com.evil.net/", &opts));
    assert!(!uri.matches("https://notexample.com/", &opts));

    // Both `matches_page` entry points reach the same default-domain rule.
    let item = VaultItem::new(
        "default-domain",
        "Example",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![LoginUri::new("https://example.com/login")],
        },
    );
    assert!(item.matches_page("https://sub.example.com/dashboard", &opts));
    let vault = Vault {
        items: vec![item],
        folders: Vec::new(),
    };
    let hits = vault.matches_page("https://sub.example.com/dashboard", &opts);
    assert_eq!(hits.len(), 1, "an item must not be duplicated per URI");
    assert_eq!(hits[0].id, "default-domain");
    assert!(vault
        .matches_page("https://sub.example.com.evil.net/", &opts)
        .is_empty());
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
fn duplicate_names_ignore_rows_with_the_same_id() {
    // The ids in a group are deduplicated (model.rs:1156-1180), so two raw
    // rows with one id cannot masquerade as a name collision. A group of two
    // *distinct* ids with the same name must still be reported.
    let mut vault = Vault::new();
    vault
        .items
        .push(login("same", "shared", "a", "pw", "https://a.example"));
    vault
        .items
        .push(login("same", "SHARED", "b", "pw", "https://b.example"));
    assert!(
        vault.duplicate_names().is_empty(),
        "one id is not a duplicate name: {:?}",
        vault.duplicate_names()
    );

    vault
        .items
        .push(login("other", "Shared", "c", "pw", "https://c.example"));
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "shared");
    assert_eq!(groups[0].1, vec!["same".to_string(), "other".to_string()]);
}

#[test]
fn toggle_favorite_returns_false_when_it_turns_an_item_off() {
    // The return value is the new flag, so an item that was already a favorite
    // must yield `Some(false)` (model.rs:1012-1017) - not `None`, which is
    // reserved for an unknown id.
    let mut vault = sample();
    let target = vault
        .items
        .iter()
        .find(|item| item.favorite)
        .expect("sample() must contain a favorite")
        .id
        .clone();
    assert_eq!(vault.toggle_favorite(&target), Some(false));
    assert!(!vault.item(&target).unwrap().favorite);
    assert_eq!(vault.toggle_favorite(&target), Some(true));
    assert!(vault.item(&target).unwrap().favorite);
    assert_eq!(vault.toggle_favorite("missing"), None);
    assert_eq!(vault.toggle_favorite(""), None);
}

#[test]
fn duplicate_id_mutations_touch_only_the_first_row_and_favorite_count_follows() {
    // `item`, `toggle_favorite` and `set_folder` all resolve an id with
    // `iter().find()` (model.rs:1013-1033), so two raw rows sharing one id
    // expose only the first row to those mutations. `favorite_count`
    // (model.rs:971-974) counts rows, so it must track the first row's flag
    // after every toggle even though the duplicate stays untouched.
    let mut vault = Vault::new();
    vault.folders = vec![
        Folder {
            id: "f1".into(),
            name: "F1".into(),
        },
        Folder {
            id: "f2".into(),
            name: "F2".into(),
        },
    ];
    let mut first = login("dup", "First", "u", "p", "https://first.example");
    first.folder_id = Some("f1".into());
    let mut second = login("dup", "Second", "v", "p", "https://second.example");
    second.favorite = true;
    second.folder_id = Some("f2".into());
    // The duplicate is kept raw on purpose: the importer normally dedups by
    // id, but the model's id helpers must still behave predictably here.
    vault.items = vec![first, second];

    assert_eq!(vault.items.len(), 2);
    assert_eq!(vault.item("dup").expect("first row").name, "First");
    assert_eq!(
        vault.favorite_count(),
        1,
        "only the second row is a favorite"
    );

    assert_eq!(vault.toggle_favorite("dup"), Some(true));
    assert!(vault.items[0].favorite, "first row toggled on");
    assert!(vault.items[1].favorite, "second row is untouched");
    assert_eq!(vault.items[1].name, "Second");
    assert_eq!(vault.favorite_count(), 2, "the count follows the toggle");

    assert_eq!(vault.toggle_favorite("dup"), Some(false));
    assert!(!vault.items[0].favorite, "first row toggled off");
    assert!(vault.items[1].favorite, "second row stays untouched");
    assert_eq!(vault.favorite_count(), 1);

    assert!(vault.set_folder("dup", None));
    assert_eq!(vault.items[0].folder_id, None);
    assert_eq!(vault.items[1].folder_id.as_deref(), Some("f2"));
    assert_eq!(
        vault.folder_counts(),
        vec![("f1".to_string(), 0), ("f2".to_string(), 1)]
    );

    assert!(vault.set_folder("dup", Some("f2".into())));
    assert_eq!(vault.items[0].folder_id.as_deref(), Some("f2"));
    assert_eq!(vault.items[1].folder_id.as_deref(), Some("f2"));
    assert_eq!(
        vault.folder_counts(),
        vec![("f1".to_string(), 0), ("f2".to_string(), 2)]
    );
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
    // not claim a complete Unicode full case fold (model.rs:35-45): only the
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
    // loop (model.rs:86-96) must leave the folded key unchanged on a second
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
fn comparison_key_trims_whitespace_revealed_by_invisible_characters() {
    // Trimming the raw input first let a leading/trailing `Cf`/`Cc` shield the
    // whitespace next to it: `fold_once` then dropped the invisible character
    // and left a trailing space in the key (model.rs:96-110). The fold must
    // now happen before the trim so padded and bare spellings agree.
    assert_eq!(comparison_key("GitHub"), "github");
    assert_eq!(comparison_key("GitHub \u{200b}"), "github");
    assert_eq!(comparison_key("\u{200b} GitHub"), "github");
    // NUL is a `Cc`, not whitespace: `str::trim()` cannot remove it either.
    assert_eq!(comparison_key(" GitHub \u{0}"), "github");
    // A name that is whitespace plus invisible characters only is blank.
    assert_eq!(comparison_key("\u{200b} \u{200b}"), "");
    assert_eq!(comparison_key("\u{200d}\u{200f} \t"), "");
    for value in ["GitHub \u{200b}", "\u{200b} GitHub", " GitHub \u{0}"] {
        assert_eq!(
            comparison_key(&comparison_key(value)),
            comparison_key(value)
        );
    }

    // All three consumers of the key agree: duplicate detection, search and
    // sorting. A padded name must be a duplicate of the bare spelling and a
    // padded needle must still find both.
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "GitHub \u{200b}", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("2", "github", "u", "p", "https://b.example"));
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].1, vec!["1".to_string(), "2".to_string()]);
    assert_eq!(
        vault.view(&Filter::All, "github", SortKey::NameAsc).len(),
        2
    );
    assert_eq!(
        vault
            .view(&Filter::All, "github \u{200b}", SortKey::NameAsc)
            .len(),
        2
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
fn filter_and_sort_key_defaults_are_all_items_name_ascending() {
    // Both enums derive `Default` by marking their first variant with
    // `#[default]` (model.rs:923-936 and 966-977). The UI's zero-argument
    // default must therefore be the widest filter and the ascending name sort,
    // not a narrower filter or a different ordering.
    assert_eq!(Filter::default(), Filter::All);
    assert_eq!(SortKey::default(), SortKey::NameAsc);
    // The explicit `Default::default()` path agrees with the inherent call.
    let filter: Filter = Default::default();
    let sort: SortKey = Default::default();
    assert_eq!(filter, Filter::All);
    assert_eq!(sort, SortKey::NameAsc);
    assert_ne!(Filter::default(), Filter::Favorites);
    assert_ne!(SortKey::default(), SortKey::NameDesc);
    // The labels pin the user-visible meaning of the two default variants.
    assert_eq!(Filter::default().label(&[]), "すべてのアイテム");
    assert_eq!(SortKey::default().label(), "名前 ↑");
}

#[test]
fn view_sorting_uses_comparison_keys_for_names() {
    // `compare()` normalizes both names with `comparison_key` before ordering
    // (model.rs:1174-1184), and `Vault::view` normalizes the query the same way
    // (model.rs:1039-1041). NFD/uppercase spellings must therefore sort and
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
fn kind_and_recently_modified_tiebreaks_use_unicode_comparison_keys() {
    // Once the primary key ties (same kind, or same revision), `compare`
    // reuses the folded name + id ordering. Full-width and ASCII spellings
    // must order by their NFKD/lowercase key, not by raw UTF-8 bytes.
    let mut vault = Vault::new();
    let item = |id: &str, name: &str, revision: i64| {
        let mut value = login(id, name, "u", "p", "https://example.test");
        value.revision_date = revision;
        value
    };
    vault.items = vec![
        item("id-1", "Ｚ", 100), // full-width Z -> key "z"
        item("id-2", "A", 100),
        item("id-3", "ａ", 100), // full-width a -> key "a"
        item("id-4", "a", 100),
    ];

    // Guard the premise: raw byte order would be A < a < Ｚ < ａ, which is not
    // the stored order and not the folded-key order asserted below.
    let raw: Vec<&str> = vault.items.iter().map(|item| item.name.as_str()).collect();
    let mut raw_sorted = raw.clone();
    raw_sorted.sort_unstable();
    assert_ne!(raw_sorted, raw, "fixture must distinguish raw from folded");

    let ids = |sort| -> Vec<&str> {
        vault
            .view(&Filter::All, "", sort)
            .iter()
            .map(|item| item.id.as_str())
            .collect()
    };
    // All four items are logins and share one revision, so both keys reduce
    // to the same folded-name + id tiebreak.
    let expected = vec!["id-2", "id-3", "id-4", "id-1"];
    assert_eq!(ids(SortKey::Kind), expected, "{:?}", raw_sorted);
    assert_eq!(ids(SortKey::RecentlyModified), expected, "{:?}", raw_sorted);
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
    // Card and Identity occupy fixed slots in the returned vector even when
    // the vault has none (model.rs:954-969).
    assert_eq!(counts[2], (ItemKind::Card, 0));
    assert_eq!(counts[3], (ItemKind::Identity, 0));
    assert_eq!(counts[4], (ItemKind::SshKey, 0));
}

#[test]
fn kind_counts_counts_card_and_identity_items() {
    // Non-zero Card/Identity counts must come from the item's `kind()`, not
    // from its name or data layout. Add a second card and an item of another
    // kind to prove each bucket counts independently.
    let mut vault = mixed_kinds();
    vault.items.push(VaultItem::new(
        "c2",
        "Second card",
        ItemData::Card(CardData::default()),
    ));
    vault.items.push(VaultItem::new(
        "s",
        "SSH key",
        ItemData::SshKey(SshKeyData::default()),
    ));

    let counts = vault.kind_counts();
    assert_eq!(counts.len(), 5);
    assert_eq!(counts[0], (ItemKind::Login, 1));
    assert_eq!(counts[1], (ItemKind::SecureNote, 0));
    assert_eq!(counts[2], (ItemKind::Card, 2), "both Card items counted");
    assert_eq!(counts[3], (ItemKind::Identity, 1));
    assert_eq!(counts[4], (ItemKind::SshKey, 1));
    assert_eq!(
        counts.iter().map(|&(_, count)| count).sum::<usize>(),
        vault.items.len()
    );

    // Removing the identity drops only its bucket.
    assert!(vault.remove("i"));
    let counts = vault.kind_counts();
    assert_eq!(counts[3], (ItemKind::Identity, 0));
    assert_eq!(counts[2], (ItemKind::Card, 2));
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
    // (model.rs:456-509).
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
fn non_default_vault_item_metadata_survives_a_serde_round_trip() {
    let mut item = login("meta-1", "Metadata", "alice", "p", "https://example.test");
    item.folder_id = Some("folder-42".to_string());
    item.favorite = true;
    item.notes = Zeroizing::new("recovery-code-7X".to_string());
    item.revision_date = 1_700_000_123;

    let json = serde_json::to_string(&item).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["folder_id"], serde_json::json!("folder-42"));
    assert_eq!(value["favorite"], serde_json::json!(true));
    assert_eq!(value["notes"], serde_json::json!("recovery-code-7X"));
    assert_eq!(value["revision_date"], serde_json::json!(1_700_000_123));

    let restored: VaultItem = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, item);
    assert_eq!(restored.folder_id.as_deref(), Some("folder-42"));
    assert!(restored.favorite);
    assert_eq!(restored.notes.as_str(), "recovery-code-7X");
    assert_eq!(restored.revision_date, 1_700_000_123);
    // A second serialization must be byte-identical: the Zeroizing-backed
    // secret adapter neither drops nor rewrites any metadata field.
    assert_eq!(serde_json::to_string(&restored).unwrap(), json);
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

    // An explicit revision is honoured in the decreasing direction too:
    // `upsert` replaces the row, it does not enforce a monotonic revision
    // clock. Only the UNKNOWN_REVISION sentinel preserves the old value.
    let mut older = original.clone();
    older.name = "Older".into();
    older.revision_date = 1_600_000_000;
    vault.upsert(older);
    assert_eq!(vault.item("u-1").unwrap().name, "Older");
    assert_eq!(
        vault.item("u-1").unwrap().revision_date,
        1_600_000_000,
        "an explicit decreasing revision overwrites the stored one"
    );
}

#[test]
fn page_matching_ties_use_the_folded_name_key_then_the_id() {
    // `matches_page` shares the `compare` tiebreak (model.rs:1109-1129,1221-1231):
    // folded names order first, and identical folded names fall back to the id
    // so the result never depends on insertion order.
    //
    // "B" and "b\u{200b}" fold to the same key (lowercasing + dropping Cf), so
    // only their ids can break the tie. Raw UTF-8 bytes order them the other
    // way ('B' = 0x42 < 'b' = 0x62), so replacing the folded comparison with
    // `a.name.cmp(&b.name)` flips `a-cf` and `b-upper` and fails this test.
    let page = "https://example.com/shared";
    let mut vault = Vault::new();
    let mut upper = login("b-upper", "B", "u", "p", page);
    upper.favorite = true;
    upper.revision_date = 10;
    let mut cf = login("a-cf", "b\u{200b}", "u", "p", page);
    cf.favorite = true;
    cf.revision_date = 10;
    let mut alpha = login("z-alpha", "Apple", "u", "p", page);
    alpha.favorite = true;
    alpha.revision_date = 10;
    // Guard the premise: the raw UTF-8 order of the two tied names disagrees
    // with the folded order asserted below, so the test really is a guard.
    assert!(upper.name < cf.name, "raw names must order differently");
    vault.items = vec![upper, cf, alpha];

    let opts = openwarden::MatchOptions::default();
    let ids: Vec<&str> = vault
        .matches_page(page, &opts)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(ids, vec!["z-alpha", "a-cf", "b-upper"]);
    assert_eq!(comparison_key("B"), comparison_key("b\u{200b}"));
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
fn saved_fingerprint_surrounding_whitespace_is_trimmed_on_comparison_only() {
    // `verify_fingerprint` compares `self.fingerprint.trim()` with the freshly
    // computed SHA256 value (model.rs:395). A saved fingerprint copied with
    // leading/trailing padding must still verify, including Unicode whitespace;
    // the stored field itself is never rewritten by verification.
    for padded in [
        format!("  {REFERENCE_FINGERPRINT}"),
        format!("{REFERENCE_FINGERPRINT}\t"),
        format!("\u{3000}{REFERENCE_FINGERPRINT}\n"),
        format!(" \t{REFERENCE_FINGERPRINT}\r\n "),
    ] {
        let key = ssh_key(REFERENCE_PUBLIC_KEY, &padded);
        assert_eq!(
            key.verify_fingerprint(),
            FingerprintVerify::Match,
            "{padded:?}"
        );
        assert!(key.fingerprint_matches(), "{padded:?}");
        assert_eq!(key.fingerprint, padded, "trim is comparison-only");
    }

    // Interior whitespace is part of the fingerprint and must not be ignored.
    let interior = format!("{REFERENCE_FINGERPRINT} trailing");
    let key = ssh_key(REFERENCE_PUBLIC_KEY, &interior);
    assert_eq!(
        key.verify_fingerprint(),
        FingerprintVerify::Mismatch {
            computed: REFERENCE_FINGERPRINT.to_string(),
        }
    );
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
    // `duplicate_names` uses the shared `comparison_key(&item.name)`, which
    // trims leading/trailing whitespace itself (model.rs:92-103), so padding a
    // name with ASCII or Unicode whitespace must not split it into a separate
    // group -- sort and page order fold the same key.
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
fn padded_names_share_one_key_in_duplicates_sort_and_page_order() {
    // The trim now lives in `comparison_key` (model.rs:86), the single key
    // shared by duplicate detection, `view` sorting and `matches_page`
    // ordering. Previously only `duplicate_names` trimmed, so those paths
    // disagreed about a padded name's key ("github" vs " github ").
    assert_eq!(comparison_key("  GitHub  "), comparison_key("GitHub"));
    assert_eq!(
        comparison_key("\u{3000}github\u{3000}"),
        comparison_key("GitHub")
    );

    let page = "https://example.com/settings";
    let mut padded = Vault::new();
    padded
        .items
        .push(login("padded", "  GitHub  ", "u", "p", page));
    padded.items.push(login("bare", "GitHub", "u", "p", page));

    // Duplicate detection groups them under the trimmed key.
    let groups = padded.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "github");
    assert_eq!(groups[0].1, vec!["padded".to_string(), "bare".to_string()]);

    // A completely bare vault must order identically: equal keys fall back to
    // the id tiebreak, not to the surrounding whitespace.
    let mut bare = Vault::new();
    bare.items.push(login("padded", "GitHub", "u", "p", page));
    bare.items.push(login("bare", "GitHub", "u", "p", page));

    let padded_sort: Vec<&str> = padded
        .view(&Filter::All, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let bare_sort: Vec<&str> = bare
        .view(&Filter::All, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(padded_sort, vec!["bare", "padded"]);
    assert_eq!(padded_sort, bare_sort);

    let opts = openwarden::MatchOptions::default();
    let padded_page: Vec<&str> = padded
        .matches_page(page, &opts)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let bare_page: Vec<&str> = bare
        .matches_page(page, &opts)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(padded_page, vec!["bare", "padded"]);
    assert_eq!(padded_page, bare_page);
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

#[test]
fn mask_uri_drops_scheme_default_ports() {
    // `url::Url::port()` reports None for a port equal to the scheme default
    // (model.rs:82-110), so explicitly written `:443` / `:80` must not survive
    // into a report or a Debug line. Non-default ports are kept verbatim.
    for (raw, expected) in [
        ("https://example.com:443/login", "https://example.com"),
        ("http://example.com:80/login", "http://example.com"),
        ("https://example.com:8443/login", "https://example.com:8443"),
        ("http://example.com:8080/login", "http://example.com:8080"),
    ] {
        assert_eq!(mask_uri(raw), expected, "{raw}");
    }
    // Credentials, path and query are still stripped alongside the port.
    assert_eq!(
        mask_uri("https://user:token@example.com:443/path?token=secret"),
        "https://example.com"
    );
    // Masking stays idempotent for both the default-port and explicit-port forms.
    assert_eq!(mask_uri("https://example.com"), "https://example.com");
    assert_eq!(
        mask_uri("https://example.com:8443"),
        "https://example.com:8443"
    );
}

#[test]
fn card_debug_keeps_expiry_but_masks_secrets() {
    // `CardData`'s manual Debug (model.rs:506-516) keeps the harmless brand and
    // expiry as diagnostics while masking the cardholder, number and code.
    let card = CardData {
        cardholder_name: "Ada Lovelace".into(),
        brand: "Visa".into(),
        number: "4111111111111234".into(),
        exp_month: "07".into(),
        exp_year: "2031".into(),
        code: "987".into(),
    };
    let debug = format!("{card:?}");

    assert!(debug.contains("CardData"), "{debug}");
    assert!(debug.contains("brand: \"Visa\""), "{debug}");
    assert!(debug.contains("exp_month: \"07\""), "{debug}");
    assert!(debug.contains("exp_year: \"2031\""), "{debug}");
    for secret in ["Ada Lovelace", "4111111111111234", "987"] {
        assert!(!debug.contains(secret), "leaked {secret}: {debug}");
    }
}

#[test]
fn filter_kind_secure_note_accepts_only_notes_and_labels_them() {
    // `Filter::Kind(kind)` compares the payload-derived item kind
    // (model.rs:845-853), and `Filter::label` delegates to `ItemKind::label`
    // (model.rs:856-867). Secure notes come from fixtures/mock data rather
    // than the login-only sync importer, so pin the sidebar path explicitly.
    let vault = sample(); // one SecureNote ("3"), two Logins ("1", "2")
    let filter = Filter::Kind(ItemKind::SecureNote);

    assert!(filter.accepts(vault.item("3").unwrap()));
    assert!(!filter.accepts(vault.item("1").unwrap()));
    assert!(!filter.accepts(vault.item("2").unwrap()));
    assert_eq!(
        vault
            .view(&filter, "", SortKey::NameAsc)
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["3"]
    );

    // The kind label does not need a folder list, and stays distinct from the
    // other kinds so a mixed-up match cannot hide behind the same string.
    assert_eq!(filter.label(&vault.folders), "メモ");
    assert_eq!(filter.label(&[]), "メモ");
    assert_eq!(Filter::Kind(ItemKind::Login).label(&[]), "ログイン");
    assert_eq!(Filter::Kind(ItemKind::Card).label(&[]), "カード");
}

#[test]
fn every_login_uri_joins_the_search_haystack() {
    // `VaultItem::haystacks` (model.rs:759-802) extends one Borrowed field per
    // login URI, so a token that only appears in the *third* URI is still
    // searchable. Passwords and TOTP secrets stay out of the index.
    const URIS: [&str; 3] = [
        "https://first.example.com/login",
        "https://second.example.net/login?token=SECOND_URI_TOKEN",
        "https://third.example.org/x#THIRD_URI_FRAGMENT",
    ];
    let item = VaultItem::new(
        "multi-uri-search",
        "Multi URI",
        ItemData::Login {
            username: "alice".into(),
            password: Zeroizing::new("HAYSTACK_PASSWORD_SECRET".into()),
            totp: Zeroizing::new("HAYSTACK_TOTP_SECRET".into()),
            uris: URIS.iter().map(|uri| LoginUri::new(*uri)).collect(),
        },
    );

    let fields: Vec<String> = item
        .haystacks()
        .iter()
        .map(|field| field.to_string())
        .collect();
    assert_eq!(fields.len(), 6, "name + notes + username + three URIs");
    for uri in URIS {
        assert!(
            fields.iter().any(|field| field.as_str() == uri),
            "URI missing from haystack: {uri}"
        );
    }
    assert!(fields.iter().any(|field| field == "alice"));
    // The empty notes field is still a haystack slot (it is not a URI).
    assert!(fields.iter().any(String::is_empty));
    for secret in ["HAYSTACK_PASSWORD_SECRET", "HAYSTACK_TOTP_SECRET"] {
        assert!(
            !fields.iter().any(|field| field.contains(secret)),
            "{secret}"
        );
    }

    for needle in [
        "first.example.com",
        "SECOND_URI_TOKEN",
        "third.example.org",
        "THIRD_URI_FRAGMENT",
    ] {
        assert!(
            item.matches_query(needle),
            "needle {needle:?} must be found"
        );
    }
    assert!(!item.matches_query("HAYSTACK_PASSWORD_SECRET"));
    assert!(!item.matches_query("HAYSTACK_TOTP_SECRET"));
    assert!(!item.matches_query("absent.example"));

    // The same hit survives the public view path (Vault::view -> matches_query).
    let mut vault = Vault::new();
    vault.items.push(item);
    let hits = vault.view(&Filter::All, "THIRD_URI_FRAGMENT", SortKey::NameAsc);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "multi-uri-search");
}

#[test]
fn favorites_filter_ands_with_a_non_empty_query() {
    // `Vault::view` applies `Filter::accepts` and the normalized query as two
    // chained filters (model.rs:977-987). With favorites among both the
    // matching and the non-matching items, each half must do real work.
    let mut favorite_match = login(
        "fav-match",
        "Favorite Bank",
        "bank-user",
        "pw",
        "https://bank.example.com",
    );
    favorite_match.favorite = true;
    let mut favorite_other = login(
        "fav-other",
        "Starred Mail",
        "mail-user",
        "pw",
        "https://mail.example.net",
    );
    favorite_other.favorite = true;
    let plain_match = login(
        "plain-match",
        "Public Bank",
        "bank-user",
        "pw",
        "https://bank.other.example.com",
    );
    let mut vault = Vault::new();
    vault.items = vec![favorite_match, favorite_other, plain_match];

    // A plain helper rather than a closure: the vault is mutated below, and a
    // closure borrowing it would keep that borrow alive across the mutation.
    fn ids_of<'a>(vault: &'a Vault, filter: &Filter, query: &str) -> Vec<&'a str> {
        vault
            .view(filter, query, SortKey::NameAsc)
            .iter()
            .map(|item| item.id.as_str())
            .collect()
    }
    assert_eq!(
        ids_of(&vault, &Filter::All, "bank"),
        vec!["fav-match", "plain-match"]
    );
    assert_eq!(
        ids_of(&vault, &Filter::Favorites, ""),
        vec!["fav-match", "fav-other"]
    );
    // The AND: only the starred item that also matches "bank" survives.
    assert_eq!(
        ids_of(&vault, &Filter::Favorites, "bank"),
        vec!["fav-match"]
    );
    // A query found only on a non-favorite item produces no hits.
    assert!(ids_of(&vault, &Filter::Favorites, "Public").is_empty());
    assert!(ids_of(&vault, &Filter::Favorites, "absent").is_empty());
    // Matching on a URI works under the same intersection.
    assert_eq!(
        ids_of(&vault, &Filter::Favorites, "mail.example.net"),
        vec!["fav-other"]
    );

    // Toggling the third item's favorite flag changes the intersection, so the
    // result is not merely the precomputed "bank" hit list.
    assert_eq!(vault.toggle_favorite("plain-match"), Some(true));
    assert_eq!(
        ids_of(&vault, &Filter::Favorites, "bank"),
        vec!["fav-match", "plain-match"]
    );
    assert_eq!(
        ids_of(&vault, &Filter::Favorites, "Public"),
        vec!["plain-match"]
    );
}

#[test]
fn filter_kind_ssh_key_accepts_and_shows_only_ssh_keys() {
    // `Filter::Kind(kind)` compares the payload-derived item kind in
    // `Filter::accepts` (model.rs:843-853), and `Vault::view` applies that
    // filter before the normalized query (model.rs:976-987). SshKey is the one
    // kind the login-only sync importer cannot produce, so pin its sidebar
    // path with fixtures as the sibling SecureNote test does.
    let ssh = VaultItem::new("s", "Deploy key", ItemData::SshKey(SshKeyData::default()));
    let vault = Vault {
        items: vec![
            login("l", "Login", "alice", "pw", "https://example.com"),
            ssh.clone(),
            VaultItem::new(
                "n",
                "Note",
                ItemData::SecureNote {
                    text: "note".into(),
                },
            ),
        ],
        folders: Vec::new(),
    };
    let filter = Filter::Kind(ItemKind::SshKey);

    assert!(filter.accepts(&ssh));
    assert!(!filter.accepts(vault.item("l").unwrap()));
    assert!(!filter.accepts(vault.item("n").unwrap()));

    let ids: Vec<&str> = vault
        .view(&filter, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(ids, vec!["s"]);

    // The query is ANDed with the kind filter: a token that only exists on a
    // login must not leak into the SSH-only view, while the SSH item's name
    // keeps it visible.
    assert!(vault.view(&filter, "alice", SortKey::NameAsc).is_empty());
    let matched: Vec<&str> = vault
        .view(&filter, "deploy", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(matched, vec!["s"]);
    assert_eq!(filter.label(&vault.folders), "SSH鍵");
}

#[test]
fn identity_email_phone_and_card_brand_are_in_the_search_haystack() {
    // `haystacks` (model.rs:784-795) pushes the identity email/phone and the
    // card brand verbatim. The neighbouring `search_haystacks_cover_kind_specific_fields`
    // test never named those three fields, so pin them directly here.
    let identity = VaultItem::new(
        "i-hay",
        "Id",
        ItemData::Identity(IdentityData {
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            email: "ADA.IDENTITY@EXAMPLE.COM".into(),
            phone: "090-1234-5678".into(),
            ..IdentityData::default()
        }),
    );
    let fields: Vec<String> = identity
        .haystacks()
        .iter()
        .map(|field| field.to_string())
        .collect();
    for expected in ["ADA.IDENTITY@EXAMPLE.COM", "090-1234-5678"] {
        assert!(
            fields.iter().any(|field| field == expected),
            "missing {expected:?} from haystack: {fields:?}"
        );
    }
    // The public search path folds case, so the lower-cased email still hits.
    assert!(identity.matches_query("ada.identity@example.com"));
    assert!(identity.matches_query("1234-5678"));

    let card = VaultItem::new(
        "c-hay",
        "Card",
        ItemData::Card(CardData {
            brand: "Mastercard".into(),
            number: "4111111111111234".into(),
            ..CardData::default()
        }),
    );
    let fields: Vec<String> = card
        .haystacks()
        .iter()
        .map(|field| field.to_string())
        .collect();
    assert!(
        fields.iter().any(|field| field == "Mastercard"),
        "card brand missing from haystack: {fields:?}"
    );
    assert!(card.matches_query("mastercard"));
    // The brand is searchable without widening the PAN rule.
    assert!(card.matches_query("1234"));
    assert!(!card.matches_query("411111111111"));
}

#[test]
fn known_type_tags_with_missing_or_malformed_payloads_are_rejected() {
    // `ItemData` is internally tagged `type` (model.rs:581-611). A known tag
    // alone must not be enough: every payload field of every variant is
    // required and typed, so dropping any one or replacing it with a wrong
    // scalar must fail to load. The table below covers all five variants.
    let valid: Vec<serde_json::Value> = vec![
        serde_json::to_value(ItemData::Login {
            username: "alice".into(),
            password: Zeroizing::new("pw".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![],
        })
        .unwrap(),
        serde_json::to_value(ItemData::SecureNote {
            text: "note".into(),
        })
        .unwrap(),
        serde_json::to_value(ItemData::Card(CardData {
            cardholder_name: "Ada".into(),
            brand: "Visa".into(),
            number: "4111111111111234".into(),
            exp_month: "01".into(),
            exp_year: "30".into(),
            code: "123".into(),
        }))
        .unwrap(),
        serde_json::to_value(ItemData::Identity(IdentityData {
            first_name: "Ada".into(),
            email: "ada@example.com".into(),
            ..IdentityData::default()
        }))
        .unwrap(),
        serde_json::to_value(ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AQ== fp".into(),
            private_key: String::new().into(),
            fingerprint: "SHA256:fp".into(),
        }))
        .unwrap(),
    ];
    // Sanity: the untouched wire forms all load, so the failures below are
    // caused by the mutation rather than by an invalid base fixture.
    for value in &valid {
        assert!(
            serde_json::from_value::<ItemData>(value.clone()).is_ok(),
            "valid payload must load: {value}"
        );
    }

    // Every payload field of every variant is listed here. The key-set check
    // below makes a newly added field fail this test until it is added to the
    // table, so "all fields" cannot silently become "one field per variant".
    for (tag, fields) in [
        ("login", &["username", "password", "totp", "uris"][..]),
        ("secure_note", &["text"][..]),
        (
            "card",
            &[
                "cardholder_name",
                "brand",
                "number",
                "exp_month",
                "exp_year",
                "code",
            ][..],
        ),
        (
            "identity",
            &[
                "first_name",
                "last_name",
                "email",
                "phone",
                "address",
                "company",
            ][..],
        ),
        ("ssh_key", &["public_key", "private_key", "fingerprint"][..]),
    ] {
        let base = valid
            .iter()
            .find(|value| value["type"].as_str() == Some(tag))
            .unwrap_or_else(|| panic!("no valid fixture for {tag}"))
            .clone();
        assert_eq!(base["type"].as_str(), Some(tag));
        let object = base.as_object().expect("payload fixture is an object");
        let present: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| *key != "type")
            .collect();
        assert_eq!(
            fields.len(),
            present.len(),
            "{tag}: the field table must cover every payload field: {present:?}"
        );
        for field in present {
            assert!(
                fields.contains(&field),
                "{tag}: {field} is missing from the field table"
            );
        }

        for &field in fields {
            let mut missing = base.clone();
            missing
                .as_object_mut()
                .expect("payload fixture is an object")
                .remove(field);
            assert!(
                serde_json::from_value::<ItemData>(missing.clone()).is_err(),
                "missing {field} under {tag} must be rejected: {missing}"
            );

            // `42` is the wrong scalar for every field here, including the
            // `zeroizing_*_serde` adapters and the `uris` vector.
            let mut wrong = base.clone();
            wrong[field] = serde_json::json!(42);
            assert!(
                serde_json::from_value::<ItemData>(wrong).is_err(),
                "wrong type for {field} under {tag} must be rejected"
            );
        }
    }
}

#[test]
fn vault_item_metadata_wrong_types_and_missing_fields_are_rejected() {
    // Sibling of `non_default_vault_item_metadata_survives_a_serde_round_trip`:
    // the positive case pins the wire names, this one pins that each metadata
    // field is required and typed. `notes` uses the `zeroizing_string_serde`
    // adapter, which must reject a non-string just like a plain `String`.
    let mut item = login(
        "meta-negative",
        "Metadata",
        "alice",
        "pw",
        "https://example.test",
    );
    item.folder_id = Some("folder-42".into());
    item.favorite = true;
    item.notes = Zeroizing::new("recovery-code-7X".into());
    item.revision_date = 1_700_000_123;
    let valid = serde_json::to_value(&item).unwrap();
    assert!(
        serde_json::from_value::<VaultItem>(valid.clone()).is_ok(),
        "the untouched fixture must load: {valid}"
    );

    for (field, wrong) in [
        ("id", serde_json::json!(42)),
        ("name", serde_json::json!(42)),
        ("folder_id", serde_json::json!(42)),
        ("favorite", serde_json::json!("true")),
        ("notes", serde_json::json!(42)),
        ("revision_date", serde_json::json!("1700000123")),
        // `data` is the internally tagged kind-specific payload: no default
        // and no way to coerce a scalar into an `ItemData`.
        ("data", serde_json::json!(42)),
    ] {
        let mut value = valid.clone();
        value[field] = wrong.clone();
        assert!(
            serde_json::from_value::<VaultItem>(value).is_err(),
            "wrong type for {field} must be rejected: {wrong}"
        );
    }
    // `folder_id` is an `Option<String>` and is allowed to be absent (it
    // deserializes to `None`), so it is excluded from the missing-field cases.
    // Pin that behaviour with a real assertion instead of relying on the
    // comment: this is the only metadata field serde may leave unset.
    let mut without_folder = valid.clone();
    without_folder
        .as_object_mut()
        .expect("a serialized VaultItem is an object")
        .remove("folder_id");
    let restored: VaultItem = serde_json::from_value(without_folder).unwrap();
    assert_eq!(restored.folder_id, None);
    assert_eq!(
        restored,
        VaultItem {
            folder_id: None,
            ..item.clone()
        }
    );
    // `data` is the tagged kind-specific payload with no serde default, so it
    // is required like the metadata fields above.
    for field in ["id", "name", "favorite", "notes", "revision_date", "data"] {
        let mut value = valid.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<VaultItem>(value).is_err(),
            "missing {field} must be rejected"
        );
    }
}

#[test]
fn match_options_allow_regex_reaches_both_matches_page_entry_points() {
    // `LoginUri::matches` already pins `allow_regex`; the two `matches_page`
    // wrappers (model.rs:820-823 and 1103-1123) must forward the same options
    // instead of silently using `MatchOptions::default()`.
    let item = VaultItem::new(
        "regex-page",
        "Regex Login",
        ItemData::Login {
            username: "alice".into(),
            password: Zeroizing::new("pw".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![LoginUri {
                uri: r"^https://[a-z]+\.example\.com/login$".into(),
                match_type: Some(4),
            }],
        },
    );
    let mut vault = Vault::new();
    vault.items.push(item.clone());

    let page = "https://app.example.com/login";
    let strict = openwarden::MatchOptions::default();
    assert!(!item.matches_page(page, &strict));
    assert!(vault.matches_page(page, &strict).is_empty());

    let regex = openwarden::MatchOptions {
        allow_regex: true,
        ..Default::default()
    };
    assert!(item.matches_page(page, &regex));
    let hits = vault.matches_page(page, &regex);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].id, "regex-page");
    // Enabling regex does not make an unrelated page match.
    assert!(!item.matches_page("https://app.example.com/other", &regex));
}

#[test]
fn ssh_base64_rejects_non_canonical_trailing_bits_without_padding() {
    use super::ssh_fingerprint::{decode, sha256_fingerprint};

    // Optional `=` padding must not weaken the canonical-bit check
    // (model.rs:415-424). With one leftover byte the final character has four
    // unused low bits: `AQ` decodes to 0x01, `AR` differs only in those bits.
    assert_eq!(decode(b"AQ"), Some(vec![0x01]));
    assert_eq!(decode(b"AR"), None);
    assert_eq!(
        sha256_fingerprint("ssh-ed25519 AQ fp"),
        sha256_fingerprint("ssh-ed25519 AQ== fp")
    );
    assert_eq!(sha256_fingerprint("ssh-ed25519 AR fp"), None);

    // Two leftover bytes leave two unused bits on the third character.
    assert_eq!(decode(b"AQI"), Some(vec![0x01, 0x02]));
    assert_eq!(decode(b"AQJ"), None);
    assert_eq!(
        sha256_fingerprint("ssh-ed25519 AQI fp"),
        sha256_fingerprint("ssh-ed25519 AQI= fp")
    );
    assert_eq!(sha256_fingerprint("ssh-ed25519 AQJ fp"), None);

    // The same check applies after a complete three-byte group: the final
    // byte is encoded by two more characters and a nonzero low bit is invalid.
    assert_eq!(decode(b"AQIDBA"), Some(vec![0x01, 0x02, 0x03, 0x04]));
    assert_eq!(decode(b"AQIDBB"), None);

    // A single trailing character has six leftover bits and is invalid in
    // both the padded and unpadded form.
    assert_eq!(decode(b"A"), None);
    assert_eq!(decode(b"A==="), None);
}

#[test]
fn mark_only_names_are_blank_for_duplicate_detection() {
    // Mn (combining acute / Greek ypogegrammeni) and Me (enclosing circle)
    // have no standalone glyph: with no base character they are decoration,
    // not a name. They must be skipped like Cf-only and blank names.
    let mut vault = Vault::new();
    vault
        .items
        .push(login("mark-1", "\u{0301}", "u", "p", "https://a.example"));
    vault.items.push(login(
        "mark-2",
        "\u{0345}\u{0301}",
        "u",
        "p",
        "https://b.example",
    ));
    vault
        .items
        .push(login("mark-3", "\u{20dd}", "u", "p", "https://c.example"));
    vault
        .items
        .push(login("blank", "  ", "u", "p", "https://d.example"));
    // A mark after a real base letter stays significant: NFC/NFD spellings of
    // the same name still form one duplicate group.
    vault
        .items
        .push(login("real-1", "Caf\u{e9}", "u", "p", "https://e.example"));
    vault.items.push(login(
        "real-2",
        "Cafe\u{301}",
        "u",
        "p",
        "https://f.example",
    ));

    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "cafe\u{301}");
    assert_eq!(
        groups[0].1,
        vec!["real-1".to_string(), "real-2".to_string()]
    );
    for id in ["mark-1", "mark-2", "mark-3", "blank"] {
        assert!(
            !groups
                .iter()
                .any(|(_, ids)| ids.iter().any(|entry| entry == id)),
            "{id} must not be a duplicate: {groups:?}"
        );
    }
}

#[test]
fn ssh_public_key_is_in_the_search_haystack() {
    // `haystacks` pushes the public key (model.rs:796-799) as a searchable
    // field while the private key stays out. The public line is not a secret,
    // so a user can find an SSH item by its key text or comment.
    const PUBLIC: &str = "ssh-ed25519 HAYSTACK_PUBLIC_TOKEN fp@example";
    const PRIVATE: &str = "PRIVATE_HAYSTACK_SECRET";
    let item = VaultItem::new(
        "ssh-hay",
        "Key",
        ItemData::SshKey(SshKeyData {
            public_key: PUBLIC.into(),
            private_key: PRIVATE.into(),
            fingerprint: "SHA256:abc".into(),
        }),
    );

    let fields: Vec<String> = item
        .haystacks()
        .iter()
        .map(|field| field.to_string())
        .collect();
    assert!(fields.iter().any(|field| field == PUBLIC), "{fields:?}");
    assert!(item.matches_query("HAYSTACK_PUBLIC_TOKEN"));
    assert!(item.matches_query("ssh-ed25519"));
    assert!(!item.matches_query("PRIVATE_HAYSTACK_SECRET"));

    let debug = format!("{item:?}");
    assert!(debug.contains(PUBLIC));
    assert!(!debug.contains(PRIVATE));
}

#[test]
fn multiple_folder_ids_resolve_to_their_own_names_and_counts() {
    // `folder_name`, `Filter::label` and `folder_counts` each resolve ids by
    // walking the folder list (model.rs:931-952, 856-867). With several
    // folders, each id must map to its own name and count, and an unknown id
    // must degrade gracefully without materialising a bucket.
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
        Folder {
            id: "f3".into(),
            name: "重要".into(),
        },
    ];
    let mut first = login("1", "One", "u", "p", "https://one.example");
    first.folder_id = Some("f1".into());
    let mut second = login("2", "Two", "u", "p", "https://two.example");
    second.folder_id = Some("f2".into());
    let mut third = login("3", "Three", "u", "p", "https://three.example");
    third.folder_id = Some("f2".into());
    vault.items = vec![first, second, third];

    for (id, name) in [("f1", "仕事"), ("f2", "私用"), ("f3", "重要")] {
        assert_eq!(vault.folder_name(id), Some(name), "{id}");
        assert_eq!(
            Filter::Folder(id.into()).label(&vault.folders),
            name,
            "{id}"
        );
    }
    assert_eq!(vault.folder_name("missing"), None);
    assert_eq!(
        Filter::Folder("missing".into()).label(&vault.folders),
        "(不明なフォルダ)"
    );
    assert_eq!(
        vault.folder_counts(),
        vec![
            ("f1".to_string(), 1),
            ("f2".to_string(), 2),
            ("f3".to_string(), 0),
        ]
    );
    let shown: Vec<&str> = vault
        .view(&Filter::Folder("f2".into()), "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    // NameAsc is by folded name, not by id; these fixtures place id 3 first.
    assert_eq!(shown, vec!["3", "2"]);
}

#[test]
fn mc_only_names_are_blank_for_duplicate_detection() {
    // Mc (spacing combining mark) is part of General_Category=Mark alongside
    // Mn/Me, so a name made only of Mc code points has no standalone glyph
    // either. `duplicate_names` uses `is_mark` (model.rs:31-33, 1156-1177)
    // and must skip these names instead of grouping them with each other.
    let mut vault = Vault::new();
    // U+0903 DEVANAGARI SIGN VISARGA and U+093E DEVANAGARI VOWEL SIGN AA are
    // both Mc; trim() leaves them intact, so only the mark rule can skip them.
    vault
        .items
        .push(login("mc-1", "\u{0903}", "u", "p", "https://a.example"));
    vault.items.push(login(
        "mc-2",
        "\u{093e}\u{0903}",
        "u",
        "p",
        "https://b.example",
    ));
    // Control: a real duplicate pair must still be reported, so the test
    // cannot pass simply because every group was suppressed.
    vault
        .items
        .push(login("name-1", "alpha", "u", "p", "https://c.example"));
    vault
        .items
        .push(login("name-2", "ALPHA", "u", "p", "https://d.example"));

    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "alpha");
    assert_eq!(
        groups[0].1,
        vec!["name-1".to_string(), "name-2".to_string()]
    );
    for id in ["mc-1", "mc-2"] {
        assert!(
            !groups
                .iter()
                .any(|(_, ids)| ids.iter().any(|entry| entry == id)),
            "{id} must not be a duplicate: {groups:?}"
        );
    }

    // A mark after an ordinary base letter stays significant: two such names
    // are still a duplicate group.
    let mut with_base = Vault::new();
    with_base.items.push(login(
        "1",
        "\u{0915}\u{0903}",
        "u",
        "p",
        "https://e.example",
    ));
    with_base.items.push(login(
        "2",
        "\u{0915}\u{0903}",
        "u",
        "p",
        "https://f.example",
    ));
    let based = with_base.duplicate_names();
    assert_eq!(based.len(), 1, "{based:?}");
    assert_eq!(based[0].1, vec!["1".to_string(), "2".to_string()]);
}

#[test]
fn mask_uri_embedded_nul_is_not_the_decryption_sentinel() {
    use crate::vault_sync::UNDECRYPTABLE_URI;

    // Only a LEADING NUL selects the undecryptable status branch (model.rs:106-132).
    assert_eq!(mask_uri(UNDECRYPTABLE_URI), "（復号できませんでした）");
    assert_eq!(
        mask_uri("\0https://example.com/path"),
        "（復号できませんでした）"
    );

    // An embedded NUL inside the host is a forbidden host code point for
    // `url::Url`, so parsing fails and the value takes the same invalid-URI
    // arm as any other unparsable input. It must NOT be reported as a
    // decryption failure just because it contains a NUL byte.
    for raw in [
        "https://exa\0mple.com/path",
        "https://user:pass@exa\0mple.com:8443/path",
    ] {
        assert_eq!(mask_uri(raw), "(不正な URI)", "{raw:?}");
    }

    // A NUL in the path/query does not change the host, so masking still
    // reduces the value to scheme + host + port and never leaks the tail.
    assert_eq!(
        mask_uri("https://example.com/pa\0th?token=SECRET"),
        "https://example.com"
    );
    assert_eq!(
        mask_uri("https://example.com:8443/pa\0th?token=SECRET"),
        "https://example.com:8443"
    );
    for masked in [
        mask_uri("https://exa\0mple.com/path"),
        mask_uri("https://example.com/pa\0th?token=SECRET"),
    ] {
        assert!(!masked.contains('\0'), "{masked:?}");
        assert!(!masked.contains("SECRET"), "{masked:?}");
    }
}

#[test]
fn comparison_key_drops_format_characters_for_search_and_duplicates() {
    // Unicode Cf code points render nothing, so a name containing one must
    // compare equal to the plain spelling on every path that shares
    // `comparison_key` (model.rs:46-96). Leaving the invisible code point in
    // the key made a plain search query miss an otherwise identical name.
    for invisible in ['\u{200b}', '\u{2060}', '\u{feff}', '\u{ad}'] {
        let with_cf = format!("Git{invisible}Hub");
        assert_eq!(
            comparison_key(&with_cf),
            comparison_key("GitHub"),
            "U+{:04X} was not dropped",
            invisible as u32
        );
        assert!(!comparison_key(&with_cf).contains(invisible));
    }
    assert_eq!(comparison_key("\u{200b}"), "");
    // Idempotence still holds after the drop.
    let key = comparison_key("Git\u{200b}Hub");
    assert_eq!(comparison_key(&key), key);

    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "Git\u{200b}Hub", "u", "p", "https://a.example"));
    // A plain query must find the item whose stored name carries a Cf char.
    assert_eq!(
        vault.view(&Filter::All, "github", SortKey::NameAsc).len(),
        1
    );
    // And a query carrying Cf must find the plain name.
    let mut plain = Vault::new();
    plain
        .items
        .push(login("2", "GitHub", "u", "p", "https://b.example"));
    assert_eq!(
        plain
            .view(&Filter::All, "Git\u{200b}Hub", SortKey::NameAsc)
            .len(),
        1
    );

    // Duplicate detection groups both spellings under the plain key.
    vault
        .items
        .push(login("3", "GitHub", "u", "p", "https://c.example"));
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "github");
    assert_eq!(groups[0].1, vec!["1".to_string(), "3".to_string()]);
}

#[test]
fn format_only_query_does_not_match_every_item() {
    // `comparison_key` drops Unicode Cf, so a query made only of invisible
    // characters folds to the empty key. That must NOT be confused with a
    // blank query, which is the "show all" sentinel in both `matches_query`
    // and `Vault::view` (model.rs:831-842, 1003-1014).
    let item = login("1", "GitHub", "u", "p", "https://example.com");
    let vault = Vault {
        items: vec![item],
        folders: Vec::new(),
    };

    // Premise: a genuinely blank query still returns everything.
    assert_eq!(vault.view(&Filter::All, "", SortKey::NameAsc).len(), 1);
    assert_eq!(vault.view(&Filter::All, "   ", SortKey::NameAsc).len(), 1);

    for invisible in [
        "\u{200b}",
        "\u{2060}",
        "\u{feff}",
        "\u{ad}",
        " \u{200b}\u{200d} ",
    ] {
        // Whitespace mixed with Cf folds to a whitespace-only key; the
        // matchers treat both invisible-only forms as "no visible needle".
        assert!(comparison_key(invisible).trim().is_empty(), "{invisible:?}");
        assert!(
            !vault.items[0].matches_query(invisible),
            "a Cf-only needle must not match all fields: {invisible:?}"
        );
        assert!(
            vault
                .view(&Filter::All, invisible, SortKey::NameAsc)
                .is_empty(),
            "a Cf-only query must not show every item: {invisible:?}"
        );
        // The filter is still applied: no items even when the filter would
        // otherwise accept them all.
        assert!(vault
            .view(&Filter::Kind(ItemKind::Login), invisible, SortKey::NameAsc)
            .is_empty());
    }

    // A query with visible characters alongside Cf still searches normally.
    assert_eq!(
        vault
            .view(&Filter::All, "\u{200b}github\u{200d}", SortKey::NameAsc)
            .len(),
        1
    );
}

#[test]
fn invisible_only_names_and_needles_share_the_view_rule() {
    // `is_visually_empty` (model.rs:110-114) is the shared "no visible content"
    // rule. Needles and names made only of whitespace + Unicode Cf must be
    // blank everywhere, including Cf separated by *internal* whitespace:
    // checking only `comparison_key().is_empty()` left a single space in the
    // key and let such a needle match every item.
    let invisible = [
        "\u{200b}",
        "\u{2060}",
        "\u{feff}",
        "\u{ad}",
        "\u{200b} \u{200d}",
        " \u{2060}\t\u{feff} ",
        "\u{ad} \u{200f}",
    ];
    for value in invisible {
        assert!(super::is_visually_empty(value), "{value:?}");
    }
    assert!(!super::is_visually_empty("GitHub"));
    assert!(
        !super::is_visually_empty("\u{200b}GitHub"),
        "visible letters remain"
    );

    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "GitHub", "u", "p", "https://a.example"));
    for value in invisible {
        assert!(
            !vault.items[0].matches_query(value),
            "Cf/whitespace-only needle matched everything: {value:?}"
        );
        assert!(
            vault.view(&Filter::All, value, SortKey::NameAsc).is_empty(),
            "Cf/whitespace-only query showed an item: {value:?}"
        );
    }
    // A genuinely blank needle keeps the "show everything" contract on both
    // paths, so the assertions above are about invisibility, not a dead matcher.
    for blank in ["", " ", " \t\u{3000}\n "] {
        assert!(vault.items[0].matches_query(blank), "{blank:?}");
        assert_eq!(
            vault.view(&Filter::All, blank, SortKey::NameAsc).len(),
            1,
            "{blank:?}"
        );
    }

    // Two invisible-only names do not form a duplicate group even with Cf
    // separated by whitespace, while a real pair still groups under the
    // Cf-free key.
    let mut names = Vault::new();
    names.items.push(login(
        "a",
        "\u{200b} \u{200d}",
        "u",
        "p",
        "https://a.example",
    ));
    names.items.push(login(
        "b",
        " \u{2060}\t\u{feff} ",
        "u",
        "p",
        "https://b.example",
    ));
    let groups = names.duplicate_names();
    assert!(groups.is_empty(), "{groups:?}");
    names
        .items
        .push(login("c", "Git\u{200b}Hub", "u", "p", "https://c.example"));
    names
        .items
        .push(login("d", "github", "u", "p", "https://d.example"));
    let groups = names.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "github");
    assert_eq!(groups[0].1, vec!["c".to_string(), "d".to_string()]);
}

#[test]
fn cf_free_key_is_shared_by_search_duplicates_and_sort() {
    let cf_name = "Git\u{200b}Hub";
    let plain_name = "GitHub";
    assert_eq!(comparison_key(cf_name), comparison_key(plain_name));
    assert_eq!(comparison_key(cf_name), "github");
    assert!(!super::is_visually_empty(cf_name));

    let mut vault = Vault::new();
    // Insert the plain spelling first: sorting must follow the folded key and
    // its id tiebreak, not insertion order.
    vault
        .items
        .push(login("b", plain_name, "u", "p", "https://b.example"));
    vault
        .items
        .push(login("a", cf_name, "u", "p", "https://a.example"));

    // Search and the public matcher use the same Cf-free key.
    for query in ["github", "Git\u{200b}Hub", "GIT\u{2060}HUB"] {
        assert_eq!(
            vault.view(&Filter::All, query, SortKey::NameAsc).len(),
            2,
            "{query:?}"
        );
        for item in &vault.items {
            assert!(item.matches_query(query), "{query:?}");
        }
    }

    // Duplicate detection groups both spellings under that key.
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "github");
    assert_eq!(groups[0].1, vec!["b".to_string(), "a".to_string()]);

    // Sorting reuses the same key: the names tie, so the id decides; the
    // descending order reverses only that tie.
    let asc: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(asc, vec!["a", "b"]);
    let desc: Vec<&str> = vault
        .view(&Filter::All, "", SortKey::NameDesc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(desc, vec!["b", "a"]);
}

#[test]
fn item_data_debug_pins_the_empty_totp_branch() {
    // The manual `ItemData` Debug (model.rs:640-664) renders an unset TOTP as
    // `totp: ""` and any non-empty value as `[redacted]`. Exercise the branch
    // directly on the payload, not only through `VaultItem`'s wrapper.
    let data = ItemData::Login {
        username: "u".into(),
        password: Zeroizing::new("pw".into()),
        totp: Zeroizing::new(String::new()),
        uris: vec![],
    };
    let empty = format!("{data:?}");
    assert!(empty.contains("totp: \"\""), "{empty}");
    assert!(!empty.contains("totp: \"[redacted]\""), "{empty}");

    // Whitespace is a non-empty value: it takes the redacted branch, so no
    // part of it reaches the log line.
    let blank = ItemData::Login {
        username: "u".into(),
        password: Zeroizing::new("pw".into()),
        totp: Zeroizing::new("   ".into()),
        uris: vec![],
    };
    let blank_debug = format!("{blank:?}");
    assert!(
        blank_debug.contains("totp: \"[redacted]\""),
        "{blank_debug}"
    );
    assert!(!blank_debug.contains("   \""), "{blank_debug}");

    let set = ItemData::Login {
        username: "u".into(),
        password: Zeroizing::new("pw".into()),
        totp: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
        uris: vec![],
    };
    let populated = format!("{set:?}");
    assert!(populated.contains("totp: \"[redacted]\""), "{populated}");
    assert!(!populated.contains("JBSWY3DPEHPK3PXP"), "{populated}");
    assert!(!populated.contains("totp: \"\""), "{populated}");
}

#[test]
fn control_characters_only_values_are_visually_empty_like_auth_credentials() {
    // `is_visually_empty` (model.rs:110-114) now includes `Cc` through
    // `char::is_control`, matching `credential_is_blank` in auth. NUL, DEL and
    // the C1 controls are not whitespace, so the old whitespace + Cf rule
    // treated a Cc-only name / TOTP value as present.
    for control in ['\u{0}', '\u{1}', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}'] {
        let value = control.to_string();
        assert!(
            super::is_visually_empty(&value),
            "Cc U+{:04X} must be invisible",
            control as u32
        );
        // Cc mixed with whitespace and Cf is still invisible on the shared rule.
        let mixed = format!(" \u{200b}{control}\t");
        assert!(
            super::is_visually_empty(&mixed),
            "mixed Cc U+{:04X} must be invisible",
            control as u32
        );
        // One visible character makes the value present again.
        assert!(!super::is_visually_empty(&format!("{control}GitHub")));
    }
    // Controls: the pre-existing halves of the rule still hold.
    assert!(super::is_visually_empty(" \t\n \u{200b}"));
    assert!(!super::is_visually_empty("GitHub"));
}

#[test]
fn control_only_names_and_needles_share_the_search_and_duplicate_rules() {
    // `is_visually_empty` (model.rs:110-114) includes `Cc`. The earlier Cf-only
    // suites cover search and duplicates separately; this test drives the
    // combined path with Cc-only values so the two consumers cannot drift.
    let controls = ["\u{0}", "\u{1}\u{1f}", "\u{7f}", "\u{80}", "\u{9f}"];

    let mut vault = Vault::new();
    for (index, value) in controls.iter().enumerate() {
        vault.items.push(login(
            &format!("cc-{index}"),
            value,
            "u",
            "p",
            "https://example.com",
        ));
        // Cc mixed with Cf and whitespace is invisible on the same rule.
        vault.items.push(login(
            &format!("cc-mixed-{index}"),
            &format!(" \u{200b}{value}\t"),
            "u",
            "p",
            "https://example.com",
        ));
    }
    // A real duplicate pair must still be reported in the same vault, so an
    // empty group list would not pass for the wrong reason.
    vault
        .items
        .push(login("visible-1", "Alpha", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("visible-2", "alpha", "u", "p", "https://b.example"));

    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "alpha");
    assert_eq!(
        groups[0].1,
        vec!["visible-1".to_string(), "visible-2".to_string()]
    );

    // Every Cc-only value is invisible to search on both public entry points.
    let item = &vault.items[0];
    for value in controls {
        assert!(!item.matches_query(value), "Cc needle matched: {value:?}");
        assert!(
            vault.view(&Filter::All, value, SortKey::NameAsc).is_empty(),
            "Cc query showed items: {value:?}"
        );
        let mixed = format!(" \u{200b}{value}\t");
        assert!(
            !item.matches_query(&mixed),
            "mixed needle matched: {mixed:?}"
        );
        assert!(
            vault
                .view(&Filter::All, &mixed, SortKey::NameAsc)
                .is_empty(),
            "mixed query showed items: {mixed:?}"
        );
    }
    // Blank queries keep the long-standing "show all" behaviour.
    assert_eq!(
        vault.view(&Filter::All, "", SortKey::NameAsc).len(),
        vault.items.len()
    );
}

#[test]
fn comparison_key_drops_embedded_control_characters() {
    // `comparison_key` (model.rs:46-96) drops `Cc` like it already dropped
    // `Cf`: a literal NUL or C1 control inside a name must not split an
    // otherwise identical search or duplicate pair. `is_visually_empty`
    // (model.rs:110-114) still handles values made *only* of such characters.
    for control in ['\u{0}', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}'] {
        let with_cc = format!("Git{control}Hub");
        assert_eq!(
            comparison_key(&with_cc),
            "github",
            "U+{:04X} was not dropped",
            control as u32
        );
        assert!(!comparison_key(&with_cc).contains(control));
        assert_eq!(
            comparison_key(comparison_key(&with_cc).as_str()),
            "github",
            "idempotence must survive the Cc drop"
        );
    }

    let mut vault = Vault::new();
    vault
        .items
        .push(login("cc-1", "Git\u{0}Hub", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("cc-2", "github", "u", "p", "https://b.example"));
    assert_eq!(
        vault.view(&Filter::All, "github", SortKey::NameAsc).len(),
        2
    );
    // A Cc-bearing needle finds the plain name too (both sides use this key).
    assert_eq!(
        vault
            .view(&Filter::All, "Git\u{1f}Hub", SortKey::NameAsc)
            .len(),
        2
    );
    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "github");
    assert_eq!(groups[0].1, vec!["cc-1".to_string(), "cc-2".to_string()]);
}

#[test]
fn mark_only_names_with_internal_whitespace_are_not_duplicates() {
    // Combining marks (Mn/Mc/Me) have no standalone glyph, and whitespace
    // between them renders nothing either. `duplicate_names` must skip such
    // rows just like a contiguous mark-only name (model.rs:1145-1180). A real
    // duplicate pair in the same vault proves the rule is not simply dropping
    // every group.
    let mut vault = Vault::new();
    for (id, name) in [
        ("m-space", "\u{0301} \u{0302}"),
        ("m-tab", "\u{0301}\t\u{0302}"),
        ("m-newline", "\u{0301}\n\u{0302}"),
        ("m-padded", " \u{0301} \u{0302} "),
        ("m-with-cf", "\u{0301}\u{200b} \u{0302}"),
    ] {
        vault
            .items
            .push(login(id, name, "u", "p", "https://example.com"));
    }
    vault
        .items
        .push(login("real-1", "Alpha", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("real-2", "alpha", "u", "p", "https://b.example"));

    let groups = vault.duplicate_names();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].0, "alpha");
    assert_eq!(
        groups[0].1,
        vec!["real-1".to_string(), "real-2".to_string()]
    );
}

#[test]
fn mark_only_queries_match_nothing_under_the_duplicate_name_rule() {
    // `duplicate_names` skips mark-only names because bare marks have no
    // visible identity. Queries now share that rule: a mark-only needle is not
    // blank, so it must match no item instead of falling through to a
    // substring match against decomposed accents or to the blank-query path.
    let mut vault = Vault::new();
    vault
        .items
        .push(login("1", "Caf\u{e9}", "u", "p", "https://a.example"));
    vault
        .items
        .push(login("2", "GitHub", "u", "p", "https://b.example"));
    // Two mark-only names must not form a duplicate group either.
    vault
        .items
        .push(login("m-1", "\u{0301}", "u", "p", "https://c.example"));
    vault.items.push(login(
        "m-2",
        " \u{0301}\u{0302} ",
        "u",
        "p",
        "https://d.example",
    ));

    for query in [
        "\u{0301}",           // a single combining acute accent
        " \u{0301}\u{0302} ", // marks with internal whitespace
        "\u{0345}",           // combining Greek ypogegrammeni
    ] {
        assert!(has_no_visible_identity(query), "{query:?}");
        for item in &vault.items {
            assert!(
                !item.matches_query(query),
                "needle {query:?} hit item {}",
                item.id
            );
        }
        assert!(
            vault.view(&Filter::All, query, SortKey::NameAsc).is_empty(),
            "needle {query:?} must not widen the view"
        );
    }

    // Controls: blank needles still keep every item visible, a real query
    // still narrows the result, and the shared rule keeps its boundary.
    assert_eq!(vault.view(&Filter::All, "", SortKey::NameAsc).len(), 4);
    assert_eq!(vault.view(&Filter::All, "   ", SortKey::NameAsc).len(), 4);
    assert_eq!(
        vault
            .view(&Filter::All, "cafe\u{301}", SortKey::NameAsc)
            .len(),
        1
    );
    assert!(has_no_visible_identity("\u{0301}\u{200b}"));
    assert!(!has_no_visible_identity("Caf\u{e9}"));
    assert!(vault.duplicate_names().is_empty());
}

#[test]
fn plain_query_finds_a_saved_name_with_surrounding_whitespace() {
    // `comparison_key` trims only the edges (model.rs:92-103), so a stored name
    // padded with whitespace still has the same key as its bare spelling and an
    // ordinary plaintext query finds it through both public search paths.
    let spaced = login(
        "spaced",
        " \t Work Mail \n",
        "alice",
        "pw",
        "https://one.example",
    );
    let bare = login("bare", "Work Mail", "bob", "pw", "https://two.example");
    let vault = Vault {
        items: vec![spaced, bare],
        folders: Vec::new(),
    };
    assert_eq!(comparison_key(" \t Work Mail \n"), "work mail");
    assert_eq!(comparison_key("Work Mail"), "work mail");

    for query in [
        "Work Mail",
        "work mail",
        "WORK MAIL",
        "  work mail  ",
        "Mail",
    ] {
        assert_eq!(
            vault.view(&Filter::All, query, SortKey::NameAsc).len(),
            2,
            "query {query:?}"
        );
        for item in &vault.items {
            assert!(
                item.matches_query(query),
                "item {} missed by query {query:?}",
                item.id
            );
        }
    }
    // Internal whitespace is part of the key, not a separator to ignore.
    assert!(!vault.items[0].matches_query("workmail"));
    assert!(vault
        .view(&Filter::All, "workmail", SortKey::NameAsc)
        .is_empty());
}

#[test]
fn is_visually_empty_and_auth_credential_is_blank_agree_on_real_values() {
    // The two rules are meant to be identical (model.rs:118-122 and
    // auth.rs:440-444). Call both real functions on the same inputs instead of
    // comparing their source, so a future divergence fails here.
    for value in [
        "",
        " ",
        " \t\n\u{3000}",
        "\u{200b}",
        "\u{feff}",
        "\u{ad}\u{feff}",
        "\u{0}",
        "\u{1f}",
        "\u{7f}",
        "\u{80}",
        "\u{9f}",
        " \u{200b}\u{0}\t",
        "\u{0301}",
        "GitHub",
        " a ",
        "a\u{200b}b",
        "\u{200b}p",
    ] {
        assert_eq!(
            super::is_visually_empty(value),
            crate::auth::credential_is_blank(value),
            "blank rules disagree for {value:?}"
        );
    }
}

#[test]
fn vault_item_new_pins_neutral_metadata_defaults() {
    // `VaultItem::new` (model.rs:766-776) fills only the caller's three fields;
    // every other metadata field starts neutral so a fresh item cannot inherit
    // a folder, a star, notes or a revision date.
    let item = VaultItem::new(
        "new-1",
        "New",
        ItemData::SecureNote {
            text: "body".into(),
        },
    );
    assert_eq!(item.id, "new-1");
    assert_eq!(item.name, "New");
    assert_eq!(item.kind(), ItemKind::SecureNote);
    assert_eq!(item.folder_id, None);
    assert!(!item.favorite);
    assert_eq!(item.notes.as_str(), "");
    assert_eq!(item.revision_date, UNKNOWN_REVISION);

    // The defaults agree with the empty-state filters and the audit's unknown
    // revision sentinel: a new item is "no folder", never a favorite, and has
    // no revision that could be reported as stale.
    assert!(Filter::NoFolder.accepts(&item));
    assert!(!Filter::Favorites.accepts(&item));
    assert!(!item.matches_query("absent-in-body"));
    assert!(item.matches_query("body"));
}

#[test]
fn empty_folder_id_is_a_present_id_for_filters() {
    // `Filter::Folder` compares the raw `Option<String>` id (model.rs:932-942),
    // so `Some("")` is a distinct, present id: it matches only an empty-string
    // folder filter and never `NoFolder`. `folder_counts` walks declared
    // folders, so the empty id gets no bucket unless a Folder declares it.
    let plain = VaultItem::new("plain", "Plain", ItemData::SecureNote { text: "x".into() });
    let mut emptied = VaultItem::new("empty", "Empty", ItemData::SecureNote { text: "x".into() });
    emptied.folder_id = Some(String::new());

    assert!(Filter::NoFolder.accepts(&plain));
    assert!(!Filter::Folder(String::new()).accepts(&plain));
    assert!(!Filter::NoFolder.accepts(&emptied));
    assert!(Filter::Folder(String::new()).accepts(&emptied));
    assert!(!Filter::Folder("f1".into()).accepts(&emptied));

    let mut vault = Vault::new();
    vault.items = vec![plain, emptied];
    assert!(vault.folder_counts().is_empty());
    assert_eq!(
        Filter::Folder(String::new()).label(&vault.folders),
        "(不明なフォルダ)"
    );

    let no_folder: Vec<&str> = vault
        .view(&Filter::NoFolder, "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let with_empty: Vec<&str> = vault
        .view(&Filter::Folder(String::new()), "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(no_folder, vec!["plain"]);
    assert_eq!(with_empty, vec!["empty"]);

    // A declared folder with the empty id does get a bucket and a real label.
    vault.folders.push(Folder {
        id: String::new(),
        name: "空".into(),
    });
    assert_eq!(vault.folder_counts(), vec![(String::new(), 1)]);
    assert_eq!(Filter::Folder(String::new()).label(&vault.folders), "空");
}

// --- R2-CORE-121: stable ordering on Equal and empty SSH blob rejection ---

#[test]
fn compare_equal_keeps_the_original_row_order() {
    // Two raw rows that `compare` ranks as Equal on every sort key must keep
    // their insertion order through `Vault::view`'s stable `sort_by`
    // (model.rs:1098, 1215-1225). They differ only in fields `compare` never
    // inspects, so the notes reveal which row came first.
    let mut first = login("dup", "Same", "u", "p", "https://first.example");
    first.revision_date = 100;
    first.notes = Zeroizing::new("FIRST".to_string());
    let mut second = login("dup", "Same", "u", "p", "https://second.example");
    second.revision_date = 100;
    second.favorite = true;
    second.notes = Zeroizing::new("SECOND".to_string());

    let keys = [
        SortKey::NameAsc,
        SortKey::NameDesc,
        SortKey::RecentlyModified,
        SortKey::Kind,
    ];
    for sort in keys {
        assert_eq!(
            super::compare(&first, &second, sort),
            std::cmp::Ordering::Equal,
            "{sort:?}"
        );
    }

    let vault = Vault {
        items: vec![first, second],
        folders: Vec::new(),
    };
    for sort in keys {
        let order: Vec<&str> = vault
            .view(&Filter::All, "", sort)
            .iter()
            .map(|item| item.notes.as_str())
            .collect();
        assert_eq!(order, vec!["FIRST", "SECOND"], "{sort:?}");
    }
}

#[test]
fn ssh_base64_decoder_rejects_an_empty_blob() {
    // `decode` rejects a zero-byte result (model.rs:456-509): an empty string
    // must never be hashed into a fingerprint. Padding-only input decodes to
    // zero bytes too and must fail for the same reason.
    assert_eq!(super::ssh_fingerprint::decode(b""), None);
    for input in [&b"="[..], &b"=="[..], &b"===="[..]] {
        assert_eq!(super::ssh_fingerprint::decode(input), None, "{input:?}");
    }
    // Whitespace cannot create a blob field through `split_whitespace`, so a
    // blob-less key line yields no fingerprint either.
    for line in ["", "   ", "ssh-ed25519", "ssh-ed25519   "] {
        assert_eq!(
            super::ssh_fingerprint::sha256_fingerprint(line),
            None,
            "{line:?}"
        );
    }
    // Premise: a real one-byte blob still decodes, so the rejection above is
    // specific to the empty case rather than a blanket refusal.
    assert_eq!(super::ssh_fingerprint::decode(b"AQ=="), Some(vec![0x01]));
    let key = ssh_key("", REFERENCE_FINGERPRINT);
    assert_eq!(
        key.verify_fingerprint(),
        FingerprintVerify::InvalidPublicKey
    );
}

#[test]
fn duplicate_folder_ids_resolve_to_the_first_folder_row() {
    // `Vault::folder_name` (model.rs:1021-1026) and `Filter::label`
    // (model.rs:945-956) both resolve an id with `iter().find()`. When two
    // folder rows carry the same id, the first row therefore wins for both;
    // reversing the rows must flip both together (the rule is positional,
    // not based on the names).
    let mut vault = Vault::new();
    vault.folders = vec![
        Folder {
            id: "dup".into(),
            name: "First".into(),
        },
        Folder {
            id: "dup".into(),
            name: "Second".into(),
        },
    ];
    assert_eq!(vault.folder_name("dup"), Some("First"));
    assert_eq!(Filter::Folder("dup".into()).label(&vault.folders), "First");

    vault.folders.reverse();
    assert_eq!(vault.folder_name("dup"), Some("Second"));
    assert_eq!(Filter::Folder("dup".into()).label(&vault.folders), "Second");
}

#[test]
fn duplicate_folder_ids_are_counted_once_per_folder_row() {
    // `folder_counts` (model.rs:1029-1041) maps over every folder row rather
    // than deduplicating ids: a duplicate id yields two entries, and each row
    // independently counts all items carrying that id. The filter still
    // accepts by id, so both rows expose the same items.
    let mut vault = Vault::new();
    vault.folders = vec![
        Folder {
            id: "dup".into(),
            name: "First".into(),
        },
        Folder {
            id: "dup".into(),
            name: "Second".into(),
        },
        Folder {
            id: "other".into(),
            name: "Other".into(),
        },
    ];
    let mut a = login("1", "A", "u", "p", "https://a.example");
    a.folder_id = Some("dup".into());
    let mut b = login("2", "B", "u", "p", "https://b.example");
    b.folder_id = Some("dup".into());
    let mut c = login("3", "C", "u", "p", "https://c.example");
    c.folder_id = Some("other".into());
    vault.items = vec![a, b, c];

    assert_eq!(
        vault.folder_counts(),
        vec![
            ("dup".to_string(), 2),
            ("dup".to_string(), 2),
            ("other".to_string(), 1),
        ]
    );
    let shown: Vec<&str> = vault
        .view(&Filter::Folder("dup".into()), "", SortKey::NameAsc)
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(shown, vec!["1", "2"]);
}

#[test]
fn ssh_fingerprint_rejects_a_non_ascii_blob() {
    // `decode` (model.rs:456-509) matches only ASCII base64 bytes, so a blob
    // containing non-ASCII characters cannot decode and no fingerprint is
    // produced. The store audit must report that as `InvalidPublicKey`
    // instead of hashing a truncated or lossy byte sequence.
    let canonical = super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQ== fp");
    assert!(
        canonical.is_some(),
        "the one-byte ASCII blob is the control"
    );
    for line in [
        "ssh-ed25519 あ fp",
        "ssh-ed25519 AQIあ fp",
        "ssh-ed25519 \u{30a2}\u{30a4}\u{30a6}",
    ] {
        assert_eq!(
            super::ssh_fingerprint::sha256_fingerprint(line),
            None,
            "{line:?}"
        );
        let key = ssh_key(line, REFERENCE_FINGERPRINT);
        assert_eq!(
            key.verify_fingerprint(),
            FingerprintVerify::InvalidPublicKey,
            "{line:?}"
        );
        assert!(!key.fingerprint_matches(), "{line:?}");
    }
    // The rejection is specific to the blob field: a non-ASCII trailing
    // comment is never decoded and must leave the fingerprint unchanged.
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQ== コメント"),
        canonical
    );
}

#[test]
fn ssh_fingerprint_rejects_five_character_base64_blob_with_nonempty_body() {
    // model.rs:493-502: five base64 characters carry 30 bits, i.e. three full
    // bytes (01 02 03 for `AQIDA`) plus six leftover bits. `leftover_bits >= 6`
    // must reject that shape even though the unused accumulator bits are zero
    // and the decoded body is non-empty. This pins the leftover-bit branch,
    // not the empty-blob guard or the non-canonical-padding-bit check.
    assert_eq!(super::ssh_fingerprint::decode(b"AQIDA"), None);
    assert_eq!(
        super::ssh_fingerprint::sha256_fingerprint("ssh-ed25519 AQIDA fp"),
        None
    );

    // Neighbouring lengths still decode: four characters give exactly three
    // bytes, six characters give four bytes with four leftover zero bits.
    assert_eq!(
        super::ssh_fingerprint::decode(b"AQID"),
        Some(vec![0x01, 0x02, 0x03])
    );
    assert_eq!(
        super::ssh_fingerprint::decode(b"AQIDAA"),
        Some(vec![0x01, 0x02, 0x03, 0x00])
    );
    // A single character leaves six bits *and* an empty body; it hits the same
    // `leftover_bits >= 6` clause but is rejected for the empty blob as well.
    assert_eq!(super::ssh_fingerprint::decode(b"A"), None);
}

#[test]
fn login_uri_debug_shows_the_numeric_match_type_and_masks_the_uri() {
    // The manual Debug (model.rs:562-569) masks the URI but keeps `match_type`
    // verbatim: diagnostics must be able to distinguish a Host rule from a
    // Never rule without ever showing credentials embedded in the URI.
    let uri = LoginUri {
        uri: "https://user:token@example.com/secret?key=VALUE".into(),
        match_type: Some(4),
    };
    let debug = format!("{uri:?}");
    assert!(debug.contains("LoginUri"), "{debug}");
    assert!(debug.contains("uri: \"https://example.com\""), "{debug}");
    assert!(debug.contains("match_type: Some(4)"), "{debug}");
    for leaked in ["user:token", "token", "/secret", "key=VALUE", "VALUE"] {
        assert!(!debug.contains(leaked), "leaked {leaked:?}: {debug}");
    }

    // None and every other number stay distinguishable in the same field.
    let none = format!("{:?}", LoginUri::new("https://example.com"));
    let never = format!(
        "{:?}",
        LoginUri {
            uri: "https://example.com".into(),
            match_type: Some(5),
        }
    );
    assert!(none.contains("match_type: None"), "{none}");
    assert!(never.contains("match_type: Some(5)"), "{never}");
    assert_ne!(none, never, "Debug must not collapse distinct match types");
}

#[test]
fn invisible_characters_in_non_name_haystack_fields_do_not_hide_search_hits() {
    // `comparison_key` drops Cc/Cf code points from every haystack
    // (model.rs:46-63), not just the name. A Cf/Cc inserted into a username,
    // URI, note or kind-specific field must therefore not hide its text from
    // search, and a needle carrying an invisible character folds the same way
    // (model.rs:837-909).
    let mut hidden = login(
        "l",
        "Unrelated Title",
        "ali\u{200b}ce@example.com",
        "pw",
        "https://ex\u{0007}ample.com/path",
    );
    hidden.notes = Zeroizing::new("rec\u{0000}overy-\u{2060}code".to_string());
    assert!(
        !hidden.name.contains("alice"),
        "precondition: name is unrelated"
    );
    assert!(hidden.matches_query("alice"), "username with ZWSP");
    assert!(hidden.matches_query("ali\u{200b}ce"), "needle with ZWSP");
    assert!(hidden.matches_query("example.com"), "URI with BEL control");
    assert!(
        hidden.matches_query("ex\u{0007}ample.com/path"),
        "URI-only needle folds like the plain spelling"
    );
    assert!(
        hidden.matches_query("recovery-code"),
        "notes with NUL + word joiner"
    );
    assert!(
        hidden.matches_query("rec\u{200b}overy-code"),
        "padded needle"
    );

    let note = VaultItem::new(
        "n",
        "Unrelated Title",
        ItemData::SecureNote {
            text: "to\u{200b}do-\u{202e}list".into(),
        },
    );
    assert!(note.matches_query("todo-list"), "secure-note text");

    let card = VaultItem::new(
        "c",
        "Unrelated Title",
        ItemData::Card(CardData {
            cardholder_name: "Vi\u{200b}sa".into(),
            brand: "Ma\u{0000}ster".into(),
            number: "4111111111111234".into(),
            ..CardData::default()
        }),
    );
    assert!(card.matches_query("visa"), "cardholder name");
    assert!(card.matches_query("master"), "card brand");

    let identity = VaultItem::new(
        "i",
        "Unrelated Title",
        ItemData::Identity(IdentityData {
            company: "A\u{2060}cme".into(),
            address: "42 Ma\u{200b}ple Ave".into(),
            ..IdentityData::default()
        }),
    );
    assert!(identity.matches_query("acme"), "identity company");
    assert!(identity.matches_query("maple ave"), "identity address");

    let ssh = VaultItem::new(
        "s",
        "Unrelated Title",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: String::new().into(),
            fingerprint: "SHA256:\u{0000}abc".into(),
        }),
    );
    assert!(ssh.matches_query("sha256:abc"), "SSH fingerprint");

    // A needle made only of invisible characters is still blank, so it must
    // not widen the result through any of those fields.
    for blank in ["\u{200b}", "\u{0000}", "\u{202e}\u{200b}", " \u{200b} "] {
        assert!(!hidden.matches_query(blank), "blank needle {blank:?}");
    }

    // The same folded key is used when the needle goes through Vault::view.
    let mut vault = Vault::new();
    vault.items = vec![hidden];
    assert_eq!(
        vault
            .view(&Filter::All, "ali\u{200b}ce", SortKey::NameAsc)
            .len(),
        1
    );
    assert_eq!(
        vault
            .view(&Filter::All, "recovery-code", SortKey::NameAsc)
            .len(),
        1
    );
}

#[test]
fn mark_only_totp_value_is_present_for_the_badge_but_has_no_visible_identity() {
    // A bare combining mark is not whitespace, Cc or Cf, so the narrow
    // `is_visually_empty` rule used by the TOTP badge keeps the field present.
    // The stricter `has_no_visible_identity` rule used by search and duplicate
    // detection adds the mark-only case and treats the same value as blank
    // (model.rs:114-149). The two rules must not be conflated for a TOTP field.
    const MARKS: &str = "\u{0301}\u{0300}\u{0301}";
    assert!(!super::is_visually_empty(MARKS));
    assert!(super::has_no_visible_identity(MARKS));
    assert!(super::is_visually_empty("\u{200b}"));
    assert!(super::has_no_visible_identity("\u{200b}"));

    let mut item = login("1", "Login", "u", "p", "https://example.com");
    if let ItemData::Login { totp, .. } = &mut item.data {
        *totp = Zeroizing::new(MARKS.to_string());
    }
    let value = item.totp_secret().expect("a login has a TOTP field");
    assert_eq!(value, MARKS);
    assert!(!super::is_visually_empty(value), "field counts as present");
    assert!(
        super::has_no_visible_identity(value),
        "but it is not a usable identifier"
    );
    assert!(
        !item.matches_query(MARKS),
        "a mark-only needle must not widen the result"
    );
}

// --- R2-CORE-146: non-blank query through every sort except the default ---

#[test]
fn non_blank_query_sorts_by_name_desc_recently_modified_and_kind() {
    // The existing sorting guards use a blank query. Here the non-blank query
    // matches every item through a shared, searchable note, so each sort must
    // order the matched subset differently (model.rs:1080-1106, 1221-1231).
    // A stub that ignored `sort` cannot satisfy all four expectations at once.
    let with_marker = |mut value: VaultItem, revision: i64| {
        value.notes = Zeroizing::new("SHARED-marker".into());
        value.revision_date = revision;
        value
    };
    let vault = Vault {
        items: vec![
            with_marker(login("l-z", "Zulu", "u", "p", "https://z.example"), 100),
            with_marker(login("l-a", "Alpha", "u", "p", "https://a.example"), 300),
            with_marker(
                VaultItem::new("c-m", "Mike", ItemData::Card(CardData::default())),
                200,
            ),
            with_marker(
                VaultItem::new("n-b", "Bravo", ItemData::SecureNote { text: "x".into() }),
                400,
            ),
        ],
        folders: Vec::new(),
    };

    let ids = |sort| -> Vec<&str> {
        vault
            .view(&Filter::All, "SHARED", sort)
            .iter()
            .map(|item| item.id.as_str())
            .collect()
    };
    assert_eq!(ids(SortKey::NameAsc), vec!["l-a", "n-b", "c-m", "l-z"]);
    assert_eq!(ids(SortKey::NameDesc), vec!["l-z", "c-m", "n-b", "l-a"]);
    assert_eq!(
        ids(SortKey::RecentlyModified),
        vec!["n-b", "l-a", "c-m", "l-z"]
    );
    // Login (wire 1), SecureNote (2), Card (3); same-kind ties by name.
    assert_eq!(ids(SortKey::Kind), vec!["l-a", "l-z", "n-b", "c-m"]);
}

#[test]
fn non_blank_query_sort_tiebreaks_survive_filtering() {
    // With a non-blank query, `NameDesc` reverses the whole name+id key while
    // `RecentlyModified` and `Kind` reuse its un-reversed form as a tiebreak
    // (model.rs:1221-1231). A filter must narrow the set before either rule
    // runs, never reintroduce a filtered-out item through sorting.
    let with_marker = |mut value: VaultItem, revision: i64| {
        value.notes = Zeroizing::new("SHARED-marker".into());
        value.revision_date = revision;
        value
    };
    let vault = Vault {
        items: vec![
            with_marker(login("z-login", "Same", "u", "p", "https://z.example"), 100),
            with_marker(
                VaultItem::new("a-card", "Same", ItemData::Card(CardData::default())),
                100,
            ),
            with_marker(login("m-login", "Zulu", "u", "p", "https://m.example"), 900),
        ],
        folders: Vec::new(),
    };

    let ids = |filter: &Filter, query: &str, sort| -> Vec<&str> {
        vault
            .view(filter, query, sort)
            .iter()
            .map(|item| item.id.as_str())
            .collect()
    };

    // All three match: descending name flips the id tie ("z-login" before
    // "a-card"), while revision/kind ties keep ascending id order.
    assert_eq!(
        ids(&Filter::All, "SHARED", SortKey::NameDesc),
        vec!["m-login", "z-login", "a-card"]
    );
    assert_eq!(
        ids(&Filter::All, "SHARED", SortKey::RecentlyModified),
        vec!["m-login", "a-card", "z-login"]
    );
    assert_eq!(
        ids(&Filter::All, "SHARED", SortKey::Kind),
        vec!["z-login", "m-login", "a-card"]
    );

    // Narrowing to logins drops the card from every sort; the kind sort then
    // reduces to the ascending name+id tiebreak.
    for sort in [SortKey::NameDesc, SortKey::RecentlyModified] {
        assert_eq!(
            ids(&Filter::Kind(ItemKind::Login), "SHARED", sort),
            vec!["m-login", "z-login"],
            "{sort:?}"
        );
    }
    assert_eq!(
        ids(&Filter::Kind(ItemKind::Login), "SHARED", SortKey::Kind),
        vec!["z-login", "m-login"]
    );

    // A non-blank query that matches one item keeps that one item under every
    // sort; the sort order cannot widen the matched set.
    for sort in [
        SortKey::NameAsc,
        SortKey::NameDesc,
        SortKey::RecentlyModified,
        SortKey::Kind,
    ] {
        assert_eq!(ids(&Filter::All, "ZULU", sort), vec!["m-login"], "{sort:?}");
    }
}
