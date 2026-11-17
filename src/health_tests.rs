#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::health::*;
use crate::model::{CardData, Folder, ItemData, LoginUri, VaultItem};

const NOW: i64 = 1_700_000_000;

fn login(id: &str, name: &str, password: &str, uri: &str, totp: &str) -> VaultItem {
    VaultItem::new(
        id,
        name,
        ItemData::Login {
            username: "user".into(),
            password: password.into(),
            totp: totp.into(),
            uris: vec![LoginUri::new(uri)],
        },
    )
}

fn report_of(items: Vec<VaultItem>) -> Report {
    let mut vault = Vault::new();
    vault.items = items;
    audit(&vault, Thresholds::default(), NOW)
}

#[test]
fn empty_password_has_no_entropy() {
    assert_eq!(estimate_entropy(""), 0);
    assert_eq!(estimate_entropy("aaaaaaaa"), 0);
}

#[test]
fn longer_and_wider_passwords_score_higher() {
    let short = estimate_entropy("aB3!");
    let long = estimate_entropy("aB3!aB3!aB3!aB3!");
    assert!(long > short, "{long} vs {short}");
    let narrow = estimate_entropy("abcdefghijklmnop");
    let wide = estimate_entropy("aB3!aB3!aB3!aB3!");
    assert!(wide > narrow, "{wide} vs {narrow}");
}

#[test]
fn numeric_pins_are_charged_the_digit_pool() {
    // 10 digits * 4 chars = ~13 bits, not 33 bits.
    assert_eq!(estimate_entropy("1234"), entropy_bits(10, 4).round() as u32);
    // 12 digits * 10 symbols ~= 40 bits; the cutoff is not precise, but a
    // date-style numeric string should not score like a random 12-byte
    // password.
    assert!(estimate_entropy("170419880001") < 45);
}

#[test]
fn common_passwords_collapse_to_a_dictionary_estimate() {
    let common = estimate_entropy("password123");
    let random = estimate_entropy("vT7#kQm2!zR9");
    assert!(common < random, "{common} vs {random}");
    assert!(common < 20, "{common}");
    assert!(estimate_entropy("PASSWORD") < 20);
    assert!(estimate_entropy("qwerty") < 20);
}

#[test]
fn word_plus_short_suffix_is_charged_only_the_suffix() {
    let suffixed = estimate_entropy("sunflower42");
    let unsuffixed = estimate_entropy("sunflower");
    assert!(suffixed > unsuffixed);
    // The raw 11-character pool estimate is ~57 bits; the suffix model
    // should cap it near the word (9 letters ~= 42 bits) plus the two
    // digit suffix (~6.6 bits), i.e. well below the raw value.
    let raw = entropy_bits(36, 11);
    assert!(suffixed < raw as u32, "{suffixed} vs raw {raw}");
}

#[test]
fn strength_buckets_follow_the_estimate() {
    let (bits, strength) = password_strength("1234");
    assert!(bits < 50);
    assert_eq!(strength, Strength::Weak);
    let (bits, strength) = password_strength("vT7#kQm2!zR9wP4$xL8@");
    assert!(bits >= 90, "{bits}");
    assert_eq!(strength, Strength::Strong);
}

#[test]
fn weak_and_reused_passwords_are_reported() {
    let report = report_of(vec![
        login("1", "A", "1234", "https://a.example", "SECRET"),
        login("2", "B", "1234", "https://b.example", "SECRET"),
    ]);
    assert_eq!(report.examined, 2);
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 2);
    assert!((report.totp_coverage() - 1.0).abs() < 1e-6);
    assert_eq!(report.affected(), 2);
    // Each item: weak + reused = 2 findings.
    assert_eq!(report.total_findings(), 4);
    assert_eq!(report.count_of(Severity::High), 2);
    assert_eq!(report.count_of(Severity::Medium), 2);
    for item in &report.items {
        assert!(item
            .findings
            .contains(&Finding::ReusedPassword { count: 2 }));
        assert!(item.findings.contains(&Finding::WeakPassword { bits: 13 }));
    }
}

#[test]
fn a_password_used_once_is_not_reuse() {
    let report = report_of(vec![login(
        "1",
        "A",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "S",
    )]);
    assert!(!report
        .items
        .iter()
        .flat_map(|item| item.findings.iter())
        .any(|finding| matches!(finding, Finding::ReusedPassword { .. })));
}

#[test]
fn reused_passwords_compare_exactly() {
    let report = report_of(vec![
        login("1", "A", "same", "https://a.example", "S"),
        login("2", "B", "same", "https://b.example", "S"),
        login("3", "C", "Same", "https://c.example", "S"),
    ]);
    let reused: Vec<usize> = report
        .items
        .iter()
        .flat_map(|item| item.findings.iter())
        .filter_map(|finding| match finding {
            Finding::ReusedPassword { count } => Some(*count),
            _ => None,
        })
        .collect();
    assert_eq!(reused, vec![2, 2]);
}

#[test]
fn insecure_uris_and_missing_totp_and_uri_are_reported() {
    let report = report_of(vec![login(
        "1",
        "A",
        "vT7#kQm2!zR9wP4$xL8@",
        "http://a.example",
        "",
    )]);
    let findings = &report.items[0].findings;
    assert!(findings.contains(&Finding::NoTotp));
    assert!(findings
        .iter()
        .any(|f| matches!(f, Finding::InsecureUri { uri } if uri == "http://a.example")));
    assert_eq!(report.with_totp, 0);
    assert_eq!(report.totp_coverage(), 0.0);

    let report = report_of(vec![VaultItem::new(
        "2",
        "NoUri",
        ItemData::Login {
            username: "u".into(),
            password: "vT7#kQm2!zR9wP4$xL8@".into(),
            totp: "S".into(),
            uris: Vec::new(),
        },
    )]);
    assert!(report.items[0].findings.contains(&Finding::NoUri));
}

#[test]
fn totp_coverage_counts_logins_only() {
    let mut note = VaultItem::new("3", "Note", ItemData::SecureNote { text: "x".into() });
    note.revision_date = NOW;
    let report = report_of(vec![
        login(
            "1",
            "A",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "SECRET",
        ),
        login("2", "B", "vT7#kQm2!zR9wP4$xL8@", "https://b.example", ""),
        note,
    ]);
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
    assert!((report.totp_coverage() - 0.5).abs() < 1e-6);
}

#[test]
fn stale_items_use_the_threshold_and_skip_unknown_dates() {
    let mut old = login("1", "Old", "vT7#kQm2!zR9wP4$xL8@", "https://a.example", "S");
    old.revision_date = NOW - 400 * 86_400;
    let mut unknown = login(
        "2",
        "Unknown",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://b.example",
        "S",
    );
    unknown.revision_date = 0;
    let mut fresh = login(
        "3",
        "Fresh",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://c.example",
        "S",
    );
    fresh.revision_date = NOW - 10 * 86_400;

    let report = report_of(vec![old, unknown, fresh]);
    let stale: Vec<&ItemReport> = report
        .items
        .iter()
        .filter(|item| {
            item.findings
                .iter()
                .any(|f| matches!(f, Finding::Stale { .. }))
        })
        .collect();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].id, "1");
    assert!(stale[0].findings.contains(&Finding::Stale { days: 400 }));
}

#[test]
fn unnamed_items_are_reported() {
    let report = report_of(vec![login(
        "1",
        "  ",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "S",
    )]);
    assert!(report.items[0].findings.contains(&Finding::Unnamed));
    assert_eq!(report.items[0].name, "  ");
}

#[test]
fn findings_sort_and_summarize() {
    let report = report_of(vec![login("1", "Weak", "1234", "http://a.example", "")]);
    assert_eq!(report.items[0].worst(), Some(Severity::High));
    let summary = report.summary();
    assert!(summary.contains("1 件を検査"), "{summary}");
    assert!(summary.contains("高 1"), "{summary}");
    let text = report.to_text();
    assert!(text.contains("Vault 健全性レポート"));
    assert!(text.contains("Weak"));
    assert!(text.contains("弱いパスワード"));
}

#[test]
fn a_clean_vault_reports_no_problems() {
    let mut item = login(
        "1",
        "Clean",
        "vT7#kQm2!zR9wP4$xL8@bN6",
        "https://clean.example",
        "GEZDGNBVGY3TQOJQ",
    );
    item.revision_date = NOW;
    let report = report_of(vec![item]);
    assert!(report.items.is_empty());
    assert_eq!(report.total_findings(), 0);
    assert_eq!(report.affected(), 0);
    assert!(report.summary().contains("問題は見つかりませんでした"));
    assert_eq!(report.totp_coverage(), 1.0);
}

#[test]
fn evidence_text_reports_when_there_is_no_login() {
    let report = report_of(Vec::new());
    assert_eq!(report.examined, 0);
    assert_eq!(report.logins, 0);
    assert_eq!(report.totp_coverage(), 0.0);
    assert!(report.to_text().contains("Vault 健全性レポート"));
}

#[test]
fn cards_without_a_number_are_flagged_and_notes_are_not() {
    let mut card = VaultItem::new("1", "Visa", ItemData::Card(CardData::default()));
    card.revision_date = NOW;
    let mut note = VaultItem::new("2", "Note", ItemData::SecureNote { text: "hi".into() });
    note.revision_date = NOW;
    note.folder_id = Some("f".into());
    let report = report_of(vec![card, note]);
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].id, "1");
    assert!(report.items[0].findings.contains(&Finding::NoUri));
    let _ = Folder {
        id: "f".into(),
        name: "F".into(),
    };
}

#[test]
fn severity_labels_and_ordering() {
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert_eq!(Severity::Low.label(), "低");
    assert!(Finding::NoTotp.message().contains("TOTP"));
    assert!(Finding::NoUri.message().contains("URI"));
    assert!(Finding::Unnamed.message().contains("名前"));
}

#[::core::prelude::v1::test]
fn insecure_uri_messages_never_include_secrets() {
    let finding = Finding::InsecureUri {
        uri: "http://user:token@example.com/path?key=secret".into(),
    };
    let message = finding.message();
    assert!(message.contains("http://example.com"), "{message}");
    assert!(!message.contains("token"), "{message}");
    assert!(!message.contains("secret"), "{message}");
}

#[test]
fn reports_are_ordered_worst_first_then_by_name() {
    let mut high = login("1", "Zebra", "1234", "http://a.example", "");
    high.revision_date = NOW;
    let mut low = login(
        "2",
        "Apple",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://b.example",
        "",
    );
    low.revision_date = NOW;
    let report = report_of(vec![low, high]);
    assert_eq!(report.items[0].id, "1");
    assert_eq!(report.items[1].id, "2");
}
