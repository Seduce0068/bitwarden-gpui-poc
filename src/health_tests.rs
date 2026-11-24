#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::generator::{entropy_bits, DIGITS, LOWERCASE, SYMBOLS, UPPERCASE};
use crate::health::*;
use crate::model::{CardData, ItemData, ItemKind, LoginUri, SshKeyData, VaultItem};
use crate::vault_sync::{is_undecryptable_password, UNDECRYPTABLE_PASSWORD, UNDECRYPTABLE_TOTP};
use zeroize::Zeroizing;

const NOW: i64 = 1_700_000_000;

fn login(id: &str, name: &str, password: &str, uri: &str, totp: &str) -> VaultItem {
    VaultItem::new(
        id,
        name,
        ItemData::Login {
            username: "user".into(),
            password: Zeroizing::new(password.to_string()),
            totp: Zeroizing::new(totp.to_string()),
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
fn mixed_case_single_character_runs_get_the_all_same_penalty() {
    // The all-same check folds case first: `aAaAaA` is one repeated
    // character, not six independent draws from a mixed-case pool. Testing
    // the original code points let it keep a positive score.
    for password in ["aAaAaA", "AaAaAa", "aAaAaA1", "AaAaAa42"] {
        assert_eq!(estimate_entropy(password), 0, "{password}");
    }
    // A genuine mixed run still scores from the character pool, and the
    // separate word + trailing-digit discount is untouched by the folded
    // all-same check.
    assert!(estimate_entropy("aAbBcC") > 0);
    assert!(estimate_entropy("sunflower42") > estimate_entropy("sunflower"));
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
fn non_ascii_passwords_use_the_wide_pool() {
    let japanese = estimate_entropy("あいうえおかきくけこ");
    let ascii_same_length = estimate_entropy("abcdefghij");
    assert!(
        japanese > ascii_same_length,
        "{japanese} vs {ascii_same_length}"
    );
    // The same non-ASCII character repeated has no entropy.
    assert_eq!(estimate_entropy("あああああ"), 0);
}

#[test]
fn entropy_pool_matches_the_generator_classes() {
    // The estimator must not inflate a symbol-only password with a generic
    // 33-symbol pool: the generator's SYMBOLS has exactly eight characters.
    let symbols = "!@#$%^&*!@#$%^&*";
    assert_eq!(
        estimate_entropy(symbols),
        entropy_bits(SYMBOLS.len(), 16).round() as u32
    );
    let lower = "abcdefghijklmnop";
    assert_eq!(
        estimate_entropy(lower),
        entropy_bits(LOWERCASE.len(), 16).round() as u32
    );
    let upper = "ABCDEFGHIJKLMNOP";
    assert_eq!(
        estimate_entropy(upper),
        entropy_bits(UPPERCASE.len(), 16).round() as u32
    );
    let mixed = "aB3!aB3!aB3!aB3!";
    let pool = LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len();
    assert_eq!(
        estimate_entropy(mixed),
        entropy_bits(pool, 16).round() as u32
    );
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
fn very_long_numeric_pins_are_clamped_like_the_character_pool_path() {
    // 400 digits * log2(10) is ~1329 bits. The character-pool and passphrase
    // paths clamp their estimate to 1000 bits; the numeric-PIN branch must
    // apply the same ceiling so an ultra-long digit run cannot report more.
    let long = "1234567890".repeat(40);
    assert_eq!(long.len(), 400);
    assert_eq!(estimate_entropy(&long), 1000);
    assert_eq!(password_strength(&long).1, Strength::Strong);
    // A mixed-character value of the same length is clamped identically.
    let mixed = "aB3!".repeat(100);
    assert_eq!(estimate_entropy(&mixed), 1000);
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
fn a_password_shared_by_three_logins_reports_a_count_of_three() {
    // `audit_item` reports the whole group size (health.rs:827-831), not a
    // fixed "2 件". A strong shared password keeps WeakPassword out of the
    // way so only the reuse finding carries the count.
    const SHARED: &str = "vT7#kQm2!zR9wP4$xL8@";
    let report = report_of(vec![
        login("1", "A", SHARED, "https://a.example", "GEZDGNBVGY3TQOJQ"),
        login("2", "B", SHARED, "https://b.example", "GEZDGNBVGY3TQOJQ"),
        login("3", "C", SHARED, "https://c.example", "GEZDGNBVGY3TQOJQ"),
    ]);
    let counts: Vec<usize> = report
        .items
        .iter()
        .flat_map(|item| item.findings.iter())
        .filter_map(|finding| match finding {
            Finding::ReusedPassword { count } => Some(*count),
            _ => None,
        })
        .collect();
    assert_eq!(counts, vec![3, 3, 3]);
    assert_eq!(report.examined, 3);
    assert_eq!(report.logins, 3);
    assert_eq!(report.affected(), 3);
    let message = (Finding::ReusedPassword { count: 3 }).message();
    assert!(message.contains("3 件"), "{message}");
    assert!(!message.contains("2 件"), "{message}");
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
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("S".into()),
            uris: Vec::new(),
        },
    )]);
    assert!(report.items[0].findings.contains(&Finding::NoUri));
}

#[test]
fn whitespace_and_format_only_uris_are_reported_as_no_uri() {
    // A blank-looking URI is no better than an empty list for autofill: the
    // audit shares the model's `is_visually_empty` rule with the name/card/
    // TOTP checks, so Cf-only and Cc-only values cannot masquerade as a real
    // URI (health.rs:860-902).
    for blank in [
        "",
        " ",
        "  \t  ",
        "\u{200b}",         // ZERO WIDTH SPACE (Cf)
        "\u{202e}\u{200b}", // bidi override + ZWSP
        "\u{00a0}",         // NO-BREAK SPACE
        "\u{0000}",         // NUL (Cc)
    ] {
        let item = VaultItem::new(
            "blank-uri",
            "Login",
            ItemData::Login {
                username: "u".into(),
                password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
                totp: Zeroizing::new("GEZDGNBVGY3TQOJQ".into()),
                uris: vec![LoginUri::new(blank)],
            },
        );
        let report = report_of(vec![item]);
        let findings = &report.items[0].findings;
        assert!(
            findings.contains(&Finding::NoUri),
            "uri {blank:?}: {findings:?}"
        );
        assert!(
            !findings.contains(&Finding::UriUninspectable),
            "uri {blank:?}"
        );
        assert_eq!(findings.len(), 1, "uri {blank:?}: {findings:?}");
    }

    // A blank entry next to a real URI must not hide the real one: the login
    // stays clean and no NoUri is produced.
    let mixed = VaultItem::new(
        "blank-and-real",
        "Login",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("GEZDGNBVGY3TQOJQ".into()),
            uris: vec![
                LoginUri::new("\u{200b}"),
                LoginUri::new("https://real.example"),
            ],
        },
    );
    assert!(
        report_of(vec![mixed]).items.is_empty(),
        "a visible URI keeps the login clean"
    );

    // The undecryptable marker still takes precedence over NoUri: it renders
    // visible text and is therefore not filtered out as a blank URI.
    use crate::vault_sync::UNDECRYPTABLE_URI;
    let marked = VaultItem::new(
        "undecryptable",
        "Login",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("GEZDGNBVGY3TQOJQ".into()),
            uris: vec![LoginUri::new(UNDECRYPTABLE_URI)],
        },
    );
    let report = report_of(vec![marked]);
    assert!(report.items[0]
        .findings
        .contains(&Finding::UriUninspectable));
    assert!(!report.items[0].findings.contains(&Finding::NoUri));
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
    // The report must show the same placeholder it uses for a truly empty
    // name: an invisible whitespace-only value is still an unnamed item.
    assert_eq!(report.items[0].name, "(名称未設定)");
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
fn to_text_reports_totp_coverage_and_medium_low_counts() {
    // Three logins with https URIs so no High/InsecureUri finding can skew the
    // counts: one weak password (Medium), one missing TOTP (Low), one clean
    // login with a usable TOTP. The weak-password login also carries a valid
    // base32 secret, so coverage is 2/3 -> 67% after rounding.
    let weak = login("1", "Weak", "1234", "https://a.example", "SECRET");
    let no_totp = login(
        "2",
        "NoTotp",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://b.example",
        "",
    );
    let clean = login(
        "3",
        "Clean",
        "tQ8#wLr1!eZ5vKp3$sM7@",
        "https://c.example",
        "GEZDGNBVGY3TQOJQ",
    );
    let report = report_of(vec![weak, no_totp, clean]);

    assert_eq!(report.examined, 3);
    assert_eq!(report.logins, 3);
    assert_eq!(report.with_totp, 2);
    assert_eq!(report.affected(), 2);
    assert_eq!(report.total_findings(), 2);
    assert_eq!(report.count_of(Severity::High), 0);
    assert_eq!(report.count_of(Severity::Medium), 1);
    assert_eq!(report.count_of(Severity::Low), 1);

    let summary = report.summary();
    assert!(summary.contains("高 0 / 中 1 / 低 1"), "{summary}");
    assert!(summary.contains("パスワード検査対象外: 0 件"), "{summary}");

    // `to_text()` (health.rs:256-282) pins the TOTP coverage line separately
    // from the summary: the ratio, denominator and rounded percentage must all
    // be rendered, not just the `totp_coverage()` float.
    let text = report.to_text();
    assert!(text.starts_with("Vault 健全性レポート\n"), "{text}");
    assert!(text.contains(summary.as_str()), "{text}");
    assert!(text.contains("TOTP 設定済み: 2/3 (67%)\n"), "{text}");
    assert!(text.contains("パスワード検査対象外: 0 件\n"), "{text}");
}

#[test]
fn to_text_renders_the_item_kind_label_for_every_kind() {
    // `Report::to_text` (health.rs:271-277) renders each finding-bearing item
    // as `[severity] name (kind.label())`. All five `ItemKind` labels are
    // user-visible vocabulary in the exported report, so pin the exact line
    // for each kind: a label regression must not silently relabel an item.
    let kinds = [
        (ItemKind::Login, "ログイン"),
        (ItemKind::SecureNote, "メモ"),
        (ItemKind::Card, "カード"),
        (ItemKind::Identity, "ID"),
        (ItemKind::SshKey, "SSH鍵"),
    ];
    let severity_label = Finding::Unnamed.severity().label();
    let report = Report {
        examined: kinds.len(),
        items: kinds
            .iter()
            .map(|(kind, _)| ItemReport {
                id: format!("id-{}", kind.to_wire()),
                name: format!("Name-{}", kind.to_wire()),
                kind: *kind,
                findings: vec![Finding::Unnamed],
            })
            .collect(),
        ..Report::default()
    };

    let text = report.to_text();
    for (kind, label) in kinds {
        let name = format!("Name-{}", kind.to_wire());
        assert!(
            text.contains(&format!("[{severity_label}] {name} ({label})\n")),
            "missing kind label {label:?} for {name}: {text}"
        );
    }
    // A stub that printed one label for every item could not satisfy the
    // five distinct per-name assertions above; guard the premise as well.
    let labels: Vec<_> = kinds.iter().map(|(_, label)| *label).collect();
    for (index, label) in labels.iter().enumerate() {
        assert!(!labels[..index].contains(label), "duplicate label: {label}");
    }
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
    let text = report.to_text();
    assert!(text.contains("Vault 健全性レポート"), "{text}");
    assert!(text.contains("TOTP 設定済み: 0/0 (0%)\n"), "{text}");
}

#[test]
fn evidence_text_reports_zero_totp_coverage_when_items_are_not_logins() {
    // A vault may hold non-login items while `logins` stays 0. The coverage
    // line must still be rendered with a zero denominator (health.rs:261-266),
    // not skipped or turned into a NaN/infinity percentage.
    let mut card = VaultItem::new("1", "Visa", ItemData::Card(CardData::default()));
    card.revision_date = NOW;
    let report = report_of(vec![card]);
    assert_eq!(report.examined, 1);
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.logins, 0);
    assert_eq!(report.with_totp, 0);
    assert_eq!(report.totp_coverage(), 0.0);
    let text = report.to_text();
    assert!(text.contains("Vault 健全性レポート"), "{text}");
    assert!(text.contains("TOTP 設定済み: 0/0 (0%)\n"), "{text}");
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
    assert!(report.items[0].findings.contains(&Finding::NoCardNumber));
    assert!(!report.items[0].findings.contains(&Finding::NoUri));
    assert!(
        !report.items.iter().any(|item| item.id == "2"),
        "a note inside a folder must not be flagged"
    );
}

#[test]
fn severity_labels_and_ordering() {
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert_eq!(Severity::Low.label(), "低");
    assert!(Finding::NoTotp.message().contains("TOTP"));
    assert!(Finding::NoUri.message().contains("URI"));
    assert!(Finding::NoCardNumber.message().contains("カード番号"));
    assert!(Finding::Unnamed.message().contains("名前"));
}

#[test]
fn findings_within_an_item_are_sorted_by_severity() {
    // The audit sorts each item's findings worst-first (health.rs:766-768).
    // One item collects all three severities: reuse + insecure URI (High),
    // weak password + stale (Medium) and a missing TOTP (Low).
    let mut primary = login("1", "Primary", "1234", "http://a.example", "");
    primary.revision_date = NOW - 400 * 86_400;
    let second = login("2", "Second", "1234", "https://b.example", "SECRET");
    let report = report_of(vec![primary, second]);
    let item = report
        .items
        .iter()
        .find(|item| item.id == "1")
        .expect("the item has findings");

    let severities: Vec<Severity> = item.findings.iter().map(Finding::severity).collect();
    assert_eq!(
        severities,
        vec![
            Severity::High,
            Severity::High,
            Severity::Medium,
            Severity::Medium,
            Severity::Low,
        ],
        "{item:?}"
    );
    assert!(matches!(
        item.findings[0],
        Finding::ReusedPassword { count: 2 }
    ));
    assert!(matches!(item.findings[1], Finding::InsecureUri { .. }));
    assert!(matches!(item.findings[2], Finding::WeakPassword { .. }));
    assert!(matches!(item.findings[3], Finding::Stale { .. }));
    assert_eq!(item.findings[4], Finding::NoTotp);
    assert_eq!(item.worst(), Some(Severity::High));
}

#[test]
fn item_without_findings_has_no_worst_severity() {
    let item = ItemReport {
        id: "x".into(),
        name: "Clean".into(),
        kind: ItemKind::Login,
        findings: Vec::new(),
    };
    assert_eq!(item.worst(), None);
}

#[test]
fn every_finding_has_a_nonempty_message() {
    let findings = [
        Finding::WeakPassword { bits: 10 },
        Finding::ReusedPassword { count: 2 },
        Finding::Stale { days: 400 },
        Finding::InsecureUri {
            uri: "http://example.com".into(),
        },
        Finding::NoTotp,
        Finding::TotpUninspectable,
        Finding::PasswordUninspectable,
        Finding::NoUri,
        Finding::UriUninspectable,
        Finding::NoCardNumber,
        Finding::SshFingerprintMismatch {
            computed: "SHA256:AAAA".into(),
        },
        Finding::SshFingerprintInvalid,
        Finding::Unnamed,
    ];
    for finding in findings {
        let message = finding.message();
        assert!(!message.trim().is_empty(), "{finding:?}");
    }
}

#[test]
fn every_finding_variant_has_a_documented_severity() {
    // `Finding::severity` (health.rs:116-130) partitions all 13 variants into
    // High/Medium/Low. This table pins every current arm, so adding a finding
    // variant is an explicit, reviewed change to this expectation as well.
    let cases = [
        (Finding::WeakPassword { bits: 10 }, Severity::Medium),
        (Finding::ReusedPassword { count: 2 }, Severity::High),
        (Finding::Stale { days: 400 }, Severity::Medium),
        (
            Finding::InsecureUri {
                uri: "http://example.com".into(),
            },
            Severity::High,
        ),
        (Finding::NoTotp, Severity::Low),
        (Finding::TotpUninspectable, Severity::Low),
        (Finding::PasswordUninspectable, Severity::Low),
        (Finding::NoUri, Severity::Low),
        (Finding::UriUninspectable, Severity::Low),
        (Finding::NoCardNumber, Severity::Medium),
        (
            Finding::SshFingerprintMismatch {
                computed: "SHA256:AAAA".into(),
            },
            Severity::High,
        ),
        (Finding::SshFingerprintInvalid, Severity::Low),
        (Finding::Unnamed, Severity::Low),
    ];
    assert_eq!(cases.len(), 13);
    for (finding, expected) in cases {
        assert_eq!(finding.severity(), expected, "{finding:?}");
    }
}

#[test]
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
fn insecure_uri_stores_only_scheme_and_host() {
    const RAW: &str = "http://user:token@example.com:8080/path?key=secret#frag";
    const MASKED: &str = "http://example.com:8080";

    let report = report_of(vec![login("1", "A", "vT7#kQm2!zR9wP4$xL8@", RAW, "")]);
    let (finding, uri) = report.items[0]
        .findings
        .iter()
        .find_map(|f| match f {
            Finding::InsecureUri { uri } => Some((f, uri)),
            _ => None,
        })
        .expect("the http URI must be reported");

    // The field itself holds the masked form, not the raw URI.
    assert_eq!(uri, MASKED, "stored uri must be masked");
    assert_eq!(finding.message(), format!("http の URI（{MASKED}）"));

    // Debug output and serde serialization must not leak credentials, path,
    // query or fragment -- neither for the finding nor for the whole report.
    let debug = format!("{finding:?}");
    let json = serde_json::to_string(finding).expect("serialize finding");
    let report_debug = format!("{report:?}");
    let report_json = serde_json::to_string(&report).expect("serialize report");
    for rendered in [&debug, &json, &report_debug, &report_json] {
        assert!(rendered.contains(MASKED), "{rendered}");
        for secret in [
            "user:token",
            "token",
            "/path",
            "key=secret",
            "secret",
            "#frag",
        ] {
            assert!(
                !rendered.contains(secret),
                "leaked {secret:?} in {rendered}"
            );
        }
    }
}

#[test]
fn empty_passwords_are_reported_as_weak() {
    let report = report_of(vec![
        login("1", "Empty", "", "https://a.example", "SECRET"),
        login("2", "Another", "", "https://b.example", "SECRET"),
    ]);
    assert_eq!(report.items.len(), 2);
    for item in &report.items {
        assert!(
            item.findings.contains(&Finding::WeakPassword { bits: 0 }),
            "{item:?}"
        );
        // Two empty passwords are not a reused password: they carry no
        // guessable value to share.
        assert!(!item
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::ReusedPassword { .. })));
    }
}

#[test]
fn visually_empty_passwords_are_not_registered_as_reused() {
    // The reuse map in `audit` now shares the model's `is_visually_empty` rule
    // with the name/card/URI/TOTP checks (health.rs:741-751). Whitespace, Cc
    // controls and Unicode `Cf` render nothing, so two logins carrying such a
    // password must not be reported as sharing one. They still take the
    // WeakPassword path, so the exclusion is not a blanket skip.
    for blank in [
        " ",
        "  \t  ",
        "\u{200b}",             // ZERO WIDTH SPACE (Cf)
        "\u{feff}\u{200d}",     // BOM + ZWJ (Cf)
        " \u{200b}\t\u{2060} ", // Cf mixed with whitespace
        "\u{0}\u{9f}",          // NUL + C1 control (Cc)
    ] {
        let report = report_of(vec![
            login("1", "A", blank, "https://a.example", "GEZDGNBVGY3TQOJQ"),
            login("2", "B", blank, "https://b.example", "GEZDGNBVGY3TQOJQ"),
        ]);
        assert_eq!(report.items.len(), 2, "password {blank:?}");
        for item in &report.items {
            assert!(
                item.findings
                    .iter()
                    .any(|finding| matches!(finding, Finding::WeakPassword { .. })),
                "password {blank:?}: {item:?}"
            );
            assert!(
                !item
                    .findings
                    .iter()
                    .any(|finding| matches!(finding, Finding::ReusedPassword { .. })),
                "blank password {blank:?} must not be a reuse match: {item:?}"
            );
        }
    }

    // Control: a real shared password is still counted, so the exclusion above
    // is about visible content rather than a disabled reuse check.
    const SHARED: &str = "vT7#kQm2!zR9wP4$xL8@";
    let report = report_of(vec![
        login("1", "A", SHARED, "https://a.example", "GEZDGNBVGY3TQOJQ"),
        login("2", "B", SHARED, "https://b.example", "GEZDGNBVGY3TQOJQ"),
    ]);
    assert_eq!(report.items.len(), 2);
    for item in &report.items {
        assert!(
            item.findings
                .contains(&Finding::ReusedPassword { count: 2 }),
            "{item:?}"
        );
    }

    // A blank-looking pair beside the real pair must not form its own reuse
    // group either: only the two real logins carry a ReusedPassword finding.
    // Under the old `!password.is_empty()` check these two Cf-only entries
    // passed the map gate and produced two extra count-2 findings.
    let mixed = report_of(vec![
        login("1", "A", SHARED, "https://a.example", "GEZDGNBVGY3TQOJQ"),
        login("2", "B", SHARED, "https://b.example", "GEZDGNBVGY3TQOJQ"),
        login(
            "3",
            "C",
            "\u{200b}",
            "https://c.example",
            "GEZDGNBVGY3TQOJQ",
        ),
        login(
            "4",
            "D",
            "\u{200b}",
            "https://d.example",
            "GEZDGNBVGY3TQOJQ",
        ),
    ]);
    let counts: Vec<usize> = mixed
        .items
        .iter()
        .flat_map(|item| item.findings.iter())
        .filter_map(|finding| match finding {
            Finding::ReusedPassword { count } => Some(*count),
            _ => None,
        })
        .collect();
    assert_eq!(counts, vec![2, 2], "{mixed:?}");
}

#[test]
fn invalid_totp_is_not_counted_as_configured() {
    const VALID: &str = "GEZDGNBVGY3TQOJQ";
    let report = report_of(vec![
        login(
            "1",
            "Broken",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "not base32!",
        ),
        login(
            "2",
            "Good",
            "wU8$kRl3#aS0yM7&tD2!",
            "https://b.example",
            VALID,
        ),
    ]);
    let broken = report.items.iter().find(|item| item.id == "1").unwrap();
    assert!(broken.findings.contains(&Finding::NoTotp));
    // The good login is clean, so it has no ItemReport at all.
    assert!(
        !report.items.iter().any(|item| item.id == "2"),
        "a valid TOTP must not create a finding: {:?}",
        report.items
    );
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
    assert!((report.totp_coverage() - 0.5).abs() < 1e-6);
}

#[test]
fn long_high_entropy_password_prefix_is_not_mistaken_for_common() {
    let long = "passwordVt7#kQm2!zR9wP4$xL8@";
    assert!(
        long.len() > PASSWORD_PREFIX_LIMIT,
        "the value must exceed the prefix cap"
    );
    let bits = estimate_entropy(long);
    assert!(bits >= 50, "{bits}");
    assert!(bits > estimate_entropy("password123"), "{bits}");
    // The classic short value must still take the dictionary shortcut.
    assert!(estimate_entropy("password123") < 20);
}

#[test]
fn short_dictionary_passwords_are_weak_at_the_default_threshold() {
    let weak_bits = Thresholds::default().weak_bits;
    // Every value here is at or below PASSWORD_PREFIX_LIMIT, so it takes the
    // dictionary shortcut: the estimate lands far below weak_bits even though
    // the raw pool x length score of e.g. `password123` is ~57 bit and would
    // otherwise clear the threshold.
    for password in [
        "password",
        "password1",
        "password123",
        "PASSWORD123",
        "password12345678", // exactly PASSWORD_PREFIX_LIMIT characters
    ] {
        assert!(password.len() <= PASSWORD_PREFIX_LIMIT, "{password}");
        let bits = estimate_entropy(password);
        assert!(bits < weak_bits, "{password}: {bits} >= {weak_bits}");
        // The audit path turns the low estimate into a WeakPassword finding.
        let report = report_of(vec![login(
            "1",
            "P",
            password,
            "https://a.example",
            "SECRET",
        )]);
        assert!(
            report.items[0]
                .findings
                .contains(&Finding::WeakPassword { bits }),
            "{password}: {report:?}"
        );
    }
}

#[test]
fn password_prefix_cap_is_the_boundary_for_the_dictionary_shortcut() {
    const VALID_TOTP: &str = "GEZDGNBVGY3TQOJQ";
    let weak_bits = Thresholds::default().weak_bits;

    // Exactly at the cap: still a dictionary guess, hence Weak. The last
    // character is alphanumeric on purpose: `strip_decoration` strips a
    // trailing digit run, so a value ending in a digit would have a shorter
    // guessable core than its raw length suggests.
    let at_cap = format!("password{}", "Vt7#kQmA"); // 8 + 8 = 16 chars
    assert_eq!(at_cap.len(), PASSWORD_PREFIX_LIMIT);
    let at_cap_lower = at_cap.to_lowercase();
    let at_cap_core = super::strip_decoration(&at_cap_lower);
    assert_eq!(at_cap_core.chars().count(), PASSWORD_PREFIX_LIMIT);
    let at_cap_bits = estimate_entropy(&at_cap);
    assert!(at_cap_bits < weak_bits, "{at_cap}: {at_cap_bits}");

    // One character past the cap: the same kind of value keeps its genuine
    // entropy and is no longer flagged Weak. Again the extra character is
    // alphanumeric: a trailing `!` is now decoration and would be stripped.
    let past_cap = format!("{at_cap}a"); // 17 chars
    assert_eq!(past_cap.len(), PASSWORD_PREFIX_LIMIT + 1);
    let past_cap_bits = estimate_entropy(&past_cap);
    assert!(past_cap_bits >= weak_bits, "{past_cap}: {past_cap_bits}");
    assert!(
        past_cap_bits > at_cap_bits,
        "{past_cap_bits} vs {at_cap_bits}"
    );

    // Confirm the boundary through the report path too: only the at-cap value
    // produces a WeakPassword finding, with a valid TOTP and https URI so no
    // other finding can appear.
    let short_report = report_of(vec![login(
        "1",
        "Short",
        &at_cap,
        "https://a.example",
        VALID_TOTP,
    )]);
    assert!(
        short_report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits: at_cap_bits }),
        "{short_report:?}"
    );
    let long_report = report_of(vec![login(
        "2",
        "Long",
        &past_cap,
        "https://b.example",
        VALID_TOTP,
    )]);
    assert!(
        !long_report.items.iter().any(|item| item
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::WeakPassword { .. }))),
        "a value past the cap must not be Weak: {long_report:?}"
    );
}

#[test]
fn undecryptable_passwords_are_excluded_from_checks_and_counted_in_summary() {
    // Two identical status markers must not be mistaken for a reused password,
    // and a marker must never be scored against a real password.
    let first = login(
        "1",
        "Undecryptable A",
        UNDECRYPTABLE_PASSWORD,
        "https://a.example",
        "SECRET",
    );
    let second = login(
        "2",
        "Undecryptable B",
        UNDECRYPTABLE_PASSWORD,
        "https://b.example",
        "SECRET",
    );
    let weak = login("3", "Weak", "1234", "https://c.example", "SECRET");
    let report = report_of(vec![first, second, weak]);

    assert_eq!(report.password_uninspectable(), 2);
    for id in ["1", "2"] {
        let item = report.items.iter().find(|item| item.id == id).unwrap();
        assert!(item.findings.contains(&Finding::PasswordUninspectable));
        assert!(
            !item.findings.iter().any(|finding| matches!(
                finding,
                Finding::WeakPassword { .. } | Finding::ReusedPassword { .. }
            )),
            "an undecryptable password must not be scored: {item:?}"
        );
    }
    let weak_item = report.items.iter().find(|item| item.id == "3").unwrap();
    assert!(
        !weak_item
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::ReusedPassword { .. })),
        "the status marker must not create a false reuse match: {weak_item:?}"
    );

    let summary = report.summary();
    assert!(summary.contains("パスワード検査対象外: 2 件"), "{summary}");
    let text = report.to_text();
    assert!(text.contains("パスワード検査対象外: 2 件"), "{text}");
    // The marker is still a password field value in the model, so the helper
    // must be the single source of truth for detecting it.
    assert!(is_undecryptable_password(UNDECRYPTABLE_PASSWORD));
    assert!(!is_undecryptable_password("1234"));
    assert!(!is_undecryptable_password(""));
}

#[test]
fn uninspectable_marker_never_reaches_report_debug_serde_or_messages() {
    let report = report_of(vec![login(
        "1",
        "Undecryptable",
        UNDECRYPTABLE_PASSWORD,
        "https://a.example",
        "SECRET",
    )]);
    let finding = Finding::PasswordUninspectable;
    for rendered in [
        format!("{report:?}"),
        serde_json::to_string(&report).expect("serialize report"),
        format!("{finding:?}"),
        serde_json::to_string(&finding).expect("serialize finding"),
        finding.message(),
    ] {
        assert!(!rendered.contains("undecryptable"), "{rendered}");
        assert!(!rendered.contains('\0'), "{rendered:?}");
    }
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

#[test]
fn undecryptable_uri_is_not_reported_as_missing() {
    use crate::vault_sync::UNDECRYPTABLE_URI;

    let report = report_of(vec![VaultItem::new(
        "uri-undecryptable",
        "Login",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new(String::new()),
            uris: vec![LoginUri {
                uri: UNDECRYPTABLE_URI.into(),
                match_type: None,
            }],
        },
    )]);
    let findings = &report.items[0].findings;
    assert!(findings.contains(&Finding::UriUninspectable));
    assert!(
        !findings.contains(&Finding::NoUri),
        "a decryption failure is not the same as an empty URI list"
    );
    assert!(Finding::UriUninspectable
        .message()
        .contains("復号できませんでした"));
}

#[test]
fn invisible_characters_do_not_hide_an_insecure_uri() {
    for raw in [
        "\u{200b}http://example.com",
        "\u{200b} http://example.com",
        "http\u{200b}://example.com",
        "\u{202e}http://example.com",
    ] {
        let item = VaultItem::new(
            "insecure-cf",
            "Login",
            ItemData::Login {
                username: "u".into(),
                password: Zeroizing::new("s3cret".into()),
                totp: Zeroizing::new(String::new()),
                uris: vec![LoginUri {
                    uri: raw.into(),
                    match_type: None,
                }],
            },
        );
        let report = report_of(vec![item]);
        let finding = report.items[0]
            .findings
            .iter()
            .find(|finding| matches!(finding, Finding::InsecureUri { .. }))
            .unwrap_or_else(|| panic!("insecure URI hidden in {raw:?}"));
        let Finding::InsecureUri { uri } = finding else {
            unreachable!()
        };
        assert_eq!(uri, "http://example.com", "raw: {raw:?}");
        assert!(finding.message().contains("http://example.com"));
    }
}

#[test]
fn uppercase_and_control_character_http_uris_are_detected() {
    for raw in [
        "HTTP://example.com",
        "Http://Example.com",
        "h\u{0007}ttp://example.com",
        "\u{200b}HTTP://example.com",
    ] {
        let report = report_of(vec![login("1", "A", "vT7#kQm2!zR9wP4$xL8@", raw, "SECRET")]);
        let finding = report.items[0]
            .findings
            .iter()
            .find(|finding| matches!(finding, Finding::InsecureUri { .. }))
            .unwrap_or_else(|| panic!("insecure URI hidden in {raw:?}"));
        let Finding::InsecureUri { uri } = finding else {
            unreachable!()
        };
        assert_eq!(uri, "http://example.com", "raw: {raw:?}");
    }
}

#[test]
fn backslashes_are_normalized_to_slashes_for_insecure_uri_detection() {
    // Browsers accept `\` where `/` is expected. `audit_item` maps every
    // backslash to '/' before both the scheme check and masking, so these
    // spellings must all produce the same masked finding (health.rs:689-705).
    for raw in [
        "http:\\\\example.com",
        "HTTP:\\\\Example.com\\path",
        "http:\\/example.com",
        "http:/\\example.com",
        "http:\\\\user:token@example.com\\secret",
    ] {
        let report = report_of(vec![login("1", "A", "vT7#kQm2!zR9wP4$xL8@", raw, "SECRET")]);
        let finding = report.items[0]
            .findings
            .iter()
            .find(|finding| matches!(finding, Finding::InsecureUri { .. }))
            .unwrap_or_else(|| panic!("insecure URI hidden in {raw:?}"));
        let Finding::InsecureUri { uri } = finding else {
            unreachable!()
        };
        assert_eq!(uri, "http://example.com", "raw: {raw:?}");
        assert!(!finding.message().contains("token"), "{raw:?}");
    }
    // The normalization does not widen the rule to secure schemes.
    let report = report_of(vec![login(
        "2",
        "B",
        "vT7#kQm2!zR9wP4$xL8@",
        "https:\\\\example.com",
        "SECRET",
    )]);
    assert!(
        !report.items.iter().any(|item| item
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::InsecureUri { .. }))),
        "{report:?}"
    );
}

#[test]
fn insecure_uri_message_shows_the_stored_mask_once() {
    // `audit_item` stores an already-masked URI (scheme + host only).
    // `mask_uri` is idempotent, so rendering it again must keep that value.
    let finding = Finding::InsecureUri {
        uri: "http://example.com:8080".into(),
    };
    assert_eq!(finding.message(), "http の URI（http://example.com:8080）");
    // A status marker must not be reinterpreted as an invalid URI.
    let marker = Finding::InsecureUri {
        uri: "（復号できませんでした）".into(),
    };
    assert_eq!(marker.message(), "http の URI（（復号できませんでした））");
}

#[test]
fn stale_boundary_is_inclusive_at_the_threshold() {
    let mut d364 = login(
        "364",
        "D364",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "SECRET",
    );
    d364.revision_date = NOW - 364 * 86_400;
    let mut d365 = login(
        "365",
        "D365",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://b.example",
        "SECRET",
    );
    d365.revision_date = NOW - 365 * 86_400;
    let mut d366 = login(
        "366",
        "D366",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://c.example",
        "SECRET",
    );
    d366.revision_date = NOW - 366 * 86_400;
    let report = report_of(vec![d364, d365, d366]);
    let stale: Vec<&str> = report
        .items
        .iter()
        .filter(|item| {
            item.findings
                .iter()
                .any(|finding| matches!(finding, Finding::Stale { .. }))
        })
        .map(|item| item.id.as_str())
        .collect();
    assert_eq!(stale, vec!["365", "366"]);
    assert!(report
        .items
        .iter()
        .find(|item| item.id == "365")
        .unwrap()
        .findings
        .contains(&Finding::Stale { days: 365 }));
    assert!(report
        .items
        .iter()
        .find(|item| item.id == "366")
        .unwrap()
        .findings
        .contains(&Finding::Stale { days: 366 }));
}

#[test]
fn custom_thresholds_change_the_findings() {
    let mut item = login("1", "Custom", "vT7#kQm2!zR9", "https://a.example", "SECRET");
    item.revision_date = NOW - 20 * 86_400;
    let vault = Vault {
        items: vec![item],
        folders: Vec::new(),
    };

    let loose = audit(&vault, Thresholds::default(), NOW);
    assert!(!loose.items.iter().any(|report| {
        report.findings.iter().any(|finding| {
            matches!(
                finding,
                Finding::WeakPassword { .. } | Finding::Stale { .. }
            )
        })
    }));

    let strict = audit(
        &vault,
        Thresholds {
            weak_bits: 100,
            stale_days: 10,
        },
        NOW,
    );
    assert_eq!(strict.items.len(), 1);
    let findings = &strict.items[0].findings;
    assert!(findings
        .iter()
        .any(|finding| matches!(finding, Finding::WeakPassword { .. })));
    assert!(findings.contains(&Finding::Stale { days: 20 }));
}

#[test]
fn non_ascii_suffix_counts_towards_the_prefix_cap_by_characters() {
    // The caps are expressed in characters. A multibyte suffix used to make
    // the byte length exceed the cap, so a short dictionary guess escaped the
    // shortcut and was scored as high-entropy (health.rs:532-539).
    let password = "passwordあいうえお";
    assert_eq!(password.chars().count(), 13);
    assert!(password.len() > PASSWORD_PREFIX_LIMIT, "{}", password.len());
    assert!(super::is_common_password(&password.to_lowercase()));
    let bits = estimate_entropy(password);
    assert!(bits < 20, "{password}: {bits}");

    let qwerty = "qwertyあいうえお";
    assert_eq!(qwerty.chars().count(), 11);
    assert!(
        qwerty.len() > super::QWERTY_PREFIX_LIMIT,
        "{}",
        qwerty.len()
    );
    assert!(super::is_common_password(qwerty));
    assert!(estimate_entropy(qwerty) < 20);

    // A genuinely long value with a multibyte suffix still keeps its real
    // estimate: the cap must not classify every non-ASCII password as common.
    let long = "passwordあいうえおかきくけこさ";
    assert!(long.chars().count() > PASSWORD_PREFIX_LIMIT);
    assert!(!super::is_common_password(long));
    assert!(estimate_entropy(long) >= Thresholds::default().weak_bits);

    // The audit path applies the same estimate through the WeakPassword
    // finding, with a valid TOTP and https URI so no other finding appears.
    let report = report_of(vec![login(
        "1",
        "NonAscii",
        password,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn qwerty_prefix_cap_boundary_changes_the_estimate() {
    // The cap counts the decoration-free core: end with a letter so neither
    // fixture loses a trailing digit run to `strip_decoration`.
    let at_cap = "qwerty12345a"; // exactly 12 characters
    let past_cap = "qwerty12345ab"; // 13 characters
    assert_eq!(at_cap.len(), 12);
    assert_eq!(past_cap.len(), 13);
    assert_eq!(
        super::strip_decoration(at_cap).chars().count(),
        QWERTY_PREFIX_LIMIT
    );
    let at_bits = estimate_entropy(at_cap);
    let past_bits = estimate_entropy(past_cap);
    assert!(at_bits < 20, "{at_bits}");
    assert!(past_bits >= Thresholds::default().weak_bits, "{past_bits}");
    assert!(past_bits > at_bits);
}

#[test]
fn exact_common_list_and_prefix_rule_are_independent_branches() {
    // Entries that do not start with "password"/"qwerty" can only be
    // classified by the exact COMMON match (health.rs:491-557).
    for word in [
        "correcthorsebatterystaple",
        "1234567890",
        "letmein",
        "trustno1",
        "zaq12wsx",
    ] {
        assert!(
            super::is_exact_common_password(word),
            "exact list entry: {word}"
        );
        assert!(super::is_common_password(word), "{word}");
    }
    // An unlisted short value is common via the prefix cap, NOT via the list.
    for prefixed in ["passwordabc", "qwertyabc"] {
        assert!(
            !super::is_exact_common_password(prefixed),
            "not a literal COMMON entry: {prefixed}"
        );
        assert!(super::is_common_password(prefixed), "{prefixed}");
    }
    // The list is matched verbatim (callers pass a lowercased value), and a
    // longer lookalike is not an exact member.
    assert!(!super::is_exact_common_password("Password123"));
    assert!(!super::is_exact_common_password(
        "correcthorsebatterystaple!"
    ));
    assert!(!super::is_exact_common_password(""));
}

#[test]
fn generator_and_audit_share_the_weak_boundary() {
    let weak = Thresholds::default().weak_bits;
    assert_eq!(weak, crate::generator::WEAK_BITS);
    let bits = f64::from(weak);
    assert_eq!(Strength::from_bits(bits - 0.1), Strength::Weak);
    assert_eq!(Strength::from_bits(bits), Strength::Fair);
}

#[test]
fn passphrase_estimate_matches_the_generator_model() {
    use crate::generator::{passphrase_entropy, PassphraseSettings};

    for settings in [
        PassphraseSettings::default(),
        PassphraseSettings {
            capitalize: false,
            include_number: true,
            ..PassphraseSettings::default()
        },
    ] {
        let phrase = settings.generate().expect("passphrase should generate");
        let expected = passphrase_entropy(&settings);
        let actual = estimate_entropy(&phrase);
        assert!(
            (f64::from(actual) - expected).abs() <= 1.0,
            "{phrase}: {actual} vs {expected}"
        );
        assert_eq!(
            password_strength(&phrase).1,
            Strength::from_bits(expected),
            "{phrase}"
        );
    }
}

#[test]
fn totp_helpers_agree_with_the_report() {
    let with = login(
        "1",
        "With",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    );
    let without = login(
        "2",
        "Without",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://b.example",
        "",
    );
    assert!(has_usable_totp(&with));
    assert!(has_totp_field(&with));
    assert!(!has_usable_totp(&without));
    assert!(!has_totp_field(&without));
    let vault = Vault {
        items: vec![with, without],
        folders: Vec::new(),
    };
    let report = audit(&vault, Thresholds::default(), NOW);
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
}

#[test]
fn ssh_fingerprint_checks_are_wired_into_the_audit() {
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVYTn6DgHoRS29obD0RhrnbKgHhM1eqLvmbTWMGwSmR fp-test@example";
    const FP: &str = "SHA256:rU5/Ssu4iQF+Dh5DRCbEpCjexkxaSKWYzYW9pUPi7R0";
    let ssh = |id: &str, public_key: &str, fingerprint: &str| {
        VaultItem::new(
            id,
            id,
            ItemData::SshKey(SshKeyData {
                public_key: public_key.into(),
                private_key: String::new().into(),
                fingerprint: fingerprint.into(),
            }),
        )
    };
    let vault = Vault {
        items: vec![
            ssh("ssh-good", KEY, FP),
            ssh(
                "ssh-bad",
                KEY,
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            ssh("ssh-invalid", "not a key", FP),
        ],
        folders: Vec::new(),
    };
    let report = audit(&vault, Thresholds::default(), NOW);
    assert!(
        !report.items.iter().any(|item| item.id == "ssh-good"),
        "a valid fingerprint must not create a finding"
    );
    let bad = report
        .items
        .iter()
        .find(|item| item.id == "ssh-bad")
        .expect("mismatch must be reported");
    assert!(bad
        .findings
        .iter()
        .any(|finding| matches!(finding, Finding::SshFingerprintMismatch { .. })));
    assert_eq!(bad.worst(), Some(Severity::High));
    let invalid = report
        .items
        .iter()
        .find(|item| item.id == "ssh-invalid")
        .expect("invalid key must be reported");
    assert!(invalid.findings.contains(&Finding::SshFingerprintInvalid));
}

#[test]
fn mismatch_computed_fingerprint_reaches_the_finding_message() {
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVYTn6DgHoRS29obD0RhrnbKgHhM1eqLvmbTWMGwSmR fp-test@example";
    const COMPUTED: &str = "SHA256:rU5/Ssu4iQF+Dh5DRCbEpCjexkxaSKWYzYW9pUPi7R0";
    let key = VaultItem::new(
        "ssh-mismatch",
        "SSH key",
        ItemData::SshKey(SshKeyData {
            public_key: KEY.into(),
            private_key: String::new().into(),
            fingerprint: "SHA256:DIFFERENT".into(),
        }),
    );
    let ItemData::SshKey(ssh) = &key.data else {
        panic!("the fixture must be an SSH key")
    };
    let computed = match ssh.verify_fingerprint() {
        crate::model::FingerprintVerify::Mismatch { computed } => computed,
        other => panic!("a wrong stored fingerprint must be a mismatch: {other:?}"),
    };
    assert_eq!(computed, COMPUTED);

    let report = report_of(vec![key]);
    let finding = report.items[0]
        .findings
        .iter()
        .find(|finding| matches!(finding, Finding::SshFingerprintMismatch { .. }))
        .expect("the recomputed mismatch must be audited");
    let Finding::SshFingerprintMismatch { computed: reported } = finding else {
        panic!("the finding must be a fingerprint mismatch")
    };
    assert_eq!(reported, &computed, "computed must propagate unchanged");
    let message = finding.message();
    assert!(message.contains("計算値"), "{message}");
    assert!(message.contains(COMPUTED), "{message}");
}

#[test]
fn whitespace_only_card_numbers_are_flagged_as_no_card_number() {
    for number in ["", " ", "  \t  ", "\n", "\u{3000}"] {
        let card = VaultItem::new(
            "card-blank",
            "Card",
            ItemData::Card(CardData {
                number: number.into(),
                ..CardData::default()
            }),
        );
        let report = report_of(vec![card]);
        let item = report
            .items
            .iter()
            .find(|item| item.id == "card-blank")
            .unwrap_or_else(|| panic!("a blank card number must be flagged: {number:?}"));
        assert!(
            item.findings.contains(&Finding::NoCardNumber),
            "number {number:?}: {:?}",
            item.findings
        );
    }

    // A real number is not flagged, so this is not a blanket rule for cards.
    let filled = VaultItem::new(
        "card-filled",
        "Card",
        ItemData::Card(CardData {
            number: "4111 1111 1111 1234".into(),
            ..CardData::default()
        }),
    );
    assert!(report_of(vec![filled]).items.is_empty());
}

#[test]
fn empty_names_use_a_placeholder_in_the_report() {
    // The placeholder covers every name whose `trim()` is empty, including
    // whitespace-only ones (see `unnamed_items_are_reported`).
    for name in ["", "  ", "\t\n", "\u{3000}"] {
        let mut item = login(
            "1",
            name,
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "GEZDGNBVGY3TQOJQ",
        );
        item.revision_date = NOW;
        let report = report_of(vec![item]);

        let reported = report
            .items
            .iter()
            .find(|entry| entry.id == "1")
            .expect("the unnamed item must be reported");
        assert_eq!(reported.name, "(名称未設定)", "name={name:?}");
        assert!(
            reported.findings.contains(&Finding::Unnamed),
            "name={name:?}"
        );
        assert!(report.to_text().contains("(名称未設定)"), "name={name:?}");
    }
}

#[test]
fn audit_report_ties_break_by_lowercased_name_then_id() {
    // `audit` sorts worst-first, then by lowercased name and id
    // (health.rs:607-612). Every item carries the same findings (a reused
    // password and NoTotp), so only the two tiebreakers decide the order.
    let item = |id: &str, name: &str| {
        let mut value = login(id, name, "vT7#kQm2!zR9wP4$xL8@", "https://a.example", "");
        value.revision_date = NOW;
        value
    };
    let report = report_of(vec![
        item("b-lower", "Alpha"),
        item("a-upper", "alpha"),
        item("d-lower", "beta"),
        item("c-upper", "Beta"),
    ]);

    let ids: Vec<&str> = report.items.iter().map(|entry| entry.id.as_str()).collect();
    assert_eq!(ids, vec!["a-upper", "b-lower", "c-upper", "d-lower"]);
    for entry in &report.items {
        assert_eq!(entry.worst(), Some(Severity::High));
        assert!(entry.findings.contains(&Finding::NoTotp));
    }
}

#[test]
fn passphrase_with_an_unknown_word_uses_the_character_pool() {
    use crate::words::WORDS;

    const UNKNOWN: &str = "zzznotaword";
    assert!(!WORDS.contains(&UNKNOWN), "pick a genuinely unknown word");
    let phrase = format!("{}-{UNKNOWN}", WORDS[0]);
    // One unknown word makes `passphrase_estimate` return None, so the
    // estimator falls back to the same character-pool model as any password.
    let pool = LOWERCASE.len() + SYMBOLS.len();
    let expected = entropy_bits(pool, phrase.chars().count()).round() as u32;
    assert_eq!(estimate_entropy(&phrase), expected);

    // A real two-word passphrase is scored with the word-list model instead.
    let genuine = format!("{}-{}", WORDS[0], WORDS[1]);
    assert_ne!(
        estimate_entropy(&genuine),
        expected,
        "a known passphrase must not use the character-pool fallback"
    );
}

#[test]
fn twelve_digit_pin_sits_exactly_on_the_40_bit_boundary() {
    // A numeric PIN is charged the 10-symbol pool: 12 * log2(10) rounds to
    // exactly 40 bits, the Weak/Fair boundary (generator.rs:249 and the
    // numeric branch of estimate_entropy). Eleven digits stay Weak.
    let twelve = "123456789012";
    let eleven = "12345678901";
    assert_eq!(estimate_entropy(twelve), 40);
    assert_eq!(estimate_entropy(eleven), 37);
    assert_eq!(password_strength(twelve).1, Strength::Fair);
    assert_eq!(password_strength(eleven).1, Strength::Weak);

    // Documented limitation: the estimator has no "sequential digits" rule,
    // so a 12-digit counter is Fair at the default threshold. The boundary is
    // asserted here so a future pattern penalty is an intentional change.
    let report = report_of(vec![login(
        "1",
        "Counter",
        twelve,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        !report.items.iter().any(|item| item
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::WeakPassword { .. }))),
        "40 bits is not below the 40-bit threshold: {report:?}"
    );
}

#[test]
fn word_suffix_discount_requires_at_least_three_letters() {
    // The word-suffix branch of `estimate_entropy` (health.rs:398-405) only
    // discounts a trailing digit run when the stripped body is at least three
    // ASCII lowercase letters. Two letters stay on the raw character-pool
    // estimate; three (or more) switch to the word + suffix model. Using the
    // same four-digit suffix isolates the length threshold from the suffix
    // itself. Neither value is a dictionary word or a generated passphrase,
    // so both take the character-pool path before the discount.
    let two = "ab1234";
    let three = "abc1234";
    let four = "abcd1234";
    let raw_two = entropy_bits(36, 6).round() as u32;
    let discounted_three = (entropy_bits(26, 3) + entropy_bits(10, 4)).round() as u32;
    let discounted_four = (entropy_bits(26, 4) + entropy_bits(10, 4)).round() as u32;

    // Premise: the word list has no `abc`/`ab` entry, so no passphrase path
    // hijacks these values (WORDS is prefix-free).
    assert!(!crate::words::WORDS.contains(&"abc"));
    assert_eq!(estimate_entropy(two), raw_two, "{two}");
    assert_eq!(estimate_entropy(three), discounted_three, "{three}");
    assert_eq!(estimate_entropy(four), discounted_four, "{four}");
    assert!(
        discounted_three < raw_two,
        "{discounted_three} vs {raw_two}"
    );
    assert!(
        discounted_four > discounted_three,
        "a longer word costs more"
    );

    // The three-letter test is on ASCII lowercase letters. A digit inside the
    // three-character body disqualifies it, and uppercase input is folded by
    // `password.to_lowercase()` before the check, so uppercase still discounts.
    assert_eq!(
        estimate_entropy("a1b1234"),
        entropy_bits(36, 7).round() as u32
    );
    assert_eq!(estimate_entropy("ABC1234"), discounted_three);

    // A two-letter body with no digits at all must also stay undiscounted:
    // the threshold is on the word length, not on the presence of a suffix
    // (`ab` alone is still the raw pool estimate).
    assert_eq!(estimate_entropy("ab"), entropy_bits(26, 2).round() as u32);
}

#[test]
fn empty_separator_passphrases_are_scored_with_the_word_list() {
    use crate::generator::{passphrase_entropy, PassphraseSettings};
    use crate::words::WORDS;

    // The generator explicitly allows an empty separator and relies on the
    // prefix-free list for unambiguous boundaries (generator.rs:169). The
    // audit used to find no "non-alphanumeric separator" and fell back to the
    // character-pool model, overestimating a two-word draw by ~20 bits.
    let plain: String = WORDS[..4].iter().copied().collect();
    let word_bits = passphrase_entropy(&PassphraseSettings {
        words: 4,
        separator: String::new(),
        capitalize: false,
        include_number: false,
    });
    let char_pool_bits = entropy_bits(LOWERCASE.len(), plain.chars().count()).round() as u32;
    assert!(
        char_pool_bits > word_bits.round() as u32 + 5,
        "the fallback must be clearly higher for this to test the bug: {char_pool_bits} vs {word_bits}"
    );
    assert!((f64::from(estimate_entropy(&plain)) - word_bits).abs() <= 1.0);

    for settings in [
        PassphraseSettings {
            words: 4,
            separator: String::new(),
            capitalize: false,
            include_number: false,
        },
        PassphraseSettings {
            words: 4,
            separator: String::new(),
            capitalize: true,
            include_number: true,
        },
        PassphraseSettings {
            words: 5,
            separator: String::new(),
            capitalize: false,
            include_number: true,
        },
    ] {
        let phrase = settings.generate().expect("passphrase should generate");
        let expected = passphrase_entropy(&settings);
        let actual = estimate_entropy(&phrase);
        assert!(
            (f64::from(actual) - expected).abs() <= 1.0,
            "{phrase}: {actual} vs {expected}"
        );
        assert_eq!(
            password_strength(&phrase).1,
            Strength::from_bits(expected),
            "{phrase}"
        );
    }

    // Recognizer contract: a real concatenated draw is accepted, while a
    // single word or a plain lowercase string is not treated as generated.
    assert!(super::passphrase_estimate(&plain).is_some());
    assert!(super::passphrase_estimate(WORDS[0]).is_none());
    assert!(super::passphrase_estimate("abcdefghij").is_none());
}

#[test]
fn passphrase_estimate_rejects_mixed_separators() {
    // The generator emits one repeated non-alphanumeric separator (or none).
    // A phrase joining list words with different separators is not a possible
    // generator output, so the recognizer must return None and let the caller
    // fall back to the character-pool estimate. There is no separate
    // separator-consistency branch: `split` on the first non-alphanumeric
    // character leaves the other separator inside a part, and that part is
    // not a shared-list word, so the existing `WORDS.contains` check rejects
    // it (passphrase_estimate in health.rs).
    let repeated = format!("{}-{}-{}", WORDS[0], WORDS[1], WORDS[2]);
    let mixed = format!("{}-{}_{}", WORDS[0], WORDS[1], WORDS[2]);
    assert!(
        super::passphrase_estimate(&repeated).is_some(),
        "{repeated}"
    );
    // Premise of that mechanism: the residual part really is not a word.
    let residual = format!("{}_{}", WORDS[1], WORDS[2]);
    assert!(!WORDS.contains(&residual.as_str()), "{residual}");
    assert_eq!(super::passphrase_estimate(&mixed), None, "{mixed}");
    assert_eq!(
        super::passphrase_estimate(&format!("{mixed}7")),
        None,
        "a trailing number must not hide a mixed separator"
    );
    // The reverse order is rejected the same way: the first separator is now
    // `_`, so the `-` stays inside the second part.
    let reversed = format!("{}_{}-{}", WORDS[0], WORDS[1], WORDS[2]);
    let reversed_residual = format!("{}-{}", WORDS[1], WORDS[2]);
    assert!(!WORDS.contains(&reversed_residual.as_str()));
    assert_eq!(super::passphrase_estimate(&reversed), None, "{reversed}");

    // A single separator that is not `-` is still accepted.
    let underscored = format!("{}_{}", WORDS[0], WORDS[1]);
    assert!(super::passphrase_estimate(&underscored).is_some());
}

#[test]
fn only_digit_suffixes_get_the_word_suffix_discount() {
    // `estimate_entropy`'s comment now matches the code: only a trailing digit
    // run is modelled (health.rs:370-377). A symbol suffix keeps the raw
    // character-pool estimate and must not be silently discounted as well.
    let digits = estimate_entropy("sunflower42");
    let symbols = estimate_entropy("sunflower!!");
    assert!(digits < symbols, "{digits} vs {symbols}");
    // The documented digit case still beats an unsuffixed word in raw bits.
    let plain = estimate_entropy("sunflower");
    assert!(digits > plain, "{digits} vs {plain}");
}

#[test]
fn separator_free_words_reject_invalid_capitalization() {
    use crate::words::WORDS;

    let lower = WORDS[0];
    let other = WORDS[1];
    let plain = format!("{lower}{other}");
    let capitalized = format!("{}{other}", upper_first(lower));
    assert_eq!(
        super::words_without_separator(&plain),
        Some((vec![lower, other], false)),
        "{plain}"
    );
    assert_eq!(
        super::words_without_separator(&capitalized),
        Some((vec![lower, other], true)),
        "{capitalized}"
    );

    // Only an ASCII-uppercase first letter with an otherwise lowercase tail
    // is accepted. A capital inside a word, an all-caps word and a mismatched
    // tail all fail instead of being silently folded (health.rs:453-459).
    let inner_caps = format!("{}{}", upper_second(lower), other);
    let all_caps = format!("{}{}", lower.to_ascii_uppercase(), other);
    let wrong_tail = format!(
        "{}{}{}",
        &lower[..1],
        lower[1..].to_ascii_uppercase(),
        other
    );
    for bad in [inner_caps, all_caps, wrong_tail] {
        assert_eq!(
            super::words_without_separator(&bad),
            None,
            "invalid capitalization must be rejected: {bad}"
        );
    }
    // A single word is never scored as a generated passphrase.
    assert_eq!(super::words_without_separator(lower), None);
}

fn upper_first(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn upper_second(word: &str) -> String {
    let mut chars = word.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) => {
            format!("{first}{}", second.to_ascii_uppercase()) + chars.as_str()
        }
        _ => word.to_string(),
    }
}

#[test]
fn future_revision_never_produces_a_stale_finding() {
    let mut future = login(
        "1",
        "Future",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "S",
    );
    // A clock-skewed or forged future revision must not stay fresh forever;
    // the guard at health.rs:727 skips it instead of computing a negative age.
    future.revision_date = NOW + 86_400;
    let mut vault = Vault::new();
    vault.items = vec![future];
    let report = audit(
        &vault,
        Thresholds {
            stale_days: 0,
            ..Thresholds::default()
        },
        NOW,
    );
    assert!(
        report.items[0]
            .findings
            .iter()
            .all(|finding| !matches!(finding, Finding::Stale { .. })),
        "{report:?}"
    );

    // A past revision with the same threshold does produce Stale, so the
    // assertion above is testing the future-date guard and not a silent skip.
    let mut past = login(
        "1",
        "Past",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "S",
    );
    past.revision_date = NOW - 86_400;
    let mut vault = Vault::new();
    vault.items = vec![past];
    let report = audit(
        &vault,
        Thresholds {
            stale_days: 0,
            ..Thresholds::default()
        },
        NOW,
    );
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::Stale { days: 1 }),
        "{report:?}"
    );
}

#[test]
fn severity_labels_cover_medium_and_high() {
    // health.rs:144-152 maps all three severities to Japanese labels; the
    // sibling test already pins Low, so pin the other two here.
    assert_eq!(Severity::Low.label(), "低");
    assert_eq!(Severity::Medium.label(), "中");
    assert_eq!(Severity::High.label(), "高");
}

#[test]
fn non_ascii_totp_does_not_crash_the_audit() {
    // The health audit calls `is_valid_secret` on untrusted decrypted fields.
    // A leading multi-byte character used to panic in openwarden's byte
    // slicing; the ASCII guard in `code_at` must turn it into an ordinary
    // `NoTotp` finding instead (totp.rs:97-110).
    const BAD: &str = "あいうえおotpauth://totp/x?secret=GEZDGNBVGY3TQOJQ";
    const GOOD: &str = "GEZDGNBVGY3TQOJQ";

    let report = report_of(vec![
        login(
            "bad",
            "Bad",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            BAD,
        ),
        login(
            "good",
            "Good",
            "tQ8#wLr1!eZ5vKp3$sM7@",
            "https://b.example",
            GOOD,
        ),
    ]);

    let bad = report.items.iter().find(|item| item.id == "bad").unwrap();
    assert!(bad.findings.contains(&Finding::NoTotp), "{bad:?}");
    assert!(
        !bad.findings.contains(&Finding::TotpUninspectable),
        "a malformed secret is not an undecryptable marker: {bad:?}"
    );
    // A clean item is omitted from the report, but it must never produce a
    // NoTotp finding just because the other item has a malformed secret.
    assert!(
        !report.items.iter().any(|item| item.id == "good"),
        "the valid TOTP login stays clean: {:?}",
        report.items
    );
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
    assert!((report.totp_coverage() - 0.5).abs() < 1e-6);
    assert!(!crate::totp::is_valid_secret(BAD));
}

#[test]
fn undecryptable_totp_marker_reaches_the_totp_uninspectable_finding() {
    // The import layer writes `UNDECRYPTABLE_TOTP` when a TOTP field exists but
    // its ciphertext cannot be opened (vault_sync.rs:329-336). The audit must
    // follow that marker to `Finding::TotpUninspectable` rather than reporting
    // `NoTotp`, so a 2FA-enabled login is not mislabelled as having no 2FA
    // (health.rs:670-677).
    let marked = login(
        "totp-marked",
        "Marked",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        UNDECRYPTABLE_TOTP,
    );
    assert!(crate::vault_sync::is_undecryptable_totp(
        marked.totp_secret().unwrap()
    ));
    assert!(!has_usable_totp(&marked), "a marker is not a usable secret");
    assert!(has_totp_field(&marked), "but the field is present");

    let report = report_of(vec![marked]);
    let item = report
        .items
        .iter()
        .find(|item| item.id == "totp-marked")
        .expect("the marked login must be reported");
    assert_eq!(item.findings, vec![Finding::TotpUninspectable], "{item:?}");
    assert!(!item.findings.contains(&Finding::NoTotp), "{item:?}");
    assert_eq!(report.logins, 1);
    assert_eq!(report.with_totp, 0);
    assert_eq!(report.totp_coverage(), 0.0);
    assert_eq!(
        Finding::TotpUninspectable.message(),
        "TOTP 検査対象外（復号できませんでした）"
    );
    // A genuinely empty field still takes the NoTotp branch.
    let empty = report_of(vec![login(
        "totp-empty",
        "Empty",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://b.example",
        "",
    )]);
    let empty_item = empty
        .items
        .iter()
        .find(|item| item.id == "totp-empty")
        .expect("the empty login must be reported");
    assert!(empty_item.findings.contains(&Finding::NoTotp));
    assert!(!empty_item.findings.contains(&Finding::TotpUninspectable));
}

#[test]
fn an_empty_uri_from_sync_is_reported_as_no_uri() {
    // openwarden drops an empty URI field while parsing a cipher
    // (vault.rs:340-363, 725-737), so the imported model has no URIs. The audit
    // must then report NoUri rather than UriUninspectable; exercise the real
    // sync -> import path instead of hand-writing an empty `uris` vector.
    let key = openwarden::UserKey::from_bytes(&[0u8; 64]).expect("a 64-byte test key");
    let state = openwarden::KeyState {
        protected_key: String::new(),
        kdf: None,
    };
    let mut vault = openwarden::Vault::open(key, state);
    let body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [],
        "ciphers": [{
            "id": "empty-uri",
            "type": 1,
            "name": null,
            "login": { "uris": [{ "uri": "" }] },
            "revisionDate": "2024-01-01T00:00:00Z"
        }]
    })
    .to_string();
    let sync = crate::vault_sync::parse_sync(body.as_bytes()).expect("sync JSON should parse");
    vault.apply_sync(sync).expect("sync should apply");
    let model = crate::vault_sync::import_logins(&vault).expect("import should succeed");
    let item = model.item("empty-uri").expect("the login must be imported");
    assert!(item.uris().is_empty(), "{:?}", item.uris());

    let mut imported = Vault::new();
    imported.items = vec![item.clone()];
    let report = audit(&imported, Thresholds::default(), NOW);
    assert!(
        report.items[0].findings.contains(&Finding::NoUri),
        "{:?}",
        report.items[0].findings
    );
    assert!(!report.items[0]
        .findings
        .contains(&Finding::UriUninspectable));
}

#[test]
fn all_thirty_eight_common_dictionary_entries_are_detected() {
    // The exact-match table in `is_exact_common_password` (health.rs:498-537)
    // has 38 entries. An earlier regression test sampled only five; pinning the
    // whole table catches a deleted or mistyped entry.
    const COMMON_ENTRIES: &[&str] = &[
        "password",
        "password1",
        "password123",
        "passw0rd",
        "p@ssw0rd",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "letmein",
        "welcome",
        "admin",
        "administrator",
        "root",
        "toor",
        "iloveyou",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "abc123",
        "master",
        "shadow",
        "superman",
        "batman",
        "trustno1",
        "starwars",
        "whatever",
        "zaq12wsx",
        "1q2w3e4r",
        "1qaz2wsx",
        "asdfghjkl",
        "correcthorsebatterystaple",
    ];
    assert_eq!(COMMON_ENTRIES.len(), 38);
    for word in COMMON_ENTRIES {
        assert!(
            super::is_exact_common_password(word),
            "missing from COMMON: {word}"
        );
        assert!(super::is_common_password(word), "{word}");
        // Matching is exact, not substring-based: a trailing character makes
        // the value fall back to the prefix/cap rules instead of the table.
        let near_miss = format!("{word}!");
        assert!(
            !super::is_exact_common_password(&near_miss),
            "exact match must not be a substring test: {near_miss}"
        );
    }
}

#[test]
fn non_ascii_digit_only_passwords_keep_the_wide_pool_constraint() {
    // health.rs:327,331,336,349-350: `has_digit` uses `is_ascii_digit`, so
    // fullwidth / Arabic-Indic / Devanagari digits only set `has_wide` and add
    // WIDE_POOL (100) to the pool. The PIN short-circuit at health.rs:359-362
    // is ASCII-only too, so they are not charged the 10-digit pool. Pin this
    // known overestimate instead of claiming PIN-equivalent scoring.
    let ascii_pin = estimate_entropy("1234");
    assert_eq!(ascii_pin, entropy_bits(10, 4).round() as u32);
    for password in ["１２３４", "١٢٣٤", "१२३४"] {
        let wide = estimate_entropy(password);
        assert_eq!(
            wide,
            entropy_bits(100, password.chars().count()).round() as u32,
            "{password}"
        );
        assert!(wide > ascii_pin, "{password}: {wide} vs {ascii_pin}");
    }
    // A mix of ASCII and non-ASCII digits stays on the wide-pool path: the
    // presence of one ASCII digit does not trigger the all-digits PIN rule.
    let mixed = estimate_entropy("12３４");
    assert_eq!(mixed, entropy_bits(100, 4).round() as u32);
    assert!(mixed > ascii_pin, "{mixed} vs {ascii_pin}");
}

#[test]
fn mixed_uri_lists_are_audited_per_uri_without_leaking_any() {
    use crate::vault_sync::UNDECRYPTABLE_URI;

    // A single login can hold secure, insecure and undecryptable URIs at once.
    // The loop in `audit_item` (health.rs:703-725) must inspect every entry,
    // keep only scheme + host for each insecure one, and preserve the separate
    // decryption finding instead of reporting a missing URI.
    let mut item = VaultItem::new(
        "mixed",
        "Mixed",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("GEZDGNBVGY3TQOJQ".into()),
            uris: vec![
                LoginUri::new("https://secure.example.com/login"),
                LoginUri::new(
                    "http://user:URI_SECRET@plain.example.com:8080/path?key=URI_KEY#frag",
                ),
                LoginUri::new(UNDECRYPTABLE_URI),
                LoginUri::new("HTTP://second.example.com/other"),
            ],
        },
    );
    item.revision_date = NOW;
    let report = report_of(vec![item]);
    let findings = &report.items[0].findings;

    let insecure: Vec<&str> = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::InsecureUri { uri } => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        insecure,
        vec!["http://plain.example.com:8080", "http://second.example.com"]
    );
    assert!(findings.contains(&Finding::UriUninspectable));
    assert!(!findings.contains(&Finding::NoUri));
    assert_eq!(findings.len(), 3, "{findings:?}");

    for rendered in [
        format!("{report:?}"),
        serde_json::to_string(&report).unwrap(),
    ] {
        for secret in [
            "URI_SECRET",
            "URI_KEY",
            "user:URI_SECRET",
            "/path",
            "#frag",
            "secure.example.com",
        ] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
    }
}

#[test]
fn separated_passphrases_reject_invalid_capitalization() {
    use crate::words::WORDS;

    let first = WORDS[0];
    let second = WORDS[1];
    let plain = format!("{first}-{second}");
    let capitalized = format!("{}-{second}", upper_first(first));
    assert!(super::passphrase_estimate(&plain).is_some(), "{plain}");
    assert!(
        super::passphrase_estimate(&capitalized).is_some(),
        "{capitalized}"
    );

    // The separator-free path already rejects these spellings; the separated
    // path must now honour the same contract (health.rs:394-433).
    let all_caps = format!("{}-{second}", first.to_ascii_uppercase());
    let inner_caps = format!("{}-{second}", upper_second(first));
    let wrong_tail = format!(
        "{}{}-{second}",
        &first[..1],
        first[1..].to_ascii_uppercase()
    );
    for bad in [&all_caps, &inner_caps, &wrong_tail] {
        assert_eq!(super::passphrase_estimate(bad), None, "{bad}");
        assert_eq!(
            super::passphrase_estimate(&format!("{bad}7")),
            None,
            "a trailing number must not hide invalid capitalization: {bad}"
        );
    }

    // Rejection falls back to the character-pool estimate rather than silently
    // crediting a two-word generator draw.
    assert!(estimate_entropy(&all_caps) > estimate_entropy(&plain));

    assert_eq!(super::word_capitalization(first, first), Some(false));
    assert_eq!(
        super::word_capitalization(&upper_first(first), first),
        Some(true)
    );
    assert_eq!(
        super::word_capitalization(&first.to_ascii_uppercase(), first),
        None
    );
    assert_eq!(
        super::word_capitalization(&upper_second(first), first),
        None
    );
    assert_eq!(super::word_capitalization("", first), None);
}

#[test]
fn non_ascii_uppercase_passphrases_are_rejected() {
    use crate::words::WORDS;

    let kite = "kite";
    let second = WORDS[0]; // "able"
    assert!(WORDS.contains(&kite));

    // The generator emits only ASCII capitals. U+212A KELVIN SIGN lowercases to
    // ASCII `k`, so the word-list lookup succeeds, but `word_capitalization`
    // must still reject the word because `is_ascii_uppercase()` is false
    // (health.rs:468-488). The ASCII-capitalized control is accepted.
    let kelvin = format!("\u{212a}ite-{second}");
    let ascii_capitalized = format!("Kite-{second}");
    assert_eq!(super::word_capitalization("\u{212a}ite", kite), None);
    assert_eq!(super::word_capitalization("Kite", kite), Some(true));
    assert_eq!(super::passphrase_estimate(&kelvin), None, "{kelvin}");
    assert!(
        super::passphrase_estimate(&ascii_capitalized).is_some(),
        "{ascii_capitalized}"
    );
    assert!(
        estimate_entropy(&kelvin) > estimate_entropy(&ascii_capitalized),
        "a rejected passphrase must fall back to the wider character pool"
    );

    // A full-width capital does not even fold to an ASCII word, so the
    // recognizer rejects it before the capitalization check. The
    // separator-free recognizer rejects the Kelvin form too: it folds with
    // `to_ascii_lowercase`, which leaves U+212A untouched.
    let fullwidth = format!("\u{ff21}ble-{second}");
    assert_eq!(super::passphrase_estimate(&fullwidth), None, "{fullwidth}");
    assert_eq!(
        super::words_without_separator(&format!("\u{212a}ite{second}")),
        None
    );
}

#[test]
fn mixed_capitalization_adds_the_passphrase_bonus_only_once() {
    use crate::words::WORDS;

    let words = [WORDS[0], WORDS[1], WORDS[2]];
    assert!(
        words
            .iter()
            .all(|word| word.chars().all(|ch| ch.is_ascii_lowercase())),
        "fixture words must be lowercase ASCII"
    );

    // `capitalized` is a single bool OR-ed across every word and then charged
    // `words.len()` bits once (health.rs:411-435, 449-467). Capitalizing just
    // one word must therefore score the same as capitalizing all three - not
    // one bonus per capitalized word.
    let base = format!("{}-{}-{}", words[0], words[1], words[2]);
    let mixed = format!("{}-{}-{}", upper_first(words[0]), words[1], words[2]);
    let all = format!(
        "{}-{}-{}",
        upper_first(words[0]),
        upper_first(words[1]),
        upper_first(words[2])
    );
    let word_bits = entropy_bits(WORDS.len(), words.len());
    let expected = (word_bits + words.len() as f64).round() as u32;

    assert_eq!(
        super::passphrase_estimate(&base),
        Some(word_bits.round() as u32),
        "{base}"
    );
    assert_eq!(
        super::passphrase_estimate(&mixed),
        Some(expected),
        "{mixed}"
    );
    assert_eq!(super::passphrase_estimate(&all), Some(expected), "{all}");
    assert_eq!(
        super::passphrase_estimate(&mixed),
        super::passphrase_estimate(&all),
        "the capitalization bonus must not scale with the number of capitals"
    );
    assert_eq!(
        super::passphrase_estimate(&mixed).unwrap() - super::passphrase_estimate(&base).unwrap(),
        words.len() as u32,
        "exactly one word's worth of bits is added"
    );

    // The separator-free recognizer ORs the same flag, so a single capitalized
    // word gets the identical one-shot bonus on that path too.
    let flat_base: String = words.concat();
    let flat_mixed = format!("{}{}{}", upper_first(words[0]), words[1], words[2]);
    let flat_all = format!(
        "{}{}{}",
        upper_first(words[0]),
        upper_first(words[1]),
        upper_first(words[2])
    );
    assert_eq!(
        super::passphrase_estimate(&flat_base),
        Some(word_bits.round() as u32),
        "{flat_base}"
    );
    assert_eq!(
        super::passphrase_estimate(&flat_mixed),
        Some(expected),
        "{flat_mixed}"
    );
    assert_eq!(
        super::passphrase_estimate(&flat_all),
        Some(expected),
        "{flat_all}"
    );

    // The public estimator forwards the same number to the strength meter.
    assert_eq!(estimate_entropy(&mixed), expected);
    assert_eq!(estimate_entropy(&flat_mixed), expected);
}

#[test]
fn duplicate_http_uris_on_one_host_are_counted_twice_today() {
    // Characterization of the current behaviour, not a desired invariant:
    // `audit_item` pushes one `InsecureUri` per URI entry (health.rs:857-879)
    // without deduplicating by host, so two http URIs on the same host produce
    // two findings. `Report::total_findings`/`count_of` count both; `affected`
    // stays item-scoped. This was reconsidered in R2 and deliberately left
    // as-is: every insecure entry is worth reporting, and deduplicating by the
    // masked host would need a new rule (how to merge different ports/paths)
    // plus a UI wording change. Pinning the double count keeps that decision
    // explicit and makes any future dedup a reviewed change.
    let mut item = VaultItem::new(
        "dup-http",
        "Duplicate HTTP",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("GEZDGNBVGY3TQOJQ".into()),
            uris: vec![
                LoginUri::new("http://dup.example.com/path-a"),
                // Port 80 is the scheme default, so `mask_uri` drops it and
                // both findings render the same masked host.
                LoginUri::new("http://dup.example.com:80/path-b?token=URI_SECRET"),
                LoginUri::new("https://dup.example.com/secure"),
            ],
        },
    );
    item.revision_date = NOW;
    let report = report_of(vec![item]);

    let insecure: Vec<&str> = report.items[0]
        .findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::InsecureUri { uri } => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        insecure,
        vec!["http://dup.example.com", "http://dup.example.com"],
        "two http URI entries produce two identical masked findings"
    );
    // No other finding should be present: strong password, valid TOTP, named
    // item and revision == NOW avoid weak/reuse/TOTP/unnamed/stale findings.
    assert_eq!(report.items[0].findings.len(), 2, "{:?}", report.items[0]);
    assert_eq!(report.total_findings(), 2);
    assert_eq!(
        report.affected(),
        1,
        "findings are counted per URI, items once"
    );
    assert_eq!(report.count_of(Severity::High), 2);
    assert_eq!(report.count_of(Severity::Medium), 0);
    assert_eq!(report.count_of(Severity::Low), 0);
    let summary = report.summary();
    assert!(summary.contains("1 件に 2 個の問題"), "{summary}");
    assert!(summary.contains("高 2"), "{summary}");
    // The raw URI token never reaches the rendered finding.
    assert!(!format!("{report:?}").contains("URI_SECRET"));

    // Control: a single http URI on the same host yields exactly one finding,
    // so the doubling above is caused by the duplicate entry, not the fixture.
    let mut single_item = VaultItem::new(
        "single-http",
        "Single HTTP",
        ItemData::Login {
            username: "u".into(),
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("GEZDGNBVGY3TQOJQ".into()),
            uris: vec![LoginUri::new("http://dup.example.com/path-a")],
        },
    );
    single_item.revision_date = NOW;
    let single = report_of(vec![single_item]);
    assert_eq!(single.total_findings(), 1, "{:?}", single.items);
    assert_eq!(single.count_of(Severity::High), 1);
    assert_eq!(single.affected(), 1);
}

#[test]
fn repeated_character_with_a_digit_suffix_does_not_escape_the_all_same_penalty() {
    // Regression: `all_same` compared every char with chars[0], so the last
    // digit in "aaaaaaaaaa1" hid a bare ten-character run. The digit-suffix
    // discount then still charged ~50 bit for those identical letters.
    assert_eq!(estimate_entropy("aaaaaaaaaa1"), 0);
    assert_eq!(estimate_entropy("AAAAAAAAAA1"), 0);
    assert_eq!(estimate_entropy("zzzz9"), 0);
    assert_eq!(estimate_entropy("aaaaaaaa"), 0);
    // A genuinely varied word keeps the documented suffix behaviour.
    let plain = estimate_entropy("sunflower");
    let suffixed = estimate_entropy("sunflower42");
    assert!(suffixed > plain, "{suffixed} vs {plain}");
    assert!(
        suffixed < estimate_entropy("sunflower!!"),
        "only digits get the suffix discount"
    );

    let bits = estimate_entropy("aaaaaaaaaa1");
    let report = report_of(vec![login(
        "repeat",
        "Repeat",
        "aaaaaaaaaa1",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn leading_digit_dictionary_passwords_take_the_prefix_cap() {
    // Regression: `is_common_password` only tested `starts_with("password")`,
    // so "1password" escaped the cap and was scored from the raw character
    // pool instead of the ~11-bit dictionary estimate.
    assert!(!super::is_exact_common_password("1password"));
    assert!(super::is_common_password("1password"));
    assert!(estimate_entropy("1password") < 20);
    assert!(super::is_common_password("1qwerty"));
    assert!(estimate_entropy("1qwerty") < 20);

    // The cap still protects long values that merely start with the prefix.
    let weak_bits = Thresholds::default().weak_bits;
    let long = "1passwordVt7#kQm2!zR9wP4$xL8@";
    assert!(!super::is_common_password(long));
    assert!(estimate_entropy(long) >= weak_bits, "{long}");

    let bits = estimate_entropy("1password");
    let report = report_of(vec![login(
        "p",
        "Leading digit",
        "1password",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn digit_suffix_only_and_exact_common_contracts_survive_the_prefix_rule() {
    // The two contracts named in the change stay pinned: only a trailing digit
    // run earns the word-suffix discount, and COMMON remains an exact match.
    assert!(estimate_entropy("sunflower42") < estimate_entropy("sunflower!!"));
    assert!(estimate_entropy("sunflower42") > estimate_entropy("sunflower"));
    for word in [
        "password",
        "password1",
        "password123",
        "qwerty123",
        "1234567890",
        "correcthorsebatterystaple",
    ] {
        assert!(super::is_exact_common_password(word), "{word}");
    }
    assert!(!super::is_exact_common_password("1password"));
    assert!(!super::is_exact_common_password("password123!"));
}

#[test]
fn entropy_estimates_are_clamped_to_1000_bits_on_both_paths() {
    use crate::words::WORDS;

    // health.rs:395 clamps the character-pool estimate before it becomes the
    // u32 in Finding::WeakPassword / password_strength. An unbounded value
    // would wrap or report an absurd strength for a very long input.
    let long = "aB3!".repeat(300); // 1200 chars, all four ASCII classes
    assert_eq!(long.chars().count(), 1200);
    let pool = LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len();
    assert!(entropy_bits(pool, long.chars().count()) > 1000.0);
    assert_eq!(estimate_entropy(&long), 1000);
    assert_eq!(password_strength(&long), (1000, Strength::Strong));

    // The generated-passphrase path has its own clamp (health.rs:454).
    let many_words = vec![WORDS[0]; 200].join("-");
    assert!(entropy_bits(WORDS.len(), 200) > 1000.0);
    assert_eq!(super::passphrase_estimate(&many_words), Some(1000));
    assert_eq!(estimate_entropy(&many_words), 1000);
}

#[test]
fn dictionary_passwords_gain_exactly_one_bit_for_uppercase() {
    // health.rs:383-385: the dictionary estimate is `entropy_bits(2_000, 1)`
    // plus one bit when the value has an uppercase letter. Pin the exact
    // numbers so a future pool/size change cannot silently remove the bonus.
    let base = entropy_bits(2_000, 1).round() as u32;
    assert_eq!(base, 11);
    for (lower, upper) in [
        ("password123", "PASSWORD123"),
        ("letmein", "LETMEIN"),
        ("password", "Password"),
    ] {
        assert!(super::is_exact_common_password(lower), "{lower}");
        assert_eq!(estimate_entropy(lower), base, "{lower}");
        assert_eq!(estimate_entropy(upper), base + 1, "{upper}");
        assert_eq!(
            estimate_entropy(upper) - estimate_entropy(lower),
            1,
            "{lower} -> {upper}"
        );
    }
    // The uppercase form is still far below the weak-password threshold, so
    // the +1 bit does not turn a dictionary guess into an acceptable password.
    assert!(estimate_entropy("PASSWORD123") < Thresholds::default().weak_bits);
}

#[test]
fn trailing_symbols_do_not_hide_a_repeated_character_run() {
    // Regression: the all-same body only stripped trailing ASCII digits, so
    // `aaaaaaaaaa!` kept a non-uniform last code point and escaped the
    // zero-entropy penalty despite being no harder to guess than `aaaaaaaaaa`.
    // Trailing non-alphanumeric decoration is now ignored in either order
    // relative to a digit run; case folding still happens first.
    for password in [
        "aaaaaaaaaa!",
        "AAAAAAAAAA!",
        "aaaaaaaaaa!!!",
        "aaaaaaaaaa!1",
        "aaaaaaaaaa1!",
        "aAaAaA!",
        "zzzz!",
        "あああああ！",
    ] {
        assert_eq!(estimate_entropy(password), 0, "{password}");
    }

    // Only the trailing edge is decoration: an interior symbol keeps the body
    // varied, and a genuinely mixed run still scores from the character pool.
    assert!(estimate_entropy("a!aaaa") > 0);
    assert!(estimate_entropy("aB3!aB3!aB3!") > 0);
    assert!(estimate_entropy("!@#$%^&*!@#$%^&*") > 0);

    // The two contracts named in the change stay intact: mixed-case folds to
    // one character, and only digits earn the word-suffix discount.
    assert_eq!(estimate_entropy("aAaAaA"), 0);
    assert_eq!(estimate_entropy("aAaAaA1"), 0);
    let plain = estimate_entropy("sunflower");
    let digits = estimate_entropy("sunflower42");
    assert!(digits > plain, "{digits} vs {plain}");
    assert!(
        digits < estimate_entropy("sunflower!!"),
        "only digits get the suffix discount"
    );

    // The audit path must surface the zero estimate as a WeakPassword finding.
    let bits = estimate_entropy("aaaaaaaaaa!");
    let report = report_of(vec![login(
        "symbol-repeat",
        "SymbolRepeat",
        "aaaaaaaaaa!",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn leading_whitespace_and_symbol_dictionary_passwords_take_the_prefix_cap() {
    // Regression: `is_common_password` only stripped a leading ASCII digit
    // run, so a short dictionary guess padded with whitespace or symbols at
    // the front escaped the cap and was scored from the raw character pool.
    let weak_bits = Thresholds::default().weak_bits;
    for password in [
        " password",
        "!password123",
        "\t1qwerty",
        "!1password",
        "  qwerty123",
        "【password1", // non-ASCII symbol decoration
    ] {
        let lower = password.to_lowercase();
        assert!(!super::is_exact_common_password(&lower), "{password}");
        assert!(super::is_common_password(&lower), "{password}");
        let bits = estimate_entropy(password);
        assert!(bits < weak_bits, "{password}: {bits} >= {weak_bits}");
    }

    // The cap still protects long values that merely start with a decorated
    // prefix: decoration is not counted toward the limit either way.
    let long = "!passwordVt7#kQm2!zR9wP4$xL8@";
    assert!(!super::is_common_password(&long.to_lowercase()));
    assert!(estimate_entropy(long) >= weak_bits, "{long}");

    // End-to-end: with a valid TOTP and HTTPS URI only the weak password can
    // produce a finding, so the estimate must reach the report verbatim.
    let password = "!password123";
    let bits = estimate_entropy(password);
    let report = report_of(vec![login(
        "leading-decoration",
        "Leading decoration",
        password,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn digit_then_symbol_then_word_leading_decoration_takes_the_prefix_cap() {
    // `strip_leading_decoration` alternates its symbol and ASCII-digit steps,
    // so "1!password" (digit -> symbol -> word) must collapse to "password"
    // just like the already-pinned symbol -> digit -> word spelling
    // "!1password". Without the digit-first pass the '!' would hide the leading
    // digit run and the raw character-pool estimate would clear the threshold.
    let weak_bits = Thresholds::default().weak_bits;
    for password in [
        "1!password",
        "1#qwerty",
        "12!@password",
        " 1 ! password",
        "1!password123",
    ] {
        assert!(
            !super::is_exact_common_password(&password.to_lowercase()),
            "{password}"
        );
        assert!(
            super::is_common_password(&password.to_lowercase()),
            "{password}"
        );
        let bits = estimate_entropy(password);
        assert!(bits < weak_bits, "{password}: {bits} >= {weak_bits}");
    }
    assert_eq!(super::strip_leading_decoration("1!password"), "password");
    assert_eq!(super::strip_leading_decoration("1#qwerty"), "qwerty");

    // The cap still protects long values that merely start with a decorated
    // dictionary prefix.
    let long = "1!passwordVt7#kQm2!zR9wP4$xL8@";
    assert!(!super::is_common_password(&long.to_lowercase()));
    assert!(estimate_entropy(long) >= weak_bits, "{long}");

    // End-to-end: with a valid TOTP and HTTPS URI only the weak password can
    // produce a finding, so the estimate reaches the report verbatim.
    let password = "1!password";
    let bits = estimate_entropy(password);
    let report = report_of(vec![login(
        "digit-symbol-word",
        "Digit then symbol",
        password,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn digit_run_with_trailing_decoration_keeps_its_numeric_core() {
    // Regression: `strip_leading_decoration` alternates its symbol and digit
    // steps. For a numeric core followed by decoration (`12345678!`) it used to
    // strip the whole digit run, hand the loop a decoration-only tail and
    // return `"!"`. The all-same check then scored the varied PIN 0 bits,
    // far below the pure-digit estimate. The digit run is the core here, not
    // decoration before a word, so it must survive to the trailing stripper.
    for password in ["12345678!", "12345678!!!", "!12345678!", "12345678!1"] {
        let body = super::strip_decoration(password);
        assert!(
            body.starts_with("12345678"),
            "{password:?} -> {body:?}: the digit core was discarded"
        );
        let bits = estimate_entropy(password);
        assert!(
            bits >= estimate_entropy("12345678"),
            "{password:?}: {bits} bits lost the numeric core"
        );
    }
    // The all-same penalty still applies to a uniform digit core.
    assert_eq!(estimate_entropy("11111111!"), 0);
    assert_eq!(estimate_entropy("1111111111!"), 0);
    // Leading digits before a real word remain decoration and are stripped.
    assert_eq!(super::strip_leading_decoration("1!password"), "password");
    assert_eq!(super::strip_decoration("12!@password!"), "password");
    assert!(super::is_common_password(&"1!password".to_lowercase()));

    // The audit surfaces the corrected estimate, not a fake zero-bit result.
    let password = "12345678!";
    let bits = estimate_entropy(password);
    let report = report_of(vec![login(
        "pin-decoration",
        "PinDecoration",
        password,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
    assert!(bits > 0, "the numeric core must not be scored as 0 bits");
}

#[test]
fn trailing_dictionary_decoration_does_not_escape_the_prefix_cap() {
    // Regression: `is_common_password` stripped only leading decoration, so a
    // short guess padded at the *end* pushed its character count past the cap
    // and was scored from the raw character pool (health.rs:669,677-678).
    let weak_bits = Thresholds::default().weak_bits;
    for password in [
        "password!",
        "password123!",
        "qwerty!",
        "qwerty123!",
        "qwerty1234567!",
        "password!!!",
        "password  ",
        "password1 ",
        "1password!",
        "!password123!",
        "1!password!2",
    ] {
        let lower = password.to_lowercase();
        assert!(!super::is_exact_common_password(&lower), "{password}");
        assert!(super::is_common_password(&lower), "{password}");
        let bits = estimate_entropy(password);
        assert!(bits < weak_bits, "{password}: {bits} >= {weak_bits}");
    }

    // Both strip helpers are applied in sequence, so mixed leading/trailing
    // runs collapse all the way to the bare dictionary prefix.
    assert_eq!(super::strip_decoration("!1password!2"), "password");
    assert_eq!(super::strip_decoration(" password123 "), "password");
    assert_eq!(super::strip_decoration("qwerty!!"), "qwerty");

    // Long values that merely start with the prefix keep their real estimate
    // even when they end with decoration: the cap is not a blanket rule.
    let long = "passwordVt7#kQm2!zR9wP4$xL8@";
    assert!(!super::is_common_password(&long.to_lowercase()));
    assert!(estimate_entropy(long) >= weak_bits, "{long}");

    // End-to-end: with a valid TOTP and HTTPS URI only the weak password can
    // produce a finding, so the estimate reaches the report verbatim.
    let password = "password123!";
    let bits = estimate_entropy(password);
    let report = report_of(vec![login(
        "trailing-decoration",
        "Trailing decoration",
        password,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn repeated_symbol_runs_take_the_zero_entropy_branch() {
    // `estimate_entropy` returns zero for a bare run of one repeated code
    // point before charging any character-pool entropy. A symbol run is no
    // exception: eight `!` are one repeated draw, not eight draws from SYMBOLS.
    for password in [
        "!!!!!!!!",
        "@@@@@@@@",
        "##########",
        "********",
        "！！！！！！",
    ] {
        assert_eq!(estimate_entropy(password), 0, "{password}");
    }
    // Decoration at the end must not hide the run, just as for a repeated
    // letter (health.rs:521-547).
    for password in ["!!!!!!!!1", "!!!!!!!!!", "!!!!!!!!!1!", "@@@@@@@1"] {
        assert_eq!(estimate_entropy(password), 0, "{password}");
    }
    assert_eq!(password_strength("!!!!!!!!").1, Strength::Weak);

    // A *varied* symbol run still scores from the generator's eight-symbol
    // pool, so this is a uniform-run penalty and not a blanket symbol rule.
    let mixed = "!@#$%^&*!@#$%^&*";
    assert_eq!(
        estimate_entropy(mixed),
        entropy_bits(SYMBOLS.len(), 16).round() as u32
    );
    assert!(estimate_entropy(mixed) > 0);
}

#[test]
fn non_login_items_still_get_unnamed_and_stale_findings() {
    // `audit_item` runs the name and revision checks for every item, not just
    // logins (health.rs:772-781, 866-871). A nameless, old card must therefore
    // carry both findings while none of the login-only checks apply.
    let mut card = VaultItem::new(
        "old-card",
        "  ",
        ItemData::Card(CardData {
            number: "4111 1111 1111 1234".into(),
            ..CardData::default()
        }),
    );
    card.revision_date = NOW - 400 * 86_400;
    let report = report_of(vec![card]);

    assert_eq!(report.examined, 1);
    assert_eq!(report.logins, 0);
    assert_eq!(report.with_totp, 0);
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].id, "old-card");
    assert_eq!(
        report.items[0].findings,
        vec![Finding::Stale { days: 400 }, Finding::Unnamed]
    );
    assert_eq!(report.items[0].worst(), Some(Severity::Medium));
    for finding in &report.items[0].findings {
        assert!(
            !matches!(
                finding,
                Finding::WeakPassword { .. }
                    | Finding::ReusedPassword { .. }
                    | Finding::NoTotp
                    | Finding::NoUri
                    | Finding::UriUninspectable
            ),
            "login-only finding on a card: {finding:?}"
        );
    }
    // The same two findings apply to a note, so this is not card-specific.
    let mut note = VaultItem::new("old-note", "", ItemData::SecureNote { text: "x".into() });
    note.revision_date = NOW - 365 * 86_400;
    let note_report = report_of(vec![note]);
    assert_eq!(
        note_report.items[0].findings,
        vec![Finding::Stale { days: 365 }, Finding::Unnamed]
    );
}

#[test]
fn leading_decoration_does_not_hide_a_repeated_character_run() {
    // Regression: the all-same body stripped only the trailing edge, so a run
    // prefixed with `!` (a digit, whitespace or a symbol) kept a non-uniform
    // first code point and escaped the zero-entropy penalty. `strip_decoration`
    // now removes decoration at both ends before the uniform-run check.
    for password in [
        "!aaaaaaaa",
        "1aaaaaaaa",
        " aaaaaaaa",
        "!1aaaaaaaa",
        "1!aaaaaaaa",
        "!aaaaaaaa!",
        "!aaaaaaaa1!",
        "!aAaAaA",
        "!@aaaaaaaa",
        "！あああああ",
        " !!!!!!!!",
        "1########",
    ] {
        assert_eq!(estimate_entropy(password), 0, "{password}");
    }

    // A bare all-digit value is still left intact for the numeric-PIN branch.
    assert_eq!(estimate_entropy("1234"), entropy_bits(10, 4).round() as u32);
    // A leading symbol makes the *input* a mixed-class value, so it keeps the
    // combined digit+symbol pool rather than the pure-PIN score.
    assert!(estimate_entropy("!1234") > estimate_entropy("1234"));

    // Only the ends are decoration: an interior symbol keeps the body varied.
    assert!(estimate_entropy("!a!aaa") > 0);
    assert!(estimate_entropy("!aB3!aB3!") > 0);
    assert!(estimate_entropy("!@#$%^&*!@#$%^&*") > 0);

    // The audit path surfaces the zero estimate as a WeakPassword finding.
    let bits = estimate_entropy("!aaaaaaaa");
    let report = report_of(vec![login(
        "leading-repeat",
        "Leading repeat",
        "!aaaaaaaa",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn whitespace_only_totp_field_counts_as_unset() {
    // A field containing only whitespace carries no secret: `is_valid_secret`
    // rejects it and the audit reports `NoTotp`. `has_totp_field` must agree
    // instead of claiming the field is present (health.rs:717-728), or the UI
    // badge would contradict the cryptographically unset secret.
    for (index, blank) in ["", " ", "\t\n", "\u{3000}"].iter().enumerate() {
        let item = login(
            &format!("blank-{index}"),
            "Blank",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            blank,
        );
        assert!(!has_totp_field(&item), "{blank:?} must be unset");
        assert!(!has_usable_totp(&item), "{blank:?} must be unusable");
        assert!(!crate::totp::is_valid_secret(blank));
    }

    let report = report_of(vec![
        login(
            "blank",
            "Blank",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "  \t ",
        ),
        login(
            "good",
            "Good",
            "tQ8#wLr1!eZ5vKp3$sM7@",
            "https://b.example",
            "GEZDGNBVGY3TQOJQ",
        ),
    ]);
    let blank = report
        .items
        .iter()
        .find(|item| item.id == "blank")
        .expect("the blank-TOTP login must be reported");
    assert!(blank.findings.contains(&Finding::NoTotp), "{blank:?}");
    assert!(
        !blank.findings.contains(&Finding::TotpUninspectable),
        "{blank:?}"
    );
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
}

#[test]
fn cf_only_totp_field_counts_as_unset() {
    // `has_totp_field` now shares the model's `is_visually_empty` rule: a field
    // made only of Unicode Cf (with or without whitespace) renders nothing and
    // carries no secret, so it must agree with `NoTotp` and `with_totp`.
    for (index, blank) in [
        "\u{200b}",
        "\u{feff}\u{200d}",
        " \u{200b}\t\u{2060} ",
        "\u{ad}",
    ]
    .into_iter()
    .enumerate()
    {
        let item = login(
            &format!("cf-{index}"),
            "Cf",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            blank,
        );
        assert!(!has_totp_field(&item), "{blank:?}");
        assert!(!has_usable_totp(&item), "{blank:?}");
        assert!(!crate::totp::is_valid_secret(blank), "{blank:?}");
    }

    // Controls: an undecryptable marker is still a present field (2FA is
    // known to be configured), and a real base32 secret is present and usable.
    let marked = login(
        "marked",
        "Marked",
        "wU8$kRl3#aS0yM7&tD2!",
        "https://b.example",
        UNDECRYPTABLE_TOTP,
    );
    assert!(has_totp_field(&marked));
    assert!(!has_usable_totp(&marked));
    let good = login(
        "good",
        "Good",
        "tQ8#wLr1!eZ5vKp3$sM7@",
        "https://c.example",
        "GEZDGNBVGY3TQOJQ",
    );
    assert!(has_totp_field(&good));
    assert!(has_usable_totp(&good));

    let report = report_of(vec![
        login(
            "cf",
            "Cf",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://d.example",
            "\u{200b} \u{200d}",
        ),
        good,
    ]);
    let cf = report
        .items
        .iter()
        .find(|item| item.id == "cf")
        .expect("the Cf-only login must be reported");
    assert!(cf.findings.contains(&Finding::NoTotp), "{cf:?}");
    assert!(!cf.findings.contains(&Finding::TotpUninspectable), "{cf:?}");
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
}

#[test]
fn steam_and_otpauth_secrets_count_toward_audit_coverage() {
    // The audit counts a login as configured when `is_valid_secret` accepts
    // its field. openwarden supports `steam://`, `otpauth://` and bare base32;
    // cover the two URI forms here so coverage cannot silently shrink to the
    // bare form only.
    const STEAM: &str = "steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const OTPAUTH: &str =
        "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example";

    let steam = login(
        "steam",
        "Steam",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        STEAM,
    );
    let otpauth = login(
        "otpauth",
        "Otpauth",
        "wU8$kRl3#aS0yM7&tD2!",
        "https://b.example",
        OTPAUTH,
    );
    let missing = login(
        "missing",
        "Missing",
        "tQ8#wLr1!eZ5vKp3$sM7@",
        "https://c.example",
        "",
    );

    assert!(crate::totp::is_valid_secret(STEAM));
    assert!(crate::totp::is_valid_secret(OTPAUTH));
    assert!(has_totp_field(&steam));
    assert!(has_totp_field(&otpauth));
    assert!(has_usable_totp(&steam));
    assert!(has_usable_totp(&otpauth));

    let report = report_of(vec![steam, otpauth, missing]);
    assert_eq!(report.logins, 3);
    assert_eq!(report.with_totp, 2);
    assert!((report.totp_coverage() - 2.0 / 3.0).abs() < 1e-6);
    for id in ["steam", "otpauth"] {
        assert!(
            !report.items.iter().any(|item| item.id == id),
            "a login with a usable {id} secret must be clean: {:?}",
            report.items
        );
    }
    let missing_report = report
        .items
        .iter()
        .find(|item| item.id == "missing")
        .expect("the unset login must be reported");
    assert!(
        missing_report.findings.contains(&Finding::NoTotp),
        "{missing_report:?}"
    );
}

#[test]
fn cf_only_names_use_the_unnamed_finding_and_placeholder() {
    // `trim()` does not remove Unicode Cf, so a name made only of zero-width
    // space / bidi controls rendered blank while escaping both the `Unnamed`
    // finding and the "(名称未設定)" placeholder. Both now share the model's
    // `is_visually_empty` rule with the TOTP badge and search paths.
    for (index, name) in [
        "\u{200b}",
        "\u{feff}\u{200d}",
        " \u{200b}\t\u{2060} ",
        "\u{ad}",
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("cf-name-{index}");
        let mut item = login(
            &id,
            name,
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "GEZDGNBVGY3TQOJQ",
        );
        item.revision_date = NOW;
        let report = report_of(vec![item]);
        let reported = report
            .items
            .iter()
            .find(|entry| entry.id == id)
            .expect("the unnamed item must be reported");
        assert_eq!(reported.name, "(名称未設定)", "name={name:?}");
        assert!(
            reported.findings.contains(&Finding::Unnamed),
            "name={name:?}"
        );
        assert!(report.to_text().contains("(名称未設定)"), "name={name:?}");
    }

    // Control: a visible character alongside Cf is a real name and must not
    // be reported as unnamed.
    let mut named = login(
        "cf-visible-name",
        "\u{200b}GitHub",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    );
    named.revision_date = NOW;
    let report = report_of(vec![named]);
    assert!(
        !report.items.iter().any(|item| item.id == "cf-visible-name"),
        "a name with visible text is not unnamed: {:?}",
        report.items
    );
}

#[test]
fn invisible_only_card_numbers_are_flagged_as_no_card_number() {
    // `audit_item` now shares the model's `is_visually_empty` rule with the
    // name/TOTP/search paths (health.rs:841). `trim()` alone kept NUL, DEL, C1
    // controls and zero-width spaces, so such a number looked present.
    for number in [
        "\u{200b}",
        "\u{0}",
        "\u{1f}",
        "\u{7f}",
        "\u{80}",
        "\u{9f}",
        " \u{200b}\u{0}\t",
    ] {
        let card = VaultItem::new(
            "card-invisible",
            "Card",
            ItemData::Card(CardData {
                number: number.into(),
                ..CardData::default()
            }),
        );
        let report = report_of(vec![card]);
        let item = report
            .items
            .iter()
            .find(|item| item.id == "card-invisible")
            .unwrap_or_else(|| panic!("an invisible number must be flagged: {number:?}"));
        assert!(
            item.findings.contains(&Finding::NoCardNumber),
            "number {number:?}: {:?}",
            item.findings
        );
    }

    // A visible character next to a control keeps the number present.
    let present = VaultItem::new(
        "card-present",
        "Card",
        ItemData::Card(CardData {
            number: "\u{0}4111 1111 1111 1234".into(),
            ..CardData::default()
        }),
    );
    assert!(!report_of(vec![present])
        .items
        .iter()
        .any(|item| item.findings.contains(&Finding::NoCardNumber)));
}

#[test]
fn single_slash_http_uris_are_detected_as_insecure() {
    // Browsers normalize `http:/host` to `http://host`, so a single slash is
    // still an insecure scheme. The check (health.rs:884) must accept `http:/`
    // as a prefix, not only `http://`.
    for raw in [
        "http:/example.com",
        "HTTP:/Example.com",
        "http:/user:token@example.com/path?key=secret",
        "http:\\example.com",
    ] {
        let report = report_of(vec![login("1", "A", "vT7#kQm2!zR9wP4$xL8@", raw, "SECRET")]);
        let finding = report.items[0]
            .findings
            .iter()
            .find(|finding| matches!(finding, Finding::InsecureUri { .. }))
            .unwrap_or_else(|| panic!("single-slash URI was not detected: {raw:?}"));
        let Finding::InsecureUri { uri } = finding else {
            unreachable!()
        };
        assert_eq!(uri, "http://example.com", "raw: {raw:?}");
        assert!(!finding.message().contains("token"), "{raw:?}");
    }

    // A scheme without any slash stays out of scope, and https is not flagged.
    for raw in ["http:example.com", "https:/example.com"] {
        let report = report_of(vec![login("2", "B", "vT7#kQm2!zR9wP4$xL8@", raw, "SECRET")]);
        assert!(
            !report.items.iter().any(|item| item
                .findings
                .iter()
                .any(|finding| matches!(finding, Finding::InsecureUri { .. }))),
            "{raw:?}"
        );
    }
}

#[test]
fn cc_only_names_use_the_unnamed_finding_and_placeholder() {
    // The Cf-only sibling covers format characters. Cc (NUL, DEL, C1 controls)
    // is not whitespace either, so `trim()` alone leaves such a name looking
    // present. `is_visually_empty` also tests `char::is_control`, so these must
    // take the same Unnamed + placeholder path (health.rs:799, 769).
    for (index, name) in [
        "\u{0}",
        "\u{1f}",
        "\u{7f}",
        "\u{80}",
        "\u{9f}",
        " \u{0}\t\u{9f} ",
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("cc-name-{index}");
        let mut item = login(
            &id,
            name,
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "GEZDGNBVGY3TQOJQ",
        );
        item.revision_date = NOW;
        let report = report_of(vec![item]);
        let reported = report
            .items
            .iter()
            .find(|entry| entry.id == id)
            .expect("the unnamed item must be reported");
        assert_eq!(reported.name, "(名称未設定)", "name={name:?}");
        assert!(
            reported.findings.contains(&Finding::Unnamed),
            "name={name:?}: {:?}",
            reported.findings
        );
        assert!(report.to_text().contains("(名称未設定)"), "name={name:?}");
    }

    // Control: a visible character beside a control is a real name and must
    // not be reported as unnamed (the login is otherwise clean).
    let mut named = login(
        "cc-visible-name",
        "\u{0}GitHub",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    );
    named.revision_date = NOW;
    assert!(
        !report_of(vec![named])
            .items
            .iter()
            .any(|item| item.id == "cc-visible-name"),
        "a name with visible text is not unnamed"
    );
}

#[test]
fn cc_only_totp_field_counts_as_unset() {
    // Same Cc coverage for the TOTP badge/finding/counter triad: a field made
    // only of NUL/DEL/C1 controls has no secret, so `has_totp_field` and
    // `has_usable_totp` must be false and the audit must emit NoTotp, not
    // TotpUninspectable (health.rs:727-730, 829-834).
    for (index, blank) in [
        "\u{0}",
        "\u{1f}",
        "\u{7f}",
        "\u{80}",
        "\u{9f}",
        " \u{0}\t\u{9f} ",
    ]
    .into_iter()
    .enumerate()
    {
        let item = login(
            &format!("cc-{index}"),
            "Cc",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            blank,
        );
        assert!(!has_totp_field(&item), "totp={blank:?}");
        assert!(!has_usable_totp(&item), "totp={blank:?}");
    }

    let report = report_of(vec![
        login(
            "cc-blank",
            "Cc",
            "vT7#kQm2!zR9wP4$xL8@",
            "https://a.example",
            "\u{0}\u{9f}",
        ),
        login(
            "good",
            "Good",
            "tQ8#wLr1!eZ5vKp3$sM7@",
            "https://b.example",
            "GEZDGNBVGY3TQOJQ",
        ),
    ]);
    let blank = report
        .items
        .iter()
        .find(|item| item.id == "cc-blank")
        .expect("the Cc-only login must be reported");
    assert!(blank.findings.contains(&Finding::NoTotp), "{blank:?}");
    assert!(
        !blank.findings.contains(&Finding::TotpUninspectable),
        "{blank:?}"
    );
    assert_eq!(report.logins, 2);
    assert_eq!(report.with_totp, 1);
}

#[test]
fn custom_weak_bits_changes_the_audit_not_the_generated_strength() {
    // Known constraint documented on `password_strength`: the generated bucket
    // uses the fixed `WEAK_BITS` boundary, while the audit uses the caller's
    // `Thresholds::weak_bits`. A custom threshold can therefore flag a password
    // the generator still labels Fair. Pin both halves so they are not silently
    // collapsed into one scale.
    const CANDIDATE: &str = "123456789012"; // 12 digits -> exactly 40 bits
    let bits = estimate_entropy(CANDIDATE);
    assert_eq!(bits, 40);
    assert_eq!(Thresholds::default().weak_bits, crate::generator::WEAK_BITS);
    assert_eq!(password_strength(CANDIDATE), (bits, Strength::Fair));

    let mut item = login(
        "custom",
        "Custom",
        CANDIDATE,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    );
    item.revision_date = NOW;
    let vault = Vault {
        items: vec![item],
        folders: Vec::new(),
    };

    // At the default threshold 40 is not *below* 40, so no WeakPassword.
    let default_report = audit(&vault, Thresholds::default(), NOW);
    assert!(
        !default_report.items.iter().any(|item| item
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::WeakPassword { .. }))),
        "{default_report:?}"
    );

    // At a custom threshold of 100 the same estimate fails the audit, but the
    // generated Strength is unchanged: the two scales are independent.
    let strict = audit(
        &vault,
        Thresholds {
            weak_bits: 100,
            ..Thresholds::default()
        },
        NOW,
    );
    assert!(strict.items[0]
        .findings
        .contains(&Finding::WeakPassword { bits }));
    assert_eq!(password_strength(CANDIDATE).1, Strength::Fair);

    // Equality with the threshold is still accepted (the audit compares `<`).
    let boundary = audit(
        &vault,
        Thresholds {
            weak_bits: bits,
            ..Thresholds::default()
        },
        NOW,
    );
    assert!(boundary.items.is_empty(), "{boundary:?}");
}

// --- R2-CORE-121: numeric rendering in Finding::message ---

#[test]
fn finding_message_renders_weak_bits_and_stale_days_numbers() {
    // `Finding::message` interpolates its payload fields verbatim
    // (health.rs:88-92). Pin the exact text plus the digits so a regression to
    // a fixed placeholder (or to a unit-less rendering) is caught.
    for bits in [0u32, 1, 13, 40, 41, 999, u32::MAX] {
        let message = Finding::WeakPassword { bits }.message();
        assert_eq!(message, format!("弱いパスワード（推定 {bits} bit）"));
        assert!(message.contains(&bits.to_string()), "{message}");
        assert!(message.contains(" bit"), "{message}");
    }
    for days in [0i64, 1, 7, 365, 400, 10_000, i64::MIN, i64::MAX] {
        let message = Finding::Stale { days }.message();
        assert_eq!(message, format!("{days} 日以上更新されていない"));
        assert!(message.contains(&days.to_string()), "{message}");
        assert!(message.contains("日以上"), "{message}");
    }
    // Distinct payloads must render distinctly: no shared placeholder.
    assert_ne!(
        Finding::WeakPassword { bits: 13 }.message(),
        Finding::WeakPassword { bits: 31 }.message()
    );
    assert_ne!(
        Finding::Stale { days: 400 }.message(),
        Finding::Stale { days: 40 }.message()
    );
}

#[test]
fn report_text_renders_finding_numbers() {
    // End-to-end: `to_text` renders each finding through `message`
    // (health.rs:278-280), so the values observed in the report must be the
    // same numbers carried by the finding variants.
    let mut item = login("1", "StaleWeak", "1234", "https://a.example", "SECRET");
    item.revision_date = NOW - 400 * 86_400;
    let report = report_of(vec![item]);
    assert!(report.items[0]
        .findings
        .contains(&Finding::WeakPassword { bits: 13 }));
    assert!(report.items[0]
        .findings
        .contains(&Finding::Stale { days: 400 }));

    let text = report.to_text();
    assert!(text.contains("推定 13 bit"), "{text}");
    assert!(text.contains("400 日以上更新されていない"), "{text}");
}

#[test]
fn invisible_characters_do_not_add_the_wide_pool() {
    // Unicode `Cf` (zero-width space, ZWJ, word joiner) and non-ASCII `Cc`
    // (C1 controls) render no glyph. They must not select the 100-character
    // WIDE_POOL allowance (health.rs:333-341); a value made only of them scores
    // zero instead of `entropy_bits(100, 4)`.
    let invisible = "\u{200b}\u{200d}\u{2060}\u{9f}";
    assert_eq!(invisible.chars().count(), 4);
    assert_eq!(
        estimate_entropy(invisible),
        entropy_bits(0, invisible.chars().count()).round() as u32
    );
    assert_eq!(estimate_entropy(invisible), 0);

    // A visible multi-byte character still selects WIDE_POOL even when the
    // value also carries invisible characters: the filter in
    // `visible_lowercase` keeps kana but drops the Cf/Cc decoration.
    let mixed = "\u{200b}あい\u{9f}";
    assert_eq!(mixed.chars().count(), 4);
    assert_eq!(
        estimate_entropy(mixed),
        entropy_bits(100, mixed.chars().count()).round() as u32,
        "{mixed:?}"
    );
    // Control: the same visible characters keep their pre-existing wide-pool
    // score, which is higher than an ASCII value of the same length.
    let visible = "あい";
    assert!(estimate_entropy(visible) > estimate_entropy("ab"));

    // The audit surfaces the invisible-only estimate as a WeakPassword finding.
    let bits = estimate_entropy(invisible);
    let report = report_of(vec![login(
        "invisible-pool",
        "Invisible",
        invisible,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn embedded_invisible_characters_do_not_break_dictionary_classification() {
    // A Cf/Cc character inserted *inside* a common password used to defeat the
    // `starts_with("password")` prefix rule (and, for non-ASCII Cf/C1, add the
    // wide pool), pushing an ~11-bit guess above the 40-bit weak threshold.
    let weak_bits = Thresholds::default().weak_bits;
    for (padded, plain) in [
        ("pass\u{200b}word123", "password123"),
        ("password\u{200b}123", "password123"),
        ("\u{200b}password123", "password123"),
        ("pass\u{0}word123", "password123"),
        ("pass\u{9f}word123", "password123"),
        ("qwerty\u{200b}123", "qwerty123"),
        ("\u{feff}letmein\u{200d}", "letmein"),
    ] {
        let bits = estimate_entropy(padded);
        assert!(bits < weak_bits, "{padded:?}: {bits} >= {weak_bits}");
        assert_eq!(bits, estimate_entropy(plain), "{padded:?} vs {plain}");
    }

    // The same normalization must not extend the prefix cap to a long value
    // that merely starts with a dictionary word: the core is still measured in
    // characters after the invisible characters are removed.
    let long = format!("password{}", "Vt7#kQm2!zR9wP4$xL8@");
    let decorated = format!("pass\u{200b}word{}", "Vt7#kQm2!zR9wP4$xL8@");
    let normalized = super::visible_lowercase(&decorated);
    assert_eq!(normalized, long.to_lowercase(), "{decorated}");
    assert!(!super::is_common_password(&normalized));
    assert!(estimate_entropy(&decorated) >= weak_bits, "{decorated}");

    // End-to-end: with a valid TOTP and HTTPS URI only the weak password can
    // produce a finding, so the low estimate reaches the report verbatim.
    let padded = "pass\u{200b}word123";
    let bits = estimate_entropy(padded);
    let report = report_of(vec![login(
        "cf-dictionary",
        "CfDictionary",
        padded,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn passphrase_estimate_accepts_a_non_ascii_single_separator() {
    use crate::generator::{passphrase_entropy, PassphraseSettings};
    use crate::words::WORDS;

    let first = WORDS[0];
    let second = WORDS[1];
    let base = PassphraseSettings {
        words: 2,
        separator: "。".into(),
        capitalize: false,
        include_number: false,
    };

    // `。` (U+3002 IDEOGRAPHIC FULL STOP) is non-alphanumeric, so it is found
    // by the generator-recognizer's separator scan and the word parts are
    // still ordinary shared-list words (health.rs:425-466).
    let plain = format!("{first}。{second}");
    let expected = passphrase_entropy(&base).round() as u32;
    assert_eq!(
        super::passphrase_estimate(&plain),
        Some(expected),
        "{plain}"
    );
    assert_eq!(estimate_entropy(&plain), expected, "{plain}");

    // A trailing digit and ASCII capitalization work with a multi-byte
    // separator too: the byte-level digit check sees only the final ASCII byte.
    let numbered = format!("{first}。{second}7");
    let numbered_expected = passphrase_entropy(&PassphraseSettings {
        include_number: true,
        ..base.clone()
    })
    .round() as u32;
    assert_eq!(
        super::passphrase_estimate(&numbered),
        Some(numbered_expected),
        "{numbered}"
    );
    let capitalized = format!("{}。{second}", upper_first(first));
    let capitalized_expected = passphrase_entropy(&PassphraseSettings {
        capitalize: true,
        ..base
    })
    .round() as u32;
    assert_eq!(
        super::passphrase_estimate(&capitalized),
        Some(capitalized_expected),
        "{capitalized}"
    );
    assert!(capitalized_expected > expected);
    assert!(numbered_expected > expected);

    // Control: a non-ASCII *alphanumeric* character is not a separator, so the
    // value is not a generated passphrase and falls back to the character pool.
    let alphanumeric_join = format!("{first}あ{second}");
    assert_eq!(super::passphrase_estimate(&alphanumeric_join), None);
}

#[test]
fn passphrase_estimate_folds_invisible_characters_inside_words() {
    use crate::generator::{passphrase_entropy, PassphraseSettings};
    use crate::words::WORDS;

    let first = WORDS[0]; // "able"
    let second = WORDS[1]; // "above"
    let base = PassphraseSettings {
        words: 2,
        separator: "-".into(),
        capitalize: false,
        include_number: false,
    };
    let plain = format!("{first}-{second}");
    let expected = passphrase_entropy(&base).round() as u32;

    // A ZWSP inside a word used to be picked up as the separator, leaving two
    // parts that are not word-list entries; a Cc or bidi control did the same.
    // All of them must fold away before the word-list check, giving the same
    // ~22-bit score as the plain two-word passphrase instead of the much higher
    // character-pool estimate.
    for padded in [
        format!("a\u{200b}ble-{second}"),
        format!("{first}-\u{202e}{second}"),
        format!("ab\u{0}ove-{first}"),
        format!("{first}-\u{9f}{second}"),
        format!("\u{feff}{first}-{second}\u{200d}"),
    ] {
        assert_eq!(
            super::passphrase_estimate(&padded),
            Some(expected),
            "{padded:?}"
        );
        assert_eq!(estimate_entropy(&padded), expected, "{padded:?}");
    }
    assert_eq!(super::passphrase_estimate(&plain), Some(expected));
    assert_eq!(estimate_entropy(&plain), expected);

    // The same folding applies to the separator-free recognizer: the prefix-
    // free word list must parse the word boundaries after the ZWSP is removed.
    let joined_base = PassphraseSettings {
        separator: String::new(),
        ..base.clone()
    };
    let joined_expected = passphrase_entropy(&joined_base).round() as u32;
    assert_eq!(
        joined_expected, expected,
        "the separator carries no entropy"
    );
    for padded in [
        format!("a\u{200b}ble{second}"),
        format!("{first}ab\u{0}ove"),
    ] {
        assert_eq!(
            super::passphrase_estimate(&padded),
            Some(joined_expected),
            "{padded:?}"
        );
        assert_eq!(estimate_entropy(&padded), joined_expected, "{padded:?}");
    }

    // Folding keeps the case, so the generator's capitalization and trailing-
    // digit bonuses still apply and are still credited to the word-list model.
    let numbered = format!("a\u{200b}ble-{second}7");
    assert_eq!(
        super::passphrase_estimate(&numbered),
        Some(
            passphrase_entropy(&PassphraseSettings {
                include_number: true,
                ..base.clone()
            })
            .round() as u32
        ),
        "{numbered:?}"
    );
    let capitalized = format!("A\u{200b}ble-{second}");
    assert_eq!(
        super::passphrase_estimate(&capitalized),
        Some(
            passphrase_entropy(&PassphraseSettings {
                capitalize: true,
                ..base
            })
            .round() as u32
        ),
        "{capitalized:?}"
    );

    // End to end: the folded 2-word value is weak and reaches the report with
    // the word-list bit count, not a character-pool score.
    let padded = format!("a\u{200b}ble-{second}");
    let bits = estimate_entropy(&padded);
    let report = report_of(vec![login(
        "cf-passphrase",
        "CfPassphrase",
        &padded,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn digits_only_common_entries_never_reach_the_common_cap() {
    // health.rs:399-410 orders the all-digits PIN short-circuit *before* the
    // `is_common_password` check. Four entries of the COMMON table
    // (health.rs:625-665) are ASCII digit runs, so their dictionary cap
    // (~11 bits) is unreachable from `estimate_entropy`: they are scored with
    // the 10-symbol PIN pool instead. Characterization of current control
    // flow, not a claim that the PIN score is the desirable one.
    let common_cap = entropy_bits(2_000, 1).round() as u32;
    for word in ["123456", "12345678", "123456789", "1234567890"] {
        assert!(super::is_exact_common_password(word), "{word}");
        assert!(super::is_common_password(word), "{word}");
        let pin = estimate_entropy(word);
        assert_eq!(
            pin,
            entropy_bits(10, word.chars().count()).round() as u32,
            "{word} must be scored by the PIN branch"
        );
        assert!(
            pin > common_cap,
            "{word}: PIN score {pin} must exceed the unreachable common cap {common_cap}"
        );
    }
}

#[test]
fn unicode_space_separators_do_not_hide_a_dictionary_password() {
    // `visible_chars` used to fold only `Cc`/`Cf`. Unicode space separators
    // (`Zs`: NBSP U+00A0, figure space U+2007, narrow NBSP U+202F,
    // ideographic space U+3000, …) are neither controls nor format characters,
    // so an inserted Zs survived the fold, defeated `starts_with("password")`
    // and let an ~11-bit dictionary guess escape the weak-password threshold.
    let weak_bits = Thresholds::default().weak_bits;
    let baseline = estimate_entropy("password123");
    assert!(baseline < weak_bits, "{baseline}");

    for (padded, plain) in [
        ("pass\u{00a0}word123", "password123"),
        ("password\u{2007}123", "password123"),
        ("pass\u{202f}word123", "password123"),
        ("pass\u{3000}word123", "password123"),
        ("\u{00a0}password123", "password123"),
        ("qwerty\u{00a0}123", "qwerty123"),
    ] {
        assert!(
            padded
                .chars()
                .any(|ch| ch.is_whitespace() && !ch.is_control()),
            "fixture must contain a Zs: {padded:?}"
        );
        assert_eq!(super::visible_chars(padded), plain, "{padded:?}");
        assert!(
            super::is_common_password(&padded.to_lowercase()),
            "{padded:?}"
        );
        assert_eq!(
            estimate_entropy(padded),
            estimate_entropy(plain),
            "{padded:?} vs {plain}"
        );
    }

    // Folding Zs must not widen the prefix cap indiscriminately: a long value
    // that merely starts with a dictionary word keeps its real estimate.
    let long = format!("password{}", "Vt7#kQm2!zR9wP4$xL8@");
    let decorated = format!("pass\u{00a0}word{}", "Vt7#kQm2!zR9wP4$xL8@");
    assert_eq!(super::visible_chars(&decorated), long);
    assert!(!super::is_common_password(&decorated.to_lowercase()));
    assert!(estimate_entropy(&decorated) >= weak_bits, "{decorated:?}");

    // End to end: the padded guess reaches the report as WeakPassword with the
    // same bit count as its plain spelling.
    let padded = "pass\u{00a0}word123";
    let bits = estimate_entropy(padded);
    let report = report_of(vec![login(
        "zs-dictionary",
        "ZsDictionary",
        padded,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn controls_and_spaces_are_not_charged_as_symbols() {
    // The SYMBOLS pool is for *visible* ASCII punctuation. An ASCII control
    // (Cc) or the space separator used to satisfy `!is_ascii_alphanumeric()`
    // and add SYMBOLS.len() to the pool, while the wide-pool path already
    // dropped non-ASCII Cc/Cf. Both sides must now use the same rule.
    let lower_pool = LOWERCASE.len();
    let symbol_pool = lower_pool + SYMBOLS.len();

    // Five letters with one invisible ASCII character between them: only the
    // lowercase class contributes to the pool.
    for invisible in [' ', '\u{0000}', '\u{0009}', '\u{007f}'] {
        let password = format!("ab{invisible}cd");
        assert_eq!(password.chars().count(), 5);
        assert_eq!(
            estimate_entropy(&password),
            entropy_bits(lower_pool, 5).round() as u32,
            "{password:?}"
        );
    }

    // A real ASCII symbol still selects the SYMBOLS pool, so this is not a
    // blanket removal of the symbol class.
    assert_eq!(
        estimate_entropy("ab!cd"),
        entropy_bits(symbol_pool, 5).round() as u32
    );
    assert_eq!(
        estimate_entropy("!@#$%^&*!@#$%^&*"),
        entropy_bits(SYMBOLS.len(), 16).round() as u32
    );

    // Whitespace-padded dictionary guesses keep the plain dictionary estimate
    // instead of gaining a symbol class from the padding.
    assert_eq!(estimate_entropy("password "), estimate_entropy("password"));
}

// --- R2-CORE-137: Unicode Zs must not select WIDE_POOL ---

#[test]
fn unicode_space_separators_do_not_add_the_wide_pool() {
    // `has_wide` used to filter only non-ASCII `Cc`/`Cf`. Unicode space
    // separators (`Zs`: NBSP U+00A0, OGHAM SPACE MARK U+1680, FIGURE SPACE
    // U+2007, NARROW NBSP U+202F, IDEOGRAPHIC SPACE U+3000, …) are neither,
    // so a run of them added WIDE_POOL (100) to the pool. Unlike the Cf-only
    // case in `invisible_characters_do_not_add_the_wide_pool`, distinct code
    // points are required here: one repeated Zs would already score zero via
    // the all-same branch and hide the pool regression.
    const ZS: &str = "\u{00a0}\u{1680}\u{2007}\u{202f}\u{205f}\u{3000}";
    assert!(ZS.chars().all(|ch| !ch.is_ascii()
        && ch.is_whitespace()
        && !ch.is_control()
        && !crate::limits::is_format_character(ch)));
    let len = ZS.chars().count();
    assert_eq!(len, 6);
    assert_eq!(estimate_entropy(ZS), entropy_bits(0, len).round() as u32);
    assert_eq!(estimate_entropy(ZS), 0);

    // `Zl`/`Zp` are whitespace too, so the same `is_whitespace()` branch must
    // drop them; the old filter counted them as wide glyphs as well.
    let line_and_paragraph = "\u{2028}\u{2029}";
    assert_eq!(estimate_entropy(line_and_paragraph), 0);

    // A visible multi-byte character keeps the wide allowance even when Zs
    // characters sit beside it: the filter removes only the invisible ones,
    // matching the Cf/Cc mixed case already pinned in health_tests.rs.
    let mixed = "あ\u{3000}い\u{00a0}";
    assert_eq!(mixed.chars().count(), 4);
    assert_eq!(
        estimate_entropy(mixed),
        entropy_bits(100, 4).round() as u32,
        "{mixed:?}"
    );
    assert_eq!(
        estimate_entropy(mixed),
        estimate_entropy("\u{200b}あい\u{9f}")
    );

    // End to end: a Zs-only password is weak with a zero-bit estimate, not a
    // high-entropy wide-string. The reuse map excludes it as visually empty.
    let bits = estimate_entropy(ZS);
    let report = report_of(vec![login(
        "zs-pool",
        "ZsPool",
        ZS,
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert_eq!(bits, 0);
    assert!(
        report.items[0]
            .findings
            .contains(&Finding::WeakPassword { bits }),
        "{report:?}"
    );
}

#[test]
fn unicode_space_separator_passwords_are_excluded_from_reuse() {
    // `Zs` is whitespace, so `model::is_visually_empty` must keep a Zs-only
    // password out of the reuse map even when two items carry the identical
    // value. A visible pair beside it must still form its own reuse group so
    // the "no reuse" assertion below is not vacuous.
    const ZS_PASSWORD: &str = "\u{00a0}\u{2007}\u{202f}\u{3000}";
    assert!(ZS_PASSWORD.chars().all(char::is_whitespace));

    let report = report_of(vec![
        login(
            "zs-one",
            "ZsOne",
            ZS_PASSWORD,
            "https://a.example",
            "GEZDGNBVGY3TQOJQ",
        ),
        login(
            "zs-two",
            "ZsTwo",
            ZS_PASSWORD,
            "https://b.example",
            "GEZDGNBVGY3TQOJQ",
        ),
        login(
            "visible-one",
            "VisibleOne",
            "VisibleSecret42!",
            "https://c.example",
            "GEZDGNBVGY3TQOJQ",
        ),
        login(
            "visible-two",
            "VisibleTwo",
            "VisibleSecret42!",
            "https://d.example",
            "GEZDGNBVGY3TQOJQ",
        ),
    ]);

    let reused: Vec<&str> = report
        .items
        .iter()
        .filter(|item| {
            item.findings
                .iter()
                .any(|finding| matches!(finding, Finding::ReusedPassword { .. }))
        })
        .map(|item| item.id.as_str())
        .collect();
    assert!(
        !reused.contains(&"zs-one") && !reused.contains(&"zs-two"),
        "a Zs-only password must not register as reused: {reused:?}"
    );
    assert!(
        reused.contains(&"visible-one") && reused.contains(&"visible-two"),
        "the visible pair must still be reused: {reused:?}"
    );
    assert_eq!(reused.len(), 2, "{reused:?}");
    assert!(
        report.items.iter().any(|item| {
            item.id == "visible-one"
                && item
                    .findings
                    .contains(&Finding::ReusedPassword { count: 2 })
        }),
        "{report:?}"
    );
}

#[test]
fn ascii_symbols_outside_the_generator_pool_are_charged_the_fixed_symbol_pool() {
    // `has_symbol` charges `SYMBOLS.len()` for *any* visible ASCII
    // non-alphanumeric character, not only the eight the generator emits.
    // Pin that weighting for punctuation outside `SYMBOLS`: such a password
    // gets the fixed eight-symbol pool -- neither zero nor the ~32 visible
    // ASCII punctuation characters.
    const OUTSIDE: &str = "()[]{};:?~|_-+=";
    assert!(OUTSIDE.chars().all(|c| c.is_ascii()
        && !c.is_ascii_alphanumeric()
        && !c.is_control()
        && !c.is_whitespace()
        && !SYMBOLS.contains(c)));
    let len = OUTSIDE.chars().count();
    assert_eq!(len, 15);
    assert_eq!(
        estimate_entropy(OUTSIDE),
        entropy_bits(SYMBOLS.len(), len).round() as u32
    );
    // An in-pool string of the same length scores identically: the pool size
    // is fixed and does not depend on which punctuation was used.
    let inside = format!("{SYMBOLS}{}", "!".repeat(len - SYMBOLS.len()));
    assert_eq!(estimate_entropy(&inside), estimate_entropy(OUTSIDE));

    // One out-of-pool symbol adds exactly the same class as one in-pool symbol,
    // and a mixed-class value keeps the combined four-class pool.
    assert_eq!(estimate_entropy("ab(cd"), estimate_entropy("ab!cd"));
    let mixed = "aB3()[]{}";
    let pool = LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len();
    assert_eq!(
        estimate_entropy(mixed),
        entropy_bits(pool, mixed.chars().count()).round() as u32,
        "{mixed}"
    );
}

#[test]
fn repeated_body_with_a_fullwidth_digit_suffix_escapes_the_all_same_penalty() {
    // Characterization of a known overestimate, not a desired invariant.
    // `strip_decoration` / `strip_trailing_digits` strip only ASCII digit runs
    // (health.rs:585-616,745-747), so a repeated body followed by a full-width
    // digit keeps two distinct code points and misses the 0-bit all-same arm
    // (health.rs:397-407). The full-width digit still switches on WIDE_POOL
    // (health.rs:345-370), so the estimate stays high even though the value is
    // no harder to guess than its ASCII-suffixed twin.
    assert_eq!(super::strip_decoration("aaaaaaaaaa1"), "aaaaaaaaaa");
    assert_eq!(super::strip_decoration("aaaaaaaaaa１"), "aaaaaaaaaa１");

    for (ascii, wide, pool) in [
        ("aaaaaaaaaa1", "aaaaaaaaaa１", LOWERCASE.len() + 100), // 126-char pool
        ("zzzz9", "zzzz９", LOWERCASE.len() + 100),
        ("あああああ1", "あああああ１", 100), // wide pool only
    ] {
        assert_eq!(estimate_entropy(ascii), 0, "{ascii}");
        let expected = entropy_bits(pool, wide.chars().count()).round() as u32;
        assert_eq!(estimate_entropy(wide), expected, "{wide}");
        assert!(expected > 0, "{wide}");
    }

    // End-to-end: the ASCII twin is flagged WeakPassword{bits: 0} while the
    // high full-width estimate clears the default 40-bit threshold and leaves
    // the login clean (valid TOTP and HTTPS URI avoid any other finding).
    let ascii_bits = estimate_entropy("aaaaaaaaaa1");
    let ascii_report = report_of(vec![login(
        "ascii-suffix",
        "AsciiSuffix",
        "aaaaaaaaaa1",
        "https://a.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert_eq!(ascii_bits, 0);
    assert!(ascii_report.items[0]
        .findings
        .contains(&Finding::WeakPassword { bits: 0 }));

    let wide_bits = estimate_entropy("aaaaaaaaaa１");
    let wide_report = report_of(vec![login(
        "wide-suffix",
        "WideSuffix",
        "aaaaaaaaaa１",
        "https://b.example",
        "GEZDGNBVGY3TQOJQ",
    )]);
    assert!(wide_bits >= Thresholds::default().weak_bits, "{wide_bits}");
    assert!(
        wide_report.items.is_empty(),
        "the overestimated value is not Weak today: {wide_report:?}"
    );
}
