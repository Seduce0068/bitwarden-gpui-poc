#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::generator::{entropy_bits, DIGITS, LOWERCASE, SYMBOLS, UPPERCASE};
use crate::health::*;
use crate::model::{CardData, ItemData, LoginUri, SshKeyData, VaultItem};
use crate::vault_sync::{is_undecryptable_password, UNDECRYPTABLE_PASSWORD};
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
            password: Zeroizing::new("vT7#kQm2!zR9wP4$xL8@".into()),
            totp: Zeroizing::new("S".into()),
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
    // The audit sorts each item's findings worst-first (health.rs:592-594).
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

    // Exactly at the cap: still a dictionary guess, hence Weak.
    let at_cap = format!("password{}", "Vt7#kQm2"); // 8 + 8 = 16 chars
    assert_eq!(at_cap.len(), PASSWORD_PREFIX_LIMIT);
    let at_cap_bits = estimate_entropy(&at_cap);
    assert!(at_cap_bits < weak_bits, "{at_cap}: {at_cap_bits}");

    // One character past the cap: the same kind of value keeps its genuine
    // entropy and is no longer flagged Weak.
    let past_cap = format!("{at_cap}!"); // 17 chars
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
    let at_cap = "qwerty123456"; // exactly 12 characters
    let past_cap = "qwerty1234567"; // 13 characters
    assert_eq!(at_cap.len(), 12);
    assert_eq!(past_cap.len(), 13);
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
                private_key: String::new(),
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
fn empty_names_use_a_placeholder_in_the_report() {
    // The placeholder branch only covers a truly empty name; whitespace-only
    // names keep their raw value (see `unnamed_items_are_reported`).
    let mut item = login(
        "1",
        "",
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
    assert_eq!(reported.name, "(名称未設定)");
    assert!(reported.findings.contains(&Finding::Unnamed));
    assert!(report.to_text().contains("(名称未設定)"));
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
    // fall back to the character-pool estimate (health.rs:399-406).
    let repeated = format!("{}-{}-{}", WORDS[0], WORDS[1], WORDS[2]);
    let mixed = format!("{}-{}_{}", WORDS[0], WORDS[1], WORDS[2]);
    assert!(
        super::passphrase_estimate(&repeated).is_some(),
        "{repeated}"
    );
    assert_eq!(super::passphrase_estimate(&mixed), None, "{mixed}");
    assert_eq!(
        super::passphrase_estimate(&format!("{mixed}7")),
        None,
        "a trailing number must not hide a mixed separator"
    );
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
