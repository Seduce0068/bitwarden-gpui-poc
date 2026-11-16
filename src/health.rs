//! Vault health: the checks behind the "vault health" panel.
//!
//! Bitwarden's security audit reports weak, reused, and exposed passwords plus
//! items missing 2FA and unsecured (`http`) URIs. The PoC can do the first
//! three from local data alone; the breach check would need an external
//! service and is deliberately absent.
//!
//! The estimate of how guessable a password is comes from a local,
//! deliberately simple model — length, character classes, and whether it looks
//! like a known-pattern password. It is not zxcvbn, and the report says so.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::generator::{entropy_bits, Strength};
use crate::model::{ItemKind, Vault, VaultItem};

/// A single finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The password's estimated entropy is below `bits`.
    WeakPassword {
        /// The estimated entropy in bits.
        bits: u32,
    },
    /// The same password appears on more than one item.
    ReusedPassword {
        /// How many items share it.
        count: usize,
    },
    /// The item's revision date is older than the threshold.
    Stale {
        /// Age in days.
        days: i64,
    },
    /// A URI is `http://`, so the credential can be sent in the clear.
    InsecureUri {
        /// The offending URI.
        uri: String,
    },
    /// A login carries no TOTP secret.
    NoTotp,
    /// The item has no URI at all, so autofill can't find it.
    NoUri,
    /// The name is empty.
    Unnamed,
}

impl Finding {
    /// A one-line message for the list.
    pub fn message(&self) -> String {
        match self {
            Self::WeakPassword { bits } => format!("弱いパスワード（推定 {bits} bit）"),
            Self::ReusedPassword { count } => format!("{count} 件で同じパスワードを再利用"),
            Self::Stale { days } => format!("{days} 日以上更新されていない"),
            Self::InsecureUri { uri } => {
                format!("http の URI（{}）", crate::model::mask_uri(uri))
            }
            Self::NoTotp => "TOTP 未設定".to_string(),
            Self::NoUri => "URI 未設定".to_string(),
            Self::Unnamed => "名前が空".to_string(),
        }
    }

    /// How severe the finding is, for sorting and colouring.
    pub const fn severity(&self) -> Severity {
        match self {
            Self::ReusedPassword { .. } | Self::InsecureUri { .. } => Severity::High,
            Self::WeakPassword { .. } | Self::Stale { .. } => Severity::Medium,
            Self::NoTotp | Self::NoUri | Self::Unnamed => Severity::Low,
        }
    }
}

/// Finding severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Cosmetic or hygiene.
    Low,
    /// Should be fixed soon.
    Medium,
    /// Fix first.
    High,
}

impl Severity {
    /// The severity's label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "低",
            Self::Medium => "中",
            Self::High => "高",
        }
    }
}

/// Everything found for one item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemReport {
    /// The item id.
    pub id: String,
    /// The item name.
    pub name: String,
    /// The item's kind.
    pub kind: ItemKind,
    /// What was found.
    pub findings: Vec<Finding>,
}

impl ItemReport {
    /// The most severe finding, if any.
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(Finding::severity).max()
    }
}

/// The whole audit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// One entry per item that has at least one finding, worst first.
    pub items: Vec<ItemReport>,
    /// How many items were examined.
    pub examined: usize,
    /// How many logins carry a TOTP secret.
    pub with_totp: usize,
    /// How many logins were examined (the denominator for TOTP coverage).
    pub logins: usize,
}

impl Report {
    /// Total findings across all items.
    pub fn total_findings(&self) -> usize {
        self.items.iter().map(|item| item.findings.len()).sum()
    }

    /// How many items have at least one finding.
    pub fn affected(&self) -> usize {
        self.items.len()
    }

    /// Findings of `severity` across all items.
    pub fn count_of(&self, severity: Severity) -> usize {
        self.items
            .iter()
            .flat_map(|item| item.findings.iter())
            .filter(|finding| finding.severity() == severity)
            .count()
    }

    /// The share of logins with a TOTP secret, 0.0..=1.0.
    pub fn totp_coverage(&self) -> f32 {
        if self.logins == 0 {
            return 0.0;
        }
        self.with_totp as f32 / self.logins as f32
    }

    /// A one-line summary for the panel header.
    pub fn summary(&self) -> String {
        if self.items.is_empty() {
            return format!("{} 件を検査: 問題は見つかりませんでした", self.examined);
        }
        format!(
            "{} 件を検査: {} 件に {} 個の問題（高 {} / 中 {} / 低 {}）",
            self.examined,
            self.affected(),
            self.total_findings(),
            self.count_of(Severity::High),
            self.count_of(Severity::Medium),
            self.count_of(Severity::Low)
        )
    }

    /// A plain-text rendering, for copying out of the app.
    pub fn to_text(&self) -> String {
        let mut out = String::from("Vault 健全性レポート\n");
        out.push_str(&self.summary());
        out.push('\n');
        out.push_str(&format!(
            "TOTP 設定済み: {}/{} ({:.0}%)\n",
            self.with_totp,
            self.logins,
            self.totp_coverage() * 100.0
        ));
        for item in &self.items {
            out.push_str(&format!(
                "\n[{}] {} ({})\n",
                item.worst().map_or("?", Severity::label),
                item.name,
                item.kind.label()
            ));
            for finding in &item.findings {
                out.push_str(&format!("  - {}\n", finding.message()));
            }
        }
        out
    }
}

/// Audit thresholds, so the report is reproducible and adjustable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Passwords below this estimated entropy (bits) are weak.
    pub weak_bits: u32,
    /// Items not modified within this many days are stale.
    pub stale_days: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            weak_bits: 50,
            stale_days: 365,
        }
    }
}

/// Estimate a password's entropy in bits.
///
/// The model: the character pool the password actually uses, times its length,
/// with a penalty for the patterns that make a password far weaker than its
/// pool size suggests (a single repeated character, an all-digit string, a
/// common word, or a short trailing-digit suffix on a word).
pub fn estimate_entropy(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }
    let chars: Vec<char> = password.chars().collect();
    let mut pool = 0usize;
    let has_lower = chars.iter().any(|c| c.is_ascii_lowercase());
    let has_upper = chars.iter().any(|c| c.is_ascii_uppercase());
    let has_digit = chars.iter().any(|c| c.is_ascii_digit());
    let has_symbol = chars
        .iter()
        .any(|c| !c.is_ascii_alphanumeric() && c.is_ascii());
    let has_wide = chars.iter().any(|c| !c.is_ascii());
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 33;
    }
    if has_wide {
        pool += 100;
    }
    let raw = entropy_bits(pool, chars.len());

    // Patterns that shrink the real search space.
    let all_same = chars.iter().all(|c| *c == chars[0]);
    if all_same {
        return 0;
    }
    if chars.iter().all(char::is_ascii_digit) {
        // A numeric PIN: length dominates, pool is 10.
        return entropy_bits(10, chars.len()).round().max(0.0) as u32;
    }
    let lower = password.to_lowercase();
    let common = is_common_password(&lower);
    let mut adjusted = raw;
    if common {
        // A dictionary word: roughly the word list plus a little for casing.
        adjusted = adjusted.min(entropy_bits(2_000, 1) + if has_upper { 1.0 } else { 0.0 });
    }
    // A word with a short digit or symbol suffix can be brute-forced by
    // trying every suffix, so charge only for the suffix length.
    if let Some(stripped) = strip_trailing_digits(&lower) {
        if !common && stripped.len() >= 3 && stripped.chars().all(|c| c.is_ascii_lowercase()) {
            let suffix = lower.len() - stripped.len();
            adjusted = adjusted.min(entropy_bits(26, stripped.len()) + entropy_bits(10, suffix));
        }
    }
    adjusted.round().clamp(0.0, 1000.0) as u32
}

fn strip_trailing_digits(value: &str) -> Option<&str> {
    let trimmed = value.trim_end_matches(|c: char| c.is_ascii_digit());
    (trimmed.len() != value.len() && !trimmed.is_empty()).then_some(trimmed)
}

/// A small list of the passwords that show up first in every breach corpus.
fn is_common_password(lower: &str) -> bool {
    const COMMON: &[&str] = &[
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
    COMMON.contains(&lower)
        || lower.starts_with("password")
        || (lower.starts_with("qwerty") && lower.len() <= 12)
}

/// Audit `vault` with `thresholds` at `now` (Unix seconds).
///
/// Reuse is computed across all logins in the vault, including ones that are
/// filtered out of the current view, so the report is stable.
pub fn audit(vault: &Vault, thresholds: Thresholds, now: i64) -> Report {
    let mut passwords: HashMap<&str, Vec<&str>> = HashMap::new();
    for item in &vault.items {
        if let Some(password) = item.password() {
            if !password.is_empty() {
                passwords.entry(password).or_default().push(&item.id);
            }
        }
    }

    let mut report = Report {
        examined: vault.items.len(),
        ..Report::default()
    };

    for item in &vault.items {
        let mut findings = Vec::new();
        audit_item(item, thresholds, now, &passwords, &mut findings);
        if item.kind() == ItemKind::Login {
            report.logins += 1;
            if item.totp_secret().is_some_and(|s| !s.trim().is_empty()) {
                report.with_totp += 1;
            }
        }
        if !findings.is_empty() {
            findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity()));
            report.items.push(ItemReport {
                id: item.id.clone(),
                name: if item.name.is_empty() {
                    "(名称未設定)".to_string()
                } else {
                    item.name.clone()
                },
                kind: item.kind(),
                findings,
            });
        }
    }

    report.items.sort_by(|a, b| {
        b.worst()
            .cmp(&a.worst())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
    report
}

fn audit_item(
    item: &VaultItem,
    thresholds: Thresholds,
    now: i64,
    passwords: &HashMap<&str, Vec<&str>>,
    findings: &mut Vec<Finding>,
) {
    if item.name.trim().is_empty() {
        findings.push(Finding::Unnamed);
    }

    match &item.data {
        crate::model::ItemData::Login {
            username: _,
            password,
            totp,
            uris: _,
        } => {
            if !password.is_empty() {
                let bits = estimate_entropy(password);
                if bits < thresholds.weak_bits {
                    findings.push(Finding::WeakPassword { bits });
                }
                if let Some(ids) = passwords.get(password.as_str()) {
                    if ids.len() > 1 {
                        findings.push(Finding::ReusedPassword { count: ids.len() });
                    }
                }
            }
            if totp.trim().is_empty() {
                findings.push(Finding::NoTotp);
            }
        }
        crate::model::ItemData::Card(card) if card.number.is_empty() => {
            findings.push(Finding::NoUri);
        }
        _ => {}
    }

    let uris = item.uris();
    if item.kind() == ItemKind::Login && uris.is_empty() {
        findings.push(Finding::NoUri);
    }
    for uri in uris {
        if uri.uri.trim().to_lowercase().starts_with("http://") {
            findings.push(Finding::InsecureUri {
                uri: uri.uri.clone(),
            });
        }
    }

    if item.revision_date > 0 && now > item.revision_date {
        let days = (now - item.revision_date) / 86_400;
        if days >= thresholds.stale_days {
            findings.push(Finding::Stale { days });
        }
    }
}

/// The strength bucket for a password, as the detail pane shows it.
pub fn password_strength(password: &str) -> (u32, Strength) {
    let bits = estimate_entropy(password);
    (bits, Strength::from_bits(f64::from(bits)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
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
}
