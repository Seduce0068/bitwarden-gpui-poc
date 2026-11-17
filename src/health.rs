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
use crate::totp::is_valid_secret;

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
    /// A login carries no usable TOTP secret.
    NoTotp,
    /// The item has no URI at all, so autofill can't find it.
    NoUri,
    /// A card item has no card number.
    NoCardNumber,
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
            Self::NoCardNumber => "カード番号が空".to_string(),
            Self::Unnamed => "名前が空".to_string(),
        }
    }

    /// How severe the finding is, for sorting and colouring.
    pub const fn severity(&self) -> Severity {
        match self {
            Self::ReusedPassword { .. } | Self::InsecureUri { .. } => Severity::High,
            Self::WeakPassword { .. } | Self::Stale { .. } | Self::NoCardNumber => Severity::Medium,
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
    /// How many logins carry a usable TOTP secret.
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

    /// A plain-text rendering of the report (currently used by tests).
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
    // A long random value that merely begins with "password" is not a
    // dictionary password. Cap the prefix match so those values keep their
    // real (high) entropy estimate; the same cap already exists for qwerty.
    const PASSWORD_PREFIX_LIMIT: usize = 16;
    COMMON.contains(&lower)
        || (lower.starts_with("password") && lower.len() <= PASSWORD_PREFIX_LIMIT)
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
            if item.totp_secret().is_some_and(is_valid_secret) {
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
            // An empty password has zero entropy, so any positive threshold
            // flags it. It is deliberately excluded from the reuse map in
            // `audit`, so the lookup below simply finds nothing for it.
            let bits = estimate_entropy(password);
            if bits < thresholds.weak_bits {
                findings.push(Finding::WeakPassword { bits });
            }
            if let Some(ids) = passwords.get(password.as_str()) {
                if ids.len() > 1 {
                    findings.push(Finding::ReusedPassword { count: ids.len() });
                }
            }
            if !is_valid_secret(totp) {
                findings.push(Finding::NoTotp);
            }
        }
        crate::model::ItemData::Card(card) if card.number.trim().is_empty() => {
            findings.push(Finding::NoCardNumber);
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
#[path = "health_tests.rs"]
mod tests;
