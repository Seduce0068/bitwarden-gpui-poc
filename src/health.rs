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

use crate::generator::{entropy_bits, Strength, DIGITS, LOWERCASE, SYMBOLS, UPPERCASE};
use crate::model::{ItemKind, Vault, VaultItem};
use crate::totp::is_valid_secret;
use crate::vault_sync::is_undecryptable_password;

/// A single finding.
///
/// Derived `Serialize` is intentional: any serialized form must be safe to
/// persist or log, so `InsecureUri` stores an already-masked URI (see below).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
        /// The offending URI reduced to scheme and host by `mask_uri` at the
        /// moment the finding is created. Never store the raw URI here: this
        /// field is exposed by `Debug` and by serialization.
        uri: String,
    },
    /// A login carries no usable TOTP secret.
    NoTotp,
    /// The encrypted password could not be decrypted, so no strength or reuse
    /// check was possible. This is informational, not a weak password.
    PasswordUninspectable,
    /// The item has no URI at all, so autofill can't find it.
    NoUri,
    /// The URI field could not be decrypted, so no URI check was possible.
    UriUninspectable,
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
            Self::PasswordUninspectable => {
                "パスワード検査対象外（復号できませんでした）".to_string()
            }
            Self::NoUri => "URI 未設定".to_string(),
            Self::UriUninspectable => "URI 検査対象外（復号できませんでした）".to_string(),
            Self::NoCardNumber => "カード番号が空".to_string(),
            Self::Unnamed => "名前が空".to_string(),
        }
    }

    /// How severe the finding is, for sorting and colouring.
    pub const fn severity(&self) -> Severity {
        match self {
            Self::ReusedPassword { .. } | Self::InsecureUri { .. } => Severity::High,
            Self::WeakPassword { .. } | Self::Stale { .. } | Self::NoCardNumber => Severity::Medium,
            Self::NoTotp
            | Self::PasswordUninspectable
            | Self::NoUri
            | Self::UriUninspectable
            | Self::Unnamed => Severity::Low,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
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

    /// How many logins had a password that could not be decrypted, so no
    /// strength or reuse check could run on them.
    ///
    /// Derived from the per-item findings instead of stored as a new `Report`
    /// field: `Report` literals also live in the UI module, so adding a field
    /// would break code outside this change's write scope.
    pub fn password_uninspectable(&self) -> usize {
        self.items
            .iter()
            .filter(|item| {
                item.findings
                    .iter()
                    .any(|finding| matches!(finding, Finding::PasswordUninspectable))
            })
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
        let mut out = if self.items.is_empty() {
            format!("{} 件を検査: 問題は見つかりませんでした", self.examined)
        } else {
            format!(
                "{} 件を検査: {} 件に {} 個の問題（高 {} / 中 {} / 低 {}）",
                self.examined,
                self.affected(),
                self.total_findings(),
                self.count_of(Severity::High),
                self.count_of(Severity::Medium),
                self.count_of(Severity::Low)
            )
        };
        out.push_str(&format!(
            " / パスワード検査対象外: {} 件",
            self.password_uninspectable()
        ));
        out
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
        out.push_str(&format!(
            "パスワード検査対象外: {} 件\n",
            self.password_uninspectable()
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
/// The model: the character pool the password actually uses (the ASCII class
/// sizes come from the generator's own constants), times its length, with a
/// penalty for the patterns that make a password far weaker than its pool size
/// suggests (a single repeated character, an all-digit string, a common word,
/// or a short trailing-digit suffix on a word).
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
    // Use the generator's class sizes so the audit and the strength meter
    // agree with what the generator can actually draw. The wide pool is an
    // audit-only allowance: the generator emits ASCII only, but vault passwords
    // may contain non-ASCII characters.
    const WIDE_POOL: usize = 100;
    if has_lower {
        pool += LOWERCASE.len();
    }
    if has_upper {
        pool += UPPERCASE.len();
    }
    if has_digit {
        pool += DIGITS.len();
    }
    if has_symbol {
        pool += SYMBOLS.len();
    }
    if has_wide {
        pool += WIDE_POOL;
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

/// The longest `"password"`-prefixed value still treated as a dictionary guess
/// by `is_common_password`.
///
/// The cap is chosen relative to `Thresholds::weak_bits` (50 by default).
/// Capped values take the dictionary estimate from `entropy_bits(2_000, 1)`
/// (~11 bit, ~12 with an uppercase letter), well below 50, so short guesses
/// such as `password123` are flagged `WeakPassword`. Without the cap their raw
/// pool x length score would already clear the threshold (`password123` scores
/// ~57 bit), letting them slip through. Longer values keep their real estimate,
/// so a long high-entropy value that merely starts with "password" is not
/// mislabelled weak. This is also the boundary asserted by the tests in
/// `health_tests.rs`.
pub(crate) const PASSWORD_PREFIX_LIMIT: usize = 16;

/// The equivalent cap for the `"qwerty"` prefix; see [`PASSWORD_PREFIX_LIMIT`].
const QWERTY_PREFIX_LIMIT: usize = 12;

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
    // A long random value that merely begins with "password" (or "qwerty")
    // is not a dictionary password. Cap the prefix matches so those values
    // keep their real (high) entropy estimate; see PASSWORD_PREFIX_LIMIT for
    // how the cap relates to the weak-entropy threshold.
    COMMON.contains(&lower)
        || (lower.starts_with("password") && lower.len() <= PASSWORD_PREFIX_LIMIT)
        || (lower.starts_with("qwerty") && lower.len() <= QWERTY_PREFIX_LIMIT)
}

/// Audit `vault` with `thresholds` at `now` (Unix seconds).
///
/// Reuse is computed across all logins in the vault, including ones that are
/// filtered out of the current view, so the report is stable.
pub fn audit(vault: &Vault, thresholds: Thresholds, now: i64) -> Report {
    let mut passwords: HashMap<&str, Vec<&str>> = HashMap::new();
    for item in &vault.items {
        if let Some(password) = item.password() {
            // Empty passwords have no guessable value, and undecryptable ones
            // are excluded from every password check (including reuse).
            if !password.is_empty() && !is_undecryptable_password(password) {
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
            if is_undecryptable_password(password) {
                // The ciphertext could not be opened, so there is nothing to
                // score. Report the exclusion itself instead of a misleading
                // "weak password" or a fake reuse match.
                findings.push(Finding::PasswordUninspectable);
            } else {
                // An empty password has zero entropy, so any positive
                // threshold flags it. It is deliberately excluded from the
                // reuse map in `audit`, so the lookup finds nothing for it.
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
    } else if uris
        .iter()
        .any(|uri| crate::vault_sync::is_undecryptable_uri(&uri.uri))
    {
        findings.push(Finding::UriUninspectable);
    }
    for uri in uris {
        // Invisible whitespace, control and format characters (e.g. zero-width
        // space) can hide an insecure scheme anywhere in the string, so strip
        // them from the value used both for detection and for the masked
        // finding. The raw URI is never stored.
        let visible: String = uri
            .uri
            .chars()
            .filter(|ch| {
                !ch.is_whitespace()
                    && !ch.is_control()
                    && !crate::auth::has_format_character(&ch.to_string())
            })
            .collect();
        if visible.to_lowercase().starts_with("http://") {
            findings.push(Finding::InsecureUri {
                uri: crate::model::mask_uri(&visible),
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
