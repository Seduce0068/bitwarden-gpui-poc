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

use crate::generator::{entropy_bits, Strength, DIGITS, LOWERCASE, SYMBOLS, UPPERCASE, WEAK_BITS};
use crate::model::{FingerprintVerify, ItemKind, Vault, VaultItem};
use crate::totp::is_valid_secret;
// Layering note: `health` depends on `vault_sync` (the openwarden bridge)
// although the bridge is conceptually a lower, import-side layer. This
// reverse dependency is temporarily allowed: the "could not decrypt" status
// markers are defined next to the code that writes them so there is a single
// source of truth, and the audit must recognize them to avoid mislabelling a
// bad ciphertext as a weak password or a missing TOTP. Moving them to `model`
// would change the model's public contract outside this change's scope;
// duplicating the literals here would let the two views drift apart.
use crate::vault_sync::{is_undecryptable_password, is_undecryptable_totp};
use crate::words::WORDS;

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
    /// A TOTP field exists but its ciphertext could not be decrypted, so the
    /// login is known to be 2FA-enabled but no code can be generated.
    TotpUninspectable,
    /// The encrypted password could not be decrypted, so no strength or reuse
    /// check was possible. This is informational, not a weak password.
    PasswordUninspectable,
    /// The item has no URI at all, so autofill can't find it.
    NoUri,
    /// The URI field could not be decrypted, so no URI check was possible.
    UriUninspectable,
    /// A card item has no card number.
    NoCardNumber,
    /// A stored SSH fingerprint does not match the one recomputed from the
    /// public key line. `computed` is a SHA256 fingerprint, never a secret.
    SshFingerprintMismatch {
        /// The fingerprint recomputed from the public key line.
        computed: String,
    },
    /// The SSH public key line could not be parsed, so the stored fingerprint
    /// could not be checked.
    SshFingerprintInvalid,
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
            // `mask_uri` is idempotent, so this also protects findings built
            // directly with a raw URI (e.g. in tests or by future callers).
            Self::InsecureUri { uri } => {
                format!("http の URI（{}）", crate::model::mask_uri(uri))
            }
            Self::NoTotp => "TOTP 未設定".to_string(),
            Self::TotpUninspectable => "TOTP 検査対象外（復号できませんでした）".to_string(),
            Self::PasswordUninspectable => {
                "パスワード検査対象外（復号できませんでした）".to_string()
            }
            Self::NoUri => "URI 未設定".to_string(),
            Self::UriUninspectable => "URI 検査対象外（復号できませんでした）".to_string(),
            Self::NoCardNumber => "カード番号が空".to_string(),
            Self::SshFingerprintMismatch { computed } => {
                format!("SSH フィンガープリントが一致しません（計算値: {computed}）")
            }
            Self::SshFingerprintInvalid => {
                "SSH 公開鍵を解析できないためフィンガープリントを検証できません".to_string()
            }
            Self::Unnamed => "名前が空".to_string(),
        }
    }

    /// How severe the finding is, for sorting and colouring.
    pub const fn severity(&self) -> Severity {
        match self {
            Self::ReusedPassword { .. }
            | Self::InsecureUri { .. }
            | Self::SshFingerprintMismatch { .. } => Severity::High,
            Self::WeakPassword { .. } | Self::Stale { .. } | Self::NoCardNumber => Severity::Medium,
            Self::NoTotp
            | Self::TotpUninspectable
            | Self::PasswordUninspectable
            | Self::NoUri
            | Self::UriUninspectable
            | Self::SshFingerprintInvalid
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
            // Same boundary as `Strength::from_bits`, so the generator's
            // "Weak" label and this audit's threshold cannot disagree.
            weak_bits: WEAK_BITS,
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
    // A generated passphrase has a word-list entropy, not a character-pool
    // entropy. Score it with the generator's model so the audit and the
    // generator's strength meter report the same number.
    if let Some(bits) = passphrase_estimate(password) {
        return bits;
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
    // A word with a short trailing digit suffix can be brute-forced by trying
    // every suffix; only digits are modelled (`strip_trailing_digits`).
    if let Some(stripped) = strip_trailing_digits(&lower) {
        if !common && stripped.len() >= 3 && stripped.chars().all(|c| c.is_ascii_lowercase()) {
            let suffix = lower.len() - stripped.len();
            adjusted = adjusted.min(entropy_bits(26, stripped.len()) + entropy_bits(10, suffix));
        }
    }
    adjusted.round().clamp(0.0, 1000.0) as u32
}

/// Score a generated passphrase with the generator's word-list model.
///
/// Recognizes only the exact shape [`PassphraseSettings`](crate::generator::PassphraseSettings)
/// can emit: at least two words from the shared list, joined by one repeated
/// non-alphanumeric separator **or by no separator at all**, each optionally
/// capitalized, with an optional single trailing digit. Both paths use the
/// same [`word_capitalization`] rule: a word is either all lowercase or has
/// just its first ASCII letter capitalized. All-caps and mid-word capitals
/// are rejected even when a separator is present. Anything else falls back to
/// the character-pool estimate in [`estimate_entropy`].
///
/// The empty separator matters: the word list is prefix-free, so the generator
/// happily emits `ableabove` for a two-word passphrase. Scoring that as a plain
/// nine-letter lowercase string would report ~42 bit from the character pool,
/// while the generator knows it is only a two-word draw (~22 bit). The audit
/// must not overestimate such a passphrase.
fn passphrase_estimate(value: &str) -> Option<u32> {
    let (body, with_number) = match value.as_bytes().last() {
        Some(byte) if byte.is_ascii_digit() => (&value[..value.len() - 1], true),
        _ => (value, false),
    };
    let (words, capitalized) = match body.chars().find(|character| !character.is_alphanumeric()) {
        Some(separator_char) => {
            let separator = separator_char.to_string();
            let parts: Vec<&str> = body.split(separator.as_str()).collect();
            // Exactly one repeated separator, not a mixture of different ones.
            if parts.join(separator.as_str()) != body {
                return None;
            }
            let mut capitalized = false;
            let mut parsed = Vec::with_capacity(parts.len());
            for word in parts {
                let lower = word.to_lowercase();
                if !WORDS.contains(&lower.as_str()) {
                    return None;
                }
                // Use the same contract as the separator-free path: only an
                // all-lowercase word or one with just its first ASCII letter
                // capitalized can be a generator output.
                capitalized |= word_capitalization(word, &lower)?;
                parsed.push(word);
            }
            (parsed, capitalized)
        }
        // No separator at all is a valid `PassphraseSettings::separator`.
        None => words_without_separator(body)?,
    };
    if words.len() < 2 {
        return None;
    }
    let mut bits = entropy_bits(WORDS.len(), words.len());
    if capitalized {
        bits += words.len() as f64;
    }
    if with_number {
        bits += (10.0f64).log2();
    }
    Some(bits.round().clamp(0.0, 1000.0) as u32)
}

/// Greedily split a separator-free passphrase into shared-list words.
///
/// The list is prefix-free, so the first matching word at each step is the
/// only possible parse. Only the two spellings the generator emits are
/// accepted: an all-lowercase word, or a word with just its first ASCII letter
/// capitalized. `None` means the value is not a generated passphrase and the
/// caller falls back to the character-pool estimate.
fn words_without_separator(body: &str) -> Option<(Vec<&str>, bool)> {
    let mut words = Vec::new();
    let mut rest = body;
    let mut capitalized = false;
    while !rest.is_empty() {
        // `to_ascii_lowercase` preserves byte offsets, so slicing `rest` with
        // the matched word's length is always a valid char boundary.
        let folded = rest.to_ascii_lowercase();
        let word: &str = WORDS
            .iter()
            .find(|candidate| folded.starts_with(**candidate))?;
        // The folded prefix matched, but only the two spellings the generator
        // emits are accepted; see `word_capitalization`.
        capitalized |= word_capitalization(rest.get(..word.len())?, word)?;
        rest = rest.get(word.len()..)?;
        words.push(word);
    }
    (words.len() >= 2).then_some((words, capitalized))
}

/// Validate one word's casing against the generator's two allowed spellings.
///
/// `Some(true)` means the word had just its first ASCII letter capitalized;
/// `Some(false)` means it was entirely lowercase. An all-caps word, a capital
/// inside the word, a non-ASCII capital or a mismatched tail is rejected with
/// `None`, so the caller falls back to the character-pool estimate instead of
/// crediting a generated-passphrase score. Shared by the separator and
/// separator-free recognizers so both paths enforce the same contract.
fn word_capitalization(word: &str, lower: &str) -> Option<bool> {
    if word == lower {
        return Some(false);
    }
    let first = word.chars().next()?;
    if first.is_ascii_uppercase()
        && word.get(first.len_utf8()..)? == lower.get(1..)?
        && !lower.is_empty()
    {
        return Some(true);
    }
    None
}

fn strip_trailing_digits(value: &str) -> Option<&str> {
    let trimmed = value.trim_end_matches(|c: char| c.is_ascii_digit());
    (trimmed.len() != value.len() && !trimmed.is_empty()).then_some(trimmed)
}

/// The longest `"password"`-prefixed value still treated as a dictionary guess
/// by `is_common_password`.
///
/// The cap is chosen relative to `Thresholds::weak_bits` ([`WEAK_BITS`] = 40
/// by default). Capped values take the dictionary estimate from
/// `entropy_bits(2_000, 1)` (~11 bit, ~12 with an uppercase letter), well below
/// 40, so short guesses
/// such as `password123` are flagged `WeakPassword`. Without the cap their raw
/// pool x length score would already clear the threshold (`password123` scores
/// ~57 bit), letting them slip through. Longer values keep their real estimate,
/// so a long high-entropy value that merely starts with "password" is not
/// mislabelled weak. This is also the boundary asserted by the tests in
/// `health_tests.rs`.
pub(crate) const PASSWORD_PREFIX_LIMIT: usize = 16;

/// The equivalent cap for the `"qwerty"` prefix; see [`PASSWORD_PREFIX_LIMIT`].
const QWERTY_PREFIX_LIMIT: usize = 12;

/// Exact membership in the small list of breach-corpus passwords.
///
/// Split out from [`is_common_password`] so the exact-match branch can be
/// tested independently of the `"password"`/`"qwerty"` prefix caps: an entry
/// such as `correcthorsebatterystaple` relies on this branch alone, while an
/// unlisted short `password...` value relies on the prefix rule alone.
fn is_exact_common_password(lower: &str) -> bool {
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
}

/// Whether a lowercase password looks like a known dictionary guess.
///
/// Two independent branches: exact membership in the common list, or a short
/// value capped to the `"password"` / `"qwerty"` prefix rule. Keeping them
/// separate lets a test pin each one without the other masking a regression.
fn is_common_password(lower: &str) -> bool {
    // A long random value that merely begins with "password" (or "qwerty")
    // is not a dictionary password. Cap the prefix matches so those values
    // keep their real (high) entropy estimate; see PASSWORD_PREFIX_LIMIT for
    // how the cap relates to the weak-entropy threshold.
    // Count Unicode characters, not UTF-8 bytes: a multibyte suffix makes the
    // byte length exceed the cap even when the value is only a short
    // dictionary guess plus a few letters, which must still be flagged weak.
    is_exact_common_password(lower)
        || (lower.starts_with("password") && lower.chars().count() <= PASSWORD_PREFIX_LIMIT)
        || (lower.starts_with("qwerty") && lower.chars().count() <= QWERTY_PREFIX_LIMIT)
}

/// Whether `item` has a TOTP field that can actually produce a code.
///
/// This is the single source of truth for the TOTP badge in the list, the
/// `Report::with_totp` counter and the per-item `NoTotp` finding, so those
/// three views cannot drift apart. A field that exists but could not be
/// decrypted is not usable (see [`has_totp_field`]).
pub fn has_usable_totp(item: &VaultItem) -> bool {
    item.totp_secret()
        .is_some_and(|secret| !is_undecryptable_totp(secret) && is_valid_secret(secret))
}

/// Whether `item` carries a TOTP field at all, including one that could not be
/// decrypted.
///
/// A decryption failure must not be collapsed into "no TOTP": the login is
/// known to be 2FA-enabled, only the secret is uninspectable.
pub fn has_totp_field(item: &VaultItem) -> bool {
    item.totp_secret().is_some_and(|secret| !secret.is_empty())
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
            if has_usable_totp(item) {
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
            if is_undecryptable_totp(totp) {
                // The field exists but its ciphertext could not be opened.
                // Preserve the "2FA is configured" information instead of
                // misreporting it as an unset TOTP.
                findings.push(Finding::TotpUninspectable);
            } else if !is_valid_secret(totp) {
                findings.push(Finding::NoTotp);
            }
        }
        crate::model::ItemData::Card(card) if card.number.trim().is_empty() => {
            findings.push(Finding::NoCardNumber);
        }
        crate::model::ItemData::SshKey(key) => match key.verify_fingerprint() {
            FingerprintVerify::Match => {}
            FingerprintVerify::Mismatch { computed } => {
                findings.push(Finding::SshFingerprintMismatch { computed });
            }
            FingerprintVerify::InvalidPublicKey => {
                findings.push(Finding::SshFingerprintInvalid);
            }
        },
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
        // finding. Backslashes are treated as slashes the way browsers do, so
        // `http:\host` cannot evade the scheme check. The raw URI is never
        // stored: both the check and `mask_uri` use this normalized value.
        let visible: String = uri
            .uri
            .chars()
            .filter(|ch| {
                !ch.is_whitespace()
                    && !ch.is_control()
                    && !crate::limits::has_format_character(&ch.to_string())
            })
            .map(|ch| if ch == '\\' { '/' } else { ch })
            .collect();
        if visible.to_lowercase().starts_with("http://") {
            findings.push(Finding::InsecureUri {
                uri: crate::model::mask_uri(&visible),
            });
        }
    }

    if item.revision_date > crate::model::UNKNOWN_REVISION && now > item.revision_date {
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
