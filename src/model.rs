//! Vault data model: item kinds, folders, filtering, search and URI matching.
//!
//! This mirrors the shape of a Bitwarden personal vault without any network
//! access, so the UI (and the tests) can work on real data structures while
//! login/sync stay out of scope.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Unicode normalization for vault-name comparison.
///
/// Reuses the mature `unicode-normalization` crate (unicode-rs, MIT OR
/// Apache-2.0) instead of a hand-maintained decomposition table, so every
/// Unicode code point is covered. NFKD is used rather than NFKC because
/// canonically or compatibility-equivalent strings share the same NFKD, so
/// comparing keys absorbs NFC/NFD and full-/half-width differences.
mod unicode_normalize {
    use unicode_normalization::UnicodeNormalization;

    pub(crate) fn nfkd(input: &str) -> String {
        input.chars().nfkd().collect()
    }

    /// Whether a code point is a Unicode mark without standalone identity.
    ///
    /// The normalization crate exposes the `General_Category=Mark` set (Mn,
    /// Mc and Me) through its public `char` module, so the blank-name rule can
    /// reuse the same Unicode table as NFKD instead of a hand-maintained range
    /// list. A name made only of these code points has no visible identity of
    /// its own and must not be treated as a duplicate of another such name.
    pub(crate) fn is_mark(ch: char) -> bool {
        unicode_normalization::char::is_combining_mark(ch)
    }

    /// One NFKD + lowercase pass with a small set of extra case mappings.
    ///
    /// This is **not** a complete Unicode full case fold. `str::to_lowercase`
    /// is Unicode lowercasing, which is not the same operation as case folding,
    /// and `unicode-normalization` supplies NFKD only. The explicit mapping
    /// below covers the well-known cases that would otherwise differ (`ß`/`ẞ`
    /// vs `ss`, final sigma `ς` vs `σ`, and long s `ſ` vs `s`); every other
    /// character falls back to the standard library's lowercase mapping.
    /// Other full-fold equivalences are therefore *not* guaranteed to compare
    /// equal here. Callers must not rely on a stronger contract than the
    /// listed cases.
    fn fold_once(input: &str) -> String {
        let mut out = String::new();
        for character in nfkd(input).chars() {
            // Invisible format characters carry no visible identity. Keeping
            // them in the key made a search for the plain spelling miss a name
            // that contained one, and split otherwise identical duplicates.
            if crate::limits::is_format_character(character) {
                continue;
            }
            match character {
                'ß' | 'ẞ' => out.push_str("ss"),
                'ς' => out.push('σ'),
                'ſ' => out.push('s'),
                other => out.extend(other.to_lowercase()),
            }
        }
        out
    }

    /// NFKD key with the documented extra case mappings, shared by search,
    /// duplicate-name detection and sorting.
    ///
    /// Unicode `Cf` (format) characters are dropped from the key. They render
    /// nothing, so a name such as `Git\u{200b}Hub` must compare equal to
    /// `GitHub`: keeping the invisible code point made a plain search query
    /// miss an otherwise identical name. Dropping it here keeps search,
    /// duplicate detection and sorting on the same normalized value.
    ///
    /// Lowercasing a decomposed string can surface a code point that NFKD
    /// would decompose again (for example U+01C4 LATIN CAPITAL LETTER DZ WITH
    /// CARON decomposes to `D` + U+017E; lowercasing leaves U+017E intact until
    /// the next NFKD pass splits it into `z` + U+030C), so a single pass is not
    /// guaranteed to be a fixed point. U+0345 COMBINING GREEK YPOGEGRAMMENI is
    /// *not* such a case: `char::to_lowercase` leaves it unchanged and NFKD
    /// keeps it as a mark (only case folding maps it to U+03B9). Repeating the
    /// pass until the text stops changing makes
    /// `comparison_key(comparison_key(x)) == comparison_key(x)` for every
    /// input, which is what the search and sort paths rely on when they feed a
    /// normalized needle back through this function. The loop bound is
    /// defensive: two passes suffice for the mappings above.
    pub(crate) fn comparison_key(input: &str) -> String {
        let mut key = fold_once(input);
        for _ in 0..3 {
            let next = fold_once(&key);
            if next == key {
                return key;
            }
            key = next;
        }
        key
    }
}
pub(crate) use unicode_normalize::comparison_key;

/// Sentinel for a missing or unparsable revision date.
///
/// Kept as a named constant so callers outside this module do not depend on
/// the literal `0`; the value's definition is gathered here, while callers
/// that compare or store it still assume `i64` (a future Option-based
/// representation would need those sites updated too). Revision 0 itself
/// (1970-01-01T00:00:00Z) is indistinguishable from this sentinel in v1.
pub const UNKNOWN_REVISION: i64 = 0;

/// Reduce a URI to scheme, host and port so embedded credentials or tokens in
/// the path/query are never shown in the UI or copied into reports.
///
/// An explicitly non-default port is kept (for example
/// `https://example.com:8443`); `url::Url::port()` drops a scheme-default port,
/// so `https://example.com:443` renders as `https://example.com`. A host-less
/// URL keeps only its scheme.
///
/// Falls back to `"(不正な URI)"` when the value cannot be parsed.
pub fn mask_uri(value: &str) -> String {
    // Status markers use a leading NUL so they cannot collide with real URIs.
    // The URL parser drops that control character, which would render a marker
    // as a plausible-looking scheme; show the status instead.
    if value.starts_with('\0') {
        return "（復号できませんでした）".to_string();
    }
    // Already-masked values and status markers must survive another pass
    // unchanged: findings may be constructed with a raw URI or with the
    // output of this function, and both paths share `Finding::message()`.
    if value == "（復号できませんでした）" || value == "(不正な URI)" {
        return value.to_string();
    }
    match url::Url::parse(value) {
        Ok(url) => {
            let scheme = url.scheme();
            match url.host_str() {
                Some(host) => match url.port() {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                },
                None => format!("{scheme}://"),
            }
        }
        Err(_) => "(不正な URI)".to_string(),
    }
}

/// The kind of a vault item, matching Bitwarden's `type` numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// `type: 1`
    Login,
    /// `type: 2`
    SecureNote,
    /// `type: 3`
    Card,
    /// `type: 4`
    Identity,
    /// `type: 5` (SSH key)
    SshKey,
}

impl ItemKind {
    /// The wire number.
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::SecureNote => 2,
            Self::Card => 3,
            Self::Identity => 4,
            Self::SshKey => 5,
        }
    }

    /// From the wire number; `None` for an unknown one.
    pub const fn from_wire(n: u8) -> Option<Self> {
        Some(match n {
            1 => Self::Login,
            2 => Self::SecureNote,
            3 => Self::Card,
            4 => Self::Identity,
            5 => Self::SshKey,
            _ => return None,
        })
    }

    /// Short label for the UI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Login => "ログイン",
            Self::SecureNote => "メモ",
            Self::Card => "カード",
            Self::Identity => "ID",
            Self::SshKey => "SSH鍵",
        }
    }
}

/// One login URI and its Bitwarden match type (`None` = default: domain).
///
/// `Debug` masks the URI to scheme + host.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginUri {
    /// The URI as stored.
    pub uri: String,
    /// 0 = domain, 1 = host, 2 = starts with, 3 = exact, 4 = regex, 5 = never.
    pub match_type: Option<u8>,
}

impl LoginUri {
    /// A URI with no explicit match type (Bitwarden's default).
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            match_type: None,
        }
    }

    /// The match type as [`openwarden::UriMatch`], if it is a valid number.
    pub fn match_enum(&self) -> Option<openwarden::UriMatch> {
        self.match_type.and_then(openwarden::UriMatch::from_wire)
    }

    /// Whether this URI matches `page`, using Bitwarden's rules.
    pub fn matches(&self, page: &str, opts: &openwarden::MatchOptions) -> bool {
        openwarden::uri_matches(&self.uri, self.match_enum(), page, opts)
    }
}

/// A text secret held in a [`Zeroizing<String>`] buffer.
///
/// The newtype exists only for construction ergonomics: `zeroize` cannot
/// implement `From<&str>` for `Zeroizing<String>` itself, so literal fixtures
/// and mock data would stop compiling if the field were the bare wrapper. The
/// buffer is still a `Zeroizing<String>`, wiped on drop and on replacement,
/// and the wire format stays a plain string via `zeroizing_text_serde`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ZeroizingText(Zeroizing<String>);

impl ZeroizingText {
    /// Wrap `value`, taking ownership of its buffer.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The plain text for search, rendering and serialization.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for ZeroizingText {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ZeroizingText {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl core::ops::Deref for ZeroizingText {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl AsRef<str> for ZeroizingText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl core::fmt::Display for ZeroizingText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Debug for ZeroizingText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Card details.
///
/// `Debug` masks the cardholder name, number and security code. The brand and
/// expiry stay visible as harmless metadata. The number and code are wiped on
/// drop; their serde shape is still a plain string.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardData {
    /// Name on the card.
    pub cardholder_name: String,
    /// Brand (Visa, Mastercard, …).
    pub brand: String,
    /// Card number.
    #[serde(with = "zeroizing_text_serde")]
    pub number: ZeroizingText,
    /// Expiry month, 1-12.
    pub exp_month: String,
    /// Expiry year.
    pub exp_year: String,
    /// Security code.
    #[serde(with = "zeroizing_text_serde")]
    pub code: ZeroizingText,
}

/// Identity details.
///
/// `Debug` masks every personal field, including the company name.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityData {
    /// Given name.
    pub first_name: String,
    /// Family name.
    pub last_name: String,
    /// Email address.
    pub email: String,
    /// Phone number.
    pub phone: String,
    /// Street address.
    pub address: String,
    /// Company name.
    pub company: String,
}

/// SSH key details.
///
/// `Debug` masks the private key, which is also held in a [`ZeroizingText`]
/// buffer and wiped on drop. Its serde shape stays a plain string so existing
/// saves and fixtures keep loading unchanged.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyData {
    /// Public key line.
    pub public_key: String,
    /// Private key. Wiped on drop and replacement; serialized as a plain string.
    #[serde(with = "zeroizing_text_serde")]
    pub private_key: ZeroizingText,
    /// Key fingerprint.
    pub fingerprint: String,
}

/// Result of comparing a stored SSH fingerprint with the one recomputed from
/// the public key line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FingerprintVerify {
    /// The stored fingerprint matches the public key.
    Match,
    /// The stored fingerprint differs from the public key.
    Mismatch {
        /// The fingerprint recomputed from the public key line.
        computed: String,
    },
    /// The public key line could not be parsed, so no comparison was possible.
    InvalidPublicKey,
}

impl SshKeyData {
    /// Compare the stored fingerprint with the one recomputed from
    /// [`Self::public_key`].
    ///
    /// OpenSSH fingerprints the decoded key blob (the second whitespace-
    /// separated field), so a changed key or a stale stored value is detected.
    ///
    /// Current contract: only the public key's *parsability* has a third
    /// outcome ([`FingerprintVerify::InvalidPublicKey`]). An unset fingerprint
    /// or one in a different format (for example an MD5-style fingerprint) is
    /// simply a different string and is reported as
    /// [`FingerprintVerify::Mismatch`] with the computed SHA256 value, not as
    /// "unset" or "unverifiable". There is deliberately no separate variant:
    /// adding one would change the audit's public `Finding` set outside this
    /// change's scope. Callers that need to distinguish the two can compare
    /// the stored `fingerprint` field with the computed value themselves.
    pub fn verify_fingerprint(&self) -> FingerprintVerify {
        let Some(computed) = ssh_fingerprint::sha256_fingerprint(&self.public_key) else {
            return FingerprintVerify::InvalidPublicKey;
        };
        if self.fingerprint.trim() == computed {
            FingerprintVerify::Match
        } else {
            FingerprintVerify::Mismatch { computed }
        }
    }

    /// Convenience wrapper: whether the stored fingerprint is valid.
    ///
    /// An unparsable public key is not a match, so callers that must tell
    /// "invalid" from "mismatch" should use [`Self::verify_fingerprint`].
    pub fn fingerprint_matches(&self) -> bool {
        matches!(self.verify_fingerprint(), FingerprintVerify::Match)
    }
}

/// Recompute OpenSSH-style SHA256 fingerprints.
///
/// SHA-256 uses the existing `sha2` dependency. `base64` is only a transitive
/// dependency in `Cargo.lock`; a crate cannot `use` a transitive dependency,
/// and adding it directly would violate the no-new-dependency constraint for
/// this change, so the small standard base64 codec lives here. The algorithm
/// mirrors `ssh-keygen -lf`: hash the decoded key blob, base64-encode the
/// digest, strip padding, and prefix `SHA256:`.
mod ssh_fingerprint {
    use sha2::{Digest, Sha256};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Decode standard base64 (with or without `=` padding).
    pub(crate) fn decode(input: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() / 4 * 3);
        let mut acc = 0u32;
        let mut leftover_bits = 0u32;
        let mut padding_count = 0usize;
        for &byte in input {
            if byte == b'=' {
                padding_count += 1;
                continue;
            }
            let saw_padding = padding_count > 0;
            if saw_padding {
                return None;
            }
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            };
            acc = (acc << 6) | u32::from(value);
            leftover_bits += 6;
            if leftover_bits >= 8 {
                leftover_bits -= 8;
                out.push((acc >> leftover_bits) as u8);
                acc &= (1u32 << leftover_bits) - 1;
            }
        }
        // Six leftover bits mean a single trailing base64 character, which is
        // not a valid encoding. An empty blob cannot be a key either. With
        // 2 or 4 leftover bits, the unused low bits of the accumulator must
        // be zero. A nonzero value means a non-canonical trailing character
        // (e.g. `AR==` instead of `AQ==`), so it must be rejected rather than
        // silently decoding to a different byte string.
        let unused_mask = (1u32 << leftover_bits) - 1;
        if leftover_bits >= 6 || out.is_empty() || acc & unused_mask != 0 {
            return None;
        }
        // Padding is optional, but when present its count must match the
        // encoded byte count: `AQ==` (1 byte) is canonical, `A===` has one
        // extra `=` and must be rejected. Without this check distinct inputs
        // would decode to one blob, defeating fingerprint comparison.
        let expected_padding = match out.len() % 3 {
            1 => 2,
            2 => 1,
            _ => 0,
        };
        if padding_count != 0 && padding_count != expected_padding {
            return None;
        }
        Some(out)
    }

    /// Encode with the standard base64 alphabet, keeping `=` padding.
    pub(crate) fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        let (chunks, remainder) = input.as_chunks::<3>();
        for chunk in chunks {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            push_quad(&mut out, n);
        }
        match remainder {
            [a] => {
                out.push(char::from(ALPHABET[((u32::from(*a) >> 2) & 0x3F) as usize]));
                out.push(char::from(ALPHABET[((u32::from(*a) << 4) & 0x3F) as usize]));
                out.push('=');
                out.push('=');
            }
            [a, b] => {
                let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
                out.push(char::from(ALPHABET[((n >> 18) & 0x3F) as usize]));
                out.push(char::from(ALPHABET[((n >> 12) & 0x3F) as usize]));
                out.push(char::from(ALPHABET[((n >> 6) & 0x3F) as usize]));
                out.push('=');
            }
            _ => {}
        }
        out
    }

    fn push_quad(out: &mut String, n: u32) {
        for shift in [18, 12, 6, 0] {
            out.push(char::from(ALPHABET[((n >> shift) & 0x3F) as usize]));
        }
    }

    /// Fingerprint of a line like `ssh-ed25519 <base64 blob> [comment]`.
    pub(crate) fn sha256_fingerprint(public_key_line: &str) -> Option<String> {
        let mut fields = public_key_line.split_whitespace();
        let _key_type = fields.next()?;
        let blob = decode(fields.next()?.as_bytes())?;
        let digest = Sha256::digest(&blob);
        let encoded = encode(digest.as_slice());
        Some(format!("SHA256:{}", encoded.trim_end_matches('=')))
    }
}

impl core::fmt::Debug for LoginUri {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoginUri")
            .field("uri", &mask_uri(&self.uri))
            .field("match_type", &self.match_type)
            .finish()
    }
}

impl core::fmt::Debug for IdentityData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityData")
            .field("first_name", &"[redacted]")
            .field("last_name", &"[redacted]")
            .field("email", &"[redacted]")
            .field("phone", &"[redacted]")
            .field("address", &"[redacted]")
            .field("company", &"[redacted]")
            .finish()
    }
}

impl core::fmt::Debug for CardData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CardData")
            .field("cardholder_name", &"[redacted]")
            .field("brand", &self.brand)
            .field("number", &"[redacted]")
            .field("exp_month", &self.exp_month)
            .field("exp_year", &self.exp_year)
            .field("code", &"[redacted]")
            .finish()
    }
}

impl core::fmt::Debug for SshKeyData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SshKeyData")
            .field("public_key", &self.public_key)
            .field("private_key", &"[redacted]")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// serde adapter for secret fields stored as [`Zeroizing<String>`].
///
/// The `zeroize` crate's optional `serde` feature is not enabled here, so the
/// conversion is implemented locally: the wire format stays a plain string
/// and deserialization immediately wraps it so it is wiped on drop.
mod zeroizing_string_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

/// serde adapter for the card fields stored as [`ZeroizingText`].
///
/// Same wire contract as [`zeroizing_string_serde`]: a plain JSON string in,
/// a wiped buffer out. Keeping both adapters next to each other means a schema
/// change has to be made in one place to affect every secret field.
mod zeroizing_text_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::ZeroizingText;

    pub fn serialize<S>(value: &ZeroizingText, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ZeroizingText, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(ZeroizingText::from)
    }
}

/// Kind-specific payload.
///
/// `Debug` is implemented manually so login secrets are never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemData {
    /// A login.
    Login {
        /// Username or email.
        username: String,
        /// Password. The final buffer is wiped on drop or replacement.
        #[serde(with = "zeroizing_string_serde")]
        password: Zeroizing<String>,
        /// TOTP field (`otpauth://` URI, `steam://`, or bare base32).
        /// The final buffer is wiped on drop or replacement.
        #[serde(with = "zeroizing_string_serde")]
        totp: Zeroizing<String>,
        /// Site URIs.
        uris: Vec<LoginUri>,
    },
    /// A secure note.
    SecureNote {
        /// Note text. Held in a [`ZeroizingText`] buffer and wiped on drop;
        /// serde still sees a plain string and `Debug` still masks it.
        #[serde(with = "zeroizing_text_serde")]
        text: ZeroizingText,
    },
    /// A payment card.
    Card(CardData),
    /// An identity.
    Identity(IdentityData),
    /// An SSH key.
    SshKey(SshKeyData),
}

impl core::fmt::Debug for ItemData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Login {
                username: _,
                password: _,
                totp,
                uris,
            } => f
                .debug_struct("Login")
                .field("username", &"[redacted]")
                .field("password", &"[redacted]")
                .field("totp", &if totp.is_empty() { "" } else { "[redacted]" })
                .field("uris", uris)
                .finish(),
            Self::SecureNote { text: _ } => f
                .debug_struct("SecureNote")
                .field("text", &"[redacted]")
                .finish(),
            Self::Card(card) => f.debug_tuple("Card").field(card).finish(),
            Self::Identity(identity) => f.debug_tuple("Identity").field(identity).finish(),
            Self::SshKey(key) => f.debug_tuple("SshKey").field(key).finish(),
        }
    }
}

impl ItemData {
    /// The kind this payload belongs to.
    pub const fn kind(&self) -> ItemKind {
        match self {
            Self::Login { .. } => ItemKind::Login,
            Self::SecureNote { .. } => ItemKind::SecureNote,
            Self::Card(_) => ItemKind::Card,
            Self::Identity(_) => ItemKind::Identity,
            Self::SshKey(_) => ItemKind::SshKey,
        }
    }
}

/// One item in the vault.
///
/// `Debug` is implemented manually because free-form notes are a secret-bearing
/// field: they may hold recovery codes, PINs or other text that must never reach
/// a log line. Every other field stays visible, and the kind-specific payload
/// applies its own redaction rules (see [`ItemData`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    /// Stable id (a UUID in a real vault).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Owning folder id, if any.
    pub folder_id: Option<String>,
    /// Whether the item is starred.
    pub favorite: bool,
    /// Free-form notes. Wiped on drop; serde still sees a plain string.
    #[serde(with = "zeroizing_string_serde")]
    pub notes: Zeroizing<String>,
    /// Last modified, in Unix seconds.
    pub revision_date: i64,
    /// The kind-specific payload.
    pub data: ItemData,
}

impl core::fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultItem")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("folder_id", &self.folder_id)
            .field("favorite", &self.favorite)
            // A placeholder replaces the whole value: even a single character
            // of a recovery code must not survive in a diagnostic rendering.
            .field("notes", &"[redacted]")
            .field("revision_date", &self.revision_date)
            .field("data", &self.data)
            .finish()
    }
}

impl VaultItem {
    /// Build an item from the caller-supplied id, name and payload.
    pub fn new(id: impl Into<String>, name: impl Into<String>, data: ItemData) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            folder_id: None,
            favorite: false,
            notes: Zeroizing::new(String::new()),
            revision_date: UNKNOWN_REVISION,
            data,
        }
    }

    /// The item's kind.
    pub const fn kind(&self) -> ItemKind {
        self.data.kind()
    }

    /// The login payload, if this is a login.
    pub fn login(&self) -> Option<(&str, &str, &str, &[LoginUri])> {
        match &self.data {
            ItemData::Login {
                username,
                password,
                totp,
                uris,
            } => Some((username, password, totp, uris)),
            _ => None,
        }
    }

    /// The password, if this is a login.
    pub fn password(&self) -> Option<&str> {
        match &self.data {
            ItemData::Login { password, .. } => Some(password),
            _ => None,
        }
    }

    /// The TOTP field, if this is a login.
    pub fn totp_secret(&self) -> Option<&str> {
        match &self.data {
            ItemData::Login { totp, .. } => Some(totp),
            _ => None,
        }
    }

    /// The URIs, if this is a login.
    pub fn uris(&self) -> &[LoginUri] {
        match &self.data {
            ItemData::Login { uris, .. } => uris,
            _ => &[],
        }
    }

    /// Whether any of this item's URIs matches `page`.
    pub fn matches_page(&self, page: &str, opts: &openwarden::MatchOptions) -> bool {
        self.uris().iter().any(|uri| uri.matches(page, opts))
    }

    /// Every searchable text field, NFKD-normalized lazily by the caller.
    ///
    /// Known constraint: login URIs are included **verbatim**, so a token or
    /// password embedded in a URI query can still be found through search
    /// hints. [`mask_uri`] protects `Debug` and reports, not this index.
    fn haystacks(&self) -> Vec<std::borrow::Cow<'_, str>> {
        use std::borrow::Cow;
        let mut out: Vec<Cow<'_, str>> = vec![
            Cow::Borrowed(self.name.as_str()),
            Cow::Borrowed(self.notes.as_str()),
        ];
        match &self.data {
            // Password and TOTP secret are deliberately not searchable: a
            // leaked secret must not be recoverable through search hints.
            ItemData::Login { username, uris, .. } => {
                out.push(Cow::Borrowed(username));
                out.extend(uris.iter().map(|u| Cow::Borrowed(u.uri.as_str())));
            }
            ItemData::SecureNote { text } => out.push(Cow::Borrowed(text.as_str())),
            ItemData::Card(card) => {
                out.push(Cow::Borrowed(&card.cardholder_name));
                out.push(Cow::Borrowed(&card.brand));
                // Only the last four digits are searchable, regardless of how
                // the number is grouped. A full PAN must never be fished out
                // through search, so strip all non-digits first.
                let digits: String = card.number.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    out.push(Cow::Owned(digits[digits.len() - 4..].to_string()));
                }
            }
            ItemData::Identity(identity) => {
                out.push(Cow::Borrowed(&identity.first_name));
                out.push(Cow::Borrowed(&identity.last_name));
                out.push(Cow::Borrowed(&identity.email));
                out.push(Cow::Borrowed(&identity.phone));
                // The street address is a normal search field, like the other
                // identity metadata. `Debug` still redacts it (see the manual
                // `IdentityData` Debug implementation), so search hints do not
                // leak it into logs.
                out.push(Cow::Borrowed(&identity.address));
                out.push(Cow::Borrowed(&identity.company));
            }
            ItemData::SshKey(key) => {
                out.push(Cow::Borrowed(&key.public_key));
                out.push(Cow::Borrowed(&key.fingerprint));
            }
        }
        out
    }

    /// Whether any searchable field contains `needle`.
    ///
    /// `Vault::view` already trims and normalizes the query, but this is a
    /// public method and callers may pass raw user input, so `needle` is
    /// trimmed here too. `comparison_key` is idempotent, so the double
    /// normalization on the `view()` path cannot change the result. A blank
    /// needle matches every item; a non-blank needle that folds to an empty
    /// key (only invisible `Cf` characters) matches none, so an invisible
    /// paste cannot silently widen the result to the whole vault.
    pub fn matches_query(&self, needle: &str) -> bool {
        let trimmed = needle.trim();
        let key = comparison_key(trimmed);
        if key.is_empty() {
            // A genuinely blank or whitespace-only needle is contained in
            // every haystack, which is the documented "show everything"
            // behaviour. A *non-blank* needle made only of invisible Unicode
            // `Cf` characters folds to the same empty key after `comparison_key`
            // drops them; letting it fall through would make a format-only
            // query match every item. It must match nothing instead.
            return needle.trim().is_empty();
        }
        self.haystacks()
            .iter()
            .any(|field| comparison_key(field.as_ref()).contains(key.as_str()))
    }
}

/// A vault folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    /// Stable id.
    pub id: String,
    /// Display name.
    pub name: String,
}

/// A filter over the vault, as the sidebar expresses it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Filter {
    /// Everything.
    #[default]
    All,
    /// Starred items only.
    Favorites,
    /// Items whose kind is `kind`.
    Kind(ItemKind),
    /// Items in folder `id`.
    Folder(String),
    /// Items with no folder.
    NoFolder,
}

impl Filter {
    /// Whether `item` passes this filter.
    pub fn accepts(&self, item: &VaultItem) -> bool {
        match self {
            Self::All => true,
            Self::Favorites => item.favorite,
            Self::Kind(kind) => item.kind() == *kind,
            Self::Folder(id) => item.folder_id.as_deref() == Some(id.as_str()),
            Self::NoFolder => item.folder_id.is_none(),
        }
    }

    /// The filter's label for the UI.
    pub fn label(&self, folders: &[Folder]) -> String {
        match self {
            Self::All => "すべてのアイテム".to_string(),
            Self::Favorites => "お気に入り".to_string(),
            Self::Kind(kind) => kind.label().to_string(),
            Self::Folder(id) => folders
                .iter()
                .find(|folder| folder.id == *id)
                .map_or_else(|| "(不明なフォルダ)".to_string(), |f| f.name.clone()),
            Self::NoFolder => "フォルダなし".to_string(),
        }
    }
}

/// How the item list is ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SortKey {
    /// By name, A→Z.
    #[default]
    NameAsc,
    /// By name, Z→A.
    NameDesc,
    /// Most recently modified first.
    RecentlyModified,
    /// By kind, then name.
    Kind,
}

impl SortKey {
    /// The next key in the cycle (for the UI's "sort" button).
    pub const fn next(self) -> Self {
        match self {
            Self::NameAsc => Self::NameDesc,
            Self::NameDesc => Self::RecentlyModified,
            Self::RecentlyModified => Self::Kind,
            Self::Kind => Self::NameAsc,
        }
    }

    /// The key's label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NameAsc => "名前 ↑",
            Self::NameDesc => "名前 ↓",
            Self::RecentlyModified => "更新が新しい順",
            Self::Kind => "種類",
        }
    }
}

/// The vault itself.
#[derive(Clone, Debug, Default)]
pub struct Vault {
    /// All items.
    pub items: Vec<VaultItem>,
    /// All folders.
    pub folders: Vec<Folder>,
}

impl Vault {
    /// An empty, locked vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether there are no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The folder name for `id`, if it exists.
    pub fn folder_name(&self, id: &str) -> Option<&str> {
        self.folders
            .iter()
            .find(|folder| folder.id == id)
            .map(|folder| folder.name.as_str())
    }

    /// How many items sit in each folder.
    pub fn folder_counts(&self) -> Vec<(String, usize)> {
        self.folders
            .iter()
            .map(|folder| {
                let count = self
                    .items
                    .iter()
                    .filter(|item| item.folder_id.as_deref() == Some(folder.id.as_str()))
                    .count();
                (folder.id.clone(), count)
            })
            .collect()
    }

    /// How many items of each kind exist.
    pub fn kind_counts(&self) -> Vec<(ItemKind, usize)> {
        [
            ItemKind::Login,
            ItemKind::SecureNote,
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::SshKey,
        ]
        .into_iter()
        .map(|kind| {
            let count = self.items.iter().filter(|item| item.kind() == kind).count();
            (kind, count)
        })
        .collect()
    }

    /// How many favorites exist.
    pub fn favorite_count(&self) -> usize {
        self.items.iter().filter(|item| item.favorite).count()
    }

    /// The items passing `filter` and matching `query`, in `sort` order.
    ///
    /// A blank (or whitespace-only) query keeps every filtered item visible.
    /// A non-blank query whose normalized key is empty — for example one made
    /// entirely of Unicode `Cf` format characters, which `comparison_key`
    /// drops — matches nothing instead of every item.
    pub fn view(&self, filter: &Filter, query: &str, sort: SortKey) -> Vec<&VaultItem> {
        let trimmed = query.trim();
        let needle = comparison_key(trimmed);
        let mut matched: Vec<&VaultItem> = self
            .items
            .iter()
            .filter(|item| filter.accepts(item))
            .filter(|item| {
                if trimmed.is_empty() {
                    // Blank/whitespace-only query: keep the long-standing
                    // "every item is visible" behaviour.
                    true
                } else if query
                    .chars()
                    .all(|ch| ch.is_whitespace() || crate::limits::is_format_character(ch))
                {
                    // Non-blank but invisible-only (e.g. U+200B): folding
                    // dropped every character, so this is not a blank query
                    // and must not fall through to the empty-needle branch.
                    false
                } else {
                    item.matches_query(&needle)
                }
            })
            .collect();
        matched.sort_by(|a, b| compare(a, b, sort));
        matched
    }

    /// Items whose URIs match `page`, best (favorite, then newest) first.
    pub fn matches_page(&self, page: &str, opts: &openwarden::MatchOptions) -> Vec<&VaultItem> {
        let mut matched: Vec<&VaultItem> = self
            .items
            .iter()
            .filter(|item| item.matches_page(page, opts))
            .collect();
        matched.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| b.revision_date.cmp(&a.revision_date))
                // Use the same folded name key as `compare` (model.rs:1114-1124)
                // and fall back to the id so equal names order deterministically
                // instead of depending on the input order.
                .then_with(|| {
                    comparison_key(&a.name)
                        .cmp(&comparison_key(&b.name))
                        .then_with(|| a.id.cmp(&b.id))
                })
        });
        matched
    }

    /// Find an item by id.
    pub fn item(&self, id: &str) -> Option<&VaultItem> {
        self.items.iter().find(|item| item.id == id)
    }

    /// Toggle the favorite flag; returns the new value.
    pub fn toggle_favorite(&mut self, id: &str) -> Option<bool> {
        let item = self.items.iter_mut().find(|item| item.id == id)?;
        item.favorite = !item.favorite;
        Some(item.favorite)
    }

    /// Move an item into `folder` (`None` = no folder).
    pub fn set_folder(&mut self, id: &str, folder: Option<String>) -> bool {
        match self.items.iter_mut().find(|item| item.id == id) {
            Some(item) => {
                item.folder_id = folder;
                true
            }
            None => false,
        }
    }

    /// Add or replace an item, preserving the previous revision when the
    /// caller left `revision_date` at zero.
    pub fn upsert(&mut self, item: VaultItem) {
        match self
            .items
            .iter_mut()
            .find(|existing| existing.id == item.id)
        {
            Some(existing) => {
                let revision = if item.revision_date == UNKNOWN_REVISION {
                    existing.revision_date
                } else {
                    item.revision_date
                };
                *existing = VaultItem {
                    revision_date: revision,
                    ..item
                };
            }
            None => self.items.push(item),
        }
    }

    /// Remove an item, returning whether it existed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.items.len();
        self.items.retain(|item| item.id != id);
        before != self.items.len()
    }

    /// Duplicate names (NFKD-equivalent and case-insensitive), each with its
    /// item ids. Blank names are ignored: an unnamed item is not a duplicate
    /// of every other unnamed item. A name made only of invisible Unicode
    /// `Cf` characters (for example a zero-width space) counts as blank too:
    /// it has no visible identity, so two such items must not be reported as
    /// duplicates of each other. The same applies to a name made only of
    /// Unicode marks (`Mn`/`Me`, such as a combining accent or an enclosing
    /// circle): with no base character they render as decoration, not as a
    /// name. A mark following an ordinary base letter stays significant.
    pub fn duplicate_names(&self) -> Vec<(String, Vec<String>)> {
        let mut groups: Vec<(String, Vec<String>)> = Vec::new();
        for item in &self.items {
            let key = comparison_key(item.name.trim());
            if key.is_empty()
                || key.chars().all(|ch| {
                    crate::limits::is_format_character(ch) || unicode_normalize::is_mark(ch)
                })
            {
                continue;
            }
            match groups.iter_mut().find(|(name, _)| *name == key) {
                Some((_, ids)) => {
                    if !ids.contains(&item.id) {
                        ids.push(item.id.clone());
                    }
                }
                None => groups.push((key, vec![item.id.clone()])),
            }
        }
        groups.retain(|(_, ids)| ids.len() > 1);
        groups
    }
}

fn compare(a: &VaultItem, b: &VaultItem, sort: SortKey) -> std::cmp::Ordering {
    let by_name = comparison_key(&a.name)
        .cmp(&comparison_key(&b.name))
        .then_with(|| a.id.cmp(&b.id));
    match sort {
        SortKey::NameAsc => by_name,
        SortKey::NameDesc => by_name.reverse(),
        SortKey::RecentlyModified => b.revision_date.cmp(&a.revision_date).then(by_name),
        SortKey::Kind => a.kind().to_wire().cmp(&b.kind().to_wire()).then(by_name),
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;

/// Tests for the invisible-name arm of [`Vault::duplicate_names`].
///
/// Kept inline here instead of in `model_tests.rs` so the fix and its
/// regression guard stay together in this change's write scope.
#[cfg(test)]
mod duplicate_name_cf_tests {
    use super::*;

    fn note(id: &str, name: &str) -> VaultItem {
        VaultItem::new(id, name, ItemData::SecureNote { text: "x".into() })
    }

    #[test]
    fn cf_only_names_are_blank_for_duplicate_detection() {
        let mut vault = Vault::new();
        // Names made only of Unicode Cf code points look non-empty to `trim`,
        // but have no visible identity: they must not form a duplicate group.
        vault.items.push(note("cf-1", "\u{200b}"));
        vault.items.push(note("cf-2", "\u{200d}\u{200b}"));
        vault.items.push(note("cf-3", " \u{200b}\u{200f} "));
        // Ordinary blank names stay skipped as before.
        vault.items.push(note("blank-1", ""));
        vault.items.push(note("blank-2", "   "));
        // A real duplicate pair must still be reported.
        vault.items.push(note("name-1", "Alpha"));
        vault.items.push(note("name-2", "alpha"));

        let groups = vault.duplicate_names();
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert_eq!(groups[0].0, "alpha");
        assert_eq!(
            groups[0].1,
            vec!["name-1".to_string(), "name-2".to_string()]
        );
        for id in ["cf-1", "cf-2", "cf-3", "blank-1", "blank-2"] {
            assert!(
                !groups
                    .iter()
                    .any(|(_, ids)| ids.iter().any(|entry| entry.as_str() == id)),
                "{id} must not be a duplicate: {groups:?}"
            );
        }
    }

    #[test]
    fn two_cf_only_names_alone_produce_no_duplicates() {
        let mut vault = Vault::new();
        vault.items.push(note("a", "\u{200b}"));
        vault.items.push(note("b", "\u{200b}"));
        assert!(vault.duplicate_names().is_empty());
    }
}
