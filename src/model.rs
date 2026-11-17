//! Vault data model: item kinds, folders, filtering, search and URI matching.
//!
//! This mirrors the shape of a Bitwarden personal vault without any network
//! access, so the UI (and the tests) can work on real data structures while
//! login/sync stay out of scope.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Reduce a URI to scheme and host so embedded credentials or tokens in the
/// path/query are never shown in the UI or copied into reports.
///
/// Falls back to `"(不正な URI)"` when the value cannot be parsed.
pub fn mask_uri(value: &str) -> String {
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

/// Card details.
///
/// `Debug` masks the number and security code.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardData {
    /// Name on the card.
    pub cardholder_name: String,
    /// Brand (Visa, Mastercard, …).
    pub brand: String,
    /// Card number.
    pub number: String,
    /// Expiry month, 1-12.
    pub exp_month: String,
    /// Expiry year.
    pub exp_year: String,
    /// Security code.
    pub code: String,
}

/// Identity details.
///
/// `Debug` masks personal fields.
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
/// `Debug` masks the private key.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyData {
    /// Public key line.
    pub public_key: String,
    /// Private key (not persisted by this PoC).
    pub private_key: String,
    /// Key fingerprint.
    pub fingerprint: String,
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
            .field("company", &self.company)
            .finish()
    }
}

impl core::fmt::Debug for CardData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CardData")
            .field("cardholder_name", &self.cardholder_name)
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
        /// Note text.
        text: String,
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
                username,
                password: _,
                totp,
                uris,
            } => f
                .debug_struct("Login")
                .field("username", username)
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    /// Stable id (a UUID in a real vault).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Owning folder id, if any.
    pub folder_id: Option<String>,
    /// Whether the item is starred.
    pub favorite: bool,
    /// Free-form notes.
    pub notes: String,
    /// Last modified, in Unix seconds.
    pub revision_date: i64,
    /// The kind-specific payload.
    pub data: ItemData,
}

impl VaultItem {
    /// Build an item with a generated id.
    pub fn new(id: impl Into<String>, name: impl Into<String>, data: ItemData) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            folder_id: None,
            favorite: false,
            notes: String::new(),
            revision_date: 0,
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

    /// Every searchable text field, lowercased lazily by the caller.
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
            ItemData::SecureNote { text } => out.push(Cow::Borrowed(text)),
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
                out.push(Cow::Borrowed(&identity.company));
            }
            ItemData::SshKey(key) => {
                out.push(Cow::Borrowed(&key.public_key));
                out.push(Cow::Borrowed(&key.fingerprint));
            }
        }
        out
    }

    /// Whether any searchable field contains `needle` (already lowercased).
    pub fn matches_query(&self, needle: &str) -> bool {
        self.haystacks()
            .iter()
            .any(|field| field.to_lowercase().contains(needle))
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
    /// Whether the vault is unlocked. The PoC never holds a real key; this
    /// only gates the UI.
    pub unlocked: bool,
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
    pub fn view(&self, filter: &Filter, query: &str, sort: SortKey) -> Vec<&VaultItem> {
        let needle = query.trim().to_lowercase();
        let mut matched: Vec<&VaultItem> = self
            .items
            .iter()
            .filter(|item| filter.accepts(item))
            .filter(|item| needle.is_empty() || item.matches_query(&needle))
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
                .then_with(|| a.name.cmp(&b.name))
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
                let revision = if item.revision_date == 0 {
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

    /// Duplicate names (case-insensitive), each with its item ids.
    pub fn duplicate_names(&self) -> Vec<(String, Vec<String>)> {
        let mut groups: Vec<(String, Vec<String>)> = Vec::new();
        for item in &self.items {
            let key = item.name.trim().to_lowercase();
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
    let by_name = a
        .name
        .to_lowercase()
        .cmp(&b.name.to_lowercase())
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
