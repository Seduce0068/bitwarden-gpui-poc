//! Vault data model: item kinds, folders, filtering, search and URI matching.
//!
//! This mirrors the shape of a Bitwarden personal vault without any network
//! access, so the UI (and the tests) can work on real data structures while
//! login/sync stay out of scope.

use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyData {
    /// Public key line.
    pub public_key: String,
    /// Private key (not persisted by this PoC).
    pub private_key: String,
    /// Key fingerprint.
    pub fingerprint: String,
}

/// Kind-specific payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemData {
    /// A login.
    Login {
        /// Username or email.
        username: String,
        /// Password.
        password: String,
        /// TOTP field (`otpauth://` URI, `steam://`, or bare base32).
        totp: String,
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
    fn haystacks(&self) -> Vec<&str> {
        let mut out = vec![self.name.as_str(), self.notes.as_str()];
        match &self.data {
            ItemData::Login {
                username,
                uris,
                totp,
                ..
            } => {
                out.push(username);
                out.push(totp);
                out.extend(uris.iter().map(|u| u.uri.as_str()));
            }
            ItemData::SecureNote { text } => out.push(text),
            ItemData::Card(card) => {
                out.push(&card.cardholder_name);
                out.push(&card.brand);
                // The full number is deliberately not searchable: only the last
                // four digits are, so a partial PAN can't be fished out.
                if let Some(last4) = card.number.rsplit(' ').next() {
                    out.push(last4);
                }
            }
            ItemData::Identity(identity) => {
                out.push(&identity.first_name);
                out.push(&identity.last_name);
                out.push(&identity.email);
                out.push(&identity.phone);
                out.push(&identity.company);
            }
            ItemData::SshKey(key) => {
                out.push(&key.public_key);
                out.push(&key.fingerprint);
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn login(id: &str, name: &str, username: &str, password: &str, uri: &str) -> VaultItem {
        VaultItem::new(
            id,
            name,
            ItemData::Login {
                username: username.to_string(),
                password: password.to_string(),
                totp: String::new(),
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
    fn favorites_folders_and_removal_round_trip() {
        let mut vault = sample();
        assert_eq!(vault.toggle_favorite("2"), Some(true));
        assert_eq!(vault.favorite_count(), 2);
        assert_eq!(vault.toggle_favorite("nope"), None);

        assert!(vault.set_folder("3", Some("f1".into())));
        assert!(!vault.set_folder("nope", None));
        assert_eq!(vault.folder_counts(), vec![("f1".to_string(), 2)]);

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
    fn kind_counts_covers_every_kind() {
        let vault = sample();
        let counts = vault.kind_counts();
        assert_eq!(counts.len(), 5);
        assert_eq!(counts[0], (ItemKind::Login, 2));
        assert_eq!(counts[1], (ItemKind::SecureNote, 1));
        assert_eq!(counts[4], (ItemKind::SshKey, 0));
    }
}
