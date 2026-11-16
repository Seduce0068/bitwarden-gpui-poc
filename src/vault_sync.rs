//! Bridge from `openwarden`'s decrypted vault to the app's [`Vault`] model.
//!
//! `openwarden` exposes login metadata and decrypts individual fields on
//! demand. This module keeps those field reads in one place and turns the
//! result into the same [`VaultItem`]s the UI and tests already use.

use openwarden::{ExposeSecret as _, LoginInfo, Vault as OpenVault};

use crate::model::{Folder, ItemData, ItemKind, LoginUri, Vault, VaultItem};

/// Errors produced while converting a synced vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The vault is still locked, so fields cannot be decrypted.
    Locked,
    /// A login's id or fields could not be read.
    InvalidLogin(String),
}

impl SyncError {
    /// A short message for the status bar.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Locked => "vault がロックされています",
            Self::InvalidLogin(_) => "ログイン項目を読み取れませんでした",
        }
    }
}

impl core::fmt::Display for SyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SyncError {}

/// Parse a `/api/sync` response body, including folder names.
///
/// # Errors
///
/// [`SyncError::InvalidLogin`] when `openwarden` rejects the body.
pub fn parse_sync(body: &[u8]) -> Result<openwarden::SyncData, SyncError> {
    openwarden::SyncData::from_json(body)
        .map_err(|error| SyncError::InvalidLogin(error.to_string()))
}

/// Folder id and decrypted name from an unlocked `openwarden` vault.
pub fn folders_from(vault: &OpenVault) -> Result<Vec<Folder>, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Locked);
    }
    let mut folders = Vec::new();
    for id in vault.folders() {
        let name = vault
            .folder_name(&id)
            .map_err(|error| SyncError::InvalidLogin(error.to_string()))?;
        folders.push(Folder {
            id: id.as_str().to_string(),
            name: name.map_or_else(
                || "(名前なし)".to_string(),
                |value| value.expose_secret().to_string(),
            ),
        });
    }
    Ok(folders)
}

/// Convert one `openwarden` login into a model item, decrypting the
/// non-secret fields through the public API.
///
/// Passwords and TOTP secrets stay blank: the UI only needs their presence
/// and length, so we avoid holding every decrypted secret in the model.
fn login_item(vault: &OpenVault, info: &LoginInfo) -> VaultItem {
    let id = info.id.as_str().to_string();
    let name = vault
        .name(&info.id)
        .ok()
        .map(|value| value.expose_secret().to_string())
        .unwrap_or_else(|| format!("ログイン ({id})"));
    let username = vault
        .username(&info.id)
        .ok()
        .flatten()
        .map(|value| value.expose_secret().to_string())
        .unwrap_or_default();
    let uris = vault
        .uris(&info.id)
        .unwrap_or_default()
        .into_iter()
        .map(|uri| LoginUri {
            uri: uri.uri.expose_secret().to_string(),
            match_type: uri.match_type.map(|kind| kind.to_wire()),
        })
        .collect();
    let mut item = VaultItem::new(
        id.clone(),
        name,
        ItemData::Login {
            username,
            password: String::new(),
            // The UI only checks whether the secret is present; keeping the
            // marker avoids decrypting every TOTP secret up front.
            totp: if info.has_totp { "available" } else { "" }.to_string(),
            uris,
        },
    );
    item.folder_id = info
        .folder_id
        .as_ref()
        .map(|folder| folder.as_str().to_string());
    item.revision_date = parse_revision(info.revision_date.as_deref()).unwrap_or(0);
    item
}

/// RFC 3339 timestamp to Unix seconds, using only the date part so the
/// conversion stays deterministic and dependency-free.
fn parse_revision(value: Option<&str>) -> Option<i64> {
    let value = value?;
    let date = value.get(0..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// algorithm), so no external date crate is needed.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Build a model vault from an unlocked `openwarden` vault.
///
/// Only login items are imported for now; other item kinds stay on the mock
/// path until their decryptors are mapped.
///
/// # Errors
///
/// [`SyncError::Locked`] when the source vault has no decryption key, or
/// [`SyncError::InvalidLogin`] when a field read fails.
pub fn import_logins(vault: &OpenVault) -> Result<Vault, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Locked);
    }
    let mut model = Vault {
        folders: folders_from(vault)?,
        unlocked: true,
        ..Vault::default()
    };
    for info in vault.logins() {
        model.items.push(login_item(vault, &info));
    }
    Ok(model)
}

/// Whether the model item kind matches an openwarden login.
pub const fn imports_logins_only() -> ItemKind {
    ItemKind::Login
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sync_body_with_empty_profile_and_folders_parses() {
        let body = br#"{
            "profile": {"id": "user-1"},
            "folders": [{"id": "f1", "name": "2.work"}],
            "ciphers": []
        }"#;
        let sync = parse_sync(body).expect("sync JSON should parse");
        assert_eq!(sync.user_id(), "user-1");
    }

    #[test]
    fn malformed_sync_body_is_reported() {
        assert!(parse_sync(b"not json").is_err());
        // profile.id is required by openwarden's sync wire format.
        assert!(parse_sync(br#"{"folders": [], "ciphers": []}"#).is_err());
        assert!(parse_sync(br#"{"profile": {}}"#).is_err());
    }

    #[test]
    fn revision_dates_convert_to_unix_seconds() {
        assert_eq!(parse_revision(Some("1970-01-01T00:00:00Z")), Some(0));
        // Only the date part is used: 2023-11-14 00:00:00Z.
        assert_eq!(
            parse_revision(Some("2023-11-14T22:13:20Z")),
            Some(1_699_920_000)
        );
        assert_eq!(parse_revision(Some("not-a-date")), None);
        assert_eq!(parse_revision(None), None);
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(days_from_civil(2023, 11, 14), 19_675);
    }

    #[test]
    fn error_messages_are_present() {
        assert!(!SyncError::Locked.message().is_empty());
        assert!(!SyncError::InvalidLogin("x".into()).message().is_empty());
        assert_eq!(imports_logins_only(), ItemKind::Login);
    }
}
