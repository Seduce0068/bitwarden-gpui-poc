//! Bridge from `openwarden`'s decrypted vault to the app's [`Vault`] model.
//!
//! `openwarden` exposes login metadata and decrypts individual fields on
//! demand. This module keeps those field reads in one place and turns the
//! result into the same [`VaultItem`]s the UI and tests already use.

use std::collections::{HashMap, HashSet};

use openwarden::{ExposeSecret as _, LoginInfo, Vault as OpenVault};

use crate::model::{Folder, ItemData, LoginUri, Vault, VaultItem};

/// A secret-free record of a decision made while importing a login row.
///
/// Only item ids and revision timestamps are kept: names, usernames, URIs,
/// passwords and TOTP secrets never enter the audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportAudit {
    /// The first row for this id was accepted.
    Added { id: String, revision: i64 },
    /// A duplicate id had a newer revision and replaced the previous row.
    Updated {
        id: String,
        old_revision: i64,
        new_revision: i64,
    },
    /// A duplicate id had an older revision and was clipped; the accepted
    /// row is unchanged.
    Clipped {
        id: String,
        old_revision: i64,
        new_revision: i64,
    },
    /// A duplicate id had the same revision and needed no change.
    Ignored { id: String, revision: i64 },
}

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
/// path until their decryptors are mapped. Use
/// [`import_logins_with_audit`] to also receive the change log.
///
/// # Errors
///
/// [`SyncError::Locked`] when the source vault has no decryption key, or
/// [`SyncError::InvalidLogin`] when a field read fails.
pub fn import_logins(vault: &OpenVault) -> Result<Vault, SyncError> {
    let (model, _) = import_logins_with_audit(vault)?;
    Ok(model)
}

/// Build a model vault from an unlocked `openwarden` vault and return the
/// secret-free audit log alongside it.
///
/// Duplicate ciphers with the same id are collapsed into a single item, so a
/// later `Vault::remove` cannot delete two rows at once. For each id the
/// highest revision wins: an out-of-order (regressed) row is clipped and
/// recorded in the audit log instead of overwriting the accepted item.
///
/// # Errors
///
/// [`SyncError::Locked`] when the source vault has no decryption key, or
/// [`SyncError::InvalidLogin`] when a field read fails.
pub fn import_logins_with_audit(vault: &OpenVault) -> Result<(Vault, Vec<ImportAudit>), SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Locked);
    }
    let mut model = Vault {
        folders: folders_from(vault)?,
        unlocked: true,
        ..Vault::default()
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut revisions: HashMap<String, i64> = HashMap::new();
    let mut audit = Vec::new();

    for info in vault.logins() {
        let id = info.id.as_str().to_string();
        let revision = parse_revision(info.revision_date.as_deref()).unwrap_or(0);

        if !seen.insert(id.clone()) {
            let old_revision = revisions.get(&id).copied().unwrap_or(0);
            if revision < old_revision {
                audit.push(ImportAudit::Clipped {
                    id,
                    old_revision,
                    new_revision: revision,
                });
                continue;
            }
            if revision == old_revision {
                audit.push(ImportAudit::Ignored { id, revision });
                continue;
            }
            if let Some(existing) = model.items.iter_mut().find(|item| item.id == id) {
                *existing = login_item(vault, &info);
            }
            revisions.insert(id.clone(), revision);
            audit.push(ImportAudit::Updated {
                id,
                old_revision,
                new_revision: revision,
            });
            continue;
        }

        model.items.push(login_item(vault, &info));
        revisions.insert(id.clone(), revision);
        audit.push(ImportAudit::Added { id, revision });
    }

    Ok((model, audit))
}

#[cfg(test)]
#[path = "vault_sync_tests.rs"]
mod tests;
