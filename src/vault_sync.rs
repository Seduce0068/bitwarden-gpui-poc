//! Bridge from `openwarden`'s decrypted vault to the app's [`Vault`] model.
//!
//! `openwarden` exposes login metadata and decrypts individual fields on
//! demand. This module keeps those field reads in one place and turns the
//! result into the same [`VaultItem`]s the UI and tests already use.

use std::collections::{HashMap, HashSet};

use openwarden::{ExposeSecret as _, LoginInfo, Vault as OpenVault};
use zeroize::Zeroizing;

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
            password: Zeroizing::new(String::new()),
            // The UI only checks whether the secret is present; keeping the
            // marker avoids decrypting every TOTP secret up front.
            totp: Zeroizing::new(if info.has_totp { "available" } else { "" }.to_string()),
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

/// RFC 3339 timestamp to Unix seconds.
///
/// Accepts `YYYY-MM-DDTHH:MM:SSZ` (also lowercase `t`/`z`), an optional
/// fractional second, and numeric `±HH:MM` offsets. The offset is applied so
/// the result is always seconds since `1970-01-01T00:00:00Z`. Calendar dates
/// are validated (including leap years) and every arithmetic step is checked,
/// so malformed or overflowing input becomes `None` rather than wrapping.
fn parse_revision(value: Option<&str>) -> Option<i64> {
    let bytes = value?.as_bytes();

    // Read the fixed-width fields directly: a signed or variable-width number
    // would let inputs such as `2023-1-01` slip through.
    let year = read_digits(bytes, 0, 4)?;
    expect_byte(bytes, 4, b'-')?;
    let month = read_digits(bytes, 5, 2)?;
    expect_byte(bytes, 7, b'-')?;
    let day = read_digits(bytes, 8, 2)?;
    if !matches!(bytes.get(10), Some(b'T') | Some(b't')) {
        return None;
    }
    let hour = read_digits(bytes, 11, 2)?;
    expect_byte(bytes, 13, b':')?;
    let minute = read_digits(bytes, 14, 2)?;
    expect_byte(bytes, 16, b':')?;
    let second = read_digits(bytes, 17, 2)?;

    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    // RFC 3339 allows a fractional second, which is ignored (truncated) for
    // the whole-second epoch value.
    let mut cursor = 19;
    if matches!(bytes.get(cursor), Some(b'.') | Some(b',')) {
        cursor += 1;
        let fraction_start = cursor;
        while matches!(bytes.get(cursor), Some(byte) if byte.is_ascii_digit()) {
            cursor += 1;
        }
        if cursor == fraction_start {
            return None;
        }
    }

    let offset_seconds = match bytes.get(cursor) {
        Some(b'Z') | Some(b'z') => {
            cursor += 1;
            0
        }
        Some(b'+') | Some(b'-') => {
            let negative = bytes[cursor] == b'-';
            expect_byte(bytes, cursor.checked_add(3)?, b':')?;
            let offset_hour = read_digits(bytes, cursor + 1, 2)?;
            let offset_minute = read_digits(bytes, cursor + 4, 2)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            cursor += 6;
            let magnitude = offset_hour
                .checked_mul(3_600)?
                .checked_add(offset_minute.checked_mul(60)?)?;
            if negative {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };
    // Reject trailing bytes instead of silently ignoring part of the input.
    if cursor != bytes.len() {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let local_seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    local_seconds.checked_sub(offset_seconds)
}

/// Parse exactly `len` ASCII digits starting at `start` as a non-negative
/// integer. Each step is checked so an oversized value is rejected.
fn read_digits(bytes: &[u8], start: usize, len: usize) -> Option<i64> {
    let slice = bytes.get(start..start.checked_add(len)?)?;
    let mut value = 0i64;
    for &byte in slice {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
    }
    Some(value)
}

fn expect_byte(bytes: &[u8], index: usize, expected: u8) -> Option<()> {
    if bytes.get(index) == Some(&expected) {
        Some(())
    } else {
        None
    }
}

fn is_leap_year(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// Number of days in a Gregorian month; `month` is assumed to be 1..=12.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// algorithm), so no external date crate is needed. `None` on overflow.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let adjusted_year = year.checked_sub(i64::from(month <= 2))?;
    let era = adjusted_year.div_euclid(400);
    let yoe = adjusted_year.checked_sub(era.checked_mul(400)?)?;
    let mp = month.checked_add(if month > 2 { -3 } else { 9 })?;
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
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
