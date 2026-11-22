//! Bridge from `openwarden`'s decrypted vault to the app's [`Vault`] model.
//!
//! `openwarden` exposes login metadata and decrypts individual fields on
//! demand. This module keeps those field reads in one place and turns the
//! result into the same [`VaultItem`]s the UI and tests already use. Passwords
//! and TOTP secrets are decrypted here and copied into the model's `Zeroizing`
//! buffers, so the UI can actually audit passwords and generate TOTP codes
//! after a real login.
//!
//! Known constraint: there is no injection seam for the field decryptors.
//! `login_item` and `folders_from` call the concrete `openwarden::Vault`
//! readers directly, so a test cannot inject a decryption failure through a
//! parameter; it must instead build a real vault with malformed `EncString`
//! ciphertexts (see `undecryptable_password_keeps_the_vault_and_is_excluded_from_audit`).
//! A private decryptor seam was considered and rejected: it would change the
//! public import signature and fork the real reader path these tests exercise.

use std::collections::{HashMap, HashSet};

use openwarden::{ExposeSecret as _, LoginInfo, Vault as OpenVault};
use zeroize::Zeroizing;

use crate::model::{Folder, ItemData, LoginUri, Vault, VaultItem};

/// Status marker written to the model's password field when `openwarden`
/// cannot decrypt a login's password.
///
/// It is never a real password and never a secret: the health audit recognises
/// it and excludes the item from password checks instead of mistaking an empty
/// buffer for a weak password. The NUL prefix makes a collision with a real
/// password practically impossible. Keeping the marker in this module (rather
/// than a new model field) preserves the model's `Debug`/serde contract: the
/// password is still redacted by `ItemData`'s manual `Debug` implementation.
pub const UNDECRYPTABLE_PASSWORD: &str = "\u{0}openwarden:undecryptable";

/// Marker used in place of a login's URI list when the field could not be
/// decrypted. Without it the audit would mistake a decryption failure for a
/// genuinely missing URI and report `NoUri`.
pub const UNDECRYPTABLE_URI: &str = "\u{0}openwarden:uri-undecryptable";

/// Whether a model URI is the undecryptable status marker.
pub fn is_undecryptable_uri(value: &str) -> bool {
    value == UNDECRYPTABLE_URI
}

/// Whether a model password is the undecryptable status marker.
pub fn is_undecryptable_password(value: &str) -> bool {
    value == UNDECRYPTABLE_PASSWORD
}

/// Marker used in place of a login's TOTP field when the field exists but its
/// ciphertext could not be decrypted. Without it the audit would mistake a
/// decryption failure for a genuinely missing TOTP and discard the fact that
/// the login is 2FA-enabled.
pub const UNDECRYPTABLE_TOTP: &str = "\u{0}openwarden:totp-undecryptable";

/// Whether a model TOTP value is the undecryptable status marker.
pub fn is_undecryptable_totp(value: &str) -> bool {
    value == UNDECRYPTABLE_TOTP
}

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
///
/// Alias of [`AppError`](crate::error::AppError); `parse_sync` attaches the
/// original `openwarden` failure as the `Error::source()` of its error.
pub type SyncError = crate::error::AppError;

/// Parse a `/api/sync` response body, including folder names.
///
/// PascalCase keys are normalized to camelCase and duplicate cipher ids are
/// collapsed to their newest revision before the `SyncData` is built, so
/// `Vault::apply_sync` never sees two rows for one id (see
/// `dedup_ciphers_by_revision`).
///
/// # Errors
///
/// [`SyncError::InvalidLogin`] when `openwarden` rejects the body.
pub fn parse_sync(body: &[u8]) -> Result<openwarden::SyncData, SyncError> {
    let mut value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        let detail = error.to_string();
        SyncError::InvalidLoginCause(detail.clone(), crate::error::BoxedCause::text(detail))
    })?;
    normalize_sync_keys(&mut value).map_err(|detail| {
        SyncError::InvalidLoginCause(detail.clone(), crate::error::BoxedCause::text(detail))
    })?;
    dedup_ciphers_by_revision(&mut value);
    let normalized = serde_json::to_vec(&value).map_err(|error| {
        let detail = format!("sync: {error}");
        SyncError::InvalidLoginCause(detail.clone(), crate::error::BoxedCause::text(detail))
    })?;
    openwarden::SyncData::from_json(&normalized).map_err(|error| {
        let detail = error.to_string();
        SyncError::InvalidLoginCause(detail.clone(), crate::error::BoxedCause::text(detail))
    })
}

/// Lowercase the first ASCII character of a JSON key (`RevisionDate` →
/// `revisionDate`). Already-camelCase keys are returned unchanged.
fn camel_case_key(key: &str) -> String {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {
            first.to_ascii_lowercase().to_string() + chars.as_str()
        }
        Some(first) => first.to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Recursively normalize PascalCase JSON keys returned by some Vaultwarden
/// versions into the camelCase that openwarden 0.1.0 expects.
///
/// Only keys change: encrypted values, ids and user data are passed through
/// verbatim, so normalization cannot alter secrets.
fn normalize_sync_keys(value: &mut serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut normalized = serde_json::Map::with_capacity(map.len());
            for (key, mut child) in std::mem::take(map) {
                normalize_sync_keys(&mut child)?;
                let target = camel_case_key(&key);
                if normalized.contains_key(&target) {
                    // Do not echo the raw key names: a server-controlled body
                    // can choose them, and this detail may reach diagnostics.
                    // The variant is enough to classify the failure.
                    return Err("sync: conflicting keys in the same object".to_string());
                }
                normalized.insert(target, child);
            }
            *map = normalized;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                normalize_sync_keys(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Collapse duplicate cipher ids to one row before `Vault::apply_sync`.
///
/// `openwarden::Vault::cipher(id)` returns the **first** matching cipher, and
/// every field reader (`name`, `password`, `totp_secret`, `uris`, …) goes
/// through it. Leaving a stale duplicate in the sync body therefore makes the
/// import read the old row's decrypted values even when
/// `import_logins_with_audit` has correctly selected a newer revision's
/// `LoginInfo`. Dropping the older rows here keeps the metadata and the
/// decrypted fields from the same cipher.
///
/// The winner is the row with the highest `revisionDate` (missing/unparsable
/// dates count as [`crate::model::UNKNOWN_REVISION`]); ties keep the first row
/// so normalization and parsing stay deterministic.
fn dedup_ciphers_by_revision(value: &mut serde_json::Value) {
    let Some(ciphers) = value
        .get_mut("ciphers")
        .and_then(|entry| entry.as_array_mut())
    else {
        return;
    };
    let mut best: HashMap<String, (usize, i64)> = HashMap::new();
    let mut drop: HashSet<usize> = HashSet::new();
    for (index, cipher) in ciphers.iter().enumerate() {
        let Some(id) = cipher.get("id").and_then(|entry| entry.as_str()) else {
            // Malformed rows are left for openwarden to skip as usual.
            continue;
        };
        let revision = cipher
            .get("revisionDate")
            .and_then(|entry| entry.as_str())
            .and_then(|value| parse_revision(Some(value)))
            .unwrap_or(crate::model::UNKNOWN_REVISION);
        match best.entry(id.to_string()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let (best_index, best_revision) = *entry.get();
                if revision > best_revision {
                    drop.insert(best_index);
                    entry.insert((index, revision));
                } else {
                    drop.insert(index);
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((index, revision));
            }
        }
    }
    if drop.is_empty() {
        return;
    }
    let mut index = 0usize;
    ciphers.retain(|_| {
        let keep = !drop.contains(&index);
        index += 1;
        keep
    });
}

/// Folder id and decrypted name from an unlocked `openwarden` vault.
///
/// A folder whose name cannot be decrypted keeps its id and gets a
/// placeholder name, so one bad field never discards the rest of the vault.
pub fn folders_from(vault: &OpenVault) -> Result<Vec<Folder>, SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Locked);
    }
    let mut folders = Vec::new();
    for id in vault.folders() {
        let name = match vault.folder_name(&id) {
            Ok(Some(value)) => value.expose_secret().to_string(),
            // Known constraint: openwarden 0.1.1 returns `Ok(None)` only for a
            // folder id that is *not* in the vault. `folders()` yields ids from
            // that same list, so this branch is unreachable through the public
            // API today and is kept defensively (with a placeholder rather than
            // dropping the folder). The reachable failure is `Err(_)`, handled
            // below. Tests cover the success and `Err(_)` branches.
            Ok(None) => "(名前なし)".to_string(),
            // Partial decryption failure: keep the folder with a placeholder
            // instead of aborting the whole import. The internal folder id is
            // deliberately not shown in the user-facing name; it remains in
            // `Folder::id` where callers need it for filtering and lookup.
            Err(_) => "(復号できませんでした)".to_string(),
        };
        folders.push(Folder {
            id: id.as_str().to_string(),
            name,
        });
    }
    Ok(folders)
}

/// Convert one `openwarden` login into a model item, decrypting every field
/// through the public API.
///
/// The password and TOTP secret are copied into the model's `Zeroizing`
/// buffers so the audit and the TOTP copy action work on real values. A field
/// that fails to decrypt never discards the rest of the vault: the password is
/// replaced with the [`UNDECRYPTABLE_PASSWORD`] status marker (which the health
/// audit excludes from password checks), a URI field whose ciphertext cannot
/// be opened becomes [`UNDECRYPTABLE_URI`] (reported as
/// `Finding::UriUninspectable` rather than `NoUri`), and a TOTP field that
/// exists but cannot be decrypted becomes [`UNDECRYPTABLE_TOTP`] (reported as
/// `Finding::TotpUninspectable` rather than `NoTotp`). A genuinely absent TOTP
/// field stays empty and is reported as `NoTotp`.
///
/// Known limitation: the model's `favorite` and `notes` keep their defaults.
/// `openwarden` 0.1.1's public `LoginInfo` carries only id, folder, revision,
/// `has_password` and `has_totp`, and `Vault` exposes no public reader for
/// notes or the favorite flag. Neither value can be imported through the
/// supported API, so this PoC leaves them untouched rather than inventing
/// values.
///
/// Known constraint (G07): a login whose name cannot be decrypted gets the
/// same id-free placeholder as an undecryptable folder name. The internal
/// cipher id remains in `VaultItem::id` for lookup and filtering, but it is
/// deliberately not shown in the user-facing name.
///
/// Known constraint: unlike password/URI/TOTP, a login's `username` has **no**
/// undecryptable marker. `vault.username()` returning `Ok(None)` (no field) and
/// `Err(_)` (ciphertext could not be opened) are both folded into an empty
/// `String`, so importers cannot distinguish "absent" from "uninspectable".
/// Adding a sentinel would change `ItemData::Login::username` from a plain
/// `String` to a tagged value, which is outside this change's model contract;
/// the health audit does not score usernames, so the current behaviour is
/// documented rather than silently changed.
fn login_item(vault: &OpenVault, info: &LoginInfo) -> VaultItem {
    let id = info.id.as_str().to_string();
    let name = vault
        .name(&info.id)
        .ok()
        .map(|value| value.expose_secret().to_string())
        .unwrap_or_else(|| "(復号できませんでした)".to_string());
    let username = vault
        .username(&info.id)
        .ok()
        .flatten()
        .map(|value| value.expose_secret().to_string())
        .unwrap_or_default();
    let uris = match vault.uris(&info.id) {
        Ok(list) => list
            .into_iter()
            .map(|uri| LoginUri {
                uri: uri.uri.expose_secret().to_string(),
                match_type: uri.match_type.map(|kind| kind.to_wire()),
            })
            .collect(),
        // Decryption failed: keep a marker so the audit distinguishes this
        // from a login that genuinely has no URI.
        Err(_) => vec![LoginUri {
            uri: UNDECRYPTABLE_URI.to_string(),
            match_type: None,
        }],
    };
    let password = match vault.password(&info.id) {
        Ok(Some(secret)) => Zeroizing::new(secret.expose_secret().to_string()),
        // No password field at all: genuinely empty, so the audit scores it
        // as a weak password instead of excluding it.
        Ok(None) => Zeroizing::new(String::new()),
        // Decryption failed: mark it as uninspectable rather than pretending
        // the row has no password.
        Err(_) => Zeroizing::new(UNDECRYPTABLE_PASSWORD.to_string()),
    };
    let totp = match vault.totp_secret(&info.id) {
        Ok(Some(secret)) => Zeroizing::new(secret.expose_secret().to_string()),
        // No TOTP field at all: genuinely unset, so the audit reports `NoTotp`.
        Ok(None) => Zeroizing::new(String::new()),
        // Decryption failed: keep a marker so the audit can tell "2FA is
        // configured but uninspectable" from "no 2FA at all".
        Err(_) => Zeroizing::new(UNDECRYPTABLE_TOTP.to_string()),
    };
    let mut item = VaultItem::new(
        id.clone(),
        name,
        ItemData::Login {
            username,
            password,
            totp,
            uris,
        },
    );
    item.folder_id = info
        .folder_id
        .as_ref()
        .map(|folder| folder.as_str().to_string());
    item.revision_date =
        parse_revision(info.revision_date.as_deref()).unwrap_or(crate::model::UNKNOWN_REVISION);
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
/// [`SyncError::Locked`] when the source vault has no decryption key.
/// Individual field decryption failures are recorded as uninspectable (see
/// [`UNDECRYPTABLE_PASSWORD`] and [`UNDECRYPTABLE_URI`]) instead of failing
/// the import.
///
/// Known constraint: this production entry point calls
/// [`import_logins_with_audit`] and **discards** its `Vec<ImportAudit>`. The
/// auth/unlock path therefore cannot show duplicate-id decisions in the UI;
/// only callers that use `import_logins_with_audit` directly (currently tests)
/// can observe the change log.
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
/// Known constraint: on the `Updated` branch the audit entry records only
/// revision metadata. The replacement item's decrypted fields are re-read
/// from the concrete `openwarden::Vault` **by id**, and `Vault::cipher(id)`
/// returns the *first* matching row. When raw duplicates reach this branch
/// (only possible for callers that bypass [`parse_sync`]), the newer revision
/// therefore inherits the first row's field values. Production is safe
/// because [`parse_sync`] collapses duplicates before `apply_sync`. See also
/// [`import_logins`], which discards the audit log entirely: the auth/unlock
/// path cannot surface duplicate-id decisions in the UI.
///
/// # Errors
///
/// [`SyncError::Locked`] when the source vault has no decryption key.
/// Individual field decryption failures are recorded as uninspectable (see
/// [`UNDECRYPTABLE_PASSWORD`] and [`UNDECRYPTABLE_URI`]) instead of failing
/// the import.
pub fn import_logins_with_audit(vault: &OpenVault) -> Result<(Vault, Vec<ImportAudit>), SyncError> {
    if vault.is_locked() {
        return Err(SyncError::Locked);
    }
    let mut model = Vault {
        folders: folders_from(vault)?,
        ..Vault::default()
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut revisions: HashMap<String, i64> = HashMap::new();
    let mut audit = Vec::new();

    for info in vault.logins() {
        let id = info.id.as_str().to_string();
        let revision =
            parse_revision(info.revision_date.as_deref()).unwrap_or(crate::model::UNKNOWN_REVISION);

        if !seen.insert(id.clone()) {
            let old_revision = revisions
                .get(&id)
                .copied()
                .unwrap_or(crate::model::UNKNOWN_REVISION);
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
            // The audit entry records only revision metadata. Field values are
            // re-read from the concrete `openwarden::Vault` by id, and
            // `Vault::cipher(id)` returns its *first* matching row. When raw
            // duplicates reach this branch (only tests bypass `parse_sync`'s
            // pre-dedup), the replacement therefore keeps the first row's
            // decrypted content even though `info` is the newer revision.
            // Production is safe because `parse_sync` collapses duplicates
            // before `apply_sync`, so a newer `LoginInfo` always refers to the
            // same row the field readers see (see `dedup_ciphers_by_revision`).
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
