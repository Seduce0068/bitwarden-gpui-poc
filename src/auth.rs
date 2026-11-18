//! Authentication and sync orchestration built on `openwarden`.
//!
//! Network calls are isolated in [`authenticate`]. Everything that can be
//! checked without a server lives in [`validate_config`], so the important
//! input rules are covered by deterministic tests.
//!
//! When `Client::sync()` fails after a successful login, the internal
//! authentication routine falls back to the encrypted offline cache
//! ([`crate::cache::cached_sync_for_detailed`])
//! and unlocks with the protected key from the live `Session`. The result is
//! tagged with [`AuthenticatedVault::from_cache`] so callers know the data may
//! be stale. See the ADR for why the cache has no production writer yet.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use openwarden::{
    ApiKey, Client, Device, ExposeSecret as _, KdfPolicy, MasterKey, SecretString, ServerUrls,
    Session, SyncData,
};

use crate::error::{AppError, BoxedCause};

/// Credentials supplied by the user at unlock time.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Base URL of the Bitwarden or Vaultwarden server.
    pub server_url: String,
    /// Personal API key `client_id`.
    pub client_id: String,
    /// Personal API key `client_secret`.
    pub client_secret: SecretString,
    /// Account email, used by prelogin and KDF derivation.
    pub email: String,
    /// Master password, used only to derive the decryption key.
    pub master_password: SecretString,
}

/// Errors the authentication layer can report.
///
/// This stays a small `Copy` enum because the UI matches and formats it
/// directly. The underlying failure is kept in [`AppError`], which this type
/// converts to and from, so `Error::source()` remains available to callers that
/// need the cause chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// A required field was empty.
    MissingField(&'static str),
    /// The server URL is not a valid HTTPS base URL.
    InvalidServerUrl,
    /// The server URL points at a link-local address (e.g. cloud metadata).
    BlockedServerUrl,
    /// The email address is malformed.
    InvalidEmail,
    /// The client could not be built.
    ClientSetup,
    /// The prelogin call failed.
    Prelogin,
    /// The API-key login failed.
    Login,
    /// The sync call failed.
    Sync,
    /// The KDF policy rejected the account's settings.
    KdfRejected,
    /// The login sequence did not finish within the allotted time.
    Timeout,
    /// A failure from another layer that this `Copy` enum cannot describe.
    Other(&'static str),
}

impl AuthError {
    /// A short message for the status bar.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MissingField(_) => "認証情報が未入力です",
            Self::InvalidServerUrl => "サーバー URL が不正です（HTTPS または loopback の HTTP）",
            Self::BlockedServerUrl => "サーバー URL が link-local アドレスを指しています",
            Self::InvalidEmail => "メールアドレスの形式が不正です",
            Self::ClientSetup => "クライアントを初期化できませんでした",
            Self::Prelogin => "サーバー情報の取得に失敗しました",
            Self::Login => "ログインに失敗しました",
            Self::Sync => "同期に失敗しました",
            Self::KdfRejected => "KDF 設定がポリシーで拒否されました",
            Self::Timeout => "ログインがタイムアウトしました",
            Self::Other(text) => text,
        }
    }
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AuthError {}

pub use crate::cache::SyncCacheError;

// ---------------------------------------------------------------------------
// Input length limits
//
// Policy: a cap is input hygiene, not credential validation. Text beyond a cap
// is silently truncated at a UTF-8 character boundary by `clamp_auth_config`
// (and by `AuthState::push_text` at the input source); length alone never
// produces an `AuthError`. Reporting an error for a long IME composition or a
// pasted value would be a confusing login failure. Whatever remains is still
// checked structurally by `validate_config` / `valid_email`, which is the
// backstop for configs assembled by callers that bypass the input layer.
// ---------------------------------------------------------------------------

/// Maximum length of an email address, in characters. RFC 5321 caps the local
/// part at 64 octets and the domain at 255; 254 is the practical ceiling mail
/// servers enforce, so longer addresses cannot be real deliverable addresses.
pub const MAX_EMAIL_LEN: usize = 254;
/// Maximum length of a server URL, in characters. Well above a normal
/// self-hosted URL, but below the ~2 KiB limit many HTTP stacks apply.
pub const MAX_SERVER_URL_LEN: usize = 2048;
/// Maximum length of a Client ID, in characters. Bitwarden keys are short
/// (`user.<uuid>`); this leaves room for custom installations.
pub const MAX_CLIENT_ID_LEN: usize = 256;
/// Maximum length of a Client Secret, in characters.
pub const MAX_CLIENT_SECRET_LEN: usize = 1024;
/// Maximum length of a master password, in characters. Long passphrases are
/// legitimate, but the in-memory buffer still needs a finite bound.
pub const MAX_MASTER_PASSWORD_LEN: usize = 1024;

/// Byte offset just past `limit` characters, or `None` when `value` fits.
fn char_boundary_at(value: &str, limit: usize) -> Option<usize> {
    value.char_indices().nth(limit).map(|(index, _)| index)
}

/// Shorten `value` to at most `limit` characters without splitting a UTF-8
/// code point. Following the policy above, this can never fail.
pub fn truncate_to_limit(value: &mut String, limit: usize) {
    if let Some(index) = char_boundary_at(value, limit) {
        value.truncate(index);
    }
}

/// Secret counterpart of [`truncate_to_limit`]. Replacing the value drops and
/// zeroizes the previous secret buffer.
fn truncate_secret_to_limit(value: &mut SecretString, limit: usize) {
    let Some(index) = char_boundary_at(value.expose_secret(), limit) else {
        return;
    };
    let prefix = value.expose_secret()[..index].to_string();
    *value = SecretString::from(prefix);
}

/// Apply every auth-field cap to a config built from untrusted text.
///
/// The caller keeps ownership; only over-long fields are shortened. Server URL
/// and email live in `Settings`, so their caps are enforced here rather than in
/// `AuthState`, which owns only the three credential fields.
pub fn clamp_auth_config(config: &mut AuthConfig) {
    truncate_to_limit(&mut config.server_url, MAX_SERVER_URL_LEN);
    truncate_to_limit(&mut config.email, MAX_EMAIL_LEN);
    truncate_to_limit(&mut config.client_id, MAX_CLIENT_ID_LEN);
    truncate_secret_to_limit(&mut config.client_secret, MAX_CLIENT_SECRET_LEN);
    truncate_secret_to_limit(&mut config.master_password, MAX_MASTER_PASSWORD_LEN);
}

/// Whether `value` contains a Unicode `Cf` (format) character.
///
/// Zero-width spaces, bidi overrides and similar invisible controls can hide
/// lookalike addresses or change how an address is rendered, so they are
/// rejected explicitly instead of being silently tolerated by the structural
/// check below. The list is the `Cf` category of Unicode 16.0.
fn has_format_character(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
    })
}

/// A minimal structural check: at most [`MAX_EMAIL_LEN`] characters, exactly
/// one `@`, no whitespace or format characters, and a dotted domain.
/// Regex-level RFC 5322 validation is out of scope for the PoC.
pub fn valid_email(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_EMAIL_LEN
        || value.chars().any(char::is_whitespace)
        || has_format_character(value)
    {
        return false;
    }
    if value.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

// ---------------------------------------------------------------------------
// URL-level SSRF guard
//
// Scope / residual risk (also reported to the reviewer):
// * `openwarden` 0.1.0 builds its `reqwest::Client` with
//   `redirect::Policy::none()` in `Client::new`, which is the constructor used
//   below, so this code path never follows a redirect and there is no redirect
//   target to inspect. `Client::with_http` is public but takes a `reqwest::Client`
//   that is not a direct dependency here (adding one is forbidden), and the
//   crate exposes no hook for per-hop or per-address inspection. This module
//   therefore validates only the configured URL plus a best-effort DNS snapshot.
// * The DNS snapshot is a TOCTOU check: a rebinding resolver can return a
//   public answer here and a link-local answer to the HTTP client later. Pinning
//   the resolved address would require replacing openwarden's transport, which
//   is not possible through its public API in this PoC.
// * Cloud metadata endpoints reachable only through a non-link-local address
//   (e.g. Alibaba's 100.100.100.200) are not covered: private/LAN-style ranges
//   stay allowed so self-hosted Vaultwarden instances keep working.
// Do not treat this guard as a complete SSRF boundary.
// ---------------------------------------------------------------------------

/// Hostnames that resolve to a cloud metadata service. Listed literally so
/// they are rejected even when DNS is unavailable or returns a different
/// answer; matching is case-insensitive and tolerates a trailing dot.
const BLOCKED_METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",   // GCP
    "metadata.goog",              // GCP short alias
    "metadata",                   // GCP guest-local short name
    "instance-data",              // AWS EC2
    "instance-data.ec2.internal", // AWS EC2
];

/// Whether a single resolved address is in a link-local range.
///
/// Only `169.254.0.0/16`, `fe80::/10` and IPv4-mapped forms of the former are
/// blocked. Private LAN addresses remain allowed so self-hosted Vaultwarden
/// instances keep working.
fn is_link_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(ip) => {
            // IPv4-mapped addresses (::ffff:a.b.c.d) must be checked as IPv4,
            // otherwise they bypass the link-local filter.
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_link_local_ip(IpAddr::V4(mapped));
            }
            // fe80::/10 link-local
            (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_blocked_metadata_host(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    BLOCKED_METADATA_HOSTS.contains(&normalized.as_str())
}

/// Wildcard DNS services encode an address in the hostname, for example
/// `169.254.169.254.nip.io`. Recognizing the embedded literal here keeps the
/// canonical bypass blocked even when resolution is offline; the general case
/// is handled by the resolver-backed check.
fn hostname_embeds_link_local(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = normalized.split('.').collect();
    // Dotted quad as leading labels: 169.254.1.1.nip.io
    for window in labels.windows(4) {
        if let Ok(ip) = window.join(".").parse::<Ipv4Addr>() {
            if is_link_local_ip(IpAddr::V4(ip)) {
                return true;
            }
        }
    }
    // Hyphenated quad inside one label: 169-254-1-1.nip.io
    for label in &labels {
        let parts: Vec<&str> = label.split('-').collect();
        if parts.len() == 4 {
            if let Ok(ip) = parts.join(".").parse::<Ipv4Addr>() {
                if is_link_local_ip(IpAddr::V4(ip)) {
                    return true;
                }
            }
        }
    }
    false
}

/// Shared classifier. `resolve` is invoked only for DNS host names, so the
/// literal and known-host rules stay network-free and the DNS path can be
/// tested with an injected resolver (no real DNS, no new dependencies).
fn is_blocked_server_url_with<F>(value: &str, resolve: F) -> bool
where
    F: Fn(&str) -> Vec<IpAddr>,
{
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    match url.host() {
        Some(url::Host::Ipv4(ip)) => is_link_local_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => is_link_local_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => {
            let Some(host) = url.host_str() else {
                return false;
            };
            if is_blocked_metadata_host(host) || hostname_embeds_link_local(host) {
                return true;
            }
            // Any link-local A/AAAA answer blocks the whole name: a rebinding
            // or split-horizon resolver may mix it with a public address.
            resolve(host).iter().copied().any(is_link_local_ip)
        }
        None => false,
    }
}

/// Resolve a DNS name with the standard library only. Resolution failures are
/// not treated as proof of safety, but openwarden will fail to connect too;
/// the deterministic rules above have already run at that point.
fn resolve_host(host: &str) -> Vec<IpAddr> {
    let Ok(addresses) = (host, 0).to_socket_addrs() else {
        return Vec::new();
    };
    addresses.into_iter().map(|socket| socket.ip()).collect()
}

/// Reject link-local servers: literal addresses, known cloud metadata
/// hostnames, wildcard-DNS aliases with an embedded link-local literal, and
/// any DNS name whose current A/AAAA answers include a link-local address.
///
/// This is the network-capable form used on the login path (off the async
/// executor). Config validation uses the DNS-free variant directly so
/// it stays deterministic and offline. See the scope comment above for the
/// DNS-rebinding and redirect limitations.
pub fn is_blocked_server_url(value: &str) -> bool {
    is_blocked_server_url_with(value, resolve_host)
}

/// Network-free subset of [`is_blocked_server_url`]: everything except the
/// live DNS lookup. Used by [`validate_config`] and deterministic tests.
fn is_blocked_server_url_without_dns(value: &str) -> bool {
    is_blocked_server_url_with(value, |_| Vec::new())
}

/// Validate everything that does not require a network round trip.
///
/// # Errors
///
/// [`AuthError::MissingField`] for an empty field,
/// [`AuthError::InvalidEmail`] for a malformed or over-long address,
/// [`AuthError::BlockedServerUrl`] for link-local hosts, or
/// [`AuthError::InvalidServerUrl`] for a URL `openwarden` rejects.
pub fn validate_config(config: &AuthConfig) -> Result<(), AuthError> {
    if config.server_url.trim().is_empty() {
        return Err(AuthError::MissingField("server_url"));
    }
    if config.client_id.trim().is_empty() {
        return Err(AuthError::MissingField("client_id"));
    }
    if config.client_secret.expose_secret().trim().is_empty() {
        return Err(AuthError::MissingField("client_secret"));
    }
    if config.email.trim().is_empty() {
        return Err(AuthError::MissingField("email"));
    }
    if !valid_email(&config.email) {
        return Err(AuthError::InvalidEmail);
    }
    if config.master_password.expose_secret().trim().is_empty() {
        return Err(AuthError::MissingField("master_password"));
    }
    if is_blocked_server_url_without_dns(config.server_url.trim()) {
        return Err(AuthError::BlockedServerUrl);
    }
    ServerUrls::self_hosted(config.server_url.trim()).map_err(|error| {
        AuthError::from(AppError::InvalidServerUrlCause(BoxedCause::text(
            error.to_string(),
        )))
    })?;
    Ok(())
}

/// A stable device identity keeps the server's device list tidy.
pub fn device_for_installation(identifier: &str) -> Device {
    Device {
        identifier: identifier.to_string(),
        name: "Bitwarden GPUI PoC".to_string(),
        device_type: Device::LINUX_CLI,
    }
}

/// A logged-in session with its decrypted-key material still sealed.
pub struct AuthenticatedVault {
    /// The bearer token returned by the API-key login.
    pub session: Session,
    /// The raw sync response, ready for `Vault::apply_sync`.
    pub sync: SyncData,
    /// The master key derived from the password and the account's KDF.
    pub master_key: MasterKey,
    /// Whether `sync` came from the offline cache instead of a fresh response.
    ///
    /// The UI does not surface this yet; the ADR records it as an open item.
    pub from_cache: bool,
}

/// Failures while turning a successful login into a usable vault.
///
/// Kept as its own enum for the UI's status formatting; [`AppError`] carries the
/// original cause and `From` converts between the two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnlockError {
    /// The token response contained no protected key.
    MissingProtectedKey,
    /// The master key could not decrypt the protected key.
    UnlockFailed(String),
    /// The sync payload could not be applied to the decrypted vault.
    ApplySyncFailed(String),
    /// The decrypted vault could not be converted into the local model.
    ImportFailed(String),
    /// An unexpected failure, keeping the original message for the status bar.
    Other(String),
}

impl UnlockError {
    /// A message for the UI status bar.
    pub fn message(&self) -> String {
        match self {
            Self::MissingProtectedKey => "復号キーが応答にありません".to_string(),
            Self::UnlockFailed(detail) => format!("復号キーを取得できません（{detail}）"),
            Self::ApplySyncFailed(detail) => format!("同期データを取り込めません（{detail}）"),
            Self::ImportFailed(detail) => format!("vault 変換に失敗しました（{detail}）"),
            Self::Other(detail) => detail.clone(),
        }
    }
}

/// Decrypt a freshly authenticated vault and convert it into the local model.
///
/// This keeps openwarden's unlock/apply_sync/import sequence in the domain
/// layer; the UI only applies the resulting vault.
///
/// # Errors
///
/// [`UnlockError`] at whichever step fails.
pub fn unlock_and_import(
    authenticated: AuthenticatedVault,
) -> Result<crate::model::Vault, UnlockError> {
    use openwarden::Vault as OpenVault;

    let protected_key = authenticated
        .session
        .protected_key()
        .unwrap_or("")
        .to_string();
    if protected_key.is_empty() {
        return Err(UnlockError::MissingProtectedKey);
    }
    let kdf = authenticated.session.kdf();
    let mut open_vault = OpenVault::unlock(&authenticated.master_key, &protected_key, kdf)
        .map_err(|error| {
            let detail = error.to_string();
            UnlockError::from(AppError::unlock_failed_cause(
                detail.clone(),
                BoxedCause::text(detail),
            ))
        })?;
    open_vault.apply_sync(authenticated.sync).map_err(|error| {
        let detail = error.to_string();
        UnlockError::from(AppError::apply_sync_failed_cause(
            detail.clone(),
            BoxedCause::text(detail),
        ))
    })?;
    crate::vault_sync::import_logins(&open_vault).map_err(|error| {
        let detail = error.to_string();
        UnlockError::from(AppError::import_failed_cause(
            detail.clone(),
            BoxedCause::text(detail),
        ))
    })
}

/// Default time budget for the whole login sequence.
pub const DEFAULT_LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Log in and fetch the vault data with a timeout.
///
/// The KDF derivation is CPU- and memory-heavy; callers should run this
/// future on a background task so the UI stays responsive.
///
/// # Errors
///
/// The corresponding [`AuthError`] variant when validation, login, sync or
/// key derivation fails, or [`AuthError::Timeout`] when the budget expires.
pub async fn authenticate_with_timeout(
    config: &AuthConfig,
    device_identifier: &str,
    timeout: std::time::Duration,
) -> Result<AuthenticatedVault, AuthError> {
    // Callers may pass text from Settings or a persisted config that was never
    // capped at the input source. Clamp a private copy so every network path
    // sees bounded fields without mutating the caller's value or erroring on
    // length alone.
    let mut bounded = config.clone();
    clamp_auth_config(&mut bounded);
    let config = &bounded;
    // Validate before starting the race so bad input fails deterministically
    // without touching the network or the timeout.
    validate_config(config)?;
    let login = authenticate_inner(config, device_identifier);
    let timer = async {
        smol::Timer::after(timeout).await;
        Err(AuthError::Timeout)
    };
    smol::future::race(login, timer).await
}

/// Log in using [`DEFAULT_LOGIN_TIMEOUT`].
pub async fn authenticate(
    config: &AuthConfig,
    device_identifier: &str,
) -> Result<AuthenticatedVault, AuthError> {
    authenticate_with_timeout(config, device_identifier, DEFAULT_LOGIN_TIMEOUT).await
}

/// Report why an offline restore failed, while keeping the sync failure as the
/// headline. A missing cache is the normal first-launch case, so it keeps the
/// original `Sync` status rather than adding noise.
pub(crate) fn cache_restore_failure(error: AppError) -> AuthError {
    if matches!(error, AppError::NotFound) {
        return AuthError::Sync;
    }
    // The classification itself lives in the cache layer; this function only
    // wraps the reason in a status message so the two cannot drift apart.
    use crate::cache::{
        cache_error_message, REASON_CORRUPT, REASON_MISSING, REASON_OUTDATED,
        REASON_SERVER_MISMATCH, REASON_TOO_LARGE, REASON_UNREADABLE, REASON_USER_MISMATCH,
    };
    match cache_error_message(error) {
        REASON_CORRUPT => AuthError::Other("同期に失敗しました（キャッシュが破損しています）"),
        REASON_UNREADABLE => AuthError::Other("同期に失敗しました（キャッシュを読み込めません）"),
        REASON_OUTDATED => {
            AuthError::Other("同期に失敗しました（キャッシュのバージョンが古いです）")
        }
        REASON_USER_MISMATCH => {
            AuthError::Other("同期に失敗しました（キャッシュが別のアカウントのものです）")
        }
        REASON_SERVER_MISMATCH => {
            AuthError::Other("同期に失敗しました（キャッシュが別のサーバーのものです）")
        }
        REASON_TOO_LARGE => {
            AuthError::Other("同期に失敗しました（キャッシュがサイズ上限を超えています）")
        }
        REASON_MISSING => AuthError::Sync,
        _ => AuthError::Other("同期に失敗しました（キャッシュを復元できませんでした）"),
    }
}

async fn authenticate_inner(
    config: &AuthConfig,
    device_identifier: &str,
) -> Result<AuthenticatedVault, AuthError> {
    validate_config(config)?;
    // DNS names can resolve to a link-local address even when the URL string
    // looks harmless. Re-check with resolution immediately before the client
    // is built. `smol::unblock` keeps the blocking standard-library resolver
    // off the async executor; the call still runs inside the login timeout.
    // This is a snapshot only - see the scope comment above for TOCTOU /
    // redirect limitations that the public openwarden API cannot close.
    let server_url = config.server_url.trim().to_string();
    if smol::unblock(move || is_blocked_server_url(&server_url)).await {
        return Err(AuthError::BlockedServerUrl);
    }
    let urls = ServerUrls::self_hosted(config.server_url.trim()).map_err(|error| {
        AuthError::from(AppError::InvalidServerUrlCause(BoxedCause::text(
            error.to_string(),
        )))
    })?;
    let client =
        Client::new(urls, device_for_installation(device_identifier)).map_err(|error| {
            AuthError::from(AppError::ClientSetupCause(BoxedCause::text(
                error.to_string(),
            )))
        })?;
    let kdf = client
        .prelogin(config.email.trim())
        .await
        .map_err(|error| {
            AuthError::from(AppError::PreloginCause(BoxedCause::text(error.to_string())))
        })?;
    let api_key = ApiKey {
        client_id: config.client_id.trim().to_string(),
        client_secret: config.client_secret.clone(),
    };
    let session = client.login_api_key(&api_key).await.map_err(|error| {
        AuthError::from(AppError::LoginCause(BoxedCause::text(error.to_string())))
    })?;
    // A successful login gives us the protected key, so an encrypted cache can
    // still be unlocked when /api/sync is unreachable. The cache never supplies
    // key material (keys are stripped on write). A missing cache keeps the
    // original `AuthError::Sync`; a present but unusable one reports the
    // classified `AuthError::Other` reason. The sync error itself is not
    // propagated. No production code writes the cache yet: openwarden 0.1.0
    // exposes neither the raw sync body nor the bearer token, so this is a
    // best-effort restore of a pre-existing file.
    let (sync, from_cache) = match client.sync(&session).await {
        Ok(sync) => (sync, false),
        Err(_sync_error) => {
            match crate::cache::cached_sync_for_detailed(config.server_url.trim()) {
                Ok(sync) => (sync, true),
                Err(cache_error) => return Err(cache_restore_failure(cache_error)),
            }
        }
    };
    // KDF derivation is CPU- and memory-heavy; move it off the UI thread.
    let password = config.master_password.clone();
    let email = config.email.trim().to_string();
    let policy = KdfPolicy::default();
    let master_key = smol::unblock(move || MasterKey::derive(&password, &email, &kdf, &policy))
        .await
        .map_err(|error| {
            AuthError::from(AppError::KdfRejectedCause(BoxedCause::text(
                error.to_string(),
            )))
        })?;
    Ok(AuthenticatedVault {
        session,
        sync,
        master_key,
        from_cache,
    })
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
