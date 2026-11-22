//! Authentication and sync orchestration built on `openwarden`.
//!
//! Network calls are isolated in [`authenticate`]. Everything that can be
//! checked without a server lives in [`validate_config`], so the important
//! input rules are covered by deterministic tests.
//!
//! When `Client::sync_body()` fails or the body cannot be parsed after a
//! successful login, the internal
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
/// Most variants stay cheap to copy so the UI can match and format them
/// directly. Five variants (the `Detail` ones) own a `String`: a cause-carrying
/// `AppError` cannot stay `Copy` while its rendered detail is surfaced in the
/// status bar, so those variants retain the text that would otherwise be
/// dropped by [`From<AppError> for AuthError`]. The typed cause itself stays in
/// [`AppError`] and is reachable through `Error::source()` for callers that
/// convert before the UI boundary; after conversion only the rendered detail
/// survives in the small enum.
#[derive(Clone, Debug)]
pub enum AuthError {
    /// A required field was empty.
    MissingField(&'static str),
    /// The server URL is not a valid HTTPS base URL.
    InvalidServerUrl,
    /// The URL was rejected with a cause; keeps its detail for the status bar.
    InvalidServerUrlDetail(String),
    /// The server URL points at a link-local address (e.g. cloud metadata).
    BlockedServerUrl,
    /// The email address is malformed.
    InvalidEmail,
    /// The client could not be built.
    ClientSetup,
    /// The client setup failed with a cause; keeps its detail for the status bar.
    ClientSetupDetail(String),
    /// The prelogin call failed.
    Prelogin,
    /// The prelogin call failed; keeps its detail for the status bar.
    PreloginDetail(String),
    /// The API-key login failed.
    Login,
    /// The API-key login failed; keeps the underlying detail for the status bar.
    LoginDetail(String),
    /// The sync call failed.
    Sync,
    /// Sync failed and the offline cache could not be restored; keeps a
    /// composed detail so the original failure is not silently discarded.
    SyncDetail(String),
    /// The KDF policy rejected the account's settings.
    KdfRejected,
    /// The KDF policy rejected the settings; keeps its detail for the status bar.
    KdfRejectedDetail(String),
    /// The login sequence did not finish within the allotted time.
    Timeout,
    /// A failure from another layer that this small enum cannot describe.
    Other(&'static str),
}

impl PartialEq for AuthError {
    /// A `Detail` variant is the same failure as its plain sibling: the cause
    /// is diagnostic context, not identity. This mirrors [`AppError`]'s rule,
    /// so adding a cause does not change how callers match or compare errors.
    fn eq(&self, other: &Self) -> bool {
        use self::AuthError::*;
        match (self, other) {
            (
                InvalidServerUrl | InvalidServerUrlDetail(_),
                InvalidServerUrl | InvalidServerUrlDetail(_),
            )
            | (ClientSetup | ClientSetupDetail(_), ClientSetup | ClientSetupDetail(_))
            | (Prelogin | PreloginDetail(_), Prelogin | PreloginDetail(_))
            | (Login | LoginDetail(_), Login | LoginDetail(_))
            | (Sync | SyncDetail(_), Sync | SyncDetail(_))
            | (KdfRejected | KdfRejectedDetail(_), KdfRejected | KdfRejectedDetail(_)) => true,
            (MissingField(left), MissingField(right)) => left == right,
            (Other(left), Other(right)) => left == right,
            (BlockedServerUrl, BlockedServerUrl)
            | (InvalidEmail, InvalidEmail)
            | (Timeout, Timeout) => true,
            _ => false,
        }
    }
}

impl Eq for AuthError {}

impl AuthError {
    /// A short message for the status bar.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::MissingField(_) => "認証情報が未入力です",
            Self::InvalidServerUrl | Self::InvalidServerUrlDetail(_) => {
                "サーバー URL が不正です（HTTPS または loopback の HTTP）"
            }
            Self::BlockedServerUrl => "サーバー URL が link-local アドレスを指しています",
            Self::InvalidEmail => "メールアドレスの形式が不正です",
            Self::ClientSetup | Self::ClientSetupDetail(_) => {
                "クライアントを初期化できませんでした"
            }
            Self::Prelogin | Self::PreloginDetail(_) => "サーバー情報の取得に失敗しました",
            Self::Login | Self::LoginDetail(_) => "ログインに失敗しました",
            Self::Sync | Self::SyncDetail(_) => "同期に失敗しました",
            Self::KdfRejected | Self::KdfRejectedDetail(_) => "KDF 設定がポリシーで拒否されました",
            Self::Timeout => "ログインがタイムアウトしました",
            Self::Other(text) => text,
        }
    }

    /// A status-bar message that keeps the distinguishing detail.
    ///
    /// `message()` stays a cheap `&'static str` for callers that only need the
    /// family; this method appends the field name for [`Self::MissingField`]
    /// and the retained cause text for the `Detail` variants, so a user can see
    /// *which* credential is missing, why the API-key login failed, or which
    /// URL/client setup error the server reported.
    pub fn status_message(&self) -> String {
        match self {
            Self::MissingField(field) => format!("{}（{field}）", self.message()),
            Self::PreloginDetail(detail)
            | Self::KdfRejectedDetail(detail)
            | Self::LoginDetail(detail)
            | Self::SyncDetail(detail)
            | Self::InvalidServerUrlDetail(detail)
            | Self::ClientSetupDetail(detail)
                if !detail.is_empty() =>
            {
                format!("{}（{detail}）", self.message())
            }
            _ => self.message().to_string(),
        }
    }
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AuthError {}

impl From<AuthError> for AppError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::MissingField(field) => Self::MissingField(field),
            AuthError::InvalidServerUrl => Self::InvalidServerUrl,
            AuthError::InvalidServerUrlDetail(detail) => {
                Self::InvalidServerUrlCause(BoxedCause::text(detail.clone()))
            }
            AuthError::BlockedServerUrl => Self::BlockedServerUrl,
            AuthError::InvalidEmail => Self::InvalidEmail,
            AuthError::ClientSetup => Self::ClientSetup,
            AuthError::ClientSetupDetail(detail) => {
                Self::ClientSetupCause(BoxedCause::text(detail.clone()))
            }
            AuthError::Prelogin => Self::Prelogin,
            AuthError::PreloginDetail(detail) => {
                Self::PreloginCause(BoxedCause::text(detail.clone()))
            }
            AuthError::Login => Self::Login,
            AuthError::LoginDetail(detail) => Self::LoginCause(BoxedCause::text(detail.clone())),
            AuthError::Sync => Self::Sync,
            AuthError::SyncDetail(detail) => Self::SyncCause(BoxedCause::text(detail.clone())),
            AuthError::KdfRejected => Self::KdfRejected,
            AuthError::KdfRejectedDetail(detail) => {
                Self::KdfRejectedCause(BoxedCause::text(detail.clone()))
            }
            AuthError::Timeout => Self::Timeout,
            AuthError::Other(text) => Self::Other(text.to_string()),
        }
    }
}

impl From<AppError> for AuthError {
    fn from(error: AppError) -> Self {
        // The `Detail` variants keep the rendered cause text for the status bar.
        // Other families still map to their plain sibling, matching the
        // `AppError::PartialEq` rule that a cause is diagnostic context only.
        match error {
            AppError::MissingField(field) => AuthError::MissingField(field),
            AppError::InvalidServerUrl => AuthError::InvalidServerUrl,
            // The URL parser's message used to vanish here: keep it in a detail
            // variant so `status_message()` can show why the URL was rejected.
            AppError::InvalidServerUrlCause(cause) => {
                AuthError::InvalidServerUrlDetail(cause.to_string())
            }
            AppError::BlockedServerUrl => AuthError::BlockedServerUrl,
            AppError::InvalidEmail => AuthError::InvalidEmail,
            AppError::ClientSetup => AuthError::ClientSetup,
            AppError::ClientSetupCause(cause) => AuthError::ClientSetupDetail(cause.to_string()),
            AppError::Prelogin => AuthError::Prelogin,
            AppError::PreloginCause(cause) => AuthError::PreloginDetail(cause.to_string()),
            AppError::Login => AuthError::Login,
            // Keep the rendered detail of a cause-carrying login failure: the
            // `Copy`-era conversion used to drop it and show only a generic
            // status. `AppError` still owns the typed cause for `source()`.
            AppError::LoginCause(cause) => AuthError::LoginDetail(cause.to_string()),
            // A malformed sync body (e.g. unexpected key casing) is a sync
            // failure, not an unexpected error, and must be retryable with `r`.
            AppError::Sync => AuthError::Sync,
            AppError::SyncCause(cause) => AuthError::SyncDetail(cause.to_string()),
            AppError::InvalidLogin(text) | AppError::InvalidLoginCause(text, _) => {
                AuthError::SyncDetail(text.clone())
            }
            AppError::KdfRejected => AuthError::KdfRejected,
            AppError::KdfRejectedCause(cause) => AuthError::KdfRejectedDetail(cause.to_string()),
            AppError::Timeout => AuthError::Timeout,
            // An honest generic message is better than silently reporting an
            // unrelated domain failure for an error this enum cannot describe.
            _ => AuthError::Other(crate::error::OTHER_ERROR_MESSAGE),
        }
    }
}

/// Strip the status prefix/suffix from legacy formatted errors.
///
/// Current `unlock_failed` values use structured variants that carry the raw
/// detail directly; this helper is only needed for older `UnlockFailed` /
/// `UnlockFailedCause` values (and the apply-sync/import families) that still
/// store a fully formatted message.
fn unlock_detail(text: &str, prefix: &str) -> String {
    text.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix('）'))
        .unwrap_or(text)
        .to_string()
}

impl From<UnlockError> for AppError {
    fn from(error: UnlockError) -> Self {
        match error {
            UnlockError::MissingProtectedKey => Self::MissingProtectedKey,
            UnlockError::UnlockFailed(detail) => Self::unlock_failed(detail),
            UnlockError::UnlockFailedCause(detail, cause) => {
                Self::unlock_failed_cause(detail, cause)
            }
            UnlockError::ApplySyncFailed(detail) => Self::apply_sync_failed(detail),
            UnlockError::ApplySyncFailedCause(detail, cause) => {
                Self::apply_sync_failed_cause(detail, cause)
            }
            UnlockError::ImportFailed(detail) => Self::import_failed(detail),
            UnlockError::ImportFailedCause(detail, cause) => {
                Self::import_failed_cause(detail, cause)
            }
            UnlockError::Other(detail) => Self::Other(detail),
        }
    }
}

impl From<AppError> for UnlockError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::MissingProtectedKey => UnlockError::MissingProtectedKey,
            AppError::UnlockFailedStructured(_, detail) => {
                UnlockError::UnlockFailed(detail.clone())
            }
            AppError::UnlockFailedStructuredCause(_, detail, cause) => {
                UnlockError::UnlockFailedCause(detail.clone(), cause)
            }
            // Legacy variants still carry a formatted message; keep the strip
            // fallback for values constructed before the structured variants.
            AppError::UnlockFailed(text) => {
                UnlockError::UnlockFailed(unlock_detail(&text, "復号キーを取得できません（"))
            }
            AppError::UnlockFailedCause(text, cause) => UnlockError::UnlockFailedCause(
                unlock_detail(&text, "復号キーを取得できません（"),
                cause,
            ),
            AppError::ApplySyncFailed(text) => {
                UnlockError::ApplySyncFailed(unlock_detail(&text, "同期データを取り込めません（"))
            }
            AppError::ApplySyncFailedCause(text, cause) => UnlockError::ApplySyncFailedCause(
                unlock_detail(&text, "同期データを取り込めません（"),
                cause,
            ),
            AppError::ImportFailed(text) => {
                UnlockError::ImportFailed(unlock_detail(&text, "vault 変換に失敗しました（"))
            }
            AppError::ImportFailedCause(text, cause) => UnlockError::ImportFailedCause(
                unlock_detail(&text, "vault 変換に失敗しました（"),
                cause,
            ),
            // Keep the real message here: this type owns its detail, so no
            // status text is lost when an unrelated failure crosses layers.
            unexpected => UnlockError::Other(unexpected.message().to_string()),
        }
    }
}

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

pub(crate) use crate::limits::{
    has_format_character, truncate_to_limit, DEFAULT_LOGIN_TIMEOUT, MAX_EMAIL_LEN,
    MAX_SERVER_URL_LEN,
};

/// Maximum length of a Client ID, in characters. Bitwarden keys are short
/// (`user.<uuid>`); this leaves room for custom installations.
pub const MAX_CLIENT_ID_LEN: usize = 256;
/// Maximum length of a Client Secret, in characters.
pub const MAX_CLIENT_SECRET_LEN: usize = 1024;
/// Maximum length of a master password, in characters. Long passphrases are
/// legitimate, but the in-memory buffer still needs a finite bound.
pub const MAX_MASTER_PASSWORD_LEN: usize = 1024;

/// Secret counterpart of [`truncate_to_limit`]. Replacing the value drops and
/// zeroizes the previous secret buffer.
fn truncate_secret_to_limit(value: &mut SecretString, limit: usize) {
    let Some(index) = crate::limits::char_boundary_at(value.expose_secret(), limit) else {
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

/// A minimal structural check: at most `MAX_EMAIL_LEN` characters, exactly
/// one `@`, no whitespace/control/format characters, and a dotted domain.
/// Regex-level RFC 5322 validation is out of scope for the PoC.
pub fn valid_email(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_EMAIL_LEN
        || value.chars().any(char::is_whitespace)
        // `char::is_control` covers the Cc category (U+0000..=U+001F and
        // U+007F..=U+009F). Cc characters such as NUL and C1 controls are not
        // whitespace, so `is_whitespace` alone let them through; like the Cf
        // characters below they can hide or alter an address in the UI.
        || value.chars().any(char::is_control)
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
/// [`AuthError::InvalidServerUrl`] for a URL `openwarden` rejects (carrying the
/// parser's message in [`AuthError::InvalidServerUrlDetail`]).
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
        AuthError::from(AppError::InvalidServerUrlCause(BoxedCause::new(error)))
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
    /// The login flow copies this flag before the vault is consumed and
    /// surfaces it in the success status, warning that the data may be stale.
    pub from_cache: bool,
}

/// Failures while turning a successful login into a usable vault.
///
/// Kept as its own enum for the UI's status formatting; [`AppError`] carries the
/// original cause and `From` converts between the two. The `*Cause` variants
/// keep that cause reachable through `Error::source()` instead of discarding it
/// at the UI boundary. Equality follows [`AppError`]'s rule: a cause-carrying
/// variant equals its plain sibling because the cause is diagnostic context,
/// not part of the failure's identity.
#[derive(Clone, Debug)]
pub enum UnlockError {
    /// The token response contained no protected key.
    MissingProtectedKey,
    /// The master key could not decrypt the protected key.
    UnlockFailed(String),
    /// The master key could not decrypt the protected key; retains the cause.
    UnlockFailedCause(String, BoxedCause),
    /// The sync payload could not be applied to the decrypted vault.
    ApplySyncFailed(String),
    /// The sync payload could not be applied; retains the cause.
    ApplySyncFailedCause(String, BoxedCause),
    /// The decrypted vault could not be converted into the local model.
    ImportFailed(String),
    /// The vault conversion failed; retains the cause.
    ImportFailedCause(String, BoxedCause),
    /// An unexpected failure, keeping the original message for the status bar.
    Other(String),
}

impl UnlockError {
    /// A message for the UI status bar.
    pub fn message(&self) -> String {
        match self {
            Self::MissingProtectedKey => "復号キーが応答にありません".to_string(),
            Self::UnlockFailed(detail) | Self::UnlockFailedCause(detail, _) => {
                format!("復号キーを取得できません（{detail}）")
            }
            Self::ApplySyncFailed(detail) | Self::ApplySyncFailedCause(detail, _) => {
                format!("同期データを取り込めません（{detail}）")
            }
            Self::ImportFailed(detail) | Self::ImportFailedCause(detail, _) => {
                format!("vault 変換に失敗しました（{detail}）")
            }
            Self::Other(detail) => detail.clone(),
        }
    }
}

impl PartialEq for UnlockError {
    /// Compare rendered messages only, mirroring `AppError`'s `PartialEq`: a
    /// retained cause must not change whether two failures count as the same.
    fn eq(&self, other: &Self) -> bool {
        self.message() == other.message()
    }
}

impl Eq for UnlockError {}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for UnlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnlockFailedCause(_, cause)
            | Self::ApplySyncFailedCause(_, cause)
            | Self::ImportFailedCause(_, cause) => Some(cause.as_error()),
            _ => None,
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
    // Keep the typed errors as causes (`BoxedCause::new`) instead of flattening
    // them into text: the source chain stays reachable through `Error::source()`
    // on the returned `UnlockError` and on the `AppError` it converts to.
    let mut open_vault = OpenVault::unlock(&authenticated.master_key, &protected_key, kdf)
        .map_err(|error| {
            let detail = error.to_string();
            UnlockError::from(AppError::unlock_failed_cause(
                detail,
                BoxedCause::new(error),
            ))
        })?;
    open_vault.apply_sync(authenticated.sync).map_err(|error| {
        let detail = error.to_string();
        UnlockError::from(AppError::apply_sync_failed_cause(
            detail,
            BoxedCause::new(error),
        ))
    })?;
    crate::vault_sync::import_logins(&open_vault).map_err(|error| {
        let detail = error.to_string();
        UnlockError::from(AppError::import_failed_cause(
            detail,
            BoxedCause::new(error),
        ))
    })
}

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

/// Log in using the default login timeout.
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
    match crate::cache::cache_restore_status(error) {
        Some(status) => AuthError::Other(status),
        None => AuthError::Sync,
    }
}

/// Compose the status when both the live sync and its cache fallback fail.
///
/// `cause` is the discarded sync/parse failure. Folding its detail into a
/// [`AuthError::SyncDetail`] keeps the sync classification and stops the
/// original reason from vanishing when the cache also fails. The cache reason
/// supplied as `fallback` stays first so an existing, tested status string is
/// preserved verbatim when there is no sync cause.
///
/// Current constraint: only the *first* [`std::error::Error::source()`] level
/// of `cause` is rendered. A nested inner cause is not flattened further, so
/// its text may still be absent from the status bar. A cause that yields no
/// text at all leaves the fallback message unchanged.
fn sync_fallback_failure(fallback: AuthError, cause: Option<AppError>) -> AuthError {
    let Some(cause) = cause else {
        return fallback;
    };
    let detail = std::error::Error::source(&cause)
        .map(|source| source.to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| cause.message().to_string());
    if detail.is_empty() {
        return fallback;
    }
    // `status_message()` adds the family prefix for `SyncDetail`, so the
    // composed detail must not repeat it. The cache fallback may itself be an
    // `Other` whose message already starts with that prefix and a parenthesized
    // reason; strip both before composing the final detail.
    let fallback_text = fallback.message();
    let mut reason = fallback_text
        .strip_prefix(AuthError::Sync.message())
        .unwrap_or(fallback_text);
    reason = reason
        .strip_prefix('（')
        .and_then(|text| text.strip_suffix('）'))
        .unwrap_or(reason);
    let detail = if reason.is_empty() {
        detail
    } else {
        format!("{reason}（{detail}）")
    };
    AuthError::SyncDetail(detail)
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
    // Box the concrete errors with `new()` so the `AppError` created here keeps
    // their typed source chain. `AuthError::from` then renders that cause into
    // an `InvalidServerUrlDetail` / `ClientSetupDetail` for the status bar: the
    // detail reaches the UI, but the typed chain stops at the `AuthError` boundary.
    let urls = ServerUrls::self_hosted(config.server_url.trim()).map_err(|error| {
        AuthError::from(AppError::InvalidServerUrlCause(BoxedCause::new(error)))
    })?;
    let client = Client::new(urls, device_for_installation(device_identifier))
        .map_err(|error| AuthError::from(AppError::ClientSetupCause(BoxedCause::new(error))))?;
    let kdf = client
        .prelogin(config.email.trim())
        .await
        .map_err(|error| AuthError::from(AppError::PreloginCause(BoxedCause::new(error))))?;
    let api_key = ApiKey {
        client_id: config.client_id.trim().to_string(),
        client_secret: config.client_secret.clone(),
    };
    let session = client
        .login_api_key(&api_key)
        .await
        .map_err(|error| AuthError::from(AppError::LoginCause(BoxedCause::new(error))))?;
    // The API secret is no longer needed after login. Drop the clone so it
    // does not survive through sync, cache restore and KDF derivation.
    drop(api_key);
    // Fetch the raw body so our normalizer can accept Vaultwarden's
    // PascalCase keys (openwarden 0.1.0's `Client::sync` rejected them).
    // openwarden 0.1.1 exposes `sync_body` without requiring our own HTTP
    // client or token handling. On failure fall back to the encrypted cache.
    //
    // Keep the failure instead of calling `.ok()` twice: a transport error
    // becomes a `SyncCause` and a malformed body keeps `parse_sync`'s
    // `InvalidLoginCause`, so the offline cache can still restore the vault
    // while a *failed* fallback reports why the live sync was unusable.
    let (parsed, sync_cause) = match client.sync_body(&session).await {
        Ok(body) => match crate::vault_sync::parse_sync(&body) {
            Ok(sync) => (Some(sync), None),
            Err(error) => (None, Some(error)),
        },
        Err(error) => (None, Some(AppError::SyncCause(BoxedCause::new(error)))),
    };
    let (sync, from_cache) = match parsed {
        Some(sync) => (sync, false),
        // A transport failure or an unparsable (e.g. PascalCase) body both
        // leave us without a fresh vault; try the encrypted cache in either
        // case, as the pre-0.1.1 path did.
        None => match crate::cache::cached_sync_for_detailed(config.server_url.trim()) {
            Ok(sync) => (sync, true),
            Err(cache_error) => {
                return Err(sync_fallback_failure(
                    cache_restore_failure(cache_error),
                    sync_cause,
                ));
            }
        },
    };
    // KDF derivation is CPU- and memory-heavy; move it off the UI thread.
    let password = config.master_password.clone();
    let email = config.email.trim().to_string();
    let policy = KdfPolicy::default();
    let master_key = smol::unblock(move || MasterKey::derive(&password, &email, &kdf, &policy))
        .await
        .map_err(|error| AuthError::from(AppError::KdfRejectedCause(BoxedCause::new(error))))?;
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
