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
//! and unlocks with the protected key from the live `Session`. The cache is
//! accepted only when both the server URL and the account id from the personal
//! API key's `client_id` match. The result is tagged with
//! [`AuthenticatedVault::from_cache`] so callers know the data may be stale.
//! See the ADR for why the cache has no production writer yet.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use openwarden::{
    ApiKey, Client, Device, ExposeSecret as _, Kdf, KdfPolicy, MasterKey, SecretString, ServerUrls,
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
/// directly. Six variants (the `Detail` ones) own a `String`: a cause-carrying
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

/// Family message for a rejected server URL, including its hint.
///
/// The hint is already parenthesized. `status_message()` therefore drops it
/// when it appends a retained cause, otherwise the status bar showed two
/// adjacent parenthetical groups. The full message is kept as one constant so
/// the plain and detail variants cannot drift apart.
const INVALID_SERVER_URL_MESSAGE: &str = "サーバー URL が不正です（HTTPS または loopback の HTTP）";
/// The parenthesized hint at the end of [`INVALID_SERVER_URL_MESSAGE`].
const INVALID_SERVER_URL_HINT: &str = "（HTTPS または loopback の HTTP）";

/// Compose a status message from a family message and a retained cause.
///
/// Used by the five non-URL detail families. An empty cause is diagnostic
/// noise, so it contributes no `（…）` suffix: the family message stays
/// verbatim. The URL family needs a separate arm because its family message
/// already ends in a parenthetical hint (see [`INVALID_SERVER_URL_MESSAGE`]).
fn cause_status(family: &'static str, detail: &str) -> String {
    if detail.is_empty() {
        family.to_string()
    } else {
        format!("{family}（{detail}）")
    }
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
            Self::InvalidServerUrl | Self::InvalidServerUrlDetail(_) => INVALID_SERVER_URL_MESSAGE,
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
    /// URL/client setup error the server reported. An empty cause adds no
    /// decoration, and the URL family drops its own hint when a cause is
    /// present so only one parenthesized group is shown.
    pub fn status_message(&self) -> String {
        match self {
            Self::MissingField(field) => format!("{}（{field}）", self.message()),
            // Drop the URL family's own parenthesized hint before appending a
            // cause. The hint is guidance for a bare InvalidServerUrl status;
            // repeating it next to the parser's reason produced a doubled
            // `）（）`. With no detail the full family message stays intact.
            Self::InvalidServerUrlDetail(detail) if !detail.is_empty() => {
                let family = INVALID_SERVER_URL_MESSAGE
                    .strip_suffix(INVALID_SERVER_URL_HINT)
                    .unwrap_or(INVALID_SERVER_URL_MESSAGE);
                cause_status(family, detail)
            }
            // The other five detail families have no parenthesized hint; the
            // shared helper also pins their empty-cause behaviour (no suffix).
            Self::PreloginDetail(detail)
            | Self::KdfRejectedDetail(detail)
            | Self::LoginDetail(detail)
            | Self::SyncDetail(detail)
            | Self::ClientSetupDetail(detail) => cause_status(self.message(), detail),
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
            // `AuthError::Other` holds a `&'static str`, so an owned
            // `AppError::Other(String)` cannot survive this boundary. The
            // generic message is used instead of mislabelling it as a known
            // family; the original text remains in `AppError` before the
            // conversion.
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

// All auth text/length caps live in `crate::limits` so the input layer, the
// login path and the settings layer cannot drift apart. Re-export them here to
// keep the existing `crate::auth::MAX_*` call sites (including the lock-screen
// input state) source-compatible.
pub(crate) use crate::limits::{
    has_format_character, truncate_to_limit, DEFAULT_LOGIN_TIMEOUT, MAX_EMAIL_LEN,
    MAX_SERVER_URL_LEN,
};
pub use crate::limits::{MAX_CLIENT_ID_LEN, MAX_CLIENT_SECRET_LEN, MAX_MASTER_PASSWORD_LEN};

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
    // `valid_email` trims before it counts characters. Apply the same
    // normalization before capping: counting surrounding padding used to cut
    // the tail off an otherwise valid address, silently turning it into a
    // different one (for example a long trailing pad left only "alice" of
    // "alice@example.com"). Trimming first keeps the address intact.
    config.email = config.email.trim().to_string();
    truncate_to_limit(&mut config.email, MAX_EMAIL_LEN);
    truncate_to_limit(&mut config.client_id, MAX_CLIENT_ID_LEN);
    truncate_secret_to_limit(&mut config.client_secret, MAX_CLIENT_SECRET_LEN);
    truncate_secret_to_limit(&mut config.master_password, MAX_MASTER_PASSWORD_LEN);
}

/// A minimal structural check: at most `MAX_EMAIL_LEN` characters, exactly
/// one `@`, no whitespace/control/format characters, no leading/trailing or
/// consecutive dots in either the local part or the domain, and a dotted
/// domain. Regex-level RFC 5322 validation is out of scope for the PoC.
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
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
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
//   (for example Alibaba's 100.100.100.200) are blocked explicitly by
//   [`BLOCKED_METADATA_IPS`] for URL literals, DNS answers and embedded
//   wildcard-DNS labels. Other private/LAN-style ranges stay allowed so
//   self-hosted Vaultwarden instances keep working.
// Do not treat this guard as a complete SSRF boundary.
// ---------------------------------------------------------------------------

/// Non-link-local addresses used by cloud metadata services.
///
/// `100.100.100.200` is Alibaba Cloud's metadata endpoint. It is not in a
/// link-local range, so the address-only guard below would otherwise let it
/// through. Keeping the entry here (rather than blocking all private ranges)
/// preserves self-hosted Vaultwarden instances on ordinary LAN addresses.
const BLOCKED_METADATA_IPS: &[IpAddr] = &[IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))];

/// Whether `ip` is a link-local or a known non-link-local metadata address.
///
/// Distinct from [`is_link_local_ip`] so the existing classifier tests keep
/// pinning the link-local rule alone; this wrapper is what the URL guard uses.
fn is_blocked_metadata_ip(ip: IpAddr) -> bool {
    // IPv4-mapped IPv6 spellings (`::ffff:a.b.c.d`) must be checked against
    // the same IPv4 metadata list. `is_link_local_ip` already unwraps them for
    // the link-local rule, but the explicit Alibaba entry is an IPv4 literal
    // and an `IpAddr::V6` never compares equal to it, so the mapped spelling
    // `::ffff:100.100.100.200` previously slipped past both halves.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    is_link_local_ip(ip) || BLOCKED_METADATA_IPS.contains(&ip)
}

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
///
/// Known constraint: IPv4-*compatible* IPv6 addresses (`::a.b.c.d`, e.g.
/// `::a9fe:a9fe`, the compatible spelling of `169.254.169.254`) are **not**
/// detected. Only `Ipv6Addr::to_ipv4_mapped()` (`::ffff:a.b.c.d`) is unwrapped
/// to IPv4 here, so the compatible form falls through to the `fe80::/10`
/// check and is treated as non-link-local. The whole-host URL path cannot
/// compensate because `url::Url` keeps that literal as an `Ipv6` host. The
/// regression test `ipv4_compatible_ipv6_link_local_is_a_known_blind_spot`
/// pins this behaviour so a fix is an explicit, reviewed change. Do not treat
/// this guard as complete; see the scope comment above.
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
/// is handled by the resolver-backed check. Despite the historical name the
/// check uses [`is_blocked_metadata_ip`], so a known non-link-local metadata
/// address embedded the same way (for example `100.100.100.200.nip.io`) is
/// blocked too.
///
/// Known constraint: only decimal IPv4 spellings are recognized here. A
/// non-decimal IPv4 literal embedded in a DNS name — hexadecimal
/// (`0xa9fea9fe.nip.io`), octal (`0251.0376.0251.0376.nip.io`) or a 32-bit
/// decimal integer (`2852039166.nip.io`) — is not decoded by this
/// network-free classifier, and neither is a link-local IPv6 address encoded
/// as wildcard-DNS labels (`fe80--1.sslip.io`,
/// `fe80-0-0-0-0-0-0-1.nip.io`). A non-decimal IPv4 spelling used as the
/// *whole URL host* is still blocked: `url::Url` applies the WHATWG IPv4
/// parser before [`is_blocked_server_url_with`] sees the host. An embedded spelling is only
/// caught when the resolver returns a link-local answer; the offline path used
/// by [`validate_config`] (and therefore a configuration assembled without
/// DNS) does not. This is recorded rather than fixed in this PoC: adding a
/// WHATWG-equivalent decoder for embedded labels would enlarge the SSRF guard
/// beyond the change scope.
///
/// Known constraint (hyphenated literals with more than four parts): the
/// hyphenated-label branch below only joins **exactly four** parts
/// (`169-254-1-1.nip.io`). A link-local literal split into five or more
/// hyphen-separated components (`169-254-1-1-9.nip.io`) is therefore not
/// decoded here and the network-free classifier **fails open** for that name;
/// only a resolver answer can block it. The regression test
/// `more_than_four_hyphen_parts_fail_open_offline` pins this behaviour. Do not
/// treat this classifier as a complete boundary; see the scope comment above.
fn hostname_embeds_link_local(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = normalized.split('.').collect();
    // Dotted quad as leading labels: 169.254.1.1.nip.io
    for window in labels.windows(4) {
        if let Ok(ip) = window.join(".").parse::<Ipv4Addr>() {
            if is_blocked_metadata_ip(IpAddr::V4(ip)) {
                return true;
            }
        }
    }
    // Hyphenated quad inside one label: 169-254-1-1.nip.io
    for label in &labels {
        let parts: Vec<&str> = label.split('-').collect();
        if parts.len() == 4 {
            if let Ok(ip) = parts.join(".").parse::<Ipv4Addr>() {
                if is_blocked_metadata_ip(IpAddr::V4(ip)) {
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
        Some(url::Host::Ipv4(ip)) => is_blocked_metadata_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => is_blocked_metadata_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => {
            let Some(host) = url.host_str() else {
                return false;
            };
            if is_blocked_metadata_host(host) || hostname_embeds_link_local(host) {
                return true;
            }
            // Any link-local A/AAAA answer blocks the whole name: a rebinding
            // or split-horizon resolver may mix it with a public address.
            resolve(host).iter().copied().any(is_blocked_metadata_ip)
        }
        None => false,
    }
}

/// Resolve a DNS name with the standard library only. Resolution failures are
/// not treated as proof of safety, but openwarden will fail to connect too;
/// the deterministic rules above have already run at that point.
///
/// Testing note: this is the only network-touching branch of the SSRF guard.
/// Link-local answers are tested deterministically through the injected
/// resolver of [`is_blocked_server_url_with`]; the real resolver is exercised
/// only with `localhost`, which resolves from the local hosts file. No test
/// depends on an external DNS server.
fn resolve_host(host: &str) -> Vec<IpAddr> {
    let Ok(addresses) = (host, 0).to_socket_addrs() else {
        return Vec::new();
    };
    addresses.into_iter().map(|socket| socket.ip()).collect()
}

/// Reject metadata servers: link-local literals, known cloud metadata
/// hostnames and IPs (including the non-link-local Alibaba endpoint),
/// wildcard-DNS aliases with an embedded metadata literal, and any DNS name
/// whose current A/AAAA answers include a blocked address.
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

/// Build the API key sent to the server from a validated config.
///
/// Both credential strings are stripped of surrounding whitespace. `client_id`
/// was already trimmed on this path; keeping `client_secret` asymmetric meant a
/// secret copied with a trailing newline (a common artifact of files and QR
/// codes) reached the server untrimmed and failed login even though
/// [`validate_config`] accepts it. That validator already rejects a
/// whitespace-only secret, so trimming here cannot turn a missing value into a
/// present one.
fn api_key_from(config: &AuthConfig) -> ApiKey {
    ApiKey {
        client_id: config.client_id.trim().to_string(),
        client_secret: SecretString::from(config.client_secret.expose_secret().trim().to_string()),
    }
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
    ///
    /// The restore is account-scoped: [`crate::cache::cached_sync_for_detailed`]
    /// receives both the server URL and the user id encoded in the personal
    /// API key's `client_id` (see `user_id_from_client_id`), and refuses a
    /// cache whose stored `profile.id` differs. The failed `/api/sync` itself
    /// supplies no fresh id and `openwarden::Session` has no accessor, so the
    /// API key is the trusted source. A non-`user.` client id fails closed: no
    /// cache is restored, rather than risking another account's vault.
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
    let protected_key = authenticated
        .session
        .protected_key()
        .unwrap_or("")
        .to_string();
    let kdf = authenticated.session.kdf();
    unlock_and_import_with(
        &protected_key,
        kdf,
        &authenticated.master_key,
        authenticated.sync,
        crate::vault_sync::import_logins,
    )
}

/// The four failure branches of [`unlock_and_import`] with the session-derived
/// inputs and the final import step passed in explicitly.
///
/// `openwarden::Session` has no public setter for `protected_key`/`kdf` (they
/// only come from a real login response), and a vault that was just unlocked
/// cannot be locked before the import step. The seam therefore lets a test
/// supply a locally generated protected key and an import stub, covering all
/// four branches with no network and no dependency changes. Production still
/// calls the same openwarden sequence and the real importer; behaviour is
/// unchanged.
fn unlock_and_import_with(
    protected_key: &str,
    kdf: Option<Kdf>,
    master_key: &MasterKey,
    sync: SyncData,
    import: fn(&openwarden::Vault) -> Result<crate::model::Vault, crate::vault_sync::SyncError>,
) -> Result<crate::model::Vault, UnlockError> {
    if protected_key.is_empty() {
        return Err(UnlockError::MissingProtectedKey);
    }
    // Keep the typed errors as causes (`BoxedCause::new`) instead of flattening
    // them into text: the source chain stays reachable through `Error::source()`
    // on the returned `UnlockError` and on the `AppError` it converts to.
    let mut open_vault =
        openwarden::Vault::unlock(master_key, protected_key, kdf).map_err(|error| {
            let detail = error.to_string();
            UnlockError::from(AppError::unlock_failed_cause(
                detail,
                BoxedCause::new(error),
            ))
        })?;
    open_vault.apply_sync(sync).map_err(|error| {
        let detail = error.to_string();
        UnlockError::from(AppError::apply_sync_failed_cause(
            detail,
            BoxedCause::new(error),
        ))
    })?;
    import(&open_vault).map_err(|error| {
        let detail = error.to_string();
        UnlockError::from(AppError::import_failed_cause(
            detail,
            BoxedCause::new(error),
        ))
    })
}

/// Which timer arms the login watchdog.
///
/// Split out from [`authenticate_with_timeout`] so the `checked_add` overflow
/// fallback is directly testable without a network call or a 584-year wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginDeadline {
    /// A representable absolute deadline (`Instant::now() + timeout`).
    At(std::time::Instant),
    /// The absolute deadline overflowed; use smol's relative timer instead.
    Relative(std::time::Duration),
}

/// Decide the watchdog timer while the race is still being set up.
///
/// Keeping this outside the async block preserves the absolute-deadline
/// anchoring described in [`authenticate_with_timeout`]: a slow first poll of
/// the login future cannot delay the start of the timeout.
fn login_deadline(now: std::time::Instant, timeout: std::time::Duration) -> LoginDeadline {
    match now.checked_add(timeout) {
        Some(at) => LoginDeadline::At(at),
        None => LoginDeadline::Relative(timeout),
    }
}

/// The timeout half of the login race.
///
/// Both arms report the same [`AuthError::Timeout`]; the relative form is the
/// fallback chosen by `login_deadline` for an unrepresentable absolute deadline
/// (auth.rs:905-910).
async fn login_watchdog(deadline: LoginDeadline) -> Result<AuthenticatedVault, AuthError> {
    match deadline {
        LoginDeadline::At(at) => {
            smol::Timer::at(at).await;
        }
        LoginDeadline::Relative(duration) => {
            smol::Timer::after(duration).await;
        }
    }
    Err(AuthError::Timeout)
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
    // Anchor the watchdog to the moment the race starts, not to the moment the
    // timer future is first polled. `smol::future::race` polls `login` first;
    // any synchronous work before its first `.await` (config clamping, DNS
    // snapshot, client setup) used to delay the timer's own start and stretch
    // the caller's budget. With an absolute deadline an already-elapsed budget
    // fires on the first poll, which the zero-duration test seam relies on.
    // An unrepresentable deadline is not a reason to skip the watchdog:
    // `login_deadline` selects smol's relative timer with the original
    // duration in that case (auth.rs:905-910).
    let deadline = login_deadline(std::time::Instant::now(), timeout);
    let timer = login_watchdog(deadline);
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

/// The account id encoded in a personal API key's `client_id` (`user.<uuid>`).
///
/// A failed `/api/sync` yields no fresh `profile.id` and the public
/// `openwarden::Session` has no user-id accessor, but the API-key login itself
/// authenticates a specific account: Bitwarden personal client ids carry that
/// account's id after the `user.` prefix. The offline cache is therefore
/// matched by both server URL and this derived id. A client id without the
/// prefix (or with nothing after it) is returned unchanged, so the comparison
/// against the cache's `profile.id` fails closed instead of restoring another
/// account's vault.
fn user_id_from_client_id(client_id: &str) -> &str {
    let trimmed = client_id.trim();
    trimmed
        .strip_prefix("user.")
        .filter(|id| !id.is_empty())
        .unwrap_or(trimmed)
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
///
/// Scope: this function is the **only** consumer of the discarded sync cause,
/// and it runs only when the cache restore also fails. On a *successful*
/// restore `sync_cause` is dropped: [`AuthenticatedVault`] has no field for it,
/// so the success status can only be guided by the `from_cache` flag (stale
/// data warning). The original live-sync failure is not surfaced in that case;
/// this is the current behaviour, recorded explicitly instead of implying a
/// status message that is not produced.
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
    let api_key = api_key_from(config);
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
        // case, as the pre-0.1.1 path did. The account id comes from the
        // personal API key's `client_id`, so the cache is matched by server URL
        // *and* account (see the `from_cache` field docs).
        None => {
            let user_id = user_id_from_client_id(&config.client_id);
            match crate::cache::cached_sync_for_detailed(config.server_url.trim(), user_id) {
                Ok(sync) => (sync, true),
                Err(cache_error) => {
                    return Err(sync_fallback_failure(
                        cache_restore_failure(cache_error),
                        sync_cause,
                    ));
                }
            }
        }
    };
    // KDF derivation is CPU- and memory-heavy; move it off the UI thread.
    //
    // Known constraint: the email is trimmed here but NOT case-folded before
    // `MasterKey::derive`. Bitwarden derives the master key from the account
    // email as stored by the server, so an address entered with different
    // casing yields a different key and unlock fails, even though
    // `validate_config` accepts every casing and no validation error is
    // reported. Lowercasing would silently change the derived key for every
    // existing mixed-case address, so this PoC records the limitation instead
    // of normalizing; the regression test
    // `uppercase_email_is_not_case_folded_before_kdf_is_a_known_constraint`
    // pins that the configured value keeps its case on the way to this call.
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
