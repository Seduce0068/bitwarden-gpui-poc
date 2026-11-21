//! One shared error type for the whole application, with a retained cause chain.
//!
//! Five module-level names are aliases of [`AppError`]:
//! [`crate::generator::GeneratorError`], [`crate::vault_sync::SyncError`],
//! [`crate::totp::TotpError`], [`crate::cache::SyncCacheError`] and
//! [`crate::cache::CacheLoadError`]. Those modules keep writing
//! `SyncError::Locked` or `TotpError::Missing`, but the value really is an
//! `AppError` and shares its `Display`, status message and
//! [`std::error::Error::source()`] implementation.
//!
//! The small UI-facing enums are different: [`crate::auth::AuthError`],
//! [`crate::auth::UnlockError`] and [`crate::settings::SettingsLoadError`] are
//! independent enums, not aliases. Each has `From` conversions to and from
//! `AppError`, so a cause-carrying domain failure can cross the UI boundary.
//! `AuthError` and `SettingsLoadError` expose a short `&'static str` family
//! message, while `UnlockError::message()` includes the failure detail and
//! returns an owned `String`.
//!
//! There is no `thiserror` dependency: `Display` and `Error` are implemented by
//! hand. Variants ending in `Cause` (and the cache's `Cache*` variants) keep a
//! [`BoxedCause`], which is returned by `source()` so the underlying failure is
//! still reachable. The plain variants are kept for compatibility with callers
//! that construct an error without a cause; equality treats a plain variant and
//! its cause-carrying counterpart as the same failure.

use std::error::Error;
use std::fmt;

/// An error that only carries text, used when cloning a boxed cause or when a
/// third-party error is not `Send + Sync` and cannot be boxed directly.
#[derive(Debug)]
struct TextCause(String);

impl fmt::Display for TextCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TextCause {}

/// The boxed underlying failure behind [`AppError::source()`].
#[derive(Debug)]
pub struct BoxedCause(Box<dyn Error + Send + Sync>);

impl BoxedCause {
    /// Box a concrete error while keeping its type reachable through
    /// [`Error::source()`].
    pub fn new<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self(Box::new(error))
    }

    /// Box an error-like value that cannot be moved into [`Self::new`], keeping
    /// its rendered text as the cause.
    pub fn text(message: impl Into<String>) -> Self {
        Self(Box::new(TextCause(message.into())))
    }

    /// View the cause as a standard error reference.
    pub fn as_error(&self) -> &(dyn Error + 'static) {
        self.0.as_ref()
    }
}

impl Clone for BoxedCause {
    /// A cloned cause cannot clone the boxed trait object, so it keeps the
    /// original message. The chain is preserved, the concrete type is not.
    fn clone(&self) -> Self {
        Self::text(self.0.to_string())
    }
}

impl fmt::Display for BoxedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for BoxedCause {}

/// Status text for failures that have no counterpart in the small UI-facing
/// error enums. Never reuse a domain-specific message for an unrelated error.
pub(crate) const OTHER_ERROR_MESSAGE: &str = "予期しないエラーが発生しました";

/// A failure from any layer of the application.
#[derive(Debug)]
pub enum AppError {
    // -- authentication (formerly `AuthError`) --
    /// A required field was empty.
    MissingField(&'static str),
    /// The server URL is not a valid HTTPS base URL.
    InvalidServerUrl,
    /// The server URL is not a valid HTTPS base URL; retains the cause.
    InvalidServerUrlCause(BoxedCause),
    /// The server URL points at a link-local address (e.g. cloud metadata).
    BlockedServerUrl,
    /// The email address is malformed.
    InvalidEmail,
    /// The client could not be built.
    ClientSetup,
    /// The client could not be built; retains the cause.
    ClientSetupCause(BoxedCause),
    /// The prelogin call failed.
    Prelogin,
    /// The prelogin call failed; retains the cause.
    PreloginCause(BoxedCause),
    /// The API-key login failed.
    Login,
    /// The API-key login failed; retains the cause.
    LoginCause(BoxedCause),
    /// The sync call failed and no usable cache was available.
    Sync,
    /// The sync call failed; retains the cause.
    SyncCause(BoxedCause),
    /// The KDF policy rejected the account's settings.
    KdfRejected,
    /// The KDF policy rejected the account's settings; retains the cause.
    KdfRejectedCause(BoxedCause),
    /// The login sequence did not finish within the allotted time.
    Timeout,

    // -- unlock (formerly `UnlockError`) --
    /// The token response contained no protected key.
    MissingProtectedKey,
    /// The master key could not decrypt the protected key.
    UnlockFailed(String),
    /// The master key could not decrypt the protected key; retains the cause.
    UnlockFailedCause(String, BoxedCause),
    /// An unlock failure: the formatted status text and the raw detail.
    UnlockFailedStructured(String, String),
    /// The same, retaining the original cause as well.
    UnlockFailedStructuredCause(String, String, BoxedCause),
    /// The sync payload could not be applied to the decrypted vault.
    ApplySyncFailed(String),
    /// The sync payload could not be applied; retains the cause.
    ApplySyncFailedCause(String, BoxedCause),
    /// The decrypted vault could not be converted into the local model.
    ImportFailed(String),
    /// The vault conversion failed; retains the cause.
    ImportFailedCause(String, BoxedCause),

    // -- vault sync (formerly `SyncError`) --
    /// The vault is still locked, so fields cannot be decrypted.
    Locked,
    /// A login's id or fields could not be read.
    InvalidLogin(String),
    /// A sync body could not be parsed; retains the cause.
    InvalidLoginCause(String, BoxedCause),

    // -- cache (formerly `SyncCacheError` / `CacheLoadError`) --
    /// Kept for callers that build a cache error without a cause.
    InvalidCache,
    /// The cached body could not be parsed.
    CacheParse(BoxedCause),
    /// Key material could not be stripped from the body.
    CacheRedact(BoxedCause),
    /// The sanitized body could not be serialized.
    CacheSerialize(BoxedCause),
    /// The cache belongs to a different account.
    UserMismatch,
    /// The cache was fetched from a different server.
    ServerMismatch,
    /// The cache or settings file does not exist yet.
    NotFound,
    /// The file exists but could not be read.
    ReadFailed,
    /// The file exists but could not be read; retains the cause.
    ReadFailedCause(BoxedCause),
    /// The file exists but is not valid JSON.
    ParseFailed,
    /// The file exists but is not valid JSON; retains the cause.
    ParseFailedCause(BoxedCause),
    /// The cache was written by an incompatible version.
    VersionMismatch,
    /// The cached response is older than the accepted offline window.
    CacheExpired,
    /// The cache file or its raw sync body exceeds the accepted size limit.
    CacheTooLarge,

    // -- settings (formerly `SettingsLoadError`) --
    /// The file is larger than `MAX_SETTINGS_BYTES`.
    TooLarge,
    /// The settings file could not be written; keeps both the rendered detail
    /// for the status bar and the original error for `Error::source()`.
    SettingsSaveCause(String, BoxedCause),

    // -- TOTP (formerly `TotpError`) --
    /// The item has no `totp` field.
    Missing,
    /// The field is not a readable secret.
    Invalid,
    /// The field is not a readable secret; retains the cause.
    InvalidCause(BoxedCause),

    // -- generator (formerly `GeneratorError`) --
    /// The OS random source failed.
    RandomUnavailable,
    /// The OS random source failed; retains the cause.
    RandomUnavailableCause(BoxedCause),
    /// The settings would produce an empty character set or result.
    InvalidSettings,
    /// A failure that does not belong to any of the layer-specific domains.
    ///
    /// Used when converting into a smaller UI-facing error type that has no
    /// variant for the original failure, so the status text stays honest
    /// instead of claiming an unrelated cause.
    Other(String),
}

impl AppError {
    /// Construct the status-bar message for an unlock failure.
    pub fn unlock_failed(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self::UnlockFailedStructured(format!("復号キーを取得できません（{detail}）"), detail)
    }

    /// Construct an unlock failure that also retains its cause.
    pub fn unlock_failed_cause(detail: impl Into<String>, cause: BoxedCause) -> Self {
        let detail = detail.into();
        Self::UnlockFailedStructuredCause(
            format!("復号キーを取得できません（{detail}）"),
            detail,
            cause,
        )
    }

    /// Construct the status-bar message for an apply-sync failure.
    pub fn apply_sync_failed(detail: impl Into<String>) -> Self {
        Self::ApplySyncFailed(format!("同期データを取り込めません（{}）", detail.into()))
    }

    /// Construct an apply-sync failure that also retains its cause.
    pub fn apply_sync_failed_cause(detail: impl Into<String>, cause: BoxedCause) -> Self {
        Self::ApplySyncFailedCause(
            format!("同期データを取り込めません（{}）", detail.into()),
            cause,
        )
    }

    /// Construct the status-bar message for a vault-import failure.
    pub fn import_failed(detail: impl Into<String>) -> Self {
        Self::ImportFailed(format!("vault 変換に失敗しました（{}）", detail.into()))
    }

    /// Construct a vault-import failure that also retains its cause.
    pub fn import_failed_cause(detail: impl Into<String>, cause: BoxedCause) -> Self {
        Self::ImportFailedCause(
            format!("vault 変換に失敗しました（{}）", detail.into()),
            cause,
        )
    }

    /// A short message for the status bar, unchanged from the old per-module
    /// `message()` methods.
    pub fn message(&self) -> &str {
        match self {
            Self::UnlockFailed(text) | Self::UnlockFailedCause(text, _) => text,
            Self::UnlockFailedStructured(text, _)
            | Self::UnlockFailedStructuredCause(text, _, _) => text,
            Self::ApplySyncFailed(text) | Self::ApplySyncFailedCause(text, _) => text,
            Self::ImportFailed(text) | Self::ImportFailedCause(text, _) => text,
            Self::MissingField(_) => "認証情報が未入力です",
            Self::InvalidServerUrl | Self::InvalidServerUrlCause(_) => {
                "サーバー URL が不正です（HTTPS または loopback の HTTP）"
            }
            Self::BlockedServerUrl => "サーバー URL が link-local アドレスを指しています",
            Self::InvalidEmail => "メールアドレスの形式が不正です",
            Self::ClientSetup | Self::ClientSetupCause(_) => "クライアントを初期化できませんでした",
            Self::Prelogin | Self::PreloginCause(_) => "サーバー情報の取得に失敗しました",
            Self::Login | Self::LoginCause(_) => "ログインに失敗しました",
            Self::Sync | Self::SyncCause(_) => "同期に失敗しました",
            Self::KdfRejected | Self::KdfRejectedCause(_) => "KDF 設定がポリシーで拒否されました",
            Self::Timeout => "ログインがタイムアウトしました",
            Self::MissingProtectedKey => "復号キーが応答にありません",
            Self::Locked => "vault がロックされています",
            Self::InvalidLogin(_) | Self::InvalidLoginCause(_, _) => {
                "ログイン項目を読み取れませんでした"
            }
            Self::InvalidCache
            | Self::CacheParse(_)
            | Self::CacheRedact(_)
            | Self::CacheSerialize(_) => "キャッシュが破損しています",
            Self::UserMismatch => "キャッシュが別のアカウントのものです",
            Self::ServerMismatch => "キャッシュが別のサーバーのものです",
            Self::NotFound => "設定ファイルが未作成です（既定値を使用）",
            Self::ReadFailed | Self::ReadFailedCause(_) => {
                "設定ファイルを読み込めません（既定値を使用）"
            }
            Self::ParseFailed | Self::ParseFailedCause(_) => {
                "設定ファイルが破損しています（既定値を使用）"
            }
            Self::VersionMismatch => "キャッシュのバージョンに互換性がありません",
            Self::CacheExpired => "キャッシュが有効期限を過ぎています",
            Self::CacheTooLarge => "キャッシュがサイズ上限を超えています",
            Self::TooLarge => "設定ファイルがサイズ上限（1 MiB）を超えています（既定値を使用）",
            Self::Missing => "この項目には TOTP が設定されていません",
            Self::Invalid | Self::InvalidCause(_) => "TOTP シークレットを解釈できません",
            Self::RandomUnavailable | Self::RandomUnavailableCause(_) => {
                "OS の乱数源を利用できません"
            }
            Self::InvalidSettings => "生成設定が不正です（文字種または長さを確認）",
            Self::Other(text) | Self::SettingsSaveCause(text, _) => text,
        }
    }

    /// The detail that distinguishes otherwise identical failures (for
    /// example, which auth field was empty).
    fn detail(&self) -> Option<&str> {
        match self {
            Self::MissingField(field) => Some(field),
            Self::UnlockFailed(text) | Self::UnlockFailedCause(text, _) => Some(text),
            Self::UnlockFailedStructured(_, detail)
            | Self::UnlockFailedStructuredCause(_, detail, _) => Some(detail),
            Self::ApplySyncFailed(text) | Self::ApplySyncFailedCause(text, _) => Some(text),
            Self::ImportFailed(text) | Self::ImportFailedCause(text, _) => Some(text),
            Self::InvalidLogin(text) | Self::InvalidLoginCause(text, _) => Some(text),
            Self::Other(text) => Some(text),
            _ => None,
        }
    }
}

impl Clone for AppError {
    fn clone(&self) -> Self {
        match self {
            Self::InvalidServerUrlCause(cause) => Self::InvalidServerUrlCause(cause.clone()),
            Self::ClientSetupCause(cause) => Self::ClientSetupCause(cause.clone()),
            Self::PreloginCause(cause) => Self::PreloginCause(cause.clone()),
            Self::LoginCause(cause) => Self::LoginCause(cause.clone()),
            Self::SyncCause(cause) => Self::SyncCause(cause.clone()),
            Self::KdfRejectedCause(cause) => Self::KdfRejectedCause(cause.clone()),
            Self::UnlockFailed(detail) => Self::UnlockFailed(detail.clone()),
            Self::UnlockFailedCause(detail, cause) => {
                Self::UnlockFailedCause(detail.clone(), cause.clone())
            }
            Self::UnlockFailedStructured(text, detail) => {
                Self::UnlockFailedStructured(text.clone(), detail.clone())
            }
            Self::UnlockFailedStructuredCause(text, detail, cause) => {
                Self::UnlockFailedStructuredCause(text.clone(), detail.clone(), cause.clone())
            }
            Self::ApplySyncFailed(detail) => Self::ApplySyncFailed(detail.clone()),
            Self::ApplySyncFailedCause(detail, cause) => {
                Self::ApplySyncFailedCause(detail.clone(), cause.clone())
            }
            Self::ImportFailed(detail) => Self::ImportFailed(detail.clone()),
            Self::ImportFailedCause(detail, cause) => {
                Self::ImportFailedCause(detail.clone(), cause.clone())
            }
            Self::InvalidLogin(detail) => Self::InvalidLogin(detail.clone()),
            Self::InvalidLoginCause(detail, cause) => {
                Self::InvalidLoginCause(detail.clone(), cause.clone())
            }
            Self::InvalidCache => Self::InvalidCache,
            Self::CacheParse(cause) => Self::CacheParse(cause.clone()),
            Self::CacheRedact(cause) => Self::CacheRedact(cause.clone()),
            Self::CacheSerialize(cause) => Self::CacheSerialize(cause.clone()),
            Self::ReadFailedCause(cause) => Self::ReadFailedCause(cause.clone()),
            Self::ParseFailedCause(cause) => Self::ParseFailedCause(cause.clone()),
            Self::InvalidCause(cause) => Self::InvalidCause(cause.clone()),
            Self::RandomUnavailableCause(cause) => Self::RandomUnavailableCause(cause.clone()),
            Self::SettingsSaveCause(detail, cause) => {
                Self::SettingsSaveCause(detail.clone(), cause.clone())
            }
            Self::MissingField(field) => Self::MissingField(field),
            Self::InvalidServerUrl => Self::InvalidServerUrl,
            Self::BlockedServerUrl => Self::BlockedServerUrl,
            Self::InvalidEmail => Self::InvalidEmail,
            Self::ClientSetup => Self::ClientSetup,
            Self::Prelogin => Self::Prelogin,
            Self::Login => Self::Login,
            Self::Sync => Self::Sync,
            Self::KdfRejected => Self::KdfRejected,
            Self::Timeout => Self::Timeout,
            Self::MissingProtectedKey => Self::MissingProtectedKey,
            Self::Locked => Self::Locked,
            Self::UserMismatch => Self::UserMismatch,
            Self::ServerMismatch => Self::ServerMismatch,
            Self::NotFound => Self::NotFound,
            Self::ReadFailed => Self::ReadFailed,
            Self::ParseFailed => Self::ParseFailed,
            Self::VersionMismatch => Self::VersionMismatch,
            Self::CacheExpired => Self::CacheExpired,
            Self::CacheTooLarge => Self::CacheTooLarge,
            Self::TooLarge => Self::TooLarge,
            Self::Missing => Self::Missing,
            Self::Invalid => Self::Invalid,
            Self::RandomUnavailable => Self::RandomUnavailable,
            Self::InvalidSettings => Self::InvalidSettings,
            Self::Other(text) => Self::Other(text.clone()),
        }
    }
}

impl PartialEq for AppError {
    /// Two values are the same failure when they render the same status message
    /// and carry the same detail. A boxed cause is deliberately not compared:
    /// it is diagnostic context, not part of the failure's identity.
    fn eq(&self, other: &Self) -> bool {
        self.message() == other.message() && self.detail() == other.detail()
    }
}

impl Eq for AppError {}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidServerUrlCause(cause)
            | Self::ClientSetupCause(cause)
            | Self::PreloginCause(cause)
            | Self::LoginCause(cause)
            | Self::SyncCause(cause)
            | Self::KdfRejectedCause(cause)
            | Self::ReadFailedCause(cause)
            | Self::ParseFailedCause(cause)
            | Self::InvalidCause(cause)
            | Self::RandomUnavailableCause(cause)
            | Self::SettingsSaveCause(_, cause)
            | Self::CacheParse(cause)
            | Self::CacheRedact(cause)
            | Self::CacheSerialize(cause) => Some(cause.as_error()),
            Self::UnlockFailedStructuredCause(_, _, cause)
            | Self::UnlockFailedCause(_, cause)
            | Self::ApplySyncFailedCause(_, cause)
            | Self::ImportFailedCause(_, cause)
            | Self::InvalidLoginCause(_, cause) => Some(cause.as_error()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cause_carrying_variant_keeps_a_source_and_a_message() {
        let cause = || BoxedCause::text("probe");
        let cases: Vec<(&str, AppError)> = vec![
            (
                "invalid_server_url",
                AppError::InvalidServerUrlCause(cause()),
            ),
            ("client_setup", AppError::ClientSetupCause(cause())),
            ("prelogin", AppError::PreloginCause(cause())),
            ("login", AppError::LoginCause(cause())),
            ("sync", AppError::SyncCause(cause())),
            ("kdf", AppError::KdfRejectedCause(cause())),
            (
                "unlock",
                AppError::UnlockFailedCause("detail".into(), cause()),
            ),
            (
                "unlock_structured",
                AppError::UnlockFailedStructuredCause("status".into(), "detail".into(), cause()),
            ),
            (
                "apply_sync",
                AppError::ApplySyncFailedCause("detail".into(), cause()),
            ),
            (
                "import",
                AppError::ImportFailedCause("detail".into(), cause()),
            ),
            (
                "invalid_login",
                AppError::InvalidLoginCause("detail".into(), cause()),
            ),
            ("cache_parse", AppError::CacheParse(cause())),
            ("cache_redact", AppError::CacheRedact(cause())),
            ("cache_serialize", AppError::CacheSerialize(cause())),
            ("read_failed", AppError::ReadFailedCause(cause())),
            ("parse_failed", AppError::ParseFailedCause(cause())),
            (
                "settings_save",
                AppError::SettingsSaveCause("detail".into(), cause()),
            ),
            ("totp_invalid", AppError::InvalidCause(cause())),
        ];
        for (name, error) in cases {
            assert!(!error.message().is_empty(), "{name}: empty message");
            assert!(
                std::error::Error::source(&error).is_some(),
                "{name}: missing source"
            );
        }
    }
}
