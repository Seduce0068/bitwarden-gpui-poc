//! One error type for the whole application, with a retained cause chain.
//!
//! Every module used to define its own error enum. They now alias [`AppError`],
//! so callers keep writing `AuthError::Sync` or `TotpError::Missing` while all
//! failures share one `Display`, one status-bar message and one
//! [`std::error::Error::source()`] implementation.
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

    // -- settings (formerly `SettingsLoadError`) --
    /// The file is larger than `MAX_SETTINGS_BYTES`.
    TooLarge,

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
        Self::UnlockFailed(format!("復号キーを取得できません（{}）", detail.into()))
    }

    /// Construct an unlock failure that also retains its cause.
    pub fn unlock_failed_cause(detail: impl Into<String>, cause: BoxedCause) -> Self {
        Self::UnlockFailedCause(
            format!("復号キーを取得できません（{}）", detail.into()),
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
            Self::VersionMismatch => "キャッシュのバージョンが古いです",
            Self::TooLarge => "設定ファイルがサイズ上限（1 MiB）を超えています（既定値を使用）",
            Self::Missing => "この項目には TOTP が設定されていません",
            Self::Invalid | Self::InvalidCause(_) => "TOTP シークレットを解釈できません",
            Self::RandomUnavailable | Self::RandomUnavailableCause(_) => {
                "OS の乱数源を利用できません"
            }
            Self::InvalidSettings => "生成設定が不正です（文字種または長さを確認）",
            Self::Other(text) => text,
        }
    }

    /// The detail that distinguishes otherwise identical failures (for
    /// example, which auth field was empty).
    fn detail(&self) -> Option<&str> {
        match self {
            Self::MissingField(field) => Some(field),
            Self::UnlockFailed(text) | Self::UnlockFailedCause(text, _) => Some(text),
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

// -- Conversion from the small UI-facing error types -------------------------
//
// `auth` and `settings` keep their own error enums because the UI formats them
// immediately and borrows their messages. These `From` implementations are the
// aggregation point: any layer can hand its failure to `AppError` and the cause
// chain stays available through `Error::source()`.

impl From<crate::auth::AuthError> for AppError {
    fn from(error: crate::auth::AuthError) -> Self {
        use crate::auth::AuthError;
        match error {
            AuthError::MissingField(field) => Self::MissingField(field),
            AuthError::InvalidServerUrl => Self::InvalidServerUrl,
            AuthError::BlockedServerUrl => Self::BlockedServerUrl,
            AuthError::InvalidEmail => Self::InvalidEmail,
            AuthError::ClientSetup => Self::ClientSetup,
            AuthError::Prelogin => Self::Prelogin,
            AuthError::Login => Self::Login,
            AuthError::Sync => Self::Sync,
            AuthError::KdfRejected => Self::KdfRejected,
            AuthError::Timeout => Self::Timeout,
            AuthError::Other(text) => Self::Other(text.to_string()),
        }
    }
}

impl From<AppError> for crate::auth::AuthError {
    fn from(error: AppError) -> Self {
        use crate::auth::AuthError;
        // A cause-carrying variant keeps the status text of its plain sibling;
        // dropping the cause here is the price of the UI's `Copy` error type.
        match error {
            AppError::MissingField(field) => AuthError::MissingField(field),
            AppError::InvalidServerUrl | AppError::InvalidServerUrlCause(_) => {
                AuthError::InvalidServerUrl
            }
            AppError::BlockedServerUrl => AuthError::BlockedServerUrl,
            AppError::InvalidEmail => AuthError::InvalidEmail,
            AppError::ClientSetup | AppError::ClientSetupCause(_) => AuthError::ClientSetup,
            AppError::Prelogin | AppError::PreloginCause(_) => AuthError::Prelogin,
            AppError::Login | AppError::LoginCause(_) => AuthError::Login,
            AppError::Sync | AppError::SyncCause(_) => AuthError::Sync,
            AppError::KdfRejected | AppError::KdfRejectedCause(_) => AuthError::KdfRejected,
            AppError::Timeout => AuthError::Timeout,
            // This type is `Copy`, so an owned detail cannot survive the
            // conversion. An honest generic message is better than silently
            // reporting an unrelated sync failure.
            _ => AuthError::Other(OTHER_ERROR_MESSAGE),
        }
    }
}

/// Strip the prefix that [`AppError::unlock_failed`] adds, so the UI's own
/// formatter does not print it twice.
fn unlock_detail(text: &str, prefix: &str) -> String {
    text.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix('）'))
        .unwrap_or(text)
        .to_string()
}

impl From<crate::auth::UnlockError> for AppError {
    fn from(error: crate::auth::UnlockError) -> Self {
        use crate::auth::UnlockError;
        match error {
            UnlockError::MissingProtectedKey => Self::MissingProtectedKey,
            UnlockError::UnlockFailed(detail) => Self::unlock_failed(detail),
            UnlockError::ApplySyncFailed(detail) => Self::apply_sync_failed(detail),
            UnlockError::ImportFailed(detail) => Self::import_failed(detail),
            UnlockError::Other(detail) => Self::Other(detail),
        }
    }
}

impl From<AppError> for crate::auth::UnlockError {
    fn from(error: AppError) -> Self {
        use crate::auth::UnlockError;
        match error {
            AppError::MissingProtectedKey => UnlockError::MissingProtectedKey,
            AppError::UnlockFailed(text) | AppError::UnlockFailedCause(text, _) => {
                UnlockError::UnlockFailed(unlock_detail(&text, "復号キーを取得できません（"))
            }
            AppError::ApplySyncFailed(text) | AppError::ApplySyncFailedCause(text, _) => {
                UnlockError::ApplySyncFailed(unlock_detail(&text, "同期データを取り込めません（"))
            }
            AppError::ImportFailed(text) | AppError::ImportFailedCause(text, _) => {
                UnlockError::ImportFailed(unlock_detail(&text, "vault 変換に失敗しました（"))
            }
            // Keep the real message here: unlike `AuthError`, this type can
            // own a `String`, so no cause text is lost on conversion.
            unexpected => UnlockError::Other(unexpected.message().to_string()),
        }
    }
}

impl From<crate::settings::SettingsLoadError> for AppError {
    fn from(error: crate::settings::SettingsLoadError) -> Self {
        use crate::settings::SettingsLoadError;
        match error {
            SettingsLoadError::NotFound => Self::NotFound,
            SettingsLoadError::ReadFailed => Self::ReadFailed,
            SettingsLoadError::ParseFailed => Self::ParseFailed,
            SettingsLoadError::TooLarge => Self::TooLarge,
            SettingsLoadError::Other(text) => Self::Other(text.to_string()),
        }
    }
}

impl From<AppError> for crate::settings::SettingsLoadError {
    fn from(error: AppError) -> Self {
        use crate::settings::SettingsLoadError;
        match error {
            AppError::NotFound => SettingsLoadError::NotFound,
            AppError::ReadFailed | AppError::ReadFailedCause(_) => SettingsLoadError::ReadFailed,
            AppError::ParseFailed | AppError::ParseFailedCause(_) => SettingsLoadError::ParseFailed,
            AppError::TooLarge => SettingsLoadError::TooLarge,
            _ => SettingsLoadError::Other(OTHER_ERROR_MESSAGE),
        }
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
            | Self::CacheParse(cause)
            | Self::CacheRedact(cause)
            | Self::CacheSerialize(cause) => Some(cause.as_error()),
            Self::UnlockFailedCause(_, cause)
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
    use crate::auth::{AuthError, UnlockError};
    use crate::settings::SettingsLoadError;

    #[test]
    fn unrelated_errors_are_not_relabeled_as_domain_failures() {
        let unexpected = AppError::RandomUnavailable;
        assert_eq!(
            AuthError::from(unexpected.clone()).message(),
            OTHER_ERROR_MESSAGE,
            "an OS RNG failure must be reported as an unexpected failure"
        );
        assert_eq!(
            UnlockError::from(unexpected.clone()).message(),
            unexpected.message(),
            "UnlockError owns its detail, so the original message must survive"
        );
        assert_eq!(
            SettingsLoadError::from(unexpected.clone()).message(),
            OTHER_ERROR_MESSAGE,
            "an unrelated failure must not claim a settings-specific cause"
        );
    }

    #[test]
    fn other_variants_round_trip_without_losing_the_status_text() {
        let auth = AuthError::from(AppError::Other("固有の認証失敗".to_string()));
        assert_eq!(auth.message(), OTHER_ERROR_MESSAGE);
        assert_eq!(AppError::from(auth).message(), OTHER_ERROR_MESSAGE);

        let unlock = UnlockError::Other("固有の失敗".to_string());
        assert_eq!(AppError::from(unlock).message(), "固有の失敗");

        let settings = SettingsLoadError::Other("設定固有の失敗");
        assert_eq!(AppError::from(settings).message(), "設定固有の失敗");
    }
}
