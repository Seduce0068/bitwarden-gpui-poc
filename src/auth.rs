//! Authentication and sync orchestration built on `openwarden`.
//!
//! Network calls are isolated in [`authenticate`]. Everything that can be
//! checked without a server lives in [`validate_config`], so the important
//! input rules are covered by deterministic tests.

use openwarden::{
    ApiKey, Client, Device, ExposeSecret as _, KdfPolicy, MasterKey, SecretString, ServerUrls,
    Session, SyncData,
};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// A required field was empty.
    MissingField(&'static str),
    /// The server URL is not a valid HTTPS base URL.
    InvalidServerUrl,
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
}

impl AuthError {
    /// A short message for the status bar.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MissingField(_) => "認証情報が未入力です",
            Self::InvalidServerUrl => "サーバー URL が不正です（HTTPS または loopback の HTTP）",
            Self::ClientSetup => "クライアントを初期化できませんでした",
            Self::Prelogin => "サーバー情報の取得に失敗しました",
            Self::Login => "ログインに失敗しました",
            Self::Sync => "同期に失敗しました",
            Self::KdfRejected => "KDF 設定がポリシーで拒否されました",
        }
    }
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AuthError {}

/// Validate everything that does not require a network round trip.
///
/// # Errors
///
/// [`AuthError::MissingField`] for an empty field, or
/// [`AuthError::InvalidServerUrl`] for a URL `openwarden` rejects.
pub fn validate_config(config: &AuthConfig) -> Result<(), AuthError> {
    if config.server_url.trim().is_empty() {
        return Err(AuthError::MissingField("server_url"));
    }
    if config.client_id.trim().is_empty() {
        return Err(AuthError::MissingField("client_id"));
    }
    if config.client_secret.expose_secret().is_empty() {
        return Err(AuthError::MissingField("client_secret"));
    }
    if config.email.trim().is_empty() {
        return Err(AuthError::MissingField("email"));
    }
    if config.master_password.expose_secret().is_empty() {
        return Err(AuthError::MissingField("master_password"));
    }
    ServerUrls::self_hosted(config.server_url.trim()).map_err(|_| AuthError::InvalidServerUrl)?;
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
}

/// Log in and fetch the vault data.
///
/// The KDF derivation is CPU- and memory-heavy; callers should run this
/// future on a background task so the UI stays responsive.
///
/// # Errors
///
/// The corresponding [`AuthError`] variant when validation, login, sync or
/// key derivation fails.
pub async fn authenticate(
    config: &AuthConfig,
    device_identifier: &str,
) -> Result<AuthenticatedVault, AuthError> {
    validate_config(config)?;
    let urls = ServerUrls::self_hosted(config.server_url.trim())
        .map_err(|_| AuthError::InvalidServerUrl)?;
    let client = Client::new(urls, device_for_installation(device_identifier))
        .map_err(|_| AuthError::ClientSetup)?;
    let kdf = client
        .prelogin(config.email.trim())
        .await
        .map_err(|_| AuthError::Prelogin)?;
    let api_key = ApiKey {
        client_id: config.client_id.trim().to_string(),
        client_secret: config.client_secret.clone(),
    };
    let session = client
        .login_api_key(&api_key)
        .await
        .map_err(|_| AuthError::Login)?;
    let sync = client.sync(&session).await.map_err(|_| AuthError::Sync)?;
    // KDF derivation is CPU- and memory-heavy; move it off the UI thread.
    let password = config.master_password.clone();
    let email = config.email.trim().to_string();
    let policy = KdfPolicy::default();
    let master_key = smol::unblock(move || MasterKey::derive(&password, &email, &kdf, &policy))
        .await
        .map_err(|_| AuthError::KdfRejected)?;
    Ok(AuthenticatedVault {
        session,
        sync,
        master_key,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn config() -> AuthConfig {
        AuthConfig {
            server_url: "https://vault.example.com".into(),
            client_id: "user.1234".into(),
            client_secret: SecretString::from("secret".to_string()),
            email: "alice@example.com".into(),
            master_password: SecretString::from("correct horse".to_string()),
        }
    }

    #[test]
    fn valid_config_passes_validation() {
        assert_eq!(validate_config(&config()), Ok(()));
    }

    #[test]
    fn every_empty_field_is_rejected() {
        let mut value = config();
        value.server_url.clear();
        assert_eq!(
            validate_config(&value),
            Err(AuthError::MissingField("server_url"))
        );

        let mut value = config();
        value.client_id = "  ".into();
        assert_eq!(
            validate_config(&value),
            Err(AuthError::MissingField("client_id"))
        );

        let mut value = config();
        value.client_secret = SecretString::from(String::new());
        assert_eq!(
            validate_config(&value),
            Err(AuthError::MissingField("client_secret"))
        );

        let mut value = config();
        value.email.clear();
        assert_eq!(
            validate_config(&value),
            Err(AuthError::MissingField("email"))
        );

        let mut value = config();
        value.master_password = SecretString::from(String::new());
        assert_eq!(
            validate_config(&value),
            Err(AuthError::MissingField("master_password"))
        );
    }

    #[test]
    fn insecure_and_malformed_urls_are_rejected() {
        let mut value = config();
        value.server_url = "http://vault.example.com".into();
        assert_eq!(validate_config(&value), Err(AuthError::InvalidServerUrl));

        let mut value = config();
        value.server_url = "not a url".into();
        assert_eq!(validate_config(&value), Err(AuthError::InvalidServerUrl));

        // A loopback http URL is the one exception openwarden allows.
        let mut value = config();
        value.server_url = "http://127.0.0.1:8080".into();
        assert_eq!(validate_config(&value), Ok(()));
    }

    #[test]
    fn device_is_stable_and_typed_for_linux() {
        let device = device_for_installation("install-1234");
        assert_eq!(device.identifier, "install-1234");
        assert_eq!(device.device_type, Device::LINUX_CLI);
        assert_eq!(device.name, "Bitwarden GPUI PoC");
    }

    #[test]
    fn debug_output_does_not_leak_secrets() {
        let rendered = format!("{:?}", config());
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(!rendered.contains("correct horse"), "{rendered}");
    }

    #[test]
    fn error_messages_are_present() {
        for error in [
            AuthError::MissingField("email"),
            AuthError::InvalidServerUrl,
            AuthError::ClientSetup,
            AuthError::Prelogin,
            AuthError::Login,
            AuthError::Sync,
            AuthError::KdfRejected,
        ] {
            assert!(!error.message().is_empty());
            assert!(!error.to_string().is_empty());
        }
    }
}
