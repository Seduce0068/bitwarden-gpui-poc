#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::auth::*;

/// A unique, non-production canary so a leak of the client secret can be
/// detected unambiguously in debug output.
const CLIENT_SECRET_CANARY: &str = "client-secret-CANARY-7f3a9b21";

fn config() -> AuthConfig {
    AuthConfig {
        server_url: "https://vault.example.com".into(),
        client_id: "user.1234".into(),
        client_secret: SecretString::from(CLIENT_SECRET_CANARY.to_string()),
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
    // The debug output really contains both secret fields, so the redaction
    // assertion below has something to act on.
    assert!(rendered.contains("client_secret"), "{rendered}");
    assert!(rendered.contains("master_password"), "{rendered}");
    assert!(!rendered.contains("correct horse"), "{rendered}");
    assert!(
        !rendered.contains(CLIENT_SECRET_CANARY),
        "client_secret value leaked: {rendered}"
    );
}

#[test]
fn email_validation_rejects_malformed_addresses() {
    assert!(valid_email("alice@example.com"));
    // Surrounding whitespace from copy-paste is tolerated.
    assert!(valid_email("  alice@example.com  "));
    assert!(!valid_email(""));
    assert!(!valid_email("alice"));
    assert!(!valid_email("alice@"));
    assert!(!valid_email("@example.com"));
    assert!(!valid_email("alice@example"));
    assert!(!valid_email("a b@example.com"));
    assert!(!valid_email("a@b@example.com"));
    assert!(!valid_email("alice@ex..ample.com"));
    assert!(!valid_email("alice@example."));
    assert!(!valid_email("alice@.example.com"));

    let mut value = config();
    value.email = "not-an-email".into();
    assert_eq!(validate_config(&value), Err(AuthError::InvalidEmail));
}

#[test]
fn link_local_servers_are_blocked() {
    assert!(is_blocked_server_url("http://169.254.169.254"));
    assert!(is_blocked_server_url("http://169.254.1.1:8080"));
    assert!(is_blocked_server_url("http://[fe80::1]"));
    // fe80::/10 spans fe80:: through febf::; fe7f is outside the range.
    assert!(is_blocked_server_url("http://[febf::1]"));
    assert!(!is_blocked_server_url("http://[fe7f::1]"));
    assert!(is_blocked_server_url("http://[::ffff:169.254.169.254]"));
    assert!(is_blocked_server_url("http://0xa9fea9fe"));
    assert!(!is_blocked_server_url("https://vault.example.com"));
    assert!(!is_blocked_server_url(" http://127.0.0.1:8080".trim()));
    assert!(!is_blocked_server_url("http://192.168.1.10"));

    let mut value = config();
    value.server_url = "http://169.254.169.254".into();
    assert_eq!(validate_config(&value), Err(AuthError::BlockedServerUrl));
}

#[test]
fn validation_fails_before_the_timeout_race() {
    let mut invalid = config();
    invalid.client_id.clear();
    let result = smol::block_on(authenticate_with_timeout(
        &invalid,
        "device",
        std::time::Duration::from_millis(0),
    ));
    assert_eq!(result.err(), Some(AuthError::MissingField("client_id")));
}

#[test]
fn error_messages_are_present() {
    for error in [
        UnlockError::MissingProtectedKey,
        UnlockError::UnlockFailed("detail".into()),
        UnlockError::ApplySyncFailed("detail".into()),
        UnlockError::ImportFailed("detail".into()),
    ] {
        assert!(!error.message().is_empty(), "{error:?}");
    }
    for error in [
        AuthError::MissingField("email"),
        AuthError::InvalidServerUrl,
        AuthError::BlockedServerUrl,
        AuthError::InvalidEmail,
        AuthError::ClientSetup,
        AuthError::Prelogin,
        AuthError::Login,
        AuthError::Sync,
        AuthError::KdfRejected,
        AuthError::Timeout,
    ] {
        assert!(!error.message().is_empty());
        assert!(!error.to_string().is_empty());
    }
}
