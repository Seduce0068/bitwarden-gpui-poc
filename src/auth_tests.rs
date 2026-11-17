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
fn whitespace_only_secrets_are_rejected() {
    let mut value = config();
    value.client_secret = SecretString::from(" \t\n\u{3000}".to_string());
    assert_eq!(
        validate_config(&value),
        Err(AuthError::MissingField("client_secret"))
    );

    let mut value = config();
    value.master_password = SecretString::from(" \t\n\u{3000}".to_string());
    assert_eq!(
        validate_config(&value),
        Err(AuthError::MissingField("master_password"))
    );
}

#[test]
fn email_validation_rejects_format_characters() {
    // Zero-width space/joiner, word joiner, BOM, bidi controls, Arabic letter
    // mark and soft hyphen are all in the Unicode Cf category.
    for invisible in [
        '\u{200b}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{202a}', '\u{202e}', '\u{061c}',
        '\u{ad}',
    ] {
        let email = format!("alice{invisible}@example.com");
        assert!(
            !valid_email(&email),
            "Cf character U+{:04X} was accepted",
            invisible as u32
        );
        let mut value = config();
        value.email = email;
        assert_eq!(validate_config(&value), Err(AuthError::InvalidEmail));
    }
    // A format character in the domain is rejected as well.
    assert!(!valid_email("alice@exa\u{200d}mple.com"));
    // Ordinary non-ASCII letters are still fine.
    assert!(valid_email("\u{e4}lice@example.com"));
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

#[test]
fn email_validation_enforces_the_254_character_ceiling() {
    let suffix = "@example.com";
    let local_len = MAX_EMAIL_LEN - suffix.len();
    let at_limit = format!("{}{suffix}", "a".repeat(local_len));
    assert_eq!(at_limit.chars().count(), MAX_EMAIL_LEN);
    assert!(valid_email(&at_limit));

    let too_long = format!("{}{suffix}", "a".repeat(local_len + 1));
    assert_eq!(too_long.chars().count(), MAX_EMAIL_LEN + 1);
    assert!(!valid_email(&too_long));

    let mut value = config();
    value.email = too_long;
    assert_eq!(validate_config(&value), Err(AuthError::InvalidEmail));

    // The ceiling counts characters, not bytes: multibyte letters stay valid.
    let multibyte = format!("{}@example.com", "あ".repeat(local_len));
    assert_eq!(multibyte.chars().count(), MAX_EMAIL_LEN);
    assert!(valid_email(&multibyte));
}

#[test]
fn clamp_caps_every_field_without_reporting_an_error() {
    let mut value = AuthConfig {
        server_url: format!(
            "https://vault.example.com/{}",
            "s".repeat(MAX_SERVER_URL_LEN)
        ),
        client_id: "i".repeat(MAX_CLIENT_ID_LEN + 10),
        client_secret: SecretString::from("x".repeat(MAX_CLIENT_SECRET_LEN + 10)),
        // Truncation keeps the leading prefix, so put the valid address at the
        // front and pad the domain tail; the capped result stays deliverable.
        email: format!("a@example.com{}", "b".repeat(MAX_EMAIL_LEN)),
        master_password: SecretString::from("p".repeat(MAX_MASTER_PASSWORD_LEN + 10)),
    };

    clamp_auth_config(&mut value);

    assert_eq!(value.server_url.chars().count(), MAX_SERVER_URL_LEN);
    assert_eq!(value.client_id.chars().count(), MAX_CLIENT_ID_LEN);
    assert_eq!(
        value.client_secret.expose_secret().chars().count(),
        MAX_CLIENT_SECRET_LEN
    );
    assert_eq!(value.email.chars().count(), MAX_EMAIL_LEN);
    assert_eq!(
        value.master_password.expose_secret().chars().count(),
        MAX_MASTER_PASSWORD_LEN
    );
    // The retained text is the original prefix, not a substituted value.
    assert!(value.client_id.chars().all(|ch| ch == 'i'));
    assert!(value
        .client_secret
        .expose_secret()
        .chars()
        .all(|ch| ch == 'x'));
    // Truncation keeps the config usable; no length-only AuthError is raised.
    assert_eq!(validate_config(&value), Ok(()));

    // Re-applying the cap is a no-op.
    let before = (
        value.server_url.clone(),
        value.client_id.clone(),
        value.client_secret.expose_secret().to_string(),
        value.email.clone(),
        value.master_password.expose_secret().to_string(),
    );
    clamp_auth_config(&mut value);
    assert_eq!(
        (
            value.server_url.as_str(),
            value.client_id.as_str(),
            value.client_secret.expose_secret(),
            value.email.as_str(),
            value.master_password.expose_secret(),
        ),
        (
            before.0.as_str(),
            before.1.as_str(),
            before.2.as_str(),
            before.3.as_str(),
            before.4.as_str(),
        )
    );
}

#[test]
fn truncation_never_splits_a_utf8_character() {
    let mut value = "あいうえお".to_string();
    truncate_to_limit(&mut value, 2);
    assert_eq!(value, "あい");
    // A limit past the end is a no-op; zero clears the whole value.
    truncate_to_limit(&mut value, 10);
    assert_eq!(value, "あい");
    truncate_to_limit(&mut value, 0);
    assert!(value.is_empty());
}
