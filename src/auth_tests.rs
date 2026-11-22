#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use super::{is_blocked_server_url_with, is_blocked_server_url_without_dns, is_link_local_ip};
use crate::auth::*;
use crate::error::OTHER_ERROR_MESSAGE;
use openwarden::{EncString, MasterKey};

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
fn device_for_installation_forwards_the_identifier_verbatim() {
    // Pure constructor check: every caller builds the openwarden `Device` from
    // the same persisted string, so the identifier reaches the network layer
    // unchanged. This test deliberately does not perform a sync (no network).
    let id = crate::settings::generate_device_id().unwrap();
    let first = device_for_installation(&id);
    let resync = device_for_installation(&id);
    assert_eq!(first.identifier, id);
    assert_eq!(resync.identifier, first.identifier);
    assert_eq!(first.name, resync.name);
    assert_eq!(first.device_type, resync.device_type);

    let another_installation =
        device_for_installation(&crate::settings::generate_device_id().unwrap());
    assert_ne!(another_installation.identifier, first.identifier);
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
    // The local part follows the same dot rules as the domain: dot-atom
    // cannot start, end, or contain consecutive dots.
    assert!(!valid_email(".alice@example.com"));
    assert!(!valid_email("alice.@example.com"));
    assert!(!valid_email("al..ice@example.com"));
    assert!(!valid_email(".alice.@example.com"));
    assert!(valid_email("al.ice@example.com"));

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
    // Literal rules are network-free; use the pure form for DNS-looking names
    // so the deterministic test suite never performs a real lookup.
    assert!(!is_blocked_server_url_without_dns(
        "https://vault.example.com"
    ));
    assert!(!is_blocked_server_url(" http://127.0.0.1:8080".trim()));
    assert!(!is_blocked_server_url("http://192.168.1.10"));

    let mut value = config();
    value.server_url = "http://169.254.169.254".into();
    assert_eq!(validate_config(&value), Err(AuthError::BlockedServerUrl));
}

#[test]
fn link_local_ip_classification_covers_mapped_and_v6_forms() {
    assert!(is_link_local_ip("169.254.0.1".parse().unwrap()));
    assert!(is_link_local_ip("169.254.169.254".parse().unwrap()));
    assert!(!is_link_local_ip("169.255.0.1".parse().unwrap()));
    assert!(is_link_local_ip("fe80::1".parse().unwrap()));
    assert!(is_link_local_ip("febf::ffff".parse().unwrap()));
    assert!(!is_link_local_ip("fec0::1".parse().unwrap()));
    assert!(is_link_local_ip("::ffff:169.254.169.254".parse().unwrap()));
    assert!(!is_link_local_ip("::ffff:192.168.1.1".parse().unwrap()));
}

#[test]
fn known_metadata_hostnames_are_blocked_without_dns() {
    for value in [
        "http://metadata.google.internal",
        "https://metadata.google.internal/",
        "http://metadata.google.internal.:80",
        "http://METADATA.GOOGLE.INTERNAL",
        "http://metadata.goog",
        "http://metadata",
        "http://instance-data",
        "http://instance-data.ec2.internal/latest/meta-data",
    ] {
        assert!(is_blocked_server_url(value), "{value}");
        assert!(is_blocked_server_url_without_dns(value), "{value}");
    }
    // A name that merely ends with / contains the blocked name stays allowed.
    assert!(!is_blocked_server_url_without_dns(
        "https://not-metadata.google.internal"
    ));
    assert!(!is_blocked_server_url_without_dns(
        "https://metadata.google.internal.example.com"
    ));

    let mut value = config();
    value.server_url = "http://metadata.google.internal".into();
    assert_eq!(validate_config(&value), Err(AuthError::BlockedServerUrl));
}

#[test]
fn wildcard_dns_aliases_with_embedded_link_local_literals_are_blocked() {
    // No DNS is needed: the address encoded in the hostname is enough.
    for value in [
        "http://169.254.169.254.nip.io",
        "https://169.254.1.1.sslip.io",
        "http://169-254-169-254.nip.io",
    ] {
        assert!(is_blocked_server_url_without_dns(value), "{value}");
    }
    assert!(!is_blocked_server_url_without_dns("https://1.1.1.1.nip.io"));
    assert!(!is_blocked_server_url_without_dns(
        "https://192.168.1.10.nip.io"
    ));

    // The public validation entry point must reach the same check, so a
    // credential-carrying config cannot bypass it by using an alias.
    for value in [
        "http://169.254.169.254.nip.io",
        "https://169.254.1.1.sslip.io",
        "http://169-254-169-254.nip.io",
    ] {
        let mut config = config();
        config.server_url = value.into();
        assert_eq!(
            validate_config(&config),
            Err(AuthError::BlockedServerUrl),
            "{value}"
        );
    }
}

#[test]
fn dns_answers_are_checked_for_link_local_addresses() {
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let lan: IpAddr = "192.168.1.10".parse().unwrap();
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    let v6_link_local: IpAddr = "fe80::1".parse().unwrap();

    // A split-horizon / rebinding answer mixing public and link-local is
    // rejected as a whole.
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { vec![public, metadata] }
    ));
    // IPv6 link-local answers are rejected too.
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { vec![public, v6_link_local] }
    ));
    // Public-only or LAN answers stay allowed, as does a failed lookup.
    assert!(!is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { vec![public] }
    ));
    assert!(!is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { vec![lan] }
    ));
    assert!(!is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { Vec::new() }
    ));

    // Literal / known-metadata hosts are classified before any resolver call.
    assert!(is_blocked_server_url_with("http://169.254.1.1", |_| {
        panic!("literal host must not trigger DNS")
    }));
    assert!(is_blocked_server_url_with(
        "http://metadata.google.internal",
        |_| panic!("metadata hostname must not trigger DNS")
    ));
}

#[test]
fn real_resolver_branch_is_exercised_with_localhost_only() {
    // `resolve_host` is the only network-touching branch of the SSRF guard
    // (auth.rs:525-542). `localhost` resolves from the local hosts file, so
    // this test needs no external DNS; loopback is deliberately allowed.
    let resolved = super::resolve_host("localhost");
    assert!(!resolved.is_empty(), "localhost must resolve locally");
    assert!(resolved.iter().any(|ip| ip.is_loopback()), "{resolved:?}");
    assert!(!is_blocked_server_url("http://localhost:8080"));

    // Link-local answers remain covered by the injected resolver, so the
    // security-relevant DNS rule is deterministic and network-free.
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| vec![metadata]
    ));
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

#[test]
fn secret_clamp_never_splits_a_utf8_character() {
    let long = "あ".repeat(MAX_CLIENT_SECRET_LEN + 2);
    let mut secret = SecretString::from(long.clone());
    super::truncate_secret_to_limit(&mut secret, MAX_CLIENT_SECRET_LEN);

    let clamped = secret.expose_secret();
    assert_eq!(clamped.chars().count(), MAX_CLIENT_SECRET_LEN);
    assert_eq!(clamped, "あ".repeat(MAX_CLIENT_SECRET_LEN));
    assert!(clamped.is_char_boundary(clamped.len()));
    // The caller's original string is untouched by the SecretString clamp.
    assert_eq!(long.chars().count(), MAX_CLIENT_SECRET_LEN + 2);

    let mut two = SecretString::from("あい".to_string());
    super::truncate_secret_to_limit(&mut two, 1);
    assert_eq!(two.expose_secret(), "あ");
    super::truncate_secret_to_limit(&mut two, 0);
    assert!(two.expose_secret().is_empty());
}

#[test]
fn secret_clamp_is_a_no_op_when_the_value_fits() {
    // `char_boundary_at` returns None for a value at or under the limit, so
    // truncate_secret_to_limit returns before replacing the buffer
    // (auth.rs:349-355). The same SecretString instance and its contents must
    // survive unchanged — in particular, no zeroizing of an in-bounds secret.
    let mut secret = SecretString::from("short-secret".to_string());
    super::truncate_secret_to_limit(&mut secret, 100);
    assert_eq!(secret.expose_secret(), "short-secret");

    // Exactly at the limit is still a no-op (the boundary is just past the end).
    let at_limit = "あ".repeat(10);
    let mut secret = SecretString::from(at_limit.clone());
    super::truncate_secret_to_limit(&mut secret, 10);
    assert_eq!(secret.expose_secret(), at_limit);
}

#[test]
fn api_key_trims_surrounding_whitespace_from_both_credentials() {
    let mut value = config();
    value.client_id = "  user.1234\t".to_string();
    value.client_secret = SecretString::from(" \tsecret-value\n".to_string());

    let api_key = super::api_key_from(&value);

    assert_eq!(api_key.client_id, "user.1234");
    assert_eq!(api_key.client_secret.expose_secret(), "secret-value");
    // The helper builds a fresh key; the caller's config is unchanged.
    assert_eq!(value.client_id, "  user.1234\t");
    assert_eq!(value.client_secret.expose_secret(), " \tsecret-value\n");
    // Validation trims too, so a padded-but-present secret stays acceptable.
    assert_eq!(validate_config(&value), Ok(()));
}

#[test]
fn cache_restore_failures_are_reported_by_cause() {
    use crate::error::{AppError, BoxedCause};

    assert_eq!(cache_restore_failure(AppError::NotFound), AuthError::Sync);
    assert_eq!(
        cache_restore_failure(AppError::ReadFailedCause(BoxedCause::text("denied"))).message(),
        "同期に失敗しました（キャッシュを読み込めません）"
    );
    assert_eq!(
        cache_restore_failure(AppError::CacheParse(BoxedCause::text("bad json"))).message(),
        "同期に失敗しました（キャッシュが破損しています）"
    );
    assert_eq!(
        cache_restore_failure(AppError::VersionMismatch).message(),
        "同期に失敗しました（キャッシュのバージョンに互換性がありません）"
    );
    assert_eq!(
        cache_restore_failure(AppError::ServerMismatch).message(),
        "同期に失敗しました（キャッシュが別のサーバーのものです）"
    );
}

#[test]
fn unrelated_cache_errors_are_not_called_corrupt() {
    let message = cache_restore_failure(AppError::RandomUnavailable).message();
    assert!(!message.contains("破損"), "{message}");
    assert_ne!(message, AuthError::Sync.message());
}

#[test]
fn expired_cache_message_reaches_the_status_bar() {
    assert_eq!(
        cache_restore_failure(AppError::CacheExpired).message(),
        "同期に失敗しました（キャッシュが有効期限を過ぎています）"
    );
}

#[test]
fn cache_too_large_message_reaches_the_status_bar() {
    assert_eq!(
        cache_restore_failure(AppError::CacheTooLarge).message(),
        "同期に失敗しました（キャッシュがサイズ上限を超えています）"
    );
}

use crate::auth::{AuthError, UnlockError};

#[test]
fn unlock_detail_survives_a_structural_round_trip() {
    // A detail that itself resembles the formatted message used to be mangled
    // by the prefix/suffix stripping conversion.
    let detail = "復号キーを取得できません（混入）";
    let app = AppError::unlock_failed(detail);
    assert_eq!(
        app.message(),
        format!("復号キーを取得できません（{detail}）")
    );
    let converted = crate::auth::UnlockError::from(app);
    assert!(
        matches!(converted, UnlockError::UnlockFailed(ref restored) if restored == detail),
        "raw detail must survive verbatim: {converted:?}"
    );

    let with_cause =
        AppError::unlock_failed_cause("cause-detail", BoxedCause::text("original io failure"));
    assert!(std::error::Error::source(&with_cause).is_some());
    let converted = crate::auth::UnlockError::from(with_cause);
    // The raw detail and the typed cause both survive the UI boundary now.
    assert!(
        matches!(converted, UnlockError::UnlockFailedCause(ref restored, _) if restored == "cause-detail"),
        "cause-carrying detail must survive: {converted:?}"
    );
    assert!(std::error::Error::source(&converted).is_some());
    assert_eq!(converted, UnlockError::UnlockFailed("cause-detail".into()));
}

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
}

#[test]
fn auth_error_other_keeps_its_text_until_the_ui_boundary() {
    // `AuthError::Other` is the honest fallback for failures this small enum
    // cannot describe. Its text is the Display/message/status value and is
    // kept when converting to `AppError`. The reverse conversion cannot keep
    // an owned String because `AuthError::Other` holds `&'static str`, so it
    // falls back to the generic message rather than mislabelling the failure
    // as a known family (auth.rs:198, 239).
    let error = AuthError::Other("unexpected OS RNG failure");
    assert_eq!(error.message(), "unexpected OS RNG failure");
    assert_eq!(error.to_string(), "unexpected OS RNG failure");
    assert_eq!(error.status_message(), "unexpected OS RNG failure");
    assert_eq!(error, AuthError::Other("unexpected OS RNG failure"));
    assert_ne!(error, AuthError::Other("different text"));
    assert_ne!(error, AuthError::Sync);

    let app = AppError::from(error.clone());
    assert!(matches!(&app, AppError::Other(text) if text == "unexpected OS RNG failure"));
    let restored = AuthError::from(app);
    assert_eq!(
        restored,
        AuthError::Other(crate::error::OTHER_ERROR_MESSAGE)
    );
    assert_ne!(restored, AuthError::Sync);
}

#[test]
fn unlock_detail_does_not_add_a_second_prefix_when_text_has_no_suffix() {
    // `unlock_detail` strips prefix+suffix as a pair (auth.rs:250-255). A
    // legacy message that carries the prefix but was truncated before the
    // closing `）` must be kept verbatim: splitting the two operations would
    // strip the prefix alone and then re-add it, producing a doubled prefix.
    for text in [
        "復号キーを取得できません（truncated detail",
        "同期データを取り込めません（truncated detail",
        "vault 変換に失敗しました（truncated detail",
    ] {
        let small = UnlockError::from(AppError::ImportFailed(text.to_string()));
        assert_eq!(
            small,
            UnlockError::ImportFailed(text.to_string()),
            "prefix-only text must not be rewritten: {small:?}"
        );
        let restored = AppError::from(small);
        assert_eq!(
            restored.message(),
            AppError::import_failed(text).message(),
            "the status bar must not show a doubled prefix: {restored:?}"
        );
    }
    // A fully decorated legacy message is still reduced to its raw detail.
    let decorated = UnlockError::from(AppError::ImportFailed(
        "vault 変換に失敗しました（raw detail）".into(),
    ));
    assert_eq!(decorated, UnlockError::ImportFailed("raw detail".into()));
}

#[test]
fn missing_field_status_message_names_the_offending_field() {
    for field in [
        "server_url",
        "client_id",
        "client_secret",
        "email",
        "master_password",
    ] {
        let error = AuthError::MissingField(field);
        assert_eq!(error.message(), "認証情報が未入力です");
        let status = error.status_message();
        assert!(status.contains(field), "{status}");
        assert!(status.contains(error.message()), "{status}");
    }
}

#[test]
fn login_cause_detail_survives_conversion_to_auth_error() {
    use crate::error::BoxedCause;

    let app = AppError::LoginCause(BoxedCause::text("login returned HTTP 400 (invalid_client)"));
    let small = AuthError::from(app);
    assert_eq!(small.message(), AuthError::Login.message());
    assert!(small.status_message().contains("invalid_client"));

    // Converting back keeps the detail as a cause instead of collapsing to the
    // plain `Login` variant; `AppError`'s PartialEq still treats both as equal.
    let restored = AppError::from(small);
    assert!(matches!(&restored, AppError::LoginCause(_)));
    assert!(std::error::Error::source(&restored).is_some());
    assert_eq!(restored, AppError::Login);
}

#[test]
fn sync_cause_detail_survives_conversion_to_auth_error() {
    use crate::error::BoxedCause;

    let small = AuthError::from(AppError::SyncCause(BoxedCause::text("HTTP timeout")));
    assert_eq!(small.message(), AuthError::Sync.message());
    assert!(small.status_message().contains("HTTP timeout"));

    let from_parse = AuthError::from(AppError::InvalidLoginCause(
        "bad sync key casing".into(),
        BoxedCause::text("bad sync key casing"),
    ));
    assert_eq!(from_parse.message(), AuthError::Sync.message());
    assert!(from_parse.status_message().contains("bad sync key casing"));
}

#[test]
fn sync_fallback_failure_keeps_both_reasons() {
    use crate::error::BoxedCause;

    let fallback = cache_restore_failure(AppError::CacheParse(BoxedCause::text("corrupt")));
    let combined = super::sync_fallback_failure(
        fallback.clone(),
        Some(AppError::SyncCause(BoxedCause::text("HTTP 503"))),
    );
    assert_eq!(combined.message(), AuthError::Sync.message());
    assert!(
        combined.status_message().contains("破損"),
        "{}",
        combined.status_message()
    );
    assert!(combined.status_message().contains("HTTP 503"));
    assert!(
        !combined
            .status_message()
            .contains("同期に失敗しました（同期に失敗しました"),
        "the family message must not be prefixed twice: {}",
        combined.status_message()
    );

    // With no discarded sync error the tested cache status is unchanged.
    assert_eq!(
        super::sync_fallback_failure(fallback.clone(), None),
        fallback
    );
}

#[test]
fn email_validation_rejects_cc_control_characters() {
    // Cc is not whitespace, so `is_whitespace` alone let NUL and C1 controls
    // through. They must be rejected like the Cf characters in the sibling
    // regression test.
    for control in ['\u{0}', '\u{1}', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}'] {
        let email = format!("alice{control}@example.com");
        assert!(
            !valid_email(&email),
            "Cc character U+{:04X} was accepted",
            control as u32
        );
        let mut value = config();
        value.email = email;
        assert_eq!(validate_config(&value), Err(AuthError::InvalidEmail));
    }
    assert!(!valid_email("alice@exa\u{0}mple.com"));
}

#[test]
fn unlock_error_cause_survives_a_round_trip() {
    use crate::error::BoxedCause;

    let error = UnlockError::UnlockFailedCause(
        "bad key".into(),
        BoxedCause::text("original decryption failure"),
    );
    assert!(std::error::Error::source(&error).is_some());
    let app = AppError::from(error);
    assert!(matches!(
        &app,
        AppError::UnlockFailedStructuredCause(_, _, _)
    ));
    let restored = UnlockError::from(app);

    // The cause-carrying variant equals its plain sibling (diagnostic context
    // is not identity), and both render the same status text.
    assert_eq!(restored, UnlockError::UnlockFailed("bad key".into()));
    assert_eq!(restored.message(), "復号キーを取得できません（bad key）");
    match restored {
        UnlockError::UnlockFailedCause(detail, cause) => {
            assert_eq!(detail, "bad key");
            assert_eq!(cause.to_string(), "original decryption failure");
        }
        other => panic!("cause was dropped: {other:?}"),
    }
}

#[test]
fn boxed_cause_new_keeps_the_source_chain() {
    use crate::error::BoxedCause;
    use std::fmt;

    #[derive(Debug)]
    struct Inner(&'static str);
    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Inner {}

    #[derive(Debug)]
    struct Outer(Inner);
    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer failure")
        }
    }
    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    let app = AppError::LoginCause(BoxedCause::new(Outer(Inner("inner cause"))));
    let cause = std::error::Error::source(&app).expect("typed cause");
    assert_eq!(cause.to_string(), "outer failure");
    let nested = std::error::Error::source(cause).expect("nested cause");
    assert_eq!(nested.to_string(), "inner cause");

    // `text()` deliberately flattens the chain; keep that documented contrast.
    let flat = AppError::LoginCause(BoxedCause::text("outer failure"));
    let flat_cause = std::error::Error::source(&flat).expect("text cause");
    assert!(std::error::Error::source(flat_cause).is_none());
}

#[test]
fn invalid_server_url_cause_detail_survives_conversion_to_auth_error() {
    use crate::error::BoxedCause;

    let app = AppError::InvalidServerUrlCause(BoxedCause::text("URL scheme must be https"));
    let small = AuthError::from(app);
    assert_eq!(small.message(), AuthError::InvalidServerUrl.message());
    assert!(
        small.status_message().contains("URL scheme must be https"),
        "{}",
        small.status_message()
    );
    assert!(
        matches!(
            &small,
            AuthError::InvalidServerUrlDetail(detail)
                if detail.as_str() == "URL scheme must be https"
        ),
        "the parser detail must survive: {small:?}"
    );

    // The detail variant is the same failure as the plain one and converts
    // back to a cause-carrying AppError instead of dropping the context.
    assert_eq!(small, AuthError::InvalidServerUrl);
    let restored = AppError::from(small);
    assert!(matches!(&restored, AppError::InvalidServerUrlCause(_)));
    assert!(std::error::Error::source(&restored).is_some());
    assert_eq!(restored, AppError::InvalidServerUrl);
}

#[test]
fn client_setup_cause_detail_survives_conversion_to_auth_error() {
    use crate::error::BoxedCause;

    let app = AppError::ClientSetupCause(BoxedCause::text("client id rejected"));
    let small = AuthError::from(app);
    assert_eq!(small.message(), AuthError::ClientSetup.message());
    assert!(
        small.status_message().contains("client id rejected"),
        "{}",
        small.status_message()
    );
    assert_eq!(small, AuthError::ClientSetup);

    let restored = AppError::from(small);
    assert!(matches!(&restored, AppError::ClientSetupCause(_)));
    assert!(std::error::Error::source(&restored).is_some());
    assert_eq!(restored, AppError::ClientSetup);
}

#[test]
fn validate_config_keeps_the_url_parser_detail_variant() {
    let mut value = config();
    value.server_url = "http://vault.example.com".into();
    let error = validate_config(&value).unwrap_err();

    // The family comparison still holds, but the returned value now carries
    // the parser's reason instead of collapsing to the bare plain variant.
    assert_eq!(error, AuthError::InvalidServerUrl);
    assert!(
        matches!(&error, AuthError::InvalidServerUrlDetail(_)),
        "the URL parser detail must survive: {error:?}"
    );
    assert!(error
        .status_message()
        .starts_with(AuthError::InvalidServerUrl.message()));
}

#[test]
fn invalid_server_url_typed_cause_is_rendered_at_the_ui_boundary() {
    use crate::error::BoxedCause;
    use std::fmt;

    #[derive(Debug)]
    struct Inner(&'static str);
    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Inner {}

    let app = AppError::InvalidServerUrlCause(BoxedCause::new(Inner("dns failure")));
    let cause = std::error::Error::source(&app).expect("typed cause kept by AppError");
    assert_eq!(cause.to_string(), "dns failure");

    let small = AuthError::from(app);
    assert!(
        small.status_message().contains("dns failure"),
        "{}",
        small.status_message()
    );
    // The typed chain stops at the small enum: only its rendered detail is
    // surfaced, which is exactly what the corrected authenticate_inner comment
    // documents.
    assert!(std::error::Error::source(&small).is_none());
}

#[test]
fn auth_detail_variants_compare_equal_to_plain_siblings() {
    // Cause/detail context is diagnostic, never part of failure identity.
    for (detailed, plain) in [
        (
            AuthError::InvalidServerUrlDetail("a".into()),
            AuthError::InvalidServerUrl,
        ),
        (
            AuthError::ClientSetupDetail("b".into()),
            AuthError::ClientSetup,
        ),
        (AuthError::LoginDetail("c".into()), AuthError::Login),
        (AuthError::SyncDetail("d".into()), AuthError::Sync),
    ] {
        assert_eq!(detailed, plain);
        assert_eq!(plain, detailed);
        assert_eq!(detailed.message(), plain.message());
    }
    assert_eq!(
        AuthError::InvalidServerUrlDetail("a".into()),
        AuthError::InvalidServerUrlDetail("b".into())
    );
    assert_ne!(AuthError::ClientSetup, AuthError::InvalidServerUrl);
    assert_ne!(
        AuthError::MissingField("email"),
        AuthError::MissingField("url")
    );
}

#[test]
fn prelogin_is_reflexive_and_keeps_its_detail() {
    assert_eq!(AuthError::Prelogin, AuthError::Prelogin);
    assert_eq!(
        AuthError::PreloginDetail("server unavailable".into()),
        AuthError::Prelogin
    );
    assert_eq!(
        AuthError::PreloginDetail("server unavailable".into()).message(),
        AuthError::Prelogin.message()
    );
    assert!(AuthError::PreloginDetail("server unavailable".into())
        .status_message()
        .contains("server unavailable"));
    let app: crate::error::AppError = AuthError::PreloginDetail("server unavailable".into()).into();
    assert!(matches!(app, crate::error::AppError::PreloginCause(_)));
    assert!(std::error::Error::source(&app).is_some());
}

#[test]
fn kdf_rejection_is_reflexive_and_keeps_its_detail() {
    assert_eq!(AuthError::KdfRejected, AuthError::KdfRejected);
    assert_eq!(
        AuthError::KdfRejectedDetail("policy".into()),
        AuthError::KdfRejected
    );
    assert!(AuthError::KdfRejectedDetail("policy".into())
        .status_message()
        .contains("policy"));
    let app: crate::error::AppError = AuthError::KdfRejectedDetail("policy".into()).into();
    assert!(matches!(app, crate::error::AppError::KdfRejectedCause(_)));
}

#[test]
fn missing_cache_plus_sync_failure_reports_only_the_sync_cause() {
    use crate::error::{AppError, BoxedCause};

    // A missing cache is the normal first-launch case, so its fallback is the
    // plain Sync status. The discarded sync error must still reach the bar.
    let fallback = cache_restore_failure(AppError::NotFound);
    assert_eq!(fallback, AuthError::Sync);
    let combined = super::sync_fallback_failure(
        fallback,
        Some(AppError::SyncCause(BoxedCause::text("HTTP 503"))),
    );
    assert_eq!(combined, AuthError::Sync);
    assert!(matches!(
        &combined,
        AuthError::SyncDetail(detail) if detail.as_str() == "HTTP 503"
    ));
    assert_eq!(combined.status_message(), "同期に失敗しました（HTTP 503）");
    assert!(!combined.status_message().contains("キャッシュ"));
}

#[test]
fn sync_fallback_without_a_cause_keeps_the_cache_status_verbatim() {
    use crate::error::AppError;

    let fallback = cache_restore_failure(AppError::CacheExpired);
    let expected = fallback.status_message();
    assert_eq!(
        super::sync_fallback_failure(fallback.clone(), None).status_message(),
        expected
    );
    // A cause that renders to no text at all (no source, empty message) also
    // leaves the fallback untouched.
    let combined = super::sync_fallback_failure(fallback, Some(AppError::Other(String::new())));
    assert_eq!(combined.status_message(), expected);
}

#[test]
fn sync_fallback_flattens_only_the_first_source_level() {
    use crate::error::{AppError, BoxedCause};
    use std::fmt;

    #[derive(Debug)]
    struct Inner(&'static str);
    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Inner {}

    #[derive(Debug)]
    struct Outer(Inner);
    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer failure")
        }
    }
    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    let cause = AppError::SyncCause(BoxedCause::new(Outer(Inner("inner failure"))));
    let combined =
        super::sync_fallback_failure(cache_restore_failure(AppError::NotFound), Some(cause));
    let status = combined.status_message();
    assert!(status.contains("outer failure"), "{status}");
    // Documented PoC constraint: the nested cause is not flattened further.
    assert!(!status.contains("inner failure"), "{status}");
}

#[test]
fn empty_detail_variants_do_not_add_empty_parentheses() {
    let cases = [
        AuthError::InvalidServerUrlDetail(String::new()),
        AuthError::ClientSetupDetail(String::new()),
        AuthError::PreloginDetail(String::new()),
        AuthError::LoginDetail(String::new()),
        AuthError::SyncDetail(String::new()),
        AuthError::KdfRejectedDetail(String::new()),
    ];
    for error in cases {
        let status = error.status_message();
        assert_eq!(status, error.message(), "{error:?}");
        assert!(!status.contains("（）"), "{status}");
    }
}

#[test]
fn unlock_error_other_round_trips_through_app_error() {
    // `UnlockError` owns its detail, unlike `AuthError::Other`'s `&'static
    // str`, so both directions of the conversion keep the original text
    // (auth.rs:260-319).
    let detail = "unexpected unlock backend failure";
    let small = UnlockError::Other(detail.to_string());
    assert_eq!(small.message(), detail);
    assert_eq!(small.to_string(), detail);
    assert!(std::error::Error::source(&small).is_none());

    let app = AppError::from(small);
    assert!(matches!(&app, AppError::Other(text) if text == detail));
    assert_eq!(app.message(), detail);
    assert_eq!(app, AppError::Other(detail.to_string()));

    let restored = UnlockError::from(app);
    assert_eq!(restored, UnlockError::Other(detail.to_string()));
    assert_eq!(restored.message(), detail);
    assert_ne!(restored, UnlockError::MissingProtectedKey);

    // An empty detail is preserved too instead of being replaced by a
    // generic family message.
    let empty = UnlockError::from(AppError::Other(String::new()));
    assert_eq!(empty, UnlockError::Other(String::new()));
    assert_eq!(empty.message(), "");
}

#[test]
fn urls_without_a_host_fail_open_in_the_ssrf_classifier() {
    // `Url::host()` is None for cannot-be-a-base schemes (auth.rs:504-519).
    // The classifier deliberately returns false for them; the separate
    // `ServerUrls::self_hosted` validation is what rejects such URLs as a
    // server base. No DNS may be consulted on the host-less path.
    for value in [
        "mailto:alice@example.com",
        "data:text/plain,hello",
        "about:blank",
    ] {
        let parsed = url::Url::parse(value).expect("a parseable URL");
        assert_eq!(parsed.host(), None, "{value}");
        assert!(
            !is_blocked_server_url_with(value, |_| {
                panic!("a host-less URL must not consult DNS")
            }),
            "{value}"
        );
        assert!(!is_blocked_server_url_without_dns(value), "{value}");
    }
}

#[test]
fn timeout_wins_when_the_login_budget_expires() {
    // Loopback keeps this test free of DNS and external traffic while still
    // passing validation, so the call reaches the race. With a zero-length
    // budget the timer must win over the first network step of the login
    // future.
    let mut local = config();
    local.server_url = "http://127.0.0.1:8080".into();
    let result = smol::block_on(authenticate_with_timeout(
        &local,
        "device",
        std::time::Duration::ZERO,
    ));
    assert_eq!(result.err(), Some(AuthError::Timeout));
    assert_eq!(
        AuthError::Timeout.status_message(),
        "ログインがタイムアウトしました"
    );
}

#[test]
fn legacy_unlock_details_lose_only_the_status_decoration_on_a_round_trip() {
    use crate::error::BoxedCause;

    // The legacy (non-structured) AppError variants store a fully formatted
    // status message. `unlock_detail` must remove exactly that prefix/suffix
    // so the round trip through UnlockError keeps the raw detail (auth.rs:250,
    // 297-310); the modern constructors already store the raw detail.
    for (app, expected_detail, formatted) in [
        (
            AppError::UnlockFailed("復号キーを取得できません（bad key）".into()),
            "bad key",
            AppError::unlock_failed("bad key"),
        ),
        (
            AppError::ApplySyncFailed("同期データを取り込めません（bad sync）".into()),
            "bad sync",
            AppError::apply_sync_failed("bad sync"),
        ),
        (
            AppError::ImportFailed("vault 変換に失敗しました（bad import）".into()),
            "bad import",
            AppError::import_failed("bad import"),
        ),
    ] {
        let small = UnlockError::from(app);
        match &small {
            UnlockError::UnlockFailed(detail)
            | UnlockError::ApplySyncFailed(detail)
            | UnlockError::ImportFailed(detail) => {
                assert_eq!(detail.as_str(), expected_detail, "{small:?}");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        let restored = AppError::from(small);
        assert_eq!(restored.message(), formatted.message(), "{restored:?}");
    }

    // A detail that itself contains the decoration is stripped only once.
    let nested = "同期データを取り込めません（混入）";
    let small = UnlockError::from(AppError::apply_sync_failed(nested));
    assert!(
        matches!(&small, UnlockError::ApplySyncFailed(detail) if detail.as_str() == nested),
        "the embedded prefix must survive: {small:?}"
    );

    // Text without the expected prefix is never truncated.
    let raw = UnlockError::from(AppError::ImportFailed("raw detail".into()));
    assert_eq!(raw, UnlockError::ImportFailed("raw detail".into()));

    // The cause-carrying legacy variants follow the same rule and keep source.
    let cause = BoxedCause::text("original io failure");
    let small = UnlockError::from(AppError::ImportFailedCause(
        "vault 変換に失敗しました（cause detail）".into(),
        cause,
    ));
    match &small {
        UnlockError::ImportFailedCause(detail, _) => assert_eq!(detail.as_str(), "cause detail"),
        other => panic!("unexpected variant: {other:?}"),
    }
    assert!(std::error::Error::source(&small).is_some());
    assert_eq!(
        AppError::from(small).message(),
        AppError::import_failed_cause("cause detail", BoxedCause::text("original io failure"))
            .message()
    );
}

#[test]
fn authenticate_with_timeout_clamps_a_copy_and_leaves_the_caller_untouched() {
    fn snapshot(config: &AuthConfig) -> (String, String, String, String, String) {
        (
            config.server_url.clone(),
            config.client_id.clone(),
            config.client_secret.expose_secret().to_string(),
            config.email.clone(),
            config.master_password.expose_secret().to_string(),
        )
    }

    // An empty client id fails validation deterministically on the clamped
    // copy, so this test never touches the network. All other fields are
    // deliberately over-long: if the function clamped `config` in place they
    // would be shortened, which this assertion forbids (auth.rs:741-747).
    let mut original = config();
    original.server_url = "http://127.0.0.1:8080".into();
    original.client_id.clear();
    original.client_secret = SecretString::from("x".repeat(MAX_CLIENT_SECRET_LEN + 10));
    original.email = format!("a@example.com{}", "b".repeat(MAX_EMAIL_LEN));
    original.master_password = SecretString::from("p".repeat(MAX_MASTER_PASSWORD_LEN + 10));
    let before = snapshot(&original);

    let result = smol::block_on(authenticate_with_timeout(
        &original,
        "device",
        std::time::Duration::ZERO,
    ));
    assert_eq!(result.err(), Some(AuthError::MissingField("client_id")));
    assert_eq!(snapshot(&original), before, "caller config was mutated");
}

/// A locally generated protected key plus a keyless sync body. `Session` has
/// no public setter for these values, so the `unlock_and_import_with` seam
/// (auth.rs:720-783) supplies them directly to the four failure branches.
fn unlock_fixture() -> (MasterKey, String, openwarden::SyncData) {
    let master_key = MasterKey::from_bytes([0x11; 32]);
    let stretched = master_key.stretch();
    let protected = EncString::encrypt(&stretched, &[0x22; 64])
        .expect("a 64-byte user key must encrypt")
        .to_string();
    let sync =
        crate::vault_sync::parse_sync(br#"{"profile":{"id":"user-1"},"folders":[],"ciphers":[]}"#)
            .expect("sync JSON should parse");
    (master_key, protected, sync)
}

#[test]
fn unlock_and_import_missing_protected_key_branch() {
    let (master_key, _protected, sync) = unlock_fixture();
    let error = super::unlock_and_import_with(
        "",
        None,
        &master_key,
        sync,
        crate::vault_sync::import_logins,
    )
    .unwrap_err();
    assert_eq!(error, UnlockError::MissingProtectedKey);
    assert_eq!(error.message(), "復号キーが応答にありません");
}

#[test]
fn unlock_and_import_unlock_failure_keeps_its_typed_cause() {
    let (master_key, _protected, sync) = unlock_fixture();
    let error = super::unlock_and_import_with(
        "not-an-enc-string",
        None,
        &master_key,
        sync,
        crate::vault_sync::import_logins,
    )
    .unwrap_err();
    assert!(
        matches!(error, UnlockError::UnlockFailedCause(ref detail, _) if !detail.is_empty()),
        "{error:?}"
    );
    assert!(error.message().starts_with("復号キーを取得できません（"));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn unlock_and_import_apply_sync_failure_keeps_its_typed_cause() {
    let (master_key, protected, _sync) = unlock_fixture();
    // A profile key that differs from the session's protected key makes
    // `Vault::apply_sync` reject the sync with a typed key-change error.
    let body = r#"{"profile":{"id":"user-1","key":"2.different-key"},"folders":[],"ciphers":[]}"#;
    let sync = crate::vault_sync::parse_sync(body.as_bytes()).expect("sync JSON should parse");
    let error = super::unlock_and_import_with(
        &protected,
        None,
        &master_key,
        sync,
        crate::vault_sync::import_logins,
    )
    .unwrap_err();
    assert!(
        matches!(error, UnlockError::ApplySyncFailedCause(ref detail, _) if !detail.is_empty()),
        "{error:?}"
    );
    assert!(error.message().starts_with("同期データを取り込めません（"));
    assert!(std::error::Error::source(&error).is_some());
}

fn locked_import(
    _vault: &openwarden::Vault,
) -> Result<crate::model::Vault, crate::vault_sync::SyncError> {
    Err(crate::vault_sync::SyncError::Locked)
}

#[test]
fn unlock_and_import_import_failure_keeps_its_typed_cause() {
    let (master_key, protected, sync) = unlock_fixture();
    // `import_logins` can only fail on a locked vault, which is unreachable
    // after a successful unlock; the injected stub exercises the mapping.
    let error = super::unlock_and_import_with(&protected, None, &master_key, sync, locked_import)
        .unwrap_err();
    assert!(
        matches!(error, UnlockError::ImportFailedCause(ref detail, _) if detail.as_str() == "vault がロックされています"),
        "{error:?}"
    );
    assert_eq!(
        error.message(),
        "vault 変換に失敗しました（vault がロックされています）"
    );
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn unlock_and_import_success_branch_uses_the_real_importer() {
    let (master_key, protected, sync) = unlock_fixture();
    let vault = super::unlock_and_import_with(
        &protected,
        None,
        &master_key,
        sync,
        crate::vault_sync::import_logins,
    )
    .expect("a valid protected key and sync must unlock");
    assert!(vault.items.is_empty());
}

#[test]
fn the_clamped_copy_is_what_validation_sees() {
    // An over-long email is rejected by `validate_config`, but the private
    // copy is clamped first. With a loopback URL and a zero budget the call
    // must therefore reach the timeout race instead of returning InvalidEmail.
    // This also proves the clamp is not merely a no-op copy.
    let mut original = config();
    original.server_url = "http://127.0.0.1:8080".into();
    original.email = format!("a@example.com{}", "b".repeat(MAX_EMAIL_LEN));
    assert_eq!(validate_config(&original), Err(AuthError::InvalidEmail));

    let before_email = original.email.clone();
    let result = smol::block_on(authenticate_with_timeout(
        &original,
        "device",
        std::time::Duration::ZERO,
    ));
    assert_eq!(result.err(), Some(AuthError::Timeout));
    assert_eq!(original.email, before_email);
}
