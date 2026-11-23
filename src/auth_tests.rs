#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test-scope notes for `crate::auth`.
//!
//! Three production branches deliberately have no injection seam; these notes
//! record the limit instead of claiming coverage that the tests cannot give.
//!
//! * The DNS re-check in `authenticate_inner` (auth.rs:1065-1074) calls
//!   `is_blocked_server_url`, whose resolver is the concrete `resolve_host`.
//!   The injected resolver of `is_blocked_server_url_with` is exercised by the
//!   classifier tests below, but `authenticate_inner` does not accept that
//!   seam, so the production re-check cannot be forced to see a link-local
//!   answer without a real lookup or a production code change. `localhost` is
//!   used to touch the real resolver with only the local hosts file.
//! * The `from_cache = true` assignment (auth.rs:1112-1131) lives after
//!   `Client::sync_body` in the private async login path; there is no seam to
//!   force that call to fail. The flag tests below pin the observable data
//!   contract at the `AuthenticatedVault` boundary only, not the assignment
//!   itself.
//! * `resolve_host` (auth.rs:621-635) takes no injected resolver, so an
//!   arbitrary DNS outage cannot be forced from this test module without a
//!   production change. Its failure arm is nevertheless deterministic: a host
//!   containing an interior NUL is rejected by `ToSocketAddrs` before any
//!   resolver call, so the empty-vector fail-open can be pinned without real
//!   DNS. A genuine "server name exists but does not resolve" answer stays a
//!   known, untestable constraint here.

use std::net::IpAddr;

use super::{is_blocked_server_url_with, is_blocked_server_url_without_dns, is_link_local_ip};
use crate::auth::*;
use crate::error::OTHER_ERROR_MESSAGE;
use openwarden::{EncString, Kdf, KdfPolicy, MasterKey};

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
    // (auth.rs:621-635). `localhost` resolves from the local hosts file, so
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
fn every_unicode_cf_range_is_rejected_in_an_email() {
    // `crate::limits::is_format_character` lists 21 disjoint ranges/characters
    // from Unicode 16.0's Cf category (limits.rs). The older regression test
    // samples only eight of them; cover every arm here (start, middle where
    // the range has one, and end) through both the primitive and the email
    // validator, so a shortened list cannot slip through unnoticed.
    const CF_RANGES: &[(u32, u32)] = &[
        (0x00ad, 0x00ad),
        (0x0600, 0x0605),
        (0x061c, 0x061c),
        (0x06dd, 0x06dd),
        (0x070f, 0x070f),
        (0x0890, 0x0891),
        (0x08e2, 0x08e2),
        (0x180e, 0x180e),
        (0x200b, 0x200f),
        (0x202a, 0x202e),
        (0x2060, 0x2064),
        (0x2066, 0x206f),
        (0xfeff, 0xfeff),
        (0xfff9, 0xfffb),
        (0x110bd, 0x110bd),
        (0x110cd, 0x110cd),
        (0x13430, 0x1343f),
        (0x1bca0, 0x1bca3),
        (0x1d173, 0x1d17a),
        (0xe0001, 0xe0001),
        (0xe0020, 0xe007f),
    ];
    assert_eq!(CF_RANGES.len(), 21, "the Cf list has 21 arms");
    for &(start, end) in CF_RANGES {
        assert!(start <= end, "bad range U+{start:04X}..U+{end:04X}");
        let mut points = vec![start, end];
        if end > start + 1 {
            points.push(start + (end - start) / 2);
        }
        for point in points {
            let ch = char::from_u32(point)
                .unwrap_or_else(|| panic!("U+{point:04X} is not a scalar value"));
            assert!(
                crate::limits::is_format_character(ch),
                "U+{point:04X} missing from the Cf list"
            );
            let email = format!("alice{ch}@example.com");
            assert!(!valid_email(&email), "U+{point:04X} accepted: {email:?}");
            let mut value = config();
            value.email = email;
            assert_eq!(
                validate_config(&value),
                Err(AuthError::InvalidEmail),
                "U+{point:04X}"
            );
        }
    }

    // Just outside a range the character is ordinary (these neighbours are
    // unassigned or non-Cf), so the assertions above are about the Cf policy
    // rather than a blanket rejection of non-ASCII input.
    for ch in ['\u{00ae}', '\u{0606}', '\u{2065}', '\u{e001f}', '\u{e0080}'] {
        assert!(
            !crate::limits::is_format_character(ch),
            "U+{:04X} should not be Cf",
            ch as u32
        );
        assert!(valid_email(&format!("alice{ch}@example.com")));
    }
}

#[test]
fn uppercase_email_is_not_case_folded_before_kdf_is_a_known_constraint() {
    // Known constraint documented at the `MasterKey::derive` call in
    // `authenticate_inner`: the address is trimmed but its case is preserved.
    // `valid_email` / `validate_config` accept any casing and clamping only
    // removes padding, so a mixed-case address reaches the KDF verbatim; a
    // user who typed a different case than the server's stored address
    // derives a different key. Pin the observable half of that contract here.
    const MIXED: &str = "Alice.MIXED@Example.COM";
    assert!(valid_email(MIXED));
    let mut value = config();
    value.email = format!("  {MIXED}\t");
    assert_eq!(validate_config(&value), Ok(()));
    clamp_auth_config(&mut value);
    assert_eq!(
        value.email, MIXED,
        "clamp trims padding but does not fold case"
    );
    // Re-applying the cap is a no-op and must not fold case either.
    clamp_auth_config(&mut value);
    assert_eq!(value.email, MIXED, "the KDF sees the original case");
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
fn email_length_ceiling_is_applied_after_trimming() {
    // `valid_email` trims before counting characters (auth.rs:409-412), and
    // `validate_config` delegates to it with the raw field (auth.rs:694).
    // Padding must therefore be ignored at the MAX_EMAIL_LEN boundary, not
    // counted as part of the address.
    let suffix = "@example.com";
    let local_len = MAX_EMAIL_LEN - suffix.len();
    let at_limit = format!("{}{suffix}", "a".repeat(local_len));

    let padded_at_limit = format!(" \t{at_limit}\n");
    assert_eq!(padded_at_limit.trim().chars().count(), MAX_EMAIL_LEN);
    assert!(valid_email(&padded_at_limit));
    let mut accepted = config();
    accepted.email = padded_at_limit;
    assert_eq!(validate_config(&accepted), Ok(()));

    // One character past the ceiling after trimming is still rejected, even
    // when the raw field is much longer because of the surrounding padding.
    let too_long = format!("{}{suffix}", "a".repeat(local_len + 1));
    let padded_too_long = format!("\u{3000}{too_long}  ");
    assert_eq!(padded_too_long.trim().chars().count(), MAX_EMAIL_LEN + 1);
    assert!(!valid_email(&padded_too_long));
    let mut rejected = config();
    rejected.email = padded_too_long;
    assert_eq!(validate_config(&rejected), Err(AuthError::InvalidEmail));
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
    // (auth.rs:376-384). The same SecretString instance and its contents must
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
fn cache_restore_failure_uses_the_generic_cache_wording() {
    use crate::error::{AppError, OTHER_ERROR_MESSAGE};

    // `cache_restore_failure` delegates classification to the cache layer
    // (auth.rs:979-989). A failure with no dedicated reason keeps the sync
    // family and the cache layer's generic fallback text
    // (cache.rs:820-831); it must neither collapse to a bare `Sync` status nor
    // be mislabelled as corruption. Pin the exact user-visible wording.
    const GENERIC: &str = "同期に失敗しました（キャッシュを復元できませんでした）";
    for error in [
        AppError::RandomUnavailable,
        AppError::Other("anything else".to_string()),
    ] {
        let status = cache_restore_failure(error);
        assert!(matches!(&status, AuthError::Other(_)), "{status:?}");
        assert_eq!(status.message(), GENERIC, "{status:?}");
        assert_eq!(status.status_message(), GENERIC, "{status:?}");
        // `Other` owns its text, so it is not equal to the plain `Sync`
        // variant; the generic text still leads with the sync family message.
        assert_ne!(status, AuthError::Sync);
        assert!(status.message().starts_with(AuthError::Sync.message()));
    }
    // The generic reason is distinct from every classified reason and from
    // the "no cache yet" silent case.
    assert_ne!(GENERIC, cache_restore_failure(AppError::NotFound).message());
    assert_ne!(
        GENERIC,
        cache_restore_failure(AppError::CacheExpired).message()
    );
    assert!(!GENERIC.contains(OTHER_ERROR_MESSAGE));
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

#[test]
fn user_mismatch_cache_error_reaches_the_status_bar() {
    // The cache layer's `UserMismatch` reason must not collapse into the plain
    // Sync status: `cache_restore_failure` wraps it in `AuthError::Other`
    // (auth.rs:979-989).
    let error = cache_restore_failure(AppError::UserMismatch);
    assert!(matches!(&error, AuthError::Other(text) if text.contains("別のアカウント")));
    assert_eq!(
        error.message(),
        "同期に失敗しました（キャッシュが別のアカウントのものです）"
    );
    assert_eq!(
        error.status_message(),
        "同期に失敗しました（キャッシュが別のアカウントのものです）"
    );
    // The small enum's `Other` owns the text, so converting back preserves it.
    let app = AppError::from(error);
    assert!(matches!(app, AppError::Other(text) if text.contains("別のアカウント")));
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
    // as a known family (auth.rs:204-234, 270-276).
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
    // `unlock_detail` strips prefix+suffix as a pair (auth.rs:286-291). A
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
    // The family message already ends in a parenthetical hint, so the detail
    // replaces that hint instead of producing two adjacent `（）` groups.
    let status = error.status_message();
    assert!(status.starts_with("サーバー URL が不正です（"), "{status}");
    assert!(
        !status.contains("HTTPS または loopback の HTTP"),
        "{status}"
    );
    assert!(!status.contains("）（"), "{status}");
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
fn kdf_rejected_detail_renders_the_same_family_message() {
    // `message()` ignores the retained detail for every Detail variant
    // (auth.rs:142-160), so the KDF family text is identical with and without
    // one; only `status_message()` is allowed to differ.
    let plain = AuthError::KdfRejected;
    let detailed = AuthError::KdfRejectedDetail("policy: iterations 1000".into());
    assert_eq!(detailed.message(), plain.message());
    assert_eq!(detailed.message(), "KDF 設定がポリシーで拒否されました");
    assert_eq!(detailed.to_string(), plain.to_string());
    assert_eq!(detailed, plain);
    assert_eq!(plain, detailed);
    assert!(detailed
        .status_message()
        .contains("policy: iterations 1000"));
    assert_eq!(plain.status_message(), plain.message());

    // The equality rule is symmetric across different detail texts, and the
    // conversion back to AppError keeps the cause attached to the same family.
    assert_eq!(
        AuthError::KdfRejectedDetail("a".into()),
        AuthError::KdfRejectedDetail("b".into())
    );
    let app: crate::error::AppError = detailed.into();
    assert!(matches!(app, crate::error::AppError::KdfRejectedCause(_)));
    assert_eq!(app.message(), AuthError::KdfRejected.message());
}

#[test]
fn unparseable_urls_never_consult_the_resolver() {
    // `Url::parse` fails before the host classifier runs (auth.rs:600-602), so
    // a resolver that panics proves no DNS path was reached. The plain
    // network-free entry point must agree and return false for the same input.
    for value in ["not a url", "://bad", "https://exa mple.com", ""] {
        assert!(
            !is_blocked_server_url_with(value, |_| {
                panic!("a URL parse failure must not consult DNS")
            }),
            "{value}"
        );
        assert!(!is_blocked_server_url_without_dns(value), "{value}");
    }
    // A parseable host still reaches the injected resolver, so the guard above
    // is about the parse branch and not a blanket "no DNS" rule.
    assert!(is_blocked_server_url_with("http://metadata", |_| {
        panic!("known metadata host must not trigger DNS")
    }));
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
fn sync_fallback_adopts_the_cause_message_when_there_is_no_source() {
    // `AppError::Other` has no `Error::source()`. `sync_fallback_failure`
    // (auth.rs:1029-1058) must then render `cause.message()` instead of dropping
    // the discarded sync reason entirely.
    let fallback = cache_restore_failure(AppError::CacheExpired);
    let combined =
        super::sync_fallback_failure(fallback, Some(AppError::Other("no-source reason".into())));
    assert_eq!(combined.message(), AuthError::Sync.message());
    assert_eq!(
        combined.status_message(),
        "同期に失敗しました（キャッシュが有効期限を過ぎています（no-source reason））"
    );
    // An empty message still leaves the tested cache status untouched.
    let empty = super::sync_fallback_failure(
        cache_restore_failure(AppError::CacheExpired),
        Some(AppError::Other(String::new())),
    );
    assert_eq!(
        empty.status_message(),
        "同期に失敗しました（キャッシュが有効期限を過ぎています）"
    );
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
    // (auth.rs:293-352).
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
    // `Url::host()` is None for cannot-be-a-base schemes (auth.rs:603-618).
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
fn hostless_urls_fail_open_in_the_classifier_but_are_rejected_by_self_hosted() {
    // The SSRF classifier has no host to inspect for cannot-be-a-base schemes
    // and deliberately returns false (auth.rs:596-618). That fail-open is only
    // safe because the *server base* parser closes the path: `self_hosted`
    // rejects every host-less URL, so `validate_config` still refuses it.
    // Pinning both halves stops either layer from silently becoming the sole
    // guard.
    use openwarden::ServerUrls;

    for value in [
        "mailto:alice@example.com",
        "data:text/plain,hello",
        "about:blank",
    ] {
        assert!(!is_blocked_server_url_without_dns(value), "{value}");
        assert!(
            ServerUrls::self_hosted(value).is_err(),
            "self_hosted must reject the host-less URL {value}"
        );
        let mut invalid = config();
        invalid.server_url = value.into();
        let error = validate_config(&invalid).unwrap_err();
        assert_eq!(error, AuthError::InvalidServerUrl, "{value}");
        assert!(
            matches!(&error, AuthError::InvalidServerUrlDetail(_)),
            "the parser reason must survive for {value}: {error:?}"
        );
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
    // so the round trip through UnlockError keeps the raw detail (auth.rs:286,
    // 295-315); the modern constructors already store the raw detail.
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
    // would be shortened, which this assertion forbids (auth.rs:943-949).
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
/// (auth.rs:851-886) supplies them directly to the four failure branches.
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
fn unlock_and_import_success_delivers_decrypted_items_to_the_model() {
    // The existing success test only asserts an empty vault, so it cannot
    // detect a success branch that silently drops or fails to decrypt items.
    // Here the login fields are real `EncString` ciphertexts under the user key
    // sealed in the fixture's protected key; the plaintext must reach `model`.
    let master_key = MasterKey::from_bytes([0x11; 32]);
    let stretched = master_key.stretch();
    let protected = EncString::encrypt(&stretched, &[0x22; 64])
        .expect("a 64-byte user key must encrypt")
        .to_string();
    // `Vault::unlock` decrypts `protected` into exactly these 64 bytes, which
    // become the user key used for every cipher field (the cipher has no own
    // `key`, so no per-item key is involved).
    let user_symmetric = openwarden::SymmetricKey::from_bytes(&[0x22; 64])
        .expect("a 64-byte user key must be valid");
    let enc = |plain: &[u8]| {
        EncString::encrypt(&user_symmetric, plain)
            .expect("a field must encrypt under the user key")
            .to_string()
    };
    // No `profile.key`: `apply_sync` would compare it with the session's
    // protected key. The fixture's keyless profile keeps the success path.
    let body = serde_json::json!({
        "profile": { "id": "user-1" },
        "folders": [],
        "ciphers": [{
            "id": "login-1",
            "type": 1,
            "name": enc(b"Decrypted Login"),
            "login": {
                "username": enc(b"alice@example.com"),
                "password": enc(b"correct horse battery staple"),
                "uris": [{ "uri": enc(b"https://example.com") }],
            },
            "revisionDate": "2024-01-01T00:00:00Z",
        }],
    })
    .to_string();
    let sync =
        crate::vault_sync::parse_sync(body.as_bytes()).expect("an encrypted sync body must parse");

    let vault = super::unlock_and_import_with(
        &protected,
        None,
        &master_key,
        sync,
        crate::vault_sync::import_logins,
    )
    .expect("a valid protected key and encrypted sync must unlock");

    assert_eq!(
        vault.items.len(),
        1,
        "the decrypted item must reach the model"
    );
    let item = &vault.items[0];
    assert_eq!(item.name, "Decrypted Login");
    let (username, password, _totp, uris) = item.login().expect("the item is a login");
    assert_eq!(username, "alice@example.com");
    assert_eq!(password, "correct horse battery staple");
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, "https://example.com");
}

#[test]
fn public_unlock_and_import_extracts_session_derived_inputs() {
    // The public entry point (auth.rs:823-839) reads `protected_key` and `kdf`
    // from the authenticated `Session` and forwards them to the shared helper.
    // `Session::from_token` is the only public constructor that needs no login
    // response; it leaves both fields unset, so the extracted protected key is
    // empty and must surface as `MissingProtectedKey`. This exercises the real
    // extraction path, not just the seam used by the four branch tests above.
    let (master_key, _protected, sync) = unlock_fixture();
    let session = Session::from_token(
        SecretString::from("test-access-token".to_string()),
        std::time::Duration::from_secs(3600),
    )
    .expect("a one-hour token must be accepted");
    assert_eq!(session.protected_key(), None, "fixture precondition");
    assert_eq!(session.kdf(), None, "fixture precondition");

    let authenticated = AuthenticatedVault {
        session,
        sync,
        master_key,
        from_cache: false,
    };
    let error = unlock_and_import(authenticated).unwrap_err();
    assert_eq!(error, UnlockError::MissingProtectedKey);
    assert_eq!(error.message(), "復号キーが応答にありません");
}

#[test]
fn authenticate_wrapper_matches_the_explicit_default_timeout_on_the_validation_path() {
    // Honest scope: `authenticate()` (auth.rs:968-974) is a thin wrapper around
    // `authenticate_with_timeout(..., DEFAULT_LOGIN_TIMEOUT)`. Its timeout
    // argument is not observable from a returned error on a config that reaches
    // the network: proving the watchdog used the default would require waiting
    // the full 30 seconds, and there is no injection seam in the public
    // signature. Validation runs *before* the race, so this test can only pin
    // delegation on the deterministic invalid-config path. The timer itself is
    // covered by `timeout_wins_when_the_login_budget_expires` (explicit zero
    // budget) and `unrepresentable_deadline_takes_the_relative_timer_fallback`;
    // the shared budget value is pinned here so a change cannot hide behind the
    // two calls using the same constant.
    let mut invalid = config();
    invalid.email.clear();
    let wrapped = smol::block_on(authenticate(&invalid, "device")).err();
    let explicit = smol::block_on(authenticate_with_timeout(
        &invalid,
        "device",
        DEFAULT_LOGIN_TIMEOUT,
    ))
    .err();
    assert_eq!(wrapped, Some(AuthError::MissingField("email")));
    assert_eq!(wrapped, explicit);
    assert_eq!(DEFAULT_LOGIN_TIMEOUT, std::time::Duration::from_secs(30));
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

#[test]
fn whitespace_only_server_url_and_email_are_missing_fields() {
    // `validate_config` checks `.trim().is_empty()` for the two text fields
    // that live in Settings (auth.rs:682,691). A whitespace-only value is a
    // missing field, not an InvalidServerUrl / InvalidEmail failure.
    let mut value = config();
    value.server_url = " \t\n\u{3000}".into();
    assert_eq!(
        validate_config(&value),
        Err(AuthError::MissingField("server_url"))
    );

    let mut value = config();
    value.email = " \t\n\u{3000}".into();
    assert_eq!(
        validate_config(&value),
        Err(AuthError::MissingField("email"))
    );

    // The same check tolerates padding around an otherwise valid value: the
    // trimmed form is what later reaches `ServerUrls` / `valid_email`.
    let mut padded = config();
    padded.server_url = "  https://vault.example.com  ".into();
    padded.email = "  alice@example.com  ".into();
    assert_eq!(validate_config(&padded), Ok(()));
}

use std::sync::atomic::{AtomicBool, Ordering};

/// Set by [`observing_import`] when the production KDF reaches openwarden.
static SAW_KDF: AtomicBool = AtomicBool::new(false);
/// A policy-valid PBKDF2 KDF, used to exercise the `Some(Kdf)` path.
const TEST_KDF: Kdf = Kdf::Pbkdf2 {
    iterations: 100_000,
};

fn observing_import(
    vault: &openwarden::Vault,
) -> Result<crate::model::Vault, crate::vault_sync::SyncError> {
    SAW_KDF.store(vault.key_state().kdf == Some(TEST_KDF), Ordering::SeqCst);
    crate::vault_sync::import_logins(vault)
}

#[test]
fn unlock_and_import_forwards_the_session_kdf_to_openwarden() {
    // Production takes `kdf` from the live `Session` and passes it to
    // `unlock_and_import_with` (auth.rs:823-839,851-886). `Session::from_token`
    // is the only public constructor needing no login response and leaves kdf
    // unset, so the existing branch tests all use `None`. This test supplies a
    // real `Some(Kdf)` and uses an import stub to observe the KDF that reached
    // the unlocked vault, covering the same path a real login takes.
    SAW_KDF.store(false, Ordering::SeqCst);

    let (master_key, protected, sync) = unlock_fixture();
    let vault = super::unlock_and_import_with(
        &protected,
        Some(TEST_KDF),
        &master_key,
        sync,
        observing_import,
    )
    .expect("a session-derived Some(Kdf) must unlock like production");
    assert!(vault.items.is_empty());
    assert!(
        SAW_KDF.load(Ordering::SeqCst),
        "the supplied KDF must reach openwarden's unlocked vault"
    );
}

#[test]
fn apply_sync_failed_cause_round_trips_through_app_error() {
    use crate::error::BoxedCause;

    // `UnlockError::ApplySyncFailedCause` becomes the legacy cause-carrying
    // `AppError`, whose text is fully decorated (auth.rs:301-304). The reverse
    // conversion strips exactly that decoration (auth.rs:336-339), so the raw
    // detail and the typed cause must both survive the round trip.
    let detail = "key changed during apply_sync";
    let small = UnlockError::ApplySyncFailedCause(
        detail.to_string(),
        BoxedCause::text("openwarden key mismatch"),
    );
    let decorated = format!("同期データを取り込めません（{detail}）");
    assert_eq!(small.message(), decorated);
    assert!(std::error::Error::source(&small).is_some());

    let app = AppError::from(small.clone());
    assert!(
        matches!(&app, AppError::ApplySyncFailedCause(text, _) if text.as_str() == decorated),
        "AppError must hold the decorated status text: {app:?}"
    );
    assert_eq!(app.message(), decorated);
    assert!(std::error::Error::source(&app).is_some());

    let restored = UnlockError::from(app);
    match &restored {
        UnlockError::ApplySyncFailedCause(restored_detail, cause) => {
            assert_eq!(restored_detail.as_str(), detail);
            assert_eq!(cause.to_string(), "openwarden key mismatch");
        }
        other => panic!("cause was dropped: {other:?}"),
    }
    assert_eq!(restored.message(), decorated);
    assert_eq!(restored, UnlockError::ApplySyncFailed(detail.into()));
    assert!(std::error::Error::source(&restored).is_some());
    // Converting back adds the decoration exactly once, never twice.
    assert_eq!(AppError::from(restored).message(), decorated);
}

#[test]
fn legacy_apply_sync_cause_text_is_stripped_only_once() {
    use crate::error::BoxedCause;

    // The legacy variant stores a formatted message. `unlock_detail` removes
    // prefix and suffix as a pair (auth.rs:286-291, 336-339); an embedded copy
    // of the decoration must not be swallowed as well.
    let nested = "同期データを取り込めません（混入）";
    let app = AppError::ApplySyncFailedCause(
        format!("同期データを取り込めません（{nested}）"),
        BoxedCause::text("io failure"),
    );
    let small = UnlockError::from(app);
    assert!(
        matches!(&small, UnlockError::ApplySyncFailedCause(detail, _) if detail == nested),
        "only the outer decoration may be stripped: {small:?}"
    );
    assert!(std::error::Error::source(&small).is_some());

    // A message with the prefix but no closing suffix is kept verbatim as the
    // detail; the next conversion decorates that text exactly once.
    let truncated = "同期データを取り込めません（truncated";
    let raw = UnlockError::from(AppError::ApplySyncFailedCause(
        truncated.to_string(),
        BoxedCause::text("io failure"),
    ));
    assert_eq!(
        raw,
        UnlockError::ApplySyncFailedCause(truncated.to_string(), BoxedCause::text("io failure"))
    );
    assert_eq!(
        AppError::from(raw).message(),
        format!("同期データを取り込めません（{truncated}）")
    );
}

#[test]
fn timeout_error_round_trips_through_app_error() {
    // `Timeout` is one of the plain variants with no detail sibling, so both
    // conversion directions must preserve identity, message and equality
    // (auth.rs:51-140, 204-234, 236-278).
    let auth = AuthError::Timeout;
    let app = crate::error::AppError::from(auth.clone());
    assert!(matches!(&app, crate::error::AppError::Timeout));
    assert_eq!(app.message(), auth.message());
    assert_eq!(AuthError::from(app), auth);
    assert_eq!(auth.status_message(), "ログインがタイムアウトしました");
    assert_eq!(auth.to_string(), "ログインがタイムアウトしました");
    assert_eq!(auth, AuthError::Timeout);
    assert_ne!(auth, AuthError::Other("ログインがタイムアウトしました"));

    // The reverse direction starts from `AppError` and must not be confused
    // with a cause-carrying failure or the generic `Other` fallback.
    let from_app = AuthError::from(crate::error::AppError::Timeout);
    assert!(matches!(&from_app, AuthError::Timeout));
    assert_eq!(
        crate::error::AppError::from(from_app),
        crate::error::AppError::Timeout
    );
}

#[test]
fn validate_config_reports_the_first_invalid_field_in_a_fixed_order() {
    // Actual order (auth.rs:681-706): the four MissingField checks for the
    // Settings-backed text fields run first, then the structural `valid_email`
    // check, then the master_password MissingField check, then
    // BlockedServerUrl, and finally the URL parser. In particular the
    // master-password check is *after* the email check, not part of the same
    // first pass, and both field checks precede both URL checks.
    let mut all_bad = config();
    all_bad.server_url = "  ".into();
    all_bad.client_id = "  ".into();
    all_bad.client_secret = SecretString::from("  ".to_string());
    all_bad.email = "not-an-email".into();
    all_bad.master_password = SecretString::from(String::new());
    assert_eq!(
        validate_config(&all_bad),
        Err(AuthError::MissingField("server_url"))
    );

    let mut cases = Vec::new();

    let mut without_server = all_bad.clone();
    without_server.server_url = "https://vault.example.com".into();
    cases.push((without_server.clone(), AuthError::MissingField("client_id")));

    let mut without_client = without_server.clone();
    without_client.client_id = "user.1234".into();
    cases.push((
        without_client.clone(),
        AuthError::MissingField("client_secret"),
    ));

    let mut without_secret = without_client.clone();
    without_secret.client_secret = SecretString::from(CLIENT_SECRET_CANARY.to_string());
    without_secret.email = String::new();
    cases.push((without_secret.clone(), AuthError::MissingField("email")));

    // A non-empty malformed email fires the structural check before the later
    // empty-master-password check. Keep master_password empty here so this case
    // really distinguishes the two orders instead of sidestepping the contest.
    let mut malformed_email = without_secret.clone();
    malformed_email.email = "not-an-email".into();
    cases.push((malformed_email, AuthError::InvalidEmail));

    // Once the email is valid, the empty master password is the next failure;
    // it still wins over both URL-level checks below.
    let mut valid_email = without_secret.clone();
    valid_email.email = "alice@example.com".into();
    cases.push((
        valid_email.clone(),
        AuthError::MissingField("master_password"),
    ));

    // Only after every field passes do the URL checks run, with the link-local
    // classifier ahead of the URL parser.
    let mut blocked = valid_email.clone();
    blocked.master_password = SecretString::from("pw".to_string());
    blocked.server_url = "http://169.254.169.254".into();
    cases.push((blocked, AuthError::BlockedServerUrl));

    let mut insecure = valid_email.clone();
    insecure.master_password = SecretString::from("pw".to_string());
    insecure.server_url = "http://vault.example.com".into();
    cases.push((insecure, AuthError::InvalidServerUrl));

    for (config, expected) in cases {
        assert_eq!(validate_config(&config), Err(expected), "{config:?}");
    }
}

#[test]
fn plain_invalid_login_uses_the_same_sync_detail_arm_as_the_cause_variant() {
    use crate::error::BoxedCause;

    // auth.rs:264-266 matches both `AppError::InvalidLogin` and
    // `AppError::InvalidLoginCause` in one arm. The plain form must keep the
    // parse detail and classify as a retryable Sync failure, exactly like its
    // cause-carrying sibling.
    const DETAIL: &str = "bad sync key casing";
    let plain = AuthError::from(AppError::InvalidLogin(DETAIL.to_string()));
    let caused = AuthError::from(AppError::InvalidLoginCause(
        DETAIL.to_string(),
        BoxedCause::text(DETAIL),
    ));

    assert_eq!(plain, AuthError::Sync);
    assert_eq!(plain, caused);
    assert_eq!(caused, plain);
    assert_eq!(plain.message(), AuthError::Sync.message());
    assert!(
        plain.status_message().contains(DETAIL),
        "{}",
        plain.status_message()
    );
    assert_eq!(plain.status_message(), caused.status_message());
}

#[test]
fn unrepresentable_deadline_takes_the_relative_timer_fallback() {
    use std::time::{Duration, Instant};

    let now = Instant::now();
    // Guard the premise: on this platform `Duration::MAX` really does make
    // `checked_add` fail, so the test exercises the fallback rather than a
    // very distant absolute deadline.
    assert_eq!(now.checked_add(Duration::MAX), None);

    assert_eq!(
        login_deadline(now, Duration::from_secs(30)),
        LoginDeadline::At(now.checked_add(Duration::from_secs(30)).unwrap())
    );
    assert_eq!(
        login_deadline(now, Duration::MAX),
        LoginDeadline::Relative(Duration::MAX)
    );
    assert_eq!(login_deadline(now, Duration::ZERO), LoginDeadline::At(now));

    // Both watchdog arms still report Timeout when their timer fires. The
    // relative form is built directly with ZERO so the assertion does not
    // wait out the sentinel duration (auth.rs:917-927).
    assert_eq!(
        smol::block_on(login_watchdog(LoginDeadline::Relative(Duration::ZERO))).err(),
        Some(AuthError::Timeout)
    );
    assert_eq!(
        smol::block_on(login_watchdog(LoginDeadline::At(Instant::now()))).err(),
        Some(AuthError::Timeout)
    );
}

#[test]
fn user_id_is_derived_from_the_personal_api_key_client_id() {
    // The failed-sync path has no fresh `profile.id` and `Session` exposes no
    // accessor, so the account id for the cache check comes from the API key.
    // Bitwarden personal client ids are `user.<uuid>` (auth.rs:991-1007).
    assert_eq!(
        super::user_id_from_client_id("user.00000000-0000-0000-0000-000000000000"),
        "00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(super::user_id_from_client_id("  user.abc  "), "abc");
    // A malformed id fails closed instead of matching a different account.
    assert_eq!(super::user_id_from_client_id("user."), "user.");
    assert_eq!(super::user_id_from_client_id("user"), "user");
    assert_eq!(
        super::user_id_from_client_id("organization.abc"),
        "organization.abc"
    );
}

#[test]
fn user_id_from_client_id_trims_and_fails_closed() {
    // `user_id_from_client_id` trims before looking for `user.`, then returns
    // the (trimmed) original when the prefix is missing or has nothing after
    // it. That fail-closed shape cannot equal a real cache `profile.id`, so a
    // malformed API key cannot restore another account's vault.
    for (client_id, expected) in [
        ("\t user.abc \n", "abc"),
        ("\u{3000}user.abc\u{3000}", "abc"),
        ("  user.1234", "1234"),
    ] {
        assert_eq!(
            super::user_id_from_client_id(client_id),
            expected,
            "{client_id:?}"
        );
    }
    // No recognized prefix, or no id after it: the trimmed value is returned
    // unchanged instead of inventing an account id.
    for malformed in [
        "",
        "   ",
        "user.",
        " user. \t",
        "user",
        "organization.",
        "USER.",
        "user .abc",
        ".user.abc",
    ] {
        let derived = super::user_id_from_client_id(malformed);
        assert_eq!(derived, malformed.trim(), "{malformed:?}");
        assert_ne!(derived, "abc", "{malformed:?} must not impersonate an id");
    }
}

#[test]
fn auth_error_family_messages_are_fixed() {
    // `AuthError::message()` (auth.rs:142-160) is what the status bar shows;
    // pin every family so a wording change is an explicit, reviewed edit.
    for (error, expected) in [
        (AuthError::MissingField("email"), "認証情報が未入力です"),
        (
            AuthError::InvalidServerUrl,
            "サーバー URL が不正です（HTTPS または loopback の HTTP）",
        ),
        (
            AuthError::BlockedServerUrl,
            "サーバー URL が link-local アドレスを指しています",
        ),
        (AuthError::InvalidEmail, "メールアドレスの形式が不正です"),
        (
            AuthError::ClientSetup,
            "クライアントを初期化できませんでした",
        ),
        (AuthError::Prelogin, "サーバー情報の取得に失敗しました"),
        (AuthError::Login, "ログインに失敗しました"),
        (AuthError::Sync, "同期に失敗しました"),
        (AuthError::KdfRejected, "KDF 設定がポリシーで拒否されました"),
        (AuthError::Timeout, "ログインがタイムアウトしました"),
    ] {
        assert_eq!(error.message(), expected, "{error:?}");
        assert_eq!(error.to_string(), expected, "{error:?}");
    }
    // A detail-carrying sibling keeps the family message; only
    // `status_message()` may append its retained cause.
    for (detailed, plain) in [
        (
            AuthError::InvalidServerUrlDetail("why".into()),
            AuthError::InvalidServerUrl,
        ),
        (
            AuthError::ClientSetupDetail("why".into()),
            AuthError::ClientSetup,
        ),
        (AuthError::PreloginDetail("why".into()), AuthError::Prelogin),
        (AuthError::LoginDetail("why".into()), AuthError::Login),
        (AuthError::SyncDetail("why".into()), AuthError::Sync),
        (
            AuthError::KdfRejectedDetail("why".into()),
            AuthError::KdfRejected,
        ),
    ] {
        assert_eq!(detailed.message(), plain.message(), "{detailed:?}");
        assert_eq!(detailed.to_string(), plain.to_string(), "{detailed:?}");
    }
}

#[test]
fn unlock_error_family_messages_are_fixed() {
    // `UnlockError::message()` (auth.rs:769-786) is the other status-bar
    // vocabulary; pin its wrapping text as well as the AuthError families.
    assert_eq!(
        UnlockError::MissingProtectedKey.message(),
        "復号キーが応答にありません"
    );
    assert_eq!(
        UnlockError::UnlockFailed("why".into()).message(),
        "復号キーを取得できません（why）"
    );
    assert_eq!(
        UnlockError::ApplySyncFailed("why".into()).message(),
        "同期データを取り込めません（why）"
    );
    assert_eq!(
        UnlockError::ImportFailed("why".into()).message(),
        "vault 変換に失敗しました（why）"
    );
    assert_eq!(UnlockError::Other("raw".into()).message(), "raw");
}

#[test]
fn unlock_error_equality_is_message_only_so_distinct_variants_can_collide() {
    // `UnlockError::PartialEq` (auth.rs:788-794) compares only `message()`.
    // Two values of different variants that render the same status text are
    // therefore equal. This characterization test pins that behaviour so a
    // future change to variant-aware equality is an explicit, reviewed edit.
    let missing = UnlockError::MissingProtectedKey;
    let impersonator = UnlockError::Other(missing.message());
    assert_ne!(
        std::mem::discriminant(&missing),
        std::mem::discriminant(&impersonator),
        "premise: these are different variants"
    );
    assert_eq!(missing.message(), impersonator.message());
    assert_eq!(missing, impersonator, "equality is message-only today");
    assert_eq!(impersonator, missing);

    // A crafted `Other` can render exactly the decorated text of a
    // detail-carrying sibling, so even those variants cross-compare equal.
    for (detailed, text) in [
        (
            UnlockError::UnlockFailed("x".into()),
            "復号キーを取得できません（x）",
        ),
        (
            UnlockError::ApplySyncFailed("x".into()),
            "同期データを取り込めません（x）",
        ),
        (
            UnlockError::ImportFailed("x".into()),
            "vault 変換に失敗しました（x）",
        ),
    ] {
        let crafted = UnlockError::Other(text.to_string());
        assert_ne!(
            std::mem::discriminant(&detailed),
            std::mem::discriminant(&crafted)
        );
        assert_eq!(detailed.message(), text);
        assert_eq!(
            detailed, crafted,
            "rendered text is the only identity: {text}"
        );
        assert_eq!(crafted, detailed);
    }
}

#[test]
fn successful_restore_reports_only_the_from_cache_flag() {
    // Known limit (module docs): the production assignment is in
    // `authenticate_inner` (auth.rs:1112-1131), after `Client::sync_body`.
    // There is no seam to force that call to fail, so this test does NOT cover
    // the assignment itself; it pins only the observable data contract at the
    // `AuthenticatedVault` boundary. `sync_cause` is consumed only in the
    // failure arm via `sync_fallback_failure`; a restored vault carries
    // `from_cache = true`, a fresh one `false`, and the struct has no field
    // for the discarded cause.
    let (master_key, _protected, sync) = unlock_fixture();
    let session = Session::from_token(
        SecretString::from("test-access-token".to_string()),
        std::time::Duration::from_secs(3600),
    )
    .expect("a one-hour token must be accepted");
    let restored = AuthenticatedVault {
        session,
        sync,
        master_key,
        from_cache: true,
    };
    assert!(restored.from_cache);
    let fresh = AuthenticatedVault {
        session: Session::from_token(
            SecretString::from("test-access-token".to_string()),
            std::time::Duration::from_secs(3600),
        )
        .expect("a one-hour token must be accepted"),
        sync: crate::vault_sync::parse_sync(
            br#"{"profile":{"id":"user-1"},"folders":[],"ciphers":[]}"#,
        )
        .expect("sync JSON should parse"),
        master_key: MasterKey::from_bytes([0x11; 32]),
        from_cache: false,
    };
    assert!(!fresh.from_cache);
    // A discarded cause is still composable when the restore fails; on the
    // success path it is simply not surfaced (documented above).
    assert_eq!(
        super::sync_fallback_failure(AuthError::Sync, None).status_message(),
        "同期に失敗しました"
    );
}

#[test]
fn auth_length_caps_are_reexported_from_limits() {
    // The caps must have a single source of truth in `crate::limits`; the
    // `crate::auth::*` path is kept for the lock-screen input state.
    assert_eq!(MAX_CLIENT_ID_LEN, crate::limits::MAX_CLIENT_ID_LEN);
    assert_eq!(MAX_CLIENT_SECRET_LEN, crate::limits::MAX_CLIENT_SECRET_LEN);
    assert_eq!(
        MAX_MASTER_PASSWORD_LEN,
        crate::limits::MAX_MASTER_PASSWORD_LEN
    );
    assert_eq!(MAX_EMAIL_LEN, crate::limits::MAX_EMAIL_LEN);
    assert_eq!(MAX_SERVER_URL_LEN, crate::limits::MAX_SERVER_URL_LEN);
    assert_eq!(DEFAULT_LOGIN_TIMEOUT, crate::limits::DEFAULT_LOGIN_TIMEOUT);
}

#[test]
fn sync_detail_round_trips_through_app_error_with_its_cause() {
    use crate::error::AppError;

    const DETAIL: &str = "sync: unexpected key casing";
    let small = AuthError::SyncDetail(DETAIL.to_string());
    assert_eq!(small.message(), AuthError::Sync.message());
    assert_eq!(
        small,
        AuthError::Sync,
        "the cause is diagnostic, not identity"
    );

    // AuthError -> AppError keeps the typed cause reachable via source().
    let app = AppError::from(small);
    assert!(
        matches!(&app, AppError::SyncCause(cause) if cause.to_string() == DETAIL),
        "the detail must become the AppError cause: {app:?}"
    );
    assert!(std::error::Error::source(&app).is_some());
    assert_eq!(app.message(), AuthError::Sync.message());
    assert_eq!(app, AppError::Sync);

    // ...and back again without losing the text the status bar shows.
    let restored = AuthError::from(app);
    assert!(
        matches!(&restored, AuthError::SyncDetail(detail) if detail == DETAIL),
        "the detail must survive both conversions: {restored:?}"
    );
    assert_eq!(
        restored.status_message(),
        format!("同期に失敗しました（{DETAIL}）")
    );

    let empty = AppError::from(AuthError::SyncDetail(String::new()));
    assert!(matches!(empty, AppError::SyncCause(_)));
    assert!(std::error::Error::source(&empty).is_some());
}

#[test]
fn embedded_literal_and_metadata_hosts_normalize_case_and_trailing_dot() {
    // Both literal rules (auth.rs:463-535) fold the host before matching, so
    // uppercase spellings and a trailing DNS dot cannot slip past the guard.
    for value in [
        "http://169.254.169.254.NIP.IO",
        "http://169.254.169.254.nip.io.",
        "http://169.254.169.254.NIP.IO.",
        "http://169-254-169-254.NIP.IO.",
        "https://169.254.1.1.SSLIP.IO.",
        "http://METADATA.GOOGLE.INTERNAL.",
        "http://INSTANCE-DATA.EC2.INTERNAL.",
    ] {
        assert!(is_blocked_server_url_without_dns(value), "{value}");
    }
    // Call the two classifiers directly as well: `url::Url` already folds
    // ASCII host case, so only this path proves the helper's own fold.
    assert!(super::hostname_embeds_link_local("169.254.169.254.NIP.IO."));
    assert!(super::hostname_embeds_link_local("169-254-169-254.NIP.IO."));
    assert!(super::is_blocked_metadata_host("METADATA.GOOGLE.INTERNAL."));

    // The same fold must not turn public hosts into blocked ones.
    for value in ["https://1.1.1.1.NIP.IO.", "https://vault.example.com."] {
        assert!(!is_blocked_server_url_without_dns(value), "{value}");
    }
    assert!(!super::hostname_embeds_link_local("1.1.1.1.NIP.IO."));

    // validate_config reaches the same classifier on the login path.
    let mut blocked = config();
    blocked.server_url = "http://169.254.169.254.NIP.IO.".into();
    assert_eq!(validate_config(&blocked), Err(AuthError::BlockedServerUrl));
}

#[test]
fn sync_fallback_renders_only_the_immediate_source_of_a_deep_cause() {
    use crate::error::{AppError, BoxedCause};
    use std::fmt;

    #[derive(Debug)]
    struct Innermost(&'static str);
    impl fmt::Display for Innermost {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Innermost {}

    #[derive(Debug)]
    struct Middle(Innermost);
    impl fmt::Display for Middle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("middle failure")
        }
    }
    impl std::error::Error for Middle {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[derive(Debug)]
    struct Outer(Middle);
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

    let cause = AppError::SyncCause(BoxedCause::new(Outer(Middle(Innermost("deepest cause")))));
    // BoxedCause::new keeps all three levels reachable through source().
    let first = std::error::Error::source(&cause).expect("typed cause");
    assert_eq!(first.to_string(), "outer failure");
    let second = std::error::Error::source(first).expect("second cause level");
    assert_eq!(second.to_string(), "middle failure");
    let third = std::error::Error::source(second).expect("third cause level");
    assert_eq!(third.to_string(), "deepest cause");

    let combined =
        super::sync_fallback_failure(cache_restore_failure(AppError::NotFound), Some(cause));
    let status = combined.status_message();
    assert!(status.contains("outer failure"), "{status}");
    // Documented PoC constraint (auth.rs:1029-1058): only the first source
    // level is flattened into the status, so the deeper text stays absent.
    assert!(!status.contains("middle failure"), "{status}");
    assert!(!status.contains("deepest cause"), "{status}");
}

#[test]
fn a_successful_cache_restore_has_no_place_to_keep_the_sync_cause() {
    use crate::error::{AppError, BoxedCause};

    // Known limit (module docs): `authenticate_inner` has no seam to force a
    // sync failure, so this cannot drive the production fallback branch. It
    // pins the current data contract instead: auth.rs:1112-1131 binds
    // `sync_cause` only for the failure arm, while a successful fallback builds
    // `AuthenticatedVault` from `(sync, true)` and drops the cause. The struct
    // has no field for it, so the success status can only be guided by
    // `from_cache`.
    let (master_key, _protected, sync) = unlock_fixture();
    let session = Session::from_token(
        SecretString::from("test-access-token".to_string()),
        std::time::Duration::from_secs(3600),
    )
    .expect("a one-hour token must be accepted");
    let restored = AuthenticatedVault {
        session,
        sync,
        master_key,
        from_cache: true,
    };
    assert!(restored.from_cache, "only the stale-data flag survives");

    // The discarded cause is still an AppError at the call site, but there is
    // no AuthenticatedVault field to forward it to and the success branch
    // never calls sync_fallback_failure.
    let discarded = AppError::SyncCause(BoxedCause::text("HTTP 503 before restore"));
    assert_eq!(
        std::error::Error::source(&discarded).map(ToString::to_string),
        Some("HTTP 503 before restore".to_string())
    );
    assert_eq!(
        super::sync_fallback_failure(AuthError::Sync, None).status_message(),
        "同期に失敗しました",
        "a restored vault carries the stale-data flag, not the sync cause"
    );
}

#[test]
fn weak_kdf_is_rejected_by_the_real_derive_and_reaches_the_status_bar() {
    use crate::error::{AppError, BoxedCause};

    // Exercise the production KDF guard through openwarden itself
    // (auth.rs:1132-1149): a below-minimum PBKDF2 count is refused before any
    // key derivation, so this is deterministic and cheap.
    let weak = Kdf::Pbkdf2 { iterations: 5_000 };
    let password = SecretString::from("correct horse".to_string());
    let error = MasterKey::derive(&password, "alice@example.com", &weak, &KdfPolicy::default())
        .expect_err("a downgraded iteration count must be refused");
    const REASON: &str = "pbkdf2 iterations below the minimum";
    let detail = error.to_string();
    assert_eq!(detail, format!("KDF parameters rejected: {REASON}"));

    // The production conversion keeps the typed error as the AppError cause
    // and renders its text into KdfRejectedDetail for the status bar.
    let small = AuthError::from(AppError::KdfRejectedCause(BoxedCause::new(error)));
    assert!(
        matches!(&small, AuthError::KdfRejectedDetail(text) if text.contains(REASON)),
        "the real KDF reason must survive: {small:?}"
    );
    assert_eq!(small.message(), "KDF 設定がポリシーで拒否されました");
    assert!(small.status_message().contains(REASON));

    let restored = AppError::from(small);
    assert!(matches!(&restored, AppError::KdfRejectedCause(_)));
    assert!(std::error::Error::source(&restored).is_some());
    assert_eq!(restored, AppError::KdfRejected);
}

#[test]
fn embedded_link_local_literals_are_detected_in_non_leading_and_hyphenated_labels() {
    // `hostname_embeds_link_local` scans every four-label window and every
    // hyphenated label (auth.rs:568-591), not only the leading labels. A
    // wildcard-DNS alias may prefix the literal or put it in the middle of the
    // name, so those spellings must still be blocked without DNS.
    for value in [
        "http://prefix.169.254.169.254.nip.io",
        "https://a.b.169.254.1.1.sslip.io",
        "http://sub.169-254-169-254.nip.io",
        "https://svc.169-254-1-1.example.com",
    ] {
        assert!(is_blocked_server_url_without_dns(value), "{value}");
    }
    // Pin the classifier directly as well: `url::Url` only lowercases/folds
    // the host, it does not move the literal into a leading label.
    assert!(super::hostname_embeds_link_local(
        "prefix.169.254.169.254.nip.io"
    ));
    assert!(super::hostname_embeds_link_local(
        "sub.169-254-169-254.nip.io"
    ));

    // A non-link-local literal in the same positions stays allowed.
    for value in [
        "https://prefix.1.1.1.1.nip.io",
        "https://sub.192-168-1-10.nip.io",
    ] {
        assert!(!is_blocked_server_url_without_dns(value), "{value}");
    }

    // The public validation entry point reaches the same non-leading check.
    let mut blocked = config();
    blocked.server_url = "http://prefix.169.254.169.254.nip.io".into();
    assert_eq!(validate_config(&blocked), Err(AuthError::BlockedServerUrl));
}

#[test]
fn sync_fallback_strips_the_sync_prefix_from_a_generic_cache_other() {
    use crate::error::{AppError, BoxedCause};

    // An unrelated cache error has no specific reason, so `cache_restore_status`
    // supplies the generic, already-prefixed status that `cache_restore_failure`
    // wraps in `AuthError::Other` (cache.rs:861-874, auth.rs:979-989).
    // `sync_fallback_failure` must strip that family prefix and the surrounding
    // parentheses before composing the detail (auth.rs:1029-1058); otherwise the
    // status bar would read "同期に失敗しました（同期に失敗しました（…））".
    let fallback = cache_restore_failure(AppError::Other("unclassified cache failure".into()));
    assert!(matches!(&fallback, AuthError::Other(_)));
    assert_eq!(
        fallback.status_message(),
        "同期に失敗しました（キャッシュを復元できませんでした）"
    );

    let combined = super::sync_fallback_failure(
        fallback,
        Some(AppError::SyncCause(BoxedCause::text("HTTP 503"))),
    );
    assert_eq!(combined.message(), AuthError::Sync.message());
    assert_eq!(
        combined.status_message(),
        "同期に失敗しました（キャッシュを復元できませんでした（HTTP 503））"
    );
    assert!(matches!(
        &combined,
        AuthError::SyncDetail(detail)
            if detail.as_str() == "キャッシュを復元できませんでした（HTTP 503）"
    ));

    // An `Other` without the family prefix is kept verbatim by the `unwrap_or`
    // of the same strip step (auth.rs:1044-1051).
    let bare = super::sync_fallback_failure(
        AuthError::Other("未分類の失敗"),
        Some(AppError::Other("no-source reason".into())),
    );
    assert_eq!(
        bare.status_message(),
        "同期に失敗しました（未分類の失敗（no-source reason））"
    );
}

#[test]
fn plain_auth_errors_convert_forward_to_the_matching_app_error_variant() {
    use crate::error::AppError;

    // `AppError`'s PartialEq compares message + detail only, so equality alone
    // cannot distinguish a wrong plain variant that shares its family text.
    // Discriminants pin the exact arm of the forward conversion
    // (auth.rs:204-234); source() must stay absent because plain variants carry
    // no typed cause.
    let cases: Vec<(&str, AuthError, AppError)> = vec![
        (
            "missing_field",
            AuthError::MissingField("client_id"),
            AppError::MissingField("client_id"),
        ),
        (
            "invalid_server_url",
            AuthError::InvalidServerUrl,
            AppError::InvalidServerUrl,
        ),
        (
            "blocked_server_url",
            AuthError::BlockedServerUrl,
            AppError::BlockedServerUrl,
        ),
        (
            "invalid_email",
            AuthError::InvalidEmail,
            AppError::InvalidEmail,
        ),
        (
            "client_setup",
            AuthError::ClientSetup,
            AppError::ClientSetup,
        ),
        ("prelogin", AuthError::Prelogin, AppError::Prelogin),
        ("login", AuthError::Login, AppError::Login),
        ("sync", AuthError::Sync, AppError::Sync),
        (
            "kdf_rejected",
            AuthError::KdfRejected,
            AppError::KdfRejected,
        ),
        ("timeout", AuthError::Timeout, AppError::Timeout),
        (
            "other",
            AuthError::Other("canary"),
            AppError::Other("canary".to_string()),
        ),
    ];
    assert_eq!(cases.len(), 11);

    for (name, auth, expected) in cases {
        let family_message = auth.message().to_string();
        let converted: AppError = auth.into();
        assert_eq!(
            std::mem::discriminant(&converted),
            std::mem::discriminant(&expected),
            "{name}: wrong AppError variant"
        );
        assert_eq!(converted, expected, "{name}");
        assert_eq!(converted.message(), family_message.as_str(), "{name}");
        assert_eq!(converted.to_string(), family_message, "{name}");
        assert!(std::error::Error::source(&converted).is_none(), "{name}");
    }
}

#[test]
fn plain_app_error_variants_convert_back_to_plain_auth_errors() {
    // The reverse direction (AppError -> AuthError) must map a plain variant
    // to its plain sibling, not to a `Detail` variant or the generic `Other`
    // fallback (auth.rs:236-278). `AppError` is not Clone, so each case is
    // consumed once and the expected family message is captured up front.
    let cases: Vec<(AppError, AuthError, &str)> = vec![
        (
            AppError::MissingField("server_url"),
            AuthError::MissingField("server_url"),
            "認証情報が未入力です",
        ),
        (
            AppError::InvalidServerUrl,
            AuthError::InvalidServerUrl,
            "サーバー URL が不正です（HTTPS または loopback の HTTP）",
        ),
        (
            AppError::BlockedServerUrl,
            AuthError::BlockedServerUrl,
            "サーバー URL が link-local アドレスを指しています",
        ),
        (
            AppError::InvalidEmail,
            AuthError::InvalidEmail,
            "メールアドレスの形式が不正です",
        ),
        (
            AppError::ClientSetup,
            AuthError::ClientSetup,
            "クライアントを初期化できませんでした",
        ),
        (
            AppError::Prelogin,
            AuthError::Prelogin,
            "サーバー情報の取得に失敗しました",
        ),
        (AppError::Login, AuthError::Login, "ログインに失敗しました"),
        (AppError::Sync, AuthError::Sync, "同期に失敗しました"),
        (
            AppError::KdfRejected,
            AuthError::KdfRejected,
            "KDF 設定がポリシーで拒否されました",
        ),
        (
            AppError::Timeout,
            AuthError::Timeout,
            "ログインがタイムアウトしました",
        ),
    ];
    assert_eq!(cases.len(), 10);

    for (app, expected, family_message) in cases {
        let converted = AuthError::from(app);
        assert_eq!(converted, expected, "{family_message}");
        assert_eq!(converted.message(), family_message);
        assert!(
            !matches!(
                &converted,
                AuthError::Other(_)
                    | AuthError::InvalidServerUrlDetail(_)
                    | AuthError::ClientSetupDetail(_)
                    | AuthError::PreloginDetail(_)
                    | AuthError::LoginDetail(_)
                    | AuthError::SyncDetail(_)
                    | AuthError::KdfRejectedDetail(_)
            ),
            "a plain failure must not pick up a detail sibling: {converted:?}"
        );
        // The forward direction still lands back in the same family.
        assert_eq!(AppError::from(converted).message(), family_message);
    }
}

#[test]
fn missing_protected_key_round_trips_through_app_error() {
    // This variant has no detail/cause sibling, so both conversions must keep
    // the exact discriminant and status text (auth.rs:293-352).
    let small = UnlockError::MissingProtectedKey;
    let message = small.message();
    assert!(!message.is_empty());

    let app = AppError::from(small.clone());
    assert!(matches!(&app, AppError::MissingProtectedKey));
    assert_eq!(app.message(), message);
    assert!(std::error::Error::source(&app).is_none());

    let restored = UnlockError::from(app);
    assert!(matches!(&restored, UnlockError::MissingProtectedKey));
    assert_eq!(restored, UnlockError::MissingProtectedKey);
    assert_eq!(restored.message(), message);
    assert!(std::error::Error::source(&restored).is_none());

    // Also start from the plain AppError, the reverse direction.
    let from_app = UnlockError::from(AppError::MissingProtectedKey);
    assert_eq!(from_app, UnlockError::MissingProtectedKey);
    assert_eq!(AppError::from(from_app).message(), message);
}

#[test]
fn every_unparseable_or_unsupported_url_is_invalid_server_url() {
    // A URL `url::Url` cannot parse, a host-less URL with no authority, and a
    // scheme `self_hosted` refuses all reach the same parser error arm
    // (auth.rs:703-705). None of these inputs is link-local, so the SSRF
    // classifier must not claim them first; none is blank, so the MissingField
    // check must not fire either. Every one must surface as InvalidServerUrl
    // with the parser detail preserved in the small enum.
    for value in [
        "not a url",                // Url::parse failure: no scheme
        "vault.example.com",        // Url::parse failure: bare relative reference
        "://bad",                   // Url::parse failure: empty scheme
        "https://exa mple.com",     // Url::parse failure: whitespace in host
        "https://",                 // Url::parse failure: empty host
        "mailto:alice@example.com", // parseable, but host-less
        "data:text/plain,hello",    // parseable, but host-less
        "about:blank",              // parseable, but host-less
        "http://vault.example.com", // parseable, but not https / loopback
    ] {
        assert!(
            !is_blocked_server_url_without_dns(value),
            "fixture must not be a blocked host: {value}"
        );
        let mut invalid = config();
        invalid.server_url = value.into();
        let error = validate_config(&invalid).unwrap_err();
        assert_eq!(error, AuthError::InvalidServerUrl, "{value}");
        assert!(
            matches!(&error, AuthError::InvalidServerUrlDetail(_)),
            "the parser reason must survive for {value}: {error:?}"
        );
        // A cause replaces the parenthesised hint, so the family wording is
        // present but the plain `message()` (with its hint) is not a prefix.
        assert!(error.status_message().contains("サーバー URL が不正です"));
    }

    // The only URL-shaped inputs that are NOT InvalidServerUrl are blank ones:
    // the earlier field check reports them as missing (auth.rs:682-684).
    for blank in ["", " ", " \t\n\u{3000}"] {
        let mut missing = config();
        missing.server_url = blank.into();
        assert_eq!(
            validate_config(&missing),
            Err(AuthError::MissingField("server_url")),
            "{blank:?}"
        );
    }
}

#[test]
fn resolve_host_failure_fails_open_to_an_empty_vector_without_dns() {
    // `resolve_host` (auth.rs:621-635) returns an empty vector when
    // `to_socket_addrs` fails. Injecting a failing resolver is impossible from
    // this module (no seam), and relying on an unresolvable public name would
    // make the test depend on real DNS. An interior NUL is rejected while the
    // `&str` is converted to a C string, i.e. before any resolver call, so the
    // error arm is exercised deterministically and offline.
    let malformed = "not\0a-host.example.com";
    assert!(super::resolve_host(malformed).is_empty());

    // Fail-open semantics: an empty answer contains no link-local address, so
    // the classifier does not block the URL. The injected-resolver path pins
    // the same policy a real lookup would use after this empty vector.
    assert!(!is_blocked_server_url_with(
        "https://vault.example.com",
        |_| Vec::new()
    ));
    assert!(!is_blocked_server_url_without_dns(
        "https://vault.example.com"
    ));
    // A non-empty link-local answer still blocks, so the assertions above are
    // about the empty-answer policy rather than a disabled SSRF guard.
    let link_local: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| vec![link_local]
    ));
}

#[test]
fn unlock_error_display_and_to_string_equal_message_for_every_variant() {
    use crate::error::BoxedCause;

    // `UnlockError`'s Display impl (auth.rs:798-802) delegates to `message()`
    // instead of keeping a second rendering. Cover all eight variants,
    // including the cause-carrying ones whose extra context is only visible
    // through `status_message()` / `source()` and must not leak into Display.
    let cases = vec![
        UnlockError::MissingProtectedKey,
        UnlockError::UnlockFailed("why".into()),
        UnlockError::UnlockFailedCause("why".into(), BoxedCause::text("root cause")),
        UnlockError::ApplySyncFailed("why".into()),
        UnlockError::ApplySyncFailedCause("why".into(), BoxedCause::text("root cause")),
        UnlockError::ImportFailed("why".into()),
        UnlockError::ImportFailedCause("why".into(), BoxedCause::text("root cause")),
        UnlockError::Other("raw detail".into()),
    ];
    assert_eq!(cases.len(), 8);

    for error in cases {
        let expected = error.message();
        assert_eq!(format!("{error}"), expected, "{error:?}");
        assert_eq!(error.to_string(), expected, "{error:?}");
        // The same string is what PartialEq compares, so no variant can drift
        // between identity, Display and the status-bar message.
        assert_eq!(error, UnlockError::Other(expected.clone()));
    }
}

#[test]
fn plain_failed_unlock_variants_have_no_source() {
    use crate::error::BoxedCause;

    // Only the three `*Cause` variants override `Error::source()`
    // (auth.rs:804-813); their plain siblings store just a String and must
    // report None instead of inventing a cause.
    let plain = [
        UnlockError::UnlockFailed("why".into()),
        UnlockError::ApplySyncFailed("why".into()),
        UnlockError::ImportFailed("why".into()),
        UnlockError::MissingProtectedKey,
        UnlockError::Other("raw detail".into()),
    ];
    for error in &plain {
        assert!(
            std::error::Error::source(error).is_none(),
            "plain variant must have no source: {error:?}"
        );
    }

    // The positive half keeps the assertion meaningful: the cause-carrying
    // siblings do expose a source with the retained text.
    let caused = [
        UnlockError::UnlockFailedCause("why".into(), BoxedCause::text("root cause")),
        UnlockError::ApplySyncFailedCause("why".into(), BoxedCause::text("root cause")),
        UnlockError::ImportFailedCause("why".into(), BoxedCause::text("root cause")),
    ];
    for error in &caused {
        let source =
            std::error::Error::source(error).expect("a *Cause variant must keep its typed cause");
        assert_eq!(source.to_string(), "root cause", "{error:?}");
    }
}

#[test]
fn plain_auth_error_variants_render_the_same_status_and_family_message() {
    // `status_message()` (auth.rs:162-193) appends text only for `MissingField`
    // and for non-empty `Detail` variants. Every plain variant must fall
    // through to `message()` unchanged, including `Other`'s owned-by-reference
    // family text. `to_string()` uses the same `message()` (auth.rs:196-200).
    let plain = [
        AuthError::InvalidServerUrl,
        AuthError::BlockedServerUrl,
        AuthError::InvalidEmail,
        AuthError::ClientSetup,
        AuthError::Prelogin,
        AuthError::Login,
        AuthError::Sync,
        AuthError::KdfRejected,
        AuthError::Timeout,
        AuthError::Other("unclassified failure"),
    ];
    for error in plain {
        assert_eq!(error.status_message(), error.message(), "{error:?}");
        assert_eq!(error.status_message(), error.to_string(), "{error:?}");
    }
    // The decorated families really do differ, so the assertions above are not
    // vacuous: a stub that always returned `message()` would fail these two.
    assert_ne!(
        AuthError::MissingField("email").status_message(),
        AuthError::MissingField("email").message()
    );
    assert_ne!(
        AuthError::LoginDetail("invalid_client".into()).status_message(),
        AuthError::Login.message()
    );
}

#[test]
fn prelogin_cause_converts_forward_to_prelogin_detail() {
    use crate::error::{AppError, BoxedCause};

    // The AppError -> AuthError direction (auth.rs:253-254) must keep the
    // rendered cause in `PreloginDetail`; the sibling conversion and the
    // reflexive equality are covered by `prelogin_is_reflexive_and_keeps_its_detail`.
    const DETAIL: &str = "prelogin: TLS handshake failed";
    let app = AppError::PreloginCause(BoxedCause::text(DETAIL));
    assert!(
        std::error::Error::source(&app).is_some(),
        "premise: typed cause"
    );

    let small = AuthError::from(app);
    assert!(
        matches!(&small, AuthError::PreloginDetail(detail) if detail == DETAIL),
        "the cause text must survive the UI boundary: {small:?}"
    );
    assert_eq!(
        small,
        AuthError::Prelogin,
        "the cause is diagnostic, not identity"
    );
    assert_eq!(small.message(), AuthError::Prelogin.message());
    assert_eq!(small.to_string(), AuthError::Prelogin.message());
    assert_eq!(
        small.status_message(),
        format!("{}（{DETAIL}）", AuthError::Prelogin.message())
    );
    // The small enum owns only text: the typed cause stops at this boundary.
    assert!(std::error::Error::source(&small).is_none());

    // Converting back restores a cause-carrying AppError with the same text.
    let restored = AppError::from(small);
    assert!(
        matches!(&restored, AppError::PreloginCause(cause) if cause.to_string() == DETAIL),
        "the detail must become the cause again: {restored:?}"
    );
    assert!(std::error::Error::source(&restored).is_some());
    assert_eq!(restored, AppError::Prelogin);

    // A typed (non-text) cause is rendered the same way at the UI boundary.
    #[derive(Debug)]
    struct Inner(&'static str);
    impl std::fmt::Display for Inner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Inner {}
    let typed = AppError::PreloginCause(BoxedCause::new(Inner("connection refused")));
    let typed_small = AuthError::from(typed);
    assert!(
        typed_small.status_message().contains("connection refused"),
        "{}",
        typed_small.status_message()
    );
    assert_eq!(typed_small, AuthError::Prelogin);

    // An empty cause still selects the Detail variant but adds no decoration.
    let empty = AuthError::from(AppError::PreloginCause(BoxedCause::text("")));
    assert!(matches!(&empty, AuthError::PreloginDetail(detail) if detail.is_empty()));
    assert_eq!(empty.status_message(), AuthError::Prelogin.message());
    assert_eq!(empty, AuthError::Prelogin);
}

#[test]
fn ipv4_mapped_ipv6_link_local_dns_answers_are_blocked() {
    // `is_link_local_ip` (auth.rs:499-530) unwraps `::ffff:a.b.c.d` before the
    // fe80::/10 check. A DNS answer in that mapped form must block a name just
    // like a native 169.254.* answer, including when mixed with a public A
    // record (split-horizon / rebinding).
    let mapped_metadata: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
    let mapped_lan: IpAddr = "::ffff:192.168.1.10".parse().unwrap();
    let public: IpAddr = "93.184.216.34".parse().unwrap();

    assert!(is_link_local_ip(mapped_metadata));
    assert!(!is_link_local_ip(mapped_lan));
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| vec![public, mapped_metadata]
    ));
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| vec![mapped_metadata]
    ));
    // A mapped private-LAN address is not link-local, so the same name stays
    // allowed -- the filter is not a blanket "block every mapped address".
    assert!(!is_blocked_server_url_with(
        "https://vault.example.com",
        |_| vec![public, mapped_lan]
    ));

    // The bracketed literal form takes the Ipv6 host arm of the classifier.
    assert!(is_blocked_server_url_without_dns(
        "https://[::ffff:169.254.169.254]"
    ));
    assert!(!is_blocked_server_url_without_dns(
        "https://[::ffff:192.168.1.10]"
    ));
}

#[test]
fn userinfo_does_not_hide_a_blocked_host_from_the_ssrf_classifier() {
    // The classifier matches on `url.host()` / `url.host_str()` (auth.rs:603-
    // 618), which exclude userinfo. Credentials in a URL must therefore not
    // change the literal, metadata-host, wildcard-alias or DNS-answer result.
    for value in [
        "https://user:pass@169.254.169.254/latest/meta-data",
        "https://user:pass@[fe80::1]/",
        "https://user:pass@[::ffff:169.254.1.1]/",
        "https://user:pass@metadata.google.internal/latest",
        "https://user:pass@169.254.169.254.nip.io",
    ] {
        assert!(
            is_blocked_server_url_without_dns(value),
            "userinfo must not hide the blocked host: {value}"
        );
        let mut invalid = config();
        invalid.server_url = value.to_string();
        assert_eq!(
            validate_config(&invalid),
            Err(AuthError::BlockedServerUrl),
            "{value}"
        );
    }

    // A public host with userinfo stays allowed without DNS and with a public
    // answer; only a link-local answer in the injected resolver blocks it.
    const PUBLIC: &str = "https://user:pass@vault.example.com/login";
    assert!(!is_blocked_server_url_without_dns(PUBLIC));
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(!is_blocked_server_url_with(PUBLIC, |_| vec![public]));
    assert!(is_blocked_server_url_with(PUBLIC, |_| vec![
        public, metadata
    ]));
}

#[test]
fn nondecimal_and_ipv6_embedded_link_local_literals_are_a_known_constraint() {
    // Documented limit of `hostname_embeds_link_local` (auth.rs:537-591):
    // only dotted/hyphenated *decimal* IPv4 quads are decoded there. A bare
    // non-decimal literal used as the WHOLE host is still normalized by
    // `url::Url`'s WHATWG IPv4 parser before the classifier sees it, so every
    // spelling of 169.254.169.254 below stays blocked offline.
    for whole_host in [
        "http://169.254.169.254",     // decimal control
        "http://0xa9fea9fe",          // hexadecimal integer
        "http://0251.0376.0251.0376", // octal dotted quad (0251=169, 0376=254)
        "http://2852039166",          // 32-bit decimal integer
    ] {
        assert!(
            is_blocked_server_url_without_dns(whole_host),
            "whole-host spelling must be blocked: {whole_host}"
        );
        // A literal Ipv4 host never reaches the resolver, so the network-capable
        // form must agree without any DNS.
        assert!(
            is_blocked_server_url(whole_host),
            "network-capable classifier must agree: {whole_host}"
        );
        // Pin the premise: `url::Url` really normalized the literal to the
        // link-local IPv4 address rather than leaving a DNS name to look up.
        assert_eq!(
            url::Url::parse(whole_host).unwrap().host(),
            Some(url::Host::Ipv4(std::net::Ipv4Addr::new(169, 254, 169, 254))),
            "{whole_host}"
        );
    }

    // The same spellings embedded in a wildcard-DNS name are invisible to the
    // network-free classifier and to `validate_config`'s SSRF check. Pin the
    // constraint so it is reviewed rather than rediscovered.
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    for alias in [
        "http://0xa9fea9fe.nip.io",
        "http://0251.0376.0251.0376.nip.io",
        "http://2852039166.nip.io",
        "http://fe80--1.sslip.io",
        "http://fe80-0-0-0-0-0-0-1.nip.io",
    ] {
        assert!(
            !is_blocked_server_url_without_dns(alias),
            "documented classifier limit: {alias}"
        );
        // The resolver-backed form still closes the gap whenever DNS is
        // available: a link-local answer rejects the whole name.
        assert!(
            is_blocked_server_url_with(alias, |_| vec![metadata]),
            "resolver path must still block {alias}"
        );
    }

    // Control: the decimal form the classifier does understand is blocked
    // without any lookup, so the assertions above are about the spelling and
    // not about a disabled wildcard-alias rule.
    assert!(is_blocked_server_url_without_dns(
        "http://169.254.169.254.nip.io"
    ));
}

#[test]
fn ipv4_compatible_ipv6_link_local_is_a_known_blind_spot() {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // `::a9fe:a9fe` is the IPv4-COMPATIBLE (`::a.b.c.d`) spelling of the
    // link-local address 169.254.169.254. It is a different form from the
    // IPv4-MAPPED `::ffff:a9fe:a9fe`, which the guard already blocks.
    let compatible: Ipv6Addr = "::a9fe:a9fe".parse().unwrap();
    // Rust's stable API has no `to_ipv4_compatible`; check the trailing
    // 32 bits directly to pin the same premise.
    let octets = compatible.octets();
    assert_eq!(
        Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]),
        Ipv4Addr::new(169, 254, 169, 254),
        "premise: compatible form of the link-local address"
    );
    assert_eq!(
        compatible.to_ipv4_mapped(),
        None,
        "premise: not an IPv4-mapped address"
    );

    // Known constraint documented on `is_link_local_ip` (auth.rs:499-530):
    // only `to_ipv4_mapped()` is unwrapped, so the compatible form falls
    // through to the fe80::/10 check and is NOT detected. Pin that behaviour
    // so a future fix is an explicit, reviewed change.
    assert!(!is_link_local_ip(IpAddr::V6(compatible)));
    assert!(!is_blocked_server_url_without_dns("http://[::a9fe:a9fe]"));
    // The bracketed URL really does reach the classifier as an Ipv6 host, so
    // the assertion above is about the compatible-form blind spot and not
    // about a parse failure that never inspected the address.
    match url::Url::parse("http://[::a9fe:a9fe]").unwrap().host() {
        Some(url::Host::Ipv6(host)) => assert_eq!(host, compatible),
        other => panic!("expected a bracketed IPv6 host, got {other:?}"),
    }

    // Control: the mapped spelling of the same address is still blocked, and
    // an IPv4-compatible spelling of a non-link-local address is likewise
    // allowed. This keeps the blind spot scoped to one specific form.
    assert!(is_link_local_ip("::ffff:169.254.169.254".parse().unwrap()));
    assert!(is_blocked_server_url_without_dns(
        "http://[::ffff:a9fe:a9fe]"
    ));
    assert!(!is_link_local_ip("::c0a8:010a".parse().unwrap()));
}

#[test]
fn injected_resolver_receives_only_the_parsed_host_name() {
    // `is_blocked_server_url_with` (auth.rs:593-619) passes `url.host_str()`
    // to the resolver, not the raw URL: userinfo, an explicit port, the path,
    // the query and ASCII host case must not reach DNS. Capture the argument
    // so the seam's contract is checked rather than only its boolean result.
    let seen = std::cell::RefCell::new(Vec::new());
    for value in [
        "https://vault.example.com:8443/path?token=x",
        "https://user:pass@VAULT.EXAMPLE.COM/login",
    ] {
        seen.borrow_mut().clear();
        let blocked = is_blocked_server_url_with(value, |host| {
            seen.borrow_mut().push(host.to_string());
            Vec::new()
        });
        assert!(!blocked, "{value}");
        let hosts = seen.borrow();
        assert_eq!(hosts.len(), 1, "{value}: {hosts:?}");
        assert_eq!(hosts[0], "vault.example.com", "{value}: {hosts:?}");
    }

    // A literal host is classified before the resolver is consulted at all.
    // A resolver that panics proves this branch never reaches DNS.
    assert!(is_blocked_server_url_with("http://169.254.1.1", |_| {
        panic!("a literal host must not consult DNS")
    }));
}

#[test]
fn more_than_four_hyphen_parts_fail_open_offline() {
    // Documented limit of `hostname_embeds_link_local` (auth.rs): the
    // hyphenated branch only joins exactly four parts. A five-part literal is
    // not decoded by the network-free classifier, so it fails open until a
    // resolver answer blocks it. Pin the constraint so a future fix is an
    // explicit, reviewed change.
    let alias = "http://169-254-1-1-9.nip.io";
    let host = "169-254-1-1-9.nip.io";
    assert!(!super::hostname_embeds_link_local(host));
    assert!(!is_blocked_server_url_without_dns(alias));
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(is_blocked_server_url_with(alias, |_| vec![metadata]));

    // Control: the four-part spelling of the same literal is decoded offline,
    // so the assertions above are about the part count and not a disabled
    // wildcard-alias rule.
    assert!(super::hostname_embeds_link_local("169-254-1-1.nip.io"));
    assert!(is_blocked_server_url_without_dns(
        "http://169-254-1-1.nip.io"
    ));
}

#[test]
fn legacy_unlock_failed_cause_loses_only_the_status_decoration() {
    use crate::error::BoxedCause;

    // The legacy `AppError::UnlockFailedCause` stores a fully formatted
    // status message. `unlock_detail` (auth.rs:286-291) must strip that one
    // prefix/suffix pair when converting to `UnlockError::UnlockFailedCause`,
    // while `Error::source()` keeps the typed cause (auth.rs:804-813).
    let decorated = "復号キーを取得できません（bad key）";
    let app = AppError::UnlockFailedCause(
        decorated.to_string(),
        BoxedCause::text("original decryption failure"),
    );
    let small = UnlockError::from(app);
    match &small {
        UnlockError::UnlockFailedCause(detail, cause) => {
            assert_eq!(detail.as_str(), "bad key", "{small:?}");
            assert_eq!(cause.to_string(), "original decryption failure");
        }
        other => panic!("cause was dropped: {other:?}"),
    }
    assert_eq!(small.message(), "復号キーを取得できません（bad key）");
    assert!(std::error::Error::source(&small).is_some());

    // Converting back decorates exactly once, never twice.
    assert_eq!(
        AppError::from(small).message(),
        AppError::unlock_failed_cause("bad key", BoxedCause::text("original decryption failure"))
            .message()
    );

    // A detail that only resembles the prefix is kept verbatim.
    let truncated = "復号キーを取得できません（truncated";
    let raw = UnlockError::from(AppError::UnlockFailedCause(
        truncated.to_string(),
        BoxedCause::text("io failure"),
    ));
    assert_eq!(
        raw,
        UnlockError::UnlockFailedCause(truncated.to_string(), BoxedCause::text("io failure"))
    );
    assert_eq!(
        AppError::from(raw).message(),
        format!("復号キーを取得できません（{truncated}）")
    );
}

#[test]
fn sync_fallback_uses_the_cause_message_when_its_source_is_empty() {
    use crate::error::{AppError, BoxedCause};
    use std::fmt;

    #[derive(Debug)]
    struct EmptySource;
    impl fmt::Display for EmptySource {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }
    impl std::error::Error for EmptySource {}

    // `sync_fallback_failure` renders `Error::source()` first and falls back
    // to `cause.message()` when that text is empty (auth.rs:1033-1036). Here the
    // source exists but renders as `""`, so the assertion distinguishes this
    // branch from "no source at all" (covered by a sibling test).
    let cause = AppError::SyncCause(BoxedCause::new(EmptySource));
    let source = std::error::Error::source(&cause).expect("a typed source exists");
    assert_eq!(source.to_string(), "", "premise: empty source text");

    let combined =
        super::sync_fallback_failure(cache_restore_failure(AppError::CacheExpired), Some(cause));
    assert_eq!(combined.message(), AuthError::Sync.message());
    assert_eq!(
        combined.status_message(),
        "同期に失敗しました（キャッシュが有効期限を過ぎています（同期に失敗しました））"
    );
    assert!(matches!(
        &combined,
        AuthError::SyncDetail(detail)
            if detail.as_str() == "キャッシュが有効期限を過ぎています（同期に失敗しました）"
    ));
}

#[test]
fn link_local_urls_with_unicode_internal_whitespace_are_blocked() {
    // Unicode whitespace in the path, query or userinfo is percent-encoded by
    // `Url::parse` and never moves the host out of a link-local range. Both the
    // network-capable classifier (literal / metadata hosts need no DNS here)
    // and the offline subset used by `validate_config` must reject these.
    for value in [
        "http://169.254.169.254/\u{3000}latest/meta-data",
        "http://169.254.169.254/latest?q=\u{3000}value",
        "http://user\u{3000}pass@169.254.169.254/",
        "http://[fe80::1]/\u{3000}path",
        "http://metadata.google.internal/\u{3000}latest",
    ] {
        assert!(is_blocked_server_url(value), "{value:?}");
        assert!(is_blocked_server_url_without_dns(value), "{value:?}");

        let mut config = config();
        config.server_url = value.into();
        assert_eq!(
            validate_config(&config),
            Err(AuthError::BlockedServerUrl),
            "{value:?}"
        );
    }
}

#[test]
fn padded_link_local_urls_are_blocked_after_the_caller_trims_them() {
    // `validate_config` and `authenticate_inner` both pass
    // `server_url.trim()` to the classifier (auth.rs:700,1071), so Rust's
    // Unicode-aware trim removes U+3000 padding before `Url::parse` sees it.
    // Padding must never let a metadata endpoint through validation.
    for padded in [
        " \thttp://169.254.169.254\u{3000}",
        "\u{3000}http://[fe80::1]\t",
        "  http://metadata.google.internal  ",
    ] {
        let trimmed = padded.trim();
        assert!(is_blocked_server_url(trimmed), "{padded:?}");
        assert!(is_blocked_server_url_without_dns(trimmed), "{padded:?}");

        let mut config = config();
        config.server_url = padded.into();
        assert_eq!(
            validate_config(&config),
            Err(AuthError::BlockedServerUrl),
            "{padded:?}"
        );
    }
}

#[test]
fn padded_email_is_trimmed_before_the_length_cap() {
    // `valid_email` trims before counting characters (auth.rs:409-412), and
    // `clamp_auth_config` now applies the same normalization before truncating
    // (auth.rs:391-403). Padding must therefore never cut the domain tail and
    // silently turn a valid address into a different one.
    let suffix = "@example.com";
    let local_len = MAX_EMAIL_LEN - suffix.len();
    let address = format!("{}{suffix}", "a".repeat(local_len));
    assert_eq!(address.chars().count(), MAX_EMAIL_LEN);
    assert!(valid_email(&address));

    let padded = format!("  {address}\t");
    let mut value = config();
    value.email = padded.clone();
    clamp_auth_config(&mut value);
    assert_eq!(value.email, address, "padding must not morph the address");
    assert_eq!(validate_config(&value), Ok(()));

    // A padded over-long value is capped *after* the trim, so the retained
    // prefix is still the original address rather than leading whitespace.
    let mut over = config();
    over.email = format!(" {address}overlong ");
    clamp_auth_config(&mut over);
    assert_eq!(over.email.chars().count(), MAX_EMAIL_LEN);
    assert_eq!(
        over.email, address,
        "the excess tail is dropped, not the domain"
    );
    assert_eq!(validate_config(&over), Ok(()));
    // Clamping is idempotent: it never reintroduces the padding.
    clamp_auth_config(&mut over);
    assert_eq!(over.email, address);
}

#[test]
fn non_link_local_metadata_ip_is_blocked_in_every_classifier_path() {
    // Alibaba's metadata endpoint uses an address outside link-local ranges.
    // The literal, wildcard-DNS and resolver paths must all reject it.
    let metadata: IpAddr = "100.100.100.200".parse().unwrap();
    assert!(!is_link_local_ip(metadata), "premise: not link-local");
    assert!(super::is_blocked_metadata_ip(metadata));

    for value in [
        "http://100.100.100.200",
        "https://100.100.100.200/latest/meta-data",
        "http://100.100.100.200.nip.io",
        "http://100-100-100-200.nip.io",
    ] {
        assert!(is_blocked_server_url_without_dns(value), "{value}");
        assert!(is_blocked_server_url(value), "{value}");
        let mut config = config();
        config.server_url = value.into();
        assert_eq!(validate_config(&config), Err(AuthError::BlockedServerUrl));
    }
    // A DNS name resolving to the metadata IP is refused as a whole.
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { vec![metadata] }
    ));

    // A neighbouring address stays allowed: the guard is not a blanket block
    // of the surrounding range.
    let neighbour: IpAddr = "100.100.100.201".parse().unwrap();
    assert!(!is_blocked_server_url_without_dns("http://100.100.100.201"));
    assert!(!is_blocked_server_url_with(
        "https://vault.example.com",
        |_| { vec![neighbour] }
    ));
    let mut allowed = config();
    allowed.server_url = "https://100.100.100.201".into();
    assert_eq!(validate_config(&allowed), Ok(()));
}

#[test]
fn empty_causes_keep_the_family_message_for_the_five_non_url_details() {
    use crate::error::{AppError, BoxedCause};

    // The five non-URL detail families share `cause_status`: an empty cause
    // adds no `（…）` suffix, a non-empty one adds exactly one group.
    let empty = [
        (
            AppError::ClientSetupCause(BoxedCause::text("")),
            AuthError::ClientSetup,
        ),
        (
            AppError::PreloginCause(BoxedCause::text("")),
            AuthError::Prelogin,
        ),
        (AppError::LoginCause(BoxedCause::text("")), AuthError::Login),
        (AppError::SyncCause(BoxedCause::text("")), AuthError::Sync),
        (
            AppError::KdfRejectedCause(BoxedCause::text("")),
            AuthError::KdfRejected,
        ),
    ];
    assert_eq!(empty.len(), 5, "all five families are pinned");
    for (app, plain) in empty {
        let small = AuthError::from(app);
        assert_eq!(small.status_message(), plain.message(), "{small:?}");
        assert_eq!(small.status_message(), small.to_string());
        assert!(!small.status_message().contains("（）"), "{small:?}");
        assert_eq!(small, plain, "the cause is diagnostic, not identity");
    }

    let populated = [
        AppError::ClientSetupCause(BoxedCause::text("reason")),
        AppError::PreloginCause(BoxedCause::text("reason")),
        AppError::LoginCause(BoxedCause::text("reason")),
        AppError::SyncCause(BoxedCause::text("reason")),
        AppError::KdfRejectedCause(BoxedCause::text("reason")),
    ];
    for app in populated {
        let status = AuthError::from(app).status_message();
        assert!(status.contains("reason"), "{status}");
        assert_eq!(status.matches('（').count(), 1, "{status}");
        assert!(status.ends_with('）'), "{status}");
    }
}

#[test]
fn invalid_server_url_detail_replaces_the_hint_instead_of_doubling_parentheses() {
    use crate::error::{AppError, BoxedCause};

    let family = "サーバー URL が不正です（HTTPS または loopback の HTTP）";
    assert_eq!(AuthError::InvalidServerUrl.message(), family);
    let detailed = AuthError::from(AppError::InvalidServerUrlCause(BoxedCause::text(
        "bad scheme",
    )));
    assert_eq!(
        detailed.status_message(),
        "サーバー URL が不正です（bad scheme）"
    );
    assert!(!detailed
        .status_message()
        .contains("HTTPS または loopback の HTTP"));
    assert!(!detailed.status_message().contains("）（"));

    // An empty cause keeps the full family message, hint included.
    let empty = AuthError::from(AppError::InvalidServerUrlCause(BoxedCause::text("")));
    assert_eq!(empty.status_message(), family);
    assert!(!empty.status_message().contains("（）"));
    assert_eq!(empty, AuthError::InvalidServerUrl);
}

#[test]
fn ipv4_mapped_non_link_local_metadata_ip_is_blocked() {
    // The Alibaba endpoint is outside link-local ranges, so only the explicit
    // BLOCKED_METADATA_IPS entry can reject it. Its IPv4-mapped IPv6 spelling
    // must be unwrapped to IPv4 before that lookup: `is_link_local_ip` alone
    // does not cover a non-link-local address, and an `IpAddr::V6` never
    // compares equal to the IPv4 entry in the list.
    let mapped: IpAddr = "::ffff:100.100.100.200".parse().unwrap();
    assert!(!is_link_local_ip(mapped), "premise: not link-local");
    assert!(super::is_blocked_metadata_ip(mapped));

    for value in [
        "http://[::ffff:100.100.100.200]",
        "https://[::ffff:100.100.100.200]/latest/meta-data",
    ] {
        assert!(is_blocked_server_url_without_dns(value), "{value}");
        assert!(is_blocked_server_url(value), "{value}");
        let mut invalid = config();
        invalid.server_url = value.into();
        assert_eq!(
            validate_config(&invalid),
            Err(AuthError::BlockedServerUrl),
            "{value}"
        );
    }
    // A DNS answer in mapped form is rejected as a whole too.
    assert!(is_blocked_server_url_with(
        "https://vault.example.com",
        |_| vec![mapped]
    ));
    // A neighbouring mapped address is not metadata and stays allowed.
    let neighbour: IpAddr = "::ffff:100.100.100.201".parse().unwrap();
    assert!(!super::is_blocked_metadata_ip(neighbour));
    assert!(!is_blocked_server_url_without_dns(
        "http://[::ffff:100.100.100.201]"
    ));
}

#[test]
fn detail_variants_convert_forward_to_their_cause_app_error_arms() {
    use crate::error::{AppError, BoxedCause};

    // `From<AuthError> for AppError` (auth.rs:204-234) keeps the rendered
    // detail as the typed cause for the URL, client-setup and login families.
    // Equality alone cannot distinguish the arms because `AppError`'s
    // PartialEq compares rendered messages, so pin the exact discriminant and
    // the cause reachable through `Error::source()`.
    let cases: Vec<(&str, AuthError, AppError, &str, &str)> = vec![
        (
            "invalid_server_url",
            AuthError::InvalidServerUrlDetail("parser rejected the scheme".into()),
            AppError::InvalidServerUrlCause(BoxedCause::text("parser rejected the scheme")),
            "parser rejected the scheme",
            "サーバー URL が不正です（HTTPS または loopback の HTTP）",
        ),
        (
            "client_setup",
            AuthError::ClientSetupDetail("client id rejected".into()),
            AppError::ClientSetupCause(BoxedCause::text("client id rejected")),
            "client id rejected",
            "クライアントを初期化できませんでした",
        ),
        (
            "login",
            AuthError::LoginDetail("HTTP 400 invalid_client".into()),
            AppError::LoginCause(BoxedCause::text("HTTP 400 invalid_client")),
            "HTTP 400 invalid_client",
            "ログインに失敗しました",
        ),
    ];
    assert_eq!(cases.len(), 3);

    for (name, auth, expected, detail, family) in cases {
        let converted: AppError = auth.into();
        assert_eq!(
            std::mem::discriminant(&converted),
            std::mem::discriminant(&expected),
            "{name}: wrong AppError variant"
        );
        assert_eq!(converted, expected, "{name}");
        assert_eq!(converted.message(), family, "{name}");
        let source = std::error::Error::source(&converted).map(ToString::to_string);
        assert_eq!(source.as_deref(), Some(detail), "{name}");
    }
}

#[test]
fn auth_error_catch_all_flattens_unlock_settings_and_cache_families_to_other() {
    use crate::error::{AppError, BoxedCause};

    // `From<AppError> for AuthError` handles the auth families explicitly and
    // sends every other family through its catch-all arm (auth.rs:270-276).
    // A failure from unlock, settings or cache must therefore be reported as
    // the honest generic failure, never mislabelled as a known auth family.
    let cases: Vec<(&str, AppError)> = vec![
        ("unlock/missing key", AppError::MissingProtectedKey),
        ("unlock/failed", AppError::UnlockFailed("bad key".into())),
        ("unlock/structured", AppError::unlock_failed("bad key")),
        ("unlock/apply sync", AppError::apply_sync_failed("bad sync")),
        ("unlock/import", AppError::import_failed("bad import")),
        ("settings/too large", AppError::TooLarge),
        (
            "settings/save",
            AppError::SettingsSaveCause("save detail".into(), BoxedCause::text("io failure")),
        ),
        ("cache/invalid", AppError::InvalidCache),
        (
            "cache/parse",
            AppError::CacheParse(BoxedCause::text("bad json")),
        ),
        (
            "cache/redact",
            AppError::CacheRedact(BoxedCause::text("bad key")),
        ),
        (
            "cache/serialize",
            AppError::CacheSerialize(BoxedCause::text("serde failure")),
        ),
        ("cache/user mismatch", AppError::UserMismatch),
        ("cache/server mismatch", AppError::ServerMismatch),
        ("cache/version mismatch", AppError::VersionMismatch),
        ("cache/expired", AppError::CacheExpired),
        ("cache/too large", AppError::CacheTooLarge),
        ("cache/not found", AppError::NotFound),
    ];
    assert_eq!(cases.len(), 17, "every representative family is pinned");

    for (name, app) in cases {
        let small = AuthError::from(app);
        assert!(
            matches!(&small, AuthError::Other(text) if *text == OTHER_ERROR_MESSAGE),
            "{name}: wrong catch-all result: {small:?}"
        );
        assert_eq!(small.message(), OTHER_ERROR_MESSAGE, "{name}");
        assert_eq!(small.status_message(), OTHER_ERROR_MESSAGE, "{name}");
        assert_eq!(small, AuthError::Other(OTHER_ERROR_MESSAGE), "{name}");
        assert!(std::error::Error::source(&small).is_none(), "{name}");
        // The generic text must not be confused with a known auth family.
        assert_ne!(small, AuthError::Sync, "{name}");
        assert_ne!(small, AuthError::Login, "{name}");
        assert_ne!(small, AuthError::MissingField("email"), "{name}");
    }
}

#[test]
fn unlock_error_catch_all_keeps_the_original_status_text_in_other() {
    use crate::error::{AppError, BoxedCause};

    // `From<AppError> for UnlockError` maps the unlock families explicitly but
    // has no variants for settings/cache/TOTP/generator failures. Its
    // catch-all (auth.rs:347-350) keeps the original message instead of
    // replacing it with the generic text, because `UnlockError::Other` owns a
    // `String`. Pin both halves: a typed cause exists on the AppError and is
    // dropped at this boundary, while the rendered text survives.
    let cases: Vec<AppError> = vec![
        AppError::TooLarge,
        AppError::SettingsSaveCause("save detail".into(), BoxedCause::text("io failure")),
        AppError::InvalidCache,
        AppError::CacheParse(BoxedCause::text("bad json")),
        AppError::UserMismatch,
        AppError::CacheExpired,
        AppError::RandomUnavailable,
    ];
    for app in cases {
        let expected = app.message().to_string();
        let small = UnlockError::from(app);
        assert!(
            matches!(&small, UnlockError::Other(text) if *text == expected),
            "the catch-all must keep the original status text: {small:?}"
        );
        assert_eq!(small.message(), expected);
        assert_eq!(small.to_string(), expected);
        assert!(std::error::Error::source(&small).is_none(), "{small:?}");
    }

    // Premise: cause-carrying inputs really do have a source before the
    // conversion; the small `Other` variant deliberately does not.
    let caused = AppError::CacheParse(BoxedCause::text("bad json"));
    assert!(std::error::Error::source(&caused).is_some());
}

#[test]
fn unlock_error_forward_conversion_pins_the_four_discriminants() {
    use crate::error::{AppError, BoxedCause};

    // `From<UnlockError> for AppError` (auth.rs:293-312) must land each of the
    // four unlock families in its own `AppError` variant. `AppError`'s
    // PartialEq compares only rendered text/detail, so a wrong variant with an
    // equal message would pass `assert_eq!`; pin the exact discriminant.
    let families: Vec<(&str, UnlockError, AppError)> = vec![
        (
            "missing_protected_key",
            UnlockError::MissingProtectedKey,
            AppError::MissingProtectedKey,
        ),
        (
            "unlock_failed",
            UnlockError::UnlockFailed("detail".into()),
            AppError::unlock_failed("detail"),
        ),
        (
            "apply_sync_failed",
            UnlockError::ApplySyncFailed("detail".into()),
            AppError::apply_sync_failed("detail"),
        ),
        (
            "import_failed",
            UnlockError::ImportFailed("detail".into()),
            AppError::import_failed("detail"),
        ),
    ];
    assert_eq!(families.len(), 4);
    for (name, small, expected) in families {
        let converted = AppError::from(small);
        assert_eq!(
            std::mem::discriminant(&converted),
            std::mem::discriminant(&expected),
            "{name}: wrong forward AppError variant"
        );
        assert_eq!(converted, expected, "{name}");
    }

    // The cause-carrying spellings must keep their structured discriminants
    // too, not collapse to the plain family variant.
    let caused: Vec<(&str, UnlockError, AppError)> = vec![
        (
            "unlock_failed_cause",
            UnlockError::UnlockFailedCause("detail".into(), BoxedCause::text("io")),
            AppError::unlock_failed_cause("detail", BoxedCause::text("io")),
        ),
        (
            "apply_sync_failed_cause",
            UnlockError::ApplySyncFailedCause("detail".into(), BoxedCause::text("io")),
            AppError::apply_sync_failed_cause("detail", BoxedCause::text("io")),
        ),
        (
            "import_failed_cause",
            UnlockError::ImportFailedCause("detail".into(), BoxedCause::text("io")),
            AppError::import_failed_cause("detail", BoxedCause::text("io")),
        ),
        (
            "other",
            UnlockError::Other("raw".into()),
            AppError::Other("raw".into()),
        ),
    ];
    for (name, small, expected) in caused {
        let converted = AppError::from(small);
        assert_eq!(
            std::mem::discriminant(&converted),
            std::mem::discriminant(&expected),
            "{name}: wrong forward AppError variant"
        );
        assert_eq!(converted, expected, "{name}");
    }
}
