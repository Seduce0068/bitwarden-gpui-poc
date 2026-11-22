#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::totp::*;

/// RFC 6238 Appendix B test vector: the ASCII secret "12345678901234567890"
/// base32-encoded, at T = 59s (SHA-1, 8 digits).
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn rfc6238_vector_matches_for_eight_digits() {
    // The default is 6 digits, so the 8-digit vector is checked through
    // the otpauth URI form, which carries `digits`.
    let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&digits=8&period=30&algorithm=SHA1");
    let code = code_at(&uri, 59).unwrap();
    assert_eq!(code.code(), "94287082");
    assert_eq!(code.period(), 30);
    assert_eq!(code.remaining(), 1);
}

#[test]
fn rfc6238_vectors_across_the_time_range() {
    let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&digits=8&period=30&algorithm=SHA1");
    for (time, expected) in [
        (59u64, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ] {
        assert_eq!(code_at(&uri, time).unwrap().code(), expected, "t={time}");
    }
}

#[test]
fn bare_base32_secret_defaults_to_six_digits_sha1() {
    let code = code_at(RFC_SECRET, 59).unwrap();
    assert_eq!(code.code(), "287082");
    assert_eq!(code.period(), 30);
}

#[test]
fn bare_secret_ignores_spaces_and_padding() {
    let spaced = "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ";
    let padded = format!("{RFC_SECRET}====");
    assert_eq!(code_at(spaced, 59).unwrap().code(), "287082");
    assert_eq!(code_at(&padded, 59).unwrap().code(), "287082");
    assert_eq!(
        code_at(&RFC_SECRET.to_lowercase(), 59).unwrap().code(),
        "287082"
    );
}

#[test]
fn steam_secrets_produce_five_letter_codes() {
    let code = code_at("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
    assert_eq!(code.code(), "PV9M4");
    assert_eq!(code.code().len(), 5);
    assert!(code
        .code()
        .chars()
        .all(|c| "23456789BCDFGHJKMNPQRTVWXY".contains(c)));
}

#[test]
fn sha256_and_sha512_are_honoured() {
    let sha256 = format!("otpauth://totp/RFC?secret={RFC_SECRET}&algorithm=SHA256&digits=8");
    let sha512 = format!("otpauth://totp/RFC?secret={RFC_SECRET}&algorithm=SHA512&digits=8");
    let a = code_at(&sha256, 59).unwrap();
    let b = code_at(&sha512, 59).unwrap();
    assert_eq!(a.code(), "32247374");
    assert_eq!(b.code(), "69342147");
    assert_ne!(a.code(), b.code());
    assert_eq!(a.code().len(), 8);
}

#[test]
fn a_custom_period_changes_the_window() {
    let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&period=60");
    let code = code_at(&uri, 59).unwrap();
    assert_eq!(code.period(), 60);
    assert_eq!(code.remaining(), 1);
    let code = code_at(&uri, 60).unwrap();
    assert_eq!(code.remaining(), 60);
}

#[test]
fn missing_and_invalid_secrets_are_distinguished() {
    assert_eq!(code_at("", 0), Err(TotpError::Missing));
    assert_eq!(code_at("   ", 0), Err(TotpError::Missing));
    assert_eq!(code_at("not base32!", 0), Err(TotpError::Invalid));
    assert_eq!(code_at("otpauth://totp/x", 0), Err(TotpError::Invalid));
    assert!(!is_valid_secret("not base32!"));
    assert!(is_valid_secret(RFC_SECRET));
}

#[test]
fn countdown_and_progress_track_the_period() {
    let code = code_at(RFC_SECRET, 0).unwrap();
    assert_eq!(code.remaining(), 30);
    assert_eq!(code.progress(), 0.0);
    let code = code_at(RFC_SECRET, 15).unwrap();
    assert_eq!(code.remaining(), 15);
    assert!((code.progress() - 0.5).abs() < 1e-6);
    let code = code_at(RFC_SECRET, 29).unwrap();
    assert!(code.expires_within(5));
    assert!(!code_at(RFC_SECRET, 0).unwrap().expires_within(5));
}

#[test]
fn progress_uses_the_codes_own_custom_period() {
    // `Code::progress()` divides by the code's period, not the usual 30s:
    // with a 60-second window the same remaining time maps to half the bar.
    let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&period=60");
    for (time, expected) in [(0u64, 0.0f32), (30, 0.5), (59, 59.0 / 60.0)] {
        let code = code_at(&uri, time).unwrap();
        assert_eq!(code.period(), 60, "t={time}");
        assert!(
            (code.progress() - expected).abs() < 1e-6,
            "t={time}: {} vs {expected}",
            code.progress()
        );
    }
    // A 30-second code at the same wall-clock instant is further along.
    let standard = code_at(RFC_SECRET, 30).unwrap();
    assert_eq!(standard.progress(), 0.0, "a new 30s window just started");
}

#[test]
fn codes_change_at_the_period_boundary() {
    let before = code_at(RFC_SECRET, 29).unwrap().code().to_string();
    let after = code_at(RFC_SECRET, 30).unwrap().code().to_string();
    assert_ne!(before, after);
    let same = code_at(RFC_SECRET, 31).unwrap().code().to_string();
    assert_eq!(after, same);
    assert_eq!(code_at(RFC_SECRET, 30).unwrap().remaining(), 30);
}

#[test]
fn grouping_splits_digits_and_leaves_steam_alone() {
    assert_eq!(code_at(RFC_SECRET, 59).unwrap().grouped(), "287 082");
    let steam = code_at("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
    assert_eq!(steam.grouped(), steam.code());

    // Eight digits split 4+4 (totp.rs:72-82); the split is by character count,
    // not by a fixed 3+3 shape.
    let eight = code_at(
        "otpauth://totp/RFC?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30",
        59,
    )
    .unwrap();
    assert_eq!(eight.code(), "94287082");
    assert_eq!(eight.grouped(), "9428 7082");
}

#[test]
fn grouping_handles_three_four_seven_and_nine_digit_codes() {
    // `Code::grouped` (totp.rs:71-82) leaves <= 3 digits untouched and splits
    // longer codes in half by character count, not by a fixed 3+3 shape.
    for digits in [3u8, 4, 7, 9] {
        let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&digits={digits}&period=30");
        let code = code_at(&uri, 59).unwrap();
        let raw = code.code();
        assert_eq!(raw.len(), digits as usize, "digits={digits}");
        assert!(raw.chars().all(|ch| ch.is_ascii_digit()), "{raw}");

        let expected = if raw.len() <= 3 {
            raw.to_string()
        } else {
            let mid = raw.len() / 2;
            format!("{} {}", &raw[..mid], &raw[mid..])
        };
        assert_eq!(code.grouped(), expected, "digits={digits}: {raw}");
        if digits > 3 {
            assert_eq!(code.grouped().matches(' ').count(), 1, "{raw}");
        } else {
            assert!(!code.grouped().contains(' '), "{raw}");
        }
    }
}

#[test]
fn debug_never_reveals_the_code() {
    let code = code_at(RFC_SECRET, 59).unwrap();
    let rendered = format!("{code:?}");
    assert!(!rendered.contains("287082"), "{rendered}");
    assert!(rendered.contains("redacted"));
}

#[test]
fn code_equality_uses_only_the_validity_window() {
    let a = code_at(RFC_SECRET, 40).unwrap();
    let b = code_at(RFC_SECRET, 40).unwrap();
    let c = code_at(RFC_SECRET, 50).unwrap();
    // Equality uses only period + remaining, never the code value. Two
    // samples at the same instant are equal without exposing the code.
    assert_eq!(a, b);
    // A different remaining time is not equal.
    assert_ne!(a, c);

    // A different secret at the same instant yields a different code value
    // but the same validity window. This is the case that proves the code
    // value is not part of PartialEq; comparing one secret against itself
    // cannot detect a regression to value-based equality.
    const OTHER_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJR";
    let other = code_at(OTHER_SECRET, 40).unwrap();
    assert_ne!(
        a.code(),
        other.code(),
        "different secrets must not share a code"
    );
    assert_eq!(a.period(), other.period());
    assert_eq!(a.remaining(), other.remaining());
    assert_eq!(
        a, other,
        "Eq compares only period + remaining, not the code"
    );
    assert_eq!(other, a);

    // Equality never exposes the code value.
    let debug = format!("{a:?}");
    assert!(debug.contains("redacted"), "{debug}");
    assert!(!debug.contains(a.code()), "{debug}");
}

#[test]
fn tick_caches_within_a_period_and_refreshes_across_it() {
    let tick = Tick::sample(RFC_SECRET, 100);
    assert!(tick.code.is_some());
    assert!(tick.error.is_none());
    assert_eq!(tick.remaining(), Some(20));
    assert!(tick.is_fresh(105));
    assert!(tick.is_fresh(100));
    // 100 / 30 == 3, 119 / 30 == 3 (same period), 120 / 30 == 4.
    assert!(tick.is_fresh(119));
    assert!(!tick.is_fresh(120));
    assert!(!tick.is_fresh(99), "a backwards clock is never fresh");

    let failed = Tick::sample("not base32!", 100);
    assert!(failed.code.is_none());
    assert_eq!(failed.error, Some(TotpError::Invalid));
    assert_eq!(failed.remaining(), None);
    assert!(failed.is_fresh(100_000));
}

#[test]
fn tick_is_fresh_uses_the_codes_own_period() {
    // A non-default period must drive the freshness window, not the usual
    // 30-second TOTP period.
    let uri = format!("otpauth://totp/RFC?secret={RFC_SECRET}&period=60");
    let tick = Tick::sample(&uri, 59);
    assert_eq!(tick.code.as_ref().map(Code::period), Some(60));
    assert_eq!(tick.remaining(), Some(1));
    // The first 60-second window is 0..=59, so 59 is the last fresh instant.
    assert!(tick.is_fresh(59));
    assert!(!tick.is_fresh(60));
    assert!(!tick.is_fresh(58), "a backwards clock is never fresh");
    let next = Tick::sample(&uri, 119);
    assert!(next.is_fresh(119));
    assert!(!next.is_fresh(120));
}

#[test]
fn now_unix_is_plausible() {
    let now = now_unix();
    // 2020-01-01 .. 2100-01-01
    assert!(now > 1_577_836_800, "{now}");
    assert!(now < 4_102_444_800, "{now}");
}

#[test]
fn error_messages_are_present() {
    assert!(!TotpError::Missing.message().is_empty());
    assert!(!TotpError::Invalid.message().is_empty());
}

#[test]
fn surrounding_whitespace_is_trimmed_before_parsing() {
    // Copy/paste commonly adds a trailing newline or leading spaces; the
    // presentation layer strips them before handing the value to openwarden.
    let padded = format!("  \t{RFC_SECRET}\n ");
    assert_eq!(
        code_at(&padded, 59).unwrap().code(),
        code_at(RFC_SECRET, 59).unwrap().code()
    );
    assert!(is_valid_secret(&padded));

    let padded_uri = format!("\n otpauth://totp/RFC?secret={RFC_SECRET}&digits=8 \t");
    assert_eq!(code_at(&padded_uri, 59).unwrap().code(), "94287082");
    assert!(is_valid_secret(&padded_uri));

    // A whitespace-only field is missing, not invalid, even with mixed
    // whitespace characters.
    assert_eq!(code_at(" \t\n\u{3000}", 0), Err(TotpError::Missing));
}

#[test]
fn non_ascii_secrets_are_rejected_without_panicking() {
    // openwarden 0.1.1 checks `secret[..10]` for the `otpauth://` prefix. Four
    // three-byte characters put byte 10 in the middle of a code point, which
    // panics in the old code path (totp.rs:97-104). These are exactly the
    // values an audit of untrusted vault fields could encounter.
    let panicking_prefix = "あいうえおotpauth://totp/x?secret=GEZDGNBVGY3TQOJQ";
    assert!(
        std::str::from_utf8(&panicking_prefix.as_bytes()[..10]).is_err(),
        "byte 10 must fall inside a code point for this to be the panic case"
    );
    for secret in [
        panicking_prefix,
        "あ",
        "éGEZDGNBVGY3TQOJQ",
        "GEZDGNBVGY3TQOJQあ",
        "あotpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
    ] {
        // The call must return an ordinary error, not unwind.
        assert_eq!(code_at(secret, 59), Err(TotpError::Invalid), "{secret:?}");
        assert!(!is_valid_secret(secret), "{secret:?}");
        let tick = Tick::sample(secret, 59);
        assert!(tick.code.is_none(), "{secret:?}");
        assert_eq!(tick.error, Some(TotpError::Invalid), "{secret:?}");
        assert!(tick.is_fresh(59), "a rejected field stays rejected");
    }
    // ASCII fields keep working after the guard: the guard is about byte
    // boundaries, not about rejecting legitimate base32/URI/steam forms.
    assert_eq!(code_at(RFC_SECRET, 59).unwrap().code(), "287082");
    assert!(is_valid_secret(&format!(
        "otpauth://totp/x?secret={RFC_SECRET}"
    )));
}
