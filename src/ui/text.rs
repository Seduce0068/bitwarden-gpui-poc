//! GPUI-independent display-text helpers.
//!
//! These predicates and status composers only touch plain strings plus the
//! shared model/limits visibility rules, so they live in a leaf module.
//! `ui::logic` (pure predicates) and `ui::app` (GPUI wiring) both depend on
//! this module instead of on each other, which removes the former
//! `logic.rs <-> app.rs` cycle.

/// Whether `value` has no visible identifier: the strict placeholder rule.
///
/// Whitespace, Unicode `Cc` (control) and `Cf` (format) characters render
/// nothing, and a value made only of Unicode marks (`Mn`/`Mc`/`Me`) has no base
/// character to decorate. Delegates to [`crate::model::has_no_visible_identity`],
/// the rule search and duplicate detection share, so a mark-only item name /
/// username cannot leave a blank cell in the list. This is **not** the rule for
/// credentials: use [`credential_is_blank`] for password / TOTP presence, or a
/// mark-only secret accepted by `crate::auth::credential_is_blank` would be
/// shown as "なし" and refused on copy.
pub(super) fn is_visually_empty(value: &str) -> bool {
    crate::model::has_no_visible_identity(value)
}

/// Whether `value` is blank as a credential: the narrow rule.
///
/// Only whitespace, Unicode `Cc` and `Cf` characters count as blank, matching
/// [`crate::model::is_visually_empty`] and `crate::auth::credential_is_blank`.
/// A value made only of combining marks is a *present* credential here, even
/// though [`is_visually_empty`] (the identifier placeholder) treats it as an
/// absent identity. This is the predicate used by the password / TOTP detail
/// labels and by the copy gate.
pub(super) fn credential_is_blank(value: &str) -> bool {
    crate::model::is_visually_empty(value)
}

/// Count code points that contribute a visible glyph, derived from the same
/// per-character predicate as [`is_visually_empty`]:
/// [`crate::model::is_invisible_identity_char`] excludes whitespace, Unicode
/// `Cc`/`Cf` (zero-width spaces, bidi overrides, controls, ...) and bare
/// combining marks. Invisible characters around or between visible ones no
/// longer inflate a user-facing "n文字" label (`a\u{200b}b` reads "2文字"), and
/// a mark-only value reports zero, matching the placeholder rule. Note that
/// this is deliberately stricter than [`credential_is_blank`]: a mark-only
/// credential is present but has no glyph to count. Pure so the wording can be
/// pinned without a GPUI window.
pub(super) fn visible_char_count(value: &str) -> usize {
    value
        .chars()
        .filter(|ch| !crate::model::is_invisible_identity_char(*ch))
        .count()
}

/// Marker appended to transient statuses and to the list detail line.
///
/// Keeping it in one place makes the unsaved state visible outside the
/// settings panels without depending on GPUI's rendering internals.
pub(super) fn unsaved_status_suffix(dirty: bool) -> &'static str {
    if dirty {
        " | [未保存の設定変更があります]"
    } else {
        ""
    }
}

/// Compose a status message with the persistent unsaved marker.
pub(super) fn status_with_unsaved(base: &str, dirty: bool) -> String {
    format!("{base}{}", unsaved_status_suffix(dirty))
}

/// Idle-lock timeout in minutes, matching the settings panel's display.
///
/// The settings panel shows `idle_lock_seconds / 60` minutes while this status
/// used to show the raw seconds, so the same setting appeared as `5 分` and
/// `300秒` in two places. A plain integer division would fix that by silently
/// dropping the remainder (90 s -> "1 分"), which reports a shorter lock than
/// the one actually configured; the leftover seconds are therefore appended
/// whenever the value is not a whole minute. Kept pure so the wording can be
/// tested without a GPUI window.
pub(super) fn idle_lock_minutes_text(idle_lock_seconds: u64) -> String {
    let minutes = idle_lock_seconds / 60;
    let seconds = idle_lock_seconds % 60;
    if seconds == 0 {
        format!("{minutes}分")
    } else {
        format!("{minutes}分{seconds}秒")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn leaf_text_helpers_keep_the_shared_visibility_and_marker_rules() {
        // Whitespace and Unicode `Cf` characters have no visible identity.
        assert!(is_visually_empty(" \t\u{200b}\u{feff}\u{202e} "));
        assert!(!is_visually_empty(" alice "));
        // Invisible characters between visible ones do not inflate the count.
        assert_eq!(visible_char_count("a\u{200b}b"), 2);
        assert_eq!(visible_char_count("\u{200b}"), 0);
        // The two rules differ exactly on mark-only values: the identifier
        // placeholder and the character count exclude marks; the credential
        // blank rule (like `auth::credential_is_blank`) keeps them present.
        assert!(is_visually_empty("\u{0301}"));
        assert!(!credential_is_blank("\u{0301}"));
        assert_eq!(visible_char_count("\u{0301}"), 0);
        assert_eq!(visible_char_count("Caf\u{0301}"), 3);
        // Whitespace / Cc / Cf are blank under both rules.
        for blank in ["", " \t ", "\u{200b}", "\u{0}\u{202e}"] {
            assert!(is_visually_empty(blank), "{blank:?}");
            assert!(credential_is_blank(blank), "{blank:?}");
        }
        // The unsaved suffix and its composition keep the established wording.
        assert_eq!(unsaved_status_suffix(false), "");
        assert_eq!(
            unsaved_status_suffix(true),
            " | [未保存の設定変更があります]"
        );
        assert_eq!(
            status_with_unsaved("x", true),
            "x | [未保存の設定変更があります]"
        );
        assert_eq!(status_with_unsaved("x", false), "x");
        // Sub-minute remainders are reported, matching the settings panel.
        assert_eq!(idle_lock_minutes_text(300), "5分");
        assert_eq!(idle_lock_minutes_text(90), "1分30秒");
    }
}
