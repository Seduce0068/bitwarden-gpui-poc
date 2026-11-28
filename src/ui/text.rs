//! GPUI-independent display-text helpers.
//!
//! These predicates and status composers only touch plain strings plus the
//! shared model/limits visibility rules, so they live in a leaf module.
//! `ui::logic` (pure predicates) and `ui::app` (GPUI wiring) both depend on
//! this module instead of on each other, which removes the former
//! `logic.rs <-> app.rs` cycle.

/// Whether `value` carries no visible content or identity.
///
/// Whitespace, Unicode `Cc` (control) characters and Unicode `Cf` (format)
/// characters such as zero-width spaces or bidi overrides all render nothing,
/// whether at the edges or between visible letters. `Cc` is not whitespace
/// (`str::trim()` alone keeps NUL and C1 controls), so it is listed explicitly
/// to match `crate::auth::credential_is_blank`. Otherwise a value that looks
/// empty still passes a plain `trim().is_empty()` guard.
///
/// A value made only of Unicode marks (`Mn`/`Mc`/`Me`, optionally separated by
/// whitespace or `Cc`/`Cf` characters) has no visible identity either: bare
/// marks have no base character to decorate. The strict rule is delegated to
/// `crate::model::has_no_visible_identity`, the same one search and duplicate
/// detection use, so a mark-only item name / username cannot leave a blank
/// cell in the list while the rest of the app sees it as an identity. Shared
/// with the list row renderer so the two places agree on what "empty" means.
pub(super) fn is_visually_empty(value: &str) -> bool {
    crate::model::has_no_visible_identity(value)
}

/// Count only characters that actually render, using the same invisibility rule
/// as [`is_visually_empty`]. Whitespace and Unicode `Cc`/`Cf` characters (zero
/// width spaces, bidi overrides, controls, ...) draw nothing, so including them
/// in a user-facing "n文字" length made a value such as `a\u{200b}b` read as
/// "3文字". Combining marks draw only together with a base character, so they
/// are not counted either; a mark-only value then reports zero just like
/// [`is_visually_empty`]. Pure so the wording can be pinned without a GPUI
/// window.
pub(super) fn visible_char_count(value: &str) -> usize {
    value
        .chars()
        .filter(|ch| {
            !ch.is_whitespace()
                && !ch.is_control()
                && !crate::limits::is_format_character(*ch)
                && !unicode_normalization::char::is_combining_mark(*ch)
        })
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
