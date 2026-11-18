//! Pure UI predicates that can be tested without a GPUI window.

use crate::health::{audit, Report, Thresholds};
use crate::model::Vault;
use crate::ui::state::Panel;

/// Whether the lock screen has enough credential input to attempt a login.
///
/// The server URL and email may be pre-filled from settings, so they are not
/// considered here. An empty client id, secret or master password means the
/// demo vault is opened instead.
#[cfg(test)]
pub(super) fn has_credentials(client_id: &str, client_secret: &str, master_password: &str) -> bool {
    !client_id.is_empty() || !client_secret.is_empty() || !master_password.is_empty()
}

/// Whether `selected_id` still names an item in the current view.
///
/// `None` is valid: the UI falls back to showing the first item.
pub(super) fn selection_in_view<'a>(
    selected_id: Option<&str>,
    ids: impl IntoIterator<Item = &'a str>,
) -> bool {
    match selected_id {
        None => true,
        Some(id) => ids.into_iter().any(|candidate| candidate == id),
    }
}

/// Run the vault health audit with an explicit clock value.
///
/// Keeping the clock as a parameter makes the audit reproducible in tests.
pub(super) fn compute_audit(vault: &Vault, thresholds: Thresholds, now: i64) -> Report {
    audit(vault, thresholds, now)
}

/// Resolve a requested panel to one that can actually be rendered.
///
/// The audit panel needs a generated report; falling back to the vault list
/// here keeps `KeyContext.panel` in sync with what is drawn.
pub(super) fn effective_panel(requested: Panel, has_audit_report: bool) -> Panel {
    if requested == Panel::Audit && !has_audit_report {
        Panel::Vault
    } else {
        requested
    }
}

/// Reduce a card number to its last four ASCII digits for display.
///
/// As in the search haystack of [`crate::model::Vault::view`], every non-digit
/// grouping character is ignored, so a number without spaces is masked just as
/// strictly as one that uses them. At most the last four digits are shown;
/// shorter numbers are shown as-is and a number with no digits at all is
/// reported explicitly instead of rendering an empty "末尾:" label.
pub(super) fn card_last_four(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return "なし".to_string();
    }
    let start = digits.len().saturating_sub(4);
    digits[start..].iter().copied().collect()
}

/// Status text for a clipboard copy.
///
/// Restoration is only promised when the pre-copy contents were readable:
/// `ClipboardState` skips creating a pending restore for `None`, so announcing
/// one would mislead the user about what will happen.
pub(super) fn clipboard_copy_status(seconds: u64, has_original: bool) -> String {
    if has_original {
        format!("クリップボードにコピーしました（{seconds}秒後に復元）")
    } else {
        "クリップボードにコピーしました（元の内容を読めないため復元しません。コピーした内容はそのまま残ります）".to_string()
    }
}

/// Adjust the idle auto-lock timeout in one-minute steps, clamped to 1..=60
/// minutes.
pub(super) fn adjust_idle_lock(current_seconds: u64, delta_minutes: i32) -> u64 {
    let current_minutes = (current_seconds / 60).clamp(1, 60) as i64;
    let next = (current_minutes + i64::from(delta_minutes)).clamp(1, 60);
    (next * 60) as u64
}

/// Adjust audit thresholds by one UI step, clamping to safe bounds:
/// 1..=200 bits and 1..=3650 days.
///
/// `delta` is +1 for `+`/`=` and -1 for `-`/`_`.
pub(super) fn adjust_thresholds(current: Thresholds, delta: i32) -> Thresholds {
    let weak_step = delta.saturating_mul(5);
    let day_step = delta.saturating_mul(30);
    Thresholds {
        weak_bits: if weak_step > 0 {
            current.weak_bits.saturating_add(weak_step as u32).min(200)
        } else {
            current
                .weak_bits
                .saturating_sub(weak_step.unsigned_abs())
                .max(1)
        },
        stale_days: if day_step > 0 {
            current.stale_days.saturating_add(day_step as i64).min(3650)
        } else {
            current
                .stale_days
                .saturating_sub(day_step.unsigned_abs() as i64)
                .max(1)
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn credentials_need_at_least_one_field() {
        assert!(!has_credentials("", "", ""));
        assert!(has_credentials("user.1234", "", ""));
        assert!(has_credentials("", "secret", ""));
        assert!(has_credentials("", "", "master"));
    }

    #[test]
    fn selection_in_view_checks_ids() {
        let ids = ["1", "2", "3"];
        assert!(selection_in_view(None, ids));
        assert!(selection_in_view(Some("2"), ids));
        assert!(!selection_in_view(Some("4"), ids));
        assert!(!selection_in_view(Some("1"), []));
    }

    #[test]
    fn audit_is_deterministic_for_a_given_clock() {
        let vault = Vault::new();
        let thresholds = Thresholds::default();
        let first = compute_audit(&vault, thresholds, 1_700_000_000);
        let second = compute_audit(&vault, thresholds, 1_700_000_000);
        assert_eq!(first, second);
        assert_eq!(first.examined, 0);
        assert!(first.items.is_empty());
    }

    #[test]
    fn audit_panel_falls_back_without_a_report() {
        assert_eq!(
            effective_panel(Panel::Audit, false),
            Panel::Vault,
            "the key context must match the rendered panel"
        );
        assert_eq!(effective_panel(Panel::Audit, true), Panel::Audit);
        assert_eq!(effective_panel(Panel::Settings, false), Panel::Settings);
        assert_eq!(effective_panel(Panel::Generator, false), Panel::Generator);
    }

    #[test]
    fn card_last_four_ignores_group_separators_and_never_leaks_the_prefix() {
        assert_eq!(card_last_four("4111 1111 1111 1234"), "1234");
        assert_eq!(card_last_four("4111111111111234"), "1234");
        assert_eq!(card_last_four("4111-1111-1111-1234"), "1234");
        assert_eq!(card_last_four("１２３４ 4111 1111 1111 1234"), "1234");
        assert_eq!(card_last_four("1234"), "1234");
        assert_eq!(card_last_four("12 34"), "1234");
        assert_eq!(card_last_four("123"), "123");
        assert_eq!(card_last_four(""), "なし");
        assert_eq!(card_last_four("   "), "なし");
        assert_eq!(card_last_four("abcd"), "なし");
    }

    #[test]
    fn clipboard_status_promises_restore_only_when_it_can_happen() {
        assert_eq!(
            clipboard_copy_status(30, true),
            "クリップボードにコピーしました（30秒後に復元）"
        );
        assert_eq!(
            clipboard_copy_status(30, false),
            "クリップボードにコピーしました（元の内容を読めないため復元しません。コピーした内容はそのまま残ります）"
        );
    }

    #[test]
    fn idle_lock_adjustment_clamps_to_one_and_sixty_minutes() {
        assert_eq!(adjust_idle_lock(300, 1), 360);
        assert_eq!(adjust_idle_lock(300, -1), 240);
        assert_eq!(adjust_idle_lock(60, -1), 60);
        assert_eq!(adjust_idle_lock(3600, 1), 3600);
        // Hand-edited / stale values are clamped back into the valid range.
        assert_eq!(adjust_idle_lock(0, 0), 60);
        assert_eq!(adjust_idle_lock(10_000, 0), 3600);
    }

    #[test]
    fn threshold_adjustment_steps_and_clamps() {
        let base = Thresholds::default();
        let up = adjust_thresholds(base, 1);
        assert_eq!(up.weak_bits, base.weak_bits + 5);
        assert_eq!(up.stale_days, base.stale_days + 30);

        let down = adjust_thresholds(base, -1);
        assert_eq!(down.weak_bits, base.weak_bits - 5);
        assert_eq!(down.stale_days, base.stale_days - 30);

        let at_max = Thresholds {
            weak_bits: 199,
            stale_days: 3640,
        };
        let clamped = adjust_thresholds(at_max, 1);
        assert_eq!(clamped.weak_bits, 200);
        assert_eq!(clamped.stale_days, 3650);

        let at_min = Thresholds {
            weak_bits: 2,
            stale_days: 10,
        };
        let clamped = adjust_thresholds(at_min, -1);
        assert_eq!(clamped.weak_bits, 1);
        assert_eq!(clamped.stale_days, 1);
    }
}
