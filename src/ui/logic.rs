//! Pure UI predicates that can be tested without a GPUI window.

use crate::health::{audit, Report, Thresholds};
use crate::model::Vault;
use crate::ui::state::Panel;

/// Whether the lock screen has enough credential input to attempt a login.
///
/// The server URL and email may be pre-filled from settings, so they are not
/// considered here. An empty client id, secret or master password means the
/// demo vault is opened instead.
pub fn has_credentials(client_id: &str, client_secret: &str, master_password: &str) -> bool {
    !client_id.is_empty() || !client_secret.is_empty() || !master_password.is_empty()
}

/// Whether `selected_id` still names an item in the current view.
///
/// `None` is valid: the UI falls back to showing the first item.
pub fn selection_in_view<'a>(
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
pub fn compute_audit(vault: &Vault, thresholds: Thresholds, now: i64) -> Report {
    audit(vault, thresholds, now)
}

/// Resolve a requested panel to one that can actually be rendered.
///
/// The audit panel needs a generated report; falling back to the vault list
/// here keeps `KeyContext.panel` in sync with what is drawn.
pub fn effective_panel(requested: Panel, has_audit_report: bool) -> Panel {
    if requested == Panel::Audit && !has_audit_report {
        Panel::Vault
    } else {
        requested
    }
}

/// Adjust the idle auto-lock timeout in one-minute steps, clamped to 1..=60
/// minutes.
pub fn adjust_idle_lock(current_seconds: u64, delta_minutes: i32) -> u64 {
    let current_minutes = (current_seconds / 60).clamp(1, 60) as i64;
    let next = (current_minutes + i64::from(delta_minutes)).clamp(1, 60);
    (next * 60) as u64
}

/// Adjust audit thresholds by one UI step, clamping to safe bounds:
/// 1..=200 bits and 1..=3650 days.
///
/// `delta` is +1 for `+`/`=` and -1 for `-`/`_`.
pub fn adjust_thresholds(current: Thresholds, delta: i32) -> Thresholds {
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

    #[::core::prelude::v1::test]
    fn audit_is_deterministic_for_a_given_clock() {
        let vault = Vault::new();
        let thresholds = Thresholds::default();
        let first = compute_audit(&vault, thresholds, 1_700_000_000);
        let second = compute_audit(&vault, thresholds, 1_700_000_000);
        assert_eq!(first, second);
        assert_eq!(first.examined, 0);
        assert!(first.items.is_empty());
    }

    #[::core::prelude::v1::test]
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

    #[::core::prelude::v1::test]
    fn idle_lock_adjustment_clamps_to_one_and_sixty_minutes() {
        assert_eq!(adjust_idle_lock(300, 1), 360);
        assert_eq!(adjust_idle_lock(300, -1), 240);
        assert_eq!(adjust_idle_lock(60, -1), 60);
        assert_eq!(adjust_idle_lock(3600, 1), 3600);
        // Hand-edited / stale values are clamped back into the valid range.
        assert_eq!(adjust_idle_lock(0, 0), 60);
        assert_eq!(adjust_idle_lock(10_000, 0), 3600);
    }

    #[::core::prelude::v1::test]
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
