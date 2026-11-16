//! Pure time-based predicates used by the UI ticker.
//!
//! Keeping these free of GPUI types lets them be tested without a window.

use std::time::{Duration, Instant};

/// Whether an unlocked session has been idle long enough to auto-lock.
pub fn idle_lock_due(last_activity: Instant, now: Instant, timeout: Duration) -> bool {
    now.duration_since(last_activity) >= timeout
}

/// What the once-a-second UI tick should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickEffect {
    /// Restore the clipboard to its pre-copy contents.
    RestoreClipboard,
    /// Invalidate the cached TOTP code so the countdown advances.
    InvalidateTotp,
    /// Lock the vault after inactivity.
    AutoLock,
}

/// Decide the actions for a tick, keeping the timer loop free of business
/// rules. Auto-lock suppresses the other actions because the vault is no
/// longer usable; otherwise clipboard restoration and TOTP refresh can both
/// run in the same tick.
pub fn evaluate_tick(
    clipboard_due: bool,
    idle_due: bool,
    totp_refresh_due: bool,
) -> Vec<TickEffect> {
    if idle_due {
        return vec![TickEffect::AutoLock];
    }
    let mut effects = Vec::with_capacity(2);
    if clipboard_due {
        effects.push(TickEffect::RestoreClipboard);
    }
    if totp_refresh_due {
        effects.push(TickEffect::InvalidateTotp);
    }
    effects
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn tick_actions_are_independent_except_for_auto_lock() {
        assert!(evaluate_tick(false, false, false).is_empty());
        assert_eq!(
            evaluate_tick(true, false, false),
            vec![TickEffect::RestoreClipboard]
        );
        assert_eq!(
            evaluate_tick(false, false, true),
            vec![TickEffect::InvalidateTotp]
        );
        assert_eq!(
            evaluate_tick(true, false, true),
            vec![TickEffect::RestoreClipboard, TickEffect::InvalidateTotp]
        );
        assert_eq!(evaluate_tick(true, true, true), vec![TickEffect::AutoLock]);
    }

    #[test]
    fn idle_lock_uses_inclusive_threshold() {
        let start = Instant::now();
        let timeout = Duration::from_secs(300);
        assert!(!idle_lock_due(
            start,
            start + timeout - Duration::from_millis(1),
            timeout
        ));
        assert!(idle_lock_due(start, start + timeout, timeout));
        assert!(idle_lock_due(
            start,
            start + timeout + Duration::from_secs(1),
            timeout
        ));
    }

    #[test]
    fn idle_lock_never_triggers_before_the_timeout() {
        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        for seconds in 0..30 {
            assert!(!idle_lock_due(
                start,
                start + Duration::from_secs(seconds),
                timeout
            ));
        }
    }
}
