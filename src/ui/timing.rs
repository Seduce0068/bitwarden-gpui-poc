//! Pure time-based predicates used by the UI ticker.
//!
//! Keeping these free of GPUI types lets them be tested without a window.

use std::time::{Duration, Instant};

/// Whether an unlocked session has been idle long enough to auto-lock.
///
/// `checked_duration_since` avoids a panic if the clock appears to move
/// backwards (for example across a suspended session).
pub(super) fn idle_lock_due(last_activity: Instant, now: Instant, timeout: Duration) -> bool {
    now.checked_duration_since(last_activity)
        .is_some_and(|elapsed| elapsed >= timeout)
}

/// The next wake-up instant for a fixed-rate ticker.
///
/// `deadline` is the instant the tick that just ran was scheduled for, `now`
/// is the time after its work finished, and `interval` is the tick period.
///
/// When the work fits inside one period the schedule is left untouched
/// (`deadline + interval`), so punctual ticks never accumulate drift. When the
/// work overruns the following slot, the next deadline is recomputed from
/// `now` instead of replaying the missed ticks — this is the catch-up limit
/// that keeps a slow tick from turning into a burst of back-to-back ticks.
pub(super) fn next_tick_deadline(deadline: Instant, now: Instant, interval: Duration) -> Instant {
    match deadline.checked_add(interval) {
        Some(scheduled) if now <= scheduled => scheduled,
        // Overrun (or an unrepresentable instant): resync from now, no catch-up.
        _ => now.checked_add(interval).unwrap_or(now),
    }
}

/// What the once-a-second UI tick should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TickEffect {
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
pub(super) fn evaluate_tick(
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

    #[test]
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
    fn idle_lock_does_not_panic_when_the_clock_moves_backwards() {
        let now = Instant::now();
        let timeout = Duration::from_secs(300);
        assert!(!idle_lock_due(now + Duration::from_secs(1), now, timeout));
        assert!(!idle_lock_due(now, now, timeout));
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

    #[test]
    fn next_deadline_keeps_the_fixed_schedule_when_work_fits() {
        let interval = Duration::from_secs(1);
        let deadline = Instant::now() + interval;
        // Finishing early or just before the next boundary keeps the original
        // grid, so a fast tick never pushes the following tick later.
        assert_eq!(
            next_tick_deadline(deadline, deadline + Duration::from_millis(20), interval),
            deadline + interval
        );
        assert_eq!(
            next_tick_deadline(
                deadline,
                deadline + interval - Duration::from_nanos(1),
                interval
            ),
            deadline + interval
        );
        // Landing exactly on the boundary is still on time.
        assert_eq!(
            next_tick_deadline(deadline, deadline + interval, interval),
            deadline + interval
        );
    }

    #[test]
    fn next_deadline_resyncs_from_now_after_an_overrun() {
        let interval = Duration::from_secs(1);
        let deadline = Instant::now() + interval;
        let late_now = deadline + Duration::from_millis(1_500);
        let next = next_tick_deadline(deadline, late_now, interval);
        // The missed boundary is not replayed: the next wake-up is a full
        // interval after the work actually finished, and never in the past.
        assert_eq!(next, late_now + interval);
        assert!(next > deadline + interval);
        assert!(next > late_now);
    }

    #[test]
    fn repeated_overruns_do_not_produce_a_catch_up_burst() {
        let interval = Duration::from_secs(1);
        let mut deadline = Instant::now() + interval;
        // Simulate five consecutive ticks whose work takes longer than the
        // period; every next deadline must stay one full interval in the
        // future, so the timer can never fire back-to-back.
        for overrun_ms in [1_100, 2_500, 1_050, 3_000, 1_200] {
            let finished = deadline + Duration::from_millis(overrun_ms);
            let next = next_tick_deadline(deadline, finished, interval);
            assert_eq!(next - finished, interval);
            deadline = next;
        }
    }
}
