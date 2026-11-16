//! Pure time-based predicates used by the UI ticker.
//!
//! Keeping these free of GPUI types lets them be tested without a window.

use std::time::{Duration, Instant};

/// Whether a copied secret's clipboard deadline has passed.
pub fn clipboard_expired(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_some_and(|deadline| now >= deadline)
}

/// Whether an unlocked session has been idle long enough to auto-lock.
pub fn idle_lock_due(last_activity: Instant, now: Instant, timeout: Duration) -> bool {
    now.duration_since(last_activity) >= timeout
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_expiry_handles_all_deadline_states() {
        let now = Instant::now();
        assert!(!clipboard_expired(None, now));
        assert!(!clipboard_expired(Some(now + Duration::from_secs(1)), now));
        assert!(clipboard_expired(Some(now), now));
        assert!(clipboard_expired(Some(now - Duration::from_secs(1)), now));
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
