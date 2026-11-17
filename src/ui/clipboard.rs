//! Clipboard state with automatic restoration of the previous contents.
//!
//! State transitions are pure; the GPUI clipboard I/O lives in the callers so
//! they can be tested independently.

use std::time::{Duration, Instant};

/// Tracks the clipboard contents from before the most recent secret copy.
///
/// The contents are restored after the delay configured in `Settings`
/// (default 30 seconds) or on lock.
#[derive(Default)]
pub struct ClipboardState {
    restore: Option<String>,
    clear_at: Option<Instant>,
}

/// Compute the restore snapshot and deadline for a new secret copy.
///
/// This is a pure transition: it performs no clipboard or GPUI I/O. `current`
/// is the text read from the clipboard *immediately before* the new secret is
/// written. It is used on **every** copy, even when another copy is already
/// pending: keeping an older snapshot would restore a previously copied secret
/// after consecutive copies. `None` means the clipboard text could not be read,
/// so restoration is skipped instead of writing an empty string.
pub fn next_restore_state(
    current: Option<String>,
    now: Instant,
    restore_seconds: u64,
) -> (Option<String>, Instant) {
    (current, now + Duration::from_secs(restore_seconds))
}

impl ClipboardState {
    /// Create an empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the previous contents should be restored at `now`.
    pub fn due(&self, now: Instant) -> bool {
        self.clear_at.is_some_and(|deadline| now >= deadline)
    }

    /// Whether a secret is currently pending restoration.
    pub fn is_pending(&self) -> bool {
        self.clear_at.is_some()
    }

    /// Record a copy made at `now`, capturing the clipboard text it replaced.
    ///
    /// Each copy starts a fresh restoration window. When the clipboard could
    /// not be read, `restore` stays empty and restoration is a no-op rather
    /// than overwriting the clipboard with an empty string.
    pub fn begin_copy(&mut self, current: Option<String>, now: Instant, restore_seconds: u64) {
        let (snapshot, deadline) = next_restore_state(current, now, restore_seconds);
        self.restore = snapshot;
        self.clear_at = Some(deadline);
    }

    /// Take the text to restore, consuming the pending state.
    ///
    /// Returns `None` when no copy is pending or the original text was
    /// unavailable; callers must not write to the clipboard in that case.
    pub fn take_restore(&mut self) -> Option<String> {
        self.clear_at.take()?;
        self.restore.take()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn due_requires_a_pending_copy_and_elapsed_deadline() {
        let state = ClipboardState::new();
        assert!(!state.due(Instant::now()));
        assert!(!state.is_pending());

        let mut state = ClipboardState::new();
        let now = Instant::now();
        state.begin_copy(Some("original".into()), now, 1);
        assert!(state.is_pending());
        assert!(!state.due(now));
        assert!(state.due(now + Duration::from_secs(2)));
    }

    #[::core::prelude::v1::test]
    fn zero_delay_is_due_immediately() {
        let mut state = ClipboardState::new();
        let now = Instant::now();
        state.begin_copy(Some("original".into()), now, 0);
        assert!(state.due(now));
    }

    #[::core::prelude::v1::test]
    fn consecutive_copies_restore_the_text_they_replaced() {
        let mut state = ClipboardState::new();
        let now = Instant::now();
        state.begin_copy(Some("original".into()), now, 30);
        state.begin_copy(Some("first secret".into()), now, 30);
        assert_eq!(state.take_restore(), Some("first secret".into()));
        assert!(!state.is_pending());
    }

    #[::core::prelude::v1::test]
    fn unreadable_original_does_not_erase_the_clipboard() {
        let mut state = ClipboardState::new();
        state.begin_copy(None, Instant::now(), 30);
        assert_eq!(state.take_restore(), None);
        assert!(!state.is_pending());
    }

    #[::core::prelude::v1::test]
    fn restore_without_a_pending_copy_is_a_no_op() {
        let mut state = ClipboardState::new();
        assert_eq!(state.take_restore(), None);
    }

    #[::core::prelude::v1::test]
    fn next_restore_state_uses_the_pre_copy_read_and_refreshes_the_deadline() {
        let now = Instant::now();

        let (snapshot, deadline) = next_restore_state(Some("user text".into()), now, 30);
        assert_eq!(snapshot.as_deref(), Some("user text"));
        assert_eq!(deadline, now + Duration::from_secs(30));

        // An unreadable clipboard yields no snapshot, so restore writes nothing.
        let (snapshot, deadline) = next_restore_state(None, now, 30);
        assert_eq!(snapshot, None);
        assert_eq!(deadline, now + Duration::from_secs(30));
    }

    #[::core::prelude::v1::test]
    fn pending_copy_does_not_suppress_recapture_or_deadline_refresh() {
        let mut state = ClipboardState::new();
        let now = Instant::now();

        state.begin_copy(Some("original".into()), now, 30);
        state.begin_copy(Some("secret A".into()), now + Duration::from_secs(20), 30);

        // The first deadline has passed, but the second copy opened a new
        // window and replaced the snapshot with its own pre-copy read.
        assert!(!state.due(now + Duration::from_secs(30)));
        assert!(state.due(now + Duration::from_secs(50)));
        assert_eq!(state.take_restore(), Some("secret A".into()));
        assert!(!state.is_pending());
    }

    #[::core::prelude::v1::test]
    fn unreadable_second_copy_skips_restoration_without_an_empty_write() {
        let mut state = ClipboardState::new();
        let now = Instant::now();
        state.begin_copy(Some("original".into()), now, 30);
        state.begin_copy(None, now, 30);

        assert!(state.is_pending());
        assert_eq!(state.take_restore(), None);
        assert!(!state.is_pending());
    }
}
