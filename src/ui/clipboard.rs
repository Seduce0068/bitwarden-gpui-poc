//! Clipboard state with automatic restoration of the previous contents.

use std::time::{Duration, Instant};

use gpui_kit::*;

/// Seconds before a copied secret is restored.
pub const CLEAR_SECONDS: u64 = 30;

/// Remembers the clipboard contents from before a secret was copied and
/// restores them after the configured delay (default [`CLEAR_SECONDS`]
/// seconds) or on lock.
#[derive(Default)]
pub struct ClipboardState {
    restore: Option<String>,
    clear_at: Option<Instant>,
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

    /// Copy `value` and remember the original clipboard text if this is the
    /// first pending copy. `restore_seconds` controls when it is put back.
    pub fn copy(&mut self, value: &str, restore_seconds: u64, cx: &mut App) {
        if self.clear_at.is_none() {
            self.restore = cx.read_from_clipboard().and_then(|item| {
                item.entries.into_iter().find_map(|entry| match entry {
                    ClipboardEntry::String(text) => Some(text.text),
                    _ => None,
                })
            });
        }
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        self.clear_at = Some(Instant::now() + Duration::from_secs(restore_seconds));
    }

    /// Put the clipboard back if a copy is pending.
    pub fn restore(&mut self, cx: &mut App) {
        if self.clear_at.is_none() {
            return;
        }
        let previous = self.restore.take().unwrap_or_default();
        cx.write_to_clipboard(ClipboardItem::new_string(previous));
        self.clear_at = None;
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
        state.clear_at = Some(Instant::now() + Duration::from_secs(1));
        assert!(state.is_pending());
        assert!(!state.due(Instant::now()));
        assert!(state.due(Instant::now() + Duration::from_secs(2)));
    }

    #[::core::prelude::v1::test]
    fn zero_delay_is_due_immediately() {
        let mut state = ClipboardState::new();
        let now = Instant::now();
        state.clear_at = Some(now + Duration::from_secs(0));
        assert!(state.due(now), "a zero-second delay must restore at once");
    }
}
