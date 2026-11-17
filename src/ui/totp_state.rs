//! Cached TOTP display state for the selected item.

use zeroize::Zeroizing;

use crate::totp::Tick;

/// Holds the secret currently being displayed and its cached code.
///
/// The secret buffer is wiped when replaced or on lock.
#[derive(Default)]
pub(super) struct TotpState {
    secret: Zeroizing<String>,
    tick: Option<Tick>,
}

impl TotpState {
    /// Create an empty state.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Whether a secret is currently being displayed.
    pub(super) fn has_secret(&self) -> bool {
        !self.secret.is_empty()
    }

    /// Drop the cached code so the next display samples a fresh one.
    pub(super) fn invalidate(&mut self) {
        self.tick = None;
    }

    /// Forget the secret entirely, e.g. when the vault is locked.
    pub(super) fn clear(&mut self) {
        // Replacing the value drops (and wipes) the old secret buffer.
        self.secret = Zeroizing::new(String::new());
        self.tick = None;
    }

    /// Return the display string for `secret` at `now`, refreshing the
    /// cached code when the secret or time period changed.
    pub(super) fn display(&mut self, secret: &str, now: u64) -> String {
        if self.secret.as_str() != secret
            || self.tick.as_ref().is_none_or(|tick| !tick.is_fresh(now))
        {
            self.secret = Zeroizing::new(secret.to_string());
            self.tick = Some(Tick::sample(secret, now));
        }
        match self.tick.as_ref().and_then(|tick| tick.code.as_ref()) {
            Some(code) => format!("{} (あと{}秒)", code.grouped(), code.remaining()),
            None => "コード生成失敗".to_string(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn empty_state_has_no_secret() {
        let state = TotpState::new();
        assert!(!state.has_secret());
    }

    #[test]
    fn display_caches_then_reuses_and_invalidates() {
        let mut state = TotpState::new();
        let first = state.display(SECRET, 40);
        assert!(state.has_secret());
        assert!(first.starts_with("287 082"), "{first}");

        // Same period: the cached code is reused.
        let second = state.display(SECRET, 50);
        assert_eq!(second, first);

        state.invalidate();
        let third = state.display(SECRET, 50);
        assert!(third.starts_with("287 082"), "{third}");

        state.clear();
        assert!(!state.has_secret());
    }

    #[test]
    fn clear_then_display_a_different_secret() {
        let mut state = TotpState::new();
        let first = state.display(SECRET, 40);
        assert!(state.has_secret());

        state.clear();
        assert!(!state.has_secret());

        let different = "JBSWY3DPEHPK3PXP";
        let second = state.display(different, 40);
        assert!(state.has_secret());
        assert_ne!(second, first, "a new secret must not reuse the old code");
    }

    #[test]
    fn invalid_secret_reports_failure() {
        let mut state = TotpState::new();
        let value = state.display("not base32!", 0);
        assert_eq!(value, "コード生成失敗");
    }
}
