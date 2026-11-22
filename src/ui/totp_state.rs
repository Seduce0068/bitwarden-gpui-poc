//! Cached TOTP display state for the selected item.

use zeroize::Zeroizing;

use crate::totp::Tick;

/// Seconds left at which the displayed code gets an explicit expiry warning.
pub(super) const EXPIRY_WARNING_SECONDS: u64 = 5;

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

    /// Whether the cached secret is exactly `secret`.
    ///
    /// Used to notice that the selection moved to a non-TOTP item (or to a
    /// different secret) so the old secret can be wiped instead of keeping the
    /// ticker redrawing a stale code every second.
    pub(super) fn matches_secret(&self, secret: &str) -> bool {
        self.secret.as_str() == secret
    }

    /// The code currently on screen, without its countdown suffix.
    ///
    /// Copying this value keeps the clipboard in sync with what the user saw,
    /// even across a period boundary where a freshly generated code could
    /// differ from the cached one.
    pub(super) fn current_code(&self) -> Option<&str> {
        self.tick
            .as_ref()
            .and_then(|tick| tick.code.as_ref())
            .map(|code| code.code())
    }

    /// The cached generation failure, if any.
    pub(super) fn error_message(&self) -> Option<String> {
        self.tick
            .as_ref()
            .and_then(|tick| tick.error.as_ref())
            .map(|error| error.message().to_string())
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
            Some(code) => {
                let base = format!("{} (あと{}秒)", code.grouped(), code.remaining());
                if code.expires_within(EXPIRY_WARNING_SECONDS) {
                    format!("{base} / まもなく期限切れ")
                } else {
                    base
                }
            }
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
    fn display_resamples_when_the_secret_changes_without_clear() {
        let mut state = TotpState::new();
        let first = state.display(SECRET, 40);
        assert!(first.starts_with("287 082"), "{first}");
        assert_eq!(state.current_code(), Some("287082"));
        assert!(state.matches_secret(SECRET));

        // No clear() here: the cached tick is still fresh at the same instant,
        // so only the `secret != ...` branch can replace the code. Without it
        // the previous item's code would keep being displayed.
        let different = "JBSWY3DPEHPK3PXP";
        let second = state.display(different, 40);
        assert_ne!(second, first, "a direct secret switch must resample");
        assert!(state.has_secret());
        assert!(state.matches_secret(different));
        assert!(!state.matches_secret(SECRET));
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(40));
        assert!(state.current_code().is_some());
        assert_ne!(state.current_code(), Some("287082"));

        // Switching back samples the original secret again instead of reusing
        // the intermediate snapshot.
        let back = state.display(SECRET, 40);
        assert_eq!(back, first);
        assert!(state.matches_secret(SECRET));
    }

    #[test]
    fn invalid_secret_reports_failure() {
        let mut state = TotpState::new();
        let value = state.display("not base32!", 0);
        assert_eq!(value, "コード生成失敗");
        assert!(
            state
                .error_message()
                .is_some_and(|message| message.contains("TOTP")),
            "the copy path needs the cached reason instead of a fresh code"
        );
    }

    #[test]
    fn invalid_secret_still_owns_the_secret_and_keeps_the_ticker_running() {
        let mut state = TotpState::new();
        let invalid = "not base32!";
        assert_eq!(state.display(invalid, 0), "コード生成失敗");
        assert!(
            state.has_secret(),
            "the invalid string is still the displayed secret, so has_secret is true"
        );
        assert!(state.matches_secret(invalid));
        assert_eq!(state.current_code(), None);
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(0));

        // A failing snapshot is considered fresh forever (there is no period
        // to advance), so re-rendering every second keeps showing the failure
        // while the ticker itself continues to run: `has_secret()` stays true
        // and `evaluate_tick` keeps requesting invalidation each second.
        assert_eq!(state.display(invalid, 1), "コード生成失敗");
        assert_eq!(
            state.tick.as_ref().map(|tick| tick.at),
            Some(0),
            "the failed snapshot is intentionally never re-parsed on its own"
        );
        assert!(state.has_secret());
        state.invalidate();
        assert_eq!(state.display(invalid, 1), "コード生成失敗");
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(1));

        // Only clearing (lock/selection change) drops the ownership.
        state.clear();
        assert!(!state.has_secret());
    }

    #[test]
    fn display_warns_shortly_before_expiry() {
        let mut state = TotpState::new();
        // A 30-second period leaves 4 seconds at t=26 and 20 at t=40.
        let expiring = state.display(SECRET, 26);
        assert!(expiring.contains("まもなく期限切れ"), "{expiring}");

        let mut state = TotpState::new();
        let fresh = state.display(SECRET, 40);
        assert!(!fresh.contains("まもなく期限切れ"), "{fresh}");
    }

    #[test]
    fn warning_boundary_includes_exactly_five_seconds_remaining() {
        assert_eq!(EXPIRY_WARNING_SECONDS, 5);

        // A 30-second period leaves exactly 5 seconds at t=25. The warning
        // includes the boundary (`expires_within` uses `<=`), but not t=24.
        let mut state = TotpState::new();
        let at_boundary = state.display(SECRET, 25);
        assert!(
            at_boundary.contains("あと5秒"),
            "expected exactly 5 seconds left, got: {at_boundary}"
        );
        assert!(
            at_boundary.contains("まもなく期限切れ"),
            "exactly 5 seconds left must warn, got: {at_boundary}"
        );
        assert_eq!(
            state
                .tick
                .as_ref()
                .and_then(|tick| tick.code.as_ref())
                .map(|code| code.remaining()),
            Some(5)
        );

        // One second earlier there are 6 seconds left: no warning yet.
        let mut state = TotpState::new();
        let before_boundary = state.display(SECRET, 24);
        assert!(
            before_boundary.contains("あと6秒"),
            "expected 6 seconds left, got: {before_boundary}"
        );
        assert!(
            !before_boundary.contains("まもなく期限切れ"),
            "6 seconds left must not warn, got: {before_boundary}"
        );
    }

    #[test]
    fn invalidate_clears_the_cached_error_message() {
        let mut state = TotpState::new();
        let invalid = "not base32!";
        assert_eq!(state.display(invalid, 0), "コード生成失敗");
        assert!(
            state.error_message().is_some(),
            "a failed sample must cache its reason for the copy path"
        );

        state.invalidate();
        assert_eq!(
            state.error_message(),
            None,
            "invalidate drops the cached error along with the tick"
        );
        assert_eq!(state.current_code(), None);

        // A fresh sample can populate the error cache again.
        assert_eq!(state.display(invalid, 1), "コード生成失敗");
        assert!(state.error_message().is_some());
    }

    #[test]
    fn display_resamples_when_the_period_boundary_is_crossed() {
        let mut state = TotpState::new();
        let before = state.display(SECRET, 29);
        assert!(before.contains("あと1秒"), "{before}");
        assert!(before.contains("まもなく期限切れ"));
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(29));

        // Same secret, but t=30 starts a new 30-second period. The cache must
        // be replaced even though the secret did not change: without the
        // re-sample branch the stale code and its expired countdown linger.
        let after = state.display(SECRET, 30);
        assert!(after.contains("あと30秒"), "{after}");
        assert!(!after.contains("まもなく期限切れ"));
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(30));
        assert_eq!(
            state
                .tick
                .as_ref()
                .and_then(|tick| tick.code.as_ref())
                .map(|code| code.remaining()),
            Some(30)
        );
        assert!(state.current_code().is_some());
    }

    #[test]
    fn display_resamples_when_the_clock_moves_backwards() {
        let mut state = TotpState::new();
        let later = state.display(SECRET, 40);
        assert!(later.contains("あと20秒"), "{later}");
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(40));

        // `Tick::is_fresh` treats any earlier timestamp as stale (see
        // totp.rs): a clock correction must replace the cached snapshot,
        // otherwise a code sampled in a future period would keep being shown.
        let earlier = state.display(SECRET, 26);
        assert!(earlier.contains("あと4秒"), "{earlier}");
        assert!(earlier.contains("まもなく期限切れ"));
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(26));
        assert_ne!(later, earlier);

        // Back in the original period: the newer (smaller) timestamp is no
        // longer fresh, so the cache is refreshed once more.
        let again = state.display(SECRET, 40);
        assert_eq!(again, later);
        assert_eq!(state.tick.as_ref().map(|tick| tick.at), Some(40));
    }

    #[test]
    fn current_code_and_secret_identity_track_the_displayed_snapshot() {
        let mut state = TotpState::new();
        assert_eq!(state.current_code(), None);
        assert!(state.matches_secret(""));

        let displayed = state.display(SECRET, 40);
        assert!(displayed.starts_with("287 082"), "{displayed}");
        assert_eq!(state.current_code(), Some("287082"));
        assert!(state.matches_secret(SECRET));
        assert!(!state.matches_secret("JBSWY3DPEHPK3PXP"));

        state.invalidate();
        assert_eq!(
            state.current_code(),
            None,
            "invalidate drops the cached code"
        );

        state.clear();
        assert!(state.matches_secret(""));
    }
}
