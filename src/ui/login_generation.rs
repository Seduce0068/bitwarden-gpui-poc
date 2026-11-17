//! Generation token for the in-flight asynchronous login.
//!
//! A login runs in a detached task. When it finishes, its result must only be
//! applied if no competing action (lock, demo vault, or a newer login) has
//! happened in the meantime. This module holds that bookkeeping as pure logic
//! so it can be tested without a GPUI window.

/// Monotonic token identifying one login attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoginGeneration(u64);

impl LoginGeneration {
    /// Advance past the current value, skipping the `0` sentinel on wrap.
    fn advance(&mut self) {
        self.0 = self.0.wrapping_add(1);
        if self.0 == 0 {
            self.0 = 1;
        }
    }

    /// Start a new attempt and return its token.
    pub fn begin(&mut self) -> Self {
        self.advance();
        *self
    }

    /// Cancel any in-flight attempt without starting a new one.
    pub fn invalidate(&mut self) {
        self.advance();
    }

    /// Whether `token` still refers to the current, unconsumed attempt.
    pub fn is_current(self, token: Self) -> bool {
        token.0 != 0 && self.0 == token.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_generation_has_no_current_attempt() {
        let generation = LoginGeneration::default();
        assert!(!generation.is_current(LoginGeneration(0)));
        assert!(!generation.is_current(LoginGeneration(1)));
    }

    #[test]
    fn begin_returns_the_only_accepted_token() {
        let mut generation = LoginGeneration::default();
        let token = generation.begin();
        assert!(generation.is_current(token));
        assert!(!generation.is_current(LoginGeneration(0)));
    }

    #[test]
    fn a_new_attempt_invalidates_the_previous_one() {
        let mut generation = LoginGeneration::default();
        let first = generation.begin();
        let second = generation.begin();
        assert_ne!(first, second);
        assert!(!generation.is_current(first));
        assert!(generation.is_current(second));
    }

    #[test]
    fn competing_action_invalidates_the_attempt() {
        let mut generation = LoginGeneration::default();
        let token = generation.begin();
        generation.invalidate();
        assert!(!generation.is_current(token));
    }

    #[test]
    fn consuming_a_token_prevents_duplicate_application() {
        let mut generation = LoginGeneration::default();
        let token = generation.begin();
        assert!(generation.is_current(token));
        generation.invalidate();
        assert!(!generation.is_current(token));
    }

    #[test]
    fn wrapping_does_not_resurrect_the_zero_sentinel() {
        let mut generation = LoginGeneration(u64::MAX);
        let token = generation.begin();
        assert_ne!(token, LoginGeneration(0));
        assert!(generation.is_current(token));
    }
}
