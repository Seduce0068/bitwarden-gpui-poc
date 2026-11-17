//! Shared view state types.

use zeroize::Zeroizing;

/// Which top-level screen is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Credentials are entered here.
    Locked,
    /// The vault is available.
    Unlocked,
}

/// Which panel occupies the main area while unlocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    /// Vault item list.
    Vault,
    /// Health audit report.
    Audit,
    /// Password and passphrase generator.
    Generator,
    /// Persistent settings.
    Settings,
}

/// A text field being edited in the settings panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsField {
    /// Server URL.
    ServerUrl,
    /// Account email.
    Email,
}

/// A credential field being edited on the lock screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthField {
    /// Server URL.
    ServerUrl,
    /// Account email.
    Email,
    /// Personal API key client id.
    ClientId,
    /// Personal API key client secret.
    ClientSecret,
    /// Master password.
    MasterPassword,
}

/// Last values drawn from the generator; configuration lives in `Settings`.
///
/// Generated values are held in [`Zeroizing<String>`] so their final buffer is
/// wiped when the state is dropped, replaced (e.g. on lock) or overwritten.
/// As with every `String`-based zeroization, copies left behind by earlier
/// reallocations cannot be wiped; see the crate's V3 note.
///
/// `Debug` masks the generated values so secrets are not printed.
#[derive(Clone, Default)]
pub struct GeneratorState {
    /// Last generated password.
    pub last_password: Option<Zeroizing<String>>,
    /// Last generated passphrase.
    pub last_passphrase: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for GeneratorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratorState")
            .field(
                "last_password",
                &self.last_password.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "last_passphrase",
                &self.last_passphrase.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn debug_masks_generated_secrets() {
        let state = GeneratorState {
            last_password: Some(Zeroizing::new("generated-password".into())),
            last_passphrase: Some(Zeroizing::new("correct-horse-battery".into())),
        };
        let debug = format!("{state:?}");
        assert!(!debug.contains("generated-password"), "{debug}");
        assert!(!debug.contains("correct-horse-battery"), "{debug}");
        assert_eq!(debug.matches("[redacted]").count(), 2, "{debug}");

        let empty = GeneratorState::default();
        let debug = format!("{empty:?}");
        assert!(!debug.contains("[redacted]"), "{debug}");
        assert!(debug.contains("None"), "{debug}");
    }

    #[::core::prelude::v1::test]
    fn generated_secrets_have_str_views_and_replacement_stays_redacted() {
        let mut state = GeneratorState {
            last_password: Some(Zeroizing::new("old-password".into())),
            last_passphrase: None,
        };
        // `Zeroizing<String>` derefs to `String`, so callers map `as_str()`
        // rather than using `Option::as_deref()` (which yields `&String`).
        let view: Option<&str> = state.last_password.as_ref().map(|value| value.as_str());
        assert_eq!(view, Some("old-password"));
        assert_eq!(
            state.last_passphrase.as_ref().map(|value| value.as_str()),
            None
        );

        // Reassignment drops (and zeroizes) the previous secret buffer.
        state.last_password = Some(Zeroizing::new("new-password".into()));
        let view: Option<&str> = state.last_password.as_ref().map(|value| value.as_str());
        assert_eq!(view, Some("new-password"));
        let debug = format!("{state:?}");
        assert!(!debug.contains("old-password"), "{debug}");
        assert!(!debug.contains("new-password"), "{debug}");
        assert_eq!(debug.matches("[redacted]").count(), 1, "{debug}");
    }
}
