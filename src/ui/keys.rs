//! Pure key classification and generator key handling, free of GPUI types.

use crate::ui::state::{AuthField, GeneratorState, Panel, Screen, SettingsField};

/// Apply a generator-panel key to its settings.
///
/// Returns whether the key was recognised, so the caller can decide whether
/// to redraw.
pub fn apply_generator_key(state: &mut GeneratorState, key: &str) -> bool {
    match key {
        "1" => state.password.lowercase = !state.password.lowercase,
        "2" => state.password.uppercase = !state.password.uppercase,
        "3" => state.password.digits = !state.password.digits,
        "4" => state.password.symbols = !state.password.symbols,
        "5" => state.password.avoid_ambiguous = !state.password.avoid_ambiguous,
        "6" => state.passphrase.capitalize = !state.passphrase.capitalize,
        "7" => state.passphrase.include_number = !state.passphrase.include_number,
        "+" | "=" => {
            state.password.length = (state.password.length + 1).min(128);
            state.passphrase.words = (state.passphrase.words + 1).min(20);
        }
        "-" | "_" => {
            state.password.length = state.password.length.saturating_sub(1).max(4);
            state.passphrase.words = state.passphrase.words.saturating_sub(1).max(2);
        }
        "," => {
            state.passphrase.separator = match state.passphrase.separator.as_str() {
                "-" => ".".into(),
                "." => "_".into(),
                "_" => String::new(),
                _ => "-".into(),
            };
        }
        _ => return false,
    }
    true
}

/// A UI intent derived from a keystroke, independent of GPUI types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAction {
    /// Leave the application.
    Quit,
    /// Attempt a real login with the entered credentials.
    Authenticate,
    /// Open the mock vault explicitly (demo only).
    OpenDemoVault,
    /// Retry a failed login.
    RetryLogin,
    /// Select the credential field to edit.
    EditAuthField(AuthField),
    /// Select the settings field to edit.
    EditSettingsField(SettingsField),
    /// Finish editing a lock-screen credential field.
    FinishAuthEdit,
    /// Finish searching.
    FinishSearch,
    /// Finish editing a settings field.
    FinishSettingsEdit,
    /// Insert a character into the active credential field.
    InsertAuthChar(char),
    /// Insert a character into the search query.
    InsertSearchChar(char),
    /// Insert a character into the active settings field.
    InsertSettingsChar(char),
    /// Remove the last character from the active credential field.
    BackspaceAuth,
    /// Remove the last character from the search query.
    BackspaceSearch,
    /// Remove the last character from the active settings field.
    BackspaceSettings,
    /// Remove the last character from the current filter query.
    BackspaceQuery,
    /// Switch to a panel.
    SetPanel(Panel),
    /// Lock the vault.
    Lock,
    /// Move the selected row.
    MoveSelection(isize),
    /// Select a row by index (mouse click); not produced by key classification.
    SelectRow(usize),
    /// Toggle the selected item's favorite flag.
    ToggleFavorite,
    /// Open the audit panel when a report exists.
    OpenAudit,
    /// Generate a password or passphrase.
    GeneratePassword,
    GeneratePassphrase,
    /// Copy a secret to the clipboard.
    CopyPassword,
    CopyPassphrase,
    CopyTotp,
    /// Cycle the item filter.
    CycleFilter,
    /// Cycle the sort key.
    CycleSort,
    /// Begin searching.
    StartSearch,
    /// Persist settings.
    SaveSettings,
    /// Adjust audit thresholds by the given delta.
    AdjustThreshold(i32),
    /// Adjust the idle auto-lock timeout by the given delta (minutes).
    AdjustIdleLock(i32),
    /// Toggle one generator option.
    ToggleLowercase,
    ToggleUppercase,
    ToggleDigits,
    ToggleSymbols,
    ToggleAmbiguous,
    ToggleCapitalize,
    ToggleNumber,
    AdjustLength(isize),
    CycleSeparator,
    /// No action for this keystroke.
    None,
}

/// The state needed to classify a keystroke, without GPUI types.
#[derive(Clone, Copy, Debug)]
pub struct KeyContext<'a> {
    /// Current screen.
    pub screen: Screen,
    /// Active panel while unlocked.
    pub panel: Panel,
    /// The pressed key.
    pub key: &'a str,
    /// A lock-screen credential field is being edited.
    pub editing_auth: bool,
    /// The vault search box is active.
    pub searching: bool,
    /// A settings field is being edited.
    pub editing_settings: bool,
    /// The last login attempt failed.
    pub login_failed: bool,
    /// A health report is available.
    pub has_audit_report: bool,
    /// The search query is not empty.
    pub query_nonempty: bool,
}

/// Map a keystroke to a UI intent.
///
/// Editing modes take priority so that typing `l` into a password field does
/// not lock the vault.
pub fn classify_key(ctx: &KeyContext<'_>) -> KeyAction {
    let single = ctx.key.chars().count() == 1;
    let character = ctx.key.chars().next();

    if ctx.screen == Screen::Locked {
        if ctx.editing_auth {
            return match ctx.key {
                "escape" | "enter" => KeyAction::FinishAuthEdit,
                "backspace" => KeyAction::BackspaceAuth,
                _value if single => character.map_or(KeyAction::None, KeyAction::InsertAuthChar),
                _ => KeyAction::None,
            };
        }
        return match ctx.key {
            "escape" => KeyAction::Quit,
            "enter" => KeyAction::Authenticate,
            "m" => KeyAction::OpenDemoVault,
            "r" if ctx.login_failed => KeyAction::RetryLogin,
            "1" => KeyAction::EditAuthField(AuthField::ServerUrl),
            "2" => KeyAction::EditAuthField(AuthField::Email),
            "3" => KeyAction::EditAuthField(AuthField::ClientId),
            "4" => KeyAction::EditAuthField(AuthField::ClientSecret),
            "5" => KeyAction::EditAuthField(AuthField::MasterPassword),
            _ => KeyAction::None,
        };
    }

    if ctx.searching {
        return match ctx.key {
            "escape" | "enter" => KeyAction::FinishSearch,
            "backspace" => KeyAction::BackspaceSearch,
            _value if single => character.map_or(KeyAction::None, KeyAction::InsertSearchChar),
            _ => KeyAction::None,
        };
    }

    match ctx.panel {
        Panel::Audit => match ctx.key {
            "escape" => KeyAction::Quit,
            "g" => KeyAction::SetPanel(Panel::Vault),
            "l" => KeyAction::Lock,
            _ => KeyAction::None,
        },
        Panel::Generator => {
            if ctx.editing_settings {
                return KeyAction::None;
            }
            match ctx.key {
                "escape" => KeyAction::Quit,
                "n" => KeyAction::SetPanel(Panel::Vault),
                "l" => KeyAction::Lock,
                "p" => KeyAction::GeneratePassword,
                "h" => KeyAction::GeneratePassphrase,
                "y" => KeyAction::CopyPassword,
                "Y" => KeyAction::CopyPassphrase,
                "1" => KeyAction::ToggleLowercase,
                "2" => KeyAction::ToggleUppercase,
                "3" => KeyAction::ToggleDigits,
                "4" => KeyAction::ToggleSymbols,
                "5" => KeyAction::ToggleAmbiguous,
                "6" => KeyAction::ToggleCapitalize,
                "7" => KeyAction::ToggleNumber,
                "+" | "=" => KeyAction::AdjustLength(1),
                "-" | "_" => KeyAction::AdjustLength(-1),
                "," => KeyAction::CycleSeparator,
                _ => KeyAction::None,
            }
        }
        Panel::Settings => {
            if ctx.editing_settings {
                return match ctx.key {
                    "escape" | "enter" => KeyAction::FinishSettingsEdit,
                    "backspace" => KeyAction::BackspaceSettings,
                    _value if single => {
                        character.map_or(KeyAction::None, KeyAction::InsertSettingsChar)
                    }
                    _ => KeyAction::None,
                };
            }
            match ctx.key {
                "escape" => KeyAction::Quit,
                "c" => KeyAction::SetPanel(Panel::Vault),
                "l" => KeyAction::Lock,
                "1" => KeyAction::EditSettingsField(SettingsField::ServerUrl),
                "2" => KeyAction::EditSettingsField(SettingsField::Email),
                "+" | "=" => KeyAction::AdjustThreshold(1),
                "-" | "_" => KeyAction::AdjustThreshold(-1),
                "i" => KeyAction::AdjustIdleLock(1),
                "u" => KeyAction::AdjustIdleLock(-1),
                "w" => KeyAction::SaveSettings,
                _ => KeyAction::None,
            }
        }
        Panel::Vault => match ctx.key {
            "escape" => KeyAction::Quit,
            "up" => KeyAction::MoveSelection(-1),
            "down" => KeyAction::MoveSelection(1),
            "l" => KeyAction::Lock,
            "t" => KeyAction::CycleFilter,
            "s" => KeyAction::CycleSort,
            "f" => KeyAction::ToggleFavorite,
            "y" => KeyAction::CopyTotp,
            "g" if ctx.has_audit_report => KeyAction::OpenAudit,
            "n" => KeyAction::SetPanel(Panel::Generator),
            "c" => KeyAction::SetPanel(Panel::Settings),
            "/" => KeyAction::StartSearch,
            "backspace" if ctx.query_nonempty => KeyAction::BackspaceQuery,
            _ => KeyAction::None,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ctx(key: &str) -> KeyContext<'_> {
        KeyContext {
            screen: Screen::Unlocked,
            panel: Panel::Vault,
            key,
            editing_auth: false,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: true,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn text_editing_actions_are_mode_specific() {
        let mut value = ctx("a");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::InsertSearchChar('a'));

        value.key = "backspace";
        assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        value.key = "b";
        assert_eq!(classify_key(&value), KeyAction::InsertSettingsChar('b'));

        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(classify_key(&value), KeyAction::InsertAuthChar('b'));
        value.key = "backspace";
        assert_eq!(classify_key(&value), KeyAction::BackspaceAuth);

        value.screen = Screen::Unlocked;
        value.panel = Panel::Vault;
        value.editing_auth = false;
        value.editing_settings = false;
        value.query_nonempty = true;
        assert_eq!(classify_key(&value), KeyAction::BackspaceQuery);
    }

    #[::core::prelude::v1::test]
    fn finish_actions_are_mode_specific() {
        let mut value = ctx("enter");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::FinishSearch);

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        assert_eq!(classify_key(&value), KeyAction::FinishSettingsEdit);

        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(classify_key(&value), KeyAction::FinishAuthEdit);
    }

    #[test]
    fn lock_screen_keys_and_retry_gate() {
        let mut value = ctx("enter");
        value.screen = Screen::Locked;
        assert_eq!(classify_key(&value), KeyAction::Authenticate);

        value.key = "m";
        assert_eq!(classify_key(&value), KeyAction::OpenDemoVault);

        value.key = "r";
        assert_eq!(classify_key(&value), KeyAction::None);
        value.login_failed = true;
        assert_eq!(classify_key(&value), KeyAction::RetryLogin);

        value.key = "4";
        assert_eq!(
            classify_key(&value),
            KeyAction::EditAuthField(AuthField::ClientSecret)
        );
    }

    #[::core::prelude::v1::test]
    fn generator_keys_toggle_options_and_clamp_lengths() {
        let mut state = GeneratorState::default();
        assert!(apply_generator_key(&mut state, "1"));
        assert!(!state.password.lowercase);
        assert!(apply_generator_key(&mut state, "6"));
        assert!(!state.passphrase.capitalize);

        assert!(apply_generator_key(&mut state, "+"));
        assert_eq!(state.password.length, 21);
        assert_eq!(state.passphrase.words, 5);
        assert!(apply_generator_key(&mut state, "-"));
        assert_eq!(state.password.length, 20);

        assert!(apply_generator_key(&mut state, ","));
        assert_eq!(state.passphrase.separator, ".");
        assert!(apply_generator_key(&mut state, ","));
        assert_eq!(state.passphrase.separator, "_");

        assert!(!apply_generator_key(&mut state, "q"));
    }

    #[test]
    fn vault_keys_map_to_actions() {
        assert_eq!(classify_key(&ctx("up")), KeyAction::MoveSelection(-1));
        assert_eq!(classify_key(&ctx("down")), KeyAction::MoveSelection(1));
        assert_eq!(classify_key(&ctx("f")), KeyAction::ToggleFavorite);
        assert_eq!(classify_key(&ctx("y")), KeyAction::CopyTotp);
        assert_eq!(classify_key(&ctx("g")), KeyAction::OpenAudit);
        assert_eq!(classify_key(&ctx("/")), KeyAction::StartSearch);
        assert_eq!(
            classify_key(&ctx("c")),
            KeyAction::SetPanel(Panel::Settings)
        );
        assert_eq!(classify_key(&ctx("q")), KeyAction::None);
    }

    #[test]
    fn settings_and_generator_keys() {
        let mut value = ctx("w");
        value.panel = Panel::Settings;
        assert_eq!(classify_key(&value), KeyAction::SaveSettings);
        value.key = "+";
        assert_eq!(classify_key(&value), KeyAction::AdjustThreshold(1));
        value.key = "i";
        assert_eq!(classify_key(&value), KeyAction::AdjustIdleLock(1));
        value.key = "u";
        assert_eq!(classify_key(&value), KeyAction::AdjustIdleLock(-1));

        value.panel = Panel::Generator;
        value.key = "p";
        assert_eq!(classify_key(&value), KeyAction::GeneratePassword);
        value.key = "Y";
        assert_eq!(classify_key(&value), KeyAction::CopyPassphrase);
        value.key = "-";
        assert_eq!(classify_key(&value), KeyAction::AdjustLength(-1));
    }

    #[test]
    fn editing_mode_swallows_shortcut_keys() {
        let mut value = ctx("l");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::InsertSearchChar('l'));

        let mut value = ctx("enter");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::FinishSearch);

        let mut value = ctx("backspace");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);
    }
}
