//! Pure UI predicates that can be tested without a GPUI window.

use crate::ui::model::{AuthField, Panel, Screen, SettingsField};

/// Whether the lock screen has enough credential input to attempt a login.
///
/// The server URL and email may be pre-filled from settings, so they are not
/// considered here. An empty client id, secret or master password means the
/// demo vault is opened instead.
pub fn has_credentials(client_id: &str, client_secret: &str, master_password: &str) -> bool {
    !client_id.is_empty() || !client_secret.is_empty() || !master_password.is_empty()
}

/// Whether `selected_id` still names an item in the current view.
///
/// `None` is valid: the UI falls back to showing the first item.
pub fn selection_in_view<'a>(
    selected_id: Option<&str>,
    ids: impl IntoIterator<Item = &'a str>,
) -> bool {
    match selected_id {
        None => true,
        Some(id) => ids.into_iter().any(|candidate| candidate == id),
    }
}

/// A UI intent derived from a keystroke, independent of GPUI types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAction {
    /// Leave the application.
    Quit,
    /// Attempt login or open the demo vault.
    Authenticate,
    /// Retry a failed login.
    RetryLogin,
    /// Select the credential field to edit.
    EditAuthField(AuthField),
    /// Select the settings field to edit.
    EditSettingsField(SettingsField),
    /// Finish editing a text field.
    FinishEdit,
    /// Insert one character into the active text field.
    InsertChar(char),
    /// Remove the last character from the active text field.
    Backspace,
    /// Switch to a panel.
    SetPanel(Panel),
    /// Lock the vault.
    Lock,
    /// Move the selected row.
    MoveSelection(isize),
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
                "escape" | "enter" => KeyAction::FinishEdit,
                "backspace" => KeyAction::Backspace,
                _value if single => character.map_or(KeyAction::None, KeyAction::InsertChar),
                _ => KeyAction::None,
            };
        }
        return match ctx.key {
            "escape" => KeyAction::Quit,
            "enter" => KeyAction::Authenticate,
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
            "escape" | "enter" => KeyAction::FinishEdit,
            "backspace" => KeyAction::Backspace,
            _value if single => character.map_or(KeyAction::None, KeyAction::InsertChar),
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
                    "escape" | "enter" => KeyAction::FinishEdit,
                    "backspace" => KeyAction::Backspace,
                    _value if single => character.map_or(KeyAction::None, KeyAction::InsertChar),
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
            "backspace" if ctx.query_nonempty => KeyAction::Backspace,
            _ => KeyAction::None,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn credentials_need_at_least_one_field() {
        assert!(!has_credentials("", "", ""));
        assert!(has_credentials("user.1234", "", ""));
        assert!(has_credentials("", "secret", ""));
        assert!(has_credentials("", "", "master"));
    }

    #[test]
    fn selection_in_view_checks_ids() {
        let ids = ["1", "2", "3"];
        assert!(selection_in_view(None, ids));
        assert!(selection_in_view(Some("2"), ids));
        assert!(!selection_in_view(Some("4"), ids));
        assert!(!selection_in_view(Some("1"), []));
    }

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
    fn editing_mode_swallows_shortcut_keys() {
        let mut value = ctx("l");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::InsertChar('l'));

        let mut value = ctx("enter");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::FinishEdit);

        let mut value = ctx("backspace");
        value.searching = true;
        assert_eq!(classify_key(&value), KeyAction::Backspace);
    }

    #[test]
    fn lock_screen_keys_and_retry_gate() {
        let mut value = ctx("enter");
        value.screen = Screen::Locked;
        assert_eq!(classify_key(&value), KeyAction::Authenticate);

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

    #[test]
    fn settings_and_generator_keys() {
        let mut value = ctx("w");
        value.panel = Panel::Settings;
        assert_eq!(classify_key(&value), KeyAction::SaveSettings);
        value.key = "+";
        assert_eq!(classify_key(&value), KeyAction::AdjustThreshold(1));

        value.panel = Panel::Generator;
        value.key = "p";
        assert_eq!(classify_key(&value), KeyAction::GeneratePassword);
        value.key = "Y";
        assert_eq!(classify_key(&value), KeyAction::CopyPassphrase);
        value.key = "-";
        assert_eq!(classify_key(&value), KeyAction::AdjustLength(-1));
    }
}
