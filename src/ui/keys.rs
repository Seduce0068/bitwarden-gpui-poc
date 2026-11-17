//! Pure key classification and generator key handling, free of GPUI types.

use crate::settings::Settings;
use crate::ui::state::{AuthField, Panel, Screen, SettingsField};

/// Apply a generator-panel key to its settings.
///
/// Returns whether the key was recognised, so the caller can decide whether
/// to redraw.
pub fn apply_generator_key(settings: &mut Settings, key: &str) -> bool {
    match key {
        "1" => settings.password_generator.lowercase = !settings.password_generator.lowercase,
        "2" => settings.password_generator.uppercase = !settings.password_generator.uppercase,
        "3" => settings.password_generator.digits = !settings.password_generator.digits,
        "4" => settings.password_generator.symbols = !settings.password_generator.symbols,
        "5" => {
            settings.password_generator.avoid_ambiguous =
                !settings.password_generator.avoid_ambiguous
        }
        "6" => settings.passphrase_generator.capitalize = !settings.passphrase_generator.capitalize,
        "7" => {
            settings.passphrase_generator.include_number =
                !settings.passphrase_generator.include_number
        }
        "+" | "=" => {
            settings.password_generator.length = (settings.password_generator.length + 1).min(128);
            settings.passphrase_generator.words = (settings.passphrase_generator.words + 1).min(20);
        }
        "-" | "_" => {
            settings.password_generator.length =
                settings.password_generator.length.saturating_sub(1).max(4);
            settings.passphrase_generator.words =
                settings.passphrase_generator.words.saturating_sub(1).max(2);
        }
        "," => {
            settings.passphrase_generator.separator =
                match settings.passphrase_generator.separator.as_str() {
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

/// Modifier keys that must not trigger single-key commands.
///
/// `shift` is deliberately absent: it is required for uppercase letters and
/// symbols such as `+` and `_`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyModifiers {
    pub control: bool,
    pub platform: bool,
    pub alt: bool,
    pub function: bool,
}

impl KeyModifiers {
    /// Whether a command-like modifier was held.
    pub fn has_command(self) -> bool {
        self.control || self.platform || self.function
    }
}

/// A UI intent derived from a keystroke, independent of GPUI types.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    InsertAuthText(String),
    /// Insert a character into the search query.
    InsertSearchText(String),
    /// Insert a character into the active settings field.
    InsertSettingsText(String),
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
    /// The pressed key (physical/ASCII equivalent).
    pub key: &'a str,
    /// The text the keystroke would insert; may be multi-character with IME.
    pub key_char: Option<&'a str>,
    /// Command-like modifiers held during the keystroke.
    pub modifiers: KeyModifiers,
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

/// Text produced by a keystroke, if any.
///
/// `key_char` is preferred because it carries IME-composed and layout-specific
/// characters; `key` is only the ASCII/physical equivalent.
fn typed_text<'a>(ctx: &KeyContext<'a>) -> Option<&'a str> {
    if let Some(text) = ctx.key_char {
        if !text.is_empty() {
            return Some(text);
        }
    }
    if ctx.key == "space" {
        return Some(" ");
    }
    (ctx.key.chars().count() == 1).then_some(ctx.key)
}

/// The key name to use for command matching.
///
/// On Linux GPUI lowercases `key` and keeps Shift characters in `key_char`,
/// so `Shift+Y` must be matched through `key_char` or `Y` never fires.
fn command_key<'a>(ctx: &KeyContext<'a>) -> &'a str {
    ctx.key_char
        .filter(|text| text.chars().count() == 1)
        .unwrap_or(ctx.key)
}

fn text_action(text: &str, action: fn(String) -> KeyAction) -> KeyAction {
    action(text.to_string())
}

/// Map a keystroke to a UI intent.
///
/// Editing modes take priority so that typing `l` into a password field does
/// not lock the vault. Keybindings with command-like modifiers are ignored so
/// they can be handled by the platform (e.g. Ctrl+C).
pub fn classify_key(ctx: &KeyContext<'_>) -> KeyAction {
    if ctx.modifiers.has_command() {
        return KeyAction::None;
    }
    // Alt alone may still produce a printable layout character (e.g. Option+S
    // -> "ß"). Allow it only while editing text and only when it produced one;
    // in command panels Alt+key must stay inert.
    let editing_text = ctx.editing_auth || ctx.searching || ctx.editing_settings;
    if ctx.modifiers.alt && !(editing_text && typed_text(ctx).is_some()) {
        return KeyAction::None;
    }
    let key = command_key(ctx);

    if ctx.screen == Screen::Locked {
        if ctx.editing_auth {
            return match key {
                "escape" | "enter" => KeyAction::FinishAuthEdit,
                "backspace" => KeyAction::BackspaceAuth,
                _ => typed_text(ctx).map_or(KeyAction::None, |text| {
                    text_action(text, KeyAction::InsertAuthText)
                }),
            };
        }
        return match key {
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
        return match key {
            "escape" | "enter" => KeyAction::FinishSearch,
            "backspace" => KeyAction::BackspaceSearch,
            _ => typed_text(ctx).map_or(KeyAction::None, |text| {
                text_action(text, KeyAction::InsertSearchText)
            }),
        };
    }

    match ctx.panel {
        Panel::Audit => match key {
            "escape" => KeyAction::Quit,
            "g" => KeyAction::SetPanel(Panel::Vault),
            "l" => KeyAction::Lock,
            _ => KeyAction::None,
        },
        Panel::Generator => {
            if ctx.editing_settings {
                return KeyAction::None;
            }
            match key {
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
                return match key {
                    "escape" | "enter" => KeyAction::FinishSettingsEdit,
                    "backspace" => KeyAction::BackspaceSettings,
                    _ => typed_text(ctx).map_or(KeyAction::None, |text| {
                        text_action(text, KeyAction::InsertSettingsText)
                    }),
                };
            }
            match key {
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
        Panel::Vault => match key {
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
#[path = "keys_tests.rs"]
mod tests;
