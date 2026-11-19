//! Pure key classification and generator key handling, free of GPUI types.

use crate::settings::Settings;
use crate::ui::state::{AuthField, Panel, Screen, SettingsField};

/// A typed generator setting change, independent of the key that triggered it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeneratorOption {
    Lowercase,
    Uppercase,
    Digits,
    Symbols,
    AvoidAmbiguous,
    Capitalize,
    IncludeNumber,
    LengthUp,
    LengthDown,
    Separator,
}

/// Apply a generator option to its settings.
pub(super) fn apply_generator_key(settings: &mut Settings, option: GeneratorOption) {
    use GeneratorOption::*;
    match option {
        Lowercase => settings.password_generator.lowercase = !settings.password_generator.lowercase,
        Uppercase => settings.password_generator.uppercase = !settings.password_generator.uppercase,
        Digits => settings.password_generator.digits = !settings.password_generator.digits,
        Symbols => settings.password_generator.symbols = !settings.password_generator.symbols,
        AvoidAmbiguous => {
            settings.password_generator.avoid_ambiguous =
                !settings.password_generator.avoid_ambiguous
        }
        Capitalize => {
            settings.passphrase_generator.capitalize = !settings.passphrase_generator.capitalize
        }
        IncludeNumber => {
            settings.passphrase_generator.include_number =
                !settings.passphrase_generator.include_number
        }
        LengthUp => {
            settings.password_generator.length = (settings.password_generator.length + 1).min(128);
            settings.passphrase_generator.words = (settings.passphrase_generator.words + 1).min(20);
        }
        LengthDown => {
            settings.password_generator.length =
                settings.password_generator.length.saturating_sub(1).max(4);
            settings.passphrase_generator.words =
                settings.passphrase_generator.words.saturating_sub(1).max(2);
        }
        Separator => {
            settings.passphrase_generator.separator =
                match settings.passphrase_generator.separator.as_str() {
                    "-" => ".".into(),
                    "." => "_".into(),
                    "_" => String::new(),
                    _ => "-".into(),
                };
        }
    }
}

/// Command-like modifiers relevant to key classification.
///
/// Shift is deliberately absent: it is required for uppercase letters and
/// symbols such as `+` and `_`, so treating it as a command modifier would
/// break the generator key bindings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct KeyModifiers {
    pub(super) control: bool,
    pub(super) platform: bool,
    pub(super) alt: bool,
    pub(super) function: bool,
}

impl KeyModifiers {
    /// Whether a platform-level command shortcut must be left to the OS.
    pub(super) fn has_command(self) -> bool {
        self.control || self.platform || self.function
    }
}

/// A UI intent derived from a keystroke or a mouse action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum KeyAction {
    Quit,
    Authenticate,
    OpenDemoVault,
    RetryLogin,
    EditAuthField(AuthField),
    EditSettingsField(SettingsField),
    FinishAuthEdit,
    FinishSearch,
    FinishSettingsEdit,
    InsertAuthText(String),
    InsertSearchText(String),
    InsertSettingsText(String),
    BackspaceAuth,
    BackspaceSearch,
    BackspaceSettings,
    BackspaceQuery,
    SetPanel(Panel),
    Lock,
    MoveSelection(isize),
    SelectRow(usize),
    ToggleFavorite,
    OpenAudit,
    GeneratePassword,
    GeneratePassphrase,
    CopyPassword,
    CopyPassphrase,
    CopyTotp,
    CopySelectedPassword,
    CopySelectedUsername,
    CycleFilter,
    CycleSort,
    StartSearch,
    SaveSettings,
    AdjustThreshold(i32),
    AdjustIdleLock(i32),
    /// Change one typed generator option.
    Generator(GeneratorOption),
    None,
}

/// The state needed to classify a keystroke, without GPUI types.
#[derive(Clone, Copy, Debug)]
pub(super) struct KeyContext<'a> {
    /// Current screen.
    pub(super) screen: Screen,
    /// Active panel while unlocked.
    pub(super) panel: Panel,
    /// The pressed key (physical/ASCII equivalent).
    pub(super) key: &'a str,
    /// The text the keystroke would insert; may be multi-character with IME.
    pub(super) key_char: Option<&'a str>,
    /// Command-like modifiers held during the keystroke.
    pub(super) modifiers: KeyModifiers,
    /// A lock-screen credential field is being edited.
    pub(super) editing_auth: bool,
    /// The vault search box is active.
    pub(super) searching: bool,
    /// A settings field is being edited.
    pub(super) editing_settings: bool,
    /// The last login attempt failed.
    pub(super) login_failed: bool,
    /// A health report is available.
    pub(super) has_audit_report: bool,
    /// The search query is not empty.
    pub(super) query_nonempty: bool,
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
pub(super) fn classify_key(ctx: &KeyContext<'_>) -> KeyAction {
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
                "1" => KeyAction::Generator(GeneratorOption::Lowercase),
                "2" => KeyAction::Generator(GeneratorOption::Uppercase),
                "3" => KeyAction::Generator(GeneratorOption::Digits),
                "4" => KeyAction::Generator(GeneratorOption::Symbols),
                "5" => KeyAction::Generator(GeneratorOption::AvoidAmbiguous),
                "6" => KeyAction::Generator(GeneratorOption::Capitalize),
                "7" => KeyAction::Generator(GeneratorOption::IncludeNumber),
                "+" | "=" => KeyAction::Generator(GeneratorOption::LengthUp),
                "-" | "_" => KeyAction::Generator(GeneratorOption::LengthDown),
                "," => KeyAction::Generator(GeneratorOption::Separator),
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
            "p" => KeyAction::CopySelectedPassword,
            "u" => KeyAction::CopySelectedUsername,
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
