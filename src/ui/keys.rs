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

/// Help text describing arrow-key handling while editing text.
///
/// Editing modes deliberately do not define a `UiAction` for arrow keys: they
/// are routed through `UiAction::None` so the GPUI text field can handle them
/// natively. This only delegates the keys; it does **not** guarantee caret
/// movement (or Home/End/Shift-selection) because that behaviour belongs to
/// GPUI's text input, not to this classifier. Adding a `MoveSelection` binding
/// here would also conflict with the list-navigation meaning of Up/Down
/// outside editing modes.
pub(super) const TEXT_EDIT_ARROW_KEYS_HINT: &str =
    "入力中: 矢印キーは GPUI のテキスト入力に任せています（キャレット移動を保証するものではありません）";

/// Apply a generator option to its settings.
///
/// `LengthUp`/`LengthDown` change **both** the password length and the
/// passphrase word count at the same time; the UI copy must say so (see
/// `ui::panels::generator_panel`).
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
pub(super) enum UiAction {
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
    DiscardSettings,
    /// Move to the vault list and select the item named by an audit finding.
    ///
    /// Also carries the reserved sentinels defined below for "focus the
    /// highlighted audit row" and "quit or warn about unsaved settings".
    FocusAuditItem(String),
    AdjustThreshold(i32),
    AdjustIdleLock(i32),
    AdjustLoginTimeout(i32),
    AdjustClipboardRestore(i32),
    /// Change one typed generator option.
    Generator(GeneratorOption),
    None,
}

/// Reserved `FocusAuditItem` id meaning "the row highlighted with Up/Down".
///
/// `UiAction` is applied by a single dispatcher in `ui::input`; a reserved id
/// lets the audit panel add commands without changing that dispatcher or its
/// exhaustive match. Real vault ids are server supplied and never collide.
pub(super) const AUDIT_SELECTED_ROW_SENTINEL: &str = "__audit_selected_row__";

/// Reserved `FocusAuditItem` id meaning "leave, or warn about unsaved edits".
///
/// Resolved by `BitwardenApp::focus_audit_item`, which owns the dirty flag and
/// can therefore decide between the warning and the existing `Quit` action.
pub(super) const QUIT_OR_WARN_SENTINEL: &str = "__quit_or_warn__";

impl UiAction {
    /// Focus the audit row currently highlighted by the keyboard.
    pub(super) fn focus_selected_audit_row() -> Self {
        Self::FocusAuditItem(AUDIT_SELECTED_ROW_SENTINEL.to_string())
    }

    /// Quit, but surface the unsaved-settings warning first when dirty.
    pub(super) fn quit_or_warn() -> Self {
        Self::FocusAuditItem(QUIT_OR_WARN_SENTINEL.to_string())
    }
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

fn text_action(text: &str, action: fn(String) -> UiAction) -> UiAction {
    action(text.to_string())
}

/// Cursor-movement key names handled natively by the GPUI text field.
///
/// Matching them explicitly in each editing mode documents the intent and
/// guarantees `UiAction::None` even if a name becomes single-character in a
/// future GPUI version (which would otherwise make `typed_text` insert it).
fn is_text_cursor_key(key: &str) -> bool {
    matches!(
        key,
        "up" | "down"
            | "left"
            | "right"
            | "arrowup"
            | "arrowdown"
            | "arrowleft"
            | "arrowright"
            | "home"
            | "end"
            | "pageup"
            | "pagedown"
    )
}

/// Map a keystroke to a UI intent.
///
/// Editing modes take priority so that typing `l` into a password field does
/// not lock the vault. Keybindings with command-like modifiers are ignored so
/// they can be handled by the platform (e.g. Ctrl+C).
pub(super) fn classify_key(ctx: &KeyContext<'_>) -> UiAction {
    if ctx.modifiers.has_command() {
        return UiAction::None;
    }
    // Alt alone may still produce a printable layout character (e.g. Option+S
    // -> "ß"). Allow it only while editing text and only when it produced one;
    // in command panels Alt+key must stay inert.
    let editing_text = ctx.editing_auth || ctx.searching || ctx.editing_settings;
    if ctx.modifiers.alt && !(editing_text && typed_text(ctx).is_some()) {
        return UiAction::None;
    }
    let key = command_key(ctx);

    if ctx.screen == Screen::Locked {
        if ctx.editing_auth {
            return match key {
                "escape" | "enter" => UiAction::FinishAuthEdit,
                "backspace" => UiAction::BackspaceAuth,
                // Arrow/Home/End stay with the GPUI text field (see
                // TEXT_EDIT_ARROW_KEYS_HINT): no new list-movement binding here.
                _ if is_text_cursor_key(key) => UiAction::None,
                _ => typed_text(ctx).map_or(UiAction::None, |text| {
                    text_action(text, UiAction::InsertAuthText)
                }),
            };
        }
        return match key {
            "escape" => UiAction::quit_or_warn(),
            "enter" => UiAction::Authenticate,
            "m" => UiAction::OpenDemoVault,
            "r" if ctx.login_failed => UiAction::RetryLogin,
            "1" => UiAction::EditAuthField(AuthField::ServerUrl),
            "2" => UiAction::EditAuthField(AuthField::Email),
            "3" => UiAction::EditAuthField(AuthField::ClientId),
            "4" => UiAction::EditAuthField(AuthField::ClientSecret),
            "5" => UiAction::EditAuthField(AuthField::MasterPassword),
            _ => UiAction::None,
        };
    }

    if ctx.searching {
        return match key {
            "escape" | "enter" => UiAction::FinishSearch,
            "backspace" => UiAction::BackspaceSearch,
            // Let GPUI move the caret in the search field; Up/Down still mean
            // MoveSelection only outside this editing mode.
            _ if is_text_cursor_key(key) => UiAction::None,
            _ => typed_text(ctx).map_or(UiAction::None, |text| {
                text_action(text, UiAction::InsertSearchText)
            }),
        };
    }

    match ctx.panel {
        Panel::Audit => match key {
            "escape" => UiAction::quit_or_warn(),
            // The audit rows are navigated with the same up/down intent as the
            // vault list; `BitwardenApp::move_selection` routes it by panel.
            "up" => UiAction::MoveSelection(-1),
            "down" => UiAction::MoveSelection(1),
            "enter" => UiAction::focus_selected_audit_row(),
            "g" => UiAction::SetPanel(Panel::Vault),
            "l" => UiAction::Lock,
            _ => UiAction::None,
        },
        Panel::Generator => {
            if ctx.editing_settings {
                return UiAction::None;
            }
            match key {
                "escape" => UiAction::quit_or_warn(),
                "n" => UiAction::SetPanel(Panel::Vault),
                "l" => UiAction::Lock,
                "p" => UiAction::GeneratePassword,
                "h" => UiAction::GeneratePassphrase,
                "y" => UiAction::CopyPassword,
                "Y" => UiAction::CopyPassphrase,
                "1" => UiAction::Generator(GeneratorOption::Lowercase),
                "2" => UiAction::Generator(GeneratorOption::Uppercase),
                "3" => UiAction::Generator(GeneratorOption::Digits),
                "4" => UiAction::Generator(GeneratorOption::Symbols),
                "5" => UiAction::Generator(GeneratorOption::AvoidAmbiguous),
                "6" => UiAction::Generator(GeneratorOption::Capitalize),
                "7" => UiAction::Generator(GeneratorOption::IncludeNumber),
                "+" | "=" => UiAction::Generator(GeneratorOption::LengthUp),
                "-" | "_" => UiAction::Generator(GeneratorOption::LengthDown),
                "," => UiAction::Generator(GeneratorOption::Separator),
                // Options are in-memory edits too: `w` persists them through
                // the same `save_settings` path the settings panel uses.
                "w" => UiAction::SaveSettings,
                "d" => UiAction::DiscardSettings,
                _ => UiAction::None,
            }
        }
        Panel::Settings => {
            if ctx.editing_settings {
                // Input-only mode: even `w`, `c` and `l` are literal text so a
                // URL or email can contain them. Saving is an explicit action
                // available only after Enter/Escape confirms the field.
                return match key {
                    "escape" | "enter" => UiAction::FinishSettingsEdit,
                    "backspace" => UiAction::BackspaceSettings,
                    // Same contract as auth/search editing: native caret
                    // movement, no vault-list navigation while typing.
                    _ if is_text_cursor_key(key) => UiAction::None,
                    _ => typed_text(ctx).map_or(UiAction::None, |text| {
                        text_action(text, UiAction::InsertSettingsText)
                    }),
                };
            }
            match key {
                "escape" => UiAction::quit_or_warn(),
                "c" => UiAction::SetPanel(Panel::Vault),
                "l" => UiAction::Lock,
                "d" => UiAction::DiscardSettings,
                "1" => UiAction::EditSettingsField(SettingsField::ServerUrl),
                "2" => UiAction::EditSettingsField(SettingsField::Email),
                "+" | "=" => UiAction::AdjustThreshold(1),
                "-" | "_" => UiAction::AdjustThreshold(-1),
                "i" => UiAction::AdjustIdleLock(1),
                "u" => UiAction::AdjustIdleLock(-1),
                "3" => UiAction::AdjustLoginTimeout(1),
                "4" => UiAction::AdjustLoginTimeout(-1),
                "5" => UiAction::AdjustClipboardRestore(1),
                "6" => UiAction::AdjustClipboardRestore(-1),
                "w" => UiAction::SaveSettings,
                _ => UiAction::None,
            }
        }
        Panel::Vault => match key {
            "escape" => UiAction::quit_or_warn(),
            "up" => UiAction::MoveSelection(-1),
            "down" => UiAction::MoveSelection(1),
            "l" => UiAction::Lock,
            "t" => UiAction::CycleFilter,
            "s" => UiAction::CycleSort,
            "f" => UiAction::ToggleFavorite,
            "y" => UiAction::CopyTotp,
            "p" => UiAction::CopySelectedPassword,
            "u" => UiAction::CopySelectedUsername,
            "g" if ctx.has_audit_report => UiAction::OpenAudit,
            "n" => UiAction::SetPanel(Panel::Generator),
            "c" => UiAction::SetPanel(Panel::Settings),
            "/" => UiAction::StartSearch,
            "backspace" if ctx.query_nonempty => UiAction::BackspaceQuery,
            _ => UiAction::None,
        },
    }
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cursor_key_tests {
    use super::*;

    /// Every name accepted by `is_text_cursor_key`, including both the bare
    /// and the `arrow`-prefixed spellings plus Home/End/PageUp/PageDown.
    const CURSOR_KEYS: &[&str] = &[
        "up",
        "down",
        "left",
        "right",
        "arrowup",
        "arrowdown",
        "arrowleft",
        "arrowright",
        "home",
        "end",
        "pageup",
        "pagedown",
    ];

    #[::core::prelude::v1::test]
    fn is_text_cursor_key_covers_every_native_name() {
        for key in CURSOR_KEYS {
            assert!(is_text_cursor_key(key), "{key} must be delegated to GPUI");
        }
        for key in ["enter", "escape", "backspace", "a", "", "f1"] {
            assert!(
                !is_text_cursor_key(key),
                "{key} must not be treated as a cursor key"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn every_cursor_key_stays_unbound_in_all_editing_modes() {
        // A multi-character key must never fall through to `typed_text`, which
        // would insert e.g. "arrowup" as literal text in a credentials field.
        for key in CURSOR_KEYS {
            let mut ctx = KeyContext {
                screen: Screen::Locked,
                panel: Panel::Vault,
                key,
                key_char: None,
                modifiers: KeyModifiers::default(),
                editing_auth: true,
                searching: false,
                editing_settings: false,
                login_failed: false,
                has_audit_report: false,
                query_nonempty: false,
            };
            assert_eq!(classify_key(&ctx), UiAction::None, "auth/{key}");

            ctx.editing_auth = false;
            ctx.screen = Screen::Unlocked;
            ctx.searching = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "search/{key}");

            ctx.searching = false;
            ctx.panel = Panel::Settings;
            ctx.editing_settings = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "settings/{key}");
        }
    }
}
