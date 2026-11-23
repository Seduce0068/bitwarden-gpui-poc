//! Pure key classification and generator key handling, free of GPUI types.

use std::borrow::Cow;

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

    /// Whether the modifiers are exactly the macOS AltGr equivalent.
    ///
    /// macOS reports AltGr as Ctrl+Alt, with the layout glyph in `key_char`.
    /// Any additional command-like modifier (Cmd/Windows or Fn) keeps the
    /// combination reserved for the platform, so it is not AltGr.
    pub(super) fn is_ctrl_alt(self) -> bool {
        self.control && self.alt && !self.platform && !self.function
    }
}

/// Which end of a selectable list a `Home`/`End` key targets.
///
/// Kept as a typed payload so the edge jump is a distinct `UiAction` instead of
/// an extreme `MoveSelection` delta: the shared move path interprets a missing
/// selection by the *sign* of a delta, so `End` cannot simply use `isize::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectionEdge {
    First,
    Last,
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
    /// Move by a whole page (`PageUp`/`PageDown`), not by a single row.
    MoveSelectionPage(isize),
    /// Jump to the first or last selectable row (`Home`/`End`).
    MoveSelectionToEdge(SelectionEdge),
    SelectRow(usize),
    ToggleFavorite,
    OpenAudit,
    /// `g` was pressed in the vault panel while no report exists yet.
    ///
    /// The mouse audit tab resolves the same case locally in `ui::render`;
    /// this intent lets the keyboard path emit the identical status through
    /// `ui::input` instead of silently doing nothing.
    AuditUnavailable,
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

/// Single-character text produced by a keystroke, if any.
///
/// `key_char` is preferred because it carries IME-composed and layout-specific
/// characters; `key` is only the ASCII/physical equivalent. A glyph is accepted
/// **only when it is exactly one character**: some backends echo a key name
/// such as `F1` into `key_char`, and inserting that multi-character string into
/// a focused field was a real bug. Genuine multi-character compositions are
/// handled separately by [`composed_text`], so they are not lost.
///
/// When no glyph is reported, a single-character physical `key` (or the `space`
/// key name) is the fallback — this is what lets Alt+<letter> insert text with
/// `key_char: None`, and it is what the Alt guard in `classify_key` tests.
fn typed_text<'a>(ctx: &KeyContext<'a>) -> Option<&'a str> {
    if let Some(text) = ctx.key_char {
        let count = text.chars().count();
        if count == 1 {
            return Some(text);
        }
        // An empty `key_char` carries no glyph, so the physical key still
        // applies. A multi-character glyph is either a composition (handled by
        // `composed_text`) or an echoed key name; never fall back to the
        // physical key in that case, or `s` would shadow "日本語".
        if count > 1 {
            return None;
        }
    }
    if ctx.key == "space" {
        return Some(" ");
    }
    (ctx.key.chars().count() == 1).then_some(ctx.key)
}

/// Whether a key name denotes a control/function key that never carries text.
///
/// Function keys are the motivating case: F1 can be reported with
/// `key = "f1"` and `key_char = "F1"`. Control and navigation names are kept in
/// the same set so a backend echoing any of them cannot insert a key name into
/// a text field. `space` is deliberately absent: it is a printable key.
fn is_non_text_key_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let bare = lower.strip_prefix("arrow").unwrap_or(&lower);
    if is_text_cursor_key(&lower) {
        return true;
    }
    if bare
        .strip_prefix('f')
        .is_some_and(|number| (1..=24).contains(&number.parse::<u8>().unwrap_or(0)))
    {
        return true;
    }
    matches!(
        bare,
        "escape"
            | "esc"
            | "enter"
            | "return"
            | "backspace"
            | "tab"
            | "delete"
            | "del"
            | "insert"
            | "ins"
            | "clear"
            | "pause"
            | "print"
            | "capslock"
            | "shift"
            | "control"
            | "alt"
            | "platform"
            | "function"
    )
}

/// Multi-character committed text, if any (IME compositions and Alt fallback).
///
/// Kept separate from [`typed_text`] so that a multi-character `key_char` which
/// merely echoes a key name (for example `"F1"`) is never inserted while
/// editing, while a genuine composition such as `"日本語"` still is — including
/// the existing Alt + multi-character fallback contract.
fn composed_text<'a>(ctx: &KeyContext<'a>) -> Option<&'a str> {
    let text = ctx.key_char?;
    if text.chars().count() <= 1 || is_non_text_key_name(ctx.key) || is_non_text_key_name(text) {
        return None;
    }
    Some(text)
}

/// Any text a focused field should receive, from one glyph or a composition.
///
/// The editing modes and the Alt guard share this helper so they cannot
/// disagree about what counts as insertable text.
fn insertable_text<'a>(ctx: &KeyContext<'a>) -> Option<&'a str> {
    // A function/control key never carries text, even if a backend echoes a
    // single character into `key_char` (`F1` -> "ñ" in some layouts).
    if is_non_text_key_name(ctx.key) || ctx.key_char.is_some_and(is_non_text_key_name) {
        return None;
    }
    typed_text(ctx).or_else(|| composed_text(ctx))
}

/// The single-character glyph a keystroke reports, before any case folding.
///
/// `key_char` carries the typed glyph (including Shift and Caps Lock results);
/// `key` is GPUI's ASCII/physical equivalent. Kept separate from
/// `command_key` because the generator's `y`/`Y` pair is deliberately
/// case-sensitive: uppercase `Y` means "copy passphrase".
fn raw_command_key<'a>(ctx: &KeyContext<'a>) -> &'a str {
    ctx.key_char
        .filter(|text| text.chars().count() == 1)
        .unwrap_or(ctx.key)
}

/// The key name to use for command matching.
///
/// On Linux GPUI lowercases `key` and keeps Shift characters in `key_char`,
/// so `Shift+Y` must be matched through `key_char` or `Y` never fires. Caps
/// Lock puts the same uppercase glyph in `key_char` for a plain letter press,
/// which would otherwise disable every lowercase binding; folding ASCII case
/// here keeps those bindings working. The one case-sensitive binding is
/// resolved from [`raw_command_key`] before this fold, so
/// `CopyPassword`/`CopyPassphrase` stay distinct.
fn command_key<'a>(ctx: &KeyContext<'a>) -> Cow<'a, str> {
    let raw = raw_command_key(ctx);
    if raw.bytes().all(|byte| !byte.is_ascii_uppercase()) {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(raw.to_ascii_lowercase())
    }
}

fn text_action(text: &str, action: fn(String) -> UiAction) -> UiAction {
    action(text.to_string())
}

/// Cursor-movement key names handled natively by the GPUI text field.
///
/// Matching them explicitly in each editing mode documents the intent and
/// guarantees `UiAction::None` even if a name becomes single-character in a
/// future GPUI version (which would otherwise make `insertable_text` insert it).
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
    let editing_text = ctx.editing_auth || ctx.searching || ctx.editing_settings;
    // macOS reports AltGr as Ctrl+Alt. In a text field the layout character in
    // `key_char` is the intended input, so give it priority over the command
    // guard. A bare Ctrl/Cmd/Fn (or Ctrl+Alt without a generated glyph) stays
    // suppressed even while editing.
    let altgr_text = ctx.modifiers.is_ctrl_alt()
        && editing_text
        && ctx.key_char.is_some_and(|text| !text.is_empty());
    if ctx.modifiers.has_command() && !altgr_text {
        return UiAction::None;
    }
    // Alt alone may still produce a printable layout character (e.g. Option+S
    // -> "ß"), but `insertable_text` also falls back to a single-character
    // physical `key` (and the `space` name) when no glyph is reported. The real
    // contract is therefore: allow Alt only while editing text and only when
    // there is insertable text — a bare one-character physical key counts even
    // with `key_char` absent, and so does a genuine multi-character IME
    // composition. Multi-character key names (F1 and friends) stay inert, and
    // in command panels every Alt+key stays inert.
    if ctx.modifiers.alt && !(editing_text && insertable_text(ctx).is_some()) {
        return UiAction::None;
    }
    let raw_key = raw_command_key(ctx);
    let command = command_key(ctx);
    let key = command.as_ref();

    if ctx.screen == Screen::Locked {
        if ctx.editing_auth {
            return match key {
                "escape" | "enter" => UiAction::FinishAuthEdit,
                "backspace" => UiAction::BackspaceAuth,
                // Arrow/Home/End stay with the GPUI text field (see
                // TEXT_EDIT_ARROW_KEYS_HINT): no new list-movement binding here.
                _ if is_text_cursor_key(key) => UiAction::None,
                // A control/function key is never text, whatever `key_char`
                // reports (including a stray single-character glyph).
                _ if is_non_text_key_name(key) => UiAction::None,
                _ => insertable_text(ctx).map_or(UiAction::None, |text| {
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
            _ if is_non_text_key_name(key) => UiAction::None,
            _ => insertable_text(ctx).map_or(UiAction::None, |text| {
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
            // Page/Home/End reuse the list-movement intent but carry their own
            // actions, so single-row Up/Down keep their existing binding and
            // `ui::input` can translate the paging into a larger move.
            "pageup" => UiAction::MoveSelectionPage(-1),
            "pagedown" => UiAction::MoveSelectionPage(1),
            "home" => UiAction::MoveSelectionToEdge(SelectionEdge::First),
            "end" => UiAction::MoveSelectionToEdge(SelectionEdge::Last),
            "enter" => UiAction::focus_selected_audit_row(),
            "g" => UiAction::SetPanel(Panel::Vault),
            "l" => UiAction::Lock,
            _ => UiAction::None,
        },
        Panel::Generator => {
            if ctx.editing_settings {
                return UiAction::None;
            }
            // The one deliberately case-sensitive binding: `Y` copies the
            // passphrase while `y` copies the password. `command_key` folds
            // ASCII case so Caps Lock cannot disable the other letter
            // commands, so settle this pair from the un-folded glyph first.
            // Both spellings stay reachable (Caps Lock inverts which physical
            // press produces `Y`).
            if raw_key == "Y" {
                return UiAction::CopyPassphrase;
            }
            match key {
                "escape" => UiAction::quit_or_warn(),
                "n" => UiAction::SetPanel(Panel::Vault),
                "l" => UiAction::Lock,
                "p" => UiAction::GeneratePassword,
                "h" => UiAction::GeneratePassphrase,
                "y" => UiAction::CopyPassword,
                // Fallback if case folding is ever removed: the raw uppercase
                // glyph above already covers it today.
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
                    _ if is_non_text_key_name(key) => UiAction::None,
                    _ => insertable_text(ctx).map_or(UiAction::None, |text| {
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
                // These keys are bound only in a settings-owning panel. The
                // report they recompute must not replace that panel's status
                // (see `audit_refresh_status_for_panel` in `ui::app`).
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
            "pageup" => UiAction::MoveSelectionPage(-1),
            "pagedown" => UiAction::MoveSelectionPage(1),
            "home" => UiAction::MoveSelectionToEdge(SelectionEdge::First),
            "end" => UiAction::MoveSelectionToEdge(SelectionEdge::Last),
            "l" => UiAction::Lock,
            "t" => UiAction::CycleFilter,
            "s" => UiAction::CycleSort,
            "f" => UiAction::ToggleFavorite,
            "y" => UiAction::CopyTotp,
            "p" => UiAction::CopySelectedPassword,
            "u" => UiAction::CopySelectedUsername,
            "g" if ctx.has_audit_report => UiAction::OpenAudit,
            // No report yet: still answer the key with the same explanation
            // the mouse audit tab gives, instead of an inert `UiAction::None`.
            "g" => UiAction::AuditUnavailable,
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
mod alt_text_tests {
    use super::*;

    fn auth_ctx<'a>(key: &'a str, key_char: Option<&'a str>, alt: bool) -> KeyContext<'a> {
        KeyContext {
            screen: Screen::Locked,
            panel: Panel::Vault,
            key,
            key_char,
            modifiers: KeyModifiers {
                alt,
                ..KeyModifiers::default()
            },
            editing_auth: true,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: false,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn alt_printable_character_is_inserted_into_the_auth_field() {
        // Option+S on a layout without `s` produces `ß` in `key_char` while
        // `key` stays the physical character. The Alt guard must let it
        // through while editing, and the auth fallback must insert the
        // composed text instead of the ASCII key.
        let ctx = auth_ctx("s", Some("ß"), true);
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertAuthText("ß".to_string())
        );

        // The same composed text without Alt follows the same insert path.
        let ctx = auth_ctx("s", Some("ß"), false);
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertAuthText("ß".to_string())
        );

        // Multi-character IME text is inserted whole while editing auth.
        let ctx = auth_ctx("unknown", Some("日本語"), true);
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertAuthText("日本語".to_string())
        );
    }

    #[::core::prelude::v1::test]
    fn alt_without_printable_text_stays_inert_in_the_auth_field() {
        // These key names produce no text, so the guard keeps them inert even
        // while an auth field is focused.
        for key in ["enter", "backspace", "up", "arrowleft"] {
            let ctx = auth_ctx(key, None, true);
            assert_eq!(classify_key(&ctx), UiAction::None, "auth/{key}");
        }
    }

    #[::core::prelude::v1::test]
    fn alt_printable_text_outside_editing_does_not_reach_the_auth_insert_path() {
        // Outside editing modes Alt stays inert even with a printable glyph,
        // so the guard never leaks into command panels.
        let mut ctx = auth_ctx("s", Some("ß"), true);
        ctx.editing_auth = false;
        assert_eq!(classify_key(&ctx), UiAction::None);

        ctx.screen = Screen::Unlocked;
        ctx.panel = Panel::Generator;
        assert_eq!(classify_key(&ctx), UiAction::None);

        ctx.panel = Panel::Settings;
        assert_eq!(classify_key(&ctx), UiAction::None);
    }

    #[::core::prelude::v1::test]
    fn ctrl_alt_layout_glyph_is_inserted_in_every_editing_mode() {
        // macOS AltGr arrives as Ctrl+Alt with the composed glyph in
        // `key_char`; it must reach the same insert path as plain Alt text.
        let mut ctx = auth_ctx("s", Some("ß"), false);
        ctx.modifiers = KeyModifiers {
            control: true,
            alt: true,
            ..KeyModifiers::default()
        };
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertAuthText("ß".into()),
            "auth"
        );

        ctx.screen = Screen::Unlocked;
        ctx.editing_auth = false;
        ctx.searching = true;
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertSearchText("ß".into()),
            "search"
        );

        ctx.searching = false;
        ctx.panel = Panel::Settings;
        ctx.editing_settings = true;
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertSettingsText("ß".into()),
            "settings"
        );
    }

    #[::core::prelude::v1::test]
    fn ctrl_alt_without_a_glyph_or_outside_editing_is_inert() {
        let ctrl_alt = KeyModifiers {
            control: true,
            alt: true,
            ..KeyModifiers::default()
        };
        let mut ctx = auth_ctx("l", None, false);
        ctx.modifiers = ctrl_alt;
        assert_eq!(
            classify_key(&ctx),
            UiAction::None,
            "without key_char the physical key must not be inserted"
        );

        ctx.key_char = Some("ß");
        ctx.editing_auth = false;
        assert_eq!(classify_key(&ctx), UiAction::None, "outside editing");

        ctx.editing_auth = true;
        for extra in [
            KeyModifiers {
                platform: true,
                ..ctrl_alt
            },
            KeyModifiers {
                function: true,
                ..ctrl_alt
            },
        ] {
            ctx.modifiers = extra;
            assert_eq!(classify_key(&ctx), UiAction::None, "{extra:?}");
        }
    }
}

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
        // A multi-character key must never fall through to `insertable_text`,
        // which would insert e.g. "arrowup" as literal text in a field.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod page_navigation_key_tests {
    use super::*;

    fn panel_ctx(panel: Panel, key: &str) -> KeyContext<'_> {
        KeyContext {
            screen: Screen::Unlocked,
            panel,
            key,
            key_char: None,
            modifiers: KeyModifiers::default(),
            editing_auth: false,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: true,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn vault_and_audit_own_page_home_and_end_keys() {
        for panel in [Panel::Vault, Panel::Audit] {
            for (key, expected) in [
                ("pageup", UiAction::MoveSelectionPage(-1)),
                ("pagedown", UiAction::MoveSelectionPage(1)),
                ("home", UiAction::MoveSelectionToEdge(SelectionEdge::First)),
                ("end", UiAction::MoveSelectionToEdge(SelectionEdge::Last)),
            ] {
                assert_eq!(
                    classify_key(&panel_ctx(panel, key)),
                    expected,
                    "{panel:?}/{key}"
                );
            }
        }
    }

    #[::core::prelude::v1::test]
    fn paging_does_not_replace_single_row_or_leak_to_other_panels() {
        for panel in [Panel::Vault, Panel::Audit] {
            assert_eq!(
                classify_key(&panel_ctx(panel, "up")),
                UiAction::MoveSelection(-1),
                "{panel:?}/up"
            );
            assert_eq!(
                classify_key(&panel_ctx(panel, "down")),
                UiAction::MoveSelection(1),
                "{panel:?}/down"
            );
        }
        // Only the two list-owning panels get a scroll handle; generator and
        // settings must keep these keys inert (see MOUSE_WHEEL_SCROLL_ONLY_HINT).
        for panel in [Panel::Generator, Panel::Settings] {
            for key in ["pageup", "pagedown", "home", "end"] {
                assert_eq!(
                    classify_key(&panel_ctx(panel, key)),
                    UiAction::None,
                    "{panel:?}/{key}"
                );
            }
        }
    }

    #[::core::prelude::v1::test]
    fn paging_keys_stay_unbound_in_every_editing_mode() {
        for key in ["pageup", "pagedown", "home", "end"] {
            let mut ctx = panel_ctx(Panel::Vault, key);
            ctx.searching = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "search/{key}");

            ctx.searching = false;
            ctx.panel = Panel::Settings;
            ctx.editing_settings = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "settings/{key}");

            ctx.editing_settings = false;
            ctx.screen = Screen::Locked;
            ctx.editing_auth = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "auth/{key}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod single_character_text_tests {
    use super::*;

    fn editing_ctx<'a>(key: &'a str, key_char: Option<&'a str>) -> KeyContext<'a> {
        KeyContext {
            screen: Screen::Locked,
            panel: Panel::Vault,
            key,
            key_char,
            modifiers: KeyModifiers::default(),
            editing_auth: true,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: false,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn typed_text_accepts_only_a_single_character_glyph() {
        let ctx = editing_ctx("s", Some("ß"));
        assert_eq!(typed_text(&ctx), Some("ß"));

        // A multi-character `key_char` is never a single glyph: neither an
        // echoed function-key name nor a genuine IME commit.
        assert_eq!(typed_text(&editing_ctx("f1", Some("F1"))), None);
        assert_eq!(typed_text(&editing_ctx("unknown", Some("日本語"))), None);

        // The physical-key and `space` fallbacks are unchanged.
        assert_eq!(typed_text(&editing_ctx("x", None)), Some("x"));
        assert_eq!(typed_text(&editing_ctx("space", None)), Some(" "));
        assert_eq!(typed_text(&editing_ctx("x", Some(""))), Some("x"));
    }

    #[::core::prelude::v1::test]
    fn non_text_key_names_cover_function_and_control_keys() {
        for name in [
            "f1",
            "F1",
            "f2",
            "F12",
            "f24",
            "escape",
            "Enter",
            "backspace",
            "pageup",
            "arrowleft",
        ] {
            assert!(is_non_text_key_name(name), "{name} must carry no text");
        }
        for name in ["space", "a", "unknown", "日本語"] {
            assert!(
                !is_non_text_key_name(name),
                "{name} must not be treated as a control key"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn composed_text_keeps_ime_and_alt_text_but_rejects_key_names() {
        for key in ["unknown", "s"] {
            let ctx = editing_ctx(key, Some("日本語"));
            assert_eq!(composed_text(&ctx), Some("日本語"), "key={key}");
            assert_eq!(insertable_text(&ctx), Some("日本語"), "key={key}");
        }
        for (key, key_char) in [
            ("f1", Some("F1")),
            ("F1", Some("F1")),
            ("f12", Some("f12")),
            ("unknown", Some("F1")),
            ("f1", None),
        ] {
            let ctx = editing_ctx(key, key_char);
            assert_eq!(composed_text(&ctx), None, "{key}/{key_char:?}");
            assert_eq!(insertable_text(&ctx), None, "{key}/{key_char:?}");
        }
    }

    #[::core::prelude::v1::test]
    fn function_keys_are_inert_in_every_editing_mode() {
        for (key, key_char) in [
            ("f1", Some("F1")),
            ("f1", Some("f1")),
            ("f1", None),
            ("F1", Some("F1")),
            ("f12", Some("F12")),
            // Even a stray single-character glyph on a function key stays inert.
            ("f1", Some("\u{f1}")),
        ] {
            let mut ctx = editing_ctx(key, key_char);
            assert_eq!(classify_key(&ctx), UiAction::None, "auth/{key}");

            ctx.editing_auth = false;
            ctx.screen = Screen::Unlocked;
            ctx.searching = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "search/{key}");

            ctx.searching = false;
            ctx.panel = Panel::Settings;
            ctx.editing_settings = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "settings/{key}");

            // Alt must not revive a function key through the text fallback.
            ctx.modifiers.alt = true;
            assert_eq!(classify_key(&ctx), UiAction::None, "settings/alt/{key}");
        }
    }

    #[::core::prelude::v1::test]
    fn alt_multi_character_text_still_reaches_every_editing_mode() {
        let mut ctx = editing_ctx("unknown", Some("日本語"));
        ctx.modifiers.alt = true;
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertAuthText("日本語".into())
        );

        ctx.editing_auth = false;
        ctx.screen = Screen::Unlocked;
        ctx.searching = true;
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertSearchText("日本語".into())
        );

        ctx.searching = false;
        ctx.panel = Panel::Settings;
        ctx.editing_settings = true;
        assert_eq!(
            classify_key(&ctx),
            UiAction::InsertSettingsText("日本語".into())
        );
    }
}
