//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`crate::ui::keys`] module; this file
//! only applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::keys::{classify_key, KeyAction, KeyContext, KeyModifiers};
use crate::ui::state::Panel;
use gpui_kit::*;

/// The dedicated key that re-acquires the view's focus handle after focus has
/// moved elsewhere (for example via Tab).
///
/// `F1` is chosen deliberately: [`crate::ui::keys::classify_key`] maps it to
/// [`KeyAction::None`] on every screen and in every editing mode, and the
/// default keymaps do not bind it. The global observer that watches this key
/// therefore cannot change normal key classification or editing behaviour.
pub(super) const FOCUS_RECOVERY_KEY: &str = "f1";

/// Whether `key` is the dedicated focus-recovery key.
///
/// Kept as a pure helper so the invariant that this key is inert in the normal
/// key classification can be exercised without a GPUI window.
pub(super) fn is_focus_recovery_key(key: &str) -> bool {
    key == FOCUS_RECOVERY_KEY
}

impl BitwardenApp {
    pub(super) fn key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.last_activity = std::time::Instant::now();
        let ctx = KeyContext {
            screen: self.screen,
            panel: self.panel,
            key: &event.keystroke.key,
            key_char: event.keystroke.key_char.as_deref(),
            modifiers: KeyModifiers {
                control: event.keystroke.modifiers.control,
                platform: event.keystroke.modifiers.platform,
                alt: event.keystroke.modifiers.alt,
                function: event.keystroke.modifiers.function,
            },
            editing_auth: self.auth.field().is_some(),
            searching: self.view.searching,
            editing_settings: self.editing.is_some(),
            login_failed: self.auth.login_failed(),
            has_audit_report: self.view.audit_report.is_some(),
            query_nonempty: !self.view.query.is_empty(),
        };
        self.apply_action(classify_key(&ctx), cx);
    }

    /// Apply a UI action to the app state. Both keyboard and mouse input go
    /// through this single path so state transitions stay consistent.
    pub(super) fn apply_action(&mut self, action: KeyAction, cx: &mut Context<Self>) {
        self.last_activity = std::time::Instant::now();
        match action {
            KeyAction::Quit => cx.quit(),
            KeyAction::Authenticate | KeyAction::RetryLogin => self.unlock_with_auth(cx),
            KeyAction::OpenDemoVault => self.unlock_mock(cx),
            KeyAction::EditAuthField(field) => {
                // Changing credentials invalidates any in-flight attempt.
                self.login_generation.invalidate();
                self.auth.set_field(Some(field));
                cx.notify();
            }
            KeyAction::EditSettingsField(field) => {
                self.editing = Some(field);
                cx.notify();
            }
            KeyAction::FinishAuthEdit => {
                self.login_generation.invalidate();
                self.auth.take_field();
                cx.notify();
            }
            KeyAction::FinishSearch => {
                self.view.finish_search();
                cx.notify();
            }
            KeyAction::FinishSettingsEdit => {
                self.editing = None;
                cx.notify();
            }
            KeyAction::InsertAuthText(text) => {
                self.login_generation.invalidate();
                self.edit_auth_field(&text);
                cx.notify();
            }
            KeyAction::InsertSearchText(text) => {
                self.view.push_query(&text);
                cx.notify();
            }
            KeyAction::InsertSettingsText(text) => {
                self.push_editing(&text);
                cx.notify();
            }
            KeyAction::BackspaceAuth => {
                self.login_generation.invalidate();
                self.backspace_auth_field();
                cx.notify();
            }
            KeyAction::BackspaceSearch => {
                self.view.pop_query();
                cx.notify();
            }
            KeyAction::BackspaceSettings => {
                self.pop_editing();
                cx.notify();
            }
            KeyAction::BackspaceQuery => {
                self.view.pop_query();
                cx.notify();
            }
            KeyAction::SetPanel(panel) => self.set_panel(panel, cx),
            KeyAction::Lock => self.lock(cx),
            KeyAction::MoveSelection(delta) => self.move_selection(delta, cx),
            KeyAction::ToggleFavorite => self.toggle_favorite(cx),
            KeyAction::OpenAudit => self.set_panel(Panel::Audit, cx),
            KeyAction::GeneratePassword => self.generate_password(cx),
            KeyAction::GeneratePassphrase => self.generate_passphrase(cx),
            KeyAction::CopyPassword => {
                if let Some(value) = self.generator.last_password.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = crate::ui::logic::no_generated_status("パスワード");
                    cx.notify();
                }
            }
            KeyAction::CopyPassphrase => {
                if let Some(value) = self.generator.last_passphrase.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = crate::ui::logic::no_generated_status("パスフレーズ");
                    cx.notify();
                }
            }
            KeyAction::CopyTotp => self.copy_totp(cx),
            KeyAction::CopySelectedPassword => self.copy_selected_field(true, cx),
            KeyAction::CopySelectedUsername => self.copy_selected_field(false, cx),
            KeyAction::CycleFilter => self.cycle_filter(cx),
            KeyAction::CycleSort => {
                self.view.sort = self.view.sort.next();
                self.view.selected_id = None;
                cx.notify();
            }
            KeyAction::StartSearch => {
                self.view.searching = true;
                self.view.query.clear();
                self.view.selected_id = None;
                cx.notify();
            }
            KeyAction::SaveSettings => self.save_settings(cx),
            KeyAction::AdjustThreshold(delta) => {
                self.settings.thresholds =
                    crate::ui::logic::adjust_thresholds(self.settings.thresholds, delta);
                self.refresh_audit();
                cx.notify();
            }
            KeyAction::AdjustIdleLock(delta) => {
                self.settings.idle_lock_seconds =
                    crate::ui::logic::adjust_idle_lock(self.settings.idle_lock_seconds, delta);
                cx.notify();
            }
            KeyAction::ToggleLowercase => self.toggle_generator("1", cx),
            KeyAction::ToggleUppercase => self.toggle_generator("2", cx),
            KeyAction::ToggleDigits => self.toggle_generator("3", cx),
            KeyAction::ToggleSymbols => self.toggle_generator("4", cx),
            KeyAction::ToggleAmbiguous => self.toggle_generator("5", cx),
            KeyAction::ToggleCapitalize => self.toggle_generator("6", cx),
            KeyAction::ToggleNumber => self.toggle_generator("7", cx),
            KeyAction::AdjustLength(delta) => {
                self.toggle_generator(if delta > 0 { "+" } else { "-" }, cx)
            }
            KeyAction::CycleSeparator => self.toggle_generator(",", cx),
            KeyAction::SelectRow(index) => {
                if self.view.select_index(index) {
                    self.view
                        .scroll_handle
                        .scroll_to_item(index, gpui_kit::ScrollStrategy::Nearest);
                }
                cx.notify();
            }
            KeyAction::None => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    // `use gpui_kit::*` at module scope brings gpui's `test` attribute macro
    // into this module through `use super::*`. A bare `#[test]` resolves to
    // that macro instead of the built-in one and expands recursively, so
    // these tests name the built-in attribute by its absolute path.
    use super::*;
    use crate::ui::state::Screen;

    fn context(screen: Screen, panel: Panel, key: &str) -> KeyContext<'_> {
        KeyContext {
            screen,
            panel,
            key,
            key_char: None,
            modifiers: KeyModifiers::default(),
            editing_auth: false,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: false,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn focus_recovery_key_is_recognised() {
        assert!(is_focus_recovery_key(FOCUS_RECOVERY_KEY));
        assert!(is_focus_recovery_key("f1"));
        assert!(!is_focus_recovery_key("F1"));
        assert!(!is_focus_recovery_key("f2"));
        assert!(!is_focus_recovery_key(""));
    }

    #[::core::prelude::v1::test]
    fn focus_recovery_key_never_changes_normal_classification() {
        // Every screen and panel must keep mapping the dedicated recovery key
        // to `None`, so the global observer cannot trigger a UI action.
        let mut contexts = vec![
            context(Screen::Locked, Panel::Vault, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Audit, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Generator, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Settings, FOCUS_RECOVERY_KEY),
        ];
        // Editing modes (search, auth field, settings field) as well.
        let mut searching = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        searching.searching = true;
        contexts.push(searching);
        let mut editing_auth = context(Screen::Locked, Panel::Vault, FOCUS_RECOVERY_KEY);
        editing_auth.editing_auth = true;
        contexts.push(editing_auth);
        let mut editing_settings = context(Screen::Unlocked, Panel::Settings, FOCUS_RECOVERY_KEY);
        editing_settings.editing_settings = true;
        contexts.push(editing_settings);

        for ctx in &contexts {
            assert_eq!(
                classify_key(ctx),
                KeyAction::None,
                "the recovery key must stay inert in {ctx:?}"
            );
        }

        // A stray `key_char` must not turn F1 into inserted text either.
        let mut with_char = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        with_char.key_char = Some("\u{f1}");
        assert_eq!(classify_key(&with_char), KeyAction::None);

        // Sanity check: the helper only fires for the dedicated key, and a
        // normal command key stays classified as before.
        assert!(!is_focus_recovery_key("l"));
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "l")),
            KeyAction::Lock
        );
    }
}
