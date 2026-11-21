//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`crate::ui::keys`] module; this file
//! only applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::keys::{classify_key, KeyContext, KeyModifiers, UiAction};
use crate::ui::state::Panel;
use gpui_kit::*;

/// The dedicated key that re-acquires the view's focus handle after focus has
/// moved elsewhere (for example via Tab).
///
/// `F1` is chosen deliberately: [`crate::ui::keys::classify_key`] maps it to
/// [`UiAction::None`] on every screen and in every editing mode, and the
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
            panel: crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some()),
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
    pub(super) fn apply_action(&mut self, action: UiAction, cx: &mut Context<Self>) {
        self.last_activity = std::time::Instant::now();
        match action {
            UiAction::Quit => cx.quit(),
            UiAction::Authenticate | UiAction::RetryLogin => self.unlock_with_auth(cx),
            UiAction::OpenDemoVault => self.unlock_mock(cx),
            UiAction::EditAuthField(field) => {
                // Changing credentials invalidates any in-flight attempt.
                self.login_generation.invalidate();
                self.auth.set_field(Some(field));
                cx.notify();
            }
            UiAction::EditSettingsField(field) => {
                self.editing = Some(field);
                cx.notify();
            }
            UiAction::FinishAuthEdit => {
                self.login_generation.invalidate();
                self.auth.take_field();
                cx.notify();
            }
            UiAction::FinishSearch => {
                self.view.finish_search();
                cx.notify();
            }
            UiAction::FinishSettingsEdit => {
                self.editing = None;
                // Enter/Escape only confirm the field; point at the explicit
                // save/discard keys so the edit is not mistaken for a save.
                self.status = "入力を確定しました（w: 保存 / d: 破棄）".to_string();
                cx.notify();
            }
            UiAction::InsertAuthText(text) => {
                self.login_generation.invalidate();
                self.edit_auth_field(&text);
                cx.notify();
            }
            UiAction::InsertSearchText(text) => {
                self.view.push_query(&text);
                cx.notify();
            }
            UiAction::InsertSettingsText(text) => {
                self.push_editing(&text);
                cx.notify();
            }
            UiAction::BackspaceAuth => {
                self.login_generation.invalidate();
                self.backspace_auth_field();
                cx.notify();
            }
            UiAction::BackspaceSearch => {
                self.view.pop_query();
                cx.notify();
            }
            UiAction::BackspaceSettings => {
                self.pop_editing();
                cx.notify();
            }
            UiAction::BackspaceQuery => {
                self.view.pop_query();
                cx.notify();
            }
            UiAction::SetPanel(panel) => self.set_panel(panel, cx),
            UiAction::Lock => self.lock(cx),
            UiAction::MoveSelection(delta) => self.move_selection(delta, cx),
            UiAction::ToggleFavorite => self.toggle_favorite(cx),
            UiAction::OpenAudit => self.set_panel(Panel::Audit, cx),
            UiAction::GeneratePassword => self.generate_password(cx),
            UiAction::GeneratePassphrase => self.generate_passphrase(cx),
            UiAction::CopyPassword => {
                if let Some(value) = self.generator.last_password.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = crate::ui::logic::no_generated_status("パスワード");
                    cx.notify();
                }
            }
            UiAction::CopyPassphrase => {
                if let Some(value) = self.generator.last_passphrase.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = crate::ui::logic::no_generated_status("パスフレーズ");
                    cx.notify();
                }
            }
            UiAction::CopyTotp => self.copy_totp(cx),
            UiAction::CopySelectedPassword => self.copy_selected_field(true, cx),
            UiAction::CopySelectedUsername => self.copy_selected_field(false, cx),
            UiAction::CycleFilter => self.cycle_filter(cx),
            UiAction::CycleSort => {
                self.view.sort = self.view.sort.next();
                self.view.deselect_and_rewind();
                self.sync_totp_to_selection();
                cx.notify();
            }
            UiAction::StartSearch => {
                self.view.searching = true;
                self.view.query.clear();
                self.view.deselect_and_rewind();
                self.sync_totp_to_selection();
                cx.notify();
            }
            UiAction::SaveSettings => self.save_settings(cx),
            UiAction::DiscardSettings => self.discard_settings(cx),
            UiAction::FocusAuditItem(id) => self.focus_audit_item(&id, cx),
            UiAction::AdjustThreshold(delta) => {
                self.settings.thresholds =
                    crate::ui::logic::adjust_thresholds(self.settings.thresholds, delta);
                self.mark_settings_dirty();
                self.refresh_audit();
                cx.notify();
            }
            UiAction::AdjustIdleLock(delta) => {
                self.settings.idle_lock_seconds =
                    crate::ui::logic::adjust_idle_lock(self.settings.idle_lock_seconds, delta);
                self.mark_settings_dirty();
                cx.notify();
            }
            UiAction::AdjustLoginTimeout(delta) => {
                self.settings.login_timeout_seconds =
                    crate::ui::logic::adjust_seconds(self.settings.login_timeout_seconds, delta);
                self.mark_settings_dirty();
                cx.notify();
            }
            UiAction::AdjustClipboardRestore(delta) => {
                self.settings.clipboard_restore_seconds = crate::ui::logic::adjust_seconds(
                    self.settings.clipboard_restore_seconds,
                    delta,
                );
                self.mark_settings_dirty();
                cx.notify();
            }
            UiAction::Generator(option) => self.toggle_generator(option, cx),
            UiAction::SelectRow(index) => {
                // A mouse click is an explicit selection: leaving search mode
                // here keeps the row click and the keyboard path consistent.
                if self.view.searching {
                    self.view.finish_search();
                }
                if self.view.select_index(index) {
                    self.view
                        .scroll_handle
                        .scroll_to_item(index, gpui_kit::ScrollStrategy::Nearest);
                }
                self.sync_totp_to_selection();
                cx.notify();
            }
            UiAction::None => {}
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
                UiAction::None,
                "the recovery key must stay inert in {ctx:?}"
            );
        }

        // A stray `key_char` must not turn F1 into inserted text either.
        let mut with_char = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        with_char.key_char = Some("\u{f1}");
        assert_eq!(classify_key(&with_char), UiAction::None);

        // Sanity check: the helper only fires for the dedicated key, and a
        // normal command key stays classified as before.
        assert!(!is_focus_recovery_key("l"));
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "l")),
            UiAction::Lock
        );
    }
}
