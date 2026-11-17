//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`crate::ui::keys`] module; this file
//! only applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::keys::{classify_key, KeyAction, KeyContext};
use crate::ui::state::Panel;
use gpui_kit::*;

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
                self.sync_settings_from_ui();
                cx.notify();
            }
            KeyAction::InsertAuthChar(character) => {
                self.login_generation.invalidate();
                self.edit_auth_field(character);
                cx.notify();
            }
            KeyAction::InsertSearchChar(character) => {
                self.view.push_query(character);
                cx.notify();
            }
            KeyAction::InsertSettingsChar(character) => {
                self.push_editing(character);
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
            KeyAction::SetPanel(panel) => {
                self.panel = panel;
                cx.notify();
            }
            KeyAction::Lock => self.lock(cx),
            KeyAction::MoveSelection(delta) => self.move_selection(delta, cx),
            KeyAction::ToggleFavorite => self.toggle_favorite(cx),
            KeyAction::OpenAudit => {
                self.panel = Panel::Audit;
                cx.notify();
            }
            KeyAction::GeneratePassword => self.generate_password(cx),
            KeyAction::GeneratePassphrase => self.generate_passphrase(cx),
            KeyAction::CopyPassword => {
                if let Some(value) = self.generator.last_password.clone() {
                    self.copy_to_clipboard(&value, cx);
                }
            }
            KeyAction::CopyPassphrase => {
                if let Some(value) = self.generator.last_passphrase.clone() {
                    self.copy_to_clipboard(&value, cx);
                }
            }
            KeyAction::CopyTotp => self.copy_totp(cx),
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
