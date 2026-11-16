//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`logic`] module; this file only
//! applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::logic::{classify_key, KeyAction, KeyContext};
use crate::ui::model::Panel;
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
            searching: self.searching,
            editing_settings: self.editing.is_some(),
            login_failed: self.auth.login_failed(),
            has_audit_report: self.audit_report.is_some(),
            query_nonempty: !self.query.is_empty(),
        };
        match classify_key(&ctx) {
            KeyAction::Quit => cx.quit(),
            KeyAction::Authenticate | KeyAction::RetryLogin => self.unlock_with_auth(cx),
            KeyAction::EditAuthField(field) => {
                self.auth.set_field(Some(field));
                cx.notify();
            }
            KeyAction::EditSettingsField(field) => {
                self.editing = Some(field);
                cx.notify();
            }
            KeyAction::FinishEdit => {
                if self.auth.take_field().is_some() {
                    // Lock-screen credentials are already stored in the
                    // fields; no extra sync is needed.
                } else if self.searching {
                    self.searching = false;
                } else if self.editing.take().is_some() {
                    self.sync_settings_from_ui();
                }
                cx.notify();
            }
            KeyAction::InsertChar(character) => {
                if self.auth.field().is_some() {
                    self.edit_auth_field(character);
                } else if self.searching {
                    self.query.push(character);
                    self.selected_id = None;
                } else if self.editing.is_some() {
                    self.push_editing(character);
                }
                cx.notify();
            }
            KeyAction::Backspace => {
                if self.auth.field().is_some() {
                    self.backspace_auth_field();
                } else if self.searching {
                    self.query.pop();
                    self.selected_id = None;
                } else if self.editing.is_some() {
                    self.pop_editing();
                } else if !self.query.is_empty() {
                    self.query.pop();
                    self.selected_id = None;
                }
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
                self.sort = self.sort.next();
                self.selected_id = None;
                cx.notify();
            }
            KeyAction::StartSearch => {
                self.searching = true;
                self.query.clear();
                self.selected_id = None;
                cx.notify();
            }
            KeyAction::SaveSettings => self.save_settings(cx),
            KeyAction::AdjustThreshold(delta) => {
                let step = delta * 5;
                let day_step = delta * 30;
                let thresholds = &mut self.settings.thresholds;
                thresholds.weak_bits = if step > 0 {
                    thresholds.weak_bits.saturating_add(step as u32).min(200)
                } else {
                    thresholds
                        .weak_bits
                        .saturating_sub(step.unsigned_abs())
                        .min(200)
                };
                thresholds.stale_days = if day_step > 0 {
                    thresholds
                        .stale_days
                        .saturating_add(day_step as i64)
                        .min(3650)
                } else {
                    thresholds
                        .stale_days
                        .saturating_sub(day_step.unsigned_abs() as i64)
                        .max(1)
                };
                self.refresh_audit();
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
            KeyAction::None => {}
        }
    }
}
