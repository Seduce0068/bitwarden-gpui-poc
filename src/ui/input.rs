//! Keyboard input handling for the app.

use crate::ui::app::BitwardenApp;
use crate::ui::model::{AuthField, Panel, Screen, SettingsField};
use gpui_kit::*;

impl BitwardenApp {
    pub(super) fn key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match self.screen {
            Screen::Locked => {
                let key = event.keystroke.key.as_str();
                if self.auth_field.is_some() {
                    match key {
                        "escape" | "enter" => {
                            self.auth_field = None;
                            cx.notify();
                        }
                        "backspace" => {
                            self.backspace_auth_field();
                            cx.notify();
                        }
                        value if value.chars().count() == 1 => {
                            if let Some(character) = value.chars().next() {
                                self.edit_auth_field(character);
                                cx.notify();
                            }
                        }
                        _ => {}
                    }
                    return;
                }
                match key {
                    "escape" => cx.quit(),
                    "enter" => self.unlock_with_auth(cx),
                    "r" if self.login_failed => self.unlock_with_auth(cx),
                    "1" => self.auth_field = Some(AuthField::ServerUrl),
                    "2" => self.auth_field = Some(AuthField::Email),
                    "3" => self.auth_field = Some(AuthField::ClientId),
                    "4" => self.auth_field = Some(AuthField::ClientSecret),
                    "5" => self.auth_field = Some(AuthField::MasterPassword),
                    _ => return,
                }
                cx.notify();
            }
            Screen::Unlocked => {
                let key = event.keystroke.key.as_str();
                if self.searching {
                    match key {
                        "escape" | "enter" => {
                            self.searching = false;
                            cx.notify();
                        }
                        "backspace" => {
                            self.query.pop();
                            self.selected = 0;
                            cx.notify();
                        }
                        value if value.chars().count() == 1 => {
                            self.query.push_str(value);
                            self.selected = 0;
                            cx.notify();
                        }
                        _ => {}
                    }
                    return;
                }
                if self.panel == Panel::Audit {
                    match key {
                        "escape" => cx.quit(),
                        "g" => {
                            self.panel = Panel::Vault;
                            cx.notify();
                        }
                        "l" => self.lock(cx),
                        _ => {}
                    }
                    return;
                }
                if self.panel == Panel::Generator {
                    match key {
                        "escape" => cx.quit(),
                        "n" => {
                            self.panel = Panel::Vault;
                            cx.notify();
                        }
                        "l" => self.lock(cx),
                        "p" => self.generate_password(cx),
                        "h" => self.generate_passphrase(cx),
                        "y" => {
                            if let Some(value) = self.generator.last_password.clone() {
                                self.copy_to_clipboard(&value, cx);
                            }
                        }
                        "Y" => {
                            if let Some(value) = self.generator.last_passphrase.clone() {
                                self.copy_to_clipboard(&value, cx);
                            }
                        }
                        value => self.toggle_generator(value, cx),
                    }
                    return;
                }
                if self.panel == Panel::Settings {
                    if self.editing.is_some() {
                        match key {
                            "escape" | "enter" => {
                                self.editing = None;
                                self.sync_settings_from_ui();
                                cx.notify();
                            }
                            "backspace" => {
                                self.pop_editing();
                                cx.notify();
                            }
                            value if value.chars().count() == 1 => {
                                if let Some(character) = value.chars().next() {
                                    self.push_editing(character);
                                    cx.notify();
                                }
                            }
                            _ => {}
                        }
                        return;
                    }
                    match key {
                        "escape" => cx.quit(),
                        "c" => {
                            self.panel = Panel::Vault;
                            cx.notify();
                        }
                        "l" => self.lock(cx),
                        "1" => {
                            self.editing = Some(SettingsField::ServerUrl);
                            cx.notify();
                        }
                        "2" => {
                            self.editing = Some(SettingsField::Email);
                            cx.notify();
                        }
                        "+" | "=" => {
                            let thresholds = &mut self.settings.thresholds;
                            thresholds.weak_bits = (thresholds.weak_bits + 5).min(200);
                            thresholds.stale_days = (thresholds.stale_days + 30).min(3650);
                            self.refresh_audit();
                            cx.notify();
                        }
                        "-" | "_" => {
                            let thresholds = &mut self.settings.thresholds;
                            thresholds.weak_bits = thresholds.weak_bits.saturating_sub(5);
                            thresholds.stale_days = thresholds.stale_days.saturating_sub(30).max(1);
                            self.refresh_audit();
                            cx.notify();
                        }
                        "w" => self.save_settings(cx),
                        _ => {}
                    }
                    return;
                }
                match key {
                    "escape" => cx.quit(),
                    "up" => self.move_selection(-1, cx),
                    "down" => self.move_selection(1, cx),
                    "l" => self.lock(cx),
                    "t" => self.cycle_filter(cx),
                    "s" => {
                        self.sort = self.sort.next();
                        self.selected = 0;
                        cx.notify();
                    }
                    "f" => self.toggle_favorite(cx),
                    "y" => self.copy_totp(cx),
                    "g" if self.audit_report.is_some() => {
                        self.panel = Panel::Audit;
                        cx.notify();
                    }
                    "n" => {
                        self.panel = Panel::Generator;
                        cx.notify();
                    }
                    "c" => {
                        self.panel = Panel::Settings;
                        cx.notify();
                    }
                    "/" => {
                        self.searching = true;
                        self.query.clear();
                        self.selected = 0;
                        cx.notify();
                    }
                    "backspace" if !self.query.is_empty() => {
                        self.query.pop();
                        self.selected = 0;
                        cx.notify();
                    }
                    _ => {}
                }
            }
        }
    }
}
