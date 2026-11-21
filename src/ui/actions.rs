//! Action helpers on the app state: clipboard, settings and generation.

use crate::settings::Settings;
use crate::totp;
use crate::ui::app::BitwardenApp;
use gpui_kit::*;
use zeroize::Zeroizing;

impl BitwardenApp {
    pub(super) fn copy_totp(&mut self, cx: &mut Context<Self>) {
        let secret = {
            let visible = self.view.visible_items();
            let Some(index) =
                crate::ui::logic::required_item_index(self.view.selected_id.as_deref(), &visible)
            else {
                self.status = crate::ui::logic::no_selection_status().to_string();
                cx.notify();
                return;
            };
            visible[index].totp_secret().unwrap_or("").to_string()
        };
        // Copy the code that is actually on screen. Generating a fresh one here
        // could disagree with the cached display across a period boundary, so
        // only refresh when the cache is empty (for example right after a
        // selection change or a ticker invalidation).
        self.sync_totp_to_selection();
        let mut displayed = self.totp.current_code().map(str::to_string);
        if displayed.is_none() && !secret.trim().is_empty() {
            let _ = self.totp_text(&secret);
            displayed = self.totp.current_code().map(str::to_string);
        }
        match displayed {
            Some(code) => self.copy_to_clipboard(&code, cx),
            None => {
                // No cached code: prefer the cached generation error, then a
                // fresh parse, so a missing/malformed secret reports its real
                // reason instead of a generic failure.
                let status = self.totp.error_message().unwrap_or_else(|| {
                    match totp::code_at(&secret, totp::now_unix()) {
                        Ok(_) => {
                            "表示中の TOTP コードがありません（一覧を表示してください）".to_string()
                        }
                        Err(error) => error.message().to_string(),
                    }
                });
                self.status = status;
                cx.notify();
            }
        }
    }

    /// Copy the selected login's password (`true`) or username (`false`).
    pub(super) fn copy_selected_field(&mut self, password: bool, cx: &mut Context<Self>) {
        let value = {
            let visible = self.view.visible_items();
            let Some(index) =
                crate::ui::logic::required_item_index(self.view.selected_id.as_deref(), &visible)
            else {
                self.status = crate::ui::logic::no_selection_status().to_string();
                cx.notify();
                return;
            };
            crate::ui::logic::select_copy_value(&visible[index].data, password)
        };
        let Some(value) = value else {
            let field = if password {
                "パスワード"
            } else {
                "ユーザー名"
            };
            self.status = crate::ui::logic::no_field_status(field);
            cx.notify();
            return;
        };
        self.copy_to_clipboard(&value, cx);
    }

    /// Copy `value` to the clipboard with automatic restoration.
    pub(super) fn copy_to_clipboard(&mut self, value: &str, cx: &mut Context<Self>) {
        let seconds = self.settings.clipboard_restore_seconds;
        let current = cx.read_from_clipboard().and_then(|item| {
            item.entries.into_iter().find_map(|entry| match entry {
                ClipboardEntry::String(text) => Some(text.text),
                _ => None,
            })
        });
        let restorable = current.is_some();
        self.clipboard
            .begin_copy(current, std::time::Instant::now(), seconds);
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        self.status = crate::ui::logic::clipboard_copy_status(seconds, restorable);
        cx.notify();
    }

    /// Put the clipboard back the way it was before the last copy.
    /// Apply a pending restore. Returns whether anything was written;
    /// notification is left to the caller so a single UI transition can
    /// notify once after its final status is set.
    pub(super) fn restore_clipboard(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(previous) = self.clipboard.take_restore() else {
            return false;
        };
        // `write_to_clipboard` returns no result, so verify the write by
        // reading the same text back and surface a mismatch in the status bar.
        let expected = previous.clone();
        cx.write_to_clipboard(ClipboardItem::new_string(previous));
        let observed = cx.read_from_clipboard().and_then(|item| {
            item.entries.into_iter().find_map(|entry| match entry {
                ClipboardEntry::String(text) => Some(text.text),
                _ => None,
            })
        });
        if observed.as_deref() == Some(expected.as_str()) {
            self.status = "クリップボードを復元しました".to_string();
        } else {
            self.status = crate::ui::logic::clipboard_restore_failure_status().to_string();
        }
        true
    }

    pub(super) fn save_settings(&mut self, cx: &mut Context<Self>) {
        self.settings = self.settings.sanitized();
        match Settings::default_path() {
            Some(path) => match self.settings.save(&path) {
                Ok(()) => {
                    self.settings_dirty = false;
                    self.status = format!("設定を保存しました: {}", path.display());
                }
                Err(error) => {
                    self.settings_dirty = true;
                    self.status = format!("設定の保存に失敗（未保存のまま）: {error}");
                }
            },
            None => {
                self.settings_dirty = true;
                self.status = "設定ディレクトリを特定できません（未保存のまま）".to_string();
            }
        }
        cx.notify();
    }

    /// Reload the persisted settings, dropping unsaved in-memory edits.
    ///
    /// Uses the same startup fallback as `BitwardenApp::new`, so first-run
    /// installs simply return to defaults without inventing a fake save.
    pub(super) fn discard_settings(&mut self, cx: &mut Context<Self>) {
        let (settings, notice) = match Settings::default_path() {
            Some(path) => match Settings::load_detailed(&path) {
                Ok(settings) => (settings, None),
                Err(error) => (
                    Settings::default(),
                    Some(format!(
                        "保存済みの設定を読み込めませんでした（{error}）。既定値へ戻しました"
                    )),
                ),
            },
            None => (Settings::default(), None),
        };
        self.settings = settings;
        self.settings_dirty = false;
        // Thresholds affect the report, so recompute it rather than leaving a
        // report produced with the discarded values on screen.
        if self.view.audit_report.is_some() {
            self.refresh_audit();
        }
        let mut notices = notice.into_iter().collect::<Vec<_>>();
        if let Some(path) = Settings::default_path() {
            notices.extend(crate::settings::load_advisories(&path));
        }
        self.status = if notices.is_empty() {
            "未保存の設定変更を破棄しました（保存済みの設定に戻しました）".to_string()
        } else {
            notices.join(" / ")
        };
        cx.notify();
    }

    pub(super) fn push_editing(&mut self, text: &str) {
        if let Some(field) = self.editing {
            self.settings.push_shared_text(field.into(), text);
            self.mark_settings_dirty();
        }
    }

    pub(super) fn pop_editing(&mut self) {
        if let Some(field) = self.editing {
            self.settings.pop_shared_char(field.into());
            self.mark_settings_dirty();
        }
    }

    pub(super) fn generate_password(&mut self, cx: &mut Context<Self>) {
        match self.settings.password_generator.generate() {
            Ok(value) => {
                self.generator.last_password = Some(Zeroizing::new(value));
                self.status = "パスワードを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    pub(super) fn generate_passphrase(&mut self, cx: &mut Context<Self>) {
        match self.settings.passphrase_generator.generate() {
            Ok(value) => {
                self.generator.last_passphrase = Some(Zeroizing::new(value));
                self.status = "パスフレーズを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    pub(super) fn toggle_generator(
        &mut self,
        option: crate::ui::keys::GeneratorOption,
        cx: &mut Context<Self>,
    ) {
        crate::ui::keys::apply_generator_key(&mut self.settings, option);
        self.mark_settings_dirty();
        self.status = "生成設定を変更しました（未保存 / w: 保存 / d: 破棄）".to_string();
        cx.notify();
    }
}
