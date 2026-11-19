//! Action helpers on the app state: clipboard, settings and generation.

use crate::settings::Settings;
use crate::totp;
use crate::ui::app::BitwardenApp;
use crate::ui::state::SettingsField;
use gpui_kit::*;
use zeroize::Zeroizing;

impl BitwardenApp {
    pub(super) fn copy_totp(&mut self, cx: &mut Context<Self>) {
        let secret = {
            let visible = self.view.visible_items();
            let Some(item) = self
                .view
                .selected_id
                .as_deref()
                .and_then(|id| visible.iter().find(|item| item.id == id))
                .or_else(|| visible.first())
            else {
                // The fallback to `visible.first()` means this branch is
                // reached only when the visible list itself is empty.
                self.status = "一覧に項目がありません（フィルタ／検索を確認）".to_string();
                cx.notify();
                return;
            };
            item.totp_secret().unwrap_or("").to_string()
        };
        // Do not classify an empty secret here: code_at already maps it to
        // TotpError::Missing. Letting the actual error decide keeps the status
        // derived from TotpError::message() in every failure path.
        match totp::code_at(&secret, totp::now_unix()) {
            Ok(code) => self.copy_to_clipboard(code.code(), cx),
            Err(error) => {
                self.status = error.message().to_string();
                cx.notify();
            }
        }
    }

    /// Copy the selected login's password (`true`) or username (`false`).
    pub(super) fn copy_selected_field(&mut self, password: bool, cx: &mut Context<Self>) {
        let value = {
            let visible = self.view.visible_items();
            let Some(item) = self
                .view
                .selected_id
                .as_deref()
                .and_then(|id| visible.iter().find(|item| item.id == id))
                .or_else(|| visible.first())
            else {
                self.status = "項目が選択されていません".to_string();
                cx.notify();
                return;
            };
            crate::ui::logic::select_copy_value(&item.data, password)
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
    pub(super) fn restore_clipboard(&mut self, cx: &mut Context<Self>) {
        if let Some(previous) = self.clipboard.take_restore() {
            cx.write_to_clipboard(ClipboardItem::new_string(previous));
            self.status = "クリップボードを復元しました".to_string();
            cx.notify();
        }
    }

    pub(super) fn save_settings(&mut self, cx: &mut Context<Self>) {
        self.settings = self.settings.sanitized();
        match Settings::default_path() {
            Some(path) => match self.settings.save(&path) {
                Ok(()) => self.status = format!("設定を保存しました: {}", path.display()),
                Err(error) => self.status = format!("設定の保存に失敗: {error}"),
            },
            None => self.status = "設定ディレクトリを特定できません".to_string(),
        }
        cx.notify();
    }

    pub(super) fn push_editing(&mut self, text: &str) {
        match self.editing {
            Some(SettingsField::ServerUrl) => self.settings.server_url.push_str(text),
            Some(SettingsField::Email) => self.settings.email.push_str(text),
            None => {}
        }
    }

    pub(super) fn pop_editing(&mut self) {
        match self.editing {
            Some(SettingsField::ServerUrl) => {
                self.settings.server_url.pop();
            }
            Some(SettingsField::Email) => {
                self.settings.email.pop();
            }
            None => {}
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

    pub(super) fn toggle_generator(&mut self, key: &str, cx: &mut Context<Self>) {
        if crate::ui::keys::apply_generator_key(&mut self.settings, key) {
            cx.notify();
        }
    }
}
