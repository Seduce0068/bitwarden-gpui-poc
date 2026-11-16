//! Action helpers on the app state: clipboard, settings and generation.

use crate::settings::Settings;
use crate::totp;
use crate::ui::app::BitwardenApp;
use crate::ui::state::SettingsField;
use gpui_kit::*;

impl BitwardenApp {
    pub(super) fn copy_totp(&mut self, cx: &mut Context<Self>) {
        let secret = {
            let visible = self.visible_items();
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
            item.totp_secret().unwrap_or("").to_string()
        };
        if secret.trim().is_empty() {
            self.status = "この項目には TOTP が設定されていません".to_string();
            cx.notify();
            return;
        }
        match totp::code_at(&secret, totp::now_unix()) {
            Ok(code) => self.copy_to_clipboard(code.code(), cx),
            Err(error) => {
                self.status = error.message().to_string();
                cx.notify();
            }
        }
    }

    /// Copy `value` to the clipboard with automatic restoration.
    pub(super) fn copy_to_clipboard(&mut self, value: &str, cx: &mut Context<Self>) {
        self.clipboard.copy(value, cx);
        self.status = format!(
            "クリップボードにコピーしました（{}秒後に復元）",
            crate::ui::clipboard::CLEAR_SECONDS
        );
        cx.notify();
    }

    /// Put the clipboard back the way it was before the last copy.
    pub(super) fn restore_clipboard(&mut self, cx: &mut Context<Self>) {
        self.clipboard.restore(cx);
    }

    /// Copy editable UI state back into the persistent settings object.
    pub(super) fn sync_settings_from_ui(&mut self) {
        self.settings.server_url = self.server_url.clone();
        self.settings.email = self.email.clone();
        self.settings.password_generator = self.generator.password.clone();
        self.settings.passphrase_generator = self.generator.passphrase.clone();
    }

    pub(super) fn save_settings(&mut self, cx: &mut Context<Self>) {
        self.sync_settings_from_ui();
        match Settings::default_path() {
            Some(path) => match self.settings.save(&path) {
                Ok(()) => self.status = format!("設定を保存しました: {}", path.display()),
                Err(error) => self.status = format!("設定の保存に失敗: {error}"),
            },
            None => self.status = "設定ディレクトリを特定できません".to_string(),
        }
        cx.notify();
    }

    pub(super) fn push_editing(&mut self, character: char) {
        match self.editing {
            Some(SettingsField::ServerUrl) => self.server_url.push(character),
            Some(SettingsField::Email) => self.email.push(character),
            None => {}
        }
    }

    pub(super) fn pop_editing(&mut self) {
        match self.editing {
            Some(SettingsField::ServerUrl) => {
                self.server_url.pop();
            }
            Some(SettingsField::Email) => {
                self.email.pop();
            }
            None => {}
        }
    }

    pub(super) fn generate_password(&mut self, cx: &mut Context<Self>) {
        match self.generator.password.generate() {
            Ok(value) => {
                self.generator.last_password = Some(value);
                self.status = "パスワードを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    pub(super) fn generate_passphrase(&mut self, cx: &mut Context<Self>) {
        match self.generator.passphrase.generate() {
            Ok(value) => {
                self.generator.last_passphrase = Some(value);
                self.status = "パスフレーズを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    pub(super) fn toggle_generator(&mut self, key: &str, cx: &mut Context<Self>) {
        if crate::ui::logic::apply_generator_key(&mut self.generator, key) {
            cx.notify();
        }
    }
}
