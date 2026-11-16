//! Authentication flow helpers on the app state.

use crate::auth::{authenticate, validate_config, AuthConfig};
use crate::ui::app::BitwardenApp;
use crate::ui::mock::mock_vault;
use crate::ui::state::{AuthField, GeneratorState, Panel, Screen};
use crate::vault_sync;
use gpui_kit::*;
use openwarden::{SecretString, Vault as OpenVault};

impl BitwardenApp {
    pub(super) fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            server_url: self.server_url.clone(),
            client_id: self.auth.client_id().to_string(),
            client_secret: SecretString::from(self.auth.client_secret().to_string()),
            email: self.email.clone(),
            master_password: SecretString::from(self.auth.master_password().to_string()),
        }
    }

    /// Validate credentials and, when present, start a real network login.
    /// Without credentials the demo vault is opened instead.
    pub(super) fn unlock_with_auth(&mut self, cx: &mut Context<Self>) {
        let config = self.auth_config();
        let has_credentials = crate::ui::logic::has_credentials(
            self.auth.client_id(),
            self.auth.client_secret(),
            self.auth.master_password(),
        );
        if !has_credentials {
            self.unlock_mock(cx);
            return;
        }
        if let Err(error) = validate_config(&config) {
            self.status = error.message().to_string();
            cx.notify();
            return;
        }
        self.auth.set_login_failed(false);
        self.status = "ログイン中…".to_string();
        cx.notify();
        // A fixed identifier is enough for the PoC; a real installation would
        // persist a UUID in Settings.
        let device_id = "bitwarden-gpui-poc-install".to_string();
        cx.spawn(
            |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    let result = authenticate(&config, &device_id).await;
                    cx.update(|cx| {
                        this.update(cx, |view, cx| view.finish_login(result, cx))
                            .ok();
                    });
                }
            },
        )
        .detach();
    }

    /// Apply the result of an asynchronous login on the UI thread.
    pub(super) fn finish_login(
        &mut self,
        result: Result<crate::auth::AuthenticatedVault, crate::auth::AuthError>,
        cx: &mut Context<Self>,
    ) {
        let authenticated = match result {
            Ok(value) => value,
            Err(error) => {
                self.auth.set_login_failed(true);
                self.status = format!("ログイン失敗: {}（r で再試行）", error.message());
                cx.notify();
                return;
            }
        };
        let protected_key = authenticated
            .session
            .protected_key()
            .unwrap_or("")
            .to_string();
        if protected_key.is_empty() {
            self.auth.set_login_failed(true);
            self.status = "ログイン失敗: 復号キーが応答にありません（r で再試行）".to_string();
            cx.notify();
            return;
        }
        let kdf = authenticated.session.kdf();
        let mut open_vault = match OpenVault::unlock(&authenticated.master_key, &protected_key, kdf)
        {
            Ok(vault) => vault,
            Err(error) => {
                self.auth.set_login_failed(true);
                self.status =
                    format!("ログイン失敗: 復号キーを取得できません（{error}）（r で再試行）");
                cx.notify();
                return;
            }
        };
        if let Err(error) = open_vault.apply_sync(authenticated.sync) {
            self.auth.set_login_failed(true);
            self.status =
                format!("ログイン失敗: 同期データを取り込めません（{error}）（r で再試行）");
            cx.notify();
            return;
        }
        match vault_sync::import_logins(&open_vault) {
            Ok(vault) => {
                self.view.vault = vault;
                self.screen = Screen::Unlocked;
                self.panel = Panel::Vault;
                self.view.selected_id = None;
                self.status = format!(
                    "ログイン成功: {} 件のログインを読み込みました",
                    self.view.vault.len()
                );
            }
            Err(error) => {
                self.auth.set_login_failed(true);
                self.status = format!("vault 変換失敗: {}（r で再試行）", error.message());
            }
        }
        cx.notify();
    }

    pub(super) fn edit_auth_field(&mut self, character: char) {
        match self.auth.field() {
            Some(AuthField::ServerUrl) => self.server_url.push(character),
            Some(AuthField::Email) => self.email.push(character),
            _ => self.auth.push_char(character),
        }
    }

    pub(super) fn backspace_auth_field(&mut self) {
        match self.auth.field() {
            Some(AuthField::ServerUrl) => {
                self.server_url.pop();
            }
            Some(AuthField::Email) => {
                self.email.pop();
            }
            _ => self.auth.pop_char(),
        }
    }

    pub(super) fn unlock_mock(&mut self, cx: &mut Context<Self>) {
        self.view.vault = mock_vault();
        self.generator = GeneratorState::from_settings(&self.settings);
        self.refresh_audit();
        self.panel = Panel::Vault;
        self.screen = Screen::Unlocked;
        self.view.selected_id = None;
        self.view
            .scroll_handle
            .scroll_to_item(0, ScrollStrategy::Top);
        self.status = format!(
            "{} 件。↑↓選択 / f お気に入り / t フィルタ / s 並び順 / / 検索 / y TOTPコピー / g 監査 / n 生成 / c 設定 / l ロック / Esc 終了",
            self.view.vault.len()
        );
        cx.notify();
    }
}
