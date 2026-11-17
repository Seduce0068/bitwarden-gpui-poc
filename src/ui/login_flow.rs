//! Authentication flow helpers on the app state.

use crate::auth::{validate_config, AuthConfig};
use crate::ui::app::BitwardenApp;
use crate::ui::mock::mock_vault;
use crate::ui::state::{AuthField, Panel, Screen};
use gpui_kit::*;
use openwarden::SecretString;

/// Outcome of the whole login pipeline, ready to apply on the UI thread.
pub(super) enum LoginResult {
    /// A decrypted vault ready for display.
    Vault(crate::model::Vault),
    /// The network login failed.
    AuthFailed(crate::auth::AuthError),
    /// Unlock/import of the authenticated vault failed.
    UnlockFailed(crate::auth::UnlockError),
}

impl BitwardenApp {
    pub(super) fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            server_url: self.settings.server_url.clone(),
            client_id: self.auth.client_id().to_string(),
            client_secret: SecretString::from(self.auth.client_secret().to_string()),
            email: self.settings.email.clone(),
            master_password: SecretString::from(self.auth.master_password().to_string()),
        }
    }

    /// Validate credentials and start a real network login.
    ///
    /// The demo vault is opened only through the explicit `OpenDemoVault`
    /// action, so `Enter` always means a real login attempt.
    pub(super) fn unlock_with_auth(&mut self, cx: &mut Context<Self>) {
        // Any new attempt cancels an in-flight one, even when validation fails.
        self.login_generation.invalidate();
        let config = self.auth_config();
        if let Err(error) = validate_config(&config) {
            self.status = error.message().to_string();
            cx.notify();
            return;
        }
        self.auth.set_login_failed(false);
        let generation = self.login_generation.begin();
        self.status = "ログイン中…".to_string();
        cx.notify();
        // A fixed identifier is enough for the PoC; a real installation would
        // persist a UUID in Settings.
        let device_id = "bitwarden-gpui-poc-install".to_string();
        let timeout = std::time::Duration::from_secs(self.settings.login_timeout_seconds);
        cx.spawn(
            move |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    let result =
                        match crate::auth::authenticate_with_timeout(&config, &device_id, timeout)
                            .await
                        {
                            Ok(authenticated) => {
                                // Decryption and import scale with the number of items;
                                // keep them off the UI thread and the 1s ticker.
                                // The generation token discards a stale result, but
                                // a job already running on the blocking pool is not
                                // cancelled; repeated logins can overlap here.
                                match smol::unblock(move || {
                                    crate::auth::unlock_and_import(authenticated)
                                })
                                .await
                                {
                                    Ok(vault) => LoginResult::Vault(vault),
                                    Err(error) => LoginResult::UnlockFailed(error),
                                }
                            }
                            Err(error) => LoginResult::AuthFailed(error),
                        };
                    cx.update(|cx| {
                        this.update(cx, |view, cx| view.finish_login(result, generation, cx))
                            .ok();
                    });
                }
            },
        )
        .detach();
    }

    /// Apply the result of an asynchronous login on the UI thread.
    ///
    /// Results from a cancelled or superseded attempt are discarded.
    pub(super) fn finish_login(
        &mut self,
        result: LoginResult,
        generation: crate::ui::login_generation::LoginGeneration,
        cx: &mut Context<Self>,
    ) {
        if !self.login_generation.is_current(generation) {
            return;
        }
        // Consume the token so a duplicate callback cannot apply twice.
        self.login_generation.invalidate();
        let vault = match result {
            LoginResult::Vault(vault) => vault,
            LoginResult::AuthFailed(error) => {
                self.auth.set_login_failed(true);
                self.status = format!("ログイン失敗: {}（r で再試行）", error.message());
                cx.notify();
                return;
            }
            LoginResult::UnlockFailed(error) => {
                self.auth.set_login_failed(true);
                self.status = format!("ログイン失敗: {}（r で再試行）", error.message());
                cx.notify();
                return;
            }
        };
        self.view.vault = vault;
        self.refresh_audit();
        self.screen = Screen::Unlocked;
        self.panel = Panel::Vault;
        self.view.selected_id = None;
        self.status = format!(
            "ログイン成功: {} 件のログインを読み込みました",
            self.view.vault.len()
        );
        cx.notify();
    }

    pub(super) fn edit_auth_field(&mut self, text: &str) {
        match self.auth.field() {
            Some(AuthField::ServerUrl) => self.settings.server_url.push_str(text),
            Some(AuthField::Email) => self.settings.email.push_str(text),
            _ => self.auth.push_text(text),
        }
    }

    pub(super) fn backspace_auth_field(&mut self) {
        match self.auth.field() {
            Some(AuthField::ServerUrl) => {
                self.settings.server_url.pop();
            }
            Some(AuthField::Email) => {
                self.settings.email.pop();
            }
            _ => self.auth.pop_char(),
        }
    }

    pub(super) fn unlock_mock(&mut self, cx: &mut Context<Self>) {
        // A pending real login must not overwrite the demo vault.
        self.login_generation.invalidate();
        self.view.vault = mock_vault();
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
