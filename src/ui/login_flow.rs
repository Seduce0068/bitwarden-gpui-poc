//! Authentication flow helpers on the app state.

use crate::auth::{clamp_auth_config, validate_config, AuthConfig, AuthError, UnlockError};
use crate::ui::app::BitwardenApp;
use crate::ui::mock::mock_vault;
use crate::ui::state::{AuthField, Panel, Screen};
use gpui_kit::*;
use openwarden::SecretString;

/// Outcome of the whole login pipeline, ready to apply on the UI thread.
pub(super) enum LoginResult {
    /// A decrypted vault ready for display, tagged with its offline-cache origin.
    Vault {
        vault: crate::model::Vault,
        from_cache: bool,
    },
    /// The network login failed.
    AuthFailed(AuthError),
    /// Unlock/import of the authenticated vault failed.
    UnlockFailed(UnlockError),
}

/// A failed login attempt, tagged by the family that decides the guidance.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LoginFailure {
    /// A network/authentication failure: `r` re-runs the pipeline and may
    /// recover from a transient problem.
    Auth(AuthError),
    /// An unlock/import failure after a successful login: the same
    /// credentials will fail again, so the user is asked to correct them.
    Unlock(UnlockError),
}

impl LoginFailure {
    /// Status-bar guidance. "r で再試行" is shown only for retryable failures.
    fn status(&self) -> String {
        match self {
            Self::Auth(error) => format!("ログイン失敗: {}（r で再試行）", error.status_message()),
            // A wrong master password/protected key will fail again with the
            // same input, so ask for corrected credentials and do not advertise
            // `r`. Every other unlock-family failure is about the vault data or
            // a transient step, so point there instead and keep `r` available.
            Self::Unlock(error) => match error {
                UnlockError::UnlockFailed(_) | UnlockError::UnlockFailedCause(_, _) => format!(
                    "ログイン失敗: {}（認証情報を確認してください）",
                    error.message()
                ),
                _ => format!(
                    "ログイン失敗: {}（vault の状態を確認し、必要なら r で再試行）",
                    error.message()
                ),
            },
        }
    }
}

impl BitwardenApp {
    pub(super) fn auth_config(&self) -> AuthConfig {
        let mut config = AuthConfig {
            server_url: self.settings.server_url.clone(),
            client_id: self.auth.client_id().to_string(),
            client_secret: SecretString::from(self.auth.client_secret().to_string()),
            email: self.settings.email.clone(),
            master_password: SecretString::from(self.auth.master_password().to_string()),
        };
        // Clamp before validating. `authenticate_with_timeout` clamps its own
        // private copy as a backstop, but callers must not see a length-only
        // validation failure for a value that would immediately be clamped
        // into a valid one. Stored and effective values now agree.
        clamp_auth_config(&mut config);
        config
    }

    /// Validate credentials and start a real network login.
    ///
    /// The demo vault is opened only through the explicit `OpenDemoVault`
    /// action, so `Enter` always means a real login attempt.
    pub(super) fn unlock_with_auth(&mut self, cx: &mut Context<Self>) {
        // Any new attempt cancels an in-flight one, even when validation fails.
        self.login_generation.invalidate();
        // Clear the previous attempt's failure marker before validation: a
        // validation error must not leave the stale "login failed" UI state on.
        self.auth.set_login_failed(false);
        let config = self.auth_config();
        if let Err(error) = validate_config(&config) {
            // `status_message` names the offending field, so "which credential
            // is missing" is visible instead of a generic message.
            self.status = error.status_message();
            cx.notify();
            return;
        }
        let generation = self.login_generation.begin();
        self.status = "ログイン中…".to_string();
        cx.notify();
        // The initial login and the resync/retry path (the `r` key maps to
        // this same method) both resolve the identifier here, so every
        // attempt sends the same persisted value. A fresh UUID is generated
        // and saved only on first use.
        let device_id = match self
            .settings
            .ensure_device_id(crate::settings::Settings::default_path().as_deref())
        {
            Ok(id) => id.to_string(),
            Err(error) => {
                self.auth.set_login_failed(true);
                self.status =
                    format!("デバイス ID を準備できませんでした（{error}）（r で再試行）");
                cx.notify();
                return;
            }
        };
        let timeout = std::time::Duration::from_secs(self.settings.login_timeout_seconds);
        cx.spawn(
            move |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    // Only the network phase needs the credential copies. Drop
                    // them as soon as it ends so a superseded or still-running
                    // task does not keep secrets alive through the (potentially
                    // long) unlock/import phase or after the user locks. The
                    // known limitation is unchanged: retrying does not cancel
                    // the previous task, so its copies now have a shorter life.
                    let auth_result =
                        crate::auth::authenticate_with_timeout(&config, &device_id, timeout).await;
                    drop(config);
                    let result = match auth_result {
                        Ok(authenticated) => {
                            // Keep the cache-origin flag before the vault is
                            // consumed by the import step, so the UI can warn
                            // that the data may be stale.
                            let from_cache = authenticated.from_cache;
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
                                Ok(vault) => LoginResult::Vault { vault, from_cache },
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
        let (vault, from_cache) = match result {
            LoginResult::Vault { vault, from_cache } => (vault, from_cache),
            LoginResult::AuthFailed(error) => {
                self.auth.set_login_failed(true);
                self.status = LoginFailure::Auth(error).status();
                cx.notify();
                return;
            }
            LoginResult::UnlockFailed(error) => {
                self.auth.set_login_failed(true);
                self.status = LoginFailure::Unlock(error).status();
                cx.notify();
                return;
            }
        };
        let status = crate::ui::logic::login_success_status(vault.len(), from_cache);
        self.enter_unlocked(vault, status, cx);
    }

    /// Enter the unlocked screen with a freshly loaded vault.
    ///
    /// Both the real login and the mock path go through here, so every
    /// transition applies the same input reset as `lock`: no auth field,
    /// settings edit, search query, generated secret or stale selection
    /// survives. Audit recomputation, `last_activity` and any pending
    /// clipboard restore keep their existing behaviour.
    pub(super) fn enter_unlocked(
        &mut self,
        vault: crate::model::Vault,
        status: String,
        cx: &mut Context<Self>,
    ) {
        self.reset_input_state();
        self.view.vault = vault;
        // Recomputed from the new vault, as both unlock paths did before.
        self.refresh_audit();
        self.panel = Panel::Vault;
        self.screen = Screen::Unlocked;
        self.view
            .scroll_handle
            .scroll_to_item(0, ScrollStrategy::Top);
        self.status = status;
        cx.notify();
    }

    pub(super) fn edit_auth_field(&mut self, text: &str) {
        match self.auth.field().and_then(AuthField::shared) {
            Some(field) => {
                self.settings.push_shared_text(field, text);
                self.mark_settings_dirty();
            }
            None => self.auth.push_text(text),
        }
    }

    pub(super) fn backspace_auth_field(&mut self) {
        if let Some(field) = self.auth.field().and_then(AuthField::shared) {
            self.settings.pop_shared_char(field);
            self.mark_settings_dirty();
            return;
        }
        self.auth.pop_char();
    }

    pub(super) fn unlock_mock(&mut self, cx: &mut Context<Self>) {
        // A pending real login must not overwrite the demo vault.
        self.login_generation.invalidate();
        let vault = mock_vault();
        let status = format!(
            "{} 件。↑↓選択 / f お気に入り / t フィルタ / s 並び順 / / 検索 / y TOTPコピー / g 監査 / n 生成 / c 設定 / l ロック / Esc 終了",
            vault.len()
        );
        self.enter_unlocked(vault, status, cx);
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

    #[::core::prelude::v1::test]
    fn auth_failures_advertise_retry() {
        for error in [
            AuthError::Prelogin,
            AuthError::Login,
            AuthError::Sync,
            AuthError::Timeout,
        ] {
            let expected = error.status_message();
            let status = LoginFailure::Auth(error).status();
            assert!(status.contains("r で再試行"), "{status}");
            assert!(status.contains(&expected), "{status}");
        }
    }

    #[::core::prelude::v1::test]
    fn unlock_failures_do_not_advertise_retry() {
        // A bad password or protected key will fail identically on retry, so
        // the guidance asks for corrected credentials and never offers `r`.
        for error in [
            UnlockError::UnlockFailed("detail".into()),
            UnlockError::UnlockFailedCause(
                "detail".into(),
                crate::error::BoxedCause::text("cause"),
            ),
        ] {
            let status = LoginFailure::Unlock(error).status();
            assert!(!status.contains("r で再試行"), "{status}");
            assert!(status.contains("認証情報を確認してください"), "{status}");
        }
    }

    #[::core::prelude::v1::test]
    fn non_credential_unlock_failures_use_other_guidance() {
        for error in [
            UnlockError::MissingProtectedKey,
            UnlockError::ApplySyncFailed("detail".into()),
            UnlockError::ImportFailed("detail".into()),
        ] {
            let expected = error.message();
            let status = LoginFailure::Unlock(error).status();
            assert!(!status.contains("認証情報を確認してください"), "{status}");
            assert!(status.contains("vault の状態を確認"), "{status}");
            assert!(status.contains(&expected), "{status}");
        }
    }

    #[::core::prelude::v1::test]
    fn auth_status_names_the_missing_field() {
        let status = LoginFailure::Auth(AuthError::MissingField("client_secret")).status();
        assert!(status.contains("client_secret"), "{status}");
        assert!(status.contains("認証情報が未入力です"), "{status}");
    }

    #[::core::prelude::v1::test]
    fn auth_status_keeps_the_login_detail() {
        let status = LoginFailure::Auth(AuthError::LoginDetail("invalid_client".into())).status();
        assert!(status.contains("invalid_client"), "{status}");
        assert!(status.contains(AuthError::Login.message()), "{status}");
    }

    #[::core::prelude::v1::test]
    fn failure_guidance_differs_by_family() {
        let auth = LoginFailure::Auth(AuthError::Login).status();
        let unlock = LoginFailure::Unlock(UnlockError::MissingProtectedKey).status();
        assert_ne!(auth, unlock);
    }
}
