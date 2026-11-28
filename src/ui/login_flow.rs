//! Authentication flow helpers on the app state.

use crate::auth::{clamp_auth_config, validate_config, AuthConfig, AuthError, UnlockError};
use crate::ui::app::BitwardenApp;
use crate::ui::mock::mock_vault;
use crate::ui::state::{AuthField, Panel, Screen};
use gpui_kit::*;

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
    /// A network/authentication failure. Only the transient variants advertise
    /// `r`; a blocked URL, a rejected KDF or a cache-permission failure names
    /// the setting to fix instead.
    Auth(AuthError),
    /// An unlock/import failure after a successful login: the same
    /// credentials will fail again, so the user is asked to correct them.
    Unlock(UnlockError),
}

/// Whether pressing `r` can clear an authentication failure.
///
/// Prelogin, login and sync are network/protocol steps that can recover on a
/// second run against the same configuration, and a timeout is transient by
/// definition. Every other variant is decided by a setting (server URL, KDF
/// policy, email, cache file permissions) or by a missing field, so a retry
/// reproduces it verbatim. Kept pure so both sides are testable.
fn auth_error_is_retryable(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::Prelogin
            | AuthError::PreloginDetail(_)
            | AuthError::Login
            | AuthError::LoginDetail(_)
            | AuthError::Sync
            | AuthError::SyncDetail(_)
            | AuthError::Timeout
    )
}

/// The knob a permanent authentication failure asks the user to correct.
///
/// Mirrors [`auth_error_is_retryable`] so every non-retryable variant names a
/// concrete fix instead of an ineffective `r`. All retryable variants are
/// listed here too (with a generic fallback) to keep the match exhaustive: a
/// future reclassification then has to update the hint as well.
fn auth_error_fix_hint(error: &AuthError) -> &'static str {
    match error {
        AuthError::InvalidServerUrl
        | AuthError::InvalidServerUrlDetail(_)
        | AuthError::BlockedServerUrl
        | AuthError::ClientSetup
        | AuthError::ClientSetupDetail(_) => "server_url を確認してください",
        AuthError::KdfRejected | AuthError::KdfRejectedDetail(_) => "KDF 設定を確認してください",
        AuthError::OtherDetail(_) => "キャッシュの権限を確認してください",
        AuthError::InvalidEmail => "メールアドレスを確認してください",
        AuthError::MissingField(_) => "認証情報を確認してください",
        // A generic failure names no knob: ask for a settings review rather
        // than promising a retry that may not help. The retryable arms below
        // are unreachable from `status()` but keep this helper exhaustive.
        AuthError::Other(_)
        | AuthError::Prelogin
        | AuthError::PreloginDetail(_)
        | AuthError::Login
        | AuthError::LoginDetail(_)
        | AuthError::Sync
        | AuthError::SyncDetail(_)
        | AuthError::Timeout => "設定を確認してください",
    }
}

impl LoginFailure {
    /// Status-bar guidance. "r で再試行" is shown only for retryable failures.
    fn status(&self) -> String {
        match self {
            Self::Auth(error) => {
                let detail = error.status_message();
                if auth_error_is_retryable(error) {
                    format!("ログイン失敗: {detail}（r で再試行）")
                } else {
                    format!("ログイン失敗: {detail}（{}）", auth_error_fix_hint(error))
                }
            }
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

/// Concrete guidance for a device-id preparation failure.
///
/// Both possible causes are local and permanent: no random source, or a
/// settings file that cannot be read/written. Pressing `r` reruns the same
/// operation against the same machine and cannot fix either, so the status
/// names the knob to correct instead of promising a retry.
pub(super) const DEVICE_ID_FIX_HINT: &str = "設定ファイルの権限と保存先を確認してください";

/// Status for a device-id preparation failure, keeping the underlying detail.
pub(super) fn device_id_failure_status(error: &str) -> String {
    format!("デバイス ID を準備できませんでした（{error}）（{DEVICE_ID_FIX_HINT}）")
}

impl BitwardenApp {
    pub(super) fn auth_config(&self) -> AuthConfig {
        // `AuthConfig::from_credentials` wraps the two secrets in the lib
        // layer, so this module never needs to name `openwarden`'s
        // `SecretString` (see ADR 2026-11-16). The remaining clamp call keeps
        // the previous input-normalization behaviour verbatim.
        let mut config = AuthConfig::from_credentials(
            &self.settings.server_url,
            self.auth.client_id(),
            self.auth.client_secret(),
            &self.settings.email,
            self.auth.master_password(),
        );
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
        // The single helper invalidates the generation and clears the start
        // timestamp/token together, so no exit below can leave a stale
        // countdown behind.
        self.cancel_login();
        // Clear the previous attempt's failure marker before validation: a
        // validation error must not leave the stale "login failed" UI state on.
        self.auth.set_login_failed(false);
        let config = self.auth_config();
        if let Err(error) = validate_config(&config) {
            // `status_message` names the offending field, so "which credential
            // is missing" is visible instead of a generic message.
            self.status =
                crate::ui::app::status_with_unsaved(&error.status_message(), self.settings_dirty);
            cx.notify();
            return;
        }
        let generation = self.login_generation.begin();
        // The start status stays deliberately number-free: no timeout or
        // elapsed/remaining figure is shown until the existing 1s ticker turns
        // this Instant into "ログイン中…（残り N 秒）".
        self.login_started_at = Some(std::time::Instant::now());
        // Pair the timestamp with the generation this attempt owns: the 1s
        // ticker uses this token to tell a live countdown from a cancelled one.
        self.login_started_generation = Some(generation);
        self.status = crate::ui::app::status_with_unsaved(
            crate::ui::app::LOGIN_IN_PROGRESS_STATUS,
            self.settings_dirty,
        );
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
                // The attempt never reached the network: stop its countdown
                // and consume the token as on any other failure.
                self.cancel_login();
                self.status = crate::ui::app::status_with_unsaved(
                    &device_id_failure_status(&error.to_string()),
                    self.settings_dirty,
                );
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
        // Consume the token so a duplicate callback cannot apply twice, and
        // clear the paired start timestamp so the ticker stops refreshing its
        // countdown over the success/failure status written below.
        self.cancel_login();
        let (vault, from_cache) = match result {
            LoginResult::Vault { vault, from_cache } => (vault, from_cache),
            LoginResult::AuthFailed(error) => {
                self.auth.set_login_failed(true);
                self.status = crate::ui::app::status_with_unsaved(
                    &LoginFailure::Auth(error).status(),
                    self.settings_dirty,
                );
                cx.notify();
                return;
            }
            LoginResult::UnlockFailed(error) => {
                self.auth.set_login_failed(true);
                self.status = crate::ui::app::status_with_unsaved(
                    &LoginFailure::Unlock(error).status(),
                    self.settings_dirty,
                );
                cx.notify();
                return;
            }
        };
        let status = crate::ui::app::status_with_unsaved(
            &crate::ui::logic::login_success_status(vault.len(), from_cache),
            self.settings_dirty,
        );
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
        // A pending real login must not overwrite the demo vault, and its
        // countdown must stop with it.
        self.cancel_login();
        let vault = mock_vault();
        let status = crate::ui::app::status_with_unsaved(
            &format!(
                "{} 件。↑↓選択 / f お気に入り / t フィルタ / s 並び順 / / 検索 / y TOTPコピー / g 監査 / n 生成 / c 設定 / l ロック / Esc 終了",
                vault.len()
            ),
            self.settings_dirty,
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
    fn auth_error_retryable_classification_covers_both_sides() {
        // Transient network/protocol steps plus the timeout are retryable.
        for error in [
            AuthError::Prelogin,
            AuthError::PreloginDetail("detail".into()),
            AuthError::Login,
            AuthError::LoginDetail("detail".into()),
            AuthError::Sync,
            AuthError::SyncDetail("detail".into()),
            AuthError::Timeout,
        ] {
            assert!(auth_error_is_retryable(&error), "{error:?}");
        }
        // Everything decided by a setting, a missing field or the cache file
        // is permanent and must not advertise `r`.
        for error in [
            AuthError::MissingField("server_url"),
            AuthError::InvalidServerUrl,
            AuthError::InvalidServerUrlDetail("detail".into()),
            AuthError::BlockedServerUrl,
            AuthError::InvalidEmail,
            AuthError::ClientSetup,
            AuthError::ClientSetupDetail("detail".into()),
            AuthError::KdfRejected,
            AuthError::KdfRejectedDetail("detail".into()),
            AuthError::Other("generic"),
            AuthError::OtherDetail("mode 0644、期待 0600".into()),
        ] {
            assert!(!auth_error_is_retryable(&error), "{error:?}");
        }
    }

    #[::core::prelude::v1::test]
    fn permanent_auth_failures_name_the_setting_instead_of_the_retry_key() {
        for (error, hint) in [
            (AuthError::BlockedServerUrl, "server_url を確認してください"),
            (
                AuthError::InvalidServerUrlDetail("bad url".into()),
                "server_url を確認してください",
            ),
            (AuthError::KdfRejected, "KDF 設定を確認してください"),
            (
                AuthError::KdfRejectedDetail("detail".into()),
                "KDF 設定を確認してください",
            ),
            (
                AuthError::OtherDetail("mode 0644、期待 0600".into()),
                "キャッシュの権限を確認してください",
            ),
        ] {
            let status = LoginFailure::Auth(error).status();
            assert!(!status.contains("r で再試行"), "{status}");
            assert!(status.contains(hint), "{status}");
            assert!(status.contains("ログイン失敗:"), "{status}");
        }
    }

    #[::core::prelude::v1::test]
    fn retryable_auth_failures_keep_the_retry_key_guidance() {
        for error in [
            AuthError::PreloginDetail("detail".into()),
            AuthError::LoginDetail("detail".into()),
            AuthError::SyncDetail("detail".into()),
            AuthError::Timeout,
        ] {
            let status = LoginFailure::Auth(error).status();
            assert!(status.contains("r で再試行"), "{status}");
            assert!(!status.contains("を確認してください"), "{status}");
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
    fn device_id_failure_names_the_fix_instead_of_the_retry_key() {
        let status = device_id_failure_status("保存先を読み込めません");
        assert!(
            status.contains("デバイス ID を準備できませんでした"),
            "{status}"
        );
        assert!(status.contains("保存先を読み込めません"), "{status}");
        assert!(status.contains(DEVICE_ID_FIX_HINT), "{status}");
        // Retrying cannot make the settings file writable or the RNG appear.
        assert!(!status.contains("r で再試行"), "{status}");
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

    #[::core::prelude::v1::test]
    fn login_status_keeps_the_unsaved_marker_after_a_relock_cycle() {
        let base = crate::ui::logic::login_success_status(3, false);
        let clean = crate::ui::app::status_with_unsaved(&base, false);
        let dirty = crate::ui::app::status_with_unsaved(&base, true);
        assert_eq!(clean, base);
        assert!(dirty.starts_with(&base));
        assert!(dirty.contains("[未保存の設定変更があります]"));
    }
}
