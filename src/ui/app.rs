//! The main application state and GPUI wiring.

use crate::model::{Filter, ItemData, SortKey, Vault, VaultItem};
use crate::settings::Settings;
use crate::totp;
use crate::ui::auth_state::AuthState;
use crate::ui::state::{GeneratorState, Panel, Screen, SettingsField};
use crate::ui::totp_state::TotpState;
use crate::ui::vault_view::VaultViewState;
use gpui_kit::prelude::*;
use gpui_kit::*;

pub struct BitwardenApp {
    pub(super) screen: Screen,
    pub(super) status: String,
    pub(super) view: crate::ui::vault_view::VaultViewState,
    pub(super) totp: crate::ui::totp_state::TotpState,
    pub(super) panel: Panel,
    pub(super) generator: GeneratorState,
    pub(super) settings: Settings,
    pub(super) editing: Option<SettingsField>,
    pub(super) auth: crate::ui::auth_state::AuthState,
    pub(super) login_generation: crate::ui::login_generation::LoginGeneration,
    pub(super) clipboard: crate::ui::clipboard::ClipboardState,
    pub(super) last_activity: std::time::Instant,
    pub focus_handle: FocusHandle,
}

/// Clear every transient input mode that must not survive a screen change.
///
/// This is shared by `lock`, `unlock_mock` and `finish_login` so the same
/// reset is applied on every transition. It is a free function over the plain
/// state pieces so it can be tested without a GPUI window (this crate does not
/// enable gpui's `test-support` feature). Clipboard restoration, vault data
/// and the audit report belong to the individual transitions and are left
/// untouched here.
fn apply_state_reset(
    editing: &mut Option<SettingsField>,
    auth: &mut AuthState,
    view: &mut VaultViewState,
    generator: &mut GeneratorState,
    totp: &mut TotpState,
    last_activity: &mut std::time::Instant,
    now: std::time::Instant,
) {
    *editing = None;
    // clear_secrets() also drops the active auth field and the failure flag,
    // and wipes the client secret / master password buffers.
    auth.clear_secrets();
    *generator = GeneratorState::default();
    totp.clear();
    view.query.clear();
    view.filter = Filter::All;
    view.sort = SortKey::NameAsc;
    view.searching = false;
    view.deselect_and_rewind();
    // Both lock and unlock count as activity: an idle lock must not fire
    // immediately after a successful transition.
    *last_activity = now;
}

impl BitwardenApp {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let path = Settings::default_path();
        let loaded = path
            .as_ref()
            .map(Settings::load_detailed)
            .unwrap_or(Err(crate::settings::SettingsLoadError::ReadFailed));
        let load_notice = match &loaded {
            Err(crate::settings::SettingsLoadError::NotFound) => None,
            Err(error) => Some(error.message()),
            Ok(_) => None,
        };
        let settings = loaded.unwrap_or_default();
        let mut this = Self {
            screen: Screen::Locked,
            status: load_notice
                .map(|notice| format!("{notice} / Enter: ログイン / m: モック / Esc: 終了"))
                .unwrap_or_else(|| "ロック中: Enter: ログイン / m: モック / Esc: 終了".to_string()),
            view: crate::ui::vault_view::VaultViewState::new(),
            totp: crate::ui::totp_state::TotpState::new(),
            panel: Panel::Vault,
            generator: GeneratorState::default(),
            settings,
            editing: None,
            auth: crate::ui::auth_state::AuthState::new(),
            login_generation: crate::ui::login_generation::LoginGeneration::default(),
            clipboard: crate::ui::clipboard::ClipboardState::new(),
            last_activity: std::time::Instant::now(),
            focus_handle: cx.focus_handle(),
        };
        this.install_focus_recovery(cx);
        this.start_totp_ticker(cx);
        this
    }

    /// Install a global keystroke observer that re-acquires this view's focus
    /// handle after focus has left it (for example via Tab).
    ///
    /// The root element owns the `on_key_down` listener (see `render.rs`), so
    /// when focus moves to another element the normal key path no longer sees
    /// key presses. A keystroke observer fires regardless of which element is
    /// focused. It watches only `FOCUS_RECOVERY_KEY`, which `classify_key`
    /// maps to `KeyAction::None` in every screen and editing mode, so key
    /// classification and editing behaviour are left completely untouched.
    pub(super) fn install_focus_recovery(&mut self, cx: &mut Context<Self>) {
        cx.observe_keystrokes(|view: &mut Self, event, window, cx| {
            if !crate::ui::input::is_focus_recovery_key(&event.keystroke.key) {
                return;
            }
            // A focused descendant already bubbles keys to the root's handler;
            // only reclaim focus when it is outside this view.
            if view.focus_handle.contains_focused(window, cx) {
                return;
            }
            view.focus_handle.focus(window, cx);
            // Regaining focus is user activity, just like `key_down`.
            view.last_activity = std::time::Instant::now();
        })
        .detach();
    }

    /// Invalidate the cached TOTP snapshot once a second so the countdown
    /// advances. The task ends when the view is dropped.
    ///
    /// The loop waits on absolute deadlines rather than `Timer::after(1s)`,
    /// so processing time does not accumulate into every subsequent tick.
    /// If a tick overruns its slot, the next deadline is recomputed from the
    /// current time instead of replaying missed ticks (catch-up limit).
    pub(super) fn start_totp_ticker(&mut self, cx: &mut Context<Self>) {
        cx.spawn(
            |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    let interval = std::time::Duration::from_secs(1);
                    let mut deadline = std::time::Instant::now()
                        .checked_add(interval)
                        .unwrap_or_else(std::time::Instant::now);
                    loop {
                        smol::Timer::at(deadline).await;
                        let alive = cx.update(|cx| {
                            this.update(cx, |view, cx| {
                                let instant = std::time::Instant::now();
                                let unlocked = view.screen == Screen::Unlocked;
                                let effects = crate::ui::timing::evaluate_tick(
                                    view.clipboard.due(instant),
                                    unlocked
                                        && crate::ui::timing::idle_lock_due(
                                            view.last_activity,
                                            instant,
                                            std::time::Duration::from_secs(
                                                view.settings.idle_lock_seconds,
                                            ),
                                        ),
                                    unlocked
                                        && view.panel == Panel::Vault
                                        && view.totp.has_secret(),
                                );
                                for effect in effects {
                                    match effect {
                                        crate::ui::timing::TickEffect::RestoreClipboard => {
                                            view.restore_clipboard(cx);
                                            cx.notify();
                                        }
                                        crate::ui::timing::TickEffect::InvalidateTotp => {
                                            view.totp.invalidate();
                                            cx.notify();
                                        }
                                        crate::ui::timing::TickEffect::AutoLock => {
                                            view.lock(cx);
                                            view.status = format!(
                                                "無操作のため自動ロックしました（{}秒）",
                                                view.settings.idle_lock_seconds
                                            );
                                        }
                                    }
                                }
                            })
                            .is_ok()
                        });
                        if !alive {
                            break;
                        }
                        deadline = crate::ui::timing::next_tick_deadline(
                            deadline,
                            std::time::Instant::now(),
                            interval,
                        );
                    }
                }
            },
        )
        .detach();
    }

    /// The current view, computed by the library exactly as the tests see it.
    pub(super) fn visible_items(&self) -> Vec<&VaultItem> {
        self.view
            .vault
            .view(&self.view.filter, &self.view.query, self.view.sort)
    }

    /// Apply the input-mode reset shared by all lock/unlock transitions.
    ///
    /// Also stamps `last_activity`; the caller keeps ownership of the vault,
    /// audit report, clipboard, screen, panel and status message.
    pub(super) fn reset_input_state(&mut self) {
        apply_state_reset(
            &mut self.editing,
            &mut self.auth,
            &mut self.view,
            &mut self.generator,
            &mut self.totp,
            &mut self.last_activity,
            std::time::Instant::now(),
        );
    }

    /// Lock the vault: discard the data and clear every transient input mode.
    pub(super) fn lock(&mut self, cx: &mut Context<Self>) {
        // A login finishing after this point must not unlock the vault again.
        self.login_generation.invalidate();
        if let Some(previous) = self.clipboard.take_restore() {
            cx.write_to_clipboard(ClipboardItem::new_string(previous));
        }
        self.reset_input_state();
        self.view.vault = Vault::new();
        self.view.audit_report = None;
        self.panel = Panel::Vault;
        self.screen = Screen::Locked;
        self.status = "ロックしました（Enter: ログイン / m: モック）".to_string();
        cx.notify();
    }

    /// Switch panels through one path so no input mode survives the change.
    ///
    /// Leaving a settings field, auth field or search active would swallow
    /// every key in the destination panel ("dead keys").
    pub(super) fn set_panel(&mut self, panel: Panel, cx: &mut Context<Self>) {
        self.editing = None;
        self.auth.take_field();
        self.view.finish_search();
        self.panel = crate::ui::logic::effective_panel(panel, self.view.audit_report.is_some());
        cx.notify();
    }

    pub(super) fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        let visible = self.visible_items();
        if visible.is_empty() {
            return;
        }
        let current = self
            .view
            .selected_id
            .as_deref()
            .and_then(|id| visible.iter().position(|item| item.id == id))
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
        let id = visible[next].id.clone();
        if self.view.selected_id.as_deref() != Some(id.as_str()) {
            self.view.selected_id = Some(id);
            self.view
                .scroll_handle
                .scroll_to_item(next, ScrollStrategy::Nearest);
            cx.notify();
        }
    }

    pub(super) fn cycle_filter(&mut self, cx: &mut Context<Self>) {
        self.view.cycle_filter();
        cx.notify();
    }

    pub(super) fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self
            .view
            .selected_id
            .clone()
            .or_else(|| self.visible_items().first().map(|item| item.id.clone()))
        else {
            return;
        };
        if let Some(favorite) = self.view.vault.toggle_favorite(&id) {
            self.status = format!(
                "お気に入りを{}にしました",
                if favorite { "設定" } else { "解除" }
            );
            // Under the Favorites filter the item may have just left the view.
            self.view.revalidate_selection();
            cx.notify();
        }
    }

    /// The current TOTP code for `secret`, cached within its validity period.
    pub(super) fn totp_text(&mut self, secret: &str) -> String {
        self.totp.display(secret, totp::now_unix())
    }

    pub(super) fn selected_detail(&mut self) -> String {
        let Some((base, data)) = (|| {
            let visible = self.visible_items();
            let item = self
                .view
                .selected_id
                .as_deref()
                .and_then(|id| visible.iter().find(|item| item.id == id))
                .or_else(|| visible.first())?;
            Some((
                format!(
                    "{} | {} | 更新: {}",
                    item.kind().label(),
                    item.name,
                    item.revision_date
                ),
                item.data.clone(),
            ))
        })() else {
            return "項目なし".to_string();
        };
        match data {
            ItemData::Login {
                username,
                password,
                totp: secret,
                uris,
            } => {
                let code = if secret.trim().is_empty() {
                    "なし".to_string()
                } else {
                    self.totp_text(&secret)
                };
                format!(
                    "{base} | {username} | パスワード: {}文字 | TOTP: {code} | URI: {}",
                    "*".repeat(password.chars().count()),
                    uris.first()
                        .map_or("なし".into(), |uri| { crate::model::mask_uri(&uri.uri) })
                )
            }
            ItemData::SecureNote { text } => {
                format!("{base} | メモ: {}文字", text.chars().count())
            }
            ItemData::Card(card) => format!(
                "{base} | {} | 末尾: {}",
                card.brand,
                card.number.rsplit(' ').next().unwrap_or("")
            ),
            ItemData::Identity(identity) => format!("{base} | {}", identity.email),
            ItemData::SshKey(key) => format!("{base} | {}", key.fingerprint),
        }
    }

    /// Recompute the health report with the current thresholds.
    pub(super) fn refresh_audit(&mut self) {
        self.view.audit_report = Some(crate::ui::logic::compute_audit(
            &self.view.vault,
            self.settings.thresholds,
            i64::try_from(totp::now_unix()).unwrap_or(i64::MAX),
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::health::Report;
    use crate::ui::clipboard::ClipboardState;
    use crate::ui::state::AuthField;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    struct DirtyState {
        editing: Option<SettingsField>,
        auth: AuthState,
        view: VaultViewState,
        generator: GeneratorState,
        totp: TotpState,
        last_activity: Instant,
    }

    /// Every input mode left active by a lock screen, settings panel or
    /// vault search before a transition.
    fn dirty_state(now: Instant) -> DirtyState {
        let mut auth = AuthState::new();
        auth.set_field(Some(AuthField::MasterPassword));
        auth.push_text("secret");
        auth.set_login_failed(true);

        let mut view = VaultViewState::new();
        view.start_search();
        view.push_query("term");
        view.filter = Filter::Folder("folder".into());
        view.sort = SortKey::NameDesc;
        view.selected_id = Some("item".into());

        let generator = GeneratorState {
            last_password: Some(Zeroizing::new("generated".into())),
            last_passphrase: Some(Zeroizing::new("generated passphrase".into())),
        };

        let mut totp = TotpState::new();
        let _ = totp.display(TOTP_SECRET, 40);
        assert!(totp.has_secret());

        DirtyState {
            editing: Some(SettingsField::Email),
            auth,
            view,
            generator,
            totp,
            last_activity: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
        }
    }

    fn reset(state: &mut DirtyState, now: Instant) {
        apply_state_reset(
            &mut state.editing,
            &mut state.auth,
            &mut state.view,
            &mut state.generator,
            &mut state.totp,
            &mut state.last_activity,
            now,
        );
    }

    #[::core::prelude::v1::test]
    fn state_reset_clears_every_transient_input_mode() {
        let now = Instant::now();
        let mut state = dirty_state(now);
        assert!(state.auth.field().is_some());
        assert!(state.auth.login_failed());

        reset(&mut state, now);

        assert_eq!(state.editing, None);
        assert_eq!(state.auth.field(), None);
        assert!(!state.auth.login_failed());
        assert!(state.auth.client_secret().is_empty());
        assert!(state.auth.master_password().is_empty());
        assert_eq!(state.view.query, "");
        assert_eq!(state.view.filter, Filter::All);
        assert_eq!(state.view.sort, SortKey::NameAsc);
        assert!(!state.view.searching);
        assert_eq!(state.view.selected_id, None);
        assert!(state.generator.last_password.is_none());
        assert!(state.generator.last_passphrase.is_none());
        assert!(!state.totp.has_secret());
        assert_eq!(state.last_activity, now);
    }

    #[::core::prelude::v1::test]
    fn state_reset_rewinds_scroll_like_every_other_deselection_path() {
        let now = Instant::now();
        let mut state = dirty_state(now);
        state
            .view
            .scroll_handle
            .scroll_to_item(7, ScrollStrategy::Nearest);

        reset(&mut state, now);

        assert_eq!(state.view.selected_id, None);
        let request = state.view.scroll_handle.0.borrow().deferred_scroll_to_item;
        assert_eq!(
            request.map(|request| (request.item_index, request.strategy)),
            Some((0, ScrollStrategy::Top)),
            "the lock/unlock reset must land on the same visible range as \
             filter, search and revalidation paths"
        );
    }

    #[::core::prelude::v1::test]
    fn state_reset_leaves_transition_owned_state_alone() {
        let now = Instant::now();
        let mut state = dirty_state(now);
        state.view.audit_report = Some(Report {
            items: Vec::new(),
            examined: 3,
            with_totp: 1,
            logins: 2,
        });
        let mut clipboard = ClipboardState::new();
        clipboard.begin_copy(Some("original".into()), now, 30);

        reset(&mut state, now);

        assert_eq!(
            state
                .view
                .audit_report
                .as_ref()
                .map(|report| report.examined),
            Some(3),
            "the unlock path recomputes the audit report after the reset"
        );
        assert!(
            clipboard.is_pending(),
            "clipboard restore must survive the reset"
        );
        assert_eq!(clipboard.take_restore(), Some("original".into()));
    }

    #[::core::prelude::v1::test]
    fn state_reset_is_idempotent() {
        let now = Instant::now();
        let mut state = dirty_state(now);
        reset(&mut state, now);
        reset(&mut state, now);

        assert_eq!(state.editing, None);
        assert_eq!(state.auth.field(), None);
        assert!(!state.view.searching);
        assert!(state.generator.last_password.is_none());
        assert!(!state.totp.has_secret());
        assert_eq!(state.last_activity, now);
    }
}
