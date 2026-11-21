//! The main application state and GPUI wiring.

use crate::model::{Filter, ItemData, SortKey, Vault};
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
    /// In-memory setting edits that have not been persisted yet.
    ///
    /// Leaving the settings panel, locking or quitting never saves silently;
    /// the flag keeps that visible until `w` saves or `d` discards.
    pub(super) settings_dirty: bool,
    /// Highlighted audit row, as an index into `Report::items`.
    ///
    /// Kept on the app rather than the (out-of-scope) panel renderer so the
    /// keyboard path can remember the row between keystrokes.
    pub(super) audit_row_selection: Option<usize>,
    /// Scroll handle for the audit panel, kept so keyboard row selection can
    /// bring the highlighted row into view.
    pub(super) audit_scroll_handle: ScrollHandle,
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

/// Status shown when leaving a settings-owning panel with unsaved edits.
///
/// The destination panel (vault list or audit) has no `w`/`d` binding, so the
/// guidance explicitly points back to the panels where those keys work.
pub(super) fn unsaved_panel_exit_status() -> &'static str {
    "未保存の設定変更があります（設定/生成パネルに戻り w: 保存 / d: 破棄）"
}

/// Marker appended to transient statuses and to the list detail line.
///
/// Keeping it in one place makes the unsaved state visible outside the
/// settings panels without depending on GPUI's rendering internals.
pub(super) fn unsaved_status_suffix(dirty: bool) -> &'static str {
    if dirty {
        " | [未保存の設定変更があります]"
    } else {
        ""
    }
}

/// Compose a status message with the persistent unsaved marker.
pub(super) fn status_with_unsaved(base: &str, dirty: bool) -> String {
    format!("{base}{}", unsaved_status_suffix(dirty))
}

/// Warning shown when Esc is pressed while settings are still unsaved.
pub(super) fn unsaved_quit_warning_status() -> &'static str {
    "警告: 未保存の設定変更があります（設定/生成パネルに戻り w: 保存 / d: 破棄）"
}

/// Pure gate for the Esc warning: `Some` keeps the user in the app, `None`
/// allows the existing Quit action to run.
pub(super) fn quit_gate_warning(dirty: bool) -> Option<&'static str> {
    dirty.then_some(unsaved_quit_warning_status())
}

/// Clamp a relative audit-row move into a report of `len` rows.
///
/// With no selection, Down starts at the first row and Up at the last one;
/// an empty report has no valid row. Out-of-range moves clamp instead of
/// wrapping so a long key repeat cannot jump unexpectedly.
pub(super) fn next_audit_row(current: Option<usize>, delta: isize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let last = len - 1;
    let Some(index) = current else {
        return Some(if delta < 0 { last } else { 0 });
    };
    let next = (index.min(last) as isize).saturating_add(delta);
    if next < 0 {
        Some(0)
    } else if next > last as isize {
        Some(last)
    } else {
        // `next` is now within 0..=last, which is at most `usize::MAX`.
        Some(next as usize)
    }
}

impl BitwardenApp {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let path = Settings::default_path();
        // No platform config directory is a supported first-run case, not a
        // failed read; fall back to defaults without a misleading notice.
        let loaded = match path.as_ref() {
            Some(path) => Settings::load_detailed(path),
            None => Ok(Settings::default()),
        };
        let mut notices: Vec<String> = Vec::new();
        match &loaded {
            Err(crate::settings::SettingsLoadError::NotFound) => {}
            Err(error) => notices.push(error.message().to_string()),
            Ok(_) => {}
        }
        if let Some(path) = path.as_ref() {
            notices.extend(crate::settings::load_advisories(path));
        }
        let load_notice = if notices.is_empty() {
            None
        } else {
            Some(notices.join(" / "))
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
            settings_dirty: false,
            audit_row_selection: None,
            audit_scroll_handle: ScrollHandle::new(),
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
    /// maps to `UiAction::None` in every screen and editing mode, so key
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
                        let tick = cx.update(|cx| {
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
                                    unlocked && view.totp.has_secret(),
                                );
                                for effect in effects {
                                    match effect {
                                        crate::ui::timing::TickEffect::RestoreClipboard => {
                                            if view.restore_clipboard(cx) {
                                                cx.notify();
                                            }
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
                        });
                        // A silent loop exit used to hide both a released view
                        // and a failed context update. Keep the reason so a
                        // dead ticker is observable in the host log.
                        if let Err(error) = tick {
                            eprintln!("[totp-ticker] ティッカーを終了しました: {error}");
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
        // A highlight into the old report has no meaning after a lock/unlock.
        self.audit_row_selection = None;
    }

    /// Lock the vault: discard the data and clear every transient input mode.
    pub(super) fn lock(&mut self, cx: &mut Context<Self>) {
        // A login finishing after this point must not unlock the vault again.
        self.login_generation.invalidate();
        // One service handles the clipboard I/O; the lock status below
        // intentionally takes precedence over the restore notice.
        self.restore_clipboard(cx);
        self.reset_input_state();
        self.view.vault = Vault::new();
        self.view.audit_report = None;
        self.panel = Panel::Vault;
        self.screen = Screen::Locked;
        let unsaved = if self.settings_dirty {
            "（未保存の設定変更があります / 再ログイン後に保存してください）"
        } else {
            ""
        };
        self.status = format!("ロックしました{unsaved}（Enter: ログイン / m: モック）");
        cx.notify();
    }

    /// Switch panels through one path so no input mode survives the change.
    ///
    /// Leaving a settings field, auth field or search active would swallow
    /// every key in the destination panel ("dead keys").
    pub(super) fn set_panel(&mut self, panel: Panel, cx: &mut Context<Self>) {
        let owns_settings = matches!(self.panel, Panel::Settings | Panel::Generator);
        if owns_settings && panel != self.panel && self.settings_dirty {
            // Leaving the panel does not persist anything. Say so before the
            // destination panel overwrites the status message.
            self.status = unsaved_panel_exit_status().to_string();
        }
        self.editing = None;
        self.auth.take_field();
        self.view.finish_search();
        self.panel = crate::ui::logic::effective_panel(panel, self.view.audit_report.is_some());
        cx.notify();
    }

    /// Mark the current in-memory settings as not persisted yet.
    pub(super) fn mark_settings_dirty(&mut self) {
        self.settings_dirty = true;
    }

    /// Drop the cached TOTP secret when the selection no longer supplies one.
    ///
    /// Without this the ticker keeps invalidating a stale code every second,
    /// and a later copy could use the previous item's secret.
    pub(super) fn sync_totp_to_selection(&mut self) {
        let visible = self.view.visible_items();
        let secret =
            crate::ui::logic::required_item_index(self.view.selected_id.as_deref(), &visible)
                .and_then(|index| visible[index].totp_secret())
                .unwrap_or("")
                .to_string();
        if !self.totp.matches_secret(&secret) {
            self.totp.clear();
        }
    }

    /// Follow an audit finding, or resolve a reserved command sentinel.
    ///
    /// Mouse clicks pass a real item id; `Enter` in the audit panel passes the
    /// "selected row" sentinel, and `Esc` passes the "quit or warn" sentinel.
    /// Both are resolved here because this is where the dirty flag and the
    /// current report live.
    pub(super) fn focus_audit_item(&mut self, id: &str, cx: &mut Context<Self>) {
        if id == crate::ui::keys::QUIT_OR_WARN_SENTINEL {
            if let Some(warning) = quit_gate_warning(self.settings_dirty) {
                // A confirmation dialog needs window APIs outside this change;
                // keep the user in the app and explain what to do instead.
                self.status = warning.to_string();
                cx.notify();
            } else {
                self.apply_action(crate::ui::keys::UiAction::Quit, cx);
            }
            return;
        }
        let resolved = if id == crate::ui::keys::AUDIT_SELECTED_ROW_SENTINEL {
            self.view
                .audit_report
                .as_ref()
                .and_then(|report| {
                    self.audit_row_selection
                        .and_then(|index| report.items.get(index))
                })
                .map(|item| item.id.clone())
        } else {
            Some(id.to_string())
        };
        let Some(id) = resolved else {
            self.status = "監査行が選択されていません（↑↓で行を選択してください）".to_string();
            cx.notify();
            return;
        };
        self.set_panel(Panel::Vault, cx);
        self.view.filter = Filter::All;
        self.view.query.clear();
        self.view.finish_search();
        if let Some(index) = self.view.select_id(&id) {
            self.view
                .scroll_handle
                .scroll_to_item(index, ScrollStrategy::Nearest);
            self.status = format!("監査の指摘項目を選択しました: {id}");
        } else {
            self.view.deselect_and_rewind();
            self.status = "指摘項目が一覧に見つかりません".to_string();
        }
        self.sync_totp_to_selection();
        cx.notify();
    }

    /// Move the vault selection, or the audit highlight while that panel is up.
    ///
    /// Both key paths dispatch `MoveSelection`; routing by the effective panel
    /// keeps the keyboard intent aligned with what is actually drawn.
    pub(super) fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        if crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some())
            == Panel::Audit
        {
            self.move_audit_selection(delta, cx);
            return;
        }
        let visible = self.view.visible_items();
        let Some(next) = self.view.next_index_in(&visible, delta) else {
            return;
        };
        let id = visible[next].id.clone();
        if self.view.selected_id.as_deref() != Some(id.as_str()) {
            self.view.selected_id = Some(id);
            self.view
                .scroll_handle
                .scroll_to_item(next, ScrollStrategy::Nearest);
            self.sync_totp_to_selection();
            cx.notify();
        }
    }

    /// Highlight the next audit row and describe it in the status bar.
    fn move_audit_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        let len = self
            .view
            .audit_report
            .as_ref()
            .map_or(0, |report| report.items.len());
        let next = next_audit_row(self.audit_row_selection, delta, len);
        self.audit_row_selection = next;
        if let Some(index) = next {
            self.audit_scroll_handle.scroll_to_item(index);
        }
        let Some(index) = next else {
            self.status = status_with_unsaved(
                "監査する問題がありません（↑↓で行を選択できません）",
                self.settings_dirty,
            );
            cx.notify();
            return;
        };
        if let Some(item) = self
            .view
            .audit_report
            .as_ref()
            .and_then(|report| report.items.get(index))
        {
            let base = format!(
                "監査行 {}/{}: {}（Enter: 対象を選択 / g: 一覧 / Esc: 終了）",
                index + 1,
                len,
                item.name
            );
            self.status = status_with_unsaved(&base, self.settings_dirty);
        }
        cx.notify();
    }

    pub(super) fn cycle_filter(&mut self, cx: &mut Context<Self>) {
        self.view.cycle_filter();
        self.sync_totp_to_selection();
        cx.notify();
    }

    pub(super) fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let id = {
            let visible = self.view.visible_items();
            crate::ui::logic::required_item_index(self.view.selected_id.as_deref(), &visible)
                .map(|index| visible[index].id.clone())
        };
        let Some(id) = id else {
            self.status = crate::ui::logic::no_selection_status().to_string();
            cx.notify();
            return;
        };
        if let Some(favorite) = self.view.vault.toggle_favorite(&id) {
            self.status = format!(
                "お気に入りを{}にしました",
                if favorite { "設定" } else { "解除" }
            );
            // Under the Favorites filter the item may have just left the view.
            self.view.revalidate_selection();
            self.sync_totp_to_selection();
            cx.notify();
        }
    }

    /// The current TOTP code for `secret`, cached within its validity period.
    pub(super) fn totp_text(&mut self, secret: &str) -> String {
        self.totp.display(secret, totp::now_unix())
    }

    pub(super) fn selected_detail(&mut self) -> String {
        // Rendering is the last place a stale TOTP secret can linger: clear it
        // before deciding what the current selection shows.
        self.sync_totp_to_selection();
        let selected = {
            let visible = self.view.visible_items();
            crate::ui::logic::required_item_index(self.view.selected_id.as_deref(), &visible).map(
                |index| {
                    let item = visible[index];
                    (
                        format!(
                            "{} | {} | 更新: {}",
                            item.kind().label(),
                            item.name,
                            item.revision_date
                        ),
                        item.data.clone(),
                    )
                },
            )
        };
        let Some((base, data)) = selected else {
            return status_with_unsaved(
                crate::ui::logic::no_selection_status(),
                self.settings_dirty,
            );
        };
        let detail = match data {
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
                crate::ui::logic::card_last_four(&card.number)
            ),
            ItemData::Identity(identity) => format!("{base} | {}", identity.email),
            ItemData::SshKey(key) => format!("{base} | {}", key.fingerprint),
        };
        status_with_unsaved(&detail, self.settings_dirty)
    }

    /// Recompute the health report with the current thresholds.
    pub(super) fn refresh_audit(&mut self) {
        self.view.audit_report = Some(crate::ui::logic::compute_audit(
            &self.view.vault,
            self.settings.thresholds,
            i64::try_from(totp::now_unix()).unwrap_or(i64::MAX),
        ));
        // Findings can disappear when a threshold changes; do not leave the
        // keyboard highlight pointing past the end of the new report.
        let len = self
            .view
            .audit_report
            .as_ref()
            .map_or(0, |report| report.items.len());
        let last = len.saturating_sub(1);
        self.audit_row_selection = self.audit_row_selection.map(|index| index.min(last));
        if len == 0 {
            self.audit_row_selection = None;
        }
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
    use crate::health::Report;
    use crate::ui::clipboard::ClipboardState;

    #[::core::prelude::v1::test]
    fn quit_gate_warns_only_when_settings_are_dirty() {
        assert_eq!(quit_gate_warning(true), Some(unsaved_quit_warning_status()));
        assert_eq!(quit_gate_warning(false), None);
        assert!(quit_gate_warning(true).is_some_and(|text| text.contains("w: 保存 / d: 破棄")));
    }

    #[::core::prelude::v1::test]
    fn audit_status_carries_the_unsaved_marker() {
        let base = "監査行 1/2: example";
        assert!(!status_with_unsaved(base, false).contains("[未保存"));
        assert!(status_with_unsaved(base, true).contains("[未保存"));
    }
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

        let before = state.view.rewind_calls;
        reset(&mut state, now);

        assert_eq!(state.view.selected_id, None);
        assert_eq!(
            state.view.rewind_calls,
            before + 1,
            "the lock/unlock reset must rewind the same way as filter, \
             search and revalidation paths"
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

    #[::core::prelude::v1::test]
    fn panel_exit_warning_points_back_to_the_panels_with_w_and_d() {
        let status = unsaved_panel_exit_status();
        assert!(status.contains("未保存"));
        assert!(status.contains("設定/生成パネルに戻り"));
        assert!(status.contains("w: 保存 / d: 破棄"));
    }

    #[::core::prelude::v1::test]
    fn unsaved_marker_is_only_added_while_dirty() {
        assert_eq!(unsaved_status_suffix(false), "");
        assert_eq!(status_with_unsaved("ログイン成功", false), "ログイン成功");
        let dirty = status_with_unsaved("ログイン成功", true);
        assert!(dirty.starts_with("ログイン成功"));
        assert!(dirty.contains("[未保存の設定変更があります]"));
        assert_eq!(
            dirty,
            format!("ログイン成功{}", unsaved_status_suffix(true))
        );
        assert!(unsaved_quit_warning_status().contains("未保存の設定変更があります"));
        assert!(unsaved_quit_warning_status().contains("w: 保存 / d: 破棄"));
    }

    #[::core::prelude::v1::test]
    fn audit_row_navigation_clamps_and_handles_empty_reports() {
        assert_eq!(next_audit_row(None, 1, 0), None);
        assert_eq!(next_audit_row(None, -1, 0), None);
        assert_eq!(next_audit_row(Some(0), 1, 0), None);

        assert_eq!(next_audit_row(None, 1, 3), Some(0));
        assert_eq!(next_audit_row(None, -1, 3), Some(2));
        assert_eq!(next_audit_row(Some(0), -1, 3), Some(0));
        assert_eq!(next_audit_row(Some(2), 1, 3), Some(2));
        assert_eq!(next_audit_row(Some(1), 1, 3), Some(2));
        assert_eq!(next_audit_row(Some(1), -1, 3), Some(0));
        assert_eq!(next_audit_row(Some(1), 100, 3), Some(2));
        assert_eq!(next_audit_row(Some(1), -100, 3), Some(0));
        // A stale index is clamped before the delta is applied.
        assert_eq!(next_audit_row(Some(99), 1, 3), Some(2));
    }
}
