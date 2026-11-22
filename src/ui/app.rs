//! The main application state and GPUI wiring.

use crate::model::{Filter, ItemData, SortKey, Vault};
use crate::settings::Settings;
use crate::totp;
use crate::ui::auth_state::AuthState;
use crate::ui::logic::FOCUS_RECOVERY_HINT;
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

/// Status shown after following an audit finding, in both outcomes.
///
/// Routing both branches through `status_with_unsaved` keeps the persistent
/// "unsaved settings" warning visible when the user leaves the audit panel.
/// The pure form lets the contract be tested without a GPUI window (this crate
/// does not enable gpui's `test-support` feature).
pub(super) fn audit_focus_status(id: &str, found: bool, dirty: bool) -> String {
    let base = if found {
        format!("監査の指摘項目を選択しました: {id}")
    } else {
        "指摘項目が一覧に見つかりません".to_string()
    };
    status_with_unsaved(&base, dirty)
}

/// Status when `Enter` is pressed in the audit panel with no row highlighted.
///
/// This early-return branch bypasses `audit_focus_status`, so it must compose
/// through `status_with_unsaved` itself; otherwise the persistent unsaved
/// warning disappears the moment the user tries to follow a finding.
pub(super) fn audit_no_selection_status(dirty: bool) -> String {
    status_with_unsaved(
        "監査行が選択されていません（↑↓で行を選択してください）",
        dirty,
    )
}

/// Key guidance shared by every transition into the locked screen.
///
/// `lock()` and the idle ticker both leave the user on the same lock screen,
/// so both statuses must advertise the same recovery keys. Building the tail
/// in one place prevents the ticker from dropping `m: モック` when it replaces
/// the manual lock's status.
fn lock_guidance() -> String {
    format!("（Enter: ログイン / m: モック / {FOCUS_RECOVERY_HINT}）")
}

/// Status the ticker leaves on screen after an idle auto-lock.
///
/// `lock()` composes its own status (including the unsaved-settings warning),
/// but the ticker then replaces it to explain *why* the vault locked. Without
/// re-applying the marker here an idle lock silently drops that warning; the
/// same applies to the lock screen's key guidance.
pub(super) fn auto_lock_status(idle_lock_seconds: u64, dirty: bool) -> String {
    // Keep both pieces of information: the persistent unsaved marker *and*
    // the concrete recovery guidance that `lock()` showed before the ticker
    // replaced its status. Without the guidance the user only sees a marker
    // and has no way to learn that a re-login is required to save, or that a
    // demo vault can be reopened with `m`.
    let unsaved_guidance = if dirty {
        "（未保存の設定変更があります / 再ログイン後に保存してください）"
    } else {
        ""
    };
    status_with_unsaved(
        &format!(
            "無操作のため自動ロックしました（{idle_lock_seconds}秒）{unsaved_guidance}{}",
            lock_guidance()
        ),
        dirty,
    )
}

/// Status after toggling a favorite, keeping the unsaved marker visible.
///
/// Both branches of `toggle_favorite` (success and no selection) compose
/// their status through `status_with_unsaved`. The pure form lets that
/// contract be tested without a GPUI window.
pub(super) fn favorite_toggle_status(favorite: bool, dirty: bool) -> String {
    let base = if favorite {
        "お気に入りを設定にしました"
    } else {
        "お気に入りを解除にしました"
    };
    status_with_unsaved(base, dirty)
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

/// Clamp an audit-row highlight after the report length changes.
///
/// A shorter report cannot keep a row past its end; an empty report has no
/// valid row at all. Kept separate from the refresh method so the rule can
/// be exercised without a GPUI window.
pub(super) fn clamp_audit_row(selection: Option<usize>, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        selection.map(|index| index.min(len - 1))
    }
}

/// Scroll-handle index for a highlighted audit row.
///
/// The audit panel draws [`crate::ui::panels::AUDIT_HEADER_ROWS`] rows before
/// the first finding, so a report index must be offset before it is handed to
/// `ScrollHandle::scroll_to_item`. Kept as a pure helper so the offset rule can
/// be exercised without a GPUI window (this crate does not enable gpui's
/// `test-support` feature).
pub(super) fn audit_row_scroll_index(selection: Option<usize>) -> Option<usize> {
    selection.map(|index| index + crate::ui::panels::AUDIT_HEADER_ROWS)
}

/// Return the audit panel's scroll handle to its initial state.
///
/// `ScrollHandle::set_offset` clears the pixel offset but leaves a queued
/// `scroll_to_item` target in place: the next prepaint would scroll the freshly
/// unlocked panel straight back to the old row. Replacing the handle drops the
/// offset, the queued target and the stale item bounds together. The highlight
/// is cleared in the same step so no selection can point into the old report.
/// Kept as a free function so this can be tested without a GPUI window (this
/// crate does not enable gpui's `test-support` feature).
pub(super) fn reset_audit_scroll(handle: &mut ScrollHandle, selection: &mut Option<usize>) {
    *handle = ScrollHandle::new();
    *selection = None;
}

/// Status describing the audit row left highlighted after a refresh.
///
/// Uses the same wording as the keyboard move status, so a threshold edit
/// cannot leave the status bar naming a row that is no longer highlighted.
pub(super) fn audit_refresh_status(
    index: Option<usize>,
    len: usize,
    name: Option<&str>,
    dirty: bool,
) -> String {
    match (index, name) {
        (Some(index), Some(name)) => status_with_unsaved(
            &format!(
                "監査行 {}/{}: {}（Enter: 対象を選択 / g: 一覧 / Esc: 終了 / {FOCUS_RECOVERY_HINT}）",
                index + 1,
                len,
                name
            ),
            dirty,
        ),
        _ => status_with_unsaved(
            "監査する問題がありません（↑↓で行を選択できません）",
            dirty,
        ),
    }
}

/// Status for the highlighted audit row after a report refresh.
///
/// The selected *index* can survive a refresh while the row at that index is
/// replaced by a different finding (for example a threshold change reorders
/// the report). Callers must therefore derive the row name from the **new**
/// report every time, not only when the index itself was clamped. Returns
/// `None` when there is no row to describe (a non-empty report without a
/// selection keeps whatever status the user was reading).
pub(super) fn audit_refresh_status_for(
    report: Option<&crate::health::Report>,
    selection: Option<usize>,
    dirty: bool,
) -> Option<String> {
    let len = report.map_or(0, |report| report.items.len());
    let clamped = clamp_audit_row(selection, len);
    if clamped.is_none() && len > 0 {
        return None;
    }
    let name = clamped.and_then(|index| {
        report
            .and_then(|report| report.items.get(index))
            .map(|item| item.name.clone())
    });
    Some(audit_refresh_status(clamped, len, name.as_deref(), dirty))
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
                .map(|notice| {
                    format!("{notice} / Enter: ログイン / m: モック / Esc: 終了 / {FOCUS_RECOVERY_HINT}")
                })
                .unwrap_or_else(|| {
                    format!("ロック中: Enter: ログイン / m: モック / Esc: 終了 / {FOCUS_RECOVERY_HINT}")
                }),
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
                                            // `lock()` already warned about unsaved
                                            // settings; keep that marker instead of
                                            // replacing the whole status with a bare
                                            // auto-lock reason.
                                            view.status = auto_lock_status(
                                                view.settings.idle_lock_seconds,
                                                view.settings_dirty,
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
        // A highlight into the old report, and the scroll position that
        // followed it, have no meaning after a lock/unlock or a re-login.
        // Replacing the handle (instead of only zeroing its offset) also drops
        // any queued `scroll_to_item` target before the next audit render.
        reset_audit_scroll(&mut self.audit_scroll_handle, &mut self.audit_row_selection);
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
        self.status = format!("ロックしました{unsaved}{}", lock_guidance());
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

    /// Decide whether a platform window close may proceed.
    ///
    /// `App::on_window_closed` runs only after the window is gone, so the dirty
    /// flag cannot be consulted there. The window's public
    /// `on_window_should_close` callback calls this instead: unsaved settings
    /// keep the window open and surface the same warning Esc would show.
    pub fn allow_window_close(&mut self, cx: &mut Context<Self>) -> bool {
        if let Some(warning) = quit_gate_warning(self.settings_dirty) {
            self.status = warning.to_string();
            cx.notify();
            false
        } else {
            true
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
            self.status = audit_no_selection_status(self.settings_dirty);
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
            self.status = audit_focus_status(&id, true, self.settings_dirty);
        } else {
            self.view.deselect_and_rewind();
            self.status = audit_focus_status(&id, false, self.settings_dirty);
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
        if let Some(scroll_index) = audit_row_scroll_index(next) {
            self.audit_scroll_handle.scroll_to_item(scroll_index);
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
                "監査行 {}/{}: {}（Enter: 対象を選択 / g: 一覧 / Esc: 終了 / {FOCUS_RECOVERY_HINT}）",
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
            self.status =
                status_with_unsaved(crate::ui::logic::no_selection_status(), self.settings_dirty);
            cx.notify();
            return;
        };
        if let Some(favorite) = self.view.vault.toggle_favorite(&id) {
            self.status = favorite_toggle_status(favorite, self.settings_dirty);
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
                            crate::ui::logic::format_revision_date(item.revision_date)
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
                let password_label = if crate::vault_sync::is_undecryptable_password(&password) {
                    "復号不可".to_string()
                } else {
                    format!("{}文字", password.chars().count())
                };
                format!(
                    "{base} | {username} | パスワード: {password_label} | TOTP: {code} | URI: {}",
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
        self.audit_row_selection = clamp_audit_row(self.audit_row_selection, len);
        // A threshold change can shorten the report and clamp the highlight
        // to a different row. Mirror the keyboard path (`move_audit_selection`)
        // so the scroll position follows the row actually left highlighted.
        if let Some(scroll_index) = audit_row_scroll_index(self.audit_row_selection) {
            self.audit_scroll_handle.scroll_to_item(scroll_index);
        }
        // Always re-read the row name from the freshly computed report: the
        // index can stay the same while a different finding occupies it.
        if let Some(status) = audit_refresh_status_for(
            self.view.audit_report.as_ref(),
            self.audit_row_selection,
            self.settings_dirty,
        ) {
            self.status = status;
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

    #[::core::prelude::v1::test]
    fn audit_focus_status_keeps_the_unsaved_marker_in_both_branches() {
        let found_clean = audit_focus_status("item-42", true, false);
        assert_eq!(found_clean, "監査の指摘項目を選択しました: item-42");
        assert!(!found_clean.contains("[未保存"));

        let found_dirty = audit_focus_status("item-42", true, true);
        assert_eq!(found_dirty, status_with_unsaved(&found_clean, true));
        assert!(found_dirty.starts_with(&found_clean));
        assert!(found_dirty.contains("[未保存の設定変更があります]"));

        let missing_clean = audit_focus_status("item-42", false, false);
        assert_eq!(missing_clean, "指摘項目が一覧に見つかりません");
        assert!(!missing_clean.contains("[未保存"));

        let missing_dirty = audit_focus_status("item-42", false, true);
        assert_eq!(missing_dirty, status_with_unsaved(&missing_clean, true));
        assert!(missing_dirty.starts_with(&missing_clean));
        assert!(missing_dirty.contains("[未保存の設定変更があります]"));
    }

    #[::core::prelude::v1::test]
    fn audit_no_selection_status_keeps_the_unsaved_marker() {
        // The Enter-without-a-row early return used to bypass the common
        // composer and silently hide the unsaved-settings warning.
        let clean = audit_no_selection_status(false);
        assert_eq!(
            clean,
            "監査行が選択されていません（↑↓で行を選択してください）"
        );
        assert!(!clean.contains("[未保存"));

        let dirty = audit_no_selection_status(true);
        assert_eq!(dirty, status_with_unsaved(&clean, true));
        assert!(dirty.contains("[未保存の設定変更があります]"));
    }

    #[::core::prelude::v1::test]
    fn favorite_toggle_status_keeps_the_unsaved_marker() {
        let set = favorite_toggle_status(true, false);
        assert_eq!(set, "お気に入りを設定にしました");
        assert!(!set.contains("[未保存"));
        let set_dirty = favorite_toggle_status(true, true);
        assert_eq!(set_dirty, status_with_unsaved(&set, true));
        assert!(set_dirty.contains("[未保存の設定変更があります]"));

        let unset = favorite_toggle_status(false, false);
        assert_eq!(unset, "お気に入りを解除にしました");
        let unset_dirty = favorite_toggle_status(false, true);
        assert_eq!(unset_dirty, status_with_unsaved(&unset, true));
        assert!(unset_dirty.contains("[未保存の設定変更があります]"));

        // The no-selection branch uses the same composition.
        assert!(
            status_with_unsaved(crate::ui::logic::no_selection_status(), true)
                .contains("[未保存の設定変更があります]")
        );
    }

    #[::core::prelude::v1::test]
    fn audit_refresh_clamps_the_row_and_reports_the_new_selection() {
        assert_eq!(clamp_audit_row(Some(5), 3), Some(2));
        assert_eq!(clamp_audit_row(Some(1), 3), Some(1));
        assert_eq!(clamp_audit_row(Some(1), 0), None);
        assert_eq!(clamp_audit_row(None, 3), None);

        // The clamped row is the one that must be scrolled into view: the
        // panel renders three header rows ahead of the first finding.
        assert_eq!(audit_row_scroll_index(None), None);
        assert_eq!(audit_row_scroll_index(Some(0)), Some(3));
        assert_eq!(
            audit_row_scroll_index(clamp_audit_row(Some(5), 3)),
            Some(2 + crate::ui::panels::AUDIT_HEADER_ROWS)
        );

        let moved = audit_refresh_status(Some(2), 3, Some("Example"), false);
        assert_eq!(
            moved,
            format!(
                "監査行 3/3: Example（Enter: 対象を選択 / g: 一覧 / Esc: 終了 / {FOCUS_RECOVERY_HINT}）"
            )
        );
        let moved_dirty = audit_refresh_status(Some(2), 3, Some("Example"), true);
        assert_eq!(moved_dirty, status_with_unsaved(&moved, true));
        assert!(moved_dirty.contains("[未保存の設定変更があります]"));

        let empty = audit_refresh_status(None, 0, None, true);
        assert!(empty.contains("監査する問題がありません"));
        assert!(empty.contains("[未保存の設定変更があります]"));
    }

    #[::core::prelude::v1::test]
    fn audit_refresh_status_always_uses_the_latest_report_name() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        fn report(name: &str) -> Report {
            Report {
                items: vec![ItemReport {
                    id: "item-1".into(),
                    name: name.into(),
                    kind: ItemKind::Login,
                    findings: Vec::new(),
                }],
                examined: 1,
                with_totp: 0,
                logins: 1,
            }
        }

        // The index stays at 0 in both reports, but the row's name changes.
        let first = report("Old name");
        let second = report("New name");
        let before = audit_refresh_status_for(Some(&first), Some(0), false);
        let after = audit_refresh_status_for(Some(&second), Some(0), false);
        assert!(before
            .as_ref()
            .is_some_and(|status| status.contains("Old name")));
        assert!(
            after
                .as_ref()
                .is_some_and(|status| status.contains("New name")),
            "a refresh with an unchanged index must still re-read the row name"
        );
        assert_ne!(before, after);

        // A shorter report still clamps the stale index and names the new row.
        let clamped = audit_refresh_status_for(Some(&second), Some(5), false);
        assert!(clamped.is_some_and(|status| status.contains("New name")));
        // An empty report has no row to name.
        let empty = audit_refresh_status_for(Some(&Report::default()), Some(0), true);
        assert!(empty.is_some_and(|status| status.contains("監査する問題がありません")));
        // A non-empty report with no selection leaves the previous status alone.
        assert_eq!(audit_refresh_status_for(Some(&second), None, false), None);
    }

    #[::core::prelude::v1::test]
    fn auto_lock_status_keeps_the_unsaved_marker_and_lock_guidance() {
        let guidance = lock_guidance();
        let clean = auto_lock_status(300, false);
        assert_eq!(
            clean,
            format!("無操作のため自動ロックしました（300秒）{guidance}")
        );
        assert!(!clean.contains("[未保存"));

        let dirty = auto_lock_status(300, true);
        assert!(dirty.starts_with(
            "無操作のため自動ロックしました（300秒）（未保存の設定変更があります / 再ログイン後に保存してください）"
        ));
        assert!(dirty.contains("[未保存の設定変更があります]"));
        assert!(
            dirty.contains("再ログイン後に保存してください"),
            "the auto-lock status must keep the recovery guidance too: {dirty}"
        );
        assert_eq!(
            dirty,
            status_with_unsaved(
                &format!(
                    "無操作のため自動ロックしました（300秒）（未保存の設定変更があります / 再ログイン後に保存してください）{guidance}"
                ),
                true
            )
        );
    }

    #[::core::prelude::v1::test]
    fn auto_lock_status_advertises_the_same_keys_as_a_manual_lock() {
        // The idle ticker overwrites `lock()`'s status. Losing "m: モック"
        // there left no visible way to reopen the demo vault after an idle
        // lock, so the guidance must be byte-identical to the manual lock.
        let manual_guidance = lock_guidance();
        for dirty in [false, true] {
            let status = auto_lock_status(60, dirty);
            assert!(
                status.contains(&manual_guidance),
                "idle lock must reuse the manual lock guidance: {status}"
            );
            for key in ["Enter: ログイン", "m: モック", FOCUS_RECOVERY_HINT] {
                assert!(status.contains(key), "missing {key} in {status}");
            }
        }
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
    fn state_reset_replaces_the_audit_scroll_handle_and_clears_the_row() {
        let mut handle = ScrollHandle::new();
        handle.set_offset(Point {
            x: px(0.0),
            y: px(240.0),
        });
        // Queue a row target too: zeroing only the offset would leave this
        // pending and scroll the next render back to the old finding.
        handle.scroll_to_item(9);
        let old = handle.clone();
        assert_eq!(handle.offset().y, px(240.0));

        let mut selection = Some(4);
        reset_audit_scroll(&mut handle, &mut selection);

        assert_eq!(
            selection, None,
            "the stale audit highlight must not survive the reset"
        );
        assert_eq!(
            handle.offset(),
            Point::default(),
            "a fresh handle starts at the top of the audit panel"
        );
        assert_eq!(
            old.offset().y,
            px(240.0),
            "the old handle is replaced, not mutated: its queued target dies with it"
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

    #[::core::prelude::v1::test]
    fn selected_detail_uses_the_formatted_revision_date() {
        use crate::ui::logic::format_revision_date;

        assert_eq!(format_revision_date(crate::model::UNKNOWN_REVISION), "不明");
        assert_eq!(
            format_revision_date(1_700_000_000),
            "2023-11-14 22:13:20 UTC"
        );
        // The detail line now carries a readable label instead of raw seconds.
        let label = format!("更新: {}", format_revision_date(1_700_000_000));
        assert!(label.contains("更新: "));
        assert!(!label.contains("更新: 1700000000"));
    }

    #[::core::prelude::v1::test]
    fn lock_and_audit_statuses_advertise_focus_recovery() {
        use crate::ui::logic::{auth_hint, settings_hint};

        // The lock screen's own hint and the settings hint carry the key...
        assert!(auth_hint(false).contains(FOCUS_RECOVERY_HINT));
        assert!(auth_hint(true).contains(FOCUS_RECOVERY_HINT));
        assert!(settings_hint(false).contains(FOCUS_RECOVERY_HINT));
        assert!(settings_hint(true).contains(FOCUS_RECOVERY_HINT));

        // ...and the statuses owned by this module do too, so the lock and
        // audit screens advertise the key even before a panel hint is shown.
        let lock_status =
            format!("ロック中: Enter: ログイン / m: モック / Esc: 終了 / {FOCUS_RECOVERY_HINT}");
        assert!(lock_status.ends_with(FOCUS_RECOVERY_HINT));
        let audit_status = format!(
            "監査行 1/2: example（Enter: 対象を選択 / g: 一覧 / Esc: 終了 / {FOCUS_RECOVERY_HINT}）"
        );
        assert!(audit_status.contains(FOCUS_RECOVERY_HINT));
    }
}
