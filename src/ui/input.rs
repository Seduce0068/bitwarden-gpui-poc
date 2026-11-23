//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`crate::ui::keys`] module; this file
//! only applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::keys::{
    classify_key, KeyContext, KeyModifiers, SelectionEdge, UiAction, TEXT_EDIT_ARROW_KEYS_HINT,
};
use crate::ui::state::Panel;
use gpui_kit::*;

/// The dedicated key that re-acquires the view's focus handle after focus has
/// moved elsewhere (for example via Tab).
///
/// `F1` is chosen deliberately: [`crate::ui::keys::classify_key`] maps it to
/// [`UiAction::None`] on every screen and in every editing mode, and the
/// default keymaps do not bind it. The global observer that watches this key
/// therefore cannot change normal key classification or editing behaviour.
pub(super) const FOCUS_RECOVERY_KEY: &str = "f1";

/// Whether `key` is the dedicated focus-recovery key.
///
/// Kept as a pure helper so the invariant that this key is inert in the normal
/// key classification can be exercised without a GPUI window.
pub(super) fn is_focus_recovery_key(key: &str) -> bool {
    key == FOCUS_RECOVERY_KEY
}

/// Number of rows a single `PageUp`/`PageDown` press moves.
///
/// This is a **fixed** step, not a viewport-sized page: GPUI does not expose
/// the live visible-row count here, so the step cannot follow the window
/// height. User-facing guidance must therefore say "固定10行" rather than
/// "ページ移動" (see [`PAGE_MOVE_FIXED_ROWS_HINT`]); a hint promising a visible
/// page would not match this behaviour.
pub(super) const PAGE_MOVE_ROWS: isize = 10;

/// Guidance wording that matches the fixed [`PAGE_MOVE_ROWS`] step.
///
/// Mirrors the intent of `ui::panels::LIST_PAGE_AND_EDGE_HINT` without
/// promising a viewport-sized page. Kept beside the code that implements the
/// step (and pinned by a test) so the "dynamic row count is not available from
/// GPUI" limitation is documented where it matters. That panel's hint itself
/// lives outside this task's edit scope.
#[allow(dead_code)]
pub(super) const PAGE_MOVE_FIXED_ROWS_HINT: &str =
    "PageUp/PageDown: 固定10行ずつ移動（表示行数に合わせた移動ではありません）";

/// Delta for a `Home`/`End` jump accepted by the shared `move_selection` path.
///
/// `next_index_in` (vault) and `next_audit_row` (audit) both interpret a
/// *missing* selection from the sign of the delta alone, so an extreme delta
/// cannot express `End`. With a real selection the exact distance to the
/// target is returned; the shared path still owns clamping, scrolling, TOTP
/// sync and the status text. `None` means the list has no selectable row.
pub(super) fn edge_move_delta(
    current: Option<usize>,
    len: usize,
    edge: SelectionEdge,
) -> Option<isize> {
    if len == 0 {
        return None;
    }
    let last = len - 1;
    let Some(index) = current else {
        return Some(match edge {
            SelectionEdge::First => 0, // non-negative: start at the first row
            SelectionEdge::Last => -1, // negative: start at the last row
        });
    };
    let target = match edge {
        SelectionEdge::First => 0,
        SelectionEdge::Last => last,
    };
    Some(target as isize - index.min(last) as isize)
}

/// View-level effect of the `CycleSort` action.
///
/// Factored out of `apply_action` so the selection-drop and scroll-rewind
/// contract can be exercised with a plain `VaultViewState` (this crate does
/// not enable gpui's `test-support` feature).
pub(super) fn cycle_sort(view: &mut crate::ui::vault_view::VaultViewState) {
    view.sort = view.sort.next();
    view.deselect_and_rewind();
}

/// Status shown when a text-editing mode begins.
///
/// This status owns the shared "入力中:" arrow-key guidance for all three
/// editing modes (auth, search, settings); the settings panel deliberately
/// draws only its settings-specific inline hint so the prefix appears once.
/// Entering a mode is a transient edit, not a save, so `dirty` must keep the
/// persistent unsaved marker visible. Keeping it in one pure helper makes both
/// the wording and the marker contract testable without a GPUI window.
pub(super) fn text_edit_start_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(
        &format!("{TEXT_EDIT_ARROW_KEYS_HINT} / Enter または Esc で確定"),
        dirty,
    )
}

/// Status after confirming a settings field with Enter/Escape.
///
/// Confirming a field is not a save, so any unsaved marker must survive just
/// like it does on every other transient status. Kept as a pure helper so the
/// contract can be exercised without a GPUI window.
pub(super) fn settings_edit_finished_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved("入力を確定しました（w: 保存 / d: 破棄）", dirty)
}

/// Base text of the status shown when the audit panel is requested before a
/// report exists.
///
/// The mouse audit tab (`ui::render::audit_unavailable_status`) uses the exact
/// same wording. That module is outside this task's edit scope, so it keeps its
/// own literal; both copies must stay byte-identical.
pub(super) const AUDIT_UNAVAILABLE_MESSAGE: &str =
    "監査レポートがありません（ログイン後に生成されます）";

/// Status for [`UiAction::AuditUnavailable`], preserving the unsaved marker.
///
/// Mirrors the mouse tab's status composition, including the persistent
/// unsaved-settings warning. Kept pure so the contract can be tested without
/// a GPUI window.
pub(super) fn audit_unavailable_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(AUDIT_UNAVAILABLE_MESSAGE, dirty)
}

/// Shared composer for the status restored when a text-editing mode ends.
///
/// `EditAuthField`, `EditSettingsField` and `StartSearch` all replace the
/// status with [`text_edit_start_status`], whose text begins with "入力中:".
/// Leaving the mode without restoring a normal status leaves that stale
/// guidance on screen after Enter/Escape. This helper overwrites it with the
/// caller's normal status while preserving the persistent unsaved marker.
/// Kept pure so the contract can be tested without a GPUI window.
pub(super) fn text_edit_finished_status(normal_status: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(normal_status, dirty)
}

/// Normal lock-screen status restored by `FinishAuthEdit`.
pub(super) fn auth_edit_finished_status(dirty: bool) -> String {
    text_edit_finished_status(crate::ui::logic::auth_hint(false), dirty)
}

/// Normal vault status restored by `FinishSearch`.
///
/// Confirming a search clears the selection and rewinds the list (see
/// `VaultViewState::finish_search`), so the restored status matches the detail
/// line's "nothing selected" state instead of claiming a selection survives.
/// With zero matches that generic prompt would point at a row that does not
/// exist, so the confirmed result count selects a dedicated message instead.
pub(super) fn search_finished_status(result_count: usize, dirty: bool) -> String {
    text_edit_finished_status(
        &crate::ui::logic::no_selection_status_for_count(result_count),
        dirty,
    )
}

/// Confirm an active search because a row was clicked, and return its status.
///
/// The mouse path in `render.rs` sends `SelectRow`, which is the click
/// equivalent of Enter/Escape: it leaves search mode, keeps the query and must
/// replace the "入力中:" status installed by `StartSearch`. Factored over the
/// `VaultViewState` so both the mode change and the count-dependent status can
/// be tested without a GPUI window.
pub(super) fn finish_search_from_row_click(
    view: &mut crate::ui::vault_view::VaultViewState,
    dirty: bool,
) -> String {
    view.finish_search();
    search_finished_status(view.visible_items().len(), dirty)
}

/// Status for a row click that actually selected a row while confirming search.
///
/// [`finish_search_from_row_click`] runs before `select_index`, so its
/// count-based text still says "項目を選択してください" even though the click
/// has just chosen that row. Callers must replace it once the selection is in
/// place. No selected row falls back to the count-based text, so an
/// out-of-range click cannot claim a selection that did not happen. Kept pure
/// so the contract can be tested without a GPUI window.
pub(super) fn selected_row_click_status(
    view: &crate::ui::vault_view::VaultViewState,
    dirty: bool,
) -> String {
    let visible = view.visible_items();
    let selected = view
        .selected_id
        .as_deref()
        .and_then(|id| visible.iter().find(|item| item.id == id));
    match selected {
        Some(item) => {
            let name = &item.name;
            crate::ui::app::status_with_unsaved(&format!("項目を選択しました: {name}"), dirty)
        }
        None => search_finished_status(visible.len(), dirty),
    }
}

/// Remove the last character of a confirmed query and return the new status.
///
/// `BackspaceQuery` (vault-panel Backspace while a query is present) edits the
/// query after search confirmation. `pop_query` drops the selection and can
/// change the match count, so leaving the previous "検索結果が0件です" text on
/// screen would be misleading. Factored out so the count-dependent wording and
/// the rewind contract are testable without a GPUI window.
pub(super) fn backspace_confirmed_query(
    view: &mut crate::ui::vault_view::VaultViewState,
    dirty: bool,
) -> String {
    view.pop_query();
    search_finished_status(view.visible_items().len(), dirty)
}

/// Append text to an already-confirmed query and return the new status.
///
/// `InsertQueryText` refines the query after Enter/Escape without re-entering
/// search mode, so `/` remains free to start a fresh search. Like
/// [`backspace_confirmed_query`], a query edit drops the selection and can
/// change the match count, so the status must be recomputed from the visible
/// items instead of leaving the confirmation text on screen.
pub(super) fn insert_confirmed_query(
    view: &mut crate::ui::vault_view::VaultViewState,
    text: &str,
    dirty: bool,
) -> String {
    view.push_query(text);
    search_finished_status(view.visible_items().len(), dirty)
}

/// Status after a settings time field is adjusted with `i`/`u`, `3`/`4` or
/// `5`/`6`.
///
/// The threshold keys already report through `refresh_audit`, but these three
/// branches previously changed the settings without touching the status bar,
/// leaving whatever the last action had written on screen. `unit` is `分` for
/// the idle auto-lock timeout (`i`/`u`, which moves in one-minute steps, see
/// [`crate::ui::logic::adjust_idle_lock`]) and `秒数` for the genuinely
/// seconds-based `3`-`6` fields. Kept pure so the wording can be tested
/// without a GPUI window.
pub(super) fn time_adjust_status(unit: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(
        &format!("{unit}を変更しました（w: 保存 / d: 破棄）"),
        dirty,
    )
}

/// Status after `i`/`u` adjusts the minute-based idle auto-lock timeout.
pub(super) fn idle_lock_adjust_status(dirty: bool) -> String {
    time_adjust_status("分", dirty)
}

/// Status after `3`-`6` adjusts a seconds-based settings field.
pub(super) fn seconds_adjust_status(dirty: bool) -> String {
    time_adjust_status("秒数", dirty)
}

/// Status after trying to copy a value the generator has not produced yet.
///
/// [`crate::ui::logic::no_generated_status`] names the missing value but does
/// not compose the persistent unsaved-settings marker. Writing it straight
/// into `self.status` made the marker disappear on this copy attempt, unlike
/// every other transient status. Kept pure so the contract can be tested
/// without a GPUI window.
pub(super) fn no_generated_copy_status(kind: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(&crate::ui::logic::no_generated_status(kind), dirty)
}

/// Status after `+`/`-` adjusts the audit thresholds.
///
/// `refresh_audit` intentionally keeps the settings panel's own status (see
/// `audit_refresh_status_for_panel`), so the threshold keys need their own
/// feedback just like the other settings-adjustment keys. Kept pure so the
/// wording can be tested without a GPUI window.
pub(super) fn threshold_adjust_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved("監査閾値を変更しました（w: 保存 / d: 破棄）", dirty)
}

/// Outcome of a clamped settings adjustment.
///
/// Every `logic::adjust_*` helper clamps its result, so pressing a key at a
/// boundary can leave the stored value identical to the previous one. In that
/// case the caller must not announce "変更しました" nor mark the settings
/// unsaved: `changed` is derived from the before/after values, not from the
/// key that was pressed. Factored out here (rather than inline in the GPUI
/// dispatcher) so the boundary contract is testable without a GPUI window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Adjustment<T> {
    /// Value to store back into the settings.
    pub(super) value: T,
    /// Whether the adjustment actually moved the value.
    pub(super) changed: bool,
}

impl<T: PartialEq> Adjustment<T> {
    pub(super) fn new(before: T, after: T) -> Self {
        Self {
            changed: after != before,
            value: after,
        }
    }
}

impl BitwardenApp {
    /// Apply `Home`/`End` through the same dispatcher as Up/Down/Page keys.
    ///
    /// Only the delta computation is panel-specific; the actual selection,
    /// scroll adjustment and status update stay in `BitwardenApp::move_selection`.
    fn move_selection_to_edge(&mut self, edge: SelectionEdge, cx: &mut Context<Self>) {
        let delta =
            if crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some())
                == Panel::Audit
            {
                let len = self
                    .view
                    .audit_report
                    .as_ref()
                    .map_or(0, |report| report.items.len());
                edge_move_delta(self.audit_row_selection, len, edge)
            } else {
                let visible = self.view.visible_items();
                let current = self
                    .view
                    .selected_id
                    .as_deref()
                    .and_then(|id| visible.iter().position(|item| item.id == id));
                edge_move_delta(current, visible.len(), edge)
            };
        if let Some(delta) = delta {
            self.move_selection(delta, cx);
        }
    }

    pub(super) fn key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.last_activity = std::time::Instant::now();
        let ctx = KeyContext {
            screen: self.screen,
            panel: crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some()),
            key: &event.keystroke.key,
            key_char: event.keystroke.key_char.as_deref(),
            modifiers: KeyModifiers {
                control: event.keystroke.modifiers.control,
                platform: event.keystroke.modifiers.platform,
                alt: event.keystroke.modifiers.alt,
                function: event.keystroke.modifiers.function,
            },
            editing_auth: self.auth.field().is_some(),
            searching: self.view.searching,
            editing_settings: self.editing.is_some(),
            login_failed: self.auth.login_failed(),
            has_audit_report: self.view.audit_report.is_some(),
            query_nonempty: !self.view.query.is_empty(),
        };
        self.apply_action(classify_key(&ctx), cx);
    }

    /// Stamp activity for wheel/trackpad scrolls.
    ///
    /// `key_down` and `apply_action` already refresh `last_activity`, but a
    /// user who only scrolls (for example through the audit report) would
    /// otherwise hit the idle-lock timer. GPUI exposes a public bubble-phase
    /// `on_scroll` handler, so the root element in `render.rs` forwards
    /// scrolls here without touching gpui-kit internals.
    pub(super) fn scrolled(
        &mut self,
        _event: &ScrollEvent,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
        self.last_activity = std::time::Instant::now();
    }

    /// Apply a UI action to the app state. Both keyboard and mouse input go
    /// through this single path so state transitions stay consistent.
    pub(super) fn apply_action(&mut self, action: UiAction, cx: &mut Context<Self>) {
        self.last_activity = std::time::Instant::now();
        match action {
            UiAction::Quit => cx.quit(),
            UiAction::Authenticate | UiAction::RetryLogin => self.unlock_with_auth(cx),
            UiAction::OpenDemoVault => self.unlock_mock(cx),
            UiAction::EditAuthField(field) => {
                // Changing credentials invalidates any in-flight attempt.
                self.login_generation.invalidate();
                self.auth.set_field(Some(field));
                self.status = text_edit_start_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::EditSettingsField(field) => {
                self.editing = Some(field);
                self.status = text_edit_start_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::FinishAuthEdit => {
                self.login_generation.invalidate();
                self.auth.take_field();
                // Enter/Escape only confirm the field; drop the "入力中"
                // guidance installed by EditAuthField.
                self.status = auth_edit_finished_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::FinishSearch => {
                self.view.finish_search();
                // `finish_search` keeps the query, so the visible count is the
                // confirmed search's result count. It lets the status report
                // "no matches" instead of asking for a non-existent row.
                let result_count = self.view.visible_items().len();
                // Same contract as the auth field: confirmation is not still
                // an editing session, so restore the normal vault status.
                self.status = search_finished_status(result_count, self.settings_dirty);
                cx.notify();
            }
            UiAction::FinishSettingsEdit => {
                self.editing = None;
                // Enter/Escape only confirm the field; point at the explicit
                // save/discard keys and keep the unsaved marker visible.
                self.status = settings_edit_finished_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::InsertAuthText(text) => {
                self.login_generation.invalidate();
                self.edit_auth_field(&text);
                cx.notify();
            }
            UiAction::InsertSearchText(text) => {
                self.view.push_query(&text);
                cx.notify();
            }
            UiAction::InsertSettingsText(text) => {
                self.push_editing(&text);
                cx.notify();
            }
            UiAction::BackspaceAuth => {
                self.login_generation.invalidate();
                self.backspace_auth_field();
                cx.notify();
            }
            UiAction::BackspaceSearch => {
                self.view.pop_query();
                cx.notify();
            }
            UiAction::BackspaceSettings => {
                self.pop_editing();
                cx.notify();
            }
            UiAction::BackspaceQuery => {
                // The previous status may still announce a zero-match
                // confirmed search; report the count after this edit instead.
                let status = backspace_confirmed_query(&mut self.view, self.settings_dirty);
                self.status = status;
                cx.notify();
            }
            UiAction::InsertQueryText(text) => {
                // Symmetric to BackspaceQuery: refine the confirmed query and
                // recompute the count-dependent status. Search mode is left
                // untouched so a later `/` still starts a fresh search.
                let status = insert_confirmed_query(&mut self.view, &text, self.settings_dirty);
                self.status = status;
                cx.notify();
            }
            UiAction::SetPanel(panel) => self.set_panel(panel, cx),
            UiAction::Lock => self.lock(cx),
            UiAction::MoveSelection(delta) => self.move_selection(delta, cx),
            UiAction::MoveSelectionPage(direction) => {
                // Direction comes from the classifier as -1/+1; saturating
                // multiplication keeps an extreme value from overflowing.
                self.move_selection(direction.saturating_mul(PAGE_MOVE_ROWS), cx)
            }
            UiAction::MoveSelectionToEdge(edge) => self.move_selection_to_edge(edge, cx),
            UiAction::ToggleFavorite => self.toggle_favorite(cx),
            UiAction::OpenAudit => self.set_panel(Panel::Audit, cx),
            UiAction::AuditUnavailable => {
                // No report to show: explain why instead of silently doing
                // nothing. Same text and unsaved-marker handling as a click
                // on the mouse audit tab (see `audit_unavailable_status`).
                self.status = audit_unavailable_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::GeneratePassword => self.generate_password(cx),
            UiAction::GeneratePassphrase => self.generate_passphrase(cx),
            UiAction::CopyPassword => {
                if let Some(value) = self.generator.last_password.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = no_generated_copy_status("パスワード", self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::CopyPassphrase => {
                if let Some(value) = self.generator.last_passphrase.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = no_generated_copy_status("パスフレーズ", self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::CopyTotp => self.copy_totp(cx),
            UiAction::CopySelectedPassword => self.copy_selected_field(true, cx),
            UiAction::CopySelectedUsername => self.copy_selected_field(false, cx),
            UiAction::CycleFilter => self.cycle_filter(cx),
            UiAction::CycleSort => {
                cycle_sort(&mut self.view);
                self.sync_totp_to_selection();
                // The sort changed but no status was written, leaving the
                // previous action's text on screen. Report the active sort.
                self.status =
                    crate::ui::app::sort_cycle_status(self.view.sort, self.settings_dirty);
                cx.notify();
            }
            UiAction::StartSearch => {
                // Delegate to the shared helper instead of duplicating its
                // query reset here: its query-clearing contract is covered by
                // `vault_view::tests::start_search_discards_a_previous_query_and_its_selection`.
                self.view.start_search();
                self.sync_totp_to_selection();
                self.status = text_edit_start_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::SaveSettings => self.save_settings(cx),
            UiAction::DiscardSettings => self.discard_settings(cx),
            UiAction::FocusAuditItem(id) => self.focus_audit_item(&id, cx),
            UiAction::AdjustThreshold(delta) => {
                let before = self.settings.thresholds;
                let adjustment =
                    Adjustment::new(before, crate::ui::logic::adjust_thresholds(before, delta));
                self.settings.thresholds = adjustment.value;
                // A clamped step changes nothing: leave the status and the
                // persistent unsaved marker exactly as they were. In
                // particular, skip `refresh_audit`, which can overwrite the
                // status with an audit-row description on other panels.
                if adjustment.changed {
                    self.mark_settings_dirty();
                    self.refresh_audit();
                    // Set the status *after* the refresh: on settings panels
                    // the refresh keeps the previous status, and on other
                    // panels this feedback must win over an audit-row
                    // description.
                    self.status = threshold_adjust_status(self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::AdjustIdleLock(delta) => {
                let before = self.settings.idle_lock_seconds;
                let adjustment =
                    Adjustment::new(before, crate::ui::logic::adjust_idle_lock(before, delta));
                self.settings.idle_lock_seconds = adjustment.value;
                if adjustment.changed {
                    self.mark_settings_dirty();
                    // `i`/`u` move in minutes, not seconds: report the right unit.
                    self.status = idle_lock_adjust_status(self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::AdjustLoginTimeout(delta) => {
                let before = self.settings.login_timeout_seconds;
                let adjustment =
                    Adjustment::new(before, crate::ui::logic::adjust_seconds(before, delta));
                self.settings.login_timeout_seconds = adjustment.value;
                if adjustment.changed {
                    self.mark_settings_dirty();
                    self.status = seconds_adjust_status(self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::AdjustClipboardRestore(delta) => {
                let before = self.settings.clipboard_restore_seconds;
                let adjustment =
                    Adjustment::new(before, crate::ui::logic::adjust_seconds(before, delta));
                self.settings.clipboard_restore_seconds = adjustment.value;
                if adjustment.changed {
                    self.mark_settings_dirty();
                    self.status = seconds_adjust_status(self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::Generator(option) => self.toggle_generator(option, cx),
            // `index` is the render-position index emitted by `ui::render`'s
            // row click, NOT a stable item id. `select_index` resolves it
            // against the current `visible_items()` snapshot and the same
            // index is reused for scrolling, so both must name the same row.
            // A snapshot change between draw and click can therefore select a
            // different row; a stable id is deliberately out of scope (R2-UI-94).
            UiAction::SelectRow(index) => {
                // A mouse click is an explicit selection: leaving search mode
                // here keeps the row click and the keyboard path consistent.
                // It must also replace the "入力中:" status from StartSearch.
                let confirming_search = self.view.searching;
                if confirming_search {
                    let status = finish_search_from_row_click(&mut self.view, self.settings_dirty);
                    self.status = status;
                }
                if self.view.select_index(index) {
                    self.view
                        .scroll_handle
                        .scroll_to_item(index, gpui_kit::ScrollStrategy::Nearest);
                    if confirming_search {
                        // The confirmation status was computed before the
                        // selection existed, so it still asks the user to
                        // choose a row. Replace it with the selected row now.
                        self.status = selected_row_click_status(&self.view, self.settings_dirty);
                    }
                }
                self.sync_totp_to_selection();
                cx.notify();
            }
            UiAction::None => {}
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
    use crate::ui::state::Screen;

    fn context(screen: Screen, panel: Panel, key: &str) -> KeyContext<'_> {
        KeyContext {
            screen,
            panel,
            key,
            key_char: None,
            modifiers: KeyModifiers::default(),
            editing_auth: false,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: false,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn cycle_sort_deselects_and_rewinds() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        let mut view = VaultViewState::new();
        view.vault.items.push(VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        view.selected_id = Some("a".into());
        let before_sort = view.sort;
        let before_rewind = view.rewind_calls;

        cycle_sort(&mut view);

        assert_ne!(
            view.sort, before_sort,
            "CycleSort must advance the sort key"
        );
        assert_eq!(
            view.selected_id, None,
            "the stale selection must be dropped"
        );
        assert_eq!(
            view.rewind_calls,
            before_rewind + 1,
            "a sort change rewinds like filter and search changes"
        );
    }

    #[::core::prelude::v1::test]
    fn cycle_sort_status_follows_the_new_sort_key() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        let mut view = VaultViewState::new();
        view.vault.items.push(VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        let before_sort = view.sort;
        let before = crate::ui::app::sort_cycle_status(before_sort, false);
        cycle_sort(&mut view);
        let after = crate::ui::app::sort_cycle_status(view.sort, false);

        assert_ne!(before, after, "a sort change must produce a new status");
        assert_eq!(
            after,
            crate::ui::app::sort_cycle_status(before_sort.next(), false),
            "the status must describe the sort now in effect"
        );
        assert_eq!(view.sort, before_sort.next());
        assert!(after.contains("並び順を切り替えました"), "{after}");
        assert!(after.contains(view.sort.label()), "{after}");
    }

    #[::core::prelude::v1::test]
    fn no_generated_copy_status_keeps_the_unsaved_marker() {
        for kind in ["パスワード", "パスフレーズ"] {
            let clean = no_generated_copy_status(kind, false);
            assert_eq!(clean, crate::ui::logic::no_generated_status(kind));
            assert!(!clean.contains("[未保存"), "{clean}");

            let dirty = no_generated_copy_status(kind, true);
            assert_eq!(
                dirty,
                crate::ui::app::status_with_unsaved(&clean, true),
                "{kind}"
            );
            assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
            assert!(dirty.contains("生成パネルで生成してください"), "{dirty}");
        }
    }

    #[::core::prelude::v1::test]
    fn text_edit_start_status_explains_arrow_key_ownership() {
        let status = text_edit_start_status(false);
        assert!(status.contains("矢印キー"), "{status}");
        assert!(status.contains("GPUI"), "{status}");
        assert_eq!(
            status,
            format!("{TEXT_EDIT_ARROW_KEYS_HINT} / Enter または Esc で確定")
        );
    }

    #[::core::prelude::v1::test]
    fn text_edit_start_status_keeps_the_unsaved_marker() {
        let clean = text_edit_start_status(false);
        assert_eq!(
            clean,
            format!("{TEXT_EDIT_ARROW_KEYS_HINT} / Enter または Esc で確定")
        );
        assert!(!clean.contains("[未保存"), "{clean}");

        // All three callers (EditAuthField, EditSettingsField, StartSearch)
        // install this status while editing. Entering a mode is not a save, so
        // the persistent warning must survive just like on any other transient
        // status.
        let dirty = text_edit_start_status(true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(&clean, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("入力中"), "{dirty}");
    }

    #[::core::prelude::v1::test]
    fn settings_edit_finished_status_keeps_the_unsaved_marker() {
        let clean = settings_edit_finished_status(false);
        assert_eq!(clean, "入力を確定しました（w: 保存 / d: 破棄）");
        let dirty = settings_edit_finished_status(true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(
            dirty.contains("[未保存の設定変更があります]"),
            "confirming a field is not a save: {dirty}"
        );
    }

    #[::core::prelude::v1::test]
    fn audit_unavailable_status_matches_the_mouse_audit_tab_wording() {
        // The base text must stay byte-identical to the literal used by the
        // mouse audit tab in `ui::render::audit_unavailable_status`.
        let base = AUDIT_UNAVAILABLE_MESSAGE;
        assert_eq!(base, "監査レポートがありません（ログイン後に生成されます）");

        let clean = audit_unavailable_status(false);
        assert_eq!(clean, base);
        assert!(!clean.contains("[未保存"), "{clean}");

        // A keyboard request must not drop the persistent warning either.
        let dirty = audit_unavailable_status(true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(base, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
    }

    #[::core::prelude::v1::test]
    fn vault_g_without_report_routes_to_the_unavailable_status() {
        let mut value = context(Screen::Unlocked, Panel::Vault, "g");
        value.has_audit_report = false;
        let action = classify_key(&value);

        assert_eq!(action, UiAction::AuditUnavailable);
        assert_ne!(action, UiAction::None, "a bare `g` must never be inert");
        assert_eq!(audit_unavailable_status(false), AUDIT_UNAVAILABLE_MESSAGE);
    }

    #[::core::prelude::v1::test]
    fn seconds_adjust_status_keeps_save_hint_and_unsaved_marker() {
        let clean = seconds_adjust_status(false);
        assert_eq!(clean, "秒数を変更しました（w: 保存 / d: 破棄）");
        assert!(!clean.contains("[未保存"), "{clean}");

        // The seconds-based 3/4 and 5/6 branches mark the settings dirty
        // before writing the status, so the unsaved marker must survive.
        let dirty = seconds_adjust_status(true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");
    }

    #[::core::prelude::v1::test]
    fn idle_lock_adjust_status_reports_minutes_not_seconds() {
        let clean = idle_lock_adjust_status(false);
        assert_eq!(clean, "分を変更しました（w: 保存 / d: 破棄）");
        assert!(!clean.contains("秒"), "{clean}");

        let dirty = idle_lock_adjust_status(true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");

        // The 3-6 fields really are seconds-based and keep their wording.
        assert_eq!(
            seconds_adjust_status(false),
            "秒数を変更しました（w: 保存 / d: 破棄）"
        );
        assert!(!seconds_adjust_status(false).contains("分を変更"));
    }

    #[::core::prelude::v1::test]
    fn idle_lock_keys_route_to_the_minute_status() {
        for (key, delta) in [("i", 1), ("u", -1)] {
            let ctx = context(Screen::Unlocked, Panel::Settings, key);
            assert_eq!(classify_key(&ctx), UiAction::AdjustIdleLock(delta));
            assert!(
                idle_lock_adjust_status(true).contains("分を変更しました"),
                "{key} must report minutes, not seconds"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn threshold_adjust_status_reports_the_change_and_unsaved_marker() {
        let clean = threshold_adjust_status(false);
        assert_eq!(clean, "監査閾値を変更しました（w: 保存 / d: 破棄）");
        assert!(!clean.contains("[未保存"), "{clean}");

        // The branch marks the settings dirty before writing the status.
        let dirty = threshold_adjust_status(true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(&clean, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");

        // Confirm the keys that reach this branch are still the threshold keys.
        for (key, delta) in [("+", 1), ("=", 1), ("-", -1), ("_", -1)] {
            let ctx = context(Screen::Unlocked, Panel::Settings, key);
            assert_eq!(
                classify_key(&ctx),
                UiAction::AdjustThreshold(delta),
                "{key}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn clamped_settings_adjustments_are_not_reported_as_changes() {
        use crate::health::Thresholds;
        use crate::ui::logic::{adjust_idle_lock, adjust_seconds, adjust_thresholds};

        // At a bound the clamp returns the stored value unchanged, so the
        // dispatcher must skip both the "変更しました" status and the unsaved
        // marker.
        let idle_before = crate::limits::MIN_IDLE_LOCK_MINUTES * 60;
        let idle = Adjustment::new(idle_before, adjust_idle_lock(idle_before, -1));
        assert!(!idle.changed, "idle {idle_before} - 1 is clamped");
        assert_eq!(idle.value, idle_before);
        let idle = Adjustment::new(idle_before, adjust_idle_lock(idle_before, 1));
        assert!(
            idle.changed,
            "a step away from the bound still changes idle"
        );

        // Both seconds-based settings share the same 1..=3600 bounds.
        for (before, delta) in [
            (crate::limits::MIN_LOGIN_TIMEOUT_SECONDS, -1),
            (crate::limits::MAX_LOGIN_TIMEOUT_SECONDS, 1),
        ] {
            let adj = Adjustment::new(before, adjust_seconds(before, delta));
            assert!(!adj.changed, "seconds {before} / {delta} is clamped");
            assert_eq!(adj.value, before);
        }

        // Both threshold fields clamp at their shared bounds.
        let at_max = Thresholds {
            weak_bits: crate::limits::MAX_WEAK_BITS,
            stale_days: crate::limits::MAX_STALE_DAYS,
        };
        let adj = Adjustment::new(at_max, adjust_thresholds(at_max, 1));
        assert!(!adj.changed);
        assert_eq!(adj.value, at_max);

        let at_min = Thresholds {
            weak_bits: crate::limits::MIN_WEAK_BITS,
            stale_days: crate::limits::MIN_STALE_DAYS,
        };
        let adj = Adjustment::new(at_min, adjust_thresholds(at_min, -1));
        assert!(!adj.changed);
        assert_eq!(adj.value, at_min);
    }

    #[::core::prelude::v1::test]
    fn effective_settings_adjustments_are_reported_as_changes() {
        use crate::health::Thresholds;
        use crate::ui::logic::{adjust_idle_lock, adjust_seconds, adjust_thresholds};

        // Guard the positive case too: the fix must not silence real changes.
        let idle = Adjustment::new(300, adjust_idle_lock(300, 1));
        assert!(idle.changed);
        assert_eq!(idle.value, 360);

        for (delta, expected) in [(1, 31), (-1, 29)] {
            let adj = Adjustment::new(30, adjust_seconds(30, delta));
            assert!(adj.changed, "delta={delta}");
            assert_eq!(adj.value, expected);
        }

        let base = Thresholds::default();
        let adj = Adjustment::new(base, adjust_thresholds(base, 1));
        assert!(adj.changed);
        assert_ne!(adj.value, base);
    }

    #[::core::prelude::v1::test]
    fn confirming_auth_or_search_clears_the_editing_status() {
        // The installed status really does carry the "入力中" prefix;
        // otherwise this test would pass without exercising the stale-status
        // bug. The inline lock-screen hint deliberately omits that prefix so
        // it is not drawn twice (see `logic::auth_hint`).
        assert!(text_edit_start_status(false).contains("入力中"));
        assert!(!crate::ui::logic::auth_hint(true).contains("入力中"));

        for dirty in [false, true] {
            let auth = auth_edit_finished_status(dirty);
            assert_eq!(
                auth,
                crate::ui::app::status_with_unsaved(crate::ui::logic::auth_hint(false), dirty)
            );
            assert!(!auth.contains("入力中"), "{auth}");
            assert!(auth.contains("F1: フォーカス復帰"), "{auth}");

            let search = search_finished_status(3, dirty);
            assert_eq!(
                search,
                crate::ui::app::status_with_unsaved(
                    &crate::ui::logic::no_selection_status_for_count(3),
                    dirty
                )
            );
            assert!(!search.contains("入力中"), "{search}");
            assert_eq!(
                search.contains("[未保存の設定変更があります]"),
                dirty,
                "{search}"
            );

            // A confirmed search with no matches must not ask the user to
            // select a row: the dedicated message keeps the unsaved marker.
            let empty = search_finished_status(0, dirty);
            assert_eq!(
                empty,
                crate::ui::app::status_with_unsaved(
                    crate::ui::logic::NO_SEARCH_RESULTS_STATUS,
                    dirty
                )
            );
            assert!(!empty.contains("項目を選択してください"), "{empty}");
        }
    }

    #[::core::prelude::v1::test]
    fn row_click_during_search_confirms_search_and_restores_status() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        fn item(id: &str, name: &str) -> VaultItem {
            VaultItem::new(
                id,
                name,
                ItemData::SecureNote {
                    text: String::new().into(),
                },
            )
        }

        let mut view = VaultViewState::new();
        view.vault.items.push(item("a", "Alpha"));
        view.vault.items.push(item("b", "Beta"));
        view.start_search();
        view.push_query("Beta");
        assert!(view.searching);
        assert_eq!(view.visible_items().len(), 1, "precondition: query matches");
        let before = view.rewind_calls;

        // This is the status the render.rs click handler installs via
        // `apply_action(UiAction::SelectRow(..))`.
        let status = finish_search_from_row_click(&mut view, false);

        assert!(!view.searching, "a row click confirms the search");
        assert_eq!(view.query, "Beta", "confirming keeps the query");
        assert_eq!(view.rewind_calls, before + 1);
        assert_eq!(status, search_finished_status(1, false));
        assert!(!status.contains("入力中"), "{status}");

        // A click that leaves zero matches must show the dedicated message.
        let mut empty = VaultViewState::new();
        empty.start_search();
        empty.push_query("missing");
        let empty_status = finish_search_from_row_click(&mut empty, false);
        assert_eq!(empty_status, search_finished_status(0, false));
        assert!(empty_status.contains("0件"), "{empty_status}");
        assert!(!empty_status.contains("入力中"), "{empty_status}");

        // The unsaved marker survives the confirmation.
        let dirty_status = finish_search_from_row_click(&mut view, true);
        assert_eq!(dirty_status, search_finished_status(1, true));
        assert!(dirty_status.contains("[未保存の設定変更があります]"));
    }

    #[::core::prelude::v1::test]
    fn row_click_during_search_replaces_the_no_selection_status_after_selecting() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        fn item(id: &str, name: &str) -> VaultItem {
            VaultItem::new(
                id,
                name,
                ItemData::SecureNote {
                    text: String::new().into(),
                },
            )
        }

        let mut view = VaultViewState::new();
        view.vault.items.push(item("a", "Alpha"));
        view.vault.items.push(item("b", "Beta"));
        view.start_search();
        view.push_query("Beta");
        assert!(view.searching);
        assert_eq!(view.visible_items().len(), 1, "precondition: one match");

        // This is the ordering of `UiAction::SelectRow`: confirm the search,
        // then select the clicked row, then compose the status from the view.
        let stale = finish_search_from_row_click(&mut view, false);
        assert_eq!(stale, crate::ui::logic::no_selection_status());
        assert!(view.select_index(0));
        let status = selected_row_click_status(&view, false);

        assert_eq!(status, "項目を選択しました: Beta", "{status}");
        assert_ne!(status, crate::ui::logic::no_selection_status());
        assert!(!status.contains("入力中"), "{status}");
        assert_eq!(view.selected_id.as_deref(), Some("b"));

        // The unsaved marker survives the replacement just like the stale
        // search-confirmation status did.
        let dirty = selected_row_click_status(&view, true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(&status, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");

        // A click that misses selects nothing, so it must not claim a
        // selection either: the count-based status stays in place.
        let mut out = VaultViewState::new();
        out.vault.items.push(item("a", "Alpha"));
        out.start_search();
        out.push_query("Alpha");
        let confirmation = finish_search_from_row_click(&mut out, false);
        assert!(!out.select_index(3), "precondition: out of range");
        assert_eq!(out.selected_id, None);
        assert_eq!(selected_row_click_status(&out, false), confirmation);
    }

    #[::core::prelude::v1::test]
    fn select_row_index_is_the_visible_render_position() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        fn item(id: &str, name: &str) -> VaultItem {
            VaultItem::new(
                id,
                name,
                ItemData::SecureNote {
                    text: String::new().into(),
                },
            )
        }

        let mut view = VaultViewState::new();
        // Insertion order deliberately differs from the visible (sorted) order:
        // a click index is a position in `visible_items()`, not an item id and
        // not the order the items were added.
        view.vault.items.push(item("zeta", "Zulu"));
        view.vault.items.push(item("alpha", "Alpha"));
        view.vault.items.push(item("mid", "Mid"));

        let visible = view.visible_items();
        assert_eq!(
            visible
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "mid", "zeta"],
            "precondition: index 1 is the sorted middle row"
        );

        // The `ui::render` -> `UiAction::SelectRow` -> `select_index` contract:
        // the drawn index selects the item drawn at that index.
        let visible_len = visible.len();
        let clicked = 1usize;
        let expected_id = visible[clicked].id.clone();
        assert!(view.select_index(clicked));
        assert_eq!(view.selected_id.as_deref(), Some(expected_id.as_str()));
        assert_eq!(view.selected_id.as_deref(), Some("mid"));

        // A repeated click on the same index is not a change: the click path
        // uses this flag to decide whether to scroll.
        let before = view.rewind_calls;
        assert!(!view.select_index(clicked));
        assert_eq!(view.rewind_calls, before, "selection-only must not rewind");

        // An out-of-range draw index is rejected rather than clamped.
        assert!(!view.select_index(visible_len));
        assert_eq!(view.selected_id.as_deref(), Some("mid"));

        // Known limitation (documented in render.rs and keys.rs): the index is
        // not stable across a list snapshot change. Once "alpha" is gone the
        // same numeric index names a different item.
        view.vault.items.remove(1);
        let shifted = view.visible_items();
        assert_eq!(shifted.len(), 2);
        assert_eq!(shifted[clicked].id, "zeta");
        assert!(view.select_index(clicked));
        assert_eq!(view.selected_id.as_deref(), Some("zeta"));
    }

    #[::core::prelude::v1::test]
    fn backspace_after_confirmed_search_updates_the_count_status() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        let mut view = VaultViewState::new();
        view.vault.items.push(VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        view.vault.items.push(VaultItem::new(
            "b",
            "Beta",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        view.start_search();
        // Two characters that match nothing, so one backspace still leaves an
        // empty result set and only the second restores the full list.
        view.push_query("Zq");
        assert_eq!(view.visible_items().len(), 0, "precondition: no matches");
        let confirmed = finish_search_from_row_click(&mut view, false);
        assert!(!view.searching);
        assert_eq!(confirmed, crate::ui::logic::NO_SEARCH_RESULTS_STATUS);

        // One backspace leaves "Z": still zero matches, so the "0件" text is
        // recomputed rather than left stale from the confirmation.
        let before = view.rewind_calls;
        let still_empty = backspace_confirmed_query(&mut view, false);
        assert_eq!(view.query, "Z");
        assert_eq!(view.visible_items().len(), 0);
        assert_eq!(still_empty, search_finished_status(0, false));
        assert_eq!(still_empty, crate::ui::logic::NO_SEARCH_RESULTS_STATUS);
        assert_eq!(view.rewind_calls, before + 1, "each backspace rewinds");

        // The next backspace empties the query: the generic selection prompt
        // replaces the zero-match message.
        let status = backspace_confirmed_query(&mut view, false);
        assert_eq!(view.query, "");
        assert_eq!(view.visible_items().len(), 2);
        assert_eq!(status, search_finished_status(2, false));
        assert_eq!(status, crate::ui::logic::no_selection_status());
        assert!(!status.contains("0件"), "{status}");

        // The unsaved marker is preserved in both count branches.
        view.push_query("Zq");
        let dirty_empty = backspace_confirmed_query(&mut view, true);
        assert_eq!(dirty_empty, search_finished_status(0, true));
        assert!(dirty_empty.contains("[未保存の設定変更があります]"));
        let dirty_found = backspace_confirmed_query(&mut view, true);
        assert_eq!(dirty_found, search_finished_status(2, true));
        assert!(dirty_found.contains("[未保存の設定変更があります]"));
    }

    #[::core::prelude::v1::test]
    fn insert_after_confirmed_search_updates_the_count_status() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        fn item(id: &str) -> VaultItem {
            VaultItem::new(
                id,
                id,
                ItemData::SecureNote {
                    text: String::new().into(),
                },
            )
        }

        let mut view = VaultViewState::new();
        view.vault.items.push(item("Alpha"));
        view.vault.items.push(item("Beta"));
        view.start_search();
        view.push_query("Zq");
        let confirmed = finish_search_from_row_click(&mut view, false);
        assert!(!view.searching);
        assert_eq!(confirmed, crate::ui::logic::NO_SEARCH_RESULTS_STATUS);

        // Appending text refines the confirmed query without re-entering
        // search mode (so `/` can still start a fresh search later).
        let before = view.rewind_calls;
        let still_empty = insert_confirmed_query(&mut view, "x", false);
        assert_eq!(view.query, "Zqx");
        assert!(!view.searching);
        assert_eq!(view.visible_items().len(), 0);
        assert_eq!(still_empty, search_finished_status(0, false));
        assert_eq!(still_empty, crate::ui::logic::NO_SEARCH_RESULTS_STATUS);
        assert_eq!(view.rewind_calls, before + 1, "each query edit rewinds");

        // Once the refined query matches, the "0件" message is replaced and
        // the unsaved marker survives both count branches.
        let mut found = VaultViewState::new();
        found.vault.items.push(item("Alpha"));
        found.vault.items.push(item("Beta"));
        found.start_search();
        found.push_query("Bet");
        finish_search_from_row_click(&mut found, false);
        let status = insert_confirmed_query(&mut found, "a", false);
        assert_eq!(found.query, "Beta");
        assert_eq!(found.visible_items().len(), 1);
        assert_eq!(status, search_finished_status(1, false));
        assert!(!status.contains("0件"), "{status}");

        let dirty_empty = insert_confirmed_query(&mut view, "y", true);
        assert_eq!(dirty_empty, search_finished_status(0, true));
        assert!(dirty_empty.contains("[未保存の設定変更があります]"));
    }

    #[::core::prelude::v1::test]
    fn generator_and_settings_panels_keep_up_down_unbound() {
        // Only the vault list and audit panel own a scroll handle; generator
        // and settings must not turn Up/Down into a hidden list selection.
        for panel in [Panel::Generator, Panel::Settings] {
            for key in ["up", "down", "arrowup", "arrowdown", "pageup", "pagedown"] {
                assert_eq!(
                    classify_key(&context(Screen::Unlocked, panel, key)),
                    UiAction::None,
                    "{panel:?}/{key}"
                );
            }
        }
        // The vault list still owns the same keys, so this is panel-local.
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "up")),
            UiAction::MoveSelection(-1)
        );
    }

    #[::core::prelude::v1::test]
    fn page_move_rows_is_a_multi_row_step() {
        const { assert!(PAGE_MOVE_ROWS > 1, "a page key must move more than one row") };
        assert_eq!(PAGE_MOVE_ROWS, 10);

        for (key, direction) in [("pageup", -1), ("pagedown", 1)] {
            for panel in [Panel::Vault, Panel::Audit] {
                assert_eq!(
                    classify_key(&context(Screen::Unlocked, panel, key)),
                    UiAction::MoveSelectionPage(direction),
                    "{panel:?}/{key}"
                );
            }
        }
    }

    #[::core::prelude::v1::test]
    fn page_move_hint_documents_the_fixed_row_count() {
        // GPUI does not expose the live visible-row count here, so the wording
        // must promise a fixed step rather than a viewport-sized page.
        assert_eq!(PAGE_MOVE_ROWS, 10);
        assert!(
            PAGE_MOVE_FIXED_ROWS_HINT.contains("固定10行"),
            "{PAGE_MOVE_FIXED_ROWS_HINT}"
        );
        assert!(
            PAGE_MOVE_FIXED_ROWS_HINT.contains("表示行数"),
            "{PAGE_MOVE_FIXED_ROWS_HINT}"
        );
    }

    #[::core::prelude::v1::test]
    fn edge_move_delta_handles_empty_and_missing_selections() {
        assert_eq!(edge_move_delta(None, 0, SelectionEdge::First), None);
        assert_eq!(edge_move_delta(None, 0, SelectionEdge::Last), None);
        assert_eq!(edge_move_delta(Some(0), 0, SelectionEdge::Last), None);

        // With no selection the shared move helpers use the delta's sign only.
        assert_eq!(edge_move_delta(None, 5, SelectionEdge::First), Some(0));
        assert_eq!(edge_move_delta(None, 5, SelectionEdge::Last), Some(-1));

        // With a selection, the delta is the exact distance to the edge and a
        // stale out-of-range index is clamped before the distance is computed.
        assert_eq!(edge_move_delta(Some(3), 5, SelectionEdge::First), Some(-3));
        assert_eq!(edge_move_delta(Some(1), 5, SelectionEdge::Last), Some(3));
        assert_eq!(edge_move_delta(Some(3), 5, SelectionEdge::Last), Some(1));
        assert_eq!(edge_move_delta(Some(99), 5, SelectionEdge::Last), Some(0));
    }

    #[::core::prelude::v1::test]
    fn edge_delta_selects_the_expected_row_through_the_shared_move_path() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        let mut view = VaultViewState::new();
        for id in ["a", "b", "c", "d"] {
            view.vault.items.push(VaultItem::new(
                id,
                id,
                ItemData::SecureNote {
                    text: String::new().into(),
                },
            ));
        }
        let visible = view.visible_items();
        assert_eq!(visible.len(), 4, "precondition: four visible rows");

        // No selection: the sign-only branch still reaches the chosen edge.
        let delta = edge_move_delta(None, visible.len(), SelectionEdge::Last)
            .expect("four rows are selectable");
        assert_eq!(view.next_index_in(&visible, delta), Some(3));
        let delta = edge_move_delta(None, visible.len(), SelectionEdge::First)
            .expect("four rows are selectable");
        assert_eq!(view.next_index_in(&visible, delta), Some(0));

        // With a selection in the middle the exact distance lands on the edge
        // in one step, not one row away.
        view.select_index(1);
        let visible = view.visible_items();
        let delta = edge_move_delta(Some(1), visible.len(), SelectionEdge::Last)
            .expect("four rows are selectable");
        assert_eq!(delta, 2);
        assert_eq!(view.next_index_in(&visible, delta), Some(3));
        let delta = edge_move_delta(Some(1), visible.len(), SelectionEdge::First)
            .expect("four rows are selectable");
        assert_eq!(delta, -1);
        assert_eq!(view.next_index_in(&visible, delta), Some(0));
    }

    #[::core::prelude::v1::test]
    fn edge_delta_also_drives_the_audit_row_clamp() {
        let next_audit = crate::ui::app::next_audit_row;
        for (edge, expected) in [
            (SelectionEdge::First, Some(0)),
            (SelectionEdge::Last, Some(2)),
        ] {
            let delta = edge_move_delta(None, 3, edge).expect("three rows exist");
            assert_eq!(next_audit(None, delta, 3), expected, "{edge:?}");
        }

        let delta = edge_move_delta(Some(1), 3, SelectionEdge::Last).expect("three rows exist");
        assert_eq!(next_audit(Some(1), delta, 3), Some(2));

        // A stale highlight past the end is clamped by the shared helper too.
        let delta = edge_move_delta(Some(99), 3, SelectionEdge::Last).expect("three rows exist");
        assert_eq!(delta, 0);
        assert_eq!(next_audit(Some(99), delta, 3), Some(2));
    }

    #[::core::prelude::v1::test]
    fn focus_recovery_key_is_recognised() {
        assert!(is_focus_recovery_key(FOCUS_RECOVERY_KEY));
        assert!(is_focus_recovery_key("f1"));
        assert!(!is_focus_recovery_key("F1"));
        assert!(!is_focus_recovery_key("f2"));
        assert!(!is_focus_recovery_key(""));
    }

    #[::core::prelude::v1::test]
    fn focus_recovery_key_never_changes_normal_classification() {
        // Every screen and panel must keep mapping the dedicated recovery key
        // to `None`, so the global observer cannot trigger a UI action.
        let mut contexts = vec![
            context(Screen::Locked, Panel::Vault, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Audit, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Generator, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Settings, FOCUS_RECOVERY_KEY),
        ];
        // Editing modes (search, auth field, settings field) as well.
        let mut searching = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        searching.searching = true;
        contexts.push(searching);
        let mut editing_auth = context(Screen::Locked, Panel::Vault, FOCUS_RECOVERY_KEY);
        editing_auth.editing_auth = true;
        contexts.push(editing_auth);
        let mut editing_settings = context(Screen::Unlocked, Panel::Settings, FOCUS_RECOVERY_KEY);
        editing_settings.editing_settings = true;
        contexts.push(editing_settings);

        for ctx in &contexts {
            assert_eq!(
                classify_key(ctx),
                UiAction::None,
                "the recovery key must stay inert in {ctx:?}"
            );
        }

        // A stray `key_char` must not turn F1 into inserted text either.
        let mut with_char = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        with_char.key_char = Some("\u{f1}");
        assert_eq!(classify_key(&with_char), UiAction::None);

        // Sanity check: the helper only fires for the dedicated key, and a
        // normal command key stays classified as before.
        assert!(!is_focus_recovery_key("l"));
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "l")),
            UiAction::Lock
        );
    }
}
