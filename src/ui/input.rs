//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`crate::ui::keys`] module; this file
//! only applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::keys::{
    classify_key, GeneratorOption, KeyContext, KeyModifiers, SelectionEdge, UiAction,
    TEXT_EDIT_ARROW_KEYS_HINT,
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
/// Backends report function keys with differing ASCII case (`"f1"` or `"F1"`),
/// so the comparison normalises ASCII case while staying deliberately narrow:
/// non-ASCII lookalikes and other key names never recover focus. The global
/// observer in `install_focus_recovery` passes `event.keystroke.key` straight
/// through, so an exact comparison silently disabled recovery on uppercase
/// backends. Kept as a pure helper so the invariant that this key is inert in
/// the normal key classification can be exercised without a GPUI window.
pub(super) fn is_focus_recovery_key(key: &str) -> bool {
    key.eq_ignore_ascii_case(FOCUS_RECOVERY_KEY)
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

/// Base text of the status written when an edge key is pressed on an empty list.
///
/// [`edge_move_delta`] returns `None` for a zero-length list, so the dispatcher
/// has no selection to move. Without an explicit status the whole keypress was
/// silently dropped and looked dead to keyboard users. The wording names the
/// missing rows rather than pretending a move happened, and mirrors the other
/// transient statuses by preserving the persistent unsaved marker.
pub(super) const NO_ROWS_MESSAGE: &str = "行がありません（移動できません）";

/// Status for a `Home`/`End` press on an empty list.
///
/// Kept pure so the wording and the unsaved-marker contract can be tested
/// without a GPUI window. Both the vault and the audit branch of
/// `move_selection_to_edge` use it whenever [`edge_move_delta`] yields `None`.
pub(super) fn no_rows_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(NO_ROWS_MESSAGE, dirty)
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
/// The wording lives in `crate::ui::app::AUDIT_UNAVAILABLE_MESSAGE` so the
/// keyboard `g` path and the mouse audit tab in `ui::render` share one literal.
/// This alias keeps the existing `ui::input` name without a second copy.
pub(super) const AUDIT_UNAVAILABLE_MESSAGE: &str = crate::ui::app::AUDIT_UNAVAILABLE_MESSAGE;

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

/// Count-only vault status restored after a confirmed search.
///
/// Confirming a search clears the selection and rewinds the list (see
/// `VaultViewState::finish_search`), so the restored status matches the detail
/// line's "nothing selected" state instead of claiming a selection survives.
/// With zero matches that generic prompt would point at a row that does not
/// exist, so the confirmed result count selects a dedicated message instead.
///
/// This form is for callers that only know the result count (for example
/// `ui::app::panel_transition_status_after_edit`). The count alone cannot tell
/// whether a confirmed query still exists: once Backspace removes its last
/// character the re-edit keys are no longer bound, so a count-only caller must
/// not advertise [`crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT`]. Callers that
/// own a `VaultViewState` use [`search_finished_status_for_view`], the single
/// view-derived composer that adds the hint only while the query is non-empty.
///
/// Kept as the count-only entry point for cross-module callers; the allowance
/// covers a future caller switching to the view-derived form entirely.
#[allow(dead_code)]
pub(super) fn search_finished_status(result_count: usize, dirty: bool) -> String {
    search_finished_status_with_query(false, result_count, dirty)
}

/// Query-aware form of [`search_finished_status`].
///
/// The re-edit hint is only meaningful while a confirmed query exists. Once
/// Backspace removes its last character, typed characters return to their
/// normal vault commands and there is nothing left to re-edit; keeping the
/// hint on screen would name keys that no longer edit a query. The
/// count-dependent base message and the unsaved marker are unchanged in both
/// branches.
pub(super) fn search_finished_status_with_query(
    query_nonempty: bool,
    result_count: usize,
    dirty: bool,
) -> String {
    let base = crate::ui::logic::no_selection_status_for_count(result_count);
    let text = if query_nonempty {
        format!("{base} / {}", crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT)
    } else {
        base
    };
    text_edit_finished_status(&text, dirty)
}

/// Whether a query still carries visible content.
///
/// Shared by the confirmed-search status and by [`BitwardenApp::key_down`]'s
/// `KeyContext`: both must use the same `crate::ui::app::is_visually_empty`
/// rule as the header placeholder in `ui::render`. A query made only of
/// whitespace and invisible `Cf` characters renders as "(なし)", so it must
/// neither advertise the re-edit keys nor keep Backspace/typed text bound to
/// query editing. `key_down` used a raw `is_empty()` check, which made such a
/// query look like an active editing session in classification alone
/// (R2-UI-127).
pub(super) fn confirmed_query_nonempty(query: &str) -> bool {
    !crate::ui::app::is_visually_empty(query)
}

/// Compose the confirmed-search status from a view's live query and result set.
///
/// Every query edit goes through a `VaultViewState`, so deriving both inputs
/// here prevents one path from forgetting to re-check whether the query is
/// still non-empty. Emptiness goes through [`confirmed_query_nonempty`], the
/// same rule [`BitwardenApp::key_down`] uses to classify the re-edit keys: an
/// invisible-only query is shown as "(なし)" in the header and must not
/// advertise those keys here either.
pub(super) fn search_finished_status_for_view(
    view: &crate::ui::vault_view::VaultViewState,
    dirty: bool,
) -> String {
    search_finished_status_with_query(
        confirmed_query_nonempty(&view.query),
        view.visible_items().len(),
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
    search_finished_status_for_view(view, dirty)
}

/// Status naming the vault row that is currently selected.
///
/// Both the mouse click path and the keyboard move path must report the same
/// row name; keeping the lookup in one pure helper prevents them from drifting.
/// Returns `None` when nothing is selected (for example an empty list), so the
/// caller keeps its current status instead of claiming a selection that did
/// not happen.
///
/// The name goes through [`crate::ui::app::item_name_text`], the same helper
/// the list row and detail row use, so an empty or invisible-only (`Cf`) name
/// shows the placeholder instead of leaving a blank after "選択しました: ".
pub(super) fn selected_row_status(
    view: &crate::ui::vault_view::VaultViewState,
    dirty: bool,
) -> Option<String> {
    let visible = view.visible_items();
    view.selected_id
        .as_deref()
        .and_then(|id| visible.iter().find(|item| item.id == id))
        .map(|item| {
            crate::ui::app::status_with_unsaved(
                &format!(
                    "項目を選択しました: {}",
                    crate::ui::app::item_name_text(&item.name)
                ),
                dirty,
            )
        })
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
    selected_row_status(view, dirty).unwrap_or_else(|| search_finished_status_for_view(view, dirty))
}

/// Status the `SelectRow` action leaves on screen.
///
/// A click that selected a row always reports that row, whether or not it also
/// confirmed a search: a plain click used to leave the previous status in
/// place. `confirmation` is the status computed while leaving search mode
/// (before the selection existed); it is reused when the click missed, and
/// `None` on a plain click means the existing status stays untouched. Kept
/// pure so the wiring can be asserted without a GPUI window.
pub(super) fn row_click_status(
    view: &crate::ui::vault_view::VaultViewState,
    dirty: bool,
    confirmation: Option<String>,
    selected: bool,
) -> Option<String> {
    if selected {
        Some(selected_row_click_status(view, dirty))
    } else {
        confirmation
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
    // After the last character is removed there is no confirmed query left to
    // re-edit, so the re-edit keys must disappear from the status as well.
    search_finished_status_for_view(view, dirty)
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
    search_finished_status_for_view(view, dirty)
}

/// Status after a settings time field is adjusted with `i`/`u`, `3`/`4` or
/// `5`/`6`.
///
/// The threshold keys already report through `refresh_audit`, but these three
/// branches previously changed the settings without touching the status bar,
/// leaving whatever the last action had written on screen. `unit` is `分` for
/// the idle auto-lock timeout (`i`/`u`, which moves in one-minute steps, see
/// [`crate::ui::logic::adjust_idle_lock`]) and `秒数` for the genuinely
/// seconds-based `3`-`6` fields. `value_text` is the post-adjustment value in
/// that same unit, so the status reports the new setting instead of only
/// saying that something changed. Kept pure so the wording can be tested
/// without a GPUI window.
pub(super) fn time_adjust_status(unit: &str, value_text: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(
        &format!("{unit}を変更しました: {value_text}（w: 保存 / d: 破棄）"),
        dirty,
    )
}

/// Status after `i`/`u` adjusts the minute-based idle auto-lock timeout.
///
/// The stored value is seconds while the settings panel shows minutes, so the
/// panel's formatter is reused rather than truncating a non-whole minute.
pub(super) fn idle_lock_adjust_status(idle_lock_seconds: u64, dirty: bool) -> String {
    time_adjust_status(
        "分",
        &crate::ui::app::idle_lock_minutes_text(idle_lock_seconds),
        dirty,
    )
}

/// Status after `3`-`6` adjusts a seconds-based settings field.
pub(super) fn seconds_adjust_status(seconds: u64, dirty: bool) -> String {
    time_adjust_status("秒数", &format!("{seconds}秒"), dirty)
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

/// Final composer for statuses written by the copy/generation helpers.
///
/// `ui::actions` owns those helpers and writes a plain base status; it cannot
/// depend on this module, so the dispatcher applies the persistent unsaved
/// marker once the action has run. An already present marker is stripped first
/// so the composition stays correct if a helper starts writing one later.
pub(super) fn action_status_with_unsaved(status: &str, dirty: bool) -> String {
    let base = status
        .strip_suffix(crate::ui::app::unsaved_status_suffix(true))
        .unwrap_or(status);
    crate::ui::app::status_with_unsaved(base, dirty)
}

/// Description of the generator value changed by `option`.
///
/// Read from the settings *after* the key was applied so the status can name
/// the new value, not just announce that a change happened. Length keys move
/// two values at once (see `keys::apply_generator_key`), so both are reported;
/// toggles report the affected flag and `Separator` reuses the panel's label.
/// Kept pure so the wording can be tested without a GPUI window.
pub(super) fn generator_value_text(
    settings: &crate::settings::Settings,
    option: GeneratorOption,
) -> String {
    use GeneratorOption::*;
    let password = &settings.password_generator;
    let passphrase = &settings.passphrase_generator;
    let enabled = |value: bool| if value { "有効" } else { "無効" };
    match option {
        LengthUp | LengthDown => format!(
            "パスワード {} 文字 / パスフレーズ {} 語",
            password.length, passphrase.words
        ),
        Lowercase => format!("英小文字: {}", enabled(password.lowercase)),
        Uppercase => format!("英大文字: {}", enabled(password.uppercase)),
        Digits => format!("数字: {}", enabled(password.digits)),
        Symbols => format!("記号: {}", enabled(password.symbols)),
        AvoidAmbiguous => format!(
            "紛らわしい文字を除外: {}",
            enabled(password.avoid_ambiguous)
        ),
        Capitalize => format!("先頭大文字: {}", enabled(passphrase.capitalize)),
        IncludeNumber => format!("数字を含める: {}", enabled(passphrase.include_number)),
        Separator => format!(
            "区切り: {}",
            crate::ui::panels::separator_label(&passphrase.separator)
        ),
    }
}

/// Status after a generator option actually changed the stored settings.
///
/// The action helper in `ui::actions` writes its own text, which the dispatcher
/// replaces with this standard settings status so the persistent unsaved
/// marker survives and the wording matches the other adjustment keys.
/// `value_text` carries the post-adjustment value from
/// [`generator_value_text`].
pub(super) fn generator_adjust_status(value_text: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(
        &format!("生成設定を変更しました: {value_text}（w: 保存 / d: 破棄）"),
        dirty,
    )
}

/// Status after `+`/`-` adjusts the audit thresholds.
///
/// `refresh_audit` intentionally keeps the settings panel's own status (see
/// `audit_refresh_status_for_panel`), so the threshold keys need their own
/// feedback just like the other settings-adjustment keys. Both post-adjustment
/// threshold values are included so the user can see what the new limits are.
/// Kept pure so the wording can be tested without a GPUI window.
pub(super) fn threshold_adjust_status(
    thresholds: crate::health::Thresholds,
    dirty: bool,
) -> String {
    crate::ui::app::status_with_unsaved(
        &format!(
            "監査閾値を変更しました: 弱パスワード < {} bit / 更新が古い: {} 日以上（w: 保存 / d: 破棄）",
            thresholds.weak_bits, thresholds.stale_days
        ),
        dirty,
    )
}

/// Outcome of a clamped settings adjustment.
///
/// Every `logic::adjust_*` helper clamps its result, so pressing a key at a
/// boundary can leave the stored value identical to the previous one. In that
/// case the caller must not announce "変更しました" nor mark the settings
/// unsaved: `changed` is derived from the before/after values, not from the
/// key that was pressed. It must still announce the clamp boundary (see
/// [`clamp_boundary_status`]) so the keypress is not silently dropped.
/// Factored out here (rather than inline in the GPUI dispatcher) so the
/// boundary contract is testable without a GPUI window.
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

/// Whether a generator key would actually change a stored value.
///
/// `keys::apply_generator_key` clamps `LengthUp`/`LengthDown`, so pressing `+`
/// at the maximum leaves both lengths as they were. Like [`Adjustment::new`]
/// for the settings keys, the dispatcher must derive "changed" from the
/// before/after values: a clamped step must neither announce a change nor mark
/// the settings unsaved, but must report the boundary instead. Applying the
/// same pure helper to a clone is deterministic, so the real action can still
/// own the state mutation.
pub(super) fn generator_key_changes(
    settings: &crate::settings::Settings,
    option: GeneratorOption,
) -> bool {
    let mut candidate = settings.clone();
    crate::ui::keys::apply_generator_key(&mut candidate, option);
    candidate.password_generator != settings.password_generator
        || candidate.passphrase_generator != settings.passphrase_generator
}

/// The clamp bound a key press pushed against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClampEdge {
    Upper,
    Lower,
}

/// Which bound a settings delta pushes towards.
///
/// All adjustment keys move by a single step in the sign's direction, so a
/// clamped positive step has hit the upper bound and a clamped negative step
/// the lower one.
pub(super) fn clamp_edge_for_delta(delta: i32) -> ClampEdge {
    if delta > 0 {
        ClampEdge::Upper
    } else {
        ClampEdge::Lower
    }
}

/// Only the length keys can be clamped; every generator toggle always changes
/// a value, so it can never reach this status.
pub(super) fn generator_clamp_edge(option: GeneratorOption) -> Option<ClampEdge> {
    match option {
        GeneratorOption::LengthUp => Some(ClampEdge::Upper),
        GeneratorOption::LengthDown => Some(ClampEdge::Lower),
        _ => None,
    }
}

/// Status for a settings key whose value was already at its clamp bound.
///
/// A clamped key leaves every stored value untouched, but staying silent made
/// the keypress look dropped. The message names the bound and the affected
/// setting while preserving the persistent unsaved marker (earlier edits may
/// still be pending). It deliberately does not mark the settings dirty.
pub(super) fn clamp_boundary_status(label: &str, edge: ClampEdge, dirty: bool) -> String {
    let base = match edge {
        ClampEdge::Upper => format!("{label}は既に上限です（これ以上増やせません）"),
        ClampEdge::Lower => format!("{label}は既に下限です（これ以上減らせません）"),
    };
    crate::ui::app::status_with_unsaved(&base, dirty)
}

pub(super) fn threshold_boundary_status(delta: i32, dirty: bool) -> String {
    clamp_boundary_status("監査閾値", clamp_edge_for_delta(delta), dirty)
}

pub(super) fn idle_lock_boundary_status(delta: i32, dirty: bool) -> String {
    clamp_boundary_status("自動ロック", clamp_edge_for_delta(delta), dirty)
}

pub(super) fn seconds_boundary_status(label: &str, delta: i32, dirty: bool) -> String {
    clamp_boundary_status(label, clamp_edge_for_delta(delta), dirty)
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
            self.report_keyboard_selection(cx);
        } else {
            // `edge_move_delta` only returns `None` for a zero-length list.
            // Moving is impossible there, but a keypress must still produce
            // feedback; otherwise Home/End are the only silent list keys.
            self.status = no_rows_status(self.settings_dirty);
            cx.notify();
        }
    }

    /// Announce the row chosen by an Up/Down/Page/Home/End key.
    ///
    /// `BitwardenApp::move_selection` owns the selection and the scroll, but
    /// the vault branch never wrote to the status bar, so keyboard users had
    /// no on-screen confirmation of which row was highlighted while a mouse
    /// click already reported its name. Only the vault branch is handled here:
    /// on the audit panel `move_selection` delegates to `move_audit_selection`,
    /// which installs its own row description and must not be overwritten.
    fn report_keyboard_selection(&mut self, cx: &mut Context<Self>) {
        if crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some())
            == Panel::Audit
        {
            return;
        }
        if let Some(status) = selected_row_status(&self.view, self.settings_dirty) {
            self.status = status;
            cx.notify();
        }
    }

    /// Run a copy/generation helper from `ui::actions`, then keep the unsaved
    /// marker on the status it wrote. The helper owns the clipboard and
    /// generator work; this dispatcher owns marker composition.
    fn run_status_action<F>(&mut self, cx: &mut Context<Self>, action: F)
    where
        F: FnOnce(&mut Self, &mut Context<Self>),
    {
        let dirty = self.settings_dirty;
        action(self, &mut *cx);
        self.status = action_status_with_unsaved(&self.status, dirty);
        cx.notify();
    }

    /// Copy the selected TOTP code with the detail row's "なし" rule.
    ///
    /// A blank or Unicode `Cf`-only secret has no visible content, so copying
    /// must not send it to generation and report a parse failure. No selection
    /// keeps its own status, exactly like `ui::actions::copy_totp`.
    fn copy_totp_with_status(&mut self, cx: &mut Context<Self>) {
        let secret = {
            let visible = self.view.visible_items();
            crate::ui::logic::required_item_index(self.view.selected_id.as_deref(), &visible)
                .map(|index| visible[index].totp_secret().unwrap_or("").to_string())
        };
        let Some(secret) = secret else {
            self.status = crate::ui::app::status_with_unsaved(
                crate::ui::logic::no_selection_status(),
                self.settings_dirty,
            );
            cx.notify();
            return;
        };
        if let Some(status) =
            crate::ui::app::totp_copy_absent_status_for(&secret, self.settings_dirty)
        {
            self.status = status;
            cx.notify();
            return;
        }
        self.run_status_action(cx, Self::copy_totp);
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
            // Same visual rule as the confirmed-search status and the header
            // placeholder: an invisible-only query is not an active re-edit
            // session, so Backspace and typed text stay vault commands.
            query_nonempty: confirmed_query_nonempty(&self.view.query),
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
                // Same contract as the auth field: confirmation is not still
                // an editing session, so restore the normal vault status. The
                // view still owns the query, so derive both the "no matches"
                // wording and the re-edit hint from it (no hint when empty).
                self.status = search_finished_status_for_view(&self.view, self.settings_dirty);
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
            UiAction::MoveSelection(delta) => {
                self.move_selection(delta, cx);
                self.report_keyboard_selection(cx);
            }
            UiAction::MoveSelectionPage(direction) => {
                // Direction comes from the classifier as -1/+1; saturating
                // multiplication keeps an extreme value from overflowing.
                self.move_selection(direction.saturating_mul(PAGE_MOVE_ROWS), cx);
                self.report_keyboard_selection(cx);
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
            UiAction::GeneratePassword => self.run_status_action(cx, Self::generate_password),
            UiAction::GeneratePassphrase => self.run_status_action(cx, Self::generate_passphrase),
            UiAction::CopyPassword => {
                if let Some(value) = self.generator.last_password.clone() {
                    self.run_status_action(cx, |this, cx| this.copy_to_clipboard(&value, cx));
                } else {
                    self.status = no_generated_copy_status("パスワード", self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::CopyPassphrase => {
                if let Some(value) = self.generator.last_passphrase.clone() {
                    self.run_status_action(cx, |this, cx| this.copy_to_clipboard(&value, cx));
                } else {
                    self.status = no_generated_copy_status("パスフレーズ", self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::CopyTotp => self.copy_totp_with_status(cx),
            UiAction::CopySelectedPassword => {
                self.run_status_action(cx, |this, cx| this.copy_selected_field(true, cx))
            }
            UiAction::CopySelectedUsername => {
                self.run_status_action(cx, |this, cx| this.copy_selected_field(false, cx))
            }
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
                if adjustment.changed {
                    self.mark_settings_dirty();
                    self.refresh_audit();
                    // Set the status *after* the refresh: on settings panels
                    // the refresh keeps the previous status, and on other
                    // panels this feedback must win over an audit-row
                    // description.
                    self.status =
                        threshold_adjust_status(self.settings.thresholds, self.settings_dirty);
                    cx.notify();
                } else {
                    // A clamped step changes nothing: do not mark the settings
                    // dirty and skip `refresh_audit`, which could overwrite
                    // the status with an audit-row description on other
                    // panels. Still explain why the key did nothing.
                    self.status = threshold_boundary_status(delta, self.settings_dirty);
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
                    self.status = idle_lock_adjust_status(
                        self.settings.idle_lock_seconds,
                        self.settings_dirty,
                    );
                    cx.notify();
                } else {
                    self.status = idle_lock_boundary_status(delta, self.settings_dirty);
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
                    self.status = seconds_adjust_status(
                        self.settings.login_timeout_seconds,
                        self.settings_dirty,
                    );
                    cx.notify();
                } else {
                    self.status =
                        seconds_boundary_status("ログイン制限", delta, self.settings_dirty);
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
                    self.status = seconds_adjust_status(
                        self.settings.clipboard_restore_seconds,
                        self.settings_dirty,
                    );
                    cx.notify();
                } else {
                    self.status = seconds_boundary_status("復元", delta, self.settings_dirty);
                    cx.notify();
                }
            }
            UiAction::Generator(option) => {
                if generator_key_changes(&self.settings, option) {
                    self.toggle_generator(option, cx);
                    self.status = generator_adjust_status(
                        &generator_value_text(&self.settings, option),
                        self.settings_dirty,
                    );
                    cx.notify();
                } else if let Some(edge) = generator_clamp_edge(option) {
                    self.status = clamp_boundary_status("生成設定", edge, self.settings_dirty);
                    cx.notify();
                }
            }
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
                // On a plain click there is no confirmation status, but a
                // successful selection still has to be reported on screen.
                let confirmation = if self.view.searching {
                    Some(finish_search_from_row_click(
                        &mut self.view,
                        self.settings_dirty,
                    ))
                } else {
                    None
                };
                let selected = self.view.select_index(index);
                if selected {
                    self.view
                        .scroll_handle
                        .scroll_to_item(index, gpui_kit::ScrollStrategy::Nearest);
                }
                if let Some(status) =
                    row_click_status(&self.view, self.settings_dirty, confirmation, selected)
                {
                    self.status = status;
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
        // The base text is the single shared constant also used by the mouse
        // audit tab in `ui::render::audit_unavailable_status`.
        let base = AUDIT_UNAVAILABLE_MESSAGE;
        assert_eq!(base, crate::ui::app::AUDIT_UNAVAILABLE_MESSAGE);
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
        let clean = seconds_adjust_status(31, false);
        assert_eq!(clean, "秒数を変更しました: 31秒（w: 保存 / d: 破棄）");
        assert!(!clean.contains("[未保存"), "{clean}");

        // The seconds-based 3/4 and 5/6 branches mark the settings dirty
        // before writing the status, so the unsaved marker must survive.
        let dirty = seconds_adjust_status(31, true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");
    }

    #[::core::prelude::v1::test]
    fn idle_lock_adjust_status_reports_minutes_not_seconds() {
        let clean = idle_lock_adjust_status(360, false);
        assert_eq!(clean, "分を変更しました: 6分（w: 保存 / d: 破棄）");
        assert!(!clean.contains("秒"), "{clean}");

        let dirty = idle_lock_adjust_status(360, true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");

        // The 3-6 fields really are seconds-based and keep their wording.
        assert_eq!(
            seconds_adjust_status(31, false),
            "秒数を変更しました: 31秒（w: 保存 / d: 破棄）"
        );
        assert!(!seconds_adjust_status(31, false).contains("分を変更"));
    }

    #[::core::prelude::v1::test]
    fn idle_lock_keys_route_to_the_minute_status() {
        for (key, delta) in [("i", 1), ("u", -1)] {
            let ctx = context(Screen::Unlocked, Panel::Settings, key);
            assert_eq!(classify_key(&ctx), UiAction::AdjustIdleLock(delta));
            assert!(
                idle_lock_adjust_status(360, true).contains("分を変更しました"),
                "{key} must report minutes, not seconds"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn threshold_adjust_status_reports_the_change_and_unsaved_marker() {
        let thresholds = crate::health::Thresholds {
            weak_bits: 45,
            stale_days: 395,
        };
        let clean = threshold_adjust_status(thresholds, false);
        assert_eq!(
            clean,
            "監査閾値を変更しました: 弱パスワード < 45 bit / 更新が古い: 395 日以上（w: 保存 / d: 破棄）"
        );
        assert!(!clean.contains("[未保存"), "{clean}");

        // The branch marks the settings dirty before writing the status.
        let dirty = threshold_adjust_status(thresholds, true);
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
        // marker; it reports the boundary instead.
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

            let search = search_finished_status_with_query(true, 3, dirty);
            assert_eq!(
                search,
                crate::ui::app::status_with_unsaved(
                    &format!(
                        "{} / {}",
                        crate::ui::logic::no_selection_status_for_count(3),
                        crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                    ),
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
            let empty = search_finished_status_with_query(true, 0, dirty);
            assert_eq!(
                empty,
                crate::ui::app::status_with_unsaved(
                    &format!(
                        "{} / {}",
                        crate::ui::logic::NO_SEARCH_RESULTS_STATUS,
                        crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                    ),
                    dirty
                )
            );
            assert!(!empty.contains("項目を選択してください"), "{empty}");
        }
    }

    #[::core::prelude::v1::test]
    fn confirmed_search_status_guides_the_requery_keys() {
        // Enter/Escape keep the query, and the vault panel rebinds Backspace
        // and typed text to edit it. The restored status must say so for both
        // the "select a row" and the "no matches" cases, clean or dirty.
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
        assert!(hint.contains("Backspace"));
        assert!(hint.contains("文字入力"));

        for count in [0, 1, 7] {
            for dirty in [false, true] {
                let status = search_finished_status_with_query(true, count, dirty);
                assert!(
                    status.contains(hint),
                    "count {count}, dirty {dirty}: {status}"
                );
                assert!(
                    status
                        .contains(crate::ui::logic::no_selection_status_for_count(count).as_str()),
                    "count {count}, dirty {dirty}: {status}"
                );
                assert_eq!(
                    status.contains("[未保存の設定変更があります]"),
                    dirty,
                    "{status}"
                );
            }
        }
    }

    #[::core::prelude::v1::test]
    fn confirmed_status_hints_only_while_a_query_exists() {
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
        for count in [0, 2] {
            for dirty in [false, true] {
                let base = crate::ui::logic::no_selection_status_for_count(count);
                let with_query = search_finished_status_with_query(true, count, dirty);
                assert_eq!(
                    with_query,
                    crate::ui::app::status_with_unsaved(&format!("{base} / {hint}"), dirty)
                );

                let without_query = search_finished_status_with_query(false, count, dirty);
                assert_eq!(
                    without_query,
                    crate::ui::app::status_with_unsaved(&base, dirty)
                );
                assert!(!without_query.contains(hint), "{without_query}");
                assert_eq!(
                    without_query.contains("[未保存の設定変更があります]"),
                    dirty,
                    "{without_query}"
                );
            }
        }
    }

    #[::core::prelude::v1::test]
    fn confirmed_search_with_an_invisible_query_drops_the_reedit_hint() {
        // R2-UI-122: `vault_search_query_text` in render.rs shows "(なし)" for a
        // visually empty query, while this status used a raw `is_empty()` check
        // and still advertised the re-edit keys. Both now share the same rule.
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
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;

        for query in ["", "  \t", "\u{200b}", "\u{202e}"] {
            assert!(
                crate::ui::app::is_visually_empty(query),
                "precondition: {query:?}"
            );
            view.query = query.to_string();
            for dirty in [false, true] {
                let status = search_finished_status_for_view(&view, dirty);
                assert!(!status.contains(hint), "{query:?}, dirty {dirty}: {status}");
                let base =
                    crate::ui::logic::no_selection_status_for_count(view.visible_items().len());
                assert_eq!(status, crate::ui::app::status_with_unsaved(&base, dirty));
                assert_eq!(
                    status.contains("[未保存の設定変更があります]"),
                    dirty,
                    "{status}"
                );
            }
        }

        // A query with visible content keeps the re-edit hint as before.
        view.query = "Alpha".to_string();
        for dirty in [false, true] {
            let status = search_finished_status_for_view(&view, dirty);
            assert!(status.contains(hint), "dirty {dirty}: {status}");
            assert_eq!(
                status,
                search_finished_status_with_query(true, view.visible_items().len(), dirty)
            );
        }
    }

    #[::core::prelude::v1::test]
    fn confirmed_query_nonempty_unifies_status_and_key_classification() {
        // R2-UI-127: an invisible-only query is rendered as "(なし)" and the
        // status drops the re-edit hint, but `key_down` used a raw `is_empty()`
        // check. That kept Backspace and typed text bound to query editing in
        // key classification alone. Both paths now share this one helper.
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
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;

        for query in ["", "  \t", "\u{200b}", "\u{202e}", "\u{feff}"] {
            assert!(crate::ui::app::is_visually_empty(query), "{query:?}");
            view.query = query.to_string();
            assert!(!confirmed_query_nonempty(&view.query), "{query:?}");

            // Status path: no re-edit hint for a visually empty query.
            let status = search_finished_status_for_view(&view, false);
            assert!(!status.contains(hint), "{query:?}: {status}");

            // Classification path: the `KeyContext` `key_down` now builds with
            // the same flag must not enter the editing branches either.
            let mut ctx = context(Screen::Unlocked, Panel::Vault, "backspace");
            ctx.query_nonempty = confirmed_query_nonempty(&view.query);
            assert_eq!(classify_key(&ctx), UiAction::None, "{query:?}");
            ctx.key = "a";
            assert_eq!(classify_key(&ctx), UiAction::None, "{query:?}");
        }

        for query in ["Alpha", " a ", "a\u{200b}"] {
            view.query = query.to_string();
            assert!(confirmed_query_nonempty(&view.query), "{query:?}");

            let status = search_finished_status_for_view(&view, false);
            assert!(status.contains(hint), "{query:?}: {status}");

            let mut ctx = context(Screen::Unlocked, Panel::Vault, "backspace");
            ctx.query_nonempty = confirmed_query_nonempty(&view.query);
            assert_eq!(classify_key(&ctx), UiAction::BackspaceQuery, "{query:?}");
            ctx.key = "a";
            assert_eq!(
                classify_key(&ctx),
                UiAction::InsertQueryText("a".into()),
                "{query:?}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn count_only_search_status_never_claims_a_reedit_query() {
        // `panel_transition_status_after_edit` only knows the visible count,
        // so it calls this count-only wrapper. It must not hard-code "a query
        // exists": an emptied query no longer binds Backspace/typed text to
        // re-editing, and the old wrapper kept advertising those keys.
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
        for count in [0, 2] {
            for dirty in [false, true] {
                let status = search_finished_status(count, dirty);
                assert_eq!(
                    status,
                    crate::ui::app::status_with_unsaved(
                        &crate::ui::logic::no_selection_status_for_count(count),
                        dirty
                    ),
                    "count {count}, dirty {dirty}"
                );
                assert!(
                    !status.contains(hint),
                    "a count-only caller cannot promise re-edit keys: {status}"
                );
            }
        }
    }

    #[::core::prelude::v1::test]
    fn reedit_hint_follows_the_confirmed_query_through_edits() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        let mut view = VaultViewState::new();
        for id in ["a", "b"] {
            view.vault.items.push(VaultItem::new(
                id,
                id,
                ItemData::SecureNote {
                    text: String::new().into(),
                },
            ));
        }
        view.start_search();
        view.push_query("Zq");
        assert_eq!(view.visible_items().len(), 0, "precondition: no match");

        let confirmed = finish_search_from_row_click(&mut view, false);
        assert!(
            confirmed.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "{confirmed}"
        );

        // One character left: still a query, so the hint stays.
        let one_left = backspace_confirmed_query(&mut view, false);
        assert_eq!(view.query, "Z");
        assert!(
            one_left.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "{one_left}"
        );

        // Removing the last character must drop the hint with the query.
        let empty = backspace_confirmed_query(&mut view, false);
        assert_eq!(view.query, "");
        assert_eq!(view.visible_items().len(), 2);
        assert_eq!(
            empty,
            crate::ui::app::status_with_unsaved(crate::ui::logic::no_selection_status(), false)
        );
        assert!(
            !empty.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "{empty}"
        );

        // Confirming the now-empty query, and a missed click that falls back
        // to the same view-derived status, must not resurrect the hint.
        let reconfirmed = finish_search_from_row_click(&mut view, false);
        assert!(
            !reconfirmed.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "{reconfirmed}"
        );
        let click_fallback = selected_row_click_status(&view, false);
        assert!(
            !click_fallback.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "{click_fallback}"
        );

        // Adding a character again restores the hint and keeps the marker.
        let refined = insert_confirmed_query(&mut view, "A", true);
        assert_eq!(view.query, "A");
        assert!(
            refined.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "{refined}"
        );
        assert!(refined.contains("[未保存の設定変更があります]"));
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
        assert_eq!(status, search_finished_status_for_view(&view, false));
        assert!(!status.contains("入力中"), "{status}");

        // A click that leaves zero matches must show the dedicated message.
        let mut empty = VaultViewState::new();
        empty.start_search();
        empty.push_query("missing");
        let empty_status = finish_search_from_row_click(&mut empty, false);
        assert_eq!(empty_status, search_finished_status_for_view(&empty, false));
        assert!(empty_status.contains("0件"), "{empty_status}");
        assert!(!empty_status.contains("入力中"), "{empty_status}");

        // The unsaved marker survives the confirmation.
        let dirty_status = finish_search_from_row_click(&mut view, true);
        assert_eq!(dirty_status, search_finished_status_for_view(&view, true));
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
        assert_eq!(
            stale,
            crate::ui::app::status_with_unsaved(
                &format!(
                    "{} / {}",
                    crate::ui::logic::no_selection_status(),
                    crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                ),
                false
            )
        );
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
    fn plain_row_click_reports_the_selected_row() {
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
        assert!(!view.searching, "precondition: a plain, non-search click");

        // A normal click has no search-confirmation status, yet a successful
        // selection must still install the selected-row status.
        let selected = view.select_index(1);
        assert!(selected);
        let status = row_click_status(&view, false, None, selected);
        assert_eq!(status.as_deref(), Some("項目を選択しました: Beta"));
        assert_eq!(view.selected_id.as_deref(), Some("b"));

        // The unsaved marker survives on this path too.
        let dirty = row_click_status(&view, true, None, true);
        let expected = crate::ui::app::status_with_unsaved("項目を選択しました: Beta", true);
        assert_eq!(dirty.as_deref(), Some(expected.as_str()));

        // A plain click that misses changes nothing, so no status is installed.
        assert_eq!(row_click_status(&view, false, None, false), None);
        // While searching, a missed click still keeps the count-based status.
        // The real panel path derives the status from the view, not from a
        // count-only wrapper that would advertise re-edit keys for no query.
        let confirmed = Some(search_finished_status_for_view(&view, false));
        assert_eq!(
            row_click_status(&view, false, confirmed.clone(), false),
            confirmed
        );
    }

    #[::core::prelude::v1::test]
    fn keyboard_row_selection_reports_the_selected_name() {
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

        // An empty selection has no row to name, so the caller keeps its
        // existing status instead of inventing one.
        assert_eq!(selected_row_status(&view, false), None);

        // With no selection, a positive delta starts at the first visible row
        // (the same rule the real `move_selection` path uses), then a second
        // positive step reaches the second row.
        let next = {
            let visible = view.visible_items();
            view.next_index_in(&visible, 1)
        }
        .expect("precondition: two visible rows");
        view.selected_id = Some(view.visible_items()[next].id.clone());
        assert_eq!(view.selected_id.as_deref(), Some("a"));
        let second = {
            let visible = view.visible_items();
            view.next_index_in(&visible, 1)
        }
        .expect("second row");
        view.selected_id = Some(view.visible_items()[second].id.clone());
        let status = selected_row_status(&view, false);
        assert_eq!(status.as_deref(), Some("項目を選択しました: Beta"));
        assert_eq!(view.selected_id.as_deref(), Some("b"));

        // The unsaved marker survives on the keyboard path too, and the
        // wording matches the mouse click path exactly.
        let dirty = selected_row_status(&view, true);
        let click = selected_row_click_status(&view, true);
        assert_eq!(dirty.as_deref(), Some(click.as_str()));
        assert!(dirty.is_some_and(|text| text.contains("[未保存の設定変更があります]")));
    }

    #[::core::prelude::v1::test]
    fn keyboard_row_selection_uses_the_empty_name_placeholder() {
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

        let placeholder = crate::ui::app::ITEM_NAME_PLACEHOLDER;
        let mut view = VaultViewState::new();
        // The same three name shapes the list row and detail row already cover:
        // empty, invisible-only (`Cf`) and visible.
        view.vault.items.push(item("empty", ""));
        view.vault.items.push(item("invisible", "\u{200b}"));
        view.vault.items.push(item("named", "Alpha"));

        let expected = format!("項目を選択しました: {placeholder}");
        for id in ["empty", "invisible"] {
            view.selected_id = Some(id.into());
            let status = selected_row_status(&view, false);
            assert_eq!(status.as_deref(), Some(expected.as_str()), "{id}");
            // The invisible character must not leak into the status either.
            assert!(!status.is_some_and(|text| text.contains('\u{200b}')));
        }

        // A visible name is still rendered verbatim.
        view.selected_id = Some("named".into());
        assert_eq!(
            selected_row_status(&view, false).as_deref(),
            Some("項目を選択しました: Alpha")
        );

        // The placeholder path keeps the persistent unsaved marker, just like
        // the ordinary-name path does.
        view.selected_id = Some("empty".into());
        let dirty = selected_row_status(&view, true).unwrap();
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(&expected, true));
        assert!(dirty.contains("[未保存の設定変更があります]"));
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
        assert_eq!(
            confirmed,
            crate::ui::app::status_with_unsaved(
                &format!(
                    "{} / {}",
                    crate::ui::logic::NO_SEARCH_RESULTS_STATUS,
                    crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                ),
                false
            )
        );

        // One backspace leaves "Z": still zero matches, so the "0件" text is
        // recomputed rather than left stale from the confirmation.
        let before = view.rewind_calls;
        let still_empty = backspace_confirmed_query(&mut view, false);
        assert_eq!(view.query, "Z");
        assert_eq!(view.visible_items().len(), 0);
        assert_eq!(still_empty, search_finished_status_for_view(&view, false));
        assert_eq!(
            still_empty,
            crate::ui::app::status_with_unsaved(
                &format!(
                    "{} / {}",
                    crate::ui::logic::NO_SEARCH_RESULTS_STATUS,
                    crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                ),
                false
            )
        );
        assert_eq!(view.rewind_calls, before + 1, "each backspace rewinds");

        // The next backspace empties the query: the generic selection prompt
        // replaces the zero-match message, and the re-edit hint goes away with
        // the query it described.
        let status = backspace_confirmed_query(&mut view, false);
        assert_eq!(view.query, "");
        assert_eq!(view.visible_items().len(), 2);
        assert_eq!(status, search_finished_status_with_query(false, 2, false));
        assert_eq!(
            status,
            crate::ui::app::status_with_unsaved(crate::ui::logic::no_selection_status(), false)
        );
        assert!(!status.contains("0件"), "{status}");
        assert!(
            !status.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT),
            "an empty query must not advertise re-edit keys: {status}"
        );

        // The unsaved marker is preserved in both count branches.
        view.push_query("Zq");
        let dirty_empty = backspace_confirmed_query(&mut view, true);
        assert_eq!(dirty_empty, search_finished_status_for_view(&view, true));
        assert!(dirty_empty.contains("[未保存の設定変更があります]"));
        let dirty_found = backspace_confirmed_query(&mut view, true);
        assert_eq!(
            dirty_found,
            search_finished_status_with_query(false, 2, true)
        );
        assert!(dirty_found.contains("[未保存の設定変更があります]"));
        assert!(!dirty_found.contains(crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT));
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
        assert_eq!(
            confirmed,
            crate::ui::app::status_with_unsaved(
                &format!(
                    "{} / {}",
                    crate::ui::logic::NO_SEARCH_RESULTS_STATUS,
                    crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                ),
                false
            )
        );

        // Appending text refines the confirmed query without re-entering
        // search mode (so `/` can still start a fresh search later).
        let before = view.rewind_calls;
        let still_empty = insert_confirmed_query(&mut view, "x", false);
        assert_eq!(view.query, "Zqx");
        assert!(!view.searching);
        assert_eq!(view.visible_items().len(), 0);
        assert_eq!(still_empty, search_finished_status_for_view(&view, false));
        assert_eq!(
            still_empty,
            crate::ui::app::status_with_unsaved(
                &format!(
                    "{} / {}",
                    crate::ui::logic::NO_SEARCH_RESULTS_STATUS,
                    crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT
                ),
                false
            )
        );
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
        assert_eq!(status, search_finished_status_for_view(&found, false));
        assert!(!status.contains("0件"), "{status}");

        let dirty_empty = insert_confirmed_query(&mut view, "y", true);
        assert_eq!(dirty_empty, search_finished_status_for_view(&view, true));
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
    fn empty_list_edge_keys_report_no_rows_instead_of_doing_nothing() {
        // `edge_move_delta` is the whole input to the dispatcher's empty
        // branch: every zero-length list (vault or audit, selected or not)
        // yields `None`, which is exactly the case that used to be silent.
        for edge in [SelectionEdge::First, SelectionEdge::Last] {
            for current in [None, Some(0), Some(9)] {
                assert_eq!(
                    edge_move_delta(current, 0, edge),
                    None,
                    "no edge can be reached in an empty list: {edge:?}/{current:?}"
                );
            }
        }

        // The status installed by that branch names the missing rows instead
        // of claiming a move, and behaves like every other transient status.
        let clean = no_rows_status(false);
        assert_eq!(clean, NO_ROWS_MESSAGE);
        assert!(clean.contains("行がありません"), "{clean}");
        assert!(!clean.contains("[未保存"), "{clean}");

        for dirty in [false, true] {
            let status = no_rows_status(dirty);
            assert_eq!(
                status,
                crate::ui::app::status_with_unsaved(NO_ROWS_MESSAGE, dirty)
            );
            assert_eq!(
                status.contains("[未保存の設定変更があります]"),
                dirty,
                "{status}"
            );
        }
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
        // Function-key names arrive in either ASCII case from different
        // backends; both must reach the observer's recovery branch.
        assert!(is_focus_recovery_key("F1"));
        assert!(!is_focus_recovery_key("f2"));
        assert!(!is_focus_recovery_key("F2"));
        assert!(!is_focus_recovery_key(""));
        // ASCII-only normalisation: a fullwidth lookalike is not the key.
        assert!(!is_focus_recovery_key("Ｆ１"));
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

        // Recognising uppercase ASCII case in the observer must not change
        // classification: the echoed name stays inert in every mode.
        let mut upper = context(Screen::Unlocked, Panel::Vault, "F1");
        upper.key_char = Some("F1");
        assert_eq!(classify_key(&upper), UiAction::None);

        // Sanity check: the helper only fires for the dedicated key, and a
        // normal command key stays classified as before.
        assert!(!is_focus_recovery_key("l"));
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "l")),
            UiAction::Lock
        );
    }

    #[::core::prelude::v1::test]
    fn action_status_with_unsaved_keeps_the_marker_without_doubling_it() {
        let base = "クリップボードにコピーしました（30秒後に復元）";
        assert_eq!(action_status_with_unsaved(base, false), base);
        let dirty = action_status_with_unsaved(base, true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(base, true));
        assert_eq!(
            action_status_with_unsaved(&dirty, true),
            dirty,
            "an already composed marker must not be appended twice"
        );
    }

    #[::core::prelude::v1::test]
    fn generator_key_changes_detects_clamped_boundaries() {
        let mut settings = crate::settings::Settings::default();

        // `+` at the maximum and `-` at the minimum are clamped to identical
        // values, so the dispatcher must skip the change announcement.
        settings.password_generator.length = crate::limits::MAX_PASSWORD_LENGTH;
        settings.passphrase_generator.words = crate::limits::MAX_PASSPHRASE_WORDS;
        assert!(!generator_key_changes(&settings, GeneratorOption::LengthUp));
        assert!(generator_key_changes(
            &settings,
            GeneratorOption::LengthDown
        ));

        settings.password_generator.length = crate::limits::MIN_PASSWORD_LENGTH;
        settings.passphrase_generator.words = crate::limits::MIN_PASSPHRASE_WORDS;
        assert!(!generator_key_changes(
            &settings,
            GeneratorOption::LengthDown
        ));
        assert!(generator_key_changes(&settings, GeneratorOption::LengthUp));

        // Every toggle still changes a stored value, at any boundary.
        for option in [
            GeneratorOption::Lowercase,
            GeneratorOption::Uppercase,
            GeneratorOption::Digits,
            GeneratorOption::Symbols,
            GeneratorOption::AvoidAmbiguous,
            GeneratorOption::Capitalize,
            GeneratorOption::IncludeNumber,
            GeneratorOption::Separator,
        ] {
            assert!(generator_key_changes(&settings, option), "{option:?}");
        }
    }

    #[::core::prelude::v1::test]
    fn generator_adjust_status_shows_the_new_value_and_unsaved_marker() {
        let mut settings = crate::settings::Settings::default();
        crate::ui::keys::apply_generator_key(&mut settings, GeneratorOption::LengthUp);
        let value = generator_value_text(&settings, GeneratorOption::LengthUp);
        assert_eq!(value, "パスワード 21 文字 / パスフレーズ 5 語");

        let clean = generator_adjust_status(&value, false);
        assert_eq!(
            clean,
            "生成設定を変更しました: パスワード 21 文字 / パスフレーズ 5 語（w: 保存 / d: 破棄）"
        );
        assert!(!clean.contains("[未保存"), "{clean}");
        let dirty = generator_adjust_status(&value, true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(&clean, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
    }

    #[::core::prelude::v1::test]
    fn adjusted_values_are_included_in_time_and_threshold_statuses() {
        assert!(seconds_adjust_status(1, false).contains("1秒"));
        assert_ne!(
            seconds_adjust_status(1, false),
            seconds_adjust_status(2, false)
        );
        assert!(idle_lock_adjust_status(90, false).contains("1分30秒"));

        let thresholds = crate::health::Thresholds {
            weak_bits: 50,
            stale_days: 400,
        };
        let status = threshold_adjust_status(thresholds, false);
        assert!(status.contains("50 bit"), "{status}");
        assert!(status.contains("400 日"), "{status}");
        assert_ne!(
            status,
            threshold_adjust_status(
                crate::health::Thresholds {
                    weak_bits: 55,
                    stale_days: 400
                },
                false
            )
        );
    }

    #[::core::prelude::v1::test]
    fn generator_value_text_describes_each_option_after_the_change() {
        let mut settings = crate::settings::Settings::default();
        for (option, expected) in [
            (GeneratorOption::Lowercase, "英小文字: 無効"),
            (GeneratorOption::Uppercase, "英大文字: 無効"),
            (GeneratorOption::Digits, "数字: 無効"),
            (GeneratorOption::Symbols, "記号: 無効"),
            (
                GeneratorOption::AvoidAmbiguous,
                "紛らわしい文字を除外: 有効",
            ),
            (GeneratorOption::Capitalize, "先頭大文字: 無効"),
            (GeneratorOption::IncludeNumber, "数字を含める: 有効"),
            (GeneratorOption::Separator, "区切り: ."),
        ] {
            crate::ui::keys::apply_generator_key(&mut settings, option);
            assert_eq!(
                generator_value_text(&settings, option),
                expected,
                "{option:?}"
            );
        }

        settings.passphrase_generator.separator = String::new();
        assert_eq!(
            generator_value_text(&settings, GeneratorOption::Separator),
            "区切り: (なし)"
        );
    }

    #[::core::prelude::v1::test]
    fn clamp_boundary_status_names_the_bound_and_keeps_the_marker() {
        for (edge, named, other) in [
            (ClampEdge::Upper, "上限", "下限"),
            (ClampEdge::Lower, "下限", "上限"),
        ] {
            let clean = clamp_boundary_status("自動ロック", edge, false);
            assert!(clean.contains(named), "{clean}");
            assert!(!clean.contains(other), "{clean}");
            assert!(!clean.contains("[未保存"), "{clean}");

            let dirty = clamp_boundary_status("自動ロック", edge, true);
            assert_eq!(dirty, crate::ui::app::status_with_unsaved(&clean, true));
            assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        }

        assert_eq!(clamp_edge_for_delta(1), ClampEdge::Upper);
        assert_eq!(clamp_edge_for_delta(-1), ClampEdge::Lower);
        assert_eq!(
            threshold_boundary_status(1, false),
            clamp_boundary_status("監査閾値", ClampEdge::Upper, false)
        );
        assert_eq!(
            idle_lock_boundary_status(-1, false),
            clamp_boundary_status("自動ロック", ClampEdge::Lower, false)
        );
        assert_eq!(
            seconds_boundary_status("復元", 1, false),
            clamp_boundary_status("復元", ClampEdge::Upper, false)
        );
    }

    #[::core::prelude::v1::test]
    fn generator_clamp_edge_only_comes_from_the_length_keys() {
        assert_eq!(
            generator_clamp_edge(GeneratorOption::LengthUp),
            Some(ClampEdge::Upper)
        );
        assert_eq!(
            generator_clamp_edge(GeneratorOption::LengthDown),
            Some(ClampEdge::Lower)
        );
        for option in [
            GeneratorOption::Lowercase,
            GeneratorOption::Uppercase,
            GeneratorOption::Digits,
            GeneratorOption::Symbols,
            GeneratorOption::AvoidAmbiguous,
            GeneratorOption::Capitalize,
            GeneratorOption::IncludeNumber,
            GeneratorOption::Separator,
        ] {
            assert_eq!(generator_clamp_edge(option), None, "{option:?}");
        }
    }
}
