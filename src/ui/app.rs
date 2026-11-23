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

/// Decide whether a panel transition needs the "return to the settings panels"
/// guidance.
///
/// Both `Settings` and `Generator` own the `w`/`d` bindings (see
/// `crate::ui::keys::classify_key`), so switching between them leaves the user
/// on a panel where saving/discarding still works. Only a transition that
/// actually leaves those panels (to `Vault` or `Audit`) should point back;
/// telling someone who just opened the generator to return to the
/// settings/generator panel is misleading. Kept pure so the contract can be
/// tested without a GPUI window (this crate does not enable gpui's
/// `test-support` feature).
pub(super) fn unsaved_panel_exit_status_for(
    from: Panel,
    to: Panel,
    dirty: bool,
) -> Option<&'static str> {
    let from_owns_settings = matches!(from, Panel::Settings | Panel::Generator);
    let to_owns_settings = matches!(to, Panel::Settings | Panel::Generator);
    if from_owns_settings && from != to && dirty && !to_owns_settings {
        Some(unsaved_panel_exit_status())
    } else {
        None
    }
}

/// Which text-edit mode, if any, a panel transition just left.
///
/// `set_panel` clears all three modes before switching panels. Passing the
/// actual mode (instead of a single `was_editing` flag) lets the status bar
/// restore the guidance belonging to the mode the user just finished: leaving
/// a settings field must not be reported as a finished search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExitedEditMode {
    /// No mode was active; the caller keeps its current status.
    None,
    /// A lock-screen auth field was being edited.
    AuthField,
    /// A settings field was being edited.
    SettingsField,
    /// A vault search was active.
    Search,
}

/// Status installed by `set_panel` when it drops an active text-edit mode.
///
/// Each cleared mode installs the "入力中:" guidance via
/// [`crate::ui::input::text_edit_start_status`], so leaving one without
/// replacing that text leaves stale guidance on screen. The status is chosen
/// from the mode that was actually exited: leaving a settings/auth field keeps
/// *its* confirmation guidance even when the destination is the vault panel.
/// The destination panel only refines the search case (audit row state on the
/// audit panel, settings feedback on a settings-owning panel). For that audit
/// case the report and the still-highlighted row are passed in so the status
/// describes the actual selection instead of always claiming none.
/// [`ExitedEditMode::None`] means the caller must keep its current status (a
/// login notice, an audit-focus message, ...). Kept pure so the contract can
/// be tested without a GPUI window (this crate does not enable gpui's
/// `test-support` feature).
pub(super) fn panel_transition_status_after_edit(
    panel: Panel,
    exited: ExitedEditMode,
    visible_count: usize,
    dirty: bool,
    audit_report: Option<&crate::health::Report>,
    audit_selection: Option<usize>,
) -> Option<String> {
    match exited {
        ExitedEditMode::None => None,
        ExitedEditMode::AuthField => Some(crate::ui::input::auth_edit_finished_status(dirty)),
        ExitedEditMode::SettingsField => {
            Some(crate::ui::input::settings_edit_finished_status(dirty))
        }
        ExitedEditMode::Search => Some(match panel {
            Panel::Audit => audit_search_exit_status(audit_report, audit_selection, dirty),
            Panel::Settings | Panel::Generator => {
                crate::ui::input::settings_edit_finished_status(dirty)
            }
            Panel::Vault => crate::ui::input::search_finished_status(visible_count, dirty),
        }),
    }
}

/// Finish search on a panel transition, but only when a search is active.
///
/// [`VaultViewState::finish_search`] always runs `deselect_and_rewind`, even
/// when `searching` is already false. Calling it unconditionally from
/// [`BitwardenApp::set_panel`] therefore dropped the selected row and its
/// scroll target on every ordinary panel change. Kept as a pure view-level
/// helper so the selection/scroll contract can be tested without a GPUI
/// window (this crate does not enable gpui's `test-support` feature).
pub(super) fn finish_search_on_panel_transition(view: &mut VaultViewState) {
    if view.searching {
        view.finish_search();
    }
}

/// Pure form of the TOTP-to-selection sync over the two state pieces it needs.
///
/// `deselect_and_rewind` raises `VaultViewState::totp_stale_after_deselect`
/// even when the deselection happens below the app layer (for example in
/// `VaultViewState::finish_search`, called from the input handlers). Consuming
/// that signal here wipes the cached secret unconditionally, so a code from
/// the dropped row can never be copied or redrawn afterwards. The ordinary
/// secret comparison is kept for selection changes that do not deselect.
/// Kept as a free function over plain state so the contract can be tested
/// without a GPUI window (this crate does not enable gpui's `test-support`).
pub(super) fn sync_totp_to_selection_state(view: &mut VaultViewState, totp: &mut TotpState) {
    let stale_after_deselect = view.take_totp_stale();
    let visible = view.visible_items();
    let secret = crate::ui::logic::required_item_index(view.selected_id.as_deref(), &visible)
        .and_then(|index| visible[index].totp_secret())
        .unwrap_or("")
        .to_string();
    if stale_after_deselect || !totp.matches_secret(&secret) {
        totp.clear();
    }
}

/// Finish a search and drop any TOTP secret belonging to the cleared row.
///
/// This is the single wiring between `VaultViewState::finish_search` (which
/// only owns the selection) and `TotpState` (owned by `BitwardenApp`). Every
/// in-scope caller should use it instead of calling `finish_search` directly;
/// out-of-scope callers are covered because the view-level stale signal is
/// consumed by the next `sync_totp_to_selection`, which both rendering and
/// copying already perform.
pub(super) fn finish_search_and_sync_totp(view: &mut VaultViewState, totp: &mut TotpState) {
    view.finish_search();
    sync_totp_to_selection_state(view, totp);
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

/// Whether `value` carries no visible content.
///
/// Whitespace, Unicode `Cc` (control) characters and Unicode `Cf` (format)
/// characters such as zero-width spaces or bidi overrides all render nothing,
/// whether at the edges or between visible letters. `Cc` is not whitespace
/// (`str::trim()` alone keeps NUL and C1 controls), so it is listed explicitly
/// to match `crate::model::is_visually_empty` and
/// `crate::auth::credential_is_blank`. Otherwise a value that looks empty still
/// passes a plain `trim().is_empty()` guard. Shared with the list row renderer
/// so the two places agree on what "empty" means.
pub(super) fn is_visually_empty(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_whitespace() || ch.is_control() || crate::limits::is_format_character(ch))
}

/// Placeholder drawn for a vault item whose name has no visible content.
pub(super) const ITEM_NAME_PLACEHOLDER: &str = "(名称未設定)";

/// Display name shared by the vault list row and the detail row.
///
/// `ui::render` used to draw the raw `item.name` in the list column, while
/// `selected_detail` interpolated it between two `" | "` separators. An empty
/// or invisible-only (`Cf`) name therefore left a blank column in the list and
/// a double separator in the detail line. Both call sites now use this helper,
/// so the same placeholder appears and the separator count stays stable. Kept
/// pure so the contract can be tested without a GPUI window.
pub(super) fn item_name_text(name: &str) -> &str {
    if is_visually_empty(name) {
        ITEM_NAME_PLACEHOLDER
    } else {
        name
    }
}

/// Join the vault detail fields with `" | "`, skipping empty ones.
///
/// A plain `format!("{base} | {a} | {b}")` leaves a double separator (`" |  | "`)
/// when a middle field is empty and a dangling one (`" | "`) when the last one
/// is. Filtering fields with no visible content before joining keeps the
/// detail row readable. `base` is always kept so the row never disappears.
fn join_detail_fields(base: &str, fields: &[String]) -> String {
    let mut parts = Vec::with_capacity(fields.len() + 1);
    parts.push(base.to_string());
    parts.extend(
        fields
            .iter()
            .filter(|field| !is_visually_empty(field))
            .cloned(),
    );
    parts.join(" | ")
}

/// Status shown after successfully following an audit finding.
///
/// `name` is the finding's display name from the current report (the same text
/// the keyboard path shows), never the internal item id. Routing every branch
/// through `status_with_unsaved` keeps the persistent "unsaved settings"
/// warning visible when the user leaves the audit panel. The pure form lets the
/// contract be tested without a GPUI window (this crate does not enable gpui's
/// `test-support` feature). A *failed* follow uses
/// [`audit_focus_missing_status`] instead, which names the internal id.
pub(super) fn audit_focus_status(name: &str, found: bool, dirty: bool) -> String {
    let base = if found {
        format!("監査の指摘項目を選択しました: {name}")
    } else {
        "指摘項目が一覧に見つかりません".to_string()
    };
    status_with_unsaved(&base, dirty)
}

/// Status shown when a followed audit finding is absent from the vault list.
///
/// The generic missing branch of [`audit_focus_status`] leaves the user unable
/// to tell *which* finding failed. This variant carries the internal item id
/// so the failed row is identifiable. The id goes through [`item_name_text`]:
/// an id made only of invisible `Cf` characters must not leave a blank after
/// the label. Composed through [`status_with_unsaved`] so the unsaved-settings
/// warning survives leaving the audit panel. Pure so the contract can be
/// tested without a GPUI window.
pub(super) fn audit_focus_missing_status(id: &str, dirty: bool) -> String {
    status_with_unsaved(
        &format!(
            "指摘項目が一覧に見つかりません（項目 ID: {}）",
            item_name_text(id)
        ),
        dirty,
    )
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

/// Status when `Enter` in the audit panel cannot resolve a finding.
///
/// [`audit_no_selection_status`] tells the user to press ↑↓, which is
/// impossible when the report has no findings at all. That case shares the
/// count-aware "監査する問題がありません" wording from [`audit_refresh_status`]
/// with the search-exit path. A non-empty report without a valid highlight,
/// and a missing report, keep the original guidance. Kept pure so the contract
/// can be tested without a GPUI window (this crate does not enable gpui's
/// `test-support` feature).
pub(super) fn audit_focus_no_selection_status(
    report: Option<&crate::health::Report>,
    dirty: bool,
) -> String {
    if report.is_some_and(|report| report.items.is_empty()) {
        audit_refresh_status(None, 0, None, dirty)
    } else {
        audit_no_selection_status(dirty)
    }
}

/// Status shown when a search is finished onto the audit panel.
///
/// Finishing a search does **not** clear [`BitwardenApp::audit_row_selection`]:
/// the user may already have highlighted a finding before starting the search.
/// Reporting "no row selected" unconditionally therefore contradicted the
/// highlight still drawn on screen. A highlighted row is described with the
/// same wording as the keyboard move and refresh paths (and its name is always
/// re-read from the current report). An *empty* report has no row at all, so it
/// goes through [`audit_focus_no_selection_status`] and uses the count-aware
/// "監査する問題がありません" wording instead of asking the user to select a
/// non-existent row with ↑↓. The remaining no-selection cases (a non-empty
/// report with no highlight, or no report at all) keep
/// [`audit_no_selection_status`] through that same helper. Kept pure so the
/// contract can be tested without a GPUI window (this crate does not enable
/// gpui's `test-support` feature).
pub(super) fn audit_search_exit_status(
    report: Option<&crate::health::Report>,
    selection: Option<usize>,
    dirty: bool,
) -> String {
    let len = report.map_or(0, |report| report.items.len());
    match clamp_audit_row(selection, len) {
        Some(index) => {
            let name = report
                .and_then(|report| report.items.get(index))
                .map(|item| item_name_text(&item.name).to_string());
            audit_refresh_status(Some(index), len, name.as_deref(), dirty)
        }
        None => audit_focus_no_selection_status(report, dirty),
    }
}

/// Detail-line text for a login's TOTP field, keeping the failure reason.
///
/// `TotpState::display` collapses every sampling failure into the same
/// `コード生成失敗`, so an undecryptable field (the ciphertext could not be
/// opened) would look identical to a malformed secret. `totp_state.rs` is
/// outside this task's write scope, so the marker check lives here and the
/// cached generation reason covers the remaining failure. `generated` is
/// returned untouched when a code was produced.
pub(super) fn totp_detail_text(secret: &str, generated: String, error: Option<String>) -> String {
    if crate::vault_sync::is_undecryptable_totp(secret) {
        "復号不可（TOTP フィールドを復号できませんでした）".to_string()
    } else if let Some(reason) = error {
        format!("コード生成失敗（不正な TOTP secret: {reason}）")
    } else {
        generated
    }
}

/// Password cell of a login detail row.
///
/// The copy path (`ui::logic::select_copy_value`) refuses a password with no
/// visible content, but the detail row used to count every `char` and render
/// e.g. "3文字" for a whitespace/Unicode `Cf`-only value. Both now go through
/// [`is_visually_empty`], so an absent password reads "なし" on both sides.
/// The undecryptable sentinel keeps its own label and is checked first because
/// it carries visible text. Pure so the wording can be pinned without a GPUI
/// window.
pub(super) fn password_detail_label(password: &str) -> String {
    if crate::vault_sync::is_undecryptable_password(password) {
        "復号不可".to_string()
    } else if is_visually_empty(password) {
        "なし".to_string()
    } else {
        format!("{}文字", password.chars().count())
    }
}

/// TOTP cell of a login detail row.
///
/// A blank or invisible-only (`Cf`) secret is *absent*, not malformed: sending
/// it to code generation would show `コード生成失敗` instead of the "なし"
/// placeholder. `generate` stays lazy so generation is skipped for absent
/// secrets and the branch can be tested without a GPUI-backed `TotpState`.
///
/// `generate` returns both the display code and the cached failure reason,
/// read *after* the re-sample. Reading the reason before calling `generate`
/// showed the previous selection's reason for one frame: `TotpState::display`
/// replaces the cached tick inside the closure, so a pre-read `error_message`
/// was always one sample behind the code on screen.
pub(super) fn totp_code_text(
    secret: &str,
    generate: impl FnOnce(&str) -> (String, Option<String>),
) -> String {
    if is_visually_empty(secret) {
        "なし".to_string()
    } else {
        let (generated, error) = generate(secret);
        totp_detail_text(secret, generated, error)
    }
}

/// Status when the selected TOTP value is visually absent on the copy path.
///
/// The detail row already renders a blank or Unicode `Cf`-only secret as
/// "なし" through [`totp_code_text`]. Feeding that same value to code
/// generation reports a parse failure instead, so copying must short-circuit
/// on the same [`is_visually_empty`] rule. Composing here also keeps the
/// persistent unsaved marker on the resulting status.
pub(super) fn totp_copy_absent_status(dirty: bool) -> String {
    status_with_unsaved(
        "コピーできる TOTP がありません（一覧では「なし」と表示されます）",
        dirty,
    )
}

/// Status when the selected TOTP field carries the undecryptable sentinel.
///
/// The sentinel marks ciphertext that could not be opened, not a malformed
/// secret. Sending it to generation reports `不正な TOTP secret`, so the copy
/// path keeps the same "復号不可" wording as [`totp_detail_text`] along with
/// the persistent unsaved marker.
pub(super) fn totp_copy_undecryptable_status(dirty: bool) -> String {
    status_with_unsaved(
        "TOTP をコピーできません（復号不可: TOTP フィールドを復号できませんでした）",
        dirty,
    )
}

/// Copy-side counterpart of [`totp_code_text`]'s absent/undecryptable checks.
///
/// `Some` is the status to show when the secret has no visible content or is
/// the undecryptable sentinel; `None` means it is a real generation target.
/// The sentinel check comes first: it contains visible text, so the visual
/// emptiness rule alone would let it reach generation and be reported as an
/// invalid secret. Pure so the copy rule can be tested without a GPUI-backed
/// `TotpState`.
pub(super) fn totp_copy_absent_status_for(secret: &str, dirty: bool) -> Option<String> {
    if crate::vault_sync::is_undecryptable_totp(secret) {
        Some(totp_copy_undecryptable_status(dirty))
    } else if is_visually_empty(secret) {
        Some(totp_copy_absent_status(dirty))
    } else {
        None
    }
}

/// URI cell of a login detail row.
///
/// `mask_uri` reports `(不正な URI)` when its input cannot be parsed, which is
/// also what an empty string produces. An absent URI is not an invalid one, so
/// blank and invisible-only entries are skipped: the first entry with visible
/// content is shown even when earlier entries are empty. Only when every entry
/// is absent does this keep the "なし" placeholder. Pure, so the selection rule
/// can be tested without a GPUI window.
pub(super) fn login_uri_text(uris: &[crate::model::LoginUri]) -> String {
    let Some(uri) = uris.iter().find(|uri| !is_visually_empty(&uri.uri)) else {
        return "なし".to_string();
    };
    crate::model::mask_uri(&uri.uri)
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

/// Idle-lock timeout in minutes, matching the settings panel's display.
///
/// The settings panel shows `idle_lock_seconds / 60` minutes while this status
/// used to show the raw seconds, so the same setting appeared as `5 分` and
/// `300秒` in two places. A plain integer division would fix that by silently
/// dropping the remainder (90 s -> "1 分"), which reports a shorter lock than
/// the one actually configured; the leftover seconds are therefore appended
/// whenever the value is not a whole minute. Kept pure so the wording can be
/// tested without a GPUI window.
pub(super) fn idle_lock_minutes_text(idle_lock_seconds: u64) -> String {
    let minutes = idle_lock_seconds / 60;
    let seconds = idle_lock_seconds % 60;
    if seconds == 0 {
        format!("{minutes}分")
    } else {
        format!("{minutes}分{seconds}秒")
    }
}

/// Status the ticker leaves on screen after an idle auto-lock.
///
/// `lock()` composes its own status (including the unsaved-settings warning),
/// but the ticker then replaces it to explain *why* the vault locked. Without
/// re-applying the marker here an idle lock silently drops that warning; the
/// same applies to the lock screen's key guidance. The timeout is shown in
/// minutes, like the settings panel (see [`idle_lock_minutes_text`]).
pub(super) fn auto_lock_status(idle_lock_seconds: u64, dirty: bool) -> String {
    let timeout = idle_lock_minutes_text(idle_lock_seconds);
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
            "無操作のため自動ロックしました（{timeout}）{unsaved_guidance}{}",
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

/// Status after cycling the sidebar filter, keeping the unsaved marker.
///
/// `CycleFilter` used to leave the previous status on screen. Building the
/// text from the filter that is now active (and its folder names) makes the
/// change observable and keeps the contract testable without a GPUI window.
pub(super) fn filter_cycle_status(
    filter: &Filter,
    folders: &[crate::model::Folder],
    dirty: bool,
) -> String {
    status_with_unsaved(
        &format!("フィルターを切り替えました: {}", filter.label(folders)),
        dirty,
    )
}

/// Status after cycling the sort key, keeping the unsaved marker.
pub(super) fn sort_cycle_status(sort: SortKey, dirty: bool) -> String {
    status_with_unsaved(&format!("並び順を切り替えました: {}", sort.label()), dirty)
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

/// Re-anchor the audit scroll after a refresh that changed the report.
///
/// When a highlight survives the clamp, this queues the same target as the
/// keyboard path (`move_audit_selection`). When no row is left highlighted,
/// there is no target to queue, so the previously queued `scroll_to_item`
/// would survive and drag the refreshed panel back to a vanished finding.
/// That branch performs the exact handle exchange of `reset_audit_scroll`
/// (fresh `ScrollHandle`) without touching the already-cleared selection, so
/// the lock/unlock reset keeps its own contract. Kept as a free function so
/// both branches can be tested without a GPUI window.
pub(super) fn refresh_audit_scroll(
    handle: &mut ScrollHandle,
    selection: &mut Option<usize>,
    len: usize,
) {
    *selection = clamp_audit_row(*selection, len);
    if let Some(scroll_index) = audit_row_scroll_index(*selection) {
        handle.scroll_to_item(scroll_index);
    } else {
        *handle = ScrollHandle::new();
    }
}

/// Resolve the audit row, scroll target and display name for a followed id.
///
/// A mouse click on an audit row carries the item id rather than a row index.
/// Translating it back against the current report is what moves the keyboard
/// highlight off the previously selected row. The name is the same one the
/// keyboard path (`move_audit_selection`) reports, so the status never shows
/// the internal id. Pure so the mapping can be tested without a GPUI window
/// (this crate does not enable gpui's `test-support` feature).
pub(super) fn audit_focus_target<'a>(
    report: Option<&'a crate::health::Report>,
    id: &str,
) -> Option<(usize, usize, &'a str)> {
    let report = report?;
    let index = report.items.iter().position(|item| item.id == id)?;
    let scroll_index = audit_row_scroll_index(Some(index))?;
    Some((
        index,
        scroll_index,
        item_name_text(&report.items[index].name),
    ))
}

/// Align the audit highlight and scroll to the row identified by `id`.
///
/// Applies the same row-and-scroll update as the keyboard path after a click.
/// Returns the row name for the status bar, or `None` when the id is not in the
/// current report (the highlight is left untouched in that case). Free so the
/// alignment can be tested without a GPUI window.
pub(super) fn align_audit_focus(
    report: Option<&crate::health::Report>,
    id: &str,
    handle: &mut ScrollHandle,
    selection: &mut Option<usize>,
) -> Option<String> {
    let (index, scroll_index, name) = audit_focus_target(report, id)?;
    *selection = Some(index);
    handle.scroll_to_item(scroll_index);
    Some(name.to_string())
}

/// Status describing the audit row left highlighted after a refresh.
///
/// Uses the same wording as the keyboard move status, so a threshold edit
/// cannot leave the status bar naming a row that is no longer highlighted.
/// The name goes through [`item_name_text`], matching the vault list/detail
/// rows: an invisible-only (`Cf`) finding name must show the shared placeholder
/// rather than leaving a blank after "監査行 n/m: ".
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
                item_name_text(name)
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
            .map(|item| item_name_text(&item.name).to_string())
    });
    Some(audit_refresh_status(clamped, len, name.as_deref(), dirty))
}

/// Status a report refresh is allowed to publish on the current panel.
///
/// The threshold keys are bound only in settings-owning panels (see the
/// `AdjustThreshold` branches in `crate::ui::keys::classify_key`). Changing a
/// threshold recomputes the report, but the audit-row description must not
/// replace the settings feedback on those panels. `None` means "keep the
/// current status"; the report itself is still refreshed in every panel.
/// Kept pure so the contract can be tested without a GPUI window.
pub(super) fn audit_refresh_status_for_panel(
    report: Option<&crate::health::Report>,
    selection: Option<usize>,
    dirty: bool,
    panel: Panel,
) -> Option<String> {
    if matches!(panel, Panel::Settings | Panel::Generator) {
        return None;
    }
    audit_refresh_status_for(report, selection, dirty)
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
        let exit_warning = unsaved_panel_exit_status_for(self.panel, panel, self.settings_dirty);
        // Capture the mode *before* clearing it: each one installed the
        // "入力中:" status, so leaving one must restore that mode's status,
        // not a status guessed from the destination panel alone.
        // (The modes are mutually exclusive in practice; the order below just
        // makes the capture deterministic if a stale state holds more than one.)
        let exited_edit_mode = if self.editing.is_some() {
            ExitedEditMode::SettingsField
        } else if self.auth.field().is_some() {
            ExitedEditMode::AuthField
        } else if self.view.searching {
            ExitedEditMode::Search
        } else {
            ExitedEditMode::None
        };
        self.editing = None;
        self.auth.take_field();
        finish_search_on_panel_transition(&mut self.view);
        // Leaving an active search deselects the row; consume the stale-TOTP
        // signal it raised so no secret from that row survives the transition.
        self.sync_totp_to_selection();
        self.panel = crate::ui::logic::effective_panel(panel, self.view.audit_report.is_some());
        if let Some(status) = exit_warning {
            // Leaving the settings-owning panels does not persist anything.
            // Say so before the destination panel overwrites the status.
            // Settings <-> Generator are excluded: `w`/`d` still work there.
            self.status = status.to_string();
        } else if let Some(status) = panel_transition_status_after_edit(
            self.panel,
            exited_edit_mode,
            self.view.visible_items().len(),
            self.settings_dirty,
            self.view.audit_report.as_ref(),
            self.audit_row_selection,
        ) {
            self.status = status;
        }
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
        sync_totp_to_selection_state(&mut self.view, &mut self.totp);
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
            // `Enter` with no resolvable row must not ask for a ↑↓ selection
            // when the report is empty: there is no row to highlight.
            self.status = audit_focus_no_selection_status(
                self.view.audit_report.as_ref(),
                self.settings_dirty,
            );
            cx.notify();
            return;
        };
        self.set_panel(Panel::Vault, cx);
        self.view.filter = Filter::All;
        self.view.query.clear();
        finish_search_and_sync_totp(&mut self.view, &mut self.totp);
        // A click carries an item id, not a row index. Move the audit highlight
        // to the clicked row (and queue its scroll) so the old row does not stay
        // highlighted, and name that row in the status as the keyboard path does.
        let focus_name = align_audit_focus(
            self.view.audit_report.as_ref(),
            &id,
            &mut self.audit_scroll_handle,
            &mut self.audit_row_selection,
        )
        .unwrap_or_else(|| item_name_text(&id).to_string());
        if let Some(index) = self.view.select_id(&id) {
            self.view
                .scroll_handle
                .scroll_to_item(index, ScrollStrategy::Nearest);
            self.status = audit_focus_status(&focus_name, true, self.settings_dirty);
        } else {
            self.view.deselect_and_rewind();
            // The followed row is not in the list: name the internal id so the
            // user knows which finding could not be selected.
            self.status = audit_focus_missing_status(&id, self.settings_dirty);
        }
        self.sync_totp_to_selection();
        cx.notify();
    }

    /// Announce an Up/Down/PageUp/PageDown press that has no row to move to.
    ///
    /// `next_index_in` returns `None` only for an empty visible vault list —
    /// the same dead-key case that `move_selection_to_edge` already reports for
    /// Home/End. Reusing [`crate::ui::input::no_rows_status`] keeps one wording
    /// and one unsaved-marker contract for every list key. The decision is a
    /// pure helper because `move_selection` itself needs a GPUI `Context`,
    /// which these unit tests cannot construct.
    fn empty_vault_move_status(dirty: bool) -> String {
        crate::ui::input::no_rows_status(dirty)
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
            // An empty list has no next index for any relative key. Without an
            // explicit status the whole keypress was silently dropped and
            // looked dead to keyboard users; `report_keyboard_selection` finds
            // no selected row here, so this announcement is not overwritten.
            self.status = Self::empty_vault_move_status(self.settings_dirty);
            cx.notify();
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
                item_name_text(&item.name)
            );
            self.status = status_with_unsaved(&base, self.settings_dirty);
        }
        cx.notify();
    }

    pub(super) fn cycle_filter(&mut self, cx: &mut Context<Self>) {
        self.view.cycle_filter();
        self.sync_totp_to_selection();
        // Report the filter that is now active, not whatever the previous
        // action happened to write into the status bar.
        self.status = filter_cycle_status(
            &self.view.filter,
            &self.view.vault.folders,
            self.settings_dirty,
        );
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
                            item_name_text(&item.name),
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
                // `totp_text` re-samples `TotpState` when the secret or the
                // period changed, so the cached reason must be read *after*
                // it. Reading it first made the detail line lag one sample
                // behind the code when the selection moved to a bad secret.
                let code = totp_code_text(&secret, |secret| {
                    let generated = self.totp_text(secret);
                    let error = self.totp.error_message();
                    (generated, error)
                });
                let password_label = password_detail_label(&password);
                let uri = login_uri_text(&uris);
                join_detail_fields(
                    &base,
                    &[
                        username.clone(),
                        format!("パスワード: {password_label}"),
                        format!("TOTP: {code}"),
                        format!("URI: {uri}"),
                    ],
                )
            }
            ItemData::SecureNote { text } => {
                join_detail_fields(&base, &[format!("メモ: {}文字", text.chars().count())])
            }
            ItemData::Card(card) => join_detail_fields(
                &base,
                &[
                    card.brand.clone(),
                    format!("末尾: {}", crate::ui::logic::card_last_four(&card.number)),
                ],
            ),
            ItemData::Identity(identity) => {
                join_detail_fields(&base, std::slice::from_ref(&identity.email))
            }
            ItemData::SshKey(key) => {
                join_detail_fields(&base, std::slice::from_ref(&key.fingerprint))
            }
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
        // A threshold change can shorten the report and clamp the highlight
        // to a different row. Mirror the keyboard path (`move_audit_selection`)
        // so the scroll position follows the row actually left highlighted.
        // When no row survives, the helper swaps in a fresh handle so the old
        // queued `scroll_to_item` target cannot outlive its finding.
        refresh_audit_scroll(
            &mut self.audit_scroll_handle,
            &mut self.audit_row_selection,
            len,
        );
        // Always re-read the row name from the freshly computed report: the
        // index can stay the same while a different finding occupies it. A
        // threshold change from a settings panel keeps its own status even
        // though the report (and its row selection) is refreshed here.
        if let Some(status) = audit_refresh_status_for_panel(
            self.view.audit_report.as_ref(),
            self.audit_row_selection,
            self.settings_dirty,
            self.panel,
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
    fn audit_focus_missing_status_names_the_internal_id() {
        // A failed follow used to say only "not found", leaving the user with
        // no way to tell which finding failed.
        let clean = audit_focus_missing_status("uuid-42", false);
        assert_eq!(clean, "指摘項目が一覧に見つかりません（項目 ID: uuid-42）");
        assert!(!clean.contains("[未保存"), "{clean}");

        let dirty = audit_focus_missing_status("uuid-42", true);
        assert_eq!(dirty, status_with_unsaved(&clean, true));
        assert!(dirty.starts_with(&clean));
        assert!(dirty.contains("[未保存の設定変更があります]"));

        // The id goes through the shared display-name helper, so an invisible
        // id cannot leave a blank after the label.
        let invisible = audit_focus_missing_status("\u{200b}", false);
        assert!(invisible.contains(ITEM_NAME_PLACEHOLDER), "{invisible}");
        assert!(!invisible.contains('\u{200b}'));
        assert_eq!(
            invisible,
            audit_focus_missing_status("", false),
            "Cf-only and empty ids must render identically"
        );
    }

    #[::core::prelude::v1::test]
    fn audit_statuses_placeholder_invisible_finding_names() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        let cf_name = "\u{200b}\u{feff}";
        let report = Report {
            items: vec![ItemReport {
                id: "item-cf".into(),
                name: cf_name.into(),
                kind: ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 0,
            logins: 1,
        };

        // Refresh path (`audit_refresh_status` and its report-aware wrappers).
        let refresh = audit_refresh_status(Some(0), 1, Some(cf_name), false);
        assert!(refresh.contains(ITEM_NAME_PLACEHOLDER), "{refresh}");
        assert!(!refresh.contains(cf_name));

        for status in [
            audit_search_exit_status(Some(&report), Some(0), false),
            audit_refresh_status_for(Some(&report), Some(0), false).unwrap(),
            audit_refresh_status_for_panel(Some(&report), Some(0), false, Panel::Audit).unwrap(),
        ] {
            assert!(status.contains(ITEM_NAME_PLACEHOLDER), "{status}");
            assert!(!status.contains(cf_name), "{status}");
        }

        // The click/focus path reuses the same display name.
        let (_, _, name) = audit_focus_target(Some(&report), "item-cf").unwrap();
        assert_eq!(name, ITEM_NAME_PLACEHOLDER);
        let focus = audit_focus_status(name, true, false);
        assert!(focus.contains(ITEM_NAME_PLACEHOLDER), "{focus}");

        // A visible name must keep flowing through unchanged.
        let visible = Report {
            items: vec![ItemReport {
                id: "item-ok".into(),
                name: "二要素なし".into(),
                kind: ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 0,
            logins: 1,
        };
        assert!(audit_search_exit_status(Some(&visible), Some(0), false).contains("二要素なし"));
    }

    #[::core::prelude::v1::test]
    fn audit_focus_target_resolves_clicked_row_name_and_scroll() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        let report = Report {
            items: vec![
                ItemReport {
                    id: "uuid-first".into(),
                    name: "古いパスワード".into(),
                    kind: ItemKind::Login,
                    findings: Vec::new(),
                },
                ItemReport {
                    id: "uuid-second".into(),
                    name: "二要素なし".into(),
                    kind: ItemKind::Login,
                    findings: Vec::new(),
                },
            ],
            examined: 2,
            with_totp: 0,
            logins: 2,
        };

        let (index, scroll_index, name) = audit_focus_target(Some(&report), "uuid-second")
            .expect("a clicked finding id must resolve to a row in the current report");
        assert_eq!(index, 1, "the clicked second row must become the highlight");
        assert_eq!(
            scroll_index,
            1 + crate::ui::panels::AUDIT_HEADER_ROWS,
            "the scroll target must match the keyboard path for the same row"
        );
        assert_eq!(name, "二要素なし");
        assert_ne!(
            name, "uuid-second",
            "the status must name the row, not the internal item id"
        );

        // Both status outcomes use that row name instead of the id.
        let found = audit_focus_status(name, true, false);
        assert!(found.contains("二要素なし"), "{found}");
        assert!(!found.contains("uuid-second"), "{found}");
        let missing = audit_focus_status(name, false, false);
        assert!(!missing.contains("uuid-second"), "{missing}");

        // Unknown ids and a missing report have no row to resolve.
        assert_eq!(audit_focus_target(Some(&report), "missing"), None);
        assert_eq!(audit_focus_target(None, "uuid-second"), None);
    }

    #[::core::prelude::v1::test]
    fn align_audit_focus_moves_the_stale_highlight_and_queues_the_clicked_row() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        let report = Report {
            items: vec![
                ItemReport {
                    id: "a".into(),
                    name: "一行目".into(),
                    kind: ItemKind::Login,
                    findings: Vec::new(),
                },
                ItemReport {
                    id: "b".into(),
                    name: "二行目".into(),
                    kind: ItemKind::Login,
                    findings: Vec::new(),
                },
            ],
            examined: 2,
            with_totp: 0,
            logins: 2,
        };

        let mut handle = ScrollHandle::new();
        handle.set_offset(Point {
            x: px(0.0),
            y: px(180.0),
        });
        let mut selection = Some(0); // stale highlight left on the old row

        let name = align_audit_focus(Some(&report), "b", &mut handle, &mut selection)
            .expect("the clicked id must be in the report");

        assert_eq!(
            selection,
            Some(1),
            "the stale highlight must move to the clicked row"
        );
        assert_eq!(name, "二行目");
        assert_eq!(
            handle.offset().y,
            px(180.0),
            "the surviving path queues a target on the same handle instead of resetting it"
        );

        // An id outside the report leaves the highlight untouched and reports
        // no name, so the caller falls back to the raw id for the status.
        assert_eq!(
            align_audit_focus(Some(&report), "missing", &mut handle, &mut selection),
            None
        );
        assert_eq!(selection, Some(1));
        assert_eq!(
            align_audit_focus(None, "b", &mut handle, &mut selection),
            None
        );
        assert_eq!(selection, Some(1));
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
    fn audit_focus_no_selection_status_counts_an_empty_report() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        // `Enter` on an empty audit report used to tell the user to press ↑↓
        // even though no finding exists to highlight.
        let empty = audit_focus_no_selection_status(Some(&Report::default()), false);
        assert_eq!(empty, "監査する問題がありません（↑↓で行を選択できません）");
        assert!(!empty.contains("選択されていません"), "{empty}");

        let dirty = audit_focus_no_selection_status(Some(&Report::default()), true);
        assert_eq!(dirty, status_with_unsaved(&empty, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");

        // A non-empty report without a valid highlight, and no report at all,
        // still need the original "press ↑↓" guidance.
        let report = Report {
            items: vec![ItemReport {
                id: "item-1".into(),
                name: "Finding".into(),
                kind: ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 0,
            logins: 1,
        };
        for (label, case) in [
            (
                "non-empty report",
                audit_focus_no_selection_status(Some(&report), false),
            ),
            ("no report", audit_focus_no_selection_status(None, false)),
        ] {
            assert_eq!(case, audit_no_selection_status(false), "{label}");
            assert!(case.contains("選択されていません"), "{label}: {case}");
        }

        // The search-exit path shares this helper, so its empty-report branch
        // cannot drift back to the row-selection prompt.
        assert_eq!(
            audit_search_exit_status(Some(&Report::default()), Some(usize::MAX), false),
            empty
        );
    }

    #[::core::prelude::v1::test]
    fn totp_detail_text_distinguishes_undecryptable_from_invalid_secret() {
        let reason = Some("TOTP シークレットを解釈できません".to_string());
        let undecryptable = totp_detail_text(
            crate::vault_sync::UNDECRYPTABLE_TOTP,
            "コード生成失敗".to_string(),
            reason.clone(),
        );
        assert!(undecryptable.contains("復号不可"), "{undecryptable}");
        assert!(!undecryptable.contains("不正"), "{undecryptable}");

        let invalid = totp_detail_text("not base32!", "コード生成失敗".to_string(), reason);
        assert!(invalid.contains("コード生成失敗"), "{invalid}");
        assert!(invalid.contains("不正"), "{invalid}");
        assert!(
            invalid.contains("TOTP シークレットを解釈できません"),
            "{invalid}"
        );
        assert!(!invalid.contains("復号不可"), "{invalid}");
        assert_ne!(undecryptable, invalid);

        // Successful codes and cached values are passed through unchanged.
        assert_eq!(
            totp_detail_text("JBSWY3DPEHPK3PXP", "123 456 (あと20秒)".to_string(), None),
            "123 456 (あと20秒)"
        );
    }

    #[::core::prelude::v1::test]
    fn totp_copy_uses_the_detail_rows_invisible_secret_rule() {
        // A blank, whitespace-only and Unicode Cf-only secret all render as
        // "なし" in the detail row. The copy path must skip generation for the
        // same values instead of surfacing a bogus parse failure.
        for secret in ["", "  \t", "\u{200b}", "\u{202e}"] {
            assert!(is_visually_empty(secret), "precondition: {secret:?}");
            assert_eq!(
                totp_code_text(secret, |_| panic!("an absent secret must not be generated")),
                "なし",
                "{secret:?}"
            );
            for dirty in [false, true] {
                let status = totp_copy_absent_status_for(secret, dirty)
                    .expect("an absent secret must be skipped on copy");
                assert_eq!(status, totp_copy_absent_status(dirty), "{secret:?}");
                assert!(status.contains("TOTP"), "{status}");
                assert!(status.contains("なし"), "{status}");
                assert_eq!(
                    status.contains("[未保存の設定変更があります]"),
                    dirty,
                    "{status}"
                );
            }
        }

        // A visible secret stays a generation target in both marker states.
        for dirty in [false, true] {
            assert_eq!(totp_copy_absent_status_for("JBSWY3DPEHPK3PXP", dirty), None);
        }
    }

    #[::core::prelude::v1::test]
    fn totp_copy_reports_the_undecryptable_sentinel_before_a_parse_failure() {
        // R2-UI-122: the sentinel carries visible text, so the visual emptiness
        // rule alone let it reach generation and be labelled an invalid secret.
        // The undecryptable branch must win and keep the unsaved marker.
        let sentinel = crate::vault_sync::UNDECRYPTABLE_TOTP;
        assert!(crate::vault_sync::is_undecryptable_totp(sentinel));
        assert!(
            !is_visually_empty(sentinel),
            "precondition: the sentinel has visible content"
        );

        for dirty in [false, true] {
            let status = totp_copy_absent_status_for(sentinel, dirty)
                .expect("an undecryptable field must be skipped on copy");
            assert!(status.contains("復号不可"), "{status}");
            assert!(!status.contains("不正"), "{status}");
            assert!(
                !status.contains("コピーできる TOTP がありません"),
                "{status}"
            );
            assert_eq!(status, totp_copy_undecryptable_status(dirty), "{status}");
            assert_ne!(status, totp_copy_absent_status(dirty), "{status}");
            assert_eq!(
                status.contains("[未保存の設定変更があります]"),
                dirty,
                "{status}"
            );
        }

        // A genuine malformed secret is not the sentinel and stays a generation
        // target; the detail row, not the copy skip, reports its parse failure.
        for dirty in [false, true] {
            assert_eq!(totp_copy_absent_status_for("not base32!", dirty), None);
        }
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
    fn cycle_statuses_report_the_current_filter_and_sort() {
        use crate::model::{Folder, ItemKind};

        let folders = [Folder {
            id: "f1".into(),
            name: "仕事".into(),
        }];
        let all = filter_cycle_status(&Filter::All, &folders, false);
        assert_eq!(all, "フィルターを切り替えました: すべてのアイテム");
        let favorites = filter_cycle_status(&Filter::Favorites, &folders, false);
        assert_eq!(favorites, "フィルターを切り替えました: お気に入り");
        assert_ne!(all, favorites);
        assert_eq!(
            filter_cycle_status(&Filter::Kind(ItemKind::Login), &folders, false),
            "フィルターを切り替えました: ログイン"
        );
        assert_eq!(
            filter_cycle_status(&Filter::Folder("f1".into()), &folders, false),
            "フィルターを切り替えました: 仕事"
        );
        assert!(
            filter_cycle_status(&Filter::Folder("missing".into()), &folders, false)
                .contains("不明なフォルダ")
        );

        // After a real cycle the status follows the filter now in effect.
        let mut view = VaultViewState::new();
        let before = filter_cycle_status(&view.filter, &folders, false);
        view.cycle_filter();
        let after = filter_cycle_status(&view.filter, &folders, false);
        assert_ne!(before, after);
        assert_eq!(after, favorites);

        let dirty = filter_cycle_status(&Filter::Favorites, &folders, true);
        assert_eq!(dirty, status_with_unsaved(&favorites, true));
        assert!(dirty.contains("[未保存の設定変更があります]"));

        let asc = sort_cycle_status(SortKey::NameAsc, false);
        assert_eq!(asc, "並び順を切り替えました: 名前 ↑");
        assert_eq!(
            sort_cycle_status(SortKey::NameDesc, false),
            "並び順を切り替えました: 名前 ↓"
        );
        assert_eq!(
            sort_cycle_status(SortKey::RecentlyModified, false),
            "並び順を切り替えました: 更新が新しい順"
        );
        assert_eq!(
            sort_cycle_status(SortKey::Kind, false),
            "並び順を切り替えました: 種類"
        );
        assert_eq!(
            sort_cycle_status(SortKey::NameAsc, true),
            status_with_unsaved(&asc, true)
        );
        assert!(sort_cycle_status(SortKey::NameAsc, true).contains("[未保存の設定変更があります]"));
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
    fn settings_panels_ignore_the_audit_refresh_status() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        let report = Report {
            items: vec![ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 0,
            logins: 1,
        };
        let normal = audit_refresh_status_for(Some(&report), Some(0), false);
        assert!(normal.as_ref().is_some_and(|s| s.contains("Example")));

        // `+`/`-` in these panels adjust thresholds and refresh the report;
        // the settings status must survive that refresh.
        for panel in [Panel::Settings, Panel::Generator] {
            assert_eq!(
                audit_refresh_status_for_panel(Some(&report), Some(0), false, panel),
                None,
                "{panel:?} must keep its settings status"
            );
        }
        for panel in [Panel::Vault, Panel::Audit] {
            assert_eq!(
                audit_refresh_status_for_panel(Some(&report), Some(0), false, panel),
                normal,
                "{panel:?} must still describe the refreshed row"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn auto_lock_status_keeps_the_unsaved_marker_and_lock_guidance() {
        let guidance = lock_guidance();
        let clean = auto_lock_status(300, false);
        assert_eq!(
            clean,
            format!("無操作のため自動ロックしました（5分）{guidance}")
        );
        assert!(!clean.contains("[未保存"));

        let dirty = auto_lock_status(300, true);
        assert!(dirty.starts_with(
            "無操作のため自動ロックしました（5分）（未保存の設定変更があります / 再ログイン後に保存してください）"
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
                    "無操作のため自動ロックしました（5分）（未保存の設定変更があります / 再ログイン後に保存してください）{guidance}"
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
                status.starts_with("無操作のため自動ロックしました（1分）"),
                "the timeout must be shown in minutes, like the settings panel: {status}"
            );
            assert!(
                status.contains(&manual_guidance),
                "idle lock must reuse the manual lock guidance: {status}"
            );
            for key in ["Enter: ログイン", "m: モック", FOCUS_RECOVERY_HINT] {
                assert!(status.contains(key), "missing {key} in {status}");
            }
        }
    }

    #[::core::prelude::v1::test]
    fn auto_lock_timeout_is_shown_in_minutes_without_dropping_the_remainder() {
        assert_eq!(idle_lock_minutes_text(0), "0分");
        assert_eq!(idle_lock_minutes_text(30), "0分30秒");
        assert_eq!(idle_lock_minutes_text(60), "1分");
        assert_eq!(idle_lock_minutes_text(61), "1分1秒");
        assert_eq!(idle_lock_minutes_text(90), "1分30秒");
        assert_eq!(idle_lock_minutes_text(300), "5分");
        assert_eq!(idle_lock_minutes_text(3600), "60分");

        // The status uses the same wording; a fractional minute keeps its
        // leftover seconds instead of being silently rounded down.
        assert_eq!(
            auto_lock_status(90, false),
            format!(
                "無操作のため自動ロックしました（1分30秒）{}",
                lock_guidance()
            )
        );
        assert_eq!(
            auto_lock_status(300, false),
            format!("無操作のため自動ロックしました（5分）{}", lock_guidance())
        );
        assert!(
            auto_lock_status(90, true).contains("[未保存の設定変更があります]"),
            "switching to minutes must not drop the unsaved marker"
        );
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
    fn refresh_audit_scroll_discards_a_queued_target_when_the_row_vanishes() {
        let mut handle = ScrollHandle::new();
        handle.set_offset(Point {
            x: px(0.0),
            y: px(240.0),
        });
        // The highlight before the refresh had a queued target at this row.
        handle.scroll_to_item(9);
        let old = handle.clone();

        let mut selection = Some(4);
        // The report became empty, so no row survives the clamp.
        refresh_audit_scroll(&mut handle, &mut selection, 0);

        assert_eq!(
            selection, None,
            "the vanished finding must not stay highlighted"
        );
        assert_eq!(
            handle.offset(),
            Point::default(),
            "a vanished selection must drop the stale queued target via a fresh handle"
        );
        assert_eq!(
            old.offset().y,
            px(240.0),
            "the old handle is replaced, not mutated: its queued target dies with it"
        );
    }

    #[::core::prelude::v1::test]
    fn refresh_audit_scroll_keeps_the_keyboard_target_when_a_row_survives() {
        let mut handle = ScrollHandle::new();
        handle.set_offset(Point {
            x: px(0.0),
            y: px(240.0),
        });
        let old = handle.clone();

        let mut selection = Some(4);
        // The report shrank but the row survives at a clamped index.
        refresh_audit_scroll(&mut handle, &mut selection, 3);

        assert_eq!(selection, Some(2), "clamping must keep the row in range");
        assert_eq!(
            handle.offset(),
            old.offset(),
            "the surviving path queues a target on the same handle instead of resetting it"
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
    fn panel_return_guidance_only_appears_when_settings_panels_are_left() {
        // Settings -> Generator (and the reverse) keeps the user on a panel
        // with `w`/`d`, so the old "go back" text must not be emitted.
        for (from, to) in [
            (Panel::Settings, Panel::Generator),
            (Panel::Generator, Panel::Settings),
        ] {
            assert_eq!(
                unsaved_panel_exit_status_for(from, to, true),
                None,
                "{from:?} -> {to:?} stays inside the settings-owning panels"
            );
        }

        // Leaving for a panel without `w`/`d` still needs the pointer back.
        for from in [Panel::Settings, Panel::Generator] {
            for to in [Panel::Vault, Panel::Audit] {
                assert_eq!(
                    unsaved_panel_exit_status_for(from, to, true),
                    Some(unsaved_panel_exit_status()),
                    "{from:?} -> {to:?} must point back to the save/discard keys"
                );
            }
        }

        // Clean state, no-op transitions and non-settings origins stay silent.
        assert_eq!(
            unsaved_panel_exit_status_for(Panel::Settings, Panel::Vault, false),
            None
        );
        assert_eq!(
            unsaved_panel_exit_status_for(Panel::Settings, Panel::Settings, true),
            None
        );
        assert_eq!(
            unsaved_panel_exit_status_for(Panel::Generator, Panel::Generator, true),
            None
        );
        assert_eq!(
            unsaved_panel_exit_status_for(Panel::Vault, Panel::Settings, true),
            None
        );
        assert_eq!(
            unsaved_panel_exit_status_for(Panel::Audit, Panel::Vault, true),
            None
        );
    }

    #[::core::prelude::v1::test]
    fn panel_transition_only_finishes_an_active_search() {
        let mut view = VaultViewState::new();
        view.vault.items.push(crate::model::VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        view.selected_id = Some("a".into());
        let rewinds = view.rewind_calls;

        // An ordinary panel change with no search must preserve the selected
        // row and its scroll target: `finish_search` rewinds unconditionally.
        finish_search_on_panel_transition(&mut view);
        assert_eq!(view.selected_id.as_deref(), Some("a"));
        assert_eq!(view.rewind_calls, rewinds);

        // Leaving an actual search still drops the now-meaningless selection.
        view.searching = true;
        finish_search_on_panel_transition(&mut view);
        assert!(!view.searching);
        assert_eq!(view.selected_id, None);
        assert_eq!(view.rewind_calls, rewinds + 1);
    }

    #[::core::prelude::v1::test]
    fn finish_search_wires_deselection_to_totp_clear() {
        let mut view = VaultViewState::new();
        view.vault.items.push(crate::model::VaultItem::new(
            "a",
            "Alpha",
            ItemData::Login {
                username: "u".into(),
                password: Zeroizing::new("p".into()),
                totp: Zeroizing::new(TOTP_SECRET.into()),
                uris: Vec::new(),
            },
        ));
        view.selected_id = Some("a".into());

        let mut totp = TotpState::new();
        let _ = totp.display(TOTP_SECRET, 40);
        assert!(totp.has_secret(), "precondition: a secret is cached");

        // An ordinary sync with a still-matching selection keeps the secret.
        sync_totp_to_selection_state(&mut view, &mut totp);
        assert!(totp.has_secret(), "a matching selection must not be wiped");

        // Confirming the search drops the selection and, in one step, the
        // cached secret from the row that was just deselected.
        finish_search_and_sync_totp(&mut view, &mut totp);
        assert_eq!(view.selected_id, None);
        assert!(
            !view.totp_stale_after_deselect,
            "the signal must be consumed"
        );
        assert!(
            !totp.has_secret(),
            "finish_search must not leave a stale TOTP secret behind"
        );

        // The view-only path used by callers that cannot see `TotpState`:
        // deselecting and then syncing must clear the cached secret too.
        let _ = totp.display(TOTP_SECRET, 40);
        assert!(totp.has_secret());
        view.selected_id = Some("a".into());
        view.deselect_and_rewind();
        sync_totp_to_selection_state(&mut view, &mut totp);
        assert!(
            !totp.has_secret(),
            "a plain sync must consume the stale signal raised by deselection"
        );
    }

    #[::core::prelude::v1::test]
    fn panel_transition_restores_a_normal_status_after_an_edit_mode() {
        // The modes cleared by `set_panel` all install the "入力中:" prefix;
        // without this assertion the test would pass without exercising the
        // stale-status bug.
        assert!(crate::ui::input::text_edit_start_status(false).contains("入力中"));

        // With no edit mode active the caller keeps its existing status.
        for panel in [
            Panel::Vault,
            Panel::Audit,
            Panel::Generator,
            Panel::Settings,
        ] {
            assert_eq!(
                panel_transition_status_after_edit(
                    panel,
                    ExitedEditMode::None,
                    3,
                    false,
                    None,
                    None,
                ),
                None,
                "{panel:?} without an edit mode must not overwrite the status"
            );
        }

        for dirty in [false, true] {
            // Leaving a search keeps the count-aware vault message (or the
            // audit message when the audit panel is the destination).
            let vault = panel_transition_status_after_edit(
                Panel::Vault,
                ExitedEditMode::Search,
                3,
                dirty,
                None,
                None,
            )
            .unwrap();
            assert_eq!(vault, crate::ui::input::search_finished_status(3, dirty));
            assert!(!vault.contains("入力中"), "{vault}");

            let audit = panel_transition_status_after_edit(
                Panel::Audit,
                ExitedEditMode::Search,
                3,
                dirty,
                None,
                None,
            )
            .unwrap();
            assert_eq!(audit, audit_no_selection_status(dirty));
            assert!(!audit.contains("入力中"), "{audit}");

            // A confirmed search with no visible row gets the dedicated
            // message, not a prompt to select a non-existent row.
            let empty = panel_transition_status_after_edit(
                Panel::Vault,
                ExitedEditMode::Search,
                0,
                dirty,
                None,
                None,
            )
            .unwrap();
            assert_eq!(empty, crate::ui::input::search_finished_status(0, dirty));
            assert!(empty.contains("0件"), "{empty}");

            // A search left for a settings-owning panel keeps the settings
            // feedback (the destination still owns `w`/`d`).
            for panel in [Panel::Settings, Panel::Generator] {
                let status = panel_transition_status_after_edit(
                    panel,
                    ExitedEditMode::Search,
                    3,
                    dirty,
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(
                    status,
                    crate::ui::input::settings_edit_finished_status(dirty),
                    "{panel:?}"
                );
            }

            // Leaving a settings field keeps its save/discard guidance,
            // whichever panel is the destination.
            for panel in [
                Panel::Vault,
                Panel::Audit,
                Panel::Settings,
                Panel::Generator,
            ] {
                let status = panel_transition_status_after_edit(
                    panel,
                    ExitedEditMode::SettingsField,
                    3,
                    dirty,
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(
                    status,
                    crate::ui::input::settings_edit_finished_status(dirty),
                    "{panel:?}"
                );
                assert!(!status.contains("入力中"), "{status}");
            }

            // Leaving an auth field restores the lock-screen hint.
            let auth = panel_transition_status_after_edit(
                Panel::Vault,
                ExitedEditMode::AuthField,
                3,
                dirty,
                None,
                None,
            )
            .unwrap();
            assert_eq!(auth, crate::ui::input::auth_edit_finished_status(dirty));
            assert!(!auth.contains("入力中"), "{auth}");
        }
    }

    #[::core::prelude::v1::test]
    fn panel_transition_status_distinguishes_the_exited_edit_mode() {
        // The old `was_editing: bool` made every edit mode landing on the
        // vault panel report a finished search, hiding the settings save
        // hint. The three modes must now produce three different statuses.
        let search = panel_transition_status_after_edit(
            Panel::Vault,
            ExitedEditMode::Search,
            3,
            false,
            None,
            None,
        )
        .unwrap();
        let settings = panel_transition_status_after_edit(
            Panel::Vault,
            ExitedEditMode::SettingsField,
            3,
            false,
            None,
            None,
        )
        .unwrap();
        let auth = panel_transition_status_after_edit(
            Panel::Vault,
            ExitedEditMode::AuthField,
            3,
            false,
            None,
            None,
        )
        .unwrap();
        assert_ne!(search, settings);
        assert_ne!(search, auth);
        assert_ne!(settings, auth);
        assert_eq!(search, crate::ui::input::search_finished_status(3, false));
        assert_eq!(
            settings,
            crate::ui::input::settings_edit_finished_status(false)
        );
        assert_eq!(auth, crate::ui::input::auth_edit_finished_status(false));
        assert!(settings.contains("w: 保存 / d: 破棄"), "{settings}");
        assert!(!settings.contains("項目を選択してください"), "{settings}");
        assert!(auth.contains("F1: フォーカス復帰"), "{auth}");

        // The unsaved marker survives every mode's restored status.
        for mode in [
            ExitedEditMode::Search,
            ExitedEditMode::SettingsField,
            ExitedEditMode::AuthField,
        ] {
            let clean =
                panel_transition_status_after_edit(Panel::Vault, mode, 3, false, None, None)
                    .unwrap();
            let dirty = panel_transition_status_after_edit(Panel::Vault, mode, 3, true, None, None)
                .unwrap();
            assert_eq!(dirty, status_with_unsaved(&clean, true), "{mode:?}");
            assert!(dirty.contains("[未保存の設定変更があります]"), "{mode:?}");
        }
    }

    #[::core::prelude::v1::test]
    fn audit_search_exit_status_describes_the_highlighted_row() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        fn report() -> Report {
            Report {
                items: vec![
                    ItemReport {
                        id: "item-1".into(),
                        name: "First finding".into(),
                        kind: ItemKind::Login,
                        findings: Vec::new(),
                    },
                    ItemReport {
                        id: "item-2".into(),
                        name: "Second finding".into(),
                        kind: ItemKind::Login,
                        findings: Vec::new(),
                    },
                ],
                examined: 2,
                with_totp: 0,
                logins: 2,
            }
        }

        let report = report();

        // A row highlighted before the search must still be described; the old
        // unconditional "no selection" status denied a visible highlight.
        let selected = audit_search_exit_status(Some(&report), Some(1), false);
        assert_eq!(
            selected,
            format!(
                "監査行 2/2: Second finding（Enter: 対象を選択 / g: 一覧 / Esc: 終了 / {FOCUS_RECOVERY_HINT}）"
            )
        );
        assert!(!selected.contains("選択されていません"), "{selected}");

        let selected_dirty = audit_search_exit_status(Some(&report), Some(1), true);
        assert_eq!(selected_dirty, status_with_unsaved(&selected, true));
        assert!(selected_dirty.contains("[未保存の設定変更があります]"));

        // A stale index is clamped to the last row instead of losing the row.
        let clamped = audit_search_exit_status(Some(&report), Some(9), false);
        assert!(clamped.contains("2/2: Second finding"), "{clamped}");

        // With no highlight the "no selection" guidance is restored.
        for dirty in [false, true] {
            let none = audit_search_exit_status(Some(&report), None, dirty);
            assert_eq!(none, audit_no_selection_status(dirty));
        }

        // No report at all is a no-selection case too.
        assert_eq!(
            audit_search_exit_status(None, Some(0), false),
            audit_no_selection_status(false)
        );
    }

    #[::core::prelude::v1::test]
    fn audit_search_exit_status_does_not_ask_for_a_row_in_an_empty_report() {
        // A confirmed search onto an empty audit report used to fall through
        // to `audit_no_selection_status`, which tells the user to press ↑↓
        // even though there is no finding to highlight.
        let empty = audit_search_exit_status(Some(&Report::default()), Some(0), false);
        assert_eq!(empty, "監査する問題がありません（↑↓で行を選択できません）");
        assert!(!empty.contains("選択されていません"), "{empty}");

        let dirty = audit_search_exit_status(Some(&Report::default()), Some(3), true);
        assert_eq!(dirty, status_with_unsaved(&empty, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");

        // A stale selection is irrelevant: an empty report has no rows to
        // clamp onto, so the wording stays count-aware for every input.
        for selection in [None, Some(0), Some(usize::MAX)] {
            assert_eq!(
                audit_search_exit_status(Some(&Report::default()), selection, false),
                empty,
                "selection {selection:?}"
            );
        }

        // The two other branches keep their wording: a non-empty report with
        // no highlight is a "no selection" case, and so is no report at all.
        assert_eq!(
            audit_search_exit_status(None, Some(0), false),
            audit_no_selection_status(false)
        );
    }

    #[::core::prelude::v1::test]
    fn search_exit_onto_audit_uses_the_selection_in_the_transition_status() {
        use crate::health::ItemReport;
        use crate::model::ItemKind;

        let report = Report {
            items: vec![ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 0,
            logins: 1,
        };

        // The audit branch of a Search exit must consult the passed-in state.
        let selected = panel_transition_status_after_edit(
            Panel::Audit,
            ExitedEditMode::Search,
            3,
            false,
            Some(&report),
            Some(0),
        )
        .unwrap();
        assert_eq!(
            selected,
            audit_search_exit_status(Some(&report), Some(0), false)
        );
        assert!(selected.contains("監査行 1/1: Example"), "{selected}");
        assert!(!selected.contains("入力中"), "{selected}");

        // Without a highlight the same branch still reports no selection.
        let none = panel_transition_status_after_edit(
            Panel::Audit,
            ExitedEditMode::Search,
            3,
            false,
            Some(&report),
            None,
        )
        .unwrap();
        assert_eq!(none, audit_no_selection_status(false));
        assert_ne!(selected, none);
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
    fn empty_vault_move_announces_the_blocked_key() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        // The branch that installs the status is reachable exactly when the
        // visible list has no rows, for every relative key and direction.
        let mut view = VaultViewState::new();
        for delta in [1, -1, 10, -10] {
            assert_eq!(view.next_index(delta), None, "delta {delta}");
        }
        view.vault.items.push(VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        assert_eq!(view.next_index(1), Some(0), "a row makes moves possible");

        for dirty in [false, true] {
            let status = BitwardenApp::empty_vault_move_status(dirty);
            assert_eq!(status, crate::ui::input::no_rows_status(dirty));
            assert!(status.contains("行がありません"), "{status}");
            assert_eq!(
                status.contains("[未保存の設定変更があります]"),
                dirty,
                "{status}"
            );
        }
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
    fn password_detail_label_agrees_with_the_copy_rule_on_absent_values() {
        use crate::model::ItemData;
        use crate::ui::logic::select_copy_value;
        use crate::vault_sync::UNDECRYPTABLE_PASSWORD;
        use zeroize::Zeroizing;

        let login = |password: &str| ItemData::Login {
            username: "alice@example.com".to_string(),
            password: Zeroizing::new(password.to_string()),
            totp: Zeroizing::new(String::new()),
            uris: Vec::new(),
        };

        // Whitespace and invisible-only (Cf) values look empty and are refused
        // by the copy path; the detail row must not advertise a character count.
        for blank in ["", "   \t ", "\u{200b}", "\u{200b}\u{feff}\u{202e}"] {
            assert_eq!(password_detail_label(blank), "なし", "{blank:?}");
            assert_eq!(select_copy_value(&login(blank), true), None, "{blank:?}");
        }

        // A visible secret keeps its old label and remains copyable.
        assert_eq!(password_detail_label("s3cret"), "6文字");
        assert_eq!(password_detail_label(" alice "), "7文字");
        assert_eq!(
            select_copy_value(&login("s3cret"), true).as_deref(),
            Some("s3cret")
        );

        // The decryption marker keeps its dedicated label and is not copied.
        assert_eq!(password_detail_label(UNDECRYPTABLE_PASSWORD), "復号不可");
        assert_eq!(
            select_copy_value(&login(UNDECRYPTABLE_PASSWORD), true),
            None
        );
    }

    #[::core::prelude::v1::test]
    fn join_detail_fields_drops_empty_fields_and_their_separators() {
        let base = "ログイン | example | 更新: 不明";

        // With no empty fields the join is unchanged.
        assert_eq!(
            join_detail_fields(base, &["alice".into(), "パスワード: 12文字".into()]),
            format!("{base} | alice | パスワード: 12文字")
        );

        // An empty middle field must not leave a double separator behind.
        assert_eq!(
            join_detail_fields(base, &["".into(), "パスワード: 12文字".into()]),
            format!("{base} | パスワード: 12文字")
        );
        assert!(!join_detail_fields(base, &["".into(), "x".into()]).contains(" |  | "));

        // An empty trailing field must not leave a dangling separator.
        assert_eq!(
            join_detail_fields(base, &["alice".into(), "".into()]),
            format!("{base} | alice")
        );
        assert!(!join_detail_fields(base, &["alice".into(), "".into()]).ends_with(" | "));

        // All fields empty: only the base remains.
        assert_eq!(join_detail_fields(base, &["".into(), "".into()]), base);

        // Whitespace-only and Unicode Cf-only fields are invisible as well.
        let joined = join_detail_fields(
            base,
            &[
                "   ".into(),
                "\u{200b}\u{feff}\u{202e}".into(),
                "末尾: 1234".into(),
            ],
        );
        assert_eq!(joined, format!("{base} | 末尾: 1234"));
        assert!(!joined.contains(" |  | "));
    }

    #[::core::prelude::v1::test]
    fn is_visually_empty_treats_blank_and_cf_only_text_as_empty() {
        assert!(is_visually_empty(""));
        assert!(is_visually_empty("  \t "));
        // Zero-width space, BOM and bidi override are all Unicode Cf.
        assert!(is_visually_empty("\u{200b}\u{feff}\u{202e}"));
        assert!(!is_visually_empty("alice"));
        assert!(!is_visually_empty(" alice "));
        // A visible character next to a Cf is still real content.
        assert!(!is_visually_empty("alice\u{200b}"));
    }

    #[::core::prelude::v1::test]
    fn is_visually_empty_treats_cc_controls_as_empty_like_the_model() {
        // NUL, DEL and the C1 controls are Unicode Cc, not whitespace. The UI
        // rule must include `char::is_control`, exactly like
        // `model::is_visually_empty` and `auth::credential_is_blank`; otherwise
        // a Cc-only name / TOTP value counts as present in the UI alone.
        for control in ['\u{0}', '\u{1}', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}'] {
            let value = control.to_string();
            assert!(
                is_visually_empty(&value),
                "Cc U+{:04X} must be invisible",
                control as u32
            );
            // Cc mixed with whitespace and Cf is still invisible on the rule.
            let mixed = format!(" \u{200b}{control}\t");
            assert!(
                is_visually_empty(&mixed),
                "mixed Cc U+{:04X} must be invisible",
                control as u32
            );
            // One visible character makes the value present again.
            assert!(!is_visually_empty(&format!("{control}GitHub")));
        }
        // The pre-existing halves of the rule still hold.
        assert!(is_visually_empty(" \t\n \u{200b}"));
        assert!(!is_visually_empty("GitHub"));
    }

    #[::core::prelude::v1::test]
    fn item_name_text_uses_a_placeholder_for_invisible_names() {
        for invisible in [
            "",
            "  \t\u{3000}",
            "\u{200b}",
            "\u{feff}\u{202e}",
            " \u{00ad} ",
        ] {
            assert_eq!(
                item_name_text(invisible),
                ITEM_NAME_PLACEHOLDER,
                "invisible name {invisible:?} must not leave a blank cell"
            );
        }
        assert_eq!(item_name_text("Bank"), "Bank");
        assert_eq!(item_name_text(" alice "), " alice ");
        // A visible character next to a Cf is a real name and is kept as-is.
        let mixed = "Bank\u{200b}";
        assert_eq!(item_name_text(mixed), mixed);

        // The detail base interpolates the name between two separators. The
        // placeholder must keep the line from collapsing into " |  | ".
        let base = format!("ログイン | {} | 更新: 不明", item_name_text("\u{200b}"));
        assert!(base.contains(ITEM_NAME_PLACEHOLDER), "{base}");
        assert!(!base.contains(" |  | "), "{base}");
        assert!(base.starts_with("ログイン | "), "{base}");
    }

    #[::core::prelude::v1::test]
    fn totp_code_text_treats_cf_only_secret_as_absent() {
        fn generated(_secret: &str) -> (String, Option<String>) {
            ("123456".to_string(), None)
        }

        // A blank secret used to be caught by `trim()`; a Cf-only one was not
        // and reached code generation. Both must now render the placeholder.
        // The generator must not even be called, so a failure reason cannot
        // leak into the placeholder.
        for absent in ["", "  \t ", "\u{200b}\u{feff}\u{202e}"] {
            let mut called = false;
            let text = totp_code_text(absent, |secret| {
                called = true;
                generated(secret)
            });
            assert_eq!(text, "なし", "secret {absent:?}");
            assert!(!called, "no generation for an absent secret {absent:?}");
        }

        // A real secret still generates a code and still reports failures.
        assert_eq!(totp_code_text("JBSWY3DPEHPK3PXP", generated), "123456");
        assert_eq!(
            totp_code_text("JBSWY3DPEHPK3PXP", |_| {
                ("コード生成失敗".to_string(), Some("理由".into()))
            }),
            "コード生成失敗（不正な TOTP secret: 理由）"
        );
    }

    #[::core::prelude::v1::test]
    fn totp_code_text_uses_the_error_sampled_after_generation() {
        // The detail row used to read `error_message()` before calling
        // `totp_text`, which re-samples the cached tick. A direct switch from
        // a valid code to a malformed secret therefore showed the previous
        // selection's (empty) reason for one frame.
        let valid = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let mut state = TotpState::new();
        assert!(state.display(valid, 40).starts_with("287 082"));
        let stale = state.error_message();
        assert_eq!(stale, None, "precondition: no cached failure yet");

        let broken = "not base32!";
        let text = totp_code_text(broken, |secret| {
            let generated = state.display(secret, 40);
            let error = state.error_message();
            assert_ne!(error, stale, "the re-sample must replace the old reason");
            (generated, error)
        });
        assert!(
            text.contains("コード生成失敗（不正な TOTP secret"),
            "{text}"
        );
        assert!(
            text.contains("解釈できません"),
            "the new sample's reason must be shown: {text}"
        );
    }

    #[::core::prelude::v1::test]
    fn login_uri_text_shows_none_for_absent_uris() {
        use crate::model::LoginUri;

        // No URI at all.
        assert_eq!(login_uri_text(&[]), "なし");
        // Empty, whitespace-only and invisible-only values are absent, not
        // invalid: `mask_uri` would otherwise report `(不正な URI)` for them.
        assert_eq!(login_uri_text(&[LoginUri::new("")]), "なし");
        assert_eq!(login_uri_text(&[LoginUri::new("  \t ")]), "なし");
        assert_eq!(
            login_uri_text(&[LoginUri::new("\u{200b}\u{feff}\u{202e}")]),
            "なし"
        );
        // A real URI is still masked to scheme + host.
        assert_eq!(
            login_uri_text(&[LoginUri::new("https://user:token@example.com/secret")]),
            "https://example.com"
        );
    }

    #[::core::prelude::v1::test]
    fn login_uri_text_skips_absent_leading_uris() {
        use crate::model::LoginUri;

        let uris = [
            LoginUri::new(""),
            LoginUri::new("  \t "),
            LoginUri::new("\u{200b}\u{feff}"),
            LoginUri::new("https://user:token@example.com/secret"),
            LoginUri::new("https://other.example.org/path"),
        ];
        let shown = login_uri_text(&uris);
        assert_eq!(
            shown, "https://example.com",
            "the first visible URI must win even behind blank entries"
        );
        assert!(
            !shown.contains("user:token"),
            "the chosen URI must be masked: {shown}"
        );

        // All entries absent: still the "なし" placeholder, never "(不正な URI)".
        let absent = [
            LoginUri::new(""),
            LoginUri::new(" \u{202e} "),
            LoginUri::new("   "),
        ];
        assert_eq!(login_uri_text(&absent), "なし");
        assert_eq!(login_uri_text(&[]), "なし");

        // A single blank entry followed by a valid one must not hide it.
        assert_eq!(
            login_uri_text(&[
                LoginUri::new("\u{00ad}"),
                LoginUri::new("https://a.example.com")
            ]),
            "https://a.example.com"
        );
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
