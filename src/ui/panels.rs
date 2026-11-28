//! Panel renderers and small row helpers used by the GPUI window.

use gpui_kit::prelude::*;
use gpui_kit::StatefulInteractiveElement;
use gpui_kit::*;

use crate::generator::{passphrase_entropy, password_entropy, Strength};
use crate::health::{has_totp_field, has_usable_totp, ItemReport, Report, Severity};
use crate::settings::Settings;
use crate::ui::app::{is_visually_empty, visible_char_count};
use crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
use crate::ui::logic::{settings_hint, unsaved_marker, FOCUS_RECOVERY_HINT};
use crate::ui::state::{GeneratorState, Panel, SettingsField};
use crate::vault_sync::is_undecryptable_totp;

/// Number of header rows rendered before the first audit item.
pub(super) const AUDIT_HEADER_ROWS: usize = 3;

/// Scroll guidance for panels with no keyboard-reachable scroll handle.
///
/// Only `audit_panel` receives a `ScrollHandle`, and only the vault list owns
/// `VaultViewState::scroll_handle`. The generator and settings roots keep their
/// offset in element state, so there is no handle for `ui::input` to scroll on
/// Up/Down; adding one would require new state outside this module. Up/Down
/// therefore stay `UiAction::None` in those panels, and the inline hints say
/// so explicitly instead of implying a keyboard path exists.
pub(super) const MOUSE_WHEEL_SCROLL_ONLY_HINT: &str = "スクロールはマウス／ホイールのみ";

/// Navigation keys for the vault list and the audit rows.
///
/// `ui::keys::classify_key` binds `PageUp`/`PageDown` to `MoveSelectionPage`
/// and `Home`/`End` to `MoveSelectionToEdge` in both panels, so their inline
/// hints must advertise those keys alongside Up/Down instead of promising only
/// single-row moves. Kept as one shared constant so the two hints cannot drift
/// apart.
pub(super) const LIST_PAGE_AND_EDGE_HINT: &str =
    "PageUp/PageDown: 固定10行ずつ移動 / Home/End: 先頭/末尾へ移動";

/// Row-navigation keys shared by every panel that renders a selectable list.
///
/// This bundles Up/Down and the shared page/edge keys, but deliberately not
/// `Enter`: the audit panel binds `Enter` to focus a finding while the vault
/// panel has no `enter` binding at all (`ui::keys::classify_key`). Keeping the
/// navigation portion in one helper lets both panels advertise the same keys
/// without either promising a selection path it does not implement.
/// `selectable_rows` is the number of rows the user can actually select. With
/// zero rows these keys would promise a selection path that does not exist, so
/// the empty case returns `""`; callers then drop only the navigation portion
/// (including its leading separator) and keep their panel-specific commands.
/// Pure, so the wording can be pinned by tests without rendering a GPUI window.
fn row_navigation_keys_hint(selectable_rows: usize) -> String {
    if selectable_rows == 0 {
        String::new()
    } else {
        format!("↑↓: 行を選択 / {LIST_PAGE_AND_EDGE_HINT}")
    }
}

/// Main vault commands shown in the list header after the row keys.
///
/// `ui::keys::classify_key` binds all of these in `Panel::Vault`: `/` starts a
/// search, `t`/`s` cycle filter and sort, `f` toggles a favorite, `y`/`p`/`u`
/// copy the TOTP code, password and username, `g` opens the audit report,
/// `n`/`c` switch panels, `l` locks the vault and `Esc` quits. The header used
/// to advertise row movement only, leaving none of these discoverable on the
/// vault screen. Kept as a constant so the wording can be pinned by tests
/// without rendering a GPUI window.
///
/// `f`/`y`/`p`/`u` act on the highlighted row, so an empty list uses
/// [`VAULT_SELECTION_FREE_KEYS_HINT`] instead of this constant. Both strings
/// are pinned by tests so the selection-dependent subset cannot drift.
pub(super) const VAULT_MAIN_KEYS_HINT: &str = "/: 検索 / t: フィルタ / s: 並び替え / f: お気に入り / y: TOTP をコピー / p: パスワードをコピー / u: ユーザー名をコピー / g: 監査 / n: 生成 / c: 設定 / l: ロック / Esc: 終了";

/// Vault commands that need no selected row.
///
/// `/` opens search, `t`/`s` change the list view and `g`/`n`/`c`/`l`/`Esc`
/// switch panels, lock or quit. None of them reads a highlighted item, so they
/// stay discoverable when the vault has zero rows; `f`/`y`/`p`/`u` do not.
pub(super) const VAULT_SELECTION_FREE_KEYS_HINT: &str =
    "/: 検索 / t: フィルタ / s: 並び替え / g: 監査 / n: 生成 / c: 設定 / l: ロック / Esc: 終了";

/// Row and command keys for the vault list, with no `Enter` promise.
///
/// `Enter` is bound only in the audit panel, so the vault header must not
/// advertise it. The navigation portion is byte-for-byte the audit variant's
/// prefix; the vault-only command list is appended after it. `searching` is
/// the vault's text-edit mode: while it is active `ui::keys::classify_key`
/// routes Up/Down/PageUp/PageDown/Home/End nowhere (or inserts them as text)
/// and the command letters become search text, so the header must not promise
/// either path.
///
/// With zero selectable rows the navigation helper returns `""` because there
/// is nothing to move to. Selection-dependent commands (`f` favorite, `y`/`p`/`u`
/// copy) are dropped too, since there is no highlighted row for them to act on;
/// returning [`VAULT_SELECTION_FREE_KEYS_HINT`] keeps the row-independent
/// commands discoverable on an empty vault without advertising row movement or
/// the audit-only `Enter`. Kept pure so the wording can be pinned by tests
/// without a GPUI window.
///
/// `query_nonempty` is the confirmed-query flag used by
/// [`crate::ui::input::confirmed_query_nonempty`] and the `KeyContext` in
/// `ui::keys`. When it is set, Backspace and non-command characters still edit
/// the query after Enter/Escape confirmed it, so the header must advertise
/// [`CONFIRMED_QUERY_REEDIT_HINT`] rather than leaving those keys discoverable
/// only through the temporary status. Search mode stays silent: there the
/// characters are a fresh query, not a confirmed one being re-edited.
pub(super) fn vault_row_keys_hint(
    selectable_rows: usize,
    searching: bool,
    query_nonempty: bool,
) -> String {
    if searching {
        String::new()
    } else {
        let navigation = row_navigation_keys_hint(selectable_rows);
        let keys = if navigation.is_empty() {
            VAULT_SELECTION_FREE_KEYS_HINT.to_string()
        } else {
            format!("{navigation} / {VAULT_MAIN_KEYS_HINT}")
        };
        if query_nonempty {
            format!("{keys} / {CONFIRMED_QUERY_REEDIT_HINT}")
        } else {
            keys
        }
    }
}

/// Row-selection keys for the audit panel, including `Enter`.
///
/// The audit detail line uses this variant because `enter` focuses the
/// highlighted finding there. It reuses the private `row_navigation_keys_hint`
/// so its navigation portion cannot drift from the vault header's. Pure, so the
/// wording can be pinned by tests without rendering a GPUI window.
pub(super) fn row_selection_keys_hint(selectable_rows: usize) -> String {
    let navigation = row_navigation_keys_hint(selectable_rows);
    if navigation.is_empty() {
        navigation
    } else {
        format!("{navigation} / Enter: 対象を選択")
    }
}

/// Labels for the two `+/-` rows in the generator panel.
///
/// Both labels explicitly say that the same key changes the *other* generator
/// setting too; `apply_generator_key` truly mutates both values at once.
pub(super) fn generator_length_labels(
    password_len: usize,
    words: usize,
    pw_bits: f64,
    pp_bits: f64,
    separator: &str,
) -> (String, String) {
    let password_label = format!(
        "+/-  長さ: {password_len}（パスフレーズ語数も同時に変更）  |  強度: {} ({pw_bits:.0} bit)",
        Strength::from_bits(pw_bits).label()
    );
    let passphrase_label = format!(
        "+/-  単語数: {words}（パスワード長も同時に変更）  |  ,  区切り: {}  |  強度: {} ({pp_bits:.0} bit)",
        separator_label(separator),
        Strength::from_bits(pp_bits).label()
    );
    (password_label, passphrase_label)
}

/// Inline key hint for the generator panel, including its scroll limitation.
///
/// `F1` is the global focus-recovery key and belongs in every persistent hint
/// just as it does in `settings_hint`; without it a generator user who loses
/// focus has no on-screen way to find the way back. `c` is the direct jump to
/// `Panel::Settings` (`ui::keys::classify_key`), matching the other panels'
/// hints, while `n` keeps its generator-local "back to vault" meaning. Pure so
/// the wording can be pinned by tests without rendering a GPUI window.
pub(super) fn generator_panel_key_hint(clipboard_restore_seconds: u64) -> String {
    format!(
        "p/h: 生成 / y: パスワードをコピー / Y: パスフレーズをコピー（{clipboard_restore_seconds}秒で復元） / w: 設定を保存 / d: 破棄 / c: 設定 / n: 一覧に戻る / l: ロック / Esc: 終了 / {FOCUS_RECOVERY_HINT} / {MOUSE_WHEEL_SCROLL_ONLY_HINT}"
    )
}

/// Inline key hint for the settings panel, including its scroll limitation.
///
/// `settings_hint` already carries the settings-specific keys and avoids the
/// status bar's "入力中:" prefix; appending the scroll note must not reintroduce
/// that prefix here. While a field is focused, the keys that look like settings
/// commands but are actually inserted as text (`+`/`-`, `1`-`6`, `i`/`u`, and
/// `n`, which otherwise jumps to the generator panel) are spelled out here,
/// because `settings_hint(true)` only lists the letter keys. Naming `n` here is
/// what makes the generator-panel key discoverable during editing: the jump
/// itself cannot fire until Enter/Escape confirms the field
/// (`ui::keys::classify_key`), so the wording says so instead of promising it.
pub(super) fn settings_panel_key_hint(editing: bool) -> String {
    if editing {
        format!(
            "{} / +/-, 1-6（1〜6）, i/u, n（生成パネルへ）も文字として入力（設定値は変更しません / n: 生成へ は確定後に有効） / {}",
            settings_hint(editing),
            MOUSE_WHEEL_SCROLL_ONLY_HINT
        )
    } else {
        format!(
            "{} / {}",
            settings_hint(editing),
            MOUSE_WHEEL_SCROLL_ONLY_HINT
        )
    }
}

/// Compose the key guidance drawn in a panel's fixed footer.
///
/// The settings and generator panels scroll their body with
/// `.overflow_y_scroll()`. Their key hint used to be the last child of that
/// scrollable div, so [`FOCUS_RECOVERY_HINT`] was invisible until the user
/// scrolled to the end — exactly when a lost focus is hardest to recover from.
/// Both panels now render the hint through this helper in a footer *outside*
/// the scroll container, so F1 is always on screen. Keeping the composition
/// pure lets the "always visible" contract be pinned without a GPUI window.
pub(super) fn panel_key_hint_footer(hint: &str) -> String {
    format!("操作: {hint}")
}

/// Generator-settings summary line shown in the settings panel.
///
/// `ui::keys::classify_key` binds `n` directly to `Panel::Generator` in
/// `Panel::Settings`, so the guidance must not send the user back to the vault
/// list first (the old wording did). While a settings field is focused, `n` is
/// inserted as text instead of jumping to the generator, so this jump hint is
/// suppressed rather than advertising a command that cannot fire; the editing
/// key guide (`settings_panel_key_hint(true)`) names the same `n` key with the
/// "文字として入力" wording instead. Pure so the rendered text can be pinned
/// without a GPUI window.
pub(super) fn settings_generator_summary_line(
    password_length: usize,
    passphrase_words: usize,
    editing: bool,
) -> String {
    // Editing: `settings_panel_key_hint(true)` already carries the n key, so
    // keep this line free of a jump promise that `classify_key` cannot honour.
    let jump_hint = if editing { "" } else { "（n: 生成へ）" };
    format!(
        "生成設定: パスワード {password_length} 文字 / パスフレーズ {passphrase_words} 語{jump_hint}"
    )
}

/// Timeout summary line shown in the settings panel.
///
/// The auto-lock value must use exactly the wording of the idle-lock status in
/// `app.rs`: a plain `idle_lock_seconds / 60` silently dropped the leftover
/// seconds, so 90 s was shown as "1 分" even though the lock fires at 1分30秒.
/// Pure so the rendered text can be pinned without a GPUI window.
pub(super) fn settings_timeout_summary_line(
    idle_lock_seconds: u64,
    login_timeout_seconds: u64,
    clipboard_restore_seconds: u64,
) -> String {
    format!(
        "自動ロック: {}（i/u） / ログイン制限: {} 秒（3/4） / 復元: {} 秒（5/6）",
        crate::ui::app::idle_lock_minutes_text(idle_lock_seconds),
        login_timeout_seconds,
        clipboard_restore_seconds
    )
}

/// Colour for a finding's severity on an unselected audit row.
fn severity_color(severity: Severity) -> u32 {
    match severity {
        Severity::High => 0xf38ba8,
        Severity::Medium => 0xf9e2af,
        Severity::Low => 0xa6adc8,
    }
}

/// Brighter severity tints for the selected audit row.
///
/// Selecting a row swaps its background from `0x1e1e2e` to `0x45475a`. The
/// normal high (`~3.9:1`) and low (`~4.1:1`) tints then fall below WCAG 1.4.3's
/// 4.5:1 minimum for small text. These variants keep the same hues while
/// clearing that threshold; medium already clears it and keeps its colour.
const SELECTED_HIGH_SEVERITY_COLOR: u32 = 0xffb3c8;
const SELECTED_LOW_SEVERITY_COLOR: u32 = 0xcdd6f4;

fn severity_color_for_row(severity: Severity, selected: bool) -> u32 {
    if selected {
        match severity {
            Severity::High => SELECTED_HIGH_SEVERITY_COLOR,
            Severity::Medium => severity_color(Severity::Medium),
            Severity::Low => SELECTED_LOW_SEVERITY_COLOR,
        }
    } else {
        severity_color(severity)
    }
}

/// Audit row text with a non-colour marker for the highlighted row.
///
/// The selection background alone cannot be distinguished by colour-blind
/// users. A leading triangle mirrors the header tabs' `panel_button_label`
/// cue, so selection stays readable without colour perception.
pub(super) fn audit_row_label(text: &str, selected: bool) -> String {
    if selected {
        format!("▶ {text}")
    } else {
        text.to_string()
    }
}

/// Compose the text drawn for one audit row, before the selection marker.
///
/// `health::audit` normally replaces a blank `ItemReport.name` with the shared
/// placeholder, but a report can also be assembled directly (tests, other
/// callers) with a visually empty name. Routing the name through
/// `item_name_text` here applies the same `is_visually_empty` rule as the vault
/// list and detail rows, so a Cf-only name cannot render as `"[高]  (Login)"`.
/// Pure so the contract can be tested without a GPUI window.
fn audit_row_text(item: &ItemReport) -> String {
    format!(
        "[{}] {} ({})",
        item.worst().map_or("?", Severity::label),
        crate::ui::app::item_name_text(&item.name),
        item.kind.label()
    )
}

/// The status of a TOTP badge in the vault list.
///
/// Uses the public health predicates added for this purpose so the list, the
/// audit counter and the `NoTotp` finding share one definition of "usable".
/// A field that exists but is malformed or undecryptable is shown as `不正`
/// / `不可`, never as a healthy `TOTP` badge.
pub(super) struct TotpBadge {
    pub(super) label: &'static str,
    pub(super) color: u32,
}

/// Brighter `不正`/`不可` badge colour for a selected row.
///
/// The normal rose `0xf38ba8` is only ~3.9:1 against the selected row
/// background `0x45475a`, below WCAG 1.4.3 for small text. This tint is
/// ~5.4:1 while still reading as the same warning.
const SELECTED_INVALID_TOTP_COLOR: u32 = 0xffb3c8;

impl TotpBadge {
    /// Foreground colour for this badge on the row it is drawn in.
    pub(super) fn color_for_row(&self, selected: bool) -> u32 {
        if selected && matches!(self.label, "不正" | "不可") {
            SELECTED_INVALID_TOTP_COLOR
        } else {
            self.color
        }
    }
}

pub(super) fn totp_badge(item: &crate::model::VaultItem) -> TotpBadge {
    if has_usable_totp(item) {
        TotpBadge {
            label: "TOTP",
            color: 0xa6e3a1,
        }
    } else if has_totp_field(item) {
        TotpBadge {
            label: if item.totp_secret().is_some_and(is_undecryptable_totp) {
                "不可"
            } else {
                "不正"
            },
            color: 0xf38ba8,
        }
    } else {
        TotpBadge {
            label: "",
            color: 0xa6adc8,
        }
    }
}

/// Detail line below the audit summary.
///
/// The row-selection keys only describe a real path when the report has rows.
/// On an empty report they promised keys that select nothing, so that case now
/// shows an explicit empty state instead. The non-empty branch uses
/// [`row_selection_keys_hint`], which keeps `Enter` because the audit panel
/// binds it; the vault header uses [`vault_row_keys_hint`] instead because
/// `Enter` is inert there. Both share the navigation wording.
///
/// This line is the audit panel's persistent hint, so it also carries
/// [`FOCUS_RECOVERY_HINT`] in both branches — just like `settings_hint` and
/// `generator_panel_key_hint`. Without it a user whose focus moved away from
/// the view (for example via Tab) has no on-screen way back. Kept pure so the
/// wording can be tested without rendering a GPUI window.
///
/// The rendered panel splits this line: [`audit_summary_base`] stays in the
/// scrollable body while [`audit_panel_key_hint`] is drawn in a fixed footer,
/// so a long report cannot push F1 out of view.
pub(super) fn audit_panel_detail_line(report: &Report, dirty: bool) -> String {
    let base = audit_summary_base(report, dirty);
    let hint = audit_panel_key_hint(report);
    format!("{base} / {hint}")
}

/// Coverage statistics rendered as the third header row of the audit body.
///
/// Split out of [`audit_panel_detail_line`] so the key guidance (and F1 with
/// it) can live in a fixed footer. This row carries no key hints, so keeping
/// it in the scroll container does not hide F1. Pure for testability.
pub(super) fn audit_summary_base(report: &Report, dirty: bool) -> String {
    format!(
        "{} TOTP 設定済み: {}/{} ({:.0}%)",
        unsaved_marker(dirty),
        report.with_totp,
        report.logins,
        report.totp_coverage() * 100.0
    )
}

/// Key guidance for the audit panel, rendered in a fixed footer.
///
/// This used to be the last part of [`audit_panel_detail_line`] inside
/// `.overflow_y_scroll()`, so a long report scrolled [`FOCUS_RECOVERY_HINT`]
/// off screen. It now mirrors the generator and settings panels: only the
/// footer carries F1, exactly once, independent of the scroll offset. The
/// scroll note is intentionally absent here because the audit panel owns a
/// `ScrollHandle` (Up/Down and PageUp/PageDown work), unlike those panels.
/// Pure so the "always visible" contract can be pinned without a GPUI window.
pub(super) fn audit_panel_key_hint(report: &Report) -> String {
    let row_keys = row_selection_keys_hint(report.items.len());
    if row_keys.is_empty() {
        format!(
            "監査する問題はありません / g: 一覧 / n: 生成 / c: 設定 / l: ロック / Esc: 終了 / {FOCUS_RECOVERY_HINT}"
        )
    } else {
        format!(
            "{row_keys} / 行クリックでも選択 / g: 一覧 / n: 生成 / c: 設定 / l: ロック / Esc: 終了 / {FOCUS_RECOVERY_HINT}"
        )
    }
}

/// Coverage row rendered inside the scrollable body.
///
/// Derived from [`audit_panel_detail_line`] so the two renderings cannot
/// drift: only the footer hint is removed. The third header row stays in the
/// body, keeping `AUDIT_HEADER_ROWS` and `audit_row_scroll_index` unchanged.
pub(super) fn audit_scroll_summary_line(report: &Report, dirty: bool) -> String {
    let detail = audit_panel_detail_line(report, dirty);
    let hint = audit_panel_key_hint(report);
    let suffix = format!(" / {hint}");
    detail.strip_suffix(&suffix).unwrap_or(&detail).to_string()
}

// The scrollable body keeps the stable id, min_h_0 and overflow_y_scroll that
// preserve the offset and reach every row when the window is short. Its three
// header rows (title, summary, coverage) are still the first children, so
// `AUDIT_HEADER_ROWS` and `audit_row_scroll_index` remain correct. Unlike the
// other scrollable panels, the key guidance is *not* the last body child: a
// long report used to push `FOCUS_RECOVERY_HINT` out of view, so F1 now lives
// in a fixed footer outside the scroll container.
pub(super) fn audit_panel<'a, V: 'static>(
    report: &'a Report,
    selected: Option<usize>,
    dirty: bool,
    scroll_handle: &'a ScrollHandle,
    on_focus: impl Fn(&mut V, &str, &mut Context<V>) + 'static,
    cx: &mut Context<V>,
) -> impl IntoElement + 'a {
    let focus = std::rc::Rc::new(on_focus);
    let mut body = div()
        .id("audit-panel-scroll")
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
        .min_h_0()
        .overflow_y_scroll()
        .track_scroll(scroll_handle)
        .child(
            div()
                .text_lg()
                .font_weight(FontWeight::BOLD)
                .child("Vault 健全性レポート"),
        )
        .child(
            div()
                .text_sm()
                .text_color(rgb(0xa6adc8))
                .child(report.summary()),
        )
        .child(
            div()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(audit_scroll_summary_line(report, dirty)),
        );
    for (index, item) in report.items.iter().enumerate() {
        let is_selected = selected == Some(index);
        let color = rgb(match item.worst() {
            Some(severity) => severity_color_for_row(severity, is_selected),
            // An item in the report has findings; keep the fallback readable
            // on the lighter selected background if that ever changes.
            None if is_selected => SELECTED_LOW_SEVERITY_COLOR,
            None => 0xa6adc8,
        });
        let id = item.id.clone();
        let focus = focus.clone();
        body = body.child(
            div()
                .id(SharedString::from(format!("audit-row-{id}")))
                .mt_2()
                .bg(if is_selected {
                    rgb(0x45475a)
                } else {
                    rgb(0x1e1e2e)
                })
                .on_click(cx.listener(move |this, _event, _window, cx| {
                    focus(this, &id, cx);
                }))
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(color)
                        .child(audit_row_label(&audit_row_text(item), is_selected)),
                )
                .children(item.findings.iter().map(|finding| {
                    let severity = finding.severity();
                    div()
                        .text_xs()
                        .pl_4()
                        .text_color(rgb(severity_color_for_row(severity, is_selected)))
                        .child(format!("- [{}] {}", severity.label(), finding.message()))
                })),
        );
    }
    // Fixed footer: F1 survives any scroll offset and any report length.
    div()
        .flex()
        .flex_col()
        .flex_1()
        .min_h_0()
        .child(body)
        .child(
            div()
                .px_4()
                .py_2()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(panel_key_hint_footer(&audit_panel_key_hint(report))),
        )
}

pub(super) fn setting_row<'a>(label: &'a str, enabled: bool) -> impl IntoElement + 'a {
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(div().w(px(170.0)).child(label.to_string()))
        .child(
            div()
                .text_color(if enabled {
                    rgb(0xa6e3a1)
                } else {
                    rgb(0xa6adc8)
                })
                .child(if enabled { "ON" } else { "OFF" }),
        )
}

pub(super) fn result_row<'a>(label: &'a str, value: Option<&'a str>) -> impl IntoElement + 'a {
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(170.0))
                .text_color(rgb(0x89b4fa))
                .child(label.to_string()),
        )
        .child(
            div()
                .flex_1()
                .font_weight(FontWeight::BOLD)
                .child(value.unwrap_or("(未生成)").to_string()),
        )
}

/// Human-readable label for the passphrase separator.
///
/// `{:?}` on the `String` adds quotes (`"-"`), which reads like a literal
/// token instead of the character actually placed between words. A visually
/// empty separator is named explicitly so a concatenated passphrase is not
/// mistaken for a missing value. The blank check goes through the shared
/// `ui::app::is_visually_empty` rule (whitespace and Unicode `Cc`/`Cf`/
/// marks), so a zero-width space or bidi override cannot leave a blank after
/// the "区切り:" label (R2-UI-150).
pub(super) fn separator_label(separator: &str) -> &str {
    if is_visually_empty(separator) {
        "(なし)"
    } else {
        separator
    }
}

pub(super) fn generator_panel<'a>(
    settings: &'a Settings,
    state: &'a GeneratorState,
    dirty: bool,
) -> impl IntoElement + 'a {
    let password = &settings.password_generator;
    let passphrase = &settings.passphrase_generator;
    let pw_bits = password_entropy(password);
    let pp_bits = passphrase_entropy(passphrase);
    let (password_label, passphrase_label) = generator_length_labels(
        password.length,
        passphrase.words,
        pw_bits,
        pp_bits,
        &passphrase.separator,
    );
    // The body scrolls, but F1 must not: a hint hidden at the bottom of the
    // scroll is useless precisely when focus has been lost. Keep the body in
    // its own scroll container and draw the key guidance in a fixed footer.
    div()
        .flex()
        .flex_col()
        .flex_1()
        .min_h_0()
        .child(
            div()
                .id("generator-panel-scroll")
                .flex()
                .flex_col()
                .gap_2()
                .p_4()
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .child(
                    div()
                        .text_lg()
                        .font_weight(FontWeight::BOLD)
                        .child("パスワード生成"),
                )
                .child(setting_row("1  小文字 a-z", password.lowercase))
                .child(setting_row("2  大文字 A-Z", password.uppercase))
                .child(setting_row("3  数字 0-9", password.digits))
                .child(setting_row("4  記号 !@#$%^&*", password.symbols))
                .child(setting_row("5  曖昧文字を除外", password.avoid_ambiguous))
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(0xa6adc8))
                        .child(password_label),
                )
                .child(result_row(
                    "p  生成",
                    state.last_password.as_ref().map(|value| value.as_str()),
                ))
                .child(
                    div()
                        .mt_4()
                        .text_lg()
                        .font_weight(FontWeight::BOLD)
                        .child("パスフレーズ生成"),
                )
                .child(setting_row("6  先頭を大文字に", passphrase.capitalize))
                .child(setting_row("7  数字を追加", passphrase.include_number))
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(0xa6adc8))
                        .child(passphrase_label),
                )
                .child(result_row(
                    "h  生成",
                    state.last_passphrase.as_ref().map(|value| value.as_str()),
                ))
                .child(
                    div()
                        .text_sm()
                        .text_color(if dirty { rgb(0xf9e2af) } else { rgb(0xa6adc8) })
                        .child(format!(
                            "{} {}",
                            unsaved_marker(dirty),
                            if dirty {
                                "生成設定は未保存です（w: 保存 / d: 破棄）"
                            } else {
                                "未保存の設定変更はありません"
                            }
                        )),
                ),
        )
        .child(
            div()
                .px_4()
                .py_2()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(panel_key_hint_footer(&generator_panel_key_hint(
                    settings.clipboard_restore_seconds,
                ))),
        )
}

pub(super) fn field_row<'a>(
    label: &'a str,
    value: &'a str,
    editing: bool,
) -> impl IntoElement + 'a {
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(170.0))
                .text_color(if editing {
                    rgb(0x89b4fa)
                } else {
                    rgb(0xa6adc8)
                })
                .child(label.to_string()),
        )
        .child(
            div()
                .flex_1()
                .font_weight(if editing {
                    FontWeight::BOLD
                } else {
                    FontWeight::NORMAL
                })
                .text_color(if editing {
                    rgb(0xf9e2af)
                } else {
                    rgb(0xcdd6f4)
                })
                .child(format!("{value}{}", if editing { " _" } else { "" })),
        )
}

pub(super) fn settings_panel<'a>(
    settings: &'a Settings,
    editing: Option<SettingsField>,
    dirty: bool,
) -> impl IntoElement + 'a {
    let server_url = settings.server_url.as_str();
    let email = settings.email.as_str();
    let path = Settings::default_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(設定ディレクトリを特定できません)".to_string());
    // As in the generator panel, F1 must not be hidden at the bottom of the
    // scrollable body. The settings rows scroll; the key guidance is a fixed
    // footer so the recovery key is always on screen.
    div()
        .flex()
        .flex_col()
        .flex_1()
        .min_h_0()
        .child(
            div()
                .id("settings-panel-scroll")
                .flex()
                .flex_col()
                .gap_2()
                .p_4()
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .child(div().text_lg().font_weight(FontWeight::BOLD).child("設定"))
                .child(
                    div()
                        .text_sm()
                        .text_color(if dirty { rgb(0xf9e2af) } else { rgb(0xa6adc8) })
                        .child(format!(
                            "{} {}",
                            unsaved_marker(dirty),
                            if dirty {
                                "未保存の変更があります（w: 保存 / d: 破棄）"
                            } else {
                                "未保存の変更はありません"
                            }
                        )),
                )
                .child(field_row(
                    "1  サーバー URL",
                    server_url,
                    editing == Some(SettingsField::ServerUrl),
                ))
                .child(field_row(
                    "2  メール",
                    email,
                    editing == Some(SettingsField::Email),
                ))
                .child(div().text_sm().text_color(rgb(0xa6adc8)).child(
                    settings_generator_summary_line(
                        settings.password_generator.length,
                        settings.passphrase_generator.words,
                        editing.is_some(),
                    ),
                ))
                .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
                    "監査閾値: 弱パスワード < {} bit / 更新が古い: {} 日以上",
                    settings.thresholds.weak_bits, settings.thresholds.stale_days
                )))
                .child(div().text_sm().text_color(rgb(0xa6adc8)).child(
                    settings_timeout_summary_line(
                        settings.idle_lock_seconds,
                        settings.login_timeout_seconds,
                        settings.clipboard_restore_seconds,
                    ),
                ))
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(0xa6adc8))
                        .child(format!("保存先: {path}")),
                ),
        )
        .child(
            div()
                .px_4()
                .py_2()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                // The editing state and arrow-key ownership are announced
                // once by the status bar (`text_edit_start_status`). The
                // helper appends only the scroll note to the settings-specific
                // hint, so no second "入力中:" line is drawn here.
                .child(panel_key_hint_footer(&settings_panel_key_hint(
                    editing.is_some(),
                ))),
        )
}

/// Label shown on a header tab, with a non-colour marker when it is active.
///
/// Colour alone cannot convey the active tab. A leading triangle (together
/// with the bold weight applied in `panel_button`) keeps the state readable
/// without relying on colour perception.
pub(super) fn panel_button_label(label: &str, active: bool) -> String {
    if active {
        format!("▶ {label}")
    } else {
        label.to_string()
    }
}

pub(super) fn panel_button<V: 'static>(
    label: &str,
    panel: Panel,
    current: Panel,
    on_select: impl Fn(&mut V, &mut Context<V>) + 'static,
    cx: &mut Context<V>,
) -> AnyElement {
    let active = panel == current;
    let select = std::rc::Rc::new(on_select);
    // Derive the identity from the original label so switching tabs does not
    // recreate the element: only the drawn text gets the active marker.
    let id = SharedString::from(format!("panel-button-{label}"));
    div()
        .id(id)
        .px_2()
        .py_1()
        .rounded_md()
        .bg(if active { rgb(0x45475a) } else { rgb(0x313244) })
        .text_color(if active { rgb(0xcdd6f4) } else { rgb(0xa6adc8) })
        .font_weight(if active {
            FontWeight::BOLD
        } else {
            FontWeight::NORMAL
        })
        .text_xs()
        .on_click(cx.listener(move |this, _event, _window, cx| {
            select(this, cx);
        }))
        .child(panel_button_label(label, active))
        .into_any_element()
}

/// Text drawn in the value column of [`auth_row`].
///
/// The trailing `_` is the non-colour marker that a field is being edited. It
/// must survive an empty value too: otherwise focusing an unset credential
/// gives no visual feedback that the field is editable.
fn auth_row_shown_text(value: &str, editing: bool, secret: bool) -> String {
    if is_visually_empty(value) {
        format!("(未入力){}", if editing { " _" } else { "" })
    } else if secret {
        // Never render secret values in plain text, not even while editing.
        // Count only rendering characters so a zero-width `Cf`, a control
        // character or a bare combining mark neither adds a phantom dot nor
        // makes a value that looks empty show a mask. Shares the rule with the
        // placeholder above and the rest of the UI.
        let masked = "•".repeat(visible_char_count(value));
        format!("{masked}{}", if editing { " _" } else { "" })
    } else {
        format!("{value}{}", if editing { " _" } else { "" })
    }
}

pub(super) fn auth_row<'a>(
    label: &'a str,
    value: &'a str,
    editing: bool,
    secret: bool,
) -> impl IntoElement + 'a {
    let shown = auth_row_shown_text(value, editing, secret);
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(150.0))
                .text_color(if editing {
                    rgb(0x89b4fa)
                } else {
                    rgb(0xa6adc8)
                })
                .child(label.to_string()),
        )
        .child(
            div()
                .flex_1()
                .text_color(if editing {
                    rgb(0xf9e2af)
                } else {
                    rgb(0xcdd6f4)
                })
                .child(shown),
        )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn channel_luminance(rgb: u32, shift: u32) -> f64 {
        let value = ((rgb >> shift) & 0xff) as f64 / 255.0;
        if value <= 0.03928 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    }

    fn relative_luminance(rgb: u32) -> f64 {
        0.2126 * channel_luminance(rgb, 16)
            + 0.7152 * channel_luminance(rgb, 8)
            + 0.0722 * channel_luminance(rgb, 0)
    }

    fn contrast_ratio(foreground: u32, background: u32) -> f64 {
        let fg = relative_luminance(foreground);
        let bg = relative_luminance(background);
        let (light, dark) = if fg > bg { (fg, bg) } else { (bg, fg) };
        (light + 0.05) / (dark + 0.05)
    }

    #[::core::prelude::v1::test]
    fn generator_length_labels_state_both_values_change_together() {
        let (password, passphrase) = generator_length_labels(20, 4, 100.0, 40.0, "-");
        assert!(
            password.contains("パスフレーズ語数も同時に変更"),
            "{password}"
        );
        assert!(
            passphrase.contains("パスワード長も同時に変更"),
            "{passphrase}"
        );
        assert!(password.contains("長さ: 20"), "{password}");
        assert!(passphrase.contains("単語数: 4"), "{passphrase}");
    }

    #[::core::prelude::v1::test]
    fn settings_timeout_summary_uses_the_shared_idle_lock_wording() {
        // A whole minute keeps the compact spelling, with no doubled "分".
        assert_eq!(
            settings_timeout_summary_line(300, 45, 60),
            "自動ロック: 5分（i/u） / ログイン制限: 45 秒（3/4） / 復元: 60 秒（5/6）"
        );
        // A fractional minute keeps its leftover seconds instead of being
        // truncated by integer division, matching `idle_lock_minutes_text`.
        let line = settings_timeout_summary_line(90, 45, 60);
        assert_eq!(
            line,
            format!(
                "自動ロック: {}（i/u） / ログイン制限: 45 秒（3/4） / 復元: 60 秒（5/6）",
                crate::ui::app::idle_lock_minutes_text(90)
            )
        );
        assert!(line.contains("1分30秒"), "{line}");
        assert!(!line.contains("1 分"), "{line}");
        assert_eq!(
            settings_timeout_summary_line(0, 1, 2),
            "自動ロック: 0分（i/u） / ログイン制限: 1 秒（3/4） / 復元: 2 秒（5/6）"
        );
    }

    #[::core::prelude::v1::test]
    fn settings_generator_summary_line_points_to_the_direct_generator_jump() {
        let line = settings_generator_summary_line(24, 6, false);
        assert_eq!(
            line,
            "生成設定: パスワード 24 文字 / パスフレーズ 6 語（n: 生成へ）"
        );
        // In `Panel::Settings`, `n` jumps straight to `Panel::Generator`
        // (`ui::keys::classify_key`); the old "go to the list first" wording is
        // stale and must not come back.
        assert!(line.contains("n: 生成へ"), "{line}");
        assert!(!line.contains("一覧"), "{line}");
    }

    #[::core::prelude::v1::test]
    fn settings_generator_summary_line_hides_jump_hint_while_editing() {
        let line = settings_generator_summary_line(24, 6, true);
        assert_eq!(line, "生成設定: パスワード 24 文字 / パスフレーズ 6 語");
        // While a settings field is focused, `n` is inserted as text rather
        // than switching to `Panel::Generator`, so advertising the jump here
        // would promise a command that cannot fire.
        assert!(!line.contains("n: 生成へ"), "{line}");
        assert!(!line.contains("n:"), "{line}");
        assert!(line.starts_with("生成設定: パスワード 24 文字"), "{line}");
    }

    #[::core::prelude::v1::test]
    fn panels_without_a_scroll_handle_advertise_mouse_wheel_only() {
        let generator = generator_panel_key_hint(30);
        assert!(
            generator.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT),
            "{generator}"
        );
        assert!(generator.contains("30秒で復元"), "{generator}");
        assert!(generator.contains("p/h: 生成"), "{generator}");

        for editing in [false, true] {
            let settings = settings_panel_key_hint(editing);
            assert!(
                settings.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT),
                "{settings}"
            );
            assert!(settings.contains(settings_hint(editing)), "{settings}");
            assert!(
                !settings.starts_with("入力中:"),
                "the inline hint must not repeat the status-bar prefix: {settings}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn generator_key_hint_names_the_two_copy_targets() {
        // The hint must mirror the key bindings in `ui::keys`: y copies the
        // generated password, Y copies the generated passphrase.
        let hint = generator_panel_key_hint(30);
        assert!(hint.contains("y: パスワードをコピー"), "{hint}");
        assert!(hint.contains("Y: パスフレーズをコピー"), "{hint}");
        assert!(!hint.contains("y/Y: コピー"), "{hint}");
        assert!(hint.contains("30秒で復元"), "{hint}");
    }

    #[::core::prelude::v1::test]
    fn generator_key_hint_advertises_the_direct_settings_jump() {
        // `ui::keys::classify_key` binds `c` to `Panel::Settings` in the
        // generator panel, so the on-screen hint must mirror it.
        let hint = generator_panel_key_hint(30);
        assert!(hint.contains("c: 設定"), "{hint}");
        // `n` keeps its generator-local meaning and must stay discoverable.
        assert!(hint.contains("n: 一覧に戻る"), "{hint}");
    }

    #[::core::prelude::v1::test]
    fn generator_key_hint_advertises_the_focus_recovery_key_once() {
        let hint = generator_panel_key_hint(30);
        assert!(
            hint.contains(FOCUS_RECOVERY_HINT),
            "the generator hint must advertise F1: {hint}"
        );
        assert_eq!(
            hint.matches(FOCUS_RECOVERY_HINT).count(),
            1,
            "the hint must not repeat the recovery key: {hint}"
        );
        assert!(hint.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT), "{hint}");
        assert!(hint.contains("30秒で復元"), "{hint}");
    }

    #[::core::prelude::v1::test]
    fn panel_key_hint_footer_keeps_focus_recovery_visible_without_scrolling() {
        // Settings and generator scroll their body; the key guidance now lives
        // in a fixed footer outside `.overflow_y_scroll()`. The footer must
        // carry F1 exactly once for every hint variant, otherwise a lost focus
        // would again be discoverable only at the end of the scroll.
        for hint in [
            generator_panel_key_hint(30),
            settings_panel_key_hint(false),
            settings_panel_key_hint(true),
        ] {
            let footer = panel_key_hint_footer(&hint);
            assert!(footer.starts_with("操作: "), "{footer}");
            assert!(
                footer.contains(FOCUS_RECOVERY_HINT),
                "the fixed footer must advertise F1: {footer}"
            );
            assert_eq!(
                footer.matches(FOCUS_RECOVERY_HINT).count(),
                1,
                "F1 must appear once in the fixed footer: {footer}"
            );
            // The scroll note still belongs to the body; the footer only
            // promises that the keys themselves are always reachable.
            assert!(footer.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT), "{footer}");
            assert!(!footer.contains("入力中:"), "{footer}");
        }
    }

    #[::core::prelude::v1::test]
    fn settings_key_hint_advertises_the_focus_recovery_key_once() {
        // Mirrors the generator hint contract: the settings footer must be the
        // single, always-visible home of F1 in the editing and idle variants.
        for editing in [false, true] {
            let hint = settings_panel_key_hint(editing);
            assert_eq!(
                hint.matches(FOCUS_RECOVERY_HINT).count(),
                1,
                "the settings hint must advertise F1 exactly once: {hint}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn severity_colours_are_distinct() {
        assert_eq!(severity_color(Severity::High), 0xf38ba8);
        assert_eq!(severity_color(Severity::Medium), 0xf9e2af);
        assert_eq!(severity_color(Severity::Low), 0xa6adc8);
        assert_ne!(
            severity_color(Severity::High),
            severity_color(Severity::Medium)
        );
    }

    #[::core::prelude::v1::test]
    fn selected_audit_row_severity_colours_meet_text_contrast() {
        const SELECTED_BG: u32 = 0x45475a;
        const UNSELECTED_BG: u32 = 0x1e1e2e;

        for severity in [Severity::High, Severity::Medium, Severity::Low] {
            // Unselected rows keep the established palette.
            assert_eq!(
                severity_color_for_row(severity, false),
                severity_color(severity)
            );

            // The original high/low tints are the regression: below 4.5:1 on
            // the lighter selected background. Medium already clears it.
            if severity != Severity::Medium {
                assert!(
                    contrast_ratio(severity_color(severity), SELECTED_BG) < 4.5,
                    "the unselected {severity:?} tint should be the low-contrast case"
                );
            }

            let selected = severity_color_for_row(severity, true);
            assert!(
                contrast_ratio(selected, SELECTED_BG) >= 4.5,
                "{severity:?} must reach WCAG 1.4.3 text contrast on the selected row"
            );
            // Moving the highlight must not make the bright tint unreadable.
            assert!(
                contrast_ratio(selected, UNSELECTED_BG) >= 4.5,
                "{severity:?} selected tint must stay readable after the highlight moves"
            );
        }

        // Pin the exact tints so a future palette tweak cannot silently undo
        // the fix while still passing the ratio assertions above.
        assert_eq!(severity_color_for_row(Severity::High, true), 0xffb3c8);
        assert_eq!(severity_color_for_row(Severity::Medium, true), 0xf9e2af);
        assert_eq!(severity_color_for_row(Severity::Low, true), 0xcdd6f4);
    }

    fn login_with_totp(secret: &str) -> crate::model::VaultItem {
        use crate::model::ItemData;
        use zeroize::Zeroizing;

        crate::model::VaultItem::new(
            "id",
            "name",
            ItemData::Login {
                username: String::new(),
                password: Zeroizing::new(String::new()),
                totp: Zeroizing::new(secret.to_string()),
                uris: Vec::new(),
            },
        )
    }

    #[::core::prelude::v1::test]
    fn totp_badge_distinguishes_valid_invalid_undecryptable_and_absent_secrets() {
        use crate::model::ItemData;

        let valid = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_badge(&login_with_totp(valid)).label, "TOTP");
        assert_eq!(totp_badge(&login_with_totp("not base32!")).label, "不正");
        assert_eq!(
            totp_badge(&login_with_totp(crate::vault_sync::UNDECRYPTABLE_TOTP)).label,
            "不可"
        );
        assert_ne!(
            totp_badge(&login_with_totp(valid)).color,
            totp_badge(&login_with_totp("not base32!")).color
        );

        let note = crate::model::VaultItem::new(
            "note",
            "note",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        );
        assert_eq!(totp_badge(&note).label, "");
        assert_eq!(totp_badge(&login_with_totp("")).label, "");
    }

    #[::core::prelude::v1::test]
    fn selected_row_invalid_totp_badge_meets_text_contrast() {
        const SELECTED_BG: u32 = 0x45475a;
        let invalid = totp_badge(&login_with_totp("not base32!"));
        let undecryptable = totp_badge(&login_with_totp(crate::vault_sync::UNDECRYPTABLE_TOTP));

        // The original colour is the bug: below 4.5:1 on the selected row.
        assert!(contrast_ratio(invalid.color, SELECTED_BG) < 4.5);
        assert!(contrast_ratio(undecryptable.color, SELECTED_BG) < 4.5);

        for badge in [&invalid, &undecryptable] {
            assert_eq!(badge.color_for_row(false), badge.color);
            assert!(
                contrast_ratio(badge.color_for_row(true), SELECTED_BG) >= 4.5,
                "badge {:?} must stay readable on the selected row",
                badge.label
            );
        }

        // Healthy and absent badges keep their existing colours on both rows.
        let valid = totp_badge(&login_with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert_eq!(valid.color_for_row(true), valid.color);
        let note = crate::model::VaultItem::new(
            "note",
            "note",
            crate::model::ItemData::SecureNote {
                text: String::new().into(),
            },
        );
        let absent = totp_badge(&note);
        assert_eq!(absent.color_for_row(true), absent.color);
    }

    #[::core::prelude::v1::test]
    fn separator_label_is_readable_without_debug_quotes() {
        assert_eq!(separator_label("-"), "-");
        assert_eq!(separator_label("."), ".");
        assert_eq!(separator_label("_"), "_");
        assert_eq!(separator_label(""), "(なし)");
        assert_ne!(separator_label("-"), "\"-\"");
    }

    #[::core::prelude::v1::test]
    fn separator_label_hides_cf_and_whitespace_only_separators() {
        // An invisible separator renders as a blank after "区切り:"; use the
        // same `is_visually_empty` rule as every other empty-value label.
        // The literals cover whitespace, ZERO WIDTH SPACE, ZERO WIDTH
        // NO-BREAK SPACE, RIGHT-TO-LEFT OVERRIDE, and a mix of them (all Cf).
        for separator in [
            "",
            " ",
            " \t\n ",
            "\u{200b}",
            "\u{feff}",
            "\u{202e}",
            "\u{200b}\u{feff}\u{202e}",
        ] {
            assert_eq!(separator_label(separator), "(なし)", "{separator:?}");
        }
        // Visible separators keep their exact glyph, including surrounding
        // whitespace and a leading invisible character.
        for separator in ["-", ".", "_", " - ", "\u{200b}-"] {
            assert_eq!(separator_label(separator), separator, "{separator:?}");
        }
    }

    #[::core::prelude::v1::test]
    fn active_header_tab_has_a_non_colour_marker() {
        assert_eq!(panel_button_label("[一覧]", true), "▶ [一覧]");
        assert_eq!(panel_button_label("[一覧]", false), "[一覧]");
        assert_ne!(
            panel_button_label("[一覧]", true),
            panel_button_label("[一覧]", false)
        );
        // Every tab label gets the same cue, including the audit placeholder.
        assert!(panel_button_label("[監査 (未生成)]", true).starts_with("▶ "));
    }

    #[::core::prelude::v1::test]
    fn auth_row_shown_text_keeps_the_editing_marker_on_an_empty_value() {
        // The regression: an empty credential field lost the `_` marker while
        // focused, so editing had no non-colour indication at all.
        assert_eq!(auth_row_shown_text("", true, false), "(未入力) _");
        assert_eq!(auth_row_shown_text("", true, true), "(未入力) _");
        // Idle empty fields keep the original wording.
        assert_eq!(auth_row_shown_text("", false, false), "(未入力)");
        assert_eq!(auth_row_shown_text("", false, true), "(未入力)");
        // Non-empty branches are unchanged by the fix.
        assert_eq!(auth_row_shown_text("user", true, false), "user _");
        assert_eq!(auth_row_shown_text("user", false, false), "user");
        assert_eq!(auth_row_shown_text("pw", true, true), "•• _");
        assert_eq!(auth_row_shown_text("pw", false, true), "••");
    }

    #[::core::prelude::v1::test]
    fn auth_row_shown_text_uses_the_shared_visible_content_rules() {
        // A value that renders nothing must read as "(未入力)" even though its
        // raw string is not `is_empty()`. This covers whitespace, Unicode Cc,
        // Cf (zero-width space / bidi override) and a bare combining mark.
        for invisible in ["\u{200b}", " \t\n", "\u{200e}", "\u{0301}"] {
            assert!(is_visually_empty(invisible), "{invisible:?}");
            assert_eq!(
                auth_row_shown_text(invisible, true, false),
                "(未入力) _",
                "{invisible:?}/plain/editing"
            );
            assert_eq!(
                auth_row_shown_text(invisible, false, true),
                "(未入力)",
                "{invisible:?}/secret/idle"
            );
        }

        // The mask counts only rendering characters: an embedded zero-width
        // format character and a combining mark must not add phantom dots.
        let secret = "a\u{200b}b\u{0301}";
        assert_eq!(crate::ui::app::visible_char_count(secret), 2);
        assert_eq!(auth_row_shown_text(secret, true, true), "•• _");
        assert_eq!(auth_row_shown_text(secret, false, true), "••");
        // A non-secret field keeps its literal value when it has visible content.
        assert_eq!(auth_row_shown_text(secret, false, false), secret);
    }

    #[::core::prelude::v1::test]
    fn audit_panel_detail_line_hides_row_keys_on_an_empty_report() {
        let empty = audit_panel_detail_line(&Report::default(), false);
        assert!(empty.contains("監査する問題はありません"), "{empty}");
        assert!(!empty.contains("↑↓"), "{empty}");
        assert!(!empty.contains("Enter: 対象を選択"), "{empty}");
        assert!(!empty.contains("行クリックでも選択"), "{empty}");
        assert!(empty.contains("TOTP 設定済み"), "{empty}");
        assert!(
            empty.contains("g: 一覧 / n: 生成 / c: 設定 / l: ロック / Esc: 終了"),
            "{empty}"
        );

        let with_rows = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        let line = audit_panel_detail_line(&with_rows, true);
        assert!(line.contains("↑↓: 行を選択"), "{line}");
        assert!(line.contains("Enter: 対象を選択"), "{line}");
        assert!(line.contains("行クリックでも選択"), "{line}");
        assert!(!line.contains("監査する問題はありません"), "{line}");
        assert!(line.contains(unsaved_marker(true)), "{line}");
        assert!(line.contains("TOTP 設定済み: 1/1 (100%)"), "{line}");
    }

    #[::core::prelude::v1::test]
    fn audit_detail_line_advertises_page_and_edge_keys_when_rows_exist() {
        for key in ["PageUp", "PageDown", "Home", "End"] {
            assert!(LIST_PAGE_AND_EDGE_HINT.contains(key), "missing {key}");
        }
        let report = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        let line = audit_panel_detail_line(&report, false);
        assert!(line.contains(LIST_PAGE_AND_EDGE_HINT), "{line}");
        assert!(line.contains("↑↓: 行を選択"), "{line}");

        // With no rows there is nothing to page through or jump to.
        let empty = audit_panel_detail_line(&Report::default(), false);
        assert!(!empty.contains(LIST_PAGE_AND_EDGE_HINT), "{empty}");
    }

    #[::core::prelude::v1::test]
    fn audit_detail_line_advertises_focus_recovery_once_in_both_states() {
        let with_rows = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        for (label, line) in [
            ("empty", audit_panel_detail_line(&Report::default(), false)),
            ("with rows", audit_panel_detail_line(&with_rows, true)),
        ] {
            assert!(
                line.contains(FOCUS_RECOVERY_HINT),
                "the persistent audit hint must advertise F1 ({label}): {line}"
            );
            assert_eq!(
                line.matches(FOCUS_RECOVERY_HINT).count(),
                1,
                "the recovery key must appear exactly once ({label}): {line}"
            );
            assert!(
                line.contains("g: 一覧 / n: 生成 / c: 設定 / l: ロック / Esc: 終了"),
                "{line}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn audit_fixed_footer_keeps_focus_recovery_visible_without_scrolling() {
        // The audit key hint used to be the last child of `.overflow_y_scroll()`,
        // so a long report pushed F1 out of view. The body row and the fixed
        // footer must split cleanly: F1 lives only in the footer, once, for
        // both empty and populated reports.
        let with_rows = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        for (label, report) in [("empty", Report::default()), ("with rows", with_rows)] {
            let body = audit_scroll_summary_line(&report, true);
            let hint = audit_panel_key_hint(&report);
            let footer = panel_key_hint_footer(&hint);

            assert_eq!(
                body,
                audit_summary_base(&report, true),
                "the scroll row must keep only the coverage stats ({label})"
            );
            assert!(footer.starts_with("操作: "), "{label}: {footer}");
            assert_eq!(
                footer.matches(FOCUS_RECOVERY_HINT).count(),
                1,
                "the fixed footer must be the single home of F1 ({label}): {footer}"
            );
            assert!(
                !body.contains(FOCUS_RECOVERY_HINT),
                "the scroll body must not carry F1 ({label}): {body}"
            );
            for key_hint in ["↑↓", "g: 一覧", "Esc: 終了"] {
                assert!(
                    !body.contains(key_hint),
                    "key guidance must stay in the footer, not the scroll body ({label}): {body}"
                );
            }
            // The audit panel owns a ScrollHandle, so it must not promise the
            // mouse-only scrolling note used by the generator/settings panels.
            assert!(
                !footer.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT),
                "{label}: {footer}"
            );
            // The pure detail line keeps its prior wording for status/tests.
            assert_eq!(
                audit_panel_detail_line(&report, true),
                format!("{body} / {hint}"),
                "{label}"
            );
            assert!(
                body.contains(unsaved_marker(true)),
                "the coverage row still shows the dirty marker ({label}): {body}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn audit_panel_key_hint_tracks_the_report_row_state() {
        let empty_hint = audit_panel_key_hint(&Report::default());
        assert!(
            empty_hint.contains("監査する問題はありません"),
            "{empty_hint}"
        );
        assert!(!empty_hint.contains("↑↓"), "{empty_hint}");
        assert!(!empty_hint.contains("Enter: 対象を選択"), "{empty_hint}");
        assert!(!empty_hint.contains("行クリックでも選択"), "{empty_hint}");
        assert!(
            !empty_hint.contains(LIST_PAGE_AND_EDGE_HINT),
            "{empty_hint}"
        );

        let with_rows = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        let hint = audit_panel_key_hint(&with_rows);
        assert!(hint.contains("↑↓: 行を選択"), "{hint}");
        assert!(hint.contains("Enter: 対象を選択"), "{hint}");
        assert!(hint.contains(LIST_PAGE_AND_EDGE_HINT), "{hint}");
        assert!(hint.contains("行クリックでも選択"), "{hint}");
        assert!(!hint.contains("監査する問題はありません"), "{hint}");
        assert!(
            hint.contains("g: 一覧 / n: 生成 / c: 設定 / l: ロック / Esc: 終了"),
            "{hint}"
        );
    }

    #[::core::prelude::v1::test]
    fn row_selection_keys_hint_hides_all_row_keys_when_the_list_is_empty() {
        let empty = row_selection_keys_hint(0);
        assert!(empty.is_empty(), "{empty}");
        assert!(!empty.contains("↑↓"), "{empty}");
        assert!(!empty.contains(LIST_PAGE_AND_EDGE_HINT), "{empty}");
        assert!(!empty.contains("Enter"), "{empty}");
        for key in ["PageUp", "PageDown", "Home", "End"] {
            assert!(!empty.contains(key), "unexpected {key} in {empty}");
        }
    }

    #[::core::prelude::v1::test]
    fn row_selection_keys_hint_advertises_row_keys_when_rows_exist() {
        let hint = row_selection_keys_hint(2);
        assert!(hint.contains("↑↓: 行を選択"), "{hint}");
        assert!(hint.contains(LIST_PAGE_AND_EDGE_HINT), "{hint}");
        assert!(hint.contains("Enter: 対象を選択"), "{hint}");
        for key in ["PageUp", "PageDown", "Home", "End"] {
            assert!(hint.contains(key), "missing {key} in {hint}");
        }
        // The bundled hint must stay a strict superset of the shared constant.
        let expected_prefix = format!("↑↓: 行を選択 / {LIST_PAGE_AND_EDGE_HINT}");
        assert!(hint.starts_with(expected_prefix.as_str()), "{hint}");
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_omits_the_audit_only_enter_binding() {
        // An empty vault still shows the row-independent commands, but no row
        // keys, no selection-dependent commands and no audit-only `Enter`.
        let empty = vault_row_keys_hint(0, false, false);
        assert_eq!(empty, VAULT_SELECTION_FREE_KEYS_HINT, "{empty}");
        assert!(!empty.contains("Enter"), "{empty}");
        assert!(!empty.contains("↑↓"), "{empty}");
        assert!(!empty.contains(LIST_PAGE_AND_EDGE_HINT), "{empty}");
        for token in [
            "f: お気に入り",
            "y: TOTP をコピー",
            "p: パスワードをコピー",
            "u: ユーザー名をコピー",
        ] {
            assert!(!empty.contains(token), "unexpected {token} in {empty}");
        }
        for key in ["PageUp", "PageDown", "Home", "End"] {
            assert!(!empty.contains(key), "unexpected {key} in {empty}");
        }

        let hint = vault_row_keys_hint(2, false, false);
        assert!(hint.contains("↑↓: 行を選択"), "{hint}");
        assert!(hint.contains(LIST_PAGE_AND_EDGE_HINT), "{hint}");
        assert!(!hint.contains("Enter"), "{hint}");
        assert!(!hint.contains("対象を選択"), "{hint}");
        for key in ["PageUp", "PageDown", "Home", "End"] {
            assert!(hint.contains(key), "missing {key} in {hint}");
        }

        // The audit variant keeps the legacy navigation wording and its own
        // `Enter` segment; it must not inherit vault-only command keys such as
        // `t`/`y`/`p`, which are inert on that panel.
        let audit = row_selection_keys_hint(2);
        assert!(audit.contains("Enter: 対象を選択"), "{audit}");
        assert!(!audit.contains(VAULT_MAIN_KEYS_HINT), "{audit}");
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_hides_all_row_keys_while_searching() {
        for rows in [0, 2] {
            let searching = vault_row_keys_hint(rows, true, false);
            assert!(searching.is_empty(), "rows={rows}: {searching}");
            assert!(!searching.contains("↑↓"), "{searching}");
            assert!(!searching.contains(LIST_PAGE_AND_EDGE_HINT), "{searching}");
            for key in ["PageUp", "PageDown", "Home", "End"] {
                assert!(!searching.contains(key), "rows={rows}: {searching}");
            }
        }

        // Outside the search field the very same rows still advertise the
        // navigation keys, including the shared page/edge wording.
        let idle = vault_row_keys_hint(2, false, false);
        assert_eq!(
            idle,
            format!("{} / {VAULT_MAIN_KEYS_HINT}", row_navigation_keys_hint(2))
        );
        assert!(idle.contains("↑↓: 行を選択"), "{idle}");
        assert!(idle.contains(LIST_PAGE_AND_EDGE_HINT), "{idle}");
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_advertises_the_main_command_keys() {
        let hint = vault_row_keys_hint(2, false, false);
        for token in [
            "/: 検索",
            "t: フィルタ",
            "s: 並び替え",
            "f: お気に入り",
            "y: TOTP をコピー",
            "p: パスワードをコピー",
            "u: ユーザー名をコピー",
            "g: 監査",
            "n: 生成",
            "c: 設定",
            "l: ロック",
            "Esc: 終了",
        ] {
            assert!(hint.contains(token), "missing {token} in {hint}");
        }
        assert!(!hint.contains("Enter"), "{hint}");

        // Search mode still hides every key hint because command letters
        // become search text. With an empty list the row keys and the
        // selection-dependent commands are dropped; the rest stay visible.
        assert_eq!(vault_row_keys_hint(2, true, false), "");
        assert_eq!(
            vault_row_keys_hint(0, false, false),
            VAULT_SELECTION_FREE_KEYS_HINT
        );
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_keeps_selection_free_commands_when_the_vault_is_empty() {
        let empty = vault_row_keys_hint(0, false, false);
        assert_eq!(empty, VAULT_SELECTION_FREE_KEYS_HINT, "{empty}");

        // Row-independent commands stay discoverable with no row to select.
        for token in [
            "/: 検索",
            "t: フィルタ",
            "s: 並び替え",
            "g: 監査",
            "n: 生成",
            "c: 設定",
            "l: ロック",
            "Esc: 終了",
        ] {
            assert!(empty.contains(token), "missing {token} in {empty}");
        }

        // Selection-dependent commands need a highlighted row and must go.
        for token in [
            "f: お気に入り",
            "y: TOTP をコピー",
            "p: パスワードをコピー",
            "u: ユーザー名をコピー",
        ] {
            assert!(!empty.contains(token), "unexpected {token} in {empty}");
        }

        // Nothing may promise a selectable row or the audit-only `Enter`.
        assert!(!empty.contains("↑↓"), "{empty}");
        assert!(!empty.contains(LIST_PAGE_AND_EDGE_HINT), "{empty}");
        assert!(!empty.contains("行を選択"), "{empty}");
        for key in ["PageUp", "PageDown", "Home", "End", "Enter"] {
            assert!(!empty.contains(key), "unexpected {key} in {empty}");
        }
        assert!(!empty.contains(" / / "), "{empty}");

        // Search mode remains fully silent: the letters become search text.
        assert_eq!(vault_row_keys_hint(0, true, false), "");

        // The non-empty branch keeps its established navigation prefix.
        let with_rows = vault_row_keys_hint(2, false, false);
        assert_eq!(
            with_rows,
            format!("{} / {VAULT_MAIN_KEYS_HINT}", row_navigation_keys_hint(2))
        );
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_drops_selection_dependent_keys_only_when_empty() {
        let selection_keys = [
            "f: お気に入り",
            "y: TOTP をコピー",
            "p: パスワードをコピー",
            "u: ユーザー名をコピー",
        ];

        let empty = vault_row_keys_hint(0, false, false);
        assert_eq!(empty, VAULT_SELECTION_FREE_KEYS_HINT, "{empty}");
        for token in selection_keys {
            assert!(!empty.contains(token), "unexpected {token} in {empty}");
        }

        let with_rows = vault_row_keys_hint(1, false, false);
        assert_eq!(
            with_rows,
            format!("{} / {VAULT_MAIN_KEYS_HINT}", row_navigation_keys_hint(1)),
            "{with_rows}"
        );
        for token in selection_keys {
            assert!(with_rows.contains(token), "missing {token} in {with_rows}");
        }

        // Both constants keep the same command order around the dropped keys.
        assert!(VAULT_MAIN_KEYS_HINT.starts_with("/: 検索 / t: フィルタ / s: 並び替え"));
        assert!(
            VAULT_MAIN_KEYS_HINT.ends_with("g: 監査 / n: 生成 / c: 設定 / l: ロック / Esc: 終了")
        );
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_appends_reedit_hint_for_a_confirmed_query() {
        // R2-UI-141: the re-edit keys used to appear only in the temporary
        // status installed after confirming a search. The persistent vault
        // header must name them too, without changing the established keys.
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
        for rows in [0, 2] {
            let base = vault_row_keys_hint(rows, false, false);
            let confirmed = vault_row_keys_hint(rows, false, true);
            assert_eq!(confirmed, format!("{base} / {hint}"), "rows={rows}");
            assert!(confirmed.ends_with(hint), "rows={rows}: {confirmed}");
            assert_eq!(confirmed.matches(hint).count(), 1, "{confirmed}");
            assert!(confirmed.contains("Esc: 終了"), "{confirmed}");
        }
        // A confirmed query needs no selected row: even an empty vault tells
        // the user how to refine the query that produced zero matches.
        let empty = vault_row_keys_hint(0, false, true);
        assert!(empty.contains(VAULT_SELECTION_FREE_KEYS_HINT), "{empty}");
        assert!(empty.contains(hint), "{empty}");
        assert!(!empty.contains("↑↓"), "{empty}");
    }

    #[::core::prelude::v1::test]
    fn vault_row_keys_hint_hides_reedit_hint_until_a_query_is_confirmed() {
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
        for rows in [0, 2] {
            // Without a confirmed query the established key lists are intact.
            let idle = vault_row_keys_hint(rows, false, false);
            assert!(!idle.contains(hint), "rows={rows}: {idle}");
            let expected = if rows == 0 {
                VAULT_SELECTION_FREE_KEYS_HINT.to_string()
            } else {
                format!(
                    "{} / {VAULT_MAIN_KEYS_HINT}",
                    row_navigation_keys_hint(rows)
                )
            };
            assert_eq!(idle, expected, "rows={rows}");

            // While the search field owns the keyboard every hint is hidden:
            // typed characters start a fresh query, not a confirmed one.
            for query_nonempty in [false, true] {
                let searching = vault_row_keys_hint(rows, true, query_nonempty);
                assert_eq!(searching, "", "rows={rows}, query={query_nonempty}");
                assert!(!searching.contains(hint), "{searching}");
            }
        }
    }

    #[::core::prelude::v1::test]
    fn audit_detail_line_uses_the_shared_row_keys_helper() {
        let report = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        let row_keys = row_selection_keys_hint(1);
        let line = audit_panel_detail_line(&report, false);
        assert!(line.contains(row_keys.as_str()), "{line}");

        let empty_line = audit_panel_detail_line(&Report::default(), false);
        assert!(!empty_line.contains(row_keys.as_str()), "{empty_line}");
        assert!(!empty_line.contains("Enter"), "{empty_line}");
    }

    #[::core::prelude::v1::test]
    fn selected_audit_row_has_a_non_colour_marker() {
        let base = "[高] Example (Login)";
        assert_eq!(audit_row_label(base, false), base);
        assert_eq!(audit_row_label(base, true), format!("▶ {base}"));
        assert!(audit_row_label(base, true).starts_with("▶ "));
        assert_ne!(audit_row_label(base, true), audit_row_label(base, false));
    }

    #[::core::prelude::v1::test]
    fn audit_row_text_replaces_visually_empty_names_with_placeholder() {
        let placeholder = crate::ui::app::ITEM_NAME_PLACEHOLDER;
        // Whitespace-only and Cf-only names both render as blank. The report
        // may arrive with such a name directly, so the label must not expose it.
        for raw in ["", " \t ", "\u{200b}", "\u{feff}\u{202e}", " \u{200b} "] {
            let item = ItemReport {
                id: "item-cf".into(),
                name: raw.into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            };
            let text = audit_row_text(&item);
            assert!(
                text.contains(placeholder),
                "expected placeholder for {raw:?}, got {text:?}"
            );
            if !raw.is_empty() {
                assert!(!text.contains(raw), "raw name leaked into {text:?}");
            }
            assert!(text.starts_with("[?] "), "{text}");
            assert!(text.ends_with(" (ログイン)"), "{text}");
            // The marker is applied on top of the resolved text in both states.
            assert_eq!(audit_row_label(&text, false), text);
            assert_eq!(audit_row_label(&text, true), format!("▶ {text}"));
        }
    }

    #[::core::prelude::v1::test]
    fn audit_row_text_keeps_visible_names_and_report_severity() {
        let item = ItemReport {
            id: "item-visible".into(),
            name: " alice ".into(),
            kind: crate::model::ItemKind::Login,
            findings: vec![crate::health::Finding::ReusedPassword { count: 2 }],
        };
        let text = audit_row_text(&item);
        assert_eq!(text, "[高]  alice  (ログイン)");
        assert!(!text.contains(crate::ui::app::ITEM_NAME_PLACEHOLDER));
    }

    #[::core::prelude::v1::test]
    fn settings_editing_hint_names_every_literal_text_key() {
        // While editing, `+`/`-`, `1`-`6`, `i`/`u` and `n` (the generator-panel
        // jump key) look like settings commands but are inserted as characters
        // (`ui::keys` editing branch).
        let editing = settings_panel_key_hint(true);
        for token in [
            "+/-",
            "1-6",
            "i/u",
            "n（生成パネルへ）",
            "文字として入力",
            "設定値は変更しません",
        ] {
            assert!(editing.contains(token), "missing {token} in {editing}");
        }
        // The original hint and the scroll note must survive the addition.
        assert!(editing.contains(settings_hint(true)), "{editing}");
        assert!(editing.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT), "{editing}");
        assert!(!editing.starts_with("入力中:"), "{editing}");

        // Outside editing those keys really are commands, so the extra note
        // belongs only to the editing variant.
        let idle = settings_panel_key_hint(false);
        assert!(!idle.contains("設定値は変更しません"), "{idle}");
        assert_eq!(
            idle,
            format!(
                "{} / {}",
                settings_hint(false),
                MOUSE_WHEEL_SCROLL_ONLY_HINT
            )
        );
    }

    #[::core::prelude::v1::test]
    fn settings_editing_hint_explains_the_generator_key_without_promising_a_jump() {
        let editing = settings_panel_key_hint(true);
        assert!(editing.contains("n（生成パネルへ）"), "{editing}");
        assert!(editing.contains("n: 生成へ は確定後に有効"), "{editing}");
        // The direct jump works only after Enter/Escape confirms the field, so
        // the summary line keeps hiding its own jump hint while editing: one
        // accurate explanation in the key guide, no duplicate promise.
        let editing_summary = settings_generator_summary_line(24, 6, true);
        assert!(!editing_summary.contains("n:"), "{editing_summary}");
        let idle_summary = settings_generator_summary_line(24, 6, false);
        assert!(idle_summary.contains("n: 生成へ"), "{idle_summary}");
        assert!(!settings_panel_key_hint(false).contains("n（生成パネルへ）"));
    }
}
