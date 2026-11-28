//! GPUI render implementations for the app.

use crate::ui::app::BitwardenApp;
use crate::ui::logic::{auth_hint, FOCUS_RECOVERY_HINT};
use crate::ui::panels::{
    audit_panel, auth_row, generator_panel, panel_button, settings_panel, totp_badge,
};
use crate::ui::state::{AuthField, Panel, Screen};
use gpui_kit::prelude::*;
use gpui_kit::StatefulInteractiveElement;
use gpui_kit::*;

/// Remove the focus-recovery hint from a status that already shows it inline.
///
/// The lock guidance in `ui::app::lock_guidance` wraps its keys in parentheses
/// and ends with F1, so deleting only the hint text left the preceding `" / "`
/// in front of `"）"`. Strip the adjacent separator together with the hint and
/// drop a parenthesis pair that becomes empty as a result. Kept pure so the
/// exact output can be tested without a GPUI window.
fn strip_inline_focus_hint(status: &str) -> String {
    let mut text = status.to_string();
    let mut removed = false;
    while let Some(start) = text.find(FOCUS_RECOVERY_HINT) {
        removed = true;
        let end = start + FOCUS_RECOVERY_HINT.len();
        let mut before = &text[..start];
        let mut after = &text[end..];
        // F1 is normally the last item, so consume the separator before it;
        // when it leads the key list, consume the one after it instead.
        if let Some(trimmed) = before.strip_suffix(" / ") {
            before = trimmed;
        } else if let Some(trimmed) = after.strip_prefix(" / ") {
            after = trimmed;
        }
        // A parenthesised key list may be empty once F1 is gone.
        if before.ends_with('（') && after.starts_with('）') {
            before = &before[..before.len() - '（'.len_utf8()];
            after = &after['）'.len_utf8()..];
        }
        text = format!("{before}{after}");
    }
    if removed {
        // Defensive: a stale separator next to a parenthesis must never be
        // rendered as " / ）" or "（ / " when F1 led the key list.
        text = text.replace(" / ）", "）");
        text = text.replace("（ / ", "（");
    }
    text
}

/// Text drawn in the status bar on the current screen.
///
/// The lock screen's `auth_hint`, the settings panel's `settings_hint` and the
/// generator panel's `generator_panel_key_hint` already carry the F1 recovery
/// guidance. The status bar is the fallback advertiser for panels without an
/// inline hint: when a hint is present, drop F1 from the status text instead of
/// appending it a second time.
fn status_bar_text(status: &str, screen: Screen, panel: Panel) -> String {
    let has_inline_hint = match screen {
        Screen::Locked => true,
        Screen::Unlocked => matches!(panel, Panel::Settings | Panel::Generator | Panel::Audit),
    };
    if has_inline_hint {
        strip_inline_focus_hint(status)
    } else if status.contains(FOCUS_RECOVERY_HINT) {
        status.to_string()
    } else {
        format!("{status}  |  {FOCUS_RECOVERY_HINT}")
    }
}

/// Status shown when the audit tab is clicked before any report exists.
///
/// The tab stays visible for discoverability, but clicking it must not drop
/// the persistent unsaved-settings marker: the user may have edited settings
/// and then returned to the header. Its base text comes from the shared
/// `ui::app::AUDIT_UNAVAILABLE_MESSAGE` (also used by the keyboard `g` path);
/// routing through `status_with_unsaved` keeps the warning. Kept pure so the
/// contract can be tested without a GPUI window.
fn audit_unavailable_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(crate::ui::app::AUDIT_UNAVAILABLE_MESSAGE, dirty)
}

/// Text for the vault list's detail row, when it should be drawn.
///
/// With zero visible items the list body already renders
/// `一致する項目がありません`. Drawing `no_selection_status()`
/// (`項目を選択してください`) underneath asked the user to select a row that
/// does not exist, so the detail row is suppressed instead. Kept pure so the
/// contract can be tested without a GPUI window.
fn vault_detail_row(count: usize, detail: String) -> Option<String> {
    (count > 0).then_some(detail)
}

/// Query text drawn in the vault header.
///
/// A plain `query.is_empty()` check let whitespace-only and invisible-only
/// (`Cf`, for example a zero-width space or bidi override) queries through
/// verbatim, leaving a blank-looking search field. Reuse the same visual
/// emptiness rule as the list row and detail line while keeping the existing
/// "(なし)" placeholder. Kept pure so the output can be tested without a GPUI
/// window.
fn vault_search_query_text(query: &str) -> &str {
    if crate::ui::app::is_visually_empty(query) {
        "(なし)"
    } else {
        query
    }
}

/// Header text above the vault list.
///
/// `PageUp`/`PageDown` and `Home`/`End` move the vault selection just like
/// Up/Down (see `ui::keys::classify_key`), so the header advertises them next
/// to the row-move key. `Enter` is bound only in the audit panel and is inert
/// in the vault panel, so it is deliberately left out of this header. A
/// confirmed (non-empty, non-searching) query keeps Backspace and typed text
/// bound to re-editing, so those keys belong in the header too instead of only
/// in the temporary status. Kept pure so the wording can be tested without a
/// GPUI window.
fn vault_list_header_text(
    count: usize,
    total: usize,
    filter_label: &str,
    sort_label: &str,
    query: &str,
    searching: bool,
) -> String {
    // While the search field owns the keyboard, row movement keys are not
    // routed to the vault selection (`ui::keys::classify_key`), so the header
    // must not advertise them during editing. The query flag uses the same
    // shared visual-emptiness rule as the status and key classification, so an
    // invisible-only query cannot make the header promise re-edit keys.
    let row_keys = crate::ui::panels::vault_row_keys_hint(
        count,
        searching,
        crate::ui::input::confirmed_query_nonempty(query),
    );
    let row_suffix = if row_keys.is_empty() {
        String::new()
    } else {
        format!("  |  {row_keys}")
    };
    format!(
        "Vault: {count} / {total} 件  |  フィルタ: {filter_label}  |  並び: {sort_label}  |  検索: {}{}{row_suffix}",
        vault_search_query_text(query),
        if searching { " _" } else { "" },
    )
}

/// Vault header with the persistent offline-restore marker appended.
///
/// The temporary login warning is replaced by the next key action, so the
/// restored-data notice belongs in a persistent element. This thin wrapper
/// keeps the established `vault_list_header_text` wording and its drawing
/// tests untouched while the app-level flag drives the extra label.
fn vault_list_header_with_offline(base: String, offline: bool, reason: Option<&str>) -> String {
    format!(
        "{base}{}",
        crate::ui::logic::offline_restore_header_label(offline, reason)
    )
}

/// Name drawn in a vault list row.
///
/// The raw `item.name` used to leave a blank column for empty or invisible-only
/// (`Cf`) names, while the detail row included the same raw value between two
/// `" | "` separators. Both call sites now use `app::item_name_text`; this thin
/// adapter keeps the list-row contract separately testable without a GPUI
/// window.
fn vault_row_name(name: &str) -> String {
    crate::ui::app::item_name_text(name).to_string()
}

/// Username drawn in a vault list row.
///
/// `VaultItem::login()` is `Some` for every login item, even one whose username
/// is empty. Drawing that string directly left a blank column that looked like
/// a rendering failure. A missing login, a whitespace-only username and a
/// username made only of invisible Unicode `Cf` (format) characters all use the
/// "-" placeholder; names with visible content are rendered unchanged. Kept
/// pure so the contract can be tested without a GPUI window.
fn vault_row_username(login: Option<(&str, &str, &str, &[crate::model::LoginUri])>) -> String {
    match login {
        Some((user, _, _, _)) if !crate::ui::app::is_visually_empty(user) => user.to_string(),
        _ => "-".to_string(),
    }
}

impl BitwardenApp {
    fn render_locked(&self, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_6()
            .max_w(px(520.0))
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::BOLD)
                    .child("Bitwarden (GPUI PoC)"),
            )
            .child(div().text_sm().text_color(rgb(0xa6adc8)).child(
                "個人 vault クライアントの UI。認証情報を入力すると実ログイン・同期を試せます。",
            ))
            .child(auth_row(
                "1  Server",
                &self.settings.server_url,
                self.auth.field() == Some(AuthField::ServerUrl),
                false,
            ))
            .child(auth_row(
                "2  Email",
                &self.settings.email,
                self.auth.field() == Some(AuthField::Email),
                false,
            ))
            .child(auth_row(
                "3  Client ID",
                self.auth.client_id(),
                self.auth.field() == Some(AuthField::ClientId),
                false,
            ))
            .child(auth_row(
                "4  Client Secret",
                self.auth.client_secret(),
                self.auth.field() == Some(AuthField::ClientSecret),
                true,
            ))
            .child(auth_row(
                "5  Master Password",
                self.auth.master_password(),
                self.auth.field() == Some(AuthField::MasterPassword),
                true,
            ))
            .child(
                div()
                    .mt_2()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(0x313244))
                    .text_sm()
                    .child(auth_hint(self.auth.field().is_some())),
            )
    }

    fn render_unlocked(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let count = self.view.visible_items().len();
        let detail = self.selected_detail();

        let list = uniform_list(
            "vault-items",
            count,
            cx.processor(
                move |this: &mut Self, range: std::ops::Range<usize>, _window, cx| {
                    let visible = this.view.visible_items();
                    let mut rows = Vec::with_capacity(range.len());
                    for index in range {
                        let Some(item) = visible.get(index) else {
                            continue;
                        };
                        let row_id = item.id.clone();
                        let selected = this.view.selected_id.as_deref() == Some(row_id.as_str());
                        let row_bg = if selected {
                            rgb(0x45475a)
                        } else {
                            rgb(0x1e1e2e)
                        };
                        // The selected row lightens its background to 0x45475a,
                        // where the muted foregrounds used on the default row
                        // fall below WCAG 1.4.3 (the username is ~4.1:1 there).
                        // Brighter variants keep every label above 4.5:1.
                        let username_color = if selected {
                            rgb(0xcdd6f4)
                        } else {
                            rgb(0xa6adc8)
                        };
                        let kind_color = if selected {
                            rgb(0xa6c8ff)
                        } else {
                            rgb(0x89b4fa)
                        };
                        // The default non-favorite star colour (0x45475a) is
                        // exactly the selected row background; give the empty
                        // star a visible muted grey on that background.
                        let star_color = if item.favorite {
                            rgb(0xf9e2af)
                        } else if selected {
                            rgb(0x9399b2)
                        } else {
                            rgb(0x45475a)
                        };
                        let username = vault_row_username(item.login());
                        let badge = totp_badge(item);
                        // Row identity here is the render-position `index`, not
                        // the item's stable id. The click below sends that same
                        // `index` as `UiAction::SelectRow`, and `ui::input`
                        // resolves it through `VaultViewState::select_index`
                        // against the visible list. Both sides must therefore
                        // observe the same snapshot: a filter/sort/query change
                        // between draw and click can make the index name a
                        // different row (or fall out of range). Moving to a
                        // stable id is intentionally out of scope (R2-UI-94).
                        rows.push(
                            div()
                                .id(index)
                                .on_click(cx.listener(move |this, _event, _window, cx| {
                                    this.apply_action(
                                        crate::ui::keys::UiAction::SelectRow(index),
                                        cx,
                                    );
                                }))
                                .flex()
                                .items_center()
                                .gap_3()
                                .px_3()
                                .h(px(30.0))
                                .bg(row_bg)
                                .text_sm()
                                // Selection marker lives in its own fixed-width
                                // column so it never blends into the name,
                                // username (email), or search query text.
                                .child(
                                    div()
                                        .w(px(14.0))
                                        .text_xs()
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(if selected {
                                            rgb(0xf9e2af)
                                        } else {
                                            rgb(0xa6adc8)
                                        })
                                        .child(if selected { ">" } else { "" }),
                                )
                                .child(
                                    div()
                                        .id(SharedString::from(format!("favorite-{index}")))
                                        .w(px(18.0))
                                        .text_xs()
                                        .text_color(star_color)
                                        .on_click(cx.listener(move |this, _event, _window, cx| {
                                            // The parent row also has a click
                                            // handler; stop the bubble so it
                                            // cannot reselect another row after
                                            // the favorite filter removed ours.
                                            cx.stop_propagation();
                                            // Select the clicked row first, so
                                            // the star toggle can never target
                                            // a different item.
                                            this.apply_action(
                                                crate::ui::keys::UiAction::SelectRow(index),
                                                cx,
                                            );
                                            this.apply_action(
                                                crate::ui::keys::UiAction::ToggleFavorite,
                                                cx,
                                            );
                                        }))
                                        .child(if item.favorite { "★" } else { "☆" }),
                                )
                                .child(
                                    div()
                                        .w(px(70.0))
                                        .text_xs()
                                        .text_color(kind_color)
                                        .child(item.kind().label().to_string()),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .overflow_hidden()
                                        .font_weight(FontWeight::MEDIUM)
                                        .child(vault_row_name(&item.name)),
                                )
                                .child(
                                    div()
                                        .w(px(200.0))
                                        .overflow_hidden()
                                        .text_color(username_color)
                                        .child(username),
                                )
                                .child(
                                    div()
                                        .w(px(40.0))
                                        .text_xs()
                                        .text_color(rgb(badge.color_for_row(selected)))
                                        .child(badge.label),
                                ),
                        );
                    }
                    rows
                },
            ),
        )
        .track_scroll(&self.view.scroll_handle)
        .flex_1();

        let filter_label = self.view.filter.label(&self.view.vault.folders);
        div()
            .flex()
            .flex_col()
            .flex_1()
            .child(
                div()
                    .px_4()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(0x313244))
                    .text_sm()
                    .text_color(rgb(0xa6adc8))
                    .child(vault_list_header_with_offline(
                        vault_list_header_text(
                            count,
                            self.view.vault.len(),
                            &filter_label,
                            self.view.sort.label(),
                            &self.view.query,
                            self.view.searching,
                        ),
                        self.offline_restore,
                        self.offline_restore_reason.as_deref(),
                    )),
            )
            .child(if count == 0 {
                div()
                    .flex_1()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(rgb(0xa6adc8))
                    .child("一致する項目がありません")
                    .into_any_element()
            } else {
                list.into_any_element()
            })
            .child(match vault_detail_row(count, detail) {
                Some(text) => div()
                    .px_4()
                    .py_2()
                    .border_t_1()
                    .border_color(rgb(0x313244))
                    .text_xs()
                    .text_color(rgb(0xcdd6f4))
                    .child(text)
                    .into_any_element(),
                // No matches: the empty-list message above is enough; an
                // empty element draws no detail row (and no border).
                None => div().into_any_element(),
            })
    }
}

impl Render for BitwardenApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // `login_flow.rs` owns `AuthenticatedVault::from_cache` and is outside
        // this task's write scope, so the post-login status is the only
        // in-scope carrier. Latch it before any panel draws; lock/unlock clear
        // the flag through `reset_input_state`, and a fresh-sync login clears
        // it here.
        self.sync_offline_restore_from_status();
        // One normalized panel value for the header tabs, the key context and
        // the body, so a stale Audit request cannot disagree with the drawing.
        let panel = crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some());
        let has_report = self.view.audit_report.is_some();
        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .px_4()
            .py_2()
            .bg(rgb(0x181825))
            .border_b_1()
            .border_color(rgb(0x313244))
            .child(
                div()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Bitwarden GPUI PoC"),
            )
            .child(if self.screen == Screen::Unlocked {
                div()
                    .flex()
                    .gap_1()
                    .child(panel_button(
                        "[一覧]",
                        Panel::Vault,
                        panel,
                        |this, cx| {
                            this.apply_action(
                                crate::ui::keys::UiAction::SetPanel(Panel::Vault),
                                cx,
                            );
                        },
                        cx,
                    ))
                    .child(panel_button(
                        if has_report {
                            "[監査]"
                        } else {
                            "[監査 (未生成)]"
                        },
                        Panel::Audit,
                        panel,
                        move |this, cx| {
                            if has_report {
                                this.apply_action(
                                    crate::ui::keys::UiAction::SetPanel(Panel::Audit),
                                    cx,
                                );
                            } else {
                                // The button stays visible for discoverability,
                                // but explains why it cannot open a panel. Keep
                                // the unsaved-settings marker (Z13).
                                let dirty = this.settings_dirty;
                                this.status = audit_unavailable_status(dirty);
                                // No panel to open, so this branch bypasses
                                // apply_action; stamp activity explicitly or an
                                // active user can hit the idle lock (R2-UI-136).
                                this.stamp_activity();
                                cx.notify();
                            }
                        },
                        cx,
                    ))
                    .child(panel_button(
                        "[生成]",
                        Panel::Generator,
                        panel,
                        |this, cx| {
                            this.apply_action(
                                crate::ui::keys::UiAction::SetPanel(Panel::Generator),
                                cx,
                            );
                        },
                        cx,
                    ))
                    .child(panel_button(
                        "[設定]",
                        Panel::Settings,
                        panel,
                        |this, cx| {
                            this.apply_action(
                                crate::ui::keys::UiAction::SetPanel(Panel::Settings),
                                cx,
                            );
                        },
                        cx,
                    ))
                    .into_any_element()
            } else {
                div()
                    .text_xs()
                    .text_color(rgb(0xa6adc8))
                    .child("gpui-kit 0.9.1 + model::Vault")
                    .into_any_element()
            });

        let body = match (self.screen, panel) {
            (Screen::Locked, _) => div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(self.render_locked(cx))
                .into_any_element(),
            (Screen::Unlocked, Panel::Audit) => match &self.view.audit_report {
                Some(report) => audit_panel(
                    report,
                    self.audit_row_selection,
                    self.settings_dirty,
                    &self.audit_scroll_handle,
                    |this, id, cx| {
                        this.apply_action(
                            crate::ui::keys::UiAction::FocusAuditItem(id.to_string()),
                            cx,
                        );
                    },
                    cx,
                )
                .into_any_element(),
                None => self.render_unlocked(cx).into_any_element(),
            },
            (Screen::Unlocked, Panel::Generator) => generator_panel(
                &self.settings,
                &self.generator,
                self.settings_dirty,
                &self.generator_scroll_handle,
            )
            .into_any_element(),
            (Screen::Unlocked, Panel::Settings) => settings_panel(
                &self.settings,
                self.editing,
                self.settings_dirty,
                &self.settings_scroll_handle,
            )
            .into_any_element(),
            (Screen::Unlocked, _) => self.render_unlocked(cx).into_any_element(),
        };

        let status = div()
            .px_4()
            .py_2()
            .bg(rgb(0x181825))
            .border_t_1()
            .border_color(rgb(0x313244))
            .text_xs()
            .text_color(rgb(0xa6adc8))
            // Panel hints are local to each panel, while the status bar is the
            // one element drawn on every screen. `status_bar_text` keeps F1
            // out of the status when an inline hint already shows it, and adds
            // it as the fallback on panels without such a hint.
            .child(status_bar_text(&self.status, self.screen, panel));

        div()
            .id("bitwarden-poc-root")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
            .on_scroll(cx.listener(Self::scrolled))
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0x1e1e2e))
            .text_color(rgb(0xcdd6f4))
            .child(header)
            .child(body)
            .child(status)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn vault_detail_row_is_hidden_when_no_items_match() {
        let prompt = crate::ui::logic::no_selection_status();
        assert_eq!(prompt, "項目を選択してください");
        assert_eq!(vault_detail_row(0, prompt.to_string()), None);
        assert_eq!(
            vault_detail_row(1, prompt.to_string()),
            Some(prompt.to_string())
        );
        assert!(vault_detail_row(7, "詳細".into()).is_some());
    }

    #[::core::prelude::v1::test]
    fn status_bar_shows_the_focus_hint_only_once() {
        // The lock screen's inline `auth_hint` already ends with F1, so the
        // status text must not repeat it.
        let lock = "ロック中: Enter: ログイン / m: モック / Esc: 終了 / F1: フォーカス復帰";
        assert_eq!(
            status_bar_text(lock, Screen::Locked, Panel::Vault),
            "ロック中: Enter: ログイン / m: モック / Esc: 終了"
        );

        // The settings panel's inline `settings_hint` does the same; a plain
        // status stays plain instead of gaining a second F1.
        let plain = "入力を確定しました（w: 保存 / d: 破棄）";
        assert_eq!(
            status_bar_text(plain, Screen::Unlocked, Panel::Settings),
            plain
        );

        // Panels without an inline hint still get the fallback guidance...
        assert_eq!(
            status_bar_text(plain, Screen::Unlocked, Panel::Vault),
            format!("{plain}  |  {FOCUS_RECOVERY_HINT}")
        );
        // The audit panel now advertises F1 inline, so its status drops it
        // instead of repeating it (Vault is the remaining fallback case).
        let with_hint = format!("監査行 1/2: example / {FOCUS_RECOVERY_HINT}");
        assert_eq!(
            status_bar_text(&with_hint, Screen::Unlocked, Panel::Audit),
            "監査行 1/2: example"
        );
    }

    #[::core::prelude::v1::test]
    fn vault_header_keeps_the_offline_restore_marker_after_status_changes() {
        let base = vault_list_header_text(3, 7, "すべて", "名前 ↑", "", false);
        assert_eq!(
            vault_list_header_with_offline(base.clone(), false, None),
            base
        );
        // An optional reason is not available yet (auth.rs drops sync_cause).
        assert_eq!(
            vault_list_header_with_offline(base.clone(), false, Some("同期失敗")),
            base
        );

        let offline = vault_list_header_with_offline(base.clone(), true, None);
        assert!(offline.starts_with(&base), "{offline}");
        assert!(offline.ends_with(" | [オフライン復元]"), "{offline}");
        // Established header wording and key hints survive unchanged.
        assert!(offline.contains("Vault: 3 / 7 件"), "{offline}");
        assert!(offline.contains("↑↓: 行を選択"), "{offline}");
        assert!(offline.contains("Esc: 終了"), "{offline}");

        let with_reason = vault_list_header_with_offline(base, true, Some("同期に失敗"));
        assert!(
            with_reason.contains("[オフライン復元: 同期に失敗]"),
            "{with_reason}"
        );
    }

    #[::core::prelude::v1::test]
    fn generator_panel_does_not_repeat_the_focus_hint_in_the_status_bar() {
        // The generator's inline `generator_panel_key_hint` already ends with
        // F1, so its status must drop the key instead of appending it again.
        let with_hint = format!("生成しました / {FOCUS_RECOVERY_HINT}");
        assert_eq!(
            status_bar_text(&with_hint, Screen::Unlocked, Panel::Generator),
            "生成しました"
        );
        let plain = "パスワードを生成しました（30秒後に復元）";
        assert_eq!(
            status_bar_text(plain, Screen::Unlocked, Panel::Generator),
            plain,
            "a plain generator status must not gain a second F1"
        );
        // The audit panel also carries an inline hint now; only Vault and
        // other inline-free panels keep the fallback.
        assert_eq!(
            status_bar_text(plain, Screen::Unlocked, Panel::Audit),
            plain
        );
        assert_eq!(
            status_bar_text(plain, Screen::Unlocked, Panel::Vault),
            format!("{plain}  |  {FOCUS_RECOVERY_HINT}")
        );
    }

    #[::core::prelude::v1::test]
    fn lock_status_f1_removal_leaves_no_separator_or_empty_parens() {
        // Mirrors `ui::app::lock_guidance`: the keys are wrapped in full-width
        // parentheses and F1 closes the list.
        let lock = format!("ロックしました（Enter: ログイン / m: モック / {FOCUS_RECOVERY_HINT}）");
        assert_eq!(
            status_bar_text(&lock, Screen::Locked, Panel::Vault),
            "ロックしました（Enter: ログイン / m: モック）"
        );

        // A stale trailing separator must be cleaned up, never shown as
        // " / ）" in the status bar.
        let stale =
            format!("ロックしました（Enter: ログイン / m: モック / {FOCUS_RECOVERY_HINT} / ）");
        assert_eq!(
            status_bar_text(&stale, Screen::Locked, Panel::Vault),
            "ロックしました（Enter: ログイン / m: モック）"
        );

        // F1 as the only key leaves no empty parentheses behind.
        let only = format!("ロックしました（{FOCUS_RECOVERY_HINT}）");
        assert_eq!(
            status_bar_text(&only, Screen::Locked, Panel::Vault),
            "ロックしました"
        );

        // The idle-lock status appends the unsaved marker after the guidance;
        // removing F1 must not consume that marker or its separator.
        let idle = format!(
            "無操作のため自動ロックしました（5分）（Enter: ログイン / m: モック / {FOCUS_RECOVERY_HINT}） | [未保存の設定変更があります]"
        );
        assert_eq!(
            status_bar_text(&idle, Screen::Locked, Panel::Vault),
            "無操作のため自動ロックしました（5分）（Enter: ログイン / m: モック） | [未保存の設定変更があります]"
        );
    }

    #[::core::prelude::v1::test]
    fn audit_tab_without_report_keeps_the_unsaved_marker() {
        let base = "監査レポートがありません（ログイン後に生成されます）";
        assert_eq!(crate::ui::app::AUDIT_UNAVAILABLE_MESSAGE, base);
        assert_eq!(audit_unavailable_status(false), base);

        let dirty = audit_unavailable_status(true);
        assert_eq!(dirty, crate::ui::app::status_with_unsaved(base, true));
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");

        // The keyboard `g` path composes the identical status from the same
        // shared constant, in both marker states.
        for flag in [false, true] {
            assert_eq!(
                audit_unavailable_status(flag),
                crate::ui::input::audit_unavailable_status(flag),
                "dirty={flag}"
            );
        }

        // The status bar adds its fallback F1 hint on the vault panel without
        // swallowing the marker appended above.
        let shown = status_bar_text(&dirty, Screen::Unlocked, Panel::Vault);
        assert!(shown.contains(base), "{shown}");
        assert!(shown.contains("[未保存の設定変更があります]"), "{shown}");
    }

    #[::core::prelude::v1::test]
    fn vault_header_advertises_page_and_edge_keys() {
        let header = vault_list_header_text(2, 7, "お気に入り", "名前 ↑", "", false);
        for key in ["PageUp", "PageDown", "Home", "End"] {
            assert!(header.contains(key), "missing {key} in {header}");
        }
        assert!(header.contains("↑↓: 行を選択"), "{header}");
        assert!(header.contains("Vault: 2 / 7 件"), "{header}");
        assert!(header.contains("検索: (なし)"), "{header}");

        let searching = vault_list_header_text(1, 7, "すべてのアイテム", "名前 ↓", "abc", true);
        assert!(searching.contains("検索: abc _"), "{searching}");
        // The search field owns Up/Down/PageUp/... while editing, so those
        // keys must not be advertised in the header during that time.
        assert!(
            !searching.contains(crate::ui::panels::LIST_PAGE_AND_EDGE_HINT),
            "row keys are inert while searching: {searching}"
        );
        assert!(!searching.contains("↑↓"), "{searching}");
    }

    #[::core::prelude::v1::test]
    fn vault_header_hides_invisible_only_queries() {
        assert_eq!(vault_search_query_text(""), "(なし)");
        assert_eq!(vault_search_query_text("  \t "), "(なし)");
        assert_eq!(
            vault_search_query_text("\u{200b}\u{feff}\u{202e}"),
            "(なし)"
        );
        // A query with any visible character is still drawn verbatim.
        assert_eq!(vault_search_query_text(" alice "), " alice ");
        assert_eq!(vault_search_query_text("alice\u{200b}"), "alice\u{200b}");

        for query in ["", "  ", "\u{200b}", "\u{200b}\u{feff}"] {
            let header = vault_list_header_text(3, 7, "すべて", "名前 ↑", query, false);
            assert!(header.contains("検索: (なし)"), "{query:?}: {header}");
            // `vault_search_query_text` reuses `is_visually_empty`, so a
            // whitespace-only query is drawn as "(なし)" here too; the raw
            // text is never printed. The check below guards the invisible
            // (`Cf`) case, whose blank appearance is easiest to overlook.
            if query.contains('\u{200b}') {
                assert!(!header.contains(query), "raw invisible query: {header}");
            }
        }

        let visible = vault_list_header_text(3, 7, "すべて", "名前 ↑", "abc", true);
        assert!(visible.contains("検索: abc _"), "{visible}");
        let processing = vault_list_header_text(3, 7, "すべて", "名前 ↑", "\u{200b}", true);
        assert!(processing.contains("検索: (なし) _"), "{processing}");
    }

    #[::core::prelude::v1::test]
    fn vault_header_drops_row_keys_while_searching() {
        for searching in [false, true] {
            let header = vault_list_header_text(3, 7, "すべて", "名前 ↑", "abc", searching);
            let advertises_rows = header.contains(crate::ui::panels::LIST_PAGE_AND_EDGE_HINT);
            assert_eq!(
                advertises_rows, !searching,
                "searching={searching}: {header}"
            );
            assert_eq!(header.contains("↑↓"), !searching, "{header}");
        }
        // The query caret marker stays independent of the row-key hint.
        let idle = vault_list_header_text(3, 7, "すべて", "名前 ↑", "abc", false);
        let editing = vault_list_header_text(3, 7, "すべて", "名前 ↑", "abc", true);
        assert!(!idle.contains("検索: abc _"), "{idle}");
        assert!(editing.contains("検索: abc _"), "{editing}");
    }

    #[::core::prelude::v1::test]
    fn vault_header_shows_reedit_keys_for_a_confirmed_query() {
        // R2-UI-141: the re-edit keys used to live only in the temporary
        // post-confirm status. The persistent header must name them whenever
        // the query is still bound to Backspace and typed text.
        let hint = crate::ui::keys::CONFIRMED_QUERY_REEDIT_HINT;
        for count in [0, 3] {
            let confirmed = vault_list_header_text(count, 7, "すべて", "名前 ↑", "alice", false);
            assert!(confirmed.contains(hint), "count={count}: {confirmed}");
            assert_eq!(confirmed.matches(hint).count(), 1, "{confirmed}");
            assert!(confirmed.contains("検索: alice"), "{confirmed}");
        }
        // The established keys survive the addition.
        let confirmed = vault_list_header_text(3, 7, "すべて", "名前 ↑", "alice", false);
        assert!(confirmed.contains("↑↓: 行を選択"), "{confirmed}");
        assert!(
            confirmed.contains(crate::ui::panels::LIST_PAGE_AND_EDGE_HINT),
            "{confirmed}"
        );
        assert!(confirmed.contains("Esc: 終了"), "{confirmed}");

        // Still typing a new query: the re-edit hint does not apply because
        // those characters are the fresh query, not a confirmed one.
        let searching = vault_list_header_text(3, 7, "すべて", "名前 ↑", "alice", true);
        assert!(!searching.contains(hint), "{searching}");

        // No query or an invisible-only one leaves nothing to re-edit. The
        // same shared emptiness rule drives key classification and status.
        for query in ["", "  \t", "\u{200b}", "\u{feff}\u{202e}"] {
            let idle = vault_list_header_text(3, 7, "すべて", "名前 ↑", query, false);
            assert!(!idle.contains(hint), "{query:?}: {idle}");
        }
    }

    #[::core::prelude::v1::test]
    fn vault_header_never_promises_the_audit_only_enter_key() {
        // `enter` is inert in the vault panel (`ui::keys::classify_key`); the
        // old shared hint advertised it here anyway. Every row count must now
        // omit both the key name and the audit-only "select target" phrase.
        for count in [0, 1, 3] {
            let header = vault_list_header_text(count, 7, "すべて", "名前 ↑", "", false);
            assert!(!header.contains("Enter"), "count={count}: {header}");
            assert!(!header.contains("対象を選択"), "count={count}: {header}");
        }

        // The remaining navigation wording is unchanged.
        let header = vault_list_header_text(2, 7, "すべて", "名前 ↑", "", false);
        assert!(header.contains("↑↓: 行を選択"), "{header}");
        assert!(
            header.contains(crate::ui::panels::LIST_PAGE_AND_EDGE_HINT),
            "{header}"
        );
    }

    #[::core::prelude::v1::test]
    fn empty_login_username_shows_the_placeholder() {
        fn login(user: &str) -> Option<(&str, &str, &str, &[crate::model::LoginUri])> {
            let uris: &[crate::model::LoginUri] = &[];
            Some((user, "", "", uris))
        }

        assert_eq!(vault_row_username(None), "-");
        assert_eq!(
            vault_row_username(login("")),
            "-",
            "Some with an empty username must not leave a blank column"
        );
        assert_eq!(
            vault_row_username(login("   ")),
            "-",
            "a whitespace-only username is invisible too"
        );
        assert_eq!(
            vault_row_username(login("alice@example.com")),
            "alice@example.com",
            "a real username must still be rendered unchanged"
        );
        assert_eq!(
            vault_row_username(None),
            vault_row_username(login("")),
            "the Some(empty) case must be indistinguishable from the old None case"
        );
    }

    #[::core::prelude::v1::test]
    fn format_only_username_also_shows_the_placeholder() {
        fn login(user: &str) -> Option<(&str, &str, &str, &[crate::model::LoginUri])> {
            let uris: &[crate::model::LoginUri] = &[];
            Some((user, "", "", uris))
        }

        // A username made only of Unicode Cf characters is invisible, so
        // `trim().is_empty()` alone let it through and left a blank column.
        // Zero-width space, BOM, bidi override, soft hyphen and a run of them:
        // all must be indistinguishable from an empty username.
        for cf in [
            "\u{200b}",
            "\u{feff}",
            "\u{202e}",
            "\u{00ad}",
            "\u{200b}\u{feff}",
        ] {
            assert_eq!(
                vault_row_username(login(cf)),
                "-",
                "Cf-only username {cf:?} must use the placeholder"
            );
        }
        // Whitespace mixed with Cf is still invisible.
        assert_eq!(vault_row_username(login(" \u{200b} ")), "-");
        // A visible character next to a Cf is a real username and is kept.
        let mixed = "alice\u{200b}";
        assert_eq!(vault_row_username(login(mixed)), mixed);
    }

    #[::core::prelude::v1::test]
    fn empty_item_name_shows_the_placeholder_in_the_list_row() {
        for invisible in ["", "  \t ", "\u{200b}", "\u{feff}\u{202e}", " \u{00ad} "] {
            assert_eq!(
                vault_row_name(invisible),
                crate::ui::app::ITEM_NAME_PLACEHOLDER,
                "invisible name {invisible:?} must not leave a blank row column"
            );
        }
        assert_eq!(vault_row_name("alice"), "alice");
        let mixed = "alice\u{200b}";
        assert_eq!(vault_row_name(mixed), mixed);
        assert_eq!(
            vault_row_name(""),
            crate::ui::app::item_name_text(""),
            "the list row and the detail row must share the same placeholder"
        );
    }
}
