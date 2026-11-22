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
        Screen::Unlocked => matches!(panel, Panel::Settings | Panel::Generator),
    };
    if has_inline_hint {
        strip_inline_focus_hint(status)
    } else if status.contains(FOCUS_RECOVERY_HINT) {
        status.to_string()
    } else {
        format!("{status}  |  {FOCUS_RECOVERY_HINT}")
    }
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

/// Header text above the vault list.
///
/// `PageUp`/`PageDown` and `Home`/`End` move the vault selection just like
/// Up/Down (see `ui::keys::classify_key`), so the header advertises them next
/// to the row-move key. Kept pure so the wording can be tested without a GPUI
/// window.
fn vault_list_header_text(
    count: usize,
    total: usize,
    filter_label: &str,
    sort_label: &str,
    query: &str,
    searching: bool,
) -> String {
    format!(
        "Vault: {count} / {total} 件  |  フィルタ: {filter_label}  |  並び: {sort_label}  |  検索: {}{}  |  ↑↓: 行を選択 / {}",
        if query.is_empty() { "(なし)" } else { query },
        if searching { " _" } else { "" },
        crate::ui::panels::LIST_PAGE_AND_EDGE_HINT
    )
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
                        let username = item
                            .login()
                            .map_or("-".to_string(), |(user, _, _, _)| user.to_string());
                        let badge = totp_badge(item);
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
                                        .child(item.name.clone()),
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
                    .child(vault_list_header_text(
                        count,
                        self.view.vault.len(),
                        &filter_label,
                        self.view.sort.label(),
                        &self.view.query,
                        self.view.searching,
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
                                // but explains why it cannot open a panel.
                                this.status =
                                    "監査レポートがありません（ログイン後に生成されます）"
                                        .to_string();
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
            (Screen::Unlocked, Panel::Generator) => {
                generator_panel(&self.settings, &self.generator, self.settings_dirty)
                    .into_any_element()
            }
            (Screen::Unlocked, Panel::Settings) => {
                settings_panel(&self.settings, self.editing, self.settings_dirty).into_any_element()
            }
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
        // ...and never append it twice when the status already mentions it.
        let with_hint = format!("監査行 1/2: example / {FOCUS_RECOVERY_HINT}");
        assert_eq!(
            status_bar_text(&with_hint, Screen::Unlocked, Panel::Audit),
            with_hint
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
        // Panels without an inline hint keep the fallback behaviour.
        assert_eq!(
            status_bar_text(plain, Screen::Unlocked, Panel::Audit),
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
            "無操作のため自動ロックしました（300秒）（Enter: ログイン / m: モック / {FOCUS_RECOVERY_HINT}） | [未保存の設定変更があります]"
        );
        assert_eq!(
            status_bar_text(&idle, Screen::Locked, Panel::Vault),
            "無操作のため自動ロックしました（300秒）（Enter: ログイン / m: モック） | [未保存の設定変更があります]"
        );
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
        assert!(
            searching.contains(crate::ui::panels::LIST_PAGE_AND_EDGE_HINT),
            "{searching}"
        );
    }
}
