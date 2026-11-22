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
                    .child(format!(
                        "Vault: {} / {} 件  |  フィルタ: {}  |  並び: {}  |  検索: {}{}",
                        count,
                        self.view.vault.len(),
                        filter_label,
                        self.view.sort.label(),
                        if self.view.query.is_empty() {
                            "(なし)"
                        } else {
                            &self.view.query
                        },
                        if self.view.searching { " _" } else { "" }
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
            .child(
                div()
                    .px_4()
                    .py_2()
                    .border_t_1()
                    .border_color(rgb(0x313244))
                    .text_xs()
                    .text_color(rgb(0xcdd6f4))
                    .child(detail),
            )
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
            // one element drawn on every screen. Advertise focus recovery here
            // so it is discoverable even on panels without an inline hint, and
            // avoid saying it twice when a status already mentions it.
            .child(if self.status.contains(FOCUS_RECOVERY_HINT) {
                self.status.clone()
            } else {
                format!("{}  |  {}", self.status, FOCUS_RECOVERY_HINT)
            });

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
