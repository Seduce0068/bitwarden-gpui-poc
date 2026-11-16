//! GPUI render implementations for the app.

use crate::ui::app::BitwardenApp;
use crate::ui::model::{AuthField, Panel, Screen};
use crate::ui::panels::{audit_panel, auth_row, generator_panel, panel_button, settings_panel};
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
                &self.server_url,
                self.auth_field == Some(AuthField::ServerUrl),
                false,
            ))
            .child(auth_row(
                "2  Email",
                &self.email,
                self.auth_field == Some(AuthField::Email),
                false,
            ))
            .child(auth_row(
                "3  Client ID",
                &self.client_id,
                self.auth_field == Some(AuthField::ClientId),
                false,
            ))
            .child(auth_row(
                "4  Client Secret",
                &self.client_secret,
                self.auth_field == Some(AuthField::ClientSecret),
                true,
            ))
            .child(auth_row(
                "5  Master Password",
                &self.master_password,
                self.auth_field == Some(AuthField::MasterPassword),
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
                    .child("1-5: 入力 / Enter: 検証して開く / Esc: 終了"),
            )
    }

    fn render_unlocked(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let count = self.visible_items().len();
        let detail = self.selected_detail();

        let list = uniform_list(
            "vault-items",
            count,
            cx.processor(
                move |this: &mut Self, range: std::ops::Range<usize>, _window, cx| {
                    let visible = this.visible_items();
                    let mut rows = Vec::with_capacity(range.len());
                    for index in range {
                        let Some(item) = visible.get(index) else {
                            continue;
                        };
                        let selected = this.selected == index;
                        let row_bg = if selected {
                            rgb(0x45475a)
                        } else {
                            rgb(0x1e1e2e)
                        };
                        let (username, totp) = item
                            .login()
                            .map_or(("-".to_string(), false), |(user, _, totp, _)| {
                                (user.to_string(), !totp.trim().is_empty())
                            });
                        rows.push(
                            div()
                                .id(index)
                                .on_click(cx.listener(move |this, _event, _window, cx| {
                                    this.selected = index;
                                    cx.notify();
                                }))
                                .flex()
                                .items_center()
                                .gap_3()
                                .px_3()
                                .h(px(30.0))
                                .bg(row_bg)
                                .text_sm()
                                .child(
                                    div()
                                        .w(px(18.0))
                                        .text_xs()
                                        .text_color(if item.favorite {
                                            rgb(0xf9e2af)
                                        } else {
                                            rgb(0x45475a)
                                        })
                                        .child(if item.favorite { "★" } else { "☆" }),
                                )
                                .child(
                                    div()
                                        .w(px(70.0))
                                        .text_xs()
                                        .text_color(rgb(0x89b4fa))
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
                                        .text_color(rgb(0xa6adc8))
                                        .child(username),
                                )
                                .child(
                                    div()
                                        .w(px(40.0))
                                        .text_xs()
                                        .text_color(if totp {
                                            rgb(0xa6e3a1)
                                        } else {
                                            rgb(0x6c7086)
                                        })
                                        .child(if totp { "TOTP" } else { "" }),
                                ),
                        );
                    }
                    rows
                },
            ),
        )
        .track_scroll(&self.scroll_handle)
        .flex_1();

        let filter_label = self.filter.label(&self.vault.folders);
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
                        self.vault.len(),
                        filter_label,
                        self.sort.label(),
                        if self.query.is_empty() {
                            "(なし)"
                        } else {
                            &self.query
                        },
                        if self.searching { " _" } else { "" }
                    )),
            )
            .child(if count == 0 {
                div()
                    .flex_1()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(rgb(0x6c7086))
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
                        self.panel,
                        |this, cx| {
                            this.panel = Panel::Vault;
                            cx.notify();
                        },
                        cx,
                    ))
                    .child(panel_button(
                        "[監査]",
                        Panel::Audit,
                        self.panel,
                        |this, cx| {
                            this.panel = Panel::Audit;
                            cx.notify();
                        },
                        cx,
                    ))
                    .child(panel_button(
                        "[生成]",
                        Panel::Generator,
                        self.panel,
                        |this, cx| {
                            this.panel = Panel::Generator;
                            cx.notify();
                        },
                        cx,
                    ))
                    .child(panel_button(
                        "[設定]",
                        Panel::Settings,
                        self.panel,
                        |this, cx| {
                            this.panel = Panel::Settings;
                            cx.notify();
                        },
                        cx,
                    ))
                    .into_any_element()
            } else {
                div()
                    .text_xs()
                    .text_color(rgb(0x6c7086))
                    .child("gpui-kit 0.9.1 + model::Vault")
                    .into_any_element()
            });

        let body = match self.screen {
            Screen::Locked => div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(self.render_locked(cx))
                .into_any_element(),
            Screen::Unlocked if self.panel == Panel::Audit => match &self.audit_report {
                Some(report) => audit_panel(report).into_any_element(),
                None => self.render_unlocked(cx).into_any_element(),
            },
            Screen::Unlocked if self.panel == Panel::Generator => {
                generator_panel(&self.generator).into_any_element()
            }
            Screen::Unlocked if self.panel == Panel::Settings => {
                settings_panel(&self.settings, &self.server_url, &self.email, self.editing)
                    .into_any_element()
            }
            Screen::Unlocked => self.render_unlocked(cx).into_any_element(),
        };

        let status = div()
            .px_4()
            .py_2()
            .bg(rgb(0x181825))
            .border_t_1()
            .border_color(rgb(0x313244))
            .text_xs()
            .text_color(rgb(0xa6adc8))
            .child(self.status.clone());

        div()
            .id("bitwarden-poc-root")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
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
