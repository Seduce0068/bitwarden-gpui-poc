//! Bitwarden/Vaultwarden client PoC built with GPUI (`gpui-kit`).
//!
//! This is a UI skeleton demonstrating how a personal-vault Bitwarden client
//! could be structured with GPUI. It currently uses mock data; wiring to the
//! [`openwarden`] crate (login, unlock, sync, decrypt) is planned.

#![forbid(unsafe_code)]

use gpui_kit::prelude::*;
use gpui_kit::*;

#[derive(Clone, Debug)]
struct VaultItem {
    name: String,
    username: String,
    uri: String,
    totp: bool,
}

fn mock_items() -> Vec<VaultItem> {
    vec![
        VaultItem {
            name: "GitHub".to_string(),
            username: "alice@example.com".to_string(),
            uri: "https://github.com/login".to_string(),
            totp: true,
        },
        VaultItem {
            name: "Vaultwarden".to_string(),
            username: "alice".to_string(),
            uri: "https://vault.example.com".to_string(),
            totp: true,
        },
        VaultItem {
            name: "Email".to_string(),
            username: "alice@example.com".to_string(),
            uri: "https://mail.example.com".to_string(),
            totp: false,
        },
        VaultItem {
            name: "Example Service".to_string(),
            username: "alice".to_string(),
            uri: "https://example.com".to_string(),
            totp: false,
        },
    ]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Locked,
    Unlocked,
}

struct BitwardenApp {
    screen: Screen,
    server_url: String,
    email: String,
    status: String,
    items: Vec<VaultItem>,
    selected: usize,
    filter: String,
    scroll_handle: UniformListScrollHandle,
    focus_handle: FocusHandle,
}

impl BitwardenApp {
    fn new(cx: &mut Context<Self>) -> Self {
        Self {
            screen: Screen::Locked,
            server_url: "https://vault.bitwarden.com".to_string(),
            email: String::new(),
            status: "ロック中: API キーまたはマスターパスワードで解除（PoC: Enter でモック解除）"
                .to_string(),
            items: Vec::new(),
            selected: 0,
            filter: String::new(),
            scroll_handle: UniformListScrollHandle::new(),
            focus_handle: cx.focus_handle(),
        }
    }

    fn unlock_mock(&mut self, cx: &mut Context<Self>) {
        self.items = mock_items();
        self.screen = Screen::Unlocked;
        self.selected = 0;
        self.scroll_handle.scroll_to_item(0, ScrollStrategy::Top);
        self.status = format!(
            "同期済み（モック）: {} 件。↑↓で選択、Lでロック、Escで終了",
            self.items.len()
        );
        cx.notify();
    }

    fn lock(&mut self, cx: &mut Context<Self>) {
        self.items.clear();
        self.selected = 0;
        self.screen = Screen::Locked;
        self.status = "ロックしました（PoC: Enter でモック解除）".to_string();
        cx.notify();
    }

    fn filtered_items(&self) -> Vec<VaultItem> {
        if self.filter.is_empty() {
            return self.items.clone();
        }
        let needle = self.filter.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.name.to_lowercase().contains(&needle)
                    || item.username.to_lowercase().contains(&needle)
                    || item.uri.to_lowercase().contains(&needle)
            })
            .cloned()
            .collect()
    }

    fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        let visible = self.filtered_items();
        if visible.is_empty() {
            return;
        }
        let len = visible.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1) as usize;
        if self.selected != next {
            self.selected = next;
            self.scroll_handle
                .scroll_to_item(next, ScrollStrategy::Nearest);
            cx.notify();
        }
    }

    fn key_down(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        match self.screen {
            Screen::Locked => match event.keystroke.key.as_str() {
                "escape" => cx.quit(),
                "enter" => self.unlock_mock(cx),
                _ => {}
            },
            Screen::Unlocked => match event.keystroke.key.as_str() {
                "escape" => cx.quit(),
                "up" => self.move_selection(-1, cx),
                "down" => self.move_selection(1, cx),
                "l" => self.lock(cx),
                _ => {}
            },
        }
    }

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
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(0xa6adc8))
                    .child("個人 vault クライアントの UI スケルトン。openwarden による実ログイン/同期は未接続です。"),
            )
            .child(info_row("Server", &self.server_url))
            .child(info_row(
                "Email",
                if self.email.is_empty() {
                    "(未入力)"
                } else {
                    &self.email
                },
            ))
            .child(info_row("Auth", "Personal API key / master password (planned)"))
            .child(
                div()
                    .mt_2()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(0x313244))
                    .text_sm()
                    .child("Enter: モック vault を開く / Esc: 終了"),
            )
    }

    fn render_unlocked(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let visible = self.filtered_items();
        let count = visible.len();
        let selected_detail = visible
            .get(self.selected.min(count.saturating_sub(1)))
            .map(|item| {
                format!(
                    "{}  |  {}  |  {}{}",
                    item.name,
                    item.username,
                    item.uri,
                    if item.totp { "  [TOTP]" } else { "" }
                )
            })
            .unwrap_or_else(|| "項目なし".to_string());

        let list = uniform_list(
            "vault-items",
            count,
            cx.processor(
                move |this: &mut Self, range: std::ops::Range<usize>, _window, _cx| {
                    let visible = this.filtered_items();
                    let mut rows = Vec::with_capacity(range.len());
                    for index in range {
                        let Some(item) = visible.get(index).cloned() else {
                            continue;
                        };
                        let selected = this.selected == index;
                        let row_bg = if selected {
                            rgb(0x45475a)
                        } else {
                            rgb(0x1e1e2e)
                        };
                        rows.push(
                            div()
                                .id(index)
                                .flex()
                                .items_center()
                                .gap_3()
                                .px_3()
                                .h(px(30.0))
                                .bg(row_bg)
                                .text_sm()
                                .child(
                                    div()
                                        .flex_1()
                                        .overflow_hidden()
                                        .font_weight(FontWeight::MEDIUM)
                                        .child(item.name.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(220.0))
                                        .overflow_hidden()
                                        .text_color(rgb(0xa6adc8))
                                        .child(item.username.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(56.0))
                                        .text_xs()
                                        .text_color(if item.totp {
                                            rgb(0xa6e3a1)
                                        } else {
                                            rgb(0x6c7086)
                                        })
                                        .child(if item.totp { "TOTP" } else { "" }),
                                ),
                        );
                    }
                    rows
                },
            ),
        )
        .track_scroll(&self.scroll_handle)
        .flex_1();

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
                        "Vault: {} 件表示（モック）  |  Filter: {}",
                        count,
                        if self.filter.is_empty() {
                            "(なし)"
                        } else {
                            &self.filter
                        }
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
                    .child(selected_detail),
            )
    }
}

fn info_row(label: &str, value: &str) -> impl IntoElement {
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(90.0))
                .text_color(rgb(0x6c7086))
                .child(label.to_string()),
        )
        .child(div().flex_1().child(value.to_string()))
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
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(0x6c7086))
                    .child("gpui-kit 0.9.1 + openwarden 0.1 (planned)"),
            );

        let body = match self.screen {
            Screen::Locked => div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .child(self.render_locked(cx))
                .into_any_element(),
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

fn main() {
    let app = gpui_kit::application();
    app.run(|cx: &mut App| {
        gpui_kit::init(cx);

        cx.on_window_closed(|cx, _window_id| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let bounds = Bounds::centered(None, size(px(980.0), px(640.0)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("Bitwarden GPUI PoC".into()),
                ..Default::default()
            }),
            focus: true,
            show: true,
            app_id: Some("bitwarden-gpui-poc".to_string()),
            ..Default::default()
        };

        if gpui_kit::open_window(options, cx, |window, cx| {
            let view = cx.new(BitwardenApp::new);
            let focus_handle = view.read(cx).focus_handle.clone();
            focus_handle.focus(window, cx);
            view
        })
        .is_err()
        {
            eprintln!("ウィンドウを開けませんでした");
            return;
        }

        cx.activate(true);
    });
}
