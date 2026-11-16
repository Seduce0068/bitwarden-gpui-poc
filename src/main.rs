//! Bitwarden/Vaultwarden client PoC built with GPUI (`gpui-kit`).
//!
//! The UI renders a [`Vault`] from the library crate: filtering, sorting and
//! searching all go through [`Vault::view`], so the same logic is exercised by
//! both the window and the tests. Login/sync/decrypt through `openwarden` are
//! still planned.

#![forbid(unsafe_code)]

use bitwarden_gpui_poc::model::{
    Filter, Folder, ItemData, ItemKind, LoginUri, SortKey, Vault, VaultItem,
};
use bitwarden_gpui_poc::totp::{self, Tick};
use gpui_kit::prelude::*;
use gpui_kit::*;

/// A small personal vault used until real sync is wired up.
fn mock_vault() -> Vault {
    fn login(
        id: &str,
        name: &str,
        username: &str,
        password: &str,
        uri: &str,
        totp: &str,
    ) -> VaultItem {
        VaultItem::new(
            id,
            name,
            ItemData::Login {
                username: username.to_string(),
                password: password.to_string(),
                totp: totp.to_string(),
                uris: vec![LoginUri::new(uri)],
            },
        )
    }

    let mut vault = Vault::new();
    vault.folders.push(Folder {
        id: "work".into(),
        name: "仕事".into(),
    });

    let mut github = login(
        "1",
        "GitHub",
        "alice@example.com",
        "hunter2",
        "https://github.com/login",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    );
    github.folder_id = Some("work".into());
    github.favorite = true;
    github.revision_date = 1_700_000_100;

    let mut vaultwarden = login(
        "2",
        "Vaultwarden",
        "alice",
        "vT7#kQm2!zR9wP4$xL8@",
        "https://vault.example.com",
        "",
    );
    vaultwarden.folder_id = Some("work".into());
    vaultwarden.revision_date = 1_700_000_200;

    let mut mail = login(
        "3",
        "Email",
        "alice@example.com",
        "1234",
        "http://mail.example.com",
        "",
    );
    mail.revision_date = 1_600_000_000;

    let mut note = VaultItem::new(
        "4",
        "Wi-Fi",
        ItemData::SecureNote {
            text: "guest / guest".into(),
        },
    );
    note.revision_date = 1_700_000_300;

    vault.items = vec![github, vaultwarden, mail, note];
    vault
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
    vault: Vault,
    filter: Filter,
    query: String,
    sort: SortKey,
    searching: bool,
    selected: usize,
    totp_secret: String,
    totp_tick: Option<Tick>,
    scroll_handle: UniformListScrollHandle,
    focus_handle: FocusHandle,
}

impl BitwardenApp {
    fn new(cx: &mut Context<Self>) -> Self {
        let mut this = Self {
            screen: Screen::Locked,
            server_url: "https://vault.bitwarden.com".to_string(),
            email: String::new(),
            status: "ロック中: Enter でモック vault を開く / Esc で終了".to_string(),
            vault: Vault::new(),
            filter: Filter::All,
            query: String::new(),
            sort: SortKey::NameAsc,
            searching: false,
            selected: 0,
            totp_secret: String::new(),
            totp_tick: None,
            scroll_handle: UniformListScrollHandle::new(),
            focus_handle: cx.focus_handle(),
        };
        this.start_totp_ticker(cx);
        this
    }

    /// Invalidate the cached TOTP snapshot once a second so the countdown
    /// advances. The task ends when the view is dropped.
    fn start_totp_ticker(&mut self, cx: &mut Context<Self>) {
        cx.spawn(
            |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    loop {
                        smol::Timer::after(std::time::Duration::from_secs(1)).await;
                        let alive = cx.update(|cx| {
                            this.update(cx, |view, cx| {
                                if view.screen == Screen::Unlocked && !view.totp_secret.is_empty() {
                                    view.totp_tick = None;
                                    cx.notify();
                                }
                            })
                            .is_ok()
                        });
                        if !alive {
                            break;
                        }
                    }
                }
            },
        )
        .detach();
    }

    /// The current view, computed by the library exactly as the tests see it.
    fn visible_items(&self) -> Vec<&VaultItem> {
        self.vault.view(&self.filter, &self.query, self.sort)
    }

    fn unlock_mock(&mut self, cx: &mut Context<Self>) {
        self.vault = mock_vault();
        self.screen = Screen::Unlocked;
        self.selected = 0;
        self.scroll_handle.scroll_to_item(0, ScrollStrategy::Top);
        self.status = format!(
            "同期済み（モック）: {} 件。↑↓選択 / f お気に入り / t フィルタ / s 並び順 / / 検索 / l ロック / Esc 終了",
            self.vault.len()
        );
        cx.notify();
    }

    fn lock(&mut self, cx: &mut Context<Self>) {
        self.vault = Vault::new();
        self.totp_secret.clear();
        self.totp_tick = None;
        self.query.clear();
        self.filter = Filter::All;
        self.sort = SortKey::NameAsc;
        self.searching = false;
        self.selected = 0;
        self.screen = Screen::Locked;
        self.status = "ロックしました（Enter でモック解除）".to_string();
        cx.notify();
    }

    fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        let count = self.visible_items().len();
        if count == 0 {
            return;
        }
        let len = count as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1) as usize;
        if self.selected != next {
            self.selected = next;
            self.scroll_handle
                .scroll_to_item(next, ScrollStrategy::Nearest);
            cx.notify();
        }
    }

    fn cycle_filter(&mut self, cx: &mut Context<Self>) {
        self.filter = match self.filter {
            Filter::All => Filter::Favorites,
            Filter::Favorites => Filter::Kind(ItemKind::Login),
            Filter::Kind(ItemKind::Login) => Filter::Kind(ItemKind::SecureNote),
            Filter::Kind(ItemKind::SecureNote) => Filter::Kind(ItemKind::Card),
            Filter::Kind(ItemKind::Card) => Filter::Kind(ItemKind::Identity),
            Filter::Kind(ItemKind::Identity) => Filter::Kind(ItemKind::SshKey),
            Filter::Kind(ItemKind::SshKey) => Filter::NoFolder,
            Filter::NoFolder | Filter::Folder(_) => Filter::All,
        };
        self.selected = 0;
        self.scroll_handle.scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self
            .visible_items()
            .get(self.selected)
            .map(|item| item.id.clone())
        else {
            return;
        };
        if let Some(favorite) = self.vault.toggle_favorite(&id) {
            self.status = format!(
                "お気に入りを{}にしました",
                if favorite { "設定" } else { "解除" }
            );
            cx.notify();
        }
    }

    /// The current TOTP code for `secret`, cached within its validity period.
    fn totp_text(&mut self, secret: &str) -> String {
        let now = totp::now_unix();
        let refresh = self.totp_secret != secret
            || self
                .totp_tick
                .as_ref()
                .is_none_or(|tick| !tick.is_fresh(now));
        if refresh {
            self.totp_secret = secret.to_string();
            self.totp_tick = Some(Tick::sample(secret, now));
        }
        match self.totp_tick.as_ref().and_then(|tick| tick.code.as_ref()) {
            Some(code) => format!("{} (あと{}秒)", code.grouped(), code.remaining()),
            None => "コード生成失敗".to_string(),
        }
    }

    fn selected_detail(&mut self) -> String {
        let Some((base, data)) = (|| {
            let visible = self.visible_items();
            let item = visible.get(self.selected.min(visible.len().saturating_sub(1)))?;
            Some((
                format!(
                    "{} | {} | 更新: {}",
                    item.kind().label(),
                    item.name,
                    item.revision_date
                ),
                item.data.clone(),
            ))
        })() else {
            return "項目なし".to_string();
        };
        match data {
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
                format!(
                    "{base} | {username} | パスワード: {}文字 | TOTP: {code} | URI: {}",
                    "*".repeat(password.chars().count()),
                    uris.first().map_or("なし".into(), |uri| uri.uri.clone())
                )
            }
            ItemData::SecureNote { text } => {
                format!("{base} | メモ: {}文字", text.chars().count())
            }
            ItemData::Card(card) => format!(
                "{base} | {} | 末尾: {}",
                card.brand,
                card.number.rsplit(' ').next().unwrap_or("")
            ),
            ItemData::Identity(identity) => format!("{base} | {}", identity.email),
            ItemData::SshKey(key) => format!("{base} | {}", key.fingerprint),
        }
    }

    fn key_down(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        match self.screen {
            Screen::Locked => match event.keystroke.key.as_str() {
                "escape" => cx.quit(),
                "enter" => self.unlock_mock(cx),
                _ => {}
            },
            Screen::Unlocked => {
                let key = event.keystroke.key.as_str();
                if self.searching {
                    match key {
                        "escape" | "enter" => {
                            self.searching = false;
                            cx.notify();
                        }
                        "backspace" => {
                            self.query.pop();
                            self.selected = 0;
                            cx.notify();
                        }
                        value if value.chars().count() == 1 => {
                            self.query.push_str(value);
                            self.selected = 0;
                            cx.notify();
                        }
                        _ => {}
                    }
                    return;
                }
                match key {
                    "escape" => cx.quit(),
                    "up" => self.move_selection(-1, cx),
                    "down" => self.move_selection(1, cx),
                    "l" => self.lock(cx),
                    "t" => self.cycle_filter(cx),
                    "s" => {
                        self.sort = self.sort.next();
                        self.selected = 0;
                        cx.notify();
                    }
                    "f" => self.toggle_favorite(cx),
                    "/" => {
                        self.searching = true;
                        self.query.clear();
                        self.selected = 0;
                        cx.notify();
                    }
                    "backspace" if !self.query.is_empty() => {
                        self.query.pop();
                        self.selected = 0;
                        cx.notify();
                    }
                    _ => {}
                }
            }
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

    fn render_unlocked(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let count = self.visible_items().len();
        let detail = self.selected_detail();

        let list = uniform_list(
            "vault-items",
            count,
            cx.processor(
                move |this: &mut Self, range: std::ops::Range<usize>, _window, _cx| {
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
                    .child("gpui-kit 0.9.1 + model::Vault"),
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
