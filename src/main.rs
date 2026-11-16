//! Bitwarden/Vaultwarden client PoC built with GPUI (`gpui-kit`).
//!
//! The UI renders a [`Vault`] from the library crate: filtering, sorting and
//! searching all go through [`Vault::view`], so the same logic is exercised by
//! both the window and the tests. Login/sync/decrypt through `openwarden` are
//! still planned.

#![forbid(unsafe_code)]

use bitwarden_gpui_poc::generator::{
    passphrase_entropy, password_entropy, PassphraseSettings, PasswordSettings, Strength,
};
use bitwarden_gpui_poc::health::{audit, Report, Severity};
use bitwarden_gpui_poc::model::{
    CardData, Filter, Folder, IdentityData, ItemData, ItemKind, LoginUri, SortKey, SshKeyData,
    Vault, VaultItem,
};
use bitwarden_gpui_poc::settings::Settings;
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

    let mut card = VaultItem::new(
        "5",
        "Visa",
        ItemData::Card(CardData {
            cardholder_name: "Alice Example".into(),
            brand: "Visa".into(),
            number: "4111 1111 1111 1234".into(),
            exp_month: "12".into(),
            exp_year: "2030".into(),
            code: "123".into(),
        }),
    );
    card.revision_date = 1_700_000_400;

    let mut identity = VaultItem::new(
        "6",
        "Personal Info",
        ItemData::Identity(IdentityData {
            first_name: "Alice".into(),
            last_name: "Example".into(),
            email: "alice@example.com".into(),
            phone: "+81-90-1234-5678".into(),
            address: "Tokyo".into(),
            company: "Example Corp".into(),
        }),
    );
    identity.revision_date = 1_700_000_500;

    let mut ssh_key = VaultItem::new(
        "7",
        "Laptop Key",
        ItemData::SshKey(SshKeyData {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@laptop".into(),
            private_key: String::new(),
            fingerprint: "SHA256:examplefingerprint".into(),
        }),
    );
    ssh_key.revision_date = 1_700_000_600;

    vault.items = vec![github, vaultwarden, mail, note, card, identity, ssh_key];
    vault
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Locked,
    Unlocked,
}

/// Which panel occupies the main area while unlocked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Panel {
    Vault,
    Audit,
    Generator,
    Settings,
}

/// A text field being edited in the settings panel.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsField {
    ServerUrl,
    Email,
}

/// Editable generator settings and the last values drawn from them.
#[derive(Clone, Debug, Default)]
struct GeneratorState {
    password: PasswordSettings,
    passphrase: PassphraseSettings,
    last_password: Option<String>,
    last_passphrase: Option<String>,
}

impl GeneratorState {
    fn from_settings(settings: &Settings) -> Self {
        Self {
            password: settings.password_generator.clone(),
            passphrase: settings.passphrase_generator.clone(),
            last_password: None,
            last_passphrase: None,
        }
    }
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
    audit_report: Option<Report>,
    panel: Panel,
    generator: GeneratorState,
    settings: Settings,
    editing: Option<SettingsField>,
    scroll_handle: UniformListScrollHandle,
    focus_handle: FocusHandle,
}

impl BitwardenApp {
    fn new(cx: &mut Context<Self>) -> Self {
        let settings = Settings::load(Settings::default_path().unwrap_or_default());
        let mut this = Self {
            screen: Screen::Locked,
            server_url: settings.server_url.clone(),
            email: settings.email.clone(),
            status: "ロック中: Enter でモック vault を開く / Esc で終了".to_string(),
            vault: Vault::new(),
            filter: Filter::All,
            query: String::new(),
            sort: SortKey::NameAsc,
            searching: false,
            selected: 0,
            totp_secret: String::new(),
            totp_tick: None,
            audit_report: None,
            panel: Panel::Vault,
            generator: GeneratorState::from_settings(&settings),
            settings,
            editing: None,
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
                                if view.screen == Screen::Unlocked
                                    && view.panel == Panel::Vault
                                    && !view.totp_secret.is_empty()
                                {
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
        self.generator = GeneratorState::from_settings(&self.settings);
        self.refresh_audit();
        self.panel = Panel::Vault;
        self.screen = Screen::Unlocked;
        self.selected = 0;
        self.scroll_handle.scroll_to_item(0, ScrollStrategy::Top);
        self.status = format!(
            "同期済み（モック）: {} 件。↑↓選択 / f お気に入り / t フィルタ / s 並び順 / / 検索 / g 監査 / n 生成 / c 設定 / l ロック / Esc 終了",
            self.vault.len()
        );
        cx.notify();
    }

    fn lock(&mut self, cx: &mut Context<Self>) {
        self.vault = Vault::new();
        self.audit_report = None;
        self.panel = Panel::Vault;
        self.generator = GeneratorState::from_settings(&self.settings);
        self.editing = None;
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

    /// Copy editable UI state back into the persistent settings object.
    fn sync_settings_from_ui(&mut self) {
        self.settings.server_url = self.server_url.clone();
        self.settings.email = self.email.clone();
        self.settings.password_generator = self.generator.password.clone();
        self.settings.passphrase_generator = self.generator.passphrase.clone();
    }

    fn save_settings(&mut self, cx: &mut Context<Self>) {
        self.sync_settings_from_ui();
        match Settings::default_path() {
            Some(path) => match self.settings.save(&path) {
                Ok(()) => self.status = format!("設定を保存しました: {}", path.display()),
                Err(error) => self.status = format!("設定の保存に失敗: {error}"),
            },
            None => self.status = "設定ディレクトリを特定できません".to_string(),
        }
        cx.notify();
    }

    fn refresh_audit(&mut self) {
        self.audit_report = Some(audit(
            &self.vault,
            self.settings.thresholds,
            i64::try_from(totp::now_unix()).unwrap_or(i64::MAX),
        ));
    }

    fn push_editing(&mut self, character: char) {
        match self.editing {
            Some(SettingsField::ServerUrl) => self.settings.server_url.push(character),
            Some(SettingsField::Email) => self.settings.email.push(character),
            None => {}
        }
    }

    fn pop_editing(&mut self) {
        match self.editing {
            Some(SettingsField::ServerUrl) => {
                self.settings.server_url.pop();
            }
            Some(SettingsField::Email) => {
                self.settings.email.pop();
            }
            None => {}
        }
    }

    fn generate_password(&mut self, cx: &mut Context<Self>) {
        match self.generator.password.generate() {
            Ok(value) => {
                self.generator.last_password = Some(value);
                self.status = "パスワードを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    fn generate_passphrase(&mut self, cx: &mut Context<Self>) {
        match self.generator.passphrase.generate() {
            Ok(value) => {
                self.generator.last_passphrase = Some(value);
                self.status = "パスフレーズを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    fn toggle_generator(&mut self, key: &str, cx: &mut Context<Self>) {
        let state = &mut self.generator;
        match key {
            "1" => state.password.lowercase = !state.password.lowercase,
            "2" => state.password.uppercase = !state.password.uppercase,
            "3" => state.password.digits = !state.password.digits,
            "4" => state.password.symbols = !state.password.symbols,
            "5" => state.password.avoid_ambiguous = !state.password.avoid_ambiguous,
            "6" => state.passphrase.capitalize = !state.passphrase.capitalize,
            "7" => state.passphrase.include_number = !state.passphrase.include_number,
            "+" | "=" => {
                state.password.length = (state.password.length + 1).min(128);
                state.passphrase.words = (state.passphrase.words + 1).min(20);
            }
            "-" | "_" => {
                state.password.length = state.password.length.saturating_sub(1).max(4);
                state.passphrase.words = state.passphrase.words.saturating_sub(1).max(2);
            }
            "," => {
                state.passphrase.separator = match state.passphrase.separator.as_str() {
                    "-" => ".".into(),
                    "." => "_".into(),
                    "_" => String::new(),
                    _ => "-".into(),
                };
            }
            _ => return,
        }
        cx.notify();
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
                if self.panel == Panel::Audit {
                    match key {
                        "escape" => cx.quit(),
                        "g" => {
                            self.panel = Panel::Vault;
                            cx.notify();
                        }
                        "l" => self.lock(cx),
                        _ => {}
                    }
                    return;
                }
                if self.panel == Panel::Generator {
                    match key {
                        "escape" => cx.quit(),
                        "n" => {
                            self.panel = Panel::Vault;
                            cx.notify();
                        }
                        "l" => self.lock(cx),
                        "p" => self.generate_password(cx),
                        "h" => self.generate_passphrase(cx),
                        value => self.toggle_generator(value, cx),
                    }
                    return;
                }
                if self.panel == Panel::Settings {
                    if self.editing.is_some() {
                        match key {
                            "escape" | "enter" => {
                                self.editing = None;
                                self.sync_settings_from_ui();
                                cx.notify();
                            }
                            "backspace" => {
                                self.pop_editing();
                                cx.notify();
                            }
                            value if value.chars().count() == 1 => {
                                if let Some(character) = value.chars().next() {
                                    self.push_editing(character);
                                    cx.notify();
                                }
                            }
                            _ => {}
                        }
                        return;
                    }
                    match key {
                        "escape" => cx.quit(),
                        "c" => {
                            self.panel = Panel::Vault;
                            cx.notify();
                        }
                        "l" => self.lock(cx),
                        "1" => {
                            self.editing = Some(SettingsField::ServerUrl);
                            cx.notify();
                        }
                        "2" => {
                            self.editing = Some(SettingsField::Email);
                            cx.notify();
                        }
                        "+" | "=" => {
                            let thresholds = &mut self.settings.thresholds;
                            thresholds.weak_bits = (thresholds.weak_bits + 5).min(200);
                            thresholds.stale_days = (thresholds.stale_days + 30).min(3650);
                            self.refresh_audit();
                            cx.notify();
                        }
                        "-" | "_" => {
                            let thresholds = &mut self.settings.thresholds;
                            thresholds.weak_bits = thresholds.weak_bits.saturating_sub(5);
                            thresholds.stale_days = thresholds.stale_days.saturating_sub(30).max(1);
                            self.refresh_audit();
                            cx.notify();
                        }
                        "w" => self.save_settings(cx),
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
                    "g" if self.audit_report.is_some() => {
                        self.panel = Panel::Audit;
                        cx.notify();
                    }
                    "n" => {
                        self.panel = Panel::Generator;
                        cx.notify();
                    }
                    "c" => {
                        self.panel = Panel::Settings;
                        cx.notify();
                    }
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

fn audit_panel<'a>(report: &'a Report) -> impl IntoElement + 'a {
    let mut panel = div()
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
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
        .child(div().text_xs().text_color(rgb(0x6c7086)).child(format!(
            "TOTP 設定済み: {}/{} ({:.0}%)",
            report.with_totp,
            report.logins,
            report.totp_coverage() * 100.0
        )));
    for item in &report.items {
        let color = match item.worst() {
            Some(Severity::High) => rgb(0xf38ba8),
            Some(Severity::Medium) => rgb(0xf9e2af),
            _ => rgb(0xa6adc8),
        };
        panel = panel.child(
            div()
                .mt_2()
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(color)
                        .child(format!(
                            "[{}] {} ({})",
                            item.worst().map_or("?", Severity::label),
                            item.name,
                            item.kind.label()
                        )),
                )
                .children(item.findings.iter().map(|finding| {
                    div()
                        .text_xs()
                        .pl_4()
                        .text_color(rgb(0xcdd6f4))
                        .child(format!("- {}", finding.message()))
                })),
        );
    }
    panel
}

fn setting_row<'a>(label: &'a str, enabled: bool) -> impl IntoElement + 'a {
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
                    rgb(0x6c7086)
                })
                .child(if enabled { "ON" } else { "OFF" }),
        )
}

fn result_row<'a>(label: &'a str, value: Option<&'a str>) -> impl IntoElement + 'a {
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

fn generator_panel<'a>(state: &'a GeneratorState) -> impl IntoElement + 'a {
    let password = &state.password;
    let passphrase = &state.passphrase;
    let pw_bits = password_entropy(password);
    let pp_bits = passphrase_entropy(passphrase);
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
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
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "+/-  長さ: {}  |  強度: {} ({:.0} bit)",
            password.length,
            Strength::from_bits(pw_bits).label(),
            pw_bits
        )))
        .child(result_row("p  生成", state.last_password.as_deref()))
        .child(
            div()
                .mt_4()
                .text_lg()
                .font_weight(FontWeight::BOLD)
                .child("パスフレーズ生成"),
        )
        .child(setting_row("6  先頭を大文字に", passphrase.capitalize))
        .child(setting_row("7  数字を追加", passphrase.include_number))
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "+/-  単語数: {}  |  ,  区切り: {:?}  |  強度: {} ({:.0} bit)",
            passphrase.words,
            passphrase.separator,
            Strength::from_bits(pp_bits).label(),
            pp_bits
        )))
        .child(result_row("h  生成", state.last_passphrase.as_deref()))
        .child(
            div()
                .mt_4()
                .text_xs()
                .text_color(rgb(0x6c7086))
                .child("n: 一覧に戻る / l: ロック / Esc: 終了"),
        )
}

fn field_row<'a>(label: &'a str, value: &'a str, editing: bool) -> impl IntoElement + 'a {
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

fn settings_panel<'a>(app: &'a BitwardenApp) -> impl IntoElement + 'a {
    let settings = &app.settings;
    let path = Settings::default_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(設定ディレクトリを特定できません)".to_string());
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
        .child(div().text_lg().font_weight(FontWeight::BOLD).child("設定"))
        .child(field_row(
            "1  サーバー URL",
            &settings.server_url,
            app.editing == Some(SettingsField::ServerUrl),
        ))
        .child(field_row(
            "2  メール",
            &settings.email,
            app.editing == Some(SettingsField::Email),
        ))
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "生成設定: パスワード {} 文字 / パスフレーズ {} 語（n キーで編集）",
            settings.password_generator.length, settings.passphrase_generator.words
        )))
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "監査閾値: 弱パスワード < {} bit / 更新が古い: {} 日以上",
            settings.thresholds.weak_bits, settings.thresholds.stale_days
        )))
        .child(
            div()
                .text_xs()
                .text_color(rgb(0x6c7086))
                .child(format!("保存先: {path}")),
        )
        .child(div().mt_4().text_xs().text_color(rgb(0x6c7086)).child(
            "1,2: 編集 / enter: 確定 / +/-: 閾値調整 / w: 保存 / c: 戻る / l: ロック / Esc: 終了",
        ))
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
            Screen::Unlocked if self.panel == Panel::Audit => match &self.audit_report {
                Some(report) => audit_panel(report).into_any_element(),
                None => self.render_unlocked(cx).into_any_element(),
            },
            Screen::Unlocked if self.panel == Panel::Generator => {
                generator_panel(&self.generator).into_any_element()
            }
            Screen::Unlocked if self.panel == Panel::Settings => {
                settings_panel(self).into_any_element()
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
