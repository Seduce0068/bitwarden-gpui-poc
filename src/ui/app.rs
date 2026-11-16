//! The main application state and GPUI wiring.

use crate::health::{audit, Report};
use crate::model::{
    CardData, Filter, Folder, IdentityData, ItemData, ItemKind, LoginUri, SortKey, SshKeyData,
    Vault, VaultItem,
};
use crate::settings::Settings;
use crate::totp::{self, Tick};
use crate::ui::model::{AuthField, GeneratorState, Panel, Screen, SettingsField};
use gpui_kit::prelude::*;
use gpui_kit::*;

/// Seconds before a copied secret is restored to the previous clipboard value.
const CLIPBOARD_CLEAR_SECONDS: u64 = 30;

/// A small personal vault used until real sync is wired up.
pub(super) fn mock_vault() -> Vault {
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

pub struct BitwardenApp {
    pub(super) screen: Screen,
    pub(super) server_url: String,
    pub(super) email: String,
    pub(super) status: String,
    pub(super) vault: Vault,
    pub(super) filter: Filter,
    pub(super) query: String,
    pub(super) sort: SortKey,
    pub(super) searching: bool,
    pub(super) selected: usize,
    pub(super) totp_secret: String,
    pub(super) totp_tick: Option<Tick>,
    pub(super) audit_report: Option<Report>,
    pub(super) panel: Panel,
    pub(super) generator: GeneratorState,
    pub(super) settings: Settings,
    pub(super) editing: Option<SettingsField>,
    pub(super) auth_field: Option<AuthField>,
    pub(super) client_id: String,
    pub(super) client_secret: String,
    pub(super) master_password: String,
    pub(super) clipboard_restore: Option<String>,
    pub(super) clipboard_clear_at: Option<u64>,
    pub(super) login_failed: bool,
    pub(super) scroll_handle: UniformListScrollHandle,
    pub focus_handle: FocusHandle,
}

impl BitwardenApp {
    pub fn new(cx: &mut Context<Self>) -> Self {
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
            auth_field: None,
            client_id: String::new(),
            client_secret: String::new(),
            master_password: String::new(),
            clipboard_restore: None,
            clipboard_clear_at: None,
            login_failed: false,
            scroll_handle: UniformListScrollHandle::new(),
            focus_handle: cx.focus_handle(),
        };
        this.start_totp_ticker(cx);
        this
    }

    /// Invalidate the cached TOTP snapshot once a second so the countdown
    /// advances. The task ends when the view is dropped.
    pub(super) fn start_totp_ticker(&mut self, cx: &mut Context<Self>) {
        cx.spawn(
            |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    loop {
                        smol::Timer::after(std::time::Duration::from_secs(1)).await;
                        let alive = cx.update(|cx| {
                            this.update(cx, |view, cx| {
                                let now = totp::now_unix();
                                if view
                                    .clipboard_clear_at
                                    .is_some_and(|deadline| now >= deadline)
                                {
                                    view.restore_clipboard(cx);
                                    cx.notify();
                                }
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
    pub(super) fn visible_items(&self) -> Vec<&VaultItem> {
        self.vault.view(&self.filter, &self.query, self.sort)
    }

    /// Build an [`AuthConfig`] from the current lock-screen fields.
    pub(super) fn lock(&mut self, cx: &mut Context<Self>) {
        self.restore_clipboard(cx);
        self.vault = Vault::new();
        self.audit_report = None;
        self.panel = Panel::Vault;
        self.generator = GeneratorState::from_settings(&self.settings);
        self.editing = None;
        self.auth_field = None;
        self.login_failed = false;
        self.client_secret.clear();
        self.master_password.clear();
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

    pub(super) fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
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

    pub(super) fn cycle_filter(&mut self, cx: &mut Context<Self>) {
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

    pub(super) fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
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
    pub(super) fn totp_text(&mut self, secret: &str) -> String {
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

    pub(super) fn selected_detail(&mut self) -> String {
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

    /// Copy the selected item's current TOTP code, if it has one.
    pub(super) fn copy_totp(&mut self, cx: &mut Context<Self>) {
        let secret = {
            let visible = self.visible_items();
            let Some(item) = visible.get(self.selected.min(visible.len().saturating_sub(1))) else {
                self.status = "項目が選択されていません".to_string();
                cx.notify();
                return;
            };
            item.totp_secret().unwrap_or("").to_string()
        };
        if secret.trim().is_empty() {
            self.status = "この項目には TOTP が設定されていません".to_string();
            cx.notify();
            return;
        }
        match totp::code_at(&secret, totp::now_unix()) {
            Ok(code) => self.copy_to_clipboard(code.code(), cx),
            Err(error) => {
                self.status = error.message().to_string();
                cx.notify();
            }
        }
    }

    /// Copy editable UI state back into the persistent settings object.
    pub(super) fn sync_settings_from_ui(&mut self) {
        self.settings.server_url = self.server_url.clone();
        self.settings.email = self.email.clone();
        self.settings.password_generator = self.generator.password.clone();
        self.settings.passphrase_generator = self.generator.passphrase.clone();
    }

    pub(super) fn save_settings(&mut self, cx: &mut Context<Self>) {
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

    /// Copy `value` to the clipboard, remembering the previous text so it can
    /// be restored automatically after [`CLIPBOARD_CLEAR_SECONDS`] seconds.
    pub(super) fn copy_to_clipboard(&mut self, value: &str, cx: &mut Context<Self>) {
        if self.clipboard_clear_at.is_none() {
            self.clipboard_restore = cx.read_from_clipboard().and_then(|item| {
                item.entries.into_iter().find_map(|entry| match entry {
                    ClipboardEntry::String(text) => Some(text.text),
                    _ => None,
                })
            });
        }
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        self.clipboard_clear_at = Some(totp::now_unix() + CLIPBOARD_CLEAR_SECONDS);
        self.status =
            format!("クリップボードにコピーしました（{CLIPBOARD_CLEAR_SECONDS}秒後に復元）");
        cx.notify();
    }

    /// Put the clipboard back the way it was before the last copy.
    pub(super) fn restore_clipboard(&mut self, cx: &mut Context<Self>) {
        if self.clipboard_clear_at.is_none() {
            return;
        }
        let previous = self.clipboard_restore.take().unwrap_or_default();
        cx.write_to_clipboard(ClipboardItem::new_string(previous));
        self.clipboard_clear_at = None;
    }

    pub(super) fn refresh_audit(&mut self) {
        self.audit_report = Some(audit(
            &self.vault,
            self.settings.thresholds,
            i64::try_from(totp::now_unix()).unwrap_or(i64::MAX),
        ));
    }

    pub(super) fn push_editing(&mut self, character: char) {
        match self.editing {
            Some(SettingsField::ServerUrl) => self.settings.server_url.push(character),
            Some(SettingsField::Email) => self.settings.email.push(character),
            None => {}
        }
    }

    pub(super) fn pop_editing(&mut self) {
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

    pub(super) fn generate_password(&mut self, cx: &mut Context<Self>) {
        match self.generator.password.generate() {
            Ok(value) => {
                self.generator.last_password = Some(value);
                self.status = "パスワードを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    pub(super) fn generate_passphrase(&mut self, cx: &mut Context<Self>) {
        match self.generator.passphrase.generate() {
            Ok(value) => {
                self.generator.last_passphrase = Some(value);
                self.status = "パスフレーズを生成しました".to_string();
            }
            Err(error) => self.status = error.message().to_string(),
        }
        cx.notify();
    }

    pub(super) fn toggle_generator(&mut self, key: &str, cx: &mut Context<Self>) {
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
}
