//! The main application state and GPUI wiring.

use crate::auth::{authenticate, validate_config, AuthConfig};
use crate::health::{audit, Report};
use crate::model::{
    CardData, Filter, Folder, IdentityData, ItemData, ItemKind, LoginUri, SortKey, SshKeyData,
    Vault, VaultItem,
};
use crate::settings::Settings;
use crate::totp::{self, Tick};
use crate::ui::model::{AuthField, GeneratorState, Panel, Screen, SettingsField};
use crate::vault_sync;
use gpui_kit::prelude::*;
use gpui_kit::*;
use openwarden::{SecretString, Vault as OpenVault};

/// Seconds before a copied secret is restored to the previous clipboard value.
const CLIPBOARD_CLEAR_SECONDS: u64 = 30;

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
    pub(super) fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            server_url: self.server_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: SecretString::from(self.client_secret.clone()),
            email: self.email.clone(),
            master_password: SecretString::from(self.master_password.clone()),
        }
    }

    /// Validate entered credentials before opening the demo vault. Real
    /// network login is still handled by `auth::authenticate` and is not
    /// wired to this button yet.
    pub(super) fn unlock_with_auth(&mut self, cx: &mut Context<Self>) {
        let config = self.auth_config();
        let has_credentials = !self.client_id.is_empty()
            || !self.client_secret.is_empty()
            || !self.master_password.is_empty();
        if !has_credentials {
            self.unlock_mock(cx);
            return;
        }
        if let Err(error) = validate_config(&config) {
            self.status = error.message().to_string();
            cx.notify();
            return;
        }
        self.login_failed = false;
        self.status = "ログイン中…".to_string();
        cx.notify();
        // A fixed identifier is enough for the PoC; a real installation would
        // persist a UUID in Settings.
        let device_id = "bitwarden-gpui-poc-install".to_string();
        cx.spawn(
            |this: gpui_kit::WeakEntity<Self>, cx: &mut gpui_kit::AsyncApp| {
                let cx = cx.clone();
                async move {
                    let result = authenticate(&config, &device_id).await;
                    cx.update(|cx| {
                        this.update(cx, |view, cx| view.finish_login(result, cx))
                            .ok();
                    });
                }
            },
        )
        .detach();
    }

    /// Apply the result of an asynchronous login on the UI thread.
    pub(super) fn finish_login(
        &mut self,
        result: Result<crate::auth::AuthenticatedVault, crate::auth::AuthError>,
        cx: &mut Context<Self>,
    ) {
        let authenticated = match result {
            Ok(value) => value,
            Err(error) => {
                self.login_failed = true;
                self.status = format!("ログイン失敗: {}（r で再試行）", error.message());
                cx.notify();
                return;
            }
        };
        let protected_key = authenticated
            .session
            .protected_key()
            .unwrap_or("")
            .to_string();
        if protected_key.is_empty() {
            self.status = "ログイン失敗: 復号キーが応答にありません".to_string();
            cx.notify();
            return;
        }
        let kdf = authenticated.session.kdf();
        let mut open_vault = match OpenVault::unlock(&authenticated.master_key, &protected_key, kdf)
        {
            Ok(vault) => vault,
            Err(error) => {
                self.status = format!("ログイン失敗: 復号キーを取得できません（{error}）");
                cx.notify();
                return;
            }
        };
        if let Err(error) = open_vault.apply_sync(authenticated.sync) {
            self.status = format!("ログイン失敗: 同期データを取り込めません（{error}）");
            cx.notify();
            return;
        }
        match vault_sync::import_logins(&open_vault) {
            Ok(vault) => {
                self.vault = vault;
                self.screen = Screen::Unlocked;
                self.panel = Panel::Vault;
                self.selected = 0;
                self.status = format!(
                    "ログイン成功: {} 件のログインを読み込みました",
                    self.vault.len()
                );
            }
            Err(error) => self.status = format!("vault 変換失敗: {}", error.message()),
        }
        cx.notify();
    }

    pub(super) fn edit_auth_field(&mut self, character: char) {
        match self.auth_field {
            Some(AuthField::ServerUrl) => self.server_url.push(character),
            Some(AuthField::Email) => self.email.push(character),
            Some(AuthField::ClientId) => self.client_id.push(character),
            Some(AuthField::ClientSecret) => self.client_secret.push(character),
            Some(AuthField::MasterPassword) => self.master_password.push(character),
            None => {}
        }
    }

    pub(super) fn backspace_auth_field(&mut self) {
        match self.auth_field {
            Some(AuthField::ServerUrl) => {
                self.server_url.pop();
            }
            Some(AuthField::Email) => {
                self.email.pop();
            }
            Some(AuthField::ClientId) => {
                self.client_id.pop();
            }
            Some(AuthField::ClientSecret) => {
                self.client_secret.pop();
            }
            Some(AuthField::MasterPassword) => {
                self.master_password.pop();
            }
            None => {}
        }
    }

    pub(super) fn unlock_mock(&mut self, cx: &mut Context<Self>) {
        self.vault = mock_vault();
        self.generator = GeneratorState::from_settings(&self.settings);
        self.refresh_audit();
        self.panel = Panel::Vault;
        self.screen = Screen::Unlocked;
        self.selected = 0;
        self.scroll_handle.scroll_to_item(0, ScrollStrategy::Top);
        self.status = format!(
            "{} 件。↑↓選択 / f お気に入り / t フィルタ / s 並び順 / / 検索 / y TOTPコピー / g 監査 / n 生成 / c 設定 / l ロック / Esc 終了",
            self.vault.len()
        );
        cx.notify();
    }

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

    pub(super) fn key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match self.screen {
            Screen::Locked => {
                let key = event.keystroke.key.as_str();
                if self.auth_field.is_some() {
                    match key {
                        "escape" | "enter" => {
                            self.auth_field = None;
                            cx.notify();
                        }
                        "backspace" => {
                            self.backspace_auth_field();
                            cx.notify();
                        }
                        value if value.chars().count() == 1 => {
                            if let Some(character) = value.chars().next() {
                                self.edit_auth_field(character);
                                cx.notify();
                            }
                        }
                        _ => {}
                    }
                    return;
                }
                match key {
                    "escape" => cx.quit(),
                    "enter" => self.unlock_with_auth(cx),
                    "r" if self.login_failed => self.unlock_with_auth(cx),
                    "1" => self.auth_field = Some(AuthField::ServerUrl),
                    "2" => self.auth_field = Some(AuthField::Email),
                    "3" => self.auth_field = Some(AuthField::ClientId),
                    "4" => self.auth_field = Some(AuthField::ClientSecret),
                    "5" => self.auth_field = Some(AuthField::MasterPassword),
                    _ => return,
                }
                cx.notify();
            }
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
                        "y" => {
                            if let Some(value) = self.generator.last_password.clone() {
                                self.copy_to_clipboard(&value, cx);
                            }
                        }
                        "Y" => {
                            if let Some(value) = self.generator.last_passphrase.clone() {
                                self.copy_to_clipboard(&value, cx);
                            }
                        }
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
                    "y" => self.copy_totp(cx),
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
}
