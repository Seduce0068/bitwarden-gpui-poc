//! The main application state and GPUI wiring.

use crate::model::{Filter, ItemData, ItemKind, SortKey, Vault, VaultItem};
use crate::settings::Settings;
use crate::totp;
use crate::ui::state::{GeneratorState, Panel, Screen, SettingsField};
use gpui_kit::prelude::*;
use gpui_kit::*;

/// Seconds of inactivity before an unlocked vault is locked automatically.
pub(super) const IDLE_LOCK_SECONDS: u64 = 300;

pub struct BitwardenApp {
    pub(super) screen: Screen,
    pub(super) server_url: String,
    pub(super) email: String,
    pub(super) status: String,
    pub(super) view: crate::ui::vault_view::VaultViewState,
    pub(super) totp: crate::ui::totp_state::TotpState,
    pub(super) panel: Panel,
    pub(super) generator: GeneratorState,
    pub(super) settings: Settings,
    pub(super) editing: Option<SettingsField>,
    pub(super) auth: crate::ui::auth_state::AuthState,
    pub(super) clipboard: crate::ui::clipboard::ClipboardState,
    pub(super) last_activity: std::time::Instant,
    pub focus_handle: FocusHandle,
}

impl BitwardenApp {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let path = Settings::default_path();
        let loaded = path
            .as_ref()
            .map(Settings::load_detailed)
            .unwrap_or(Err(crate::settings::SettingsLoadError::ReadFailed));
        let load_notice = match &loaded {
            Err(crate::settings::SettingsLoadError::NotFound) => None,
            Err(error) => Some(error.message()),
            Ok(_) => None,
        };
        let settings = loaded.unwrap_or_default();
        let mut this = Self {
            screen: Screen::Locked,
            server_url: settings.server_url.clone(),
            email: settings.email.clone(),
            status: load_notice
                .map(|notice| format!("{notice} / Enter: ログイン / m: モック / Esc: 終了"))
                .unwrap_or_else(|| "ロック中: Enter: ログイン / m: モック / Esc: 終了".to_string()),
            view: crate::ui::vault_view::VaultViewState::new(),
            totp: crate::ui::totp_state::TotpState::new(),
            panel: Panel::Vault,
            generator: GeneratorState::from_settings(&settings),
            settings,
            editing: None,
            auth: crate::ui::auth_state::AuthState::new(),
            clipboard: crate::ui::clipboard::ClipboardState::new(),
            last_activity: std::time::Instant::now(),
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
                                let instant = std::time::Instant::now();
                                let unlocked = view.screen == Screen::Unlocked;
                                let effects = crate::ui::timing::evaluate_tick(
                                    view.clipboard.due(instant),
                                    unlocked
                                        && crate::ui::timing::idle_lock_due(
                                            view.last_activity,
                                            instant,
                                            std::time::Duration::from_secs(IDLE_LOCK_SECONDS),
                                        ),
                                    unlocked
                                        && view.panel == Panel::Vault
                                        && view.totp.has_secret(),
                                );
                                for effect in effects {
                                    match effect {
                                        crate::ui::timing::TickEffect::RestoreClipboard => {
                                            view.restore_clipboard(cx);
                                            cx.notify();
                                        }
                                        crate::ui::timing::TickEffect::InvalidateTotp => {
                                            view.totp.invalidate();
                                            cx.notify();
                                        }
                                        crate::ui::timing::TickEffect::AutoLock => {
                                            view.lock(cx);
                                            view.status = format!(
                                                "無操作のため自動ロックしました（{IDLE_LOCK_SECONDS}秒）"
                                            );
                                        }
                                    }
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
        self.view
            .vault
            .view(&self.view.filter, &self.view.query, self.view.sort)
    }

    /// Build an [`AuthConfig`] from the current lock-screen fields.
    pub(super) fn lock(&mut self, cx: &mut Context<Self>) {
        self.clipboard.restore(cx);
        self.view.vault = Vault::new();
        self.view.audit_report = None;
        self.panel = Panel::Vault;
        self.generator = GeneratorState::from_settings(&self.settings);
        self.editing = None;
        self.auth.clear_secrets();
        self.totp.clear();
        self.view.query.clear();
        self.view.filter = Filter::All;
        self.view.sort = SortKey::NameAsc;
        self.view.searching = false;
        self.view.selected_id = None;
        self.screen = Screen::Locked;
        self.last_activity = std::time::Instant::now();
        self.status = "ロックしました（Enter: ログイン / m: モック）".to_string();
        cx.notify();
    }

    /// Keep the selected row inside the current filtered view.
    ///
    /// Called after any mutation that can change which items are visible,
    /// such as toggling a favorite while the Favorites filter is active.
    pub(super) fn revalidate_selection(&mut self) -> bool {
        let visible = self.visible_items();
        let valid = crate::ui::logic::selection_in_view(
            self.view.selected_id.as_deref(),
            visible.iter().map(|item| item.id.as_str()),
        );
        if !valid {
            self.view.selected_id = None;
            self.view
                .scroll_handle
                .scroll_to_item(0, ScrollStrategy::Top);
        }
        valid
    }

    pub(super) fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        let visible = self.visible_items();
        if visible.is_empty() {
            return;
        }
        let current = self
            .view
            .selected_id
            .as_deref()
            .and_then(|id| visible.iter().position(|item| item.id == id))
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
        let id = visible[next].id.clone();
        if self.view.selected_id.as_deref() != Some(id.as_str()) {
            self.view.selected_id = Some(id);
            self.view
                .scroll_handle
                .scroll_to_item(next, ScrollStrategy::Nearest);
            cx.notify();
        }
    }

    pub(super) fn cycle_filter(&mut self, cx: &mut Context<Self>) {
        self.view.filter = match self.view.filter {
            Filter::All => Filter::Favorites,
            Filter::Favorites => Filter::Kind(ItemKind::Login),
            Filter::Kind(ItemKind::Login) => Filter::Kind(ItemKind::SecureNote),
            Filter::Kind(ItemKind::SecureNote) => Filter::Kind(ItemKind::Card),
            Filter::Kind(ItemKind::Card) => Filter::Kind(ItemKind::Identity),
            Filter::Kind(ItemKind::Identity) => Filter::Kind(ItemKind::SshKey),
            Filter::Kind(ItemKind::SshKey) => Filter::NoFolder,
            Filter::NoFolder | Filter::Folder(_) => Filter::All,
        };
        self.view.selected_id = None;
        self.view
            .scroll_handle
            .scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    pub(super) fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self
            .view
            .selected_id
            .clone()
            .or_else(|| self.visible_items().first().map(|item| item.id.clone()))
        else {
            return;
        };
        if let Some(favorite) = self.view.vault.toggle_favorite(&id) {
            self.status = format!(
                "お気に入りを{}にしました",
                if favorite { "設定" } else { "解除" }
            );
            // Under the Favorites filter the item may have just left the view.
            self.revalidate_selection();
            cx.notify();
        }
    }

    /// The current TOTP code for `secret`, cached within its validity period.
    pub(super) fn totp_text(&mut self, secret: &str) -> String {
        self.totp.display(secret, totp::now_unix())
    }

    pub(super) fn selected_detail(&mut self) -> String {
        let Some((base, data)) = (|| {
            let visible = self.visible_items();
            let item = self
                .view
                .selected_id
                .as_deref()
                .and_then(|id| visible.iter().find(|item| item.id == id))
                .or_else(|| visible.first())?;
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
                    uris.first()
                        .map_or("なし".into(), |uri| { crate::model::mask_uri(&uri.uri) })
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

    /// Recompute the health report with the current thresholds.
    pub(super) fn refresh_audit(&mut self) {
        self.view.audit_report = Some(crate::ui::logic::compute_audit(
            &self.view.vault,
            self.settings.thresholds,
            i64::try_from(totp::now_unix()).unwrap_or(i64::MAX),
        ));
    }
}
