//! Keyboard input handling for the app.
//!
//! Key classification lives in the pure [`crate::ui::keys`] module; this file
//! only applies the resulting action to the app state.

use crate::ui::app::BitwardenApp;
use crate::ui::keys::{
    classify_key, KeyContext, KeyModifiers, UiAction, TEXT_EDIT_ARROW_KEYS_HINT,
};
use crate::ui::state::Panel;
use gpui_kit::*;

/// The dedicated key that re-acquires the view's focus handle after focus has
/// moved elsewhere (for example via Tab).
///
/// `F1` is chosen deliberately: [`crate::ui::keys::classify_key`] maps it to
/// [`UiAction::None`] on every screen and in every editing mode, and the
/// default keymaps do not bind it. The global observer that watches this key
/// therefore cannot change normal key classification or editing behaviour.
pub(super) const FOCUS_RECOVERY_KEY: &str = "f1";

/// Whether `key` is the dedicated focus-recovery key.
///
/// Kept as a pure helper so the invariant that this key is inert in the normal
/// key classification can be exercised without a GPUI window.
pub(super) fn is_focus_recovery_key(key: &str) -> bool {
    key == FOCUS_RECOVERY_KEY
}

/// View-level effect of the `CycleSort` action.
///
/// Factored out of `apply_action` so the selection-drop and scroll-rewind
/// contract can be exercised with a plain `VaultViewState` (this crate does
/// not enable gpui's `test-support` feature).
pub(super) fn cycle_sort(view: &mut crate::ui::vault_view::VaultViewState) {
    view.sort = view.sort.next();
    view.deselect_and_rewind();
}

/// Status shown when a text-editing mode begins.
///
/// This status owns the shared "入力中:" arrow-key guidance for all three
/// editing modes (auth, search, settings); the settings panel deliberately
/// draws only its settings-specific inline hint so the prefix appears once.
/// Keeping it in one pure helper makes the wording testable without a GPUI
/// window.
pub(super) fn text_edit_start_status() -> String {
    format!("{TEXT_EDIT_ARROW_KEYS_HINT} / Enter または Esc で確定")
}

/// Status after confirming a settings field with Enter/Escape.
///
/// Confirming a field is not a save, so any unsaved marker must survive just
/// like it does on every other transient status. Kept as a pure helper so the
/// contract can be exercised without a GPUI window.
pub(super) fn settings_edit_finished_status(dirty: bool) -> String {
    crate::ui::app::status_with_unsaved("入力を確定しました（w: 保存 / d: 破棄）", dirty)
}

/// Shared composer for the status restored when a text-editing mode ends.
///
/// `EditAuthField`, `EditSettingsField` and `StartSearch` all replace the
/// status with [`text_edit_start_status`], whose text begins with "入力中:".
/// Leaving the mode without restoring a normal status leaves that stale
/// guidance on screen after Enter/Escape. This helper overwrites it with the
/// caller's normal status while preserving the persistent unsaved marker.
/// Kept pure so the contract can be tested without a GPUI window.
pub(super) fn text_edit_finished_status(normal_status: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(normal_status, dirty)
}

/// Normal lock-screen status restored by `FinishAuthEdit`.
pub(super) fn auth_edit_finished_status(dirty: bool) -> String {
    text_edit_finished_status(crate::ui::logic::auth_hint(false), dirty)
}

/// Normal vault status restored by `FinishSearch`.
///
/// Confirming a search clears the selection and rewinds the list (see
/// `VaultViewState::finish_search`), so the restored status matches the detail
/// line's "nothing selected" state instead of claiming a selection survives.
pub(super) fn search_finished_status(dirty: bool) -> String {
    text_edit_finished_status(crate::ui::logic::no_selection_status(), dirty)
}

/// Status after a settings time field is adjusted with `i`/`u`, `3`/`4` or
/// `5`/`6`.
///
/// The threshold keys already report through `refresh_audit`, but these three
/// branches previously changed the settings without touching the status bar,
/// leaving whatever the last action had written on screen. `unit` is `分` for
/// the idle auto-lock timeout (`i`/`u`, which moves in one-minute steps, see
/// [`crate::ui::logic::adjust_idle_lock`]) and `秒数` for the genuinely
/// seconds-based `3`-`6` fields. Kept pure so the wording can be tested
/// without a GPUI window.
pub(super) fn time_adjust_status(unit: &str, dirty: bool) -> String {
    crate::ui::app::status_with_unsaved(
        &format!("{unit}を変更しました（w: 保存 / d: 破棄）"),
        dirty,
    )
}

/// Status after `i`/`u` adjusts the minute-based idle auto-lock timeout.
pub(super) fn idle_lock_adjust_status(dirty: bool) -> String {
    time_adjust_status("分", dirty)
}

/// Status after `3`-`6` adjusts a seconds-based settings field.
pub(super) fn seconds_adjust_status(dirty: bool) -> String {
    time_adjust_status("秒数", dirty)
}

impl BitwardenApp {
    pub(super) fn key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.last_activity = std::time::Instant::now();
        let ctx = KeyContext {
            screen: self.screen,
            panel: crate::ui::logic::effective_panel(self.panel, self.view.audit_report.is_some()),
            key: &event.keystroke.key,
            key_char: event.keystroke.key_char.as_deref(),
            modifiers: KeyModifiers {
                control: event.keystroke.modifiers.control,
                platform: event.keystroke.modifiers.platform,
                alt: event.keystroke.modifiers.alt,
                function: event.keystroke.modifiers.function,
            },
            editing_auth: self.auth.field().is_some(),
            searching: self.view.searching,
            editing_settings: self.editing.is_some(),
            login_failed: self.auth.login_failed(),
            has_audit_report: self.view.audit_report.is_some(),
            query_nonempty: !self.view.query.is_empty(),
        };
        self.apply_action(classify_key(&ctx), cx);
    }

    /// Stamp activity for wheel/trackpad scrolls.
    ///
    /// `key_down` and `apply_action` already refresh `last_activity`, but a
    /// user who only scrolls (for example through the audit report) would
    /// otherwise hit the idle-lock timer. GPUI exposes a public bubble-phase
    /// `on_scroll` handler, so the root element in `render.rs` forwards
    /// scrolls here without touching gpui-kit internals.
    pub(super) fn scrolled(
        &mut self,
        _event: &ScrollEvent,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
        self.last_activity = std::time::Instant::now();
    }

    /// Apply a UI action to the app state. Both keyboard and mouse input go
    /// through this single path so state transitions stay consistent.
    pub(super) fn apply_action(&mut self, action: UiAction, cx: &mut Context<Self>) {
        self.last_activity = std::time::Instant::now();
        match action {
            UiAction::Quit => cx.quit(),
            UiAction::Authenticate | UiAction::RetryLogin => self.unlock_with_auth(cx),
            UiAction::OpenDemoVault => self.unlock_mock(cx),
            UiAction::EditAuthField(field) => {
                // Changing credentials invalidates any in-flight attempt.
                self.login_generation.invalidate();
                self.auth.set_field(Some(field));
                self.status = text_edit_start_status();
                cx.notify();
            }
            UiAction::EditSettingsField(field) => {
                self.editing = Some(field);
                self.status = text_edit_start_status();
                cx.notify();
            }
            UiAction::FinishAuthEdit => {
                self.login_generation.invalidate();
                self.auth.take_field();
                // Enter/Escape only confirm the field; drop the "入力中"
                // guidance installed by EditAuthField.
                self.status = auth_edit_finished_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::FinishSearch => {
                self.view.finish_search();
                // Same contract as the auth field: confirmation is not still
                // an editing session, so restore the normal vault status.
                self.status = search_finished_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::FinishSettingsEdit => {
                self.editing = None;
                // Enter/Escape only confirm the field; point at the explicit
                // save/discard keys and keep the unsaved marker visible.
                self.status = settings_edit_finished_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::InsertAuthText(text) => {
                self.login_generation.invalidate();
                self.edit_auth_field(&text);
                cx.notify();
            }
            UiAction::InsertSearchText(text) => {
                self.view.push_query(&text);
                cx.notify();
            }
            UiAction::InsertSettingsText(text) => {
                self.push_editing(&text);
                cx.notify();
            }
            UiAction::BackspaceAuth => {
                self.login_generation.invalidate();
                self.backspace_auth_field();
                cx.notify();
            }
            UiAction::BackspaceSearch => {
                self.view.pop_query();
                cx.notify();
            }
            UiAction::BackspaceSettings => {
                self.pop_editing();
                cx.notify();
            }
            UiAction::BackspaceQuery => {
                self.view.pop_query();
                cx.notify();
            }
            UiAction::SetPanel(panel) => self.set_panel(panel, cx),
            UiAction::Lock => self.lock(cx),
            UiAction::MoveSelection(delta) => self.move_selection(delta, cx),
            UiAction::ToggleFavorite => self.toggle_favorite(cx),
            UiAction::OpenAudit => self.set_panel(Panel::Audit, cx),
            UiAction::GeneratePassword => self.generate_password(cx),
            UiAction::GeneratePassphrase => self.generate_passphrase(cx),
            UiAction::CopyPassword => {
                if let Some(value) = self.generator.last_password.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = crate::ui::logic::no_generated_status("パスワード");
                    cx.notify();
                }
            }
            UiAction::CopyPassphrase => {
                if let Some(value) = self.generator.last_passphrase.clone() {
                    self.copy_to_clipboard(&value, cx);
                } else {
                    self.status = crate::ui::logic::no_generated_status("パスフレーズ");
                    cx.notify();
                }
            }
            UiAction::CopyTotp => self.copy_totp(cx),
            UiAction::CopySelectedPassword => self.copy_selected_field(true, cx),
            UiAction::CopySelectedUsername => self.copy_selected_field(false, cx),
            UiAction::CycleFilter => self.cycle_filter(cx),
            UiAction::CycleSort => {
                cycle_sort(&mut self.view);
                self.sync_totp_to_selection();
                cx.notify();
            }
            UiAction::StartSearch => {
                // Delegate to the shared helper instead of duplicating its
                // query reset here: its query-clearing contract is covered by
                // `vault_view::tests::start_search_discards_a_previous_query_and_its_selection`.
                self.view.start_search();
                self.sync_totp_to_selection();
                self.status = text_edit_start_status();
                cx.notify();
            }
            UiAction::SaveSettings => self.save_settings(cx),
            UiAction::DiscardSettings => self.discard_settings(cx),
            UiAction::FocusAuditItem(id) => self.focus_audit_item(&id, cx),
            UiAction::AdjustThreshold(delta) => {
                self.settings.thresholds =
                    crate::ui::logic::adjust_thresholds(self.settings.thresholds, delta);
                self.mark_settings_dirty();
                self.refresh_audit();
                cx.notify();
            }
            UiAction::AdjustIdleLock(delta) => {
                self.settings.idle_lock_seconds =
                    crate::ui::logic::adjust_idle_lock(self.settings.idle_lock_seconds, delta);
                self.mark_settings_dirty();
                // `i`/`u` move in minutes, not seconds: report the right unit.
                self.status = idle_lock_adjust_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::AdjustLoginTimeout(delta) => {
                self.settings.login_timeout_seconds =
                    crate::ui::logic::adjust_seconds(self.settings.login_timeout_seconds, delta);
                self.mark_settings_dirty();
                self.status = seconds_adjust_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::AdjustClipboardRestore(delta) => {
                self.settings.clipboard_restore_seconds = crate::ui::logic::adjust_seconds(
                    self.settings.clipboard_restore_seconds,
                    delta,
                );
                self.mark_settings_dirty();
                self.status = seconds_adjust_status(self.settings_dirty);
                cx.notify();
            }
            UiAction::Generator(option) => self.toggle_generator(option, cx),
            UiAction::SelectRow(index) => {
                // A mouse click is an explicit selection: leaving search mode
                // here keeps the row click and the keyboard path consistent.
                if self.view.searching {
                    self.view.finish_search();
                }
                if self.view.select_index(index) {
                    self.view
                        .scroll_handle
                        .scroll_to_item(index, gpui_kit::ScrollStrategy::Nearest);
                }
                self.sync_totp_to_selection();
                cx.notify();
            }
            UiAction::None => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    // `use gpui_kit::*` at module scope brings gpui's `test` attribute macro
    // into this module through `use super::*`. A bare `#[test]` resolves to
    // that macro instead of the built-in one and expands recursively, so
    // these tests name the built-in attribute by its absolute path.
    use super::*;
    use crate::ui::state::Screen;

    fn context(screen: Screen, panel: Panel, key: &str) -> KeyContext<'_> {
        KeyContext {
            screen,
            panel,
            key,
            key_char: None,
            modifiers: KeyModifiers::default(),
            editing_auth: false,
            searching: false,
            editing_settings: false,
            login_failed: false,
            has_audit_report: false,
            query_nonempty: false,
        }
    }

    #[::core::prelude::v1::test]
    fn cycle_sort_deselects_and_rewinds() {
        use crate::model::{ItemData, VaultItem};
        use crate::ui::vault_view::VaultViewState;

        let mut view = VaultViewState::new();
        view.vault.items.push(VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        view.selected_id = Some("a".into());
        let before_sort = view.sort;
        let before_rewind = view.rewind_calls;

        cycle_sort(&mut view);

        assert_ne!(
            view.sort, before_sort,
            "CycleSort must advance the sort key"
        );
        assert_eq!(
            view.selected_id, None,
            "the stale selection must be dropped"
        );
        assert_eq!(
            view.rewind_calls,
            before_rewind + 1,
            "a sort change rewinds like filter and search changes"
        );
    }

    #[::core::prelude::v1::test]
    fn text_edit_start_status_explains_arrow_key_ownership() {
        let status = text_edit_start_status();
        assert!(status.contains("矢印キー"), "{status}");
        assert!(status.contains("GPUI"), "{status}");
        assert_eq!(
            status,
            format!("{TEXT_EDIT_ARROW_KEYS_HINT} / Enter または Esc で確定")
        );
    }

    #[::core::prelude::v1::test]
    fn settings_edit_finished_status_keeps_the_unsaved_marker() {
        let clean = settings_edit_finished_status(false);
        assert_eq!(clean, "入力を確定しました（w: 保存 / d: 破棄）");
        let dirty = settings_edit_finished_status(true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(
            dirty.contains("[未保存の設定変更があります]"),
            "confirming a field is not a save: {dirty}"
        );
    }

    #[::core::prelude::v1::test]
    fn seconds_adjust_status_keeps_save_hint_and_unsaved_marker() {
        let clean = seconds_adjust_status(false);
        assert_eq!(clean, "秒数を変更しました（w: 保存 / d: 破棄）");
        assert!(!clean.contains("[未保存"), "{clean}");

        // The seconds-based 3/4 and 5/6 branches mark the settings dirty
        // before writing the status, so the unsaved marker must survive.
        let dirty = seconds_adjust_status(true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");
    }

    #[::core::prelude::v1::test]
    fn idle_lock_adjust_status_reports_minutes_not_seconds() {
        let clean = idle_lock_adjust_status(false);
        assert_eq!(clean, "分を変更しました（w: 保存 / d: 破棄）");
        assert!(!clean.contains("秒"), "{clean}");

        let dirty = idle_lock_adjust_status(true);
        assert_eq!(
            dirty,
            crate::ui::app::status_with_unsaved(clean.as_str(), true)
        );
        assert!(dirty.contains("[未保存の設定変更があります]"), "{dirty}");
        assert!(dirty.contains("w: 保存 / d: 破棄"), "{dirty}");

        // The 3-6 fields really are seconds-based and keep their wording.
        assert_eq!(
            seconds_adjust_status(false),
            "秒数を変更しました（w: 保存 / d: 破棄）"
        );
        assert!(!seconds_adjust_status(false).contains("分を変更"));
    }

    #[::core::prelude::v1::test]
    fn idle_lock_keys_route_to_the_minute_status() {
        for (key, delta) in [("i", 1), ("u", -1)] {
            let ctx = context(Screen::Unlocked, Panel::Settings, key);
            assert_eq!(classify_key(&ctx), UiAction::AdjustIdleLock(delta));
            assert!(
                idle_lock_adjust_status(true).contains("分を変更しました"),
                "{key} must report minutes, not seconds"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn confirming_auth_or_search_clears_the_editing_status() {
        // The start statuses really do carry the "入力中" prefix; otherwise
        // this test would pass without exercising the stale-status bug.
        assert!(text_edit_start_status().contains("入力中"));
        assert!(crate::ui::logic::auth_hint(true).contains("入力中"));

        for dirty in [false, true] {
            let auth = auth_edit_finished_status(dirty);
            assert_eq!(
                auth,
                crate::ui::app::status_with_unsaved(crate::ui::logic::auth_hint(false), dirty)
            );
            assert!(!auth.contains("入力中"), "{auth}");
            assert!(auth.contains("F1: フォーカス復帰"), "{auth}");

            let search = search_finished_status(dirty);
            assert_eq!(
                search,
                crate::ui::app::status_with_unsaved(crate::ui::logic::no_selection_status(), dirty)
            );
            assert!(!search.contains("入力中"), "{search}");
            assert_eq!(
                search.contains("[未保存の設定変更があります]"),
                dirty,
                "{search}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn generator_and_settings_panels_keep_up_down_unbound() {
        // Only the vault list and audit panel own a scroll handle; generator
        // and settings must not turn Up/Down into a hidden list selection.
        for panel in [Panel::Generator, Panel::Settings] {
            for key in ["up", "down", "arrowup", "arrowdown", "pageup", "pagedown"] {
                assert_eq!(
                    classify_key(&context(Screen::Unlocked, panel, key)),
                    UiAction::None,
                    "{panel:?}/{key}"
                );
            }
        }
        // The vault list still owns the same keys, so this is panel-local.
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "up")),
            UiAction::MoveSelection(-1)
        );
    }

    #[::core::prelude::v1::test]
    fn focus_recovery_key_is_recognised() {
        assert!(is_focus_recovery_key(FOCUS_RECOVERY_KEY));
        assert!(is_focus_recovery_key("f1"));
        assert!(!is_focus_recovery_key("F1"));
        assert!(!is_focus_recovery_key("f2"));
        assert!(!is_focus_recovery_key(""));
    }

    #[::core::prelude::v1::test]
    fn focus_recovery_key_never_changes_normal_classification() {
        // Every screen and panel must keep mapping the dedicated recovery key
        // to `None`, so the global observer cannot trigger a UI action.
        let mut contexts = vec![
            context(Screen::Locked, Panel::Vault, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Audit, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Generator, FOCUS_RECOVERY_KEY),
            context(Screen::Unlocked, Panel::Settings, FOCUS_RECOVERY_KEY),
        ];
        // Editing modes (search, auth field, settings field) as well.
        let mut searching = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        searching.searching = true;
        contexts.push(searching);
        let mut editing_auth = context(Screen::Locked, Panel::Vault, FOCUS_RECOVERY_KEY);
        editing_auth.editing_auth = true;
        contexts.push(editing_auth);
        let mut editing_settings = context(Screen::Unlocked, Panel::Settings, FOCUS_RECOVERY_KEY);
        editing_settings.editing_settings = true;
        contexts.push(editing_settings);

        for ctx in &contexts {
            assert_eq!(
                classify_key(ctx),
                UiAction::None,
                "the recovery key must stay inert in {ctx:?}"
            );
        }

        // A stray `key_char` must not turn F1 into inserted text either.
        let mut with_char = context(Screen::Unlocked, Panel::Vault, FOCUS_RECOVERY_KEY);
        with_char.key_char = Some("\u{f1}");
        assert_eq!(classify_key(&with_char), UiAction::None);

        // Sanity check: the helper only fires for the dedicated key, and a
        // normal command key stays classified as before.
        assert!(!is_focus_recovery_key("l"));
        assert_eq!(
            classify_key(&context(Screen::Unlocked, Panel::Vault, "l")),
            UiAction::Lock
        );
    }
}
