//! Pure UI predicates that can be tested without a GPUI window.

use crate::health::{audit, Report, Thresholds};
use crate::model::Vault;
use crate::ui::state::Panel;

/// Whether any credential field is non-empty (test helper only).
///
/// `Enter` always attempts a real login and the demo vault requires the
/// explicit `m` key, so this predicate is not a login gate; it only describes
/// the state of the credential fields in tests.
#[cfg(test)]
pub(super) fn has_credentials(client_id: &str, client_secret: &str, master_password: &str) -> bool {
    !client_id.is_empty() || !client_secret.is_empty() || !master_password.is_empty()
}

/// Whether `selected_id` still names an item in the current view.
///
/// `None` means "there is nothing to validate" and is left untouched. The
/// actions that *require* a selection use [`required_item_index`] instead;
/// they never fall back to the first visible row.
pub(super) fn selection_in_view<'a>(
    selected_id: Option<&str>,
    ids: impl IntoIterator<Item = &'a str>,
) -> bool {
    match selected_id {
        None => true,
        Some(id) => ids.into_iter().any(|candidate| candidate == id),
    }
}

/// Index of the explicitly selected item, or `None` when nothing is selected.
///
/// Actions that act on "the current item" must go through this predicate so a
/// stale or absent selection can never silently target `visible[0]`.
pub(super) fn required_item_index(
    selected_id: Option<&str>,
    visible: &[&crate::model::VaultItem],
) -> Option<usize> {
    let id = selected_id?;
    visible.iter().position(|item| item.id == id)
}

/// Status shown when an action needs a selection but none is active.
pub(super) fn no_selection_status() -> &'static str {
    "項目を選択してください"
}

/// Status when a confirmed search matched no item at all.
pub(super) const NO_SEARCH_RESULTS_STATUS: &str = "検索結果が0件です（一致する項目がありません）";

/// Status for a "nothing selected" state that knows the visible item count.
///
/// [`no_selection_status`] asks the user to choose a row. After confirming a
/// search with zero matches there is no row to choose, so callers pass the
/// result count here and get a dedicated message instead. The generic helper
/// is kept unchanged for the callers that have no count to report.
pub(super) fn no_selection_status_for_count(count: usize) -> String {
    if count == 0 {
        NO_SEARCH_RESULTS_STATUS.to_string()
    } else {
        no_selection_status().to_string()
    }
}

/// Run the vault health audit with an explicit clock value.
///
/// Keeping the clock as a parameter makes the audit reproducible in tests.
pub(super) fn compute_audit(vault: &Vault, thresholds: Thresholds, now: i64) -> Report {
    audit(vault, thresholds, now)
}

/// Resolve a requested panel to one that can actually be rendered.
///
/// The audit panel needs a generated report; falling back to the vault list
/// here keeps `KeyContext.panel` in sync with what is drawn.
pub(super) fn effective_panel(requested: Panel, has_audit_report: bool) -> Panel {
    if requested == Panel::Audit && !has_audit_report {
        Panel::Vault
    } else {
        requested
    }
}

/// Reduce a card number to its last four ASCII digits for display.
///
/// As in the search haystack of [`crate::model::Vault::view`], every non-digit
/// grouping character is ignored, so a number without spaces is masked just as
/// strictly as one that uses them. At most the last four digits are shown;
/// shorter numbers are shown as-is and a number with no digits at all is
/// reported explicitly instead of rendering an empty "末尾:" label.
pub(super) fn card_last_four(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return "なし".to_string();
    }
    let start = digits.len().saturating_sub(4);
    digits[start..].iter().copied().collect()
}

/// Value to copy from a login item, or `None` when nothing may be copied.
///
/// Empty values and the undecryptable marker are refused so no placeholder or
/// empty string is written into the user's clipboard.
pub(super) fn select_copy_value(data: &crate::model::ItemData, password: bool) -> Option<String> {
    match data {
        crate::model::ItemData::Login {
            username,
            password: secret,
            ..
        } => {
            let raw = if password {
                secret.as_str()
            } else {
                username.as_str()
            };
            if raw.is_empty() || (password && crate::vault_sync::is_undecryptable_password(raw)) {
                None
            } else {
                Some(raw.to_string())
            }
        }
        _ => None,
    }
}

/// Status text when no generated value exists yet (never a decryption issue).
pub(super) fn no_generated_status(kind: &str) -> String {
    format!("生成済み{kind}がありません（生成パネルで生成してください）")
}

/// Status text when the selected item has no copyable value for `field`.
pub(super) fn no_field_status(field: &str) -> String {
    format!("コピーできる {field} がありません（復号できない場合も同様です）")
}

/// Status when a pending clipboard restore could not be confirmed.
///
/// The write API returns no result, so the caller verifies it by reading the
/// clipboard back. A mismatch must be visible instead of claiming success.
pub(super) fn clipboard_restore_failure_status() -> &'static str {
    "クリップボードの復元を確認できませんでした（コピーした内容を手動で消去してください）"
}

/// Label appended to settings panels while in-memory changes are not saved.
pub(super) fn unsaved_marker(dirty: bool) -> &'static str {
    if dirty {
        "[未保存]"
    } else {
        ""
    }
}

/// Guidance for the dedicated focus-recovery key.
///
/// `F1` is watched by the global keystroke observer installed in `app.rs`.
/// Listing it in the UI hints makes the way back from a lost focus discoverable
/// instead of leaving it documented only in the source.
pub(super) const FOCUS_RECOVERY_HINT: &str = "F1: フォーカス復帰";

/// Hint for the lock screen. While a field is active `1`-`5` insert text and
/// `Enter` only confirms that field; it never starts authentication.
pub(super) fn auth_hint(editing: bool) -> &'static str {
    if editing {
        "入力中: 1-5 も文字として入力 / Backspace: 削除 / Enter: 確定のみ（認証はしません） / Esc: 確定 / F1: フォーカス復帰"
    } else {
        // After Enter/Escape confirms a field this text replaces the "入力中:"
        // status, so it must keep advertising the lock-screen shortcuts that
        // are otherwise only shown by the initial lock status.
        "1-5: 欄を選択 / Enter: 検証して開く / m: デモボルト / r: ログイン失敗時の再試行 / Esc: 終了 / F1: フォーカス復帰"
    }
}

/// Hint for the settings panel, switched while a field is being edited.
///
/// The status bar already announces the editing state through
/// `ui::input::text_edit_start_status` (which starts with the shared
/// "入力中:" prefix from `TEXT_EDIT_ARROW_KEYS_HINT`), and the panel no
/// longer draws that shared constant itself. Mirroring the status bar's F1
/// de-duplication policy, the inline hint drops the prefix too so the two
/// lines do not both open with "入力中:" while a field is active.
pub(super) fn settings_hint(editing: bool) -> &'static str {
    if editing {
        "w/c/l/d も文字として入力（保存はしません） / Backspace: 削除 / Enter: 確定（保存はしません） / Esc: 確定 / F1: フォーカス復帰"
    } else {
        "1,2: 編集 / +/-: 閾値 / i/u: 自動ロック / 3,4: ログイン制限 / 5,6: 復元 / w: 保存 / d: 破棄 / c: 戻る / l: ロック / Esc: 終了 / F1: フォーカス復帰"
    }
}

/// Convert a day count since 1970-01-01 to a proleptic-Gregorian calendar date.
///
/// This is the inverse of the standard `days_from_civil` calculation (Howard
/// Hinnant's public-domain algorithm). It is integer-only, so it needs no date
/// crate, no system clock and no `unsafe`, and is fully deterministic in tests.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

/// Format a revision timestamp as a wall-clock date-time with an explicit
/// UTC offset.
///
/// `UNKNOWN_REVISION` (0) means "never recorded" and is rendered as `不明`
/// instead of the misleading 1970-01-01. `offset_secs` shifts the instant into
/// the caller's local zone; pass 0 for UTC. The zone is always named in the
/// output so a UTC-rendered value can never be mistaken for local time.
///
/// `std` has no local-timezone API and adding a date crate would require a
/// `Cargo.toml` change outside this task's scope, so the production caller uses
/// the UTC form. The offset parameter keeps the conversion pure and testable.
pub(super) fn format_revision_date_at(revision: i64, offset_secs: i64) -> String {
    if revision == crate::model::UNKNOWN_REVISION {
        return "不明".to_string();
    }
    let local = revision.saturating_add(offset_secs);
    let days = local.div_euclid(86_400);
    let seconds_in_day = local.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_in_day / 3600;
    let minute = (seconds_in_day % 3600) / 60;
    let second = seconds_in_day % 60;
    let zone = if offset_secs == 0 {
        "UTC".to_string()
    } else {
        let sign = if offset_secs > 0 { '+' } else { '-' };
        let magnitude = offset_secs.unsigned_abs();
        format!(
            "UTC{sign}{:02}:{:02}",
            magnitude / 3600,
            (magnitude % 3600) / 60
        )
    };
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} {zone}")
}

/// Revision formatter used by the detail line (UTC until a timezone source is
/// wired in; see [`format_revision_date_at`]).
pub(super) fn format_revision_date(revision: i64) -> String {
    format_revision_date_at(revision, 0)
}

/// Status text after a successful login.
///
/// A vault restored from the encrypted offline cache may be stale (the sync
/// call failed), so the status says so instead of implying fresh data.
pub(super) fn login_success_status(count: usize, from_cache: bool) -> String {
    let base = format!("ログイン成功: {count} 件の項目を読み込みました");
    if from_cache {
        format!("{base}（オフラインキャッシュから復元。最新でない可能性があります）")
    } else {
        base
    }
}

/// Status text for a clipboard copy.
///
/// Restoration is only promised when the pre-copy contents were readable:
/// `ClipboardState` skips creating a pending restore for `None`, so announcing
/// one would mislead the user about what will happen.
pub(super) fn clipboard_copy_status(seconds: u64, has_original: bool) -> String {
    if has_original {
        format!("クリップボードにコピーしました（{seconds}秒後に復元）")
    } else {
        "クリップボードにコピーしました（元の内容を読めないため復元しません。コピーした内容はそのまま残ります）".to_string()
    }
}

/// Adjust the idle auto-lock timeout in one-minute steps, clamped to 1..=60
/// minutes.
pub(super) fn adjust_idle_lock(current_seconds: u64, delta_minutes: i32) -> u64 {
    let current_minutes = (current_seconds / 60).clamp(
        crate::limits::MIN_IDLE_LOCK_MINUTES,
        crate::limits::MAX_IDLE_LOCK_MINUTES,
    ) as i64;
    let next = (current_minutes + i64::from(delta_minutes)).clamp(
        crate::limits::MIN_IDLE_LOCK_MINUTES as i64,
        crate::limits::MAX_IDLE_LOCK_MINUTES as i64,
    );
    (next * 60) as u64
}

/// Adjust a seconds-based setting by one UI step, clamped to the shared
/// 1..=3600 second bounds declared in [`crate::limits`].
///
/// Both seconds-based settings use the same range, and the login-timeout
/// constants are its canonical pair (`MIN/MAX_CLIPBOARD_RESTORE_SECONDS` have
/// the same values), so the clamp no longer duplicates the magic numbers.
pub(super) fn adjust_seconds(current: u64, delta_seconds: i32) -> u64 {
    // A stored value larger than `i64::MAX` saturates at `i64::MAX`; adding a
    // positive step to that sentinel would overflow in a debug build and wrap
    // in release, jumping a huge value to the *minimum* after the clamp below.
    let next = i64::try_from(current)
        .unwrap_or(i64::MAX)
        .saturating_add(i64::from(delta_seconds));
    next.clamp(
        crate::limits::MIN_LOGIN_TIMEOUT_SECONDS as i64,
        crate::limits::MAX_LOGIN_TIMEOUT_SECONDS as i64,
    ) as u64
}

/// Adjust audit thresholds by one UI step, clamped to the shared bounds in
/// [`crate::limits`]: `MIN_WEAK_BITS..=MAX_WEAK_BITS` and
/// `MIN_STALE_DAYS..=MAX_STALE_DAYS`.
///
/// `delta` is +1 for `+`/`=` and -1 for `-`/`_`.
pub(super) fn adjust_thresholds(current: Thresholds, delta: i32) -> Thresholds {
    let weak_step = delta.saturating_mul(5);
    let day_step = delta.saturating_mul(30);
    Thresholds {
        weak_bits: if weak_step > 0 {
            current
                .weak_bits
                .saturating_add(weak_step as u32)
                .min(crate::limits::MAX_WEAK_BITS)
        } else {
            current
                .weak_bits
                .saturating_sub(weak_step.unsigned_abs())
                .max(crate::limits::MIN_WEAK_BITS)
        },
        stale_days: if day_step > 0 {
            current
                .stale_days
                .saturating_add(day_step as i64)
                .min(crate::limits::MAX_STALE_DAYS)
        } else {
            current
                .stale_days
                .saturating_sub(day_step.unsigned_abs() as i64)
                .max(crate::limits::MIN_STALE_DAYS)
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn credentials_need_at_least_one_field() {
        assert!(!has_credentials("", "", ""));
        assert!(has_credentials("user.1234", "", ""));
        assert!(has_credentials("", "secret", ""));
        assert!(has_credentials("", "", "master"));
    }

    #[test]
    fn selection_in_view_checks_ids() {
        let ids = ["1", "2", "3"];
        assert!(selection_in_view(None, ids));
        assert!(selection_in_view(Some("2"), ids));
        assert!(!selection_in_view(Some("4"), ids));
        assert!(!selection_in_view(Some("1"), []));
    }

    #[test]
    fn required_item_index_never_falls_back_to_the_first_row() {
        use crate::model::{ItemData, VaultItem};

        let first = VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        );
        let second = VaultItem::new(
            "b",
            "Beta",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        );
        let visible = [&first, &second];
        assert_eq!(required_item_index(Some("b"), &visible), Some(1));
        assert_eq!(required_item_index(Some("a"), &visible), Some(0));
        // No selection and a stale id are both refused instead of hitting the
        // first row.
        assert_eq!(required_item_index(None, &visible), None);
        assert_eq!(required_item_index(Some("missing"), &visible), None);
        assert_eq!(required_item_index(Some("a"), &[]), None);
    }

    #[test]
    fn selection_related_status_texts_are_explicit() {
        assert_eq!(no_selection_status(), "項目を選択してください");
        assert!(clipboard_restore_failure_status().contains("手動で消去"));
        assert_eq!(unsaved_marker(true), "[未保存]");
        assert_eq!(unsaved_marker(false), "");
    }

    #[test]
    fn no_selection_status_for_count_explains_an_empty_result() {
        assert_eq!(
            no_selection_status_for_count(0),
            "検索結果が0件です（一致する項目がありません）"
        );
        assert_eq!(no_selection_status_for_count(1), no_selection_status());
        assert_eq!(no_selection_status_for_count(7), no_selection_status());
        // The shared helper is still the generic prompt for callers without a
        // result count (render.rs / actions.rs).
        assert_eq!(no_selection_status(), "項目を選択してください");
    }

    #[test]
    fn editing_hints_never_promise_a_save_or_an_authentication() {
        let locked = auth_hint(true);
        assert!(locked.contains("1-5 も文字として入力"));
        assert!(locked.contains("認証はしません"));
        assert!(auth_hint(false).contains("Enter: 検証して開く"));

        let settings = settings_hint(true);
        assert!(settings.contains("保存はしません"));
        assert!(settings.contains("w/c/l/d も文字として入力"));
        assert!(settings_hint(false).contains("w: 保存 / d: 破棄"));
    }

    #[test]
    fn idle_lock_hint_keeps_demo_and_retry_keys_after_a_field_is_confirmed() {
        // `FinishAuthEdit` restores `auth_hint(false)` into the status bar;
        // losing `m`/`r` there hid the only shortcuts left on the lock screen.
        let idle = auth_hint(false);
        assert!(idle.contains("Enter: 検証して開く"));
        assert!(idle.contains("m: デモボルト"), "{idle}");
        assert!(idle.contains("r: ログイン失敗時の再試行"), "{idle}");
        assert!(idle.contains(FOCUS_RECOVERY_HINT));

        // While editing, those letters are literal text, not commands.
        let editing = auth_hint(true);
        assert!(!editing.contains("m: デモボルト"));
        assert!(!editing.contains("r: ログイン失敗時の再試行"));
        assert!(editing.contains("1-5 も文字として入力"));
    }

    #[test]
    fn settings_inline_hint_does_not_repeat_the_status_bar_editing_prefix() {
        // The status bar's editing status starts with the shared arrow-key
        // hint, which itself begins with "入力中:". The inline settings hint
        // must therefore carry only settings-specific keys, mirroring the
        // status bar's F1 de-duplication policy.
        assert!(crate::ui::keys::TEXT_EDIT_ARROW_KEYS_HINT.starts_with("入力中:"));
        let editing = settings_hint(true);
        assert!(
            !editing.starts_with("入力中:"),
            "the inline hint must not repeat the status-bar prefix: {editing}"
        );
        assert!(!editing.contains("矢印キー"), "{editing}");
        assert!(!settings_hint(false).starts_with("入力中:"));
    }

    #[test]
    fn every_hint_advertises_the_focus_recovery_key() {
        assert!(auth_hint(true).contains(FOCUS_RECOVERY_HINT));
        assert!(auth_hint(false).contains(FOCUS_RECOVERY_HINT));
        assert!(settings_hint(true).contains(FOCUS_RECOVERY_HINT));
        assert!(settings_hint(false).contains(FOCUS_RECOVERY_HINT));
    }

    #[test]
    fn revision_dates_format_to_a_calendar_date_and_name_unknown() {
        assert_eq!(
            format_revision_date(crate::model::UNKNOWN_REVISION),
            "不明",
            "0 must never be shown as a 1970 timestamp"
        );
        assert_eq!(
            format_revision_date(1_700_000_000),
            "2023-11-14 22:13:20 UTC"
        );
        // Same instant, different wall clock and an explicit zone label.
        assert_eq!(
            format_revision_date_at(1_700_000_000, 9 * 3600),
            "2023-11-15 07:13:20 UTC+09:00"
        );
        assert_eq!(
            format_revision_date_at(1_700_000_000, -5 * 3600),
            "2023-11-14 17:13:20 UTC-05:00"
        );
        // Deterministic: no system clock or timezone lookup is involved.
        assert_eq!(
            format_revision_date(1_700_000_000),
            format_revision_date(1_700_000_000)
        );
    }

    #[test]
    fn audit_is_deterministic_for_a_given_clock() {
        let vault = Vault::new();
        let thresholds = Thresholds::default();
        let first = compute_audit(&vault, thresholds, 1_700_000_000);
        let second = compute_audit(&vault, thresholds, 1_700_000_000);
        assert_eq!(first, second);
        assert_eq!(first.examined, 0);
        assert!(first.items.is_empty());
    }

    #[test]
    fn audit_panel_falls_back_without_a_report() {
        assert_eq!(
            effective_panel(Panel::Audit, false),
            Panel::Vault,
            "the key context must match the rendered panel"
        );
        assert_eq!(effective_panel(Panel::Audit, true), Panel::Audit);
        assert_eq!(effective_panel(Panel::Settings, false), Panel::Settings);
        assert_eq!(effective_panel(Panel::Generator, false), Panel::Generator);
    }

    #[test]
    fn card_last_four_ignores_group_separators_and_never_leaks_the_prefix() {
        assert_eq!(card_last_four("4111 1111 1111 1234"), "1234");
        assert_eq!(card_last_four("4111111111111234"), "1234");
        assert_eq!(card_last_four("4111-1111-1111-1234"), "1234");
        assert_eq!(card_last_four("１２３４ 4111 1111 1111 1234"), "1234");
        assert_eq!(card_last_four("1234"), "1234");
        assert_eq!(card_last_four("12 34"), "1234");
        assert_eq!(card_last_four("123"), "123");
        assert_eq!(card_last_four(""), "なし");
        assert_eq!(card_last_four("   "), "なし");
        assert_eq!(card_last_four("abcd"), "なし");
    }

    #[test]
    fn select_copy_value_refuses_empty_and_undecryptable_secrets() {
        use crate::model::ItemData;
        use crate::vault_sync::UNDECRYPTABLE_PASSWORD;
        use zeroize::Zeroizing;

        let data = ItemData::Login {
            username: "alice@example.com".to_string(),
            password: Zeroizing::new("s3cret".to_string()),
            totp: Zeroizing::new(String::new()),
            uris: Vec::new(),
        };
        assert_eq!(select_copy_value(&data, true).as_deref(), Some("s3cret"));
        assert_eq!(
            select_copy_value(&data, false).as_deref(),
            Some("alice@example.com")
        );

        let broken = ItemData::Login {
            username: "alice@example.com".to_string(),
            password: Zeroizing::new(UNDECRYPTABLE_PASSWORD.to_string()),
            totp: Zeroizing::new(String::new()),
            uris: Vec::new(),
        };
        assert_eq!(select_copy_value(&broken, true), None);
        assert!(select_copy_value(&broken, false).is_some());

        let empty = ItemData::Login {
            username: String::new(),
            password: Zeroizing::new(String::new()),
            totp: Zeroizing::new(String::new()),
            uris: Vec::new(),
        };
        assert_eq!(select_copy_value(&empty, true), None);
        assert_eq!(select_copy_value(&empty, false), None);

        let note = ItemData::SecureNote {
            text: "body".to_string().into(),
        };
        assert_eq!(select_copy_value(&note, true), None);
    }

    #[test]
    fn generated_value_status_does_not_mention_decryption() {
        let status = no_generated_status("パスワード");
        assert_eq!(
            status,
            "生成済みパスワードがありません（生成パネルで生成してください）"
        );
        assert!(!status.contains("復号"));
    }

    #[test]
    fn missing_field_status_names_the_field() {
        assert_eq!(
            no_field_status("パスワード"),
            "コピーできる パスワード がありません（復号できない場合も同様です）"
        );
        assert!(no_field_status("ユーザー名").contains("ユーザー名"));
    }

    #[test]
    fn login_status_warns_only_for_cache_restores() {
        let fresh = login_success_status(3, false);
        assert_eq!(fresh, "ログイン成功: 3 件の項目を読み込みました");

        let restored = login_success_status(3, true);
        assert!(restored.starts_with(&fresh), "{restored}");
        assert!(
            restored.contains("オフラインキャッシュから復元"),
            "{restored}"
        );
        assert!(
            restored.contains("最新でない可能性があります"),
            "{restored}"
        );
    }

    #[test]
    fn clipboard_status_promises_restore_only_when_it_can_happen() {
        assert_eq!(
            clipboard_copy_status(30, true),
            "クリップボードにコピーしました（30秒後に復元）"
        );
        assert_eq!(
            clipboard_copy_status(30, false),
            "クリップボードにコピーしました（元の内容を読めないため復元しません。コピーした内容はそのまま残ります）"
        );
    }

    #[test]
    fn idle_lock_adjustment_clamps_to_one_and_sixty_minutes() {
        assert_eq!(adjust_idle_lock(300, 1), 360);
        assert_eq!(adjust_idle_lock(300, -1), 240);
        assert_eq!(adjust_idle_lock(60, -1), 60);
        assert_eq!(adjust_idle_lock(3600, 1), 3600);
        // Hand-edited / stale values are clamped back into the valid range.
        assert_eq!(adjust_idle_lock(0, 0), 60);
        assert_eq!(adjust_idle_lock(10_000, 0), 3600);
    }

    #[test]
    fn threshold_adjustment_steps_and_clamps() {
        let base = Thresholds::default();
        let up = adjust_thresholds(base, 1);
        assert_eq!(up.weak_bits, base.weak_bits + 5);
        assert_eq!(up.stale_days, base.stale_days + 30);

        let down = adjust_thresholds(base, -1);
        assert_eq!(down.weak_bits, base.weak_bits - 5);
        assert_eq!(down.stale_days, base.stale_days - 30);

        let at_max = Thresholds {
            weak_bits: 199,
            stale_days: 3640,
        };
        let clamped = adjust_thresholds(at_max, 1);
        assert_eq!(clamped.weak_bits, 200);
        assert_eq!(clamped.stale_days, 3650);

        let at_min = Thresholds {
            weak_bits: 2,
            stale_days: 10,
        };
        let clamped = adjust_thresholds(at_min, -1);
        assert_eq!(clamped.weak_bits, 1);
        assert_eq!(clamped.stale_days, 1);
    }
}

#[cfg(test)]
mod seconds_tests {
    use super::*;

    #[test]
    fn seconds_adjustments_clamp_to_one_and_3600() {
        assert_eq!(adjust_seconds(30, 1), 31);
        assert_eq!(adjust_seconds(30, -1), 29);
        assert_eq!(adjust_seconds(1, -1), 1);
        assert_eq!(adjust_seconds(3600, 1), 3600);
        assert_eq!(adjust_seconds(0, 0), 1);
        assert_eq!(adjust_seconds(u64::MAX, -1), 3600);
    }

    #[test]
    fn adjust_seconds_saturates_large_values_before_clamping() {
        let max = crate::limits::MAX_LOGIN_TIMEOUT_SECONDS;
        // Overflow cases: the `u64::MAX` sentinel and the largest valid `i64`
        // both overflow on `+ 1`, which used to panic in debug builds.
        assert_eq!(adjust_seconds(u64::MAX, 1), max);
        assert_eq!(adjust_seconds(u64::MAX, i32::MAX), max);
        assert_eq!(adjust_seconds(i64::MAX as u64, 1), max);
        // Normal steps are unchanged.
        assert_eq!(adjust_seconds(30, 1), 31);
    }
}
