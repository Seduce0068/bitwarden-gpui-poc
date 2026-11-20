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
/// `None` is valid: the UI falls back to showing the first item.
pub(super) fn selection_in_view<'a>(
    selected_id: Option<&str>,
    ids: impl IntoIterator<Item = &'a str>,
) -> bool {
    match selected_id {
        None => true,
        Some(id) => ids.into_iter().any(|candidate| candidate == id),
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

/// Status text after a successful login.
///
/// A vault restored from the encrypted offline cache may be stale (the sync
/// call failed), so the status says so instead of implying fresh data.
pub(super) fn login_success_status(count: usize, from_cache: bool) -> String {
    let base = format!("ログイン成功: {count} 件のログインを読み込みました");
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
    let current_minutes = (current_seconds / 60).clamp(1, 60) as i64;
    let next = (current_minutes + i64::from(delta_minutes)).clamp(1, 60);
    (next * 60) as u64
}

/// Adjust a seconds-based setting by one UI step, clamped to 1..=3600.
pub(super) fn adjust_seconds(current: u64, delta_seconds: i32) -> u64 {
    let next = i64::try_from(current).unwrap_or(i64::MAX) + i64::from(delta_seconds);
    next.clamp(1, 3600) as u64
}

/// Adjust audit thresholds by one UI step, clamping to safe bounds:
/// 1..=200 bits and 1..=3650 days.
///
/// `delta` is +1 for `+`/`=` and -1 for `-`/`_`.
pub(super) fn adjust_thresholds(current: Thresholds, delta: i32) -> Thresholds {
    let weak_step = delta.saturating_mul(5);
    let day_step = delta.saturating_mul(30);
    Thresholds {
        weak_bits: if weak_step > 0 {
            current.weak_bits.saturating_add(weak_step as u32).min(200)
        } else {
            current
                .weak_bits
                .saturating_sub(weak_step.unsigned_abs())
                .max(1)
        },
        stale_days: if day_step > 0 {
            current.stale_days.saturating_add(day_step as i64).min(3650)
        } else {
            current
                .stale_days
                .saturating_sub(day_step.unsigned_abs() as i64)
                .max(1)
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
            text: "body".to_string(),
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
        assert_eq!(fresh, "ログイン成功: 3 件のログインを読み込みました");

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
}
