//! Panel renderers and small row helpers used by the GPUI window.

use gpui_kit::prelude::*;
use gpui_kit::StatefulInteractiveElement;
use gpui_kit::*;

use crate::generator::{passphrase_entropy, password_entropy, Strength};
use crate::health::{has_totp_field, has_usable_totp, Report, Severity};
use crate::settings::Settings;
use crate::ui::logic::{settings_hint, unsaved_marker};
use crate::ui::state::{GeneratorState, Panel, SettingsField};
use crate::vault_sync::is_undecryptable_totp;

/// Number of header rows rendered before the first audit item.
pub(super) const AUDIT_HEADER_ROWS: usize = 3;

/// Colour for a finding's severity, shared by the item header and its rows.
fn severity_color(severity: Severity) -> u32 {
    match severity {
        Severity::High => 0xf38ba8,
        Severity::Medium => 0xf9e2af,
        Severity::Low => 0xa6adc8,
    }
}

/// The status of a TOTP badge in the vault list.
///
/// Uses the public health predicates added for this purpose so the list, the
/// audit counter and the `NoTotp` finding share one definition of "usable".
/// A field that exists but is malformed or undecryptable is shown as `不正`
/// / `不可`, never as a healthy `TOTP` badge.
pub(super) struct TotpBadge {
    pub(super) label: &'static str,
    pub(super) color: u32,
}

/// Brighter `不正`/`不可` badge colour for a selected row.
///
/// The normal rose `0xf38ba8` is only ~3.9:1 against the selected row
/// background `0x45475a`, below WCAG 1.4.3 for small text. This tint is
/// ~5.4:1 while still reading as the same warning.
const SELECTED_INVALID_TOTP_COLOR: u32 = 0xffb3c8;

impl TotpBadge {
    /// Foreground colour for this badge on the row it is drawn in.
    pub(super) fn color_for_row(&self, selected: bool) -> u32 {
        if selected && matches!(self.label, "不正" | "不可") {
            SELECTED_INVALID_TOTP_COLOR
        } else {
            self.color
        }
    }
}

pub(super) fn totp_badge(item: &crate::model::VaultItem) -> TotpBadge {
    if has_usable_totp(item) {
        TotpBadge {
            label: "TOTP",
            color: 0xa6e3a1,
        }
    } else if has_totp_field(item) {
        TotpBadge {
            label: if item.totp_secret().is_some_and(is_undecryptable_totp) {
                "不可"
            } else {
                "不正"
            },
            color: 0xf38ba8,
        }
    } else {
        TotpBadge {
            label: "",
            color: 0xa6adc8,
        }
    }
}

// Scrollable panel roots share the same pattern: a stable id keeps the scroll
// offset in element state across frames, min_h_0 lets the flex item shrink
// below its content height, and overflow_y_scroll keeps every row reachable
// when the window is short.
pub(super) fn audit_panel<'a, V: 'static>(
    report: &'a Report,
    selected: Option<usize>,
    dirty: bool,
    scroll_handle: &'a ScrollHandle,
    on_focus: impl Fn(&mut V, &str, &mut Context<V>) + 'static,
    cx: &mut Context<V>,
) -> impl IntoElement + 'a {
    let focus = std::rc::Rc::new(on_focus);
    let mut panel = div()
        .id("audit-panel-scroll")
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
        .min_h_0()
        .overflow_y_scroll()
        .track_scroll(scroll_handle)
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
        .child(div().text_xs().text_color(rgb(0xa6adc8)).child(format!(
            "{} TOTP 設定済み: {}/{} ({:.0}%) / ↑↓: 行を選択 / Enter: 対象を選択 / 行クリックでも選択 / g: 一覧 / l: ロック / Esc: 終了",
            unsaved_marker(dirty),
            report.with_totp,
            report.logins,
            report.totp_coverage() * 100.0
        )));
    for (index, item) in report.items.iter().enumerate() {
        let color = rgb(item.worst().map_or(0xa6adc8, severity_color));
        let id = item.id.clone();
        let focus = focus.clone();
        panel = panel.child(
            div()
                .id(SharedString::from(format!("audit-row-{id}")))
                .mt_2()
                .bg(if selected == Some(index) {
                    rgb(0x45475a)
                } else {
                    rgb(0x1e1e2e)
                })
                .on_click(cx.listener(move |this, _event, _window, cx| {
                    focus(this, &id, cx);
                }))
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
                    let severity = finding.severity();
                    div()
                        .text_xs()
                        .pl_4()
                        .text_color(rgb(severity_color(severity)))
                        .child(format!("- [{}] {}", severity.label(), finding.message()))
                })),
        );
    }
    panel
}

pub(super) fn setting_row<'a>(label: &'a str, enabled: bool) -> impl IntoElement + 'a {
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
                    rgb(0xa6adc8)
                })
                .child(if enabled { "ON" } else { "OFF" }),
        )
}

pub(super) fn result_row<'a>(label: &'a str, value: Option<&'a str>) -> impl IntoElement + 'a {
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

pub(super) fn generator_panel<'a>(
    settings: &'a Settings,
    state: &'a GeneratorState,
    dirty: bool,
) -> impl IntoElement + 'a {
    let password = &settings.password_generator;
    let passphrase = &settings.passphrase_generator;
    let pw_bits = password_entropy(password);
    let pp_bits = passphrase_entropy(passphrase);
    div()
        .id("generator-panel-scroll")
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
        .min_h_0()
        .overflow_y_scroll()
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
        .child(result_row(
            "p  生成",
            state.last_password.as_ref().map(|value| value.as_str()),
        ))
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
        .child(result_row(
            "h  生成",
            state.last_passphrase.as_ref().map(|value| value.as_str()),
        ))
        .child(
            div()
                .text_sm()
                .text_color(if dirty {
                    rgb(0xf9e2af)
                } else {
                    rgb(0xa6adc8)
                })
                .child(format!(
                    "{} {}",
                    unsaved_marker(dirty),
                    if dirty {
                        "生成設定は未保存です（w: 保存 / d: 破棄）"
                    } else {
                        "未保存の設定変更はありません"
                    }
                )),
        )
        .child(
            div()
                .mt_4()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(format!(
                    "p/h: 生成 / y/Y: コピー（{}秒で復元） / w: 設定を保存 / d: 破棄 / n: 一覧に戻る / l: ロック / Esc: 終了",
                    settings.clipboard_restore_seconds
                )),
        )
}

pub(super) fn field_row<'a>(
    label: &'a str,
    value: &'a str,
    editing: bool,
) -> impl IntoElement + 'a {
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(170.0))
                .text_color(if editing {
                    rgb(0x89b4fa)
                } else {
                    rgb(0xa6adc8)
                })
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

pub(super) fn settings_panel<'a>(
    settings: &'a Settings,
    editing: Option<SettingsField>,
    dirty: bool,
) -> impl IntoElement + 'a {
    let server_url = settings.server_url.as_str();
    let email = settings.email.as_str();
    let path = Settings::default_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(設定ディレクトリを特定できません)".to_string());
    div()
        .id("settings-panel-scroll")
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .flex_1()
        .min_h_0()
        .overflow_y_scroll()
        .child(div().text_lg().font_weight(FontWeight::BOLD).child("設定"))
        .child(
            div()
                .text_sm()
                .text_color(if dirty { rgb(0xf9e2af) } else { rgb(0xa6adc8) })
                .child(format!(
                    "{} {}",
                    unsaved_marker(dirty),
                    if dirty {
                        "未保存の変更があります（w: 保存 / d: 破棄）"
                    } else {
                        "未保存の変更はありません"
                    }
                )),
        )
        .child(field_row(
            "1  サーバー URL",
            server_url,
            editing == Some(SettingsField::ServerUrl),
        ))
        .child(field_row(
            "2  メール",
            email,
            editing == Some(SettingsField::Email),
        ))
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "生成設定: パスワード {} 文字 / パスフレーズ {} 語（一覧で n キー）",
            settings.password_generator.length, settings.passphrase_generator.words
        )))
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "監査閾値: 弱パスワード < {} bit / 更新が古い: {} 日以上",
            settings.thresholds.weak_bits, settings.thresholds.stale_days
        )))
        .child(div().text_sm().text_color(rgb(0xa6adc8)).child(format!(
            "自動ロック: {} 分（i/u） / ログイン制限: {} 秒（3/4） / 復元: {} 秒（5/6）",
            settings.idle_lock_seconds / 60,
            settings.login_timeout_seconds,
            settings.clipboard_restore_seconds
        )))
        .child(
            div()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(format!("保存先: {path}")),
        )
        .child(
            div()
                .mt_4()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(settings_hint(editing.is_some())),
        )
}

/// Label shown on a header tab, with a non-colour marker when it is active.
///
/// Colour alone cannot convey the active tab. A leading triangle (together
/// with the bold weight applied in `panel_button`) keeps the state readable
/// without relying on colour perception.
pub(super) fn panel_button_label(label: &str, active: bool) -> String {
    if active {
        format!("▶ {label}")
    } else {
        label.to_string()
    }
}

pub(super) fn panel_button<V: 'static>(
    label: &str,
    panel: Panel,
    current: Panel,
    on_select: impl Fn(&mut V, &mut Context<V>) + 'static,
    cx: &mut Context<V>,
) -> AnyElement {
    let active = panel == current;
    let select = std::rc::Rc::new(on_select);
    // Derive the identity from the original label so switching tabs does not
    // recreate the element: only the drawn text gets the active marker.
    let id = SharedString::from(format!("panel-button-{label}"));
    div()
        .id(id)
        .px_2()
        .py_1()
        .rounded_md()
        .bg(if active { rgb(0x45475a) } else { rgb(0x313244) })
        .text_color(if active { rgb(0xcdd6f4) } else { rgb(0xa6adc8) })
        .font_weight(if active {
            FontWeight::BOLD
        } else {
            FontWeight::NORMAL
        })
        .text_xs()
        .on_click(cx.listener(move |this, _event, _window, cx| {
            select(this, cx);
        }))
        .child(panel_button_label(label, active))
        .into_any_element()
}

pub(super) fn auth_row<'a>(
    label: &'a str,
    value: &'a str,
    editing: bool,
    secret: bool,
) -> impl IntoElement + 'a {
    let shown = if value.is_empty() {
        "(未入力)".to_string()
    } else if secret {
        // Never render secret values in plain text, not even while editing.
        let masked = "•".repeat(value.chars().count());
        format!("{masked}{}", if editing { " _" } else { "" })
    } else {
        format!("{value}{}", if editing { " _" } else { "" })
    };
    div()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(150.0))
                .text_color(if editing {
                    rgb(0x89b4fa)
                } else {
                    rgb(0xa6adc8)
                })
                .child(label.to_string()),
        )
        .child(
            div()
                .flex_1()
                .text_color(if editing {
                    rgb(0xf9e2af)
                } else {
                    rgb(0xcdd6f4)
                })
                .child(shown),
        )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn channel_luminance(rgb: u32, shift: u32) -> f64 {
        let value = ((rgb >> shift) & 0xff) as f64 / 255.0;
        if value <= 0.03928 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    }

    fn relative_luminance(rgb: u32) -> f64 {
        0.2126 * channel_luminance(rgb, 16)
            + 0.7152 * channel_luminance(rgb, 8)
            + 0.0722 * channel_luminance(rgb, 0)
    }

    fn contrast_ratio(foreground: u32, background: u32) -> f64 {
        let fg = relative_luminance(foreground);
        let bg = relative_luminance(background);
        let (light, dark) = if fg > bg { (fg, bg) } else { (bg, fg) };
        (light + 0.05) / (dark + 0.05)
    }

    #[::core::prelude::v1::test]
    fn severity_colours_are_distinct() {
        assert_eq!(severity_color(Severity::High), 0xf38ba8);
        assert_eq!(severity_color(Severity::Medium), 0xf9e2af);
        assert_eq!(severity_color(Severity::Low), 0xa6adc8);
        assert_ne!(
            severity_color(Severity::High),
            severity_color(Severity::Medium)
        );
    }

    fn login_with_totp(secret: &str) -> crate::model::VaultItem {
        use crate::model::ItemData;
        use zeroize::Zeroizing;

        crate::model::VaultItem::new(
            "id",
            "name",
            ItemData::Login {
                username: String::new(),
                password: Zeroizing::new(String::new()),
                totp: Zeroizing::new(secret.to_string()),
                uris: Vec::new(),
            },
        )
    }

    #[::core::prelude::v1::test]
    fn totp_badge_distinguishes_valid_invalid_undecryptable_and_absent_secrets() {
        use crate::model::ItemData;

        let valid = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_badge(&login_with_totp(valid)).label, "TOTP");
        assert_eq!(totp_badge(&login_with_totp("not base32!")).label, "不正");
        assert_eq!(
            totp_badge(&login_with_totp(crate::vault_sync::UNDECRYPTABLE_TOTP)).label,
            "不可"
        );
        assert_ne!(
            totp_badge(&login_with_totp(valid)).color,
            totp_badge(&login_with_totp("not base32!")).color
        );

        let note = crate::model::VaultItem::new(
            "note",
            "note",
            ItemData::SecureNote {
                text: String::new(),
            },
        );
        assert_eq!(totp_badge(&note).label, "");
        assert_eq!(totp_badge(&login_with_totp("")).label, "");
    }

    #[::core::prelude::v1::test]
    fn selected_row_invalid_totp_badge_meets_text_contrast() {
        const SELECTED_BG: u32 = 0x45475a;
        let invalid = totp_badge(&login_with_totp("not base32!"));
        let undecryptable = totp_badge(&login_with_totp(crate::vault_sync::UNDECRYPTABLE_TOTP));

        // The original colour is the bug: below 4.5:1 on the selected row.
        assert!(contrast_ratio(invalid.color, SELECTED_BG) < 4.5);
        assert!(contrast_ratio(undecryptable.color, SELECTED_BG) < 4.5);

        for badge in [&invalid, &undecryptable] {
            assert_eq!(badge.color_for_row(false), badge.color);
            assert!(
                contrast_ratio(badge.color_for_row(true), SELECTED_BG) >= 4.5,
                "badge {:?} must stay readable on the selected row",
                badge.label
            );
        }

        // Healthy and absent badges keep their existing colours on both rows.
        let valid = totp_badge(&login_with_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert_eq!(valid.color_for_row(true), valid.color);
        let note = crate::model::VaultItem::new(
            "note",
            "note",
            crate::model::ItemData::SecureNote {
                text: String::new(),
            },
        );
        let absent = totp_badge(&note);
        assert_eq!(absent.color_for_row(true), absent.color);
    }

    #[::core::prelude::v1::test]
    fn active_header_tab_has_a_non_colour_marker() {
        assert_eq!(panel_button_label("[一覧]", true), "▶ [一覧]");
        assert_eq!(panel_button_label("[一覧]", false), "[一覧]");
        assert_ne!(
            panel_button_label("[一覧]", true),
            panel_button_label("[一覧]", false)
        );
        // Every tab label gets the same cue, including the audit placeholder.
        assert!(panel_button_label("[監査 (未生成)]", true).starts_with("▶ "));
    }
}
