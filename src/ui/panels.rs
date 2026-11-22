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

/// Scroll guidance for panels with no keyboard-reachable scroll handle.
///
/// Only `audit_panel` receives a `ScrollHandle`, and only the vault list owns
/// `VaultViewState::scroll_handle`. The generator and settings roots keep their
/// offset in element state, so there is no handle for `ui::input` to scroll on
/// Up/Down; adding one would require new state outside this module. Up/Down
/// therefore stay `UiAction::None` in those panels, and the inline hints say
/// so explicitly instead of implying a keyboard path exists.
pub(super) const MOUSE_WHEEL_SCROLL_ONLY_HINT: &str = "スクロールはマウス／ホイールのみ";

/// Labels for the two `+/-` rows in the generator panel.
///
/// Both labels explicitly say that the same key changes the *other* generator
/// setting too; `apply_generator_key` truly mutates both values at once.
pub(super) fn generator_length_labels(
    password_len: usize,
    words: usize,
    pw_bits: f64,
    pp_bits: f64,
    separator: &str,
) -> (String, String) {
    let password_label = format!(
        "+/-  長さ: {password_len}（パスフレーズ語数も同時に変更）  |  強度: {} ({pw_bits:.0} bit)",
        Strength::from_bits(pw_bits).label()
    );
    let passphrase_label = format!(
        "+/-  単語数: {words}（パスワード長も同時に変更）  |  ,  区切り: {}  |  強度: {} ({pp_bits:.0} bit)",
        separator_label(separator),
        Strength::from_bits(pp_bits).label()
    );
    (password_label, passphrase_label)
}

/// Inline key hint for the generator panel, including its scroll limitation.
///
/// Pure so the wording can be pinned by tests without rendering a GPUI window.
pub(super) fn generator_panel_key_hint(clipboard_restore_seconds: u64) -> String {
    format!(
        "p/h: 生成 / y: パスワードをコピー / Y: パスフレーズをコピー（{clipboard_restore_seconds}秒で復元） / w: 設定を保存 / d: 破棄 / n: 一覧に戻る / l: ロック / Esc: 終了 / {MOUSE_WHEEL_SCROLL_ONLY_HINT}"
    )
}

/// Inline key hint for the settings panel, including its scroll limitation.
///
/// `settings_hint` already carries the settings-specific keys and avoids the
/// status bar's "入力中:" prefix; appending the scroll note must not reintroduce
/// that prefix here.
pub(super) fn settings_panel_key_hint(editing: bool) -> String {
    format!(
        "{} / {}",
        settings_hint(editing),
        MOUSE_WHEEL_SCROLL_ONLY_HINT
    )
}

/// Colour for a finding's severity on an unselected audit row.
fn severity_color(severity: Severity) -> u32 {
    match severity {
        Severity::High => 0xf38ba8,
        Severity::Medium => 0xf9e2af,
        Severity::Low => 0xa6adc8,
    }
}

/// Brighter severity tints for the selected audit row.
///
/// Selecting a row swaps its background from `0x1e1e2e` to `0x45475a`. The
/// normal high (`~3.9:1`) and low (`~4.1:1`) tints then fall below WCAG 1.4.3's
/// 4.5:1 minimum for small text. These variants keep the same hues while
/// clearing that threshold; medium already clears it and keeps its colour.
const SELECTED_HIGH_SEVERITY_COLOR: u32 = 0xffb3c8;
const SELECTED_LOW_SEVERITY_COLOR: u32 = 0xcdd6f4;

fn severity_color_for_row(severity: Severity, selected: bool) -> u32 {
    if selected {
        match severity {
            Severity::High => SELECTED_HIGH_SEVERITY_COLOR,
            Severity::Medium => severity_color(Severity::Medium),
            Severity::Low => SELECTED_LOW_SEVERITY_COLOR,
        }
    } else {
        severity_color(severity)
    }
}

/// Audit row text with a non-colour marker for the highlighted row.
///
/// The selection background alone cannot be distinguished by colour-blind
/// users. A leading triangle mirrors the header tabs' `panel_button_label`
/// cue, so selection stays readable without colour perception.
pub(super) fn audit_row_label(text: &str, selected: bool) -> String {
    if selected {
        format!("▶ {text}")
    } else {
        text.to_string()
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

/// Detail line below the audit summary.
///
/// The row-selection keys only describe a real path when the report has rows.
/// On an empty report they promised keys that select nothing, so that case now
/// shows an explicit empty state instead. Kept pure so the wording can be
/// tested without rendering a GPUI window.
pub(super) fn audit_panel_detail_line(report: &Report, dirty: bool) -> String {
    let base = format!(
        "{} TOTP 設定済み: {}/{} ({:.0}%)",
        unsaved_marker(dirty),
        report.with_totp,
        report.logins,
        report.totp_coverage() * 100.0
    );
    if report.items.is_empty() {
        format!("{base} / 監査する問題はありません / g: 一覧 / l: ロック / Esc: 終了")
    } else {
        format!("{base} / ↑↓: 行を選択 / Enter: 対象を選択 / 行クリックでも選択 / g: 一覧 / l: ロック / Esc: 終了")
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
        .child(
            div()
                .text_xs()
                .text_color(rgb(0xa6adc8))
                .child(audit_panel_detail_line(report, dirty)),
        );
    for (index, item) in report.items.iter().enumerate() {
        let is_selected = selected == Some(index);
        let color = rgb(match item.worst() {
            Some(severity) => severity_color_for_row(severity, is_selected),
            // An item in the report has findings; keep the fallback readable
            // on the lighter selected background if that ever changes.
            None if is_selected => SELECTED_LOW_SEVERITY_COLOR,
            None => 0xa6adc8,
        });
        let id = item.id.clone();
        let focus = focus.clone();
        panel = panel.child(
            div()
                .id(SharedString::from(format!("audit-row-{id}")))
                .mt_2()
                .bg(if is_selected {
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
                        .child(audit_row_label(
                            &format!(
                                "[{}] {} ({})",
                                item.worst().map_or("?", Severity::label),
                                item.name,
                                item.kind.label()
                            ),
                            is_selected,
                        )),
                )
                .children(item.findings.iter().map(|finding| {
                    let severity = finding.severity();
                    div()
                        .text_xs()
                        .pl_4()
                        .text_color(rgb(severity_color_for_row(severity, is_selected)))
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

/// Human-readable label for the passphrase separator.
///
/// `{:?}` on the `String` adds quotes (`"-"`), which reads like a literal
/// token instead of the character actually placed between words. The empty
/// separator is named explicitly so a concatenated passphrase is not mistaken
/// for a missing value.
pub(super) fn separator_label(separator: &str) -> &str {
    if separator.is_empty() {
        "(なし)"
    } else {
        separator
    }
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
    let (password_label, passphrase_label) = generator_length_labels(
        password.length,
        passphrase.words,
        pw_bits,
        pp_bits,
        &passphrase.separator,
    );
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
        .child(
            div()
                .text_sm()
                .text_color(rgb(0xa6adc8))
                .child(password_label),
        )
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
        .child(
            div()
                .text_sm()
                .text_color(rgb(0xa6adc8))
                .child(passphrase_label),
        )
        .child(result_row(
            "h  生成",
            state.last_passphrase.as_ref().map(|value| value.as_str()),
        ))
        .child(
            div()
                .text_sm()
                .text_color(if dirty { rgb(0xf9e2af) } else { rgb(0xa6adc8) })
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
                .child(generator_panel_key_hint(settings.clipboard_restore_seconds)),
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
                // The editing state and arrow-key ownership are announced
                // once by the status bar (`text_edit_start_status`). The
                // helper appends only the scroll note to the settings-specific
                // hint, so no second "入力中:" line is drawn here.
                .child(settings_panel_key_hint(editing.is_some())),
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
    fn generator_length_labels_state_both_values_change_together() {
        let (password, passphrase) = generator_length_labels(20, 4, 100.0, 40.0, "-");
        assert!(
            password.contains("パスフレーズ語数も同時に変更"),
            "{password}"
        );
        assert!(
            passphrase.contains("パスワード長も同時に変更"),
            "{passphrase}"
        );
        assert!(password.contains("長さ: 20"), "{password}");
        assert!(passphrase.contains("単語数: 4"), "{passphrase}");
    }

    #[::core::prelude::v1::test]
    fn panels_without_a_scroll_handle_advertise_mouse_wheel_only() {
        let generator = generator_panel_key_hint(30);
        assert!(
            generator.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT),
            "{generator}"
        );
        assert!(generator.contains("30秒で復元"), "{generator}");
        assert!(generator.contains("p/h: 生成"), "{generator}");

        for editing in [false, true] {
            let settings = settings_panel_key_hint(editing);
            assert!(
                settings.contains(MOUSE_WHEEL_SCROLL_ONLY_HINT),
                "{settings}"
            );
            assert!(settings.contains(settings_hint(editing)), "{settings}");
            assert!(
                !settings.starts_with("入力中:"),
                "the inline hint must not repeat the status-bar prefix: {settings}"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn generator_key_hint_names_the_two_copy_targets() {
        // The hint must mirror the key bindings in `ui::keys`: y copies the
        // generated password, Y copies the generated passphrase.
        let hint = generator_panel_key_hint(30);
        assert!(hint.contains("y: パスワードをコピー"), "{hint}");
        assert!(hint.contains("Y: パスフレーズをコピー"), "{hint}");
        assert!(!hint.contains("y/Y: コピー"), "{hint}");
        assert!(hint.contains("30秒で復元"), "{hint}");
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

    #[::core::prelude::v1::test]
    fn selected_audit_row_severity_colours_meet_text_contrast() {
        const SELECTED_BG: u32 = 0x45475a;
        const UNSELECTED_BG: u32 = 0x1e1e2e;

        for severity in [Severity::High, Severity::Medium, Severity::Low] {
            // Unselected rows keep the established palette.
            assert_eq!(
                severity_color_for_row(severity, false),
                severity_color(severity)
            );

            // The original high/low tints are the regression: below 4.5:1 on
            // the lighter selected background. Medium already clears it.
            if severity != Severity::Medium {
                assert!(
                    contrast_ratio(severity_color(severity), SELECTED_BG) < 4.5,
                    "the unselected {severity:?} tint should be the low-contrast case"
                );
            }

            let selected = severity_color_for_row(severity, true);
            assert!(
                contrast_ratio(selected, SELECTED_BG) >= 4.5,
                "{severity:?} must reach WCAG 1.4.3 text contrast on the selected row"
            );
            // Moving the highlight must not make the bright tint unreadable.
            assert!(
                contrast_ratio(selected, UNSELECTED_BG) >= 4.5,
                "{severity:?} selected tint must stay readable after the highlight moves"
            );
        }

        // Pin the exact tints so a future palette tweak cannot silently undo
        // the fix while still passing the ratio assertions above.
        assert_eq!(severity_color_for_row(Severity::High, true), 0xffb3c8);
        assert_eq!(severity_color_for_row(Severity::Medium, true), 0xf9e2af);
        assert_eq!(severity_color_for_row(Severity::Low, true), 0xcdd6f4);
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
                text: String::new().into(),
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
                text: String::new().into(),
            },
        );
        let absent = totp_badge(&note);
        assert_eq!(absent.color_for_row(true), absent.color);
    }

    #[::core::prelude::v1::test]
    fn separator_label_is_readable_without_debug_quotes() {
        assert_eq!(separator_label("-"), "-");
        assert_eq!(separator_label("."), ".");
        assert_eq!(separator_label("_"), "_");
        assert_eq!(separator_label(""), "(なし)");
        assert_ne!(separator_label("-"), "\"-\"");
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

    #[::core::prelude::v1::test]
    fn audit_panel_detail_line_hides_row_keys_on_an_empty_report() {
        let empty = audit_panel_detail_line(&Report::default(), false);
        assert!(empty.contains("監査する問題はありません"), "{empty}");
        assert!(!empty.contains("↑↓"), "{empty}");
        assert!(!empty.contains("Enter: 対象を選択"), "{empty}");
        assert!(!empty.contains("行クリックでも選択"), "{empty}");
        assert!(empty.contains("TOTP 設定済み"), "{empty}");
        assert!(empty.contains("g: 一覧 / l: ロック / Esc: 終了"), "{empty}");

        let with_rows = Report {
            items: vec![crate::health::ItemReport {
                id: "item-1".into(),
                name: "Example".into(),
                kind: crate::model::ItemKind::Login,
                findings: Vec::new(),
            }],
            examined: 1,
            with_totp: 1,
            logins: 1,
        };
        let line = audit_panel_detail_line(&with_rows, true);
        assert!(line.contains("↑↓: 行を選択"), "{line}");
        assert!(line.contains("Enter: 対象を選択"), "{line}");
        assert!(line.contains("行クリックでも選択"), "{line}");
        assert!(!line.contains("監査する問題はありません"), "{line}");
        assert!(line.contains(unsaved_marker(true)), "{line}");
        assert!(line.contains("TOTP 設定済み: 1/1 (100%)"), "{line}");
    }

    #[::core::prelude::v1::test]
    fn selected_audit_row_has_a_non_colour_marker() {
        let base = "[高] Example (Login)";
        assert_eq!(audit_row_label(base, false), base);
        assert_eq!(audit_row_label(base, true), format!("▶ {base}"));
        assert!(audit_row_label(base, true).starts_with("▶ "));
        assert_ne!(audit_row_label(base, true), audit_row_label(base, false));
    }
}
