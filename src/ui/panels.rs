//! Panel renderers and small row helpers used by the GPUI window.

use gpui_kit::prelude::*;
use gpui_kit::*;

use crate::generator::{passphrase_entropy, password_entropy, Strength};
use crate::health::{Report, Severity};
use crate::settings::Settings;
use crate::ui::state::{GeneratorState, Panel, SettingsField};

// Scrollable panel roots share the same pattern: a stable id keeps the scroll
// offset in element state across frames, min_h_0 lets the flex item shrink
// below its content height, and overflow_y_scroll keeps every row reachable
// when the window is short.
pub(super) fn audit_panel<'a>(report: &'a Report) -> impl IntoElement + 'a {
    let mut panel = div()
        .id("audit-panel-scroll")
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
                    rgb(0x6c7086)
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
                .mt_4()
                .text_xs()
                .text_color(rgb(0x6c7086))
                .child(format!(
                    "p/h: 生成 / y/Y: コピー（{}秒で復元） / n: 一覧に戻る / l: ロック / Esc: 終了",
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
                    rgb(0x6c7086)
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
                .text_color(rgb(0x6c7086))
                .child(format!("保存先: {path}")),
        )
        .child(div().mt_4().text_xs().text_color(rgb(0x6c7086)).child(
            "1,2: 編集 / +/-: 閾値 / i/u: 自動ロック / 3,4: ログイン制限 / 5,6: 復元 / w: 保存 / c: 戻る / l: ロック / Esc: 確定/終了",
        ))
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
    div()
        .id(SharedString::from(format!("panel-button-{label}")))
        .px_2()
        .py_1()
        .rounded_md()
        .bg(if active { rgb(0x45475a) } else { rgb(0x313244) })
        .text_color(if active { rgb(0xcdd6f4) } else { rgb(0xa6adc8) })
        .text_xs()
        .on_click(cx.listener(move |this, _event, _window, cx| {
            select(this, cx);
        }))
        .child(label.to_string())
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
                    rgb(0x6c7086)
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
