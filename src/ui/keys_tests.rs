#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::ui::keys::*;

fn ctx(key: &str) -> KeyContext<'_> {
    KeyContext {
        screen: Screen::Unlocked,
        panel: Panel::Vault,
        key,
        editing_auth: false,
        searching: false,
        editing_settings: false,
        login_failed: false,
        has_audit_report: true,
        query_nonempty: false,
    }
}

#[::core::prelude::v1::test]
fn text_editing_actions_are_mode_specific() {
    let mut value = ctx("a");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::InsertSearchChar('a'));

    value.key = "backspace";
    assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    value.key = "b";
    assert_eq!(classify_key(&value), KeyAction::InsertSettingsChar('b'));

    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), KeyAction::InsertAuthChar('b'));
    value.key = "backspace";
    assert_eq!(classify_key(&value), KeyAction::BackspaceAuth);

    value.screen = Screen::Unlocked;
    value.panel = Panel::Vault;
    value.editing_auth = false;
    value.editing_settings = false;
    value.query_nonempty = true;
    assert_eq!(classify_key(&value), KeyAction::BackspaceQuery);
}

#[::core::prelude::v1::test]
fn finish_actions_are_mode_specific() {
    let mut value = ctx("enter");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::FinishSearch);

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(classify_key(&value), KeyAction::FinishSettingsEdit);

    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), KeyAction::FinishAuthEdit);
}

#[test]
fn lock_screen_keys_and_retry_gate() {
    let mut value = ctx("enter");
    value.screen = Screen::Locked;
    assert_eq!(classify_key(&value), KeyAction::Authenticate);

    value.key = "m";
    assert_eq!(classify_key(&value), KeyAction::OpenDemoVault);

    value.key = "r";
    assert_eq!(classify_key(&value), KeyAction::None);
    value.login_failed = true;
    assert_eq!(classify_key(&value), KeyAction::RetryLogin);

    value.key = "4";
    assert_eq!(
        classify_key(&value),
        KeyAction::EditAuthField(AuthField::ClientSecret)
    );
}

#[::core::prelude::v1::test]
fn generator_keys_toggle_options_and_clamp_lengths() {
    let mut state = GeneratorState::default();
    assert!(apply_generator_key(&mut state, "1"));
    assert!(!state.password.lowercase);
    assert!(apply_generator_key(&mut state, "6"));
    assert!(!state.passphrase.capitalize);

    assert!(apply_generator_key(&mut state, "+"));
    assert_eq!(state.password.length, 21);
    assert_eq!(state.passphrase.words, 5);
    assert!(apply_generator_key(&mut state, "-"));
    assert_eq!(state.password.length, 20);

    assert!(apply_generator_key(&mut state, ","));
    assert_eq!(state.passphrase.separator, ".");
    assert!(apply_generator_key(&mut state, ","));
    assert_eq!(state.passphrase.separator, "_");

    assert!(!apply_generator_key(&mut state, "q"));
}

#[test]
fn vault_keys_map_to_actions() {
    assert_eq!(classify_key(&ctx("up")), KeyAction::MoveSelection(-1));
    assert_eq!(classify_key(&ctx("down")), KeyAction::MoveSelection(1));
    assert_eq!(classify_key(&ctx("f")), KeyAction::ToggleFavorite);
    assert_eq!(classify_key(&ctx("y")), KeyAction::CopyTotp);
    assert_eq!(classify_key(&ctx("g")), KeyAction::OpenAudit);
    assert_eq!(classify_key(&ctx("/")), KeyAction::StartSearch);
    assert_eq!(
        classify_key(&ctx("c")),
        KeyAction::SetPanel(Panel::Settings)
    );
    assert_eq!(classify_key(&ctx("q")), KeyAction::None);
}

#[test]
fn settings_and_generator_keys() {
    let mut value = ctx("w");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), KeyAction::SaveSettings);
    value.key = "+";
    assert_eq!(classify_key(&value), KeyAction::AdjustThreshold(1));
    value.key = "i";
    assert_eq!(classify_key(&value), KeyAction::AdjustIdleLock(1));
    value.key = "u";
    assert_eq!(classify_key(&value), KeyAction::AdjustIdleLock(-1));

    value.panel = Panel::Generator;
    value.key = "p";
    assert_eq!(classify_key(&value), KeyAction::GeneratePassword);
    value.key = "Y";
    assert_eq!(classify_key(&value), KeyAction::CopyPassphrase);
    value.key = "-";
    assert_eq!(classify_key(&value), KeyAction::AdjustLength(-1));
}

#[test]
fn editing_mode_swallows_shortcut_keys() {
    let mut value = ctx("l");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::InsertSearchChar('l'));

    let mut value = ctx("enter");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::FinishSearch);

    let mut value = ctx("backspace");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);
}
