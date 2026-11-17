#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::settings::Settings;
use crate::ui::keys::*;

fn ctx(key: &str) -> KeyContext<'_> {
    KeyContext {
        screen: Screen::Unlocked,
        panel: Panel::Vault,
        key,
        key_char: None,
        modifiers: KeyModifiers::default(),
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
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSearchText("a".into())
    );

    value.key = "backspace";
    assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    value.key = "b";
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSettingsText("b".into())
    );

    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), KeyAction::InsertAuthText("b".into()));
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
    let mut state = Settings::default();
    assert!(apply_generator_key(&mut state, "1"));
    assert!(!state.password_generator.lowercase);
    assert!(apply_generator_key(&mut state, "6"));
    assert!(!state.passphrase_generator.capitalize);

    assert!(apply_generator_key(&mut state, "+"));
    assert_eq!(state.password_generator.length, 21);
    assert_eq!(state.passphrase_generator.words, 5);
    assert!(apply_generator_key(&mut state, "-"));
    assert_eq!(state.password_generator.length, 20);
    assert_eq!(state.passphrase_generator.words, 4);

    // The upper bounds are 128 characters and 20 words: a step from just
    // below them reaches the bound, further steps must not exceed it.
    state.password_generator.length = 127;
    state.passphrase_generator.words = 19;
    assert!(apply_generator_key(&mut state, "+"));
    assert_eq!(state.password_generator.length, 128);
    assert_eq!(state.passphrase_generator.words, 20);
    assert!(
        apply_generator_key(&mut state, "="),
        "'=' is an alias for '+'"
    );
    assert_eq!(state.password_generator.length, 128);
    assert_eq!(state.passphrase_generator.words, 20);

    // The lower bounds are 4 characters and 2 words.
    state.password_generator.length = 5;
    state.passphrase_generator.words = 3;
    assert!(apply_generator_key(&mut state, "-"));
    assert_eq!(state.password_generator.length, 4);
    assert_eq!(state.passphrase_generator.words, 2);
    assert!(
        apply_generator_key(&mut state, "_"),
        "'_' is an alias for '-'"
    );
    assert_eq!(state.password_generator.length, 4);
    assert_eq!(state.passphrase_generator.words, 2);

    assert!(apply_generator_key(&mut state, ","));
    assert_eq!(state.passphrase_generator.separator, ".");
    assert!(apply_generator_key(&mut state, ","));
    assert_eq!(state.passphrase_generator.separator, "_");
    assert!(apply_generator_key(&mut state, ","));
    assert_eq!(state.passphrase_generator.separator, "");
    assert!(apply_generator_key(&mut state, ","));
    assert_eq!(state.passphrase_generator.separator, "-");

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
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSearchText("l".into())
    );

    let mut value = ctx("enter");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::FinishSearch);

    let mut value = ctx("backspace");
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);
}

#[::core::prelude::v1::test]
fn command_modifiers_suppress_key_actions() {
    let mut value = ctx("l");
    for modifier in [
        KeyModifiers {
            control: true,
            ..Default::default()
        },
        KeyModifiers {
            platform: true,
            ..Default::default()
        },
        KeyModifiers {
            alt: true,
            ..Default::default()
        },
        KeyModifiers {
            function: true,
            ..Default::default()
        },
    ] {
        value.modifiers = modifier;
        assert_eq!(classify_key(&value), KeyAction::None);
    }
}

#[::core::prelude::v1::test]
fn ime_composed_text_is_inserted_whole() {
    let mut value = ctx("unknown");
    value.key_char = Some("日本語");
    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertAuthText("日本語".into())
    );

    value.screen = Screen::Unlocked;
    value.editing_auth = false;
    value.searching = true;
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSearchText("日本語".into())
    );

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSettingsText("日本語".into())
    );
}

#[::core::prelude::v1::test]
fn key_char_is_preferred_over_ascii_key() {
    let mut value = ctx("a");
    value.key_char = Some("ä");
    value.searching = true;
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSearchText("ä".into())
    );
}

#[::core::prelude::v1::test]
fn shift_characters_are_matched_through_key_char() {
    let mut value = ctx("y");
    value.key_char = Some("Y");
    value.panel = Panel::Generator;
    assert_eq!(classify_key(&value), KeyAction::CopyPassphrase);

    value.key = "=";
    value.key_char = Some("+");
    assert_eq!(classify_key(&value), KeyAction::AdjustLength(1));
}

#[::core::prelude::v1::test]
fn alt_produced_text_is_inserted() {
    let mut value = ctx("s");
    value.key_char = Some("ß");
    value.modifiers.alt = true;
    value.searching = true;
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSearchText("ß".into())
    );
}

#[::core::prelude::v1::test]
fn space_key_name_inserts_a_space() {
    let mut value = ctx("space");
    value.searching = true;
    assert_eq!(
        classify_key(&value),
        KeyAction::InsertSearchText(" ".into())
    );
}

#[::core::prelude::v1::test]
fn audit_shortcut_requires_an_available_report() {
    let mut value = ctx("g");
    assert_eq!(classify_key(&value), KeyAction::OpenAudit);

    value.has_audit_report = false;
    assert_eq!(
        classify_key(&value),
        KeyAction::None,
        "'g' must not open the audit panel when no report exists"
    );

    // The guard is local to that shortcut; other vault keys stay available.
    value.key = "y";
    assert_eq!(classify_key(&value), KeyAction::CopyTotp);
}

#[::core::prelude::v1::test]
fn backspace_query_requires_a_nonempty_query() {
    let mut value = ctx("backspace");
    assert_eq!(classify_key(&value), KeyAction::None);

    value.query_nonempty = true;
    assert_eq!(classify_key(&value), KeyAction::BackspaceQuery);

    // Editing modes keep their own backspace action even with an empty query.
    value.query_nonempty = false;
    value.searching = true;
    assert_eq!(classify_key(&value), KeyAction::BackspaceSearch);
}
