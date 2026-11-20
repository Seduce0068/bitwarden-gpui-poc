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

#[test]
fn text_editing_actions_are_mode_specific() {
    let mut value = ctx("a");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("a".into()));

    value.key = "backspace";
    assert_eq!(classify_key(&value), UiAction::BackspaceSearch);

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    value.key = "b";
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText("b".into())
    );

    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), UiAction::InsertAuthText("b".into()));
    value.key = "backspace";
    assert_eq!(classify_key(&value), UiAction::BackspaceAuth);

    value.screen = Screen::Unlocked;
    value.panel = Panel::Vault;
    value.editing_auth = false;
    value.editing_settings = false;
    value.query_nonempty = true;
    assert_eq!(classify_key(&value), UiAction::BackspaceQuery);
}

#[test]
fn finish_actions_are_mode_specific() {
    let mut value = ctx("enter");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::FinishSearch);

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(classify_key(&value), UiAction::FinishSettingsEdit);

    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), UiAction::FinishAuthEdit);
}

#[test]
fn lock_screen_keys_and_retry_gate() {
    let mut value = ctx("enter");
    value.screen = Screen::Locked;
    assert_eq!(classify_key(&value), UiAction::Authenticate);

    value.key = "m";
    assert_eq!(classify_key(&value), UiAction::OpenDemoVault);

    value.key = "r";
    assert_eq!(classify_key(&value), UiAction::None);
    value.login_failed = true;
    assert_eq!(classify_key(&value), UiAction::RetryLogin);

    value.key = "4";
    assert_eq!(
        classify_key(&value),
        UiAction::EditAuthField(AuthField::ClientSecret)
    );
}

#[test]
fn generator_keys_toggle_options_and_clamp_lengths() {
    use crate::ui::keys::GeneratorOption;

    let mut state = Settings::default();
    apply_generator_key(&mut state, GeneratorOption::Lowercase);
    assert!(!state.password_generator.lowercase);
    apply_generator_key(&mut state, GeneratorOption::Capitalize);
    assert!(!state.passphrase_generator.capitalize);

    apply_generator_key(&mut state, GeneratorOption::LengthUp);
    assert_eq!(state.password_generator.length, 21);
    assert_eq!(state.passphrase_generator.words, 5);
    apply_generator_key(&mut state, GeneratorOption::LengthDown);
    assert_eq!(state.password_generator.length, 20);
    assert_eq!(state.passphrase_generator.words, 4);

    state.password_generator.length = 127;
    state.passphrase_generator.words = 19;
    apply_generator_key(&mut state, GeneratorOption::LengthUp);
    assert_eq!(state.password_generator.length, 128);
    assert_eq!(state.passphrase_generator.words, 20);
    apply_generator_key(&mut state, GeneratorOption::LengthUp);
    assert_eq!(state.password_generator.length, 128);
    assert_eq!(state.passphrase_generator.words, 20);

    state.password_generator.length = 5;
    state.passphrase_generator.words = 3;
    apply_generator_key(&mut state, GeneratorOption::LengthDown);
    assert_eq!(state.password_generator.length, 4);
    assert_eq!(state.passphrase_generator.words, 2);
    apply_generator_key(&mut state, GeneratorOption::LengthDown);
    assert_eq!(state.password_generator.length, 4);
    assert_eq!(state.passphrase_generator.words, 2);

    for expected in [".", "_", "", "-"] {
        apply_generator_key(&mut state, GeneratorOption::Separator);
        assert_eq!(state.passphrase_generator.separator, expected);
    }
}

#[test]
fn vault_keys_map_to_actions() {
    assert_eq!(classify_key(&ctx("up")), UiAction::MoveSelection(-1));
    assert_eq!(classify_key(&ctx("down")), UiAction::MoveSelection(1));
    assert_eq!(classify_key(&ctx("f")), UiAction::ToggleFavorite);
    assert_eq!(classify_key(&ctx("y")), UiAction::CopyTotp);
    assert_eq!(classify_key(&ctx("p")), UiAction::CopySelectedPassword);
    assert_eq!(classify_key(&ctx("u")), UiAction::CopySelectedUsername);
    assert_eq!(classify_key(&ctx("g")), UiAction::OpenAudit);
    assert_eq!(classify_key(&ctx("/")), UiAction::StartSearch);
    assert_eq!(classify_key(&ctx("c")), UiAction::SetPanel(Panel::Settings));
    assert_eq!(classify_key(&ctx("q")), UiAction::None);
}

#[test]
fn settings_and_generator_keys() {
    let mut value = ctx("w");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::SaveSettings);
    value.key = "+";
    assert_eq!(classify_key(&value), UiAction::AdjustThreshold(1));
    value.key = "i";
    assert_eq!(classify_key(&value), UiAction::AdjustIdleLock(1));
    value.key = "u";
    assert_eq!(classify_key(&value), UiAction::AdjustIdleLock(-1));

    value.panel = Panel::Generator;
    value.key = "p";
    assert_eq!(classify_key(&value), UiAction::GeneratePassword);
    value.key = "Y";
    assert_eq!(classify_key(&value), UiAction::CopyPassphrase);
    value.key = "-";
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::LengthDown)
    );
}

#[test]
fn editing_mode_swallows_shortcut_keys() {
    let mut value = ctx("l");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("l".into()));

    let mut value = ctx("enter");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::FinishSearch);

    let mut value = ctx("backspace");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::BackspaceSearch);
}

#[test]
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
        assert_eq!(classify_key(&value), UiAction::None);
    }
}

#[test]
fn ime_composed_text_is_inserted_whole() {
    let mut value = ctx("unknown");
    value.key_char = Some("日本語");
    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(
        classify_key(&value),
        UiAction::InsertAuthText("日本語".into())
    );

    value.screen = Screen::Unlocked;
    value.editing_auth = false;
    value.searching = true;
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSearchText("日本語".into())
    );

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText("日本語".into())
    );
}

#[test]
fn key_char_is_preferred_over_ascii_key() {
    let mut value = ctx("a");
    value.key_char = Some("ä");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("ä".into()));
}

#[test]
fn shift_characters_are_matched_through_key_char() {
    let mut value = ctx("y");
    value.key_char = Some("Y");
    value.panel = Panel::Generator;
    assert_eq!(classify_key(&value), UiAction::CopyPassphrase);

    value.key = "=";
    value.key_char = Some("+");
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::LengthUp)
    );
}

#[test]
fn alt_produced_text_is_inserted() {
    let mut value = ctx("s");
    value.key_char = Some("ß");
    value.modifiers.alt = true;
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("ß".into()));
}

#[test]
fn space_key_name_inserts_a_space() {
    let mut value = ctx("space");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText(" ".into()));
}

#[test]
fn audit_shortcut_requires_an_available_report() {
    let mut value = ctx("g");
    assert_eq!(classify_key(&value), UiAction::OpenAudit);

    value.has_audit_report = false;
    assert_eq!(
        classify_key(&value),
        UiAction::None,
        "'g' must not open the audit panel when no report exists"
    );

    // The guard is local to that shortcut; other vault keys stay available.
    value.key = "y";
    assert_eq!(classify_key(&value), UiAction::CopyTotp);
}

#[test]
fn backspace_query_requires_a_nonempty_query() {
    let mut value = ctx("backspace");
    assert_eq!(classify_key(&value), UiAction::None);

    value.query_nonempty = true;
    assert_eq!(classify_key(&value), UiAction::BackspaceQuery);

    // Editing modes keep their own backspace action even with an empty query.
    value.query_nonempty = false;
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::BackspaceSearch);
}

#[test]
fn field_routing_distinguishes_shared_and_credential_fields() {
    use crate::settings::SharedSettingsField;
    use crate::ui::state::{AuthField, SettingsField};

    assert_eq!(
        SharedSettingsField::from(SettingsField::ServerUrl),
        SharedSettingsField::ServerUrl
    );
    assert_eq!(
        SharedSettingsField::from(SettingsField::Email),
        SharedSettingsField::Email
    );
    assert_eq!(
        AuthField::ServerUrl.shared(),
        Some(SharedSettingsField::ServerUrl)
    );
    assert_eq!(AuthField::Email.shared(), Some(SharedSettingsField::Email));
    assert_eq!(AuthField::ClientId.shared(), None);
    assert_eq!(AuthField::ClientSecret.shared(), None);
    assert_eq!(AuthField::MasterPassword.shared(), None);
}

#[test]
fn every_generator_option_toggles_from_its_default() {
    use crate::ui::keys::GeneratorOption;

    for option in [
        GeneratorOption::Lowercase,
        GeneratorOption::Uppercase,
        GeneratorOption::Digits,
        GeneratorOption::Symbols,
        GeneratorOption::AvoidAmbiguous,
        GeneratorOption::Capitalize,
        GeneratorOption::IncludeNumber,
    ] {
        let mut state = Settings::default();
        let before = state.clone();
        apply_generator_key(&mut state, option);
        assert_ne!(state, before, "{option:?} must change the settings");
        apply_generator_key(&mut state, option);
        assert_eq!(state, before, "{option:?} must toggle back");
    }
}

#[test]
fn generator_keys_map_to_typed_options() {
    use crate::ui::keys::GeneratorOption;

    let mut value = ctx("enter");
    value.panel = Panel::Generator;
    for (key, option) in [
        ("1", GeneratorOption::Lowercase),
        ("2", GeneratorOption::Uppercase),
        ("3", GeneratorOption::Digits),
        ("4", GeneratorOption::Symbols),
        ("5", GeneratorOption::AvoidAmbiguous),
        ("6", GeneratorOption::Capitalize),
        ("7", GeneratorOption::IncludeNumber),
        ("+", GeneratorOption::LengthUp),
        ("=", GeneratorOption::LengthUp),
        ("-", GeneratorOption::LengthDown),
        ("_", GeneratorOption::LengthDown),
        (",", GeneratorOption::Separator),
    ] {
        value.key = key;
        assert_eq!(
            classify_key(&value),
            UiAction::Generator(option),
            "key {key:?}"
        );
    }
}

#[test]
fn settings_keys_adjust_seconds_fields() {
    let mut value = ctx("3");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::AdjustLoginTimeout(1));
    value.key = "4";
    assert_eq!(classify_key(&value), UiAction::AdjustLoginTimeout(-1));
    value.key = "5";
    assert_eq!(classify_key(&value), UiAction::AdjustClipboardRestore(1));
    value.key = "6";
    assert_eq!(classify_key(&value), UiAction::AdjustClipboardRestore(-1));
}
