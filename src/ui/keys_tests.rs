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
fn arrow_keys_in_text_editing_are_delegated_to_gpui() {
    // Auth, search and settings editing deliberately do not add a movement
    // action: GPUI's text field owns the caret, so classification is `None`.
    for key in ["up", "down", "left", "right", "arrowleft", "home", "end"] {
        let mut value = ctx(key);
        value.searching = true;
        assert_eq!(classify_key(&value), UiAction::None, "search/{key}");

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        assert_eq!(classify_key(&value), UiAction::None, "settings/{key}");

        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(classify_key(&value), UiAction::None, "auth/{key}");
    }

    // Outside editing modes the same key keeps the existing list-navigation
    // meaning, so no new binding was introduced by this delegation.
    assert_eq!(classify_key(&ctx("up")), UiAction::MoveSelection(-1));
    assert_eq!(classify_key(&ctx("down")), UiAction::MoveSelection(1));

    // The hint must not promise caret movement: classification only delegates
    // to GPUI's text input via `UiAction::None`, so native caret behaviour is
    // not guaranteed by this module.
    assert!(TEXT_EDIT_ARROW_KEYS_HINT.contains("矢印キー"));
    assert!(TEXT_EDIT_ARROW_KEYS_HINT.contains("GPUI"));
    assert!(
        TEXT_EDIT_ARROW_KEYS_HINT.contains("保証"),
        "the hint must state that caret movement is not guaranteed, got: {TEXT_EDIT_ARROW_KEYS_HINT}"
    );
    assert!(
        !TEXT_EDIT_ARROW_KEYS_HINT.contains("（キャレット移動）"),
        "the old unconditional caret-movement promise must be gone"
    );
}

#[test]
fn generator_plus_minus_change_length_and_word_count_together() {
    let mut value = ctx("+");
    value.panel = Panel::Generator;
    let action = classify_key(&value);
    assert_eq!(action, UiAction::Generator(GeneratorOption::LengthUp));

    let mut settings = Settings::default();
    let before_length = settings.password_generator.length;
    let before_words = settings.passphrase_generator.words;
    apply_generator_key(&mut settings, GeneratorOption::LengthUp);
    assert_eq!(settings.password_generator.length, before_length + 1);
    assert_eq!(settings.passphrase_generator.words, before_words + 1);

    value.key = "-";
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::LengthDown)
    );
    apply_generator_key(&mut settings, GeneratorOption::LengthDown);
    assert_eq!(settings.password_generator.length, before_length);
    assert_eq!(settings.passphrase_generator.words, before_words);
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
fn lock_screen_email_client_id_and_master_password_field_keys() {
    let mut value = ctx("2");
    value.screen = Screen::Locked;
    assert_eq!(
        classify_key(&value),
        UiAction::EditAuthField(AuthField::Email)
    );

    value.key = "3";
    assert_eq!(
        classify_key(&value),
        UiAction::EditAuthField(AuthField::ClientId)
    );

    value.key = "5";
    assert_eq!(
        classify_key(&value),
        UiAction::EditAuthField(AuthField::MasterPassword)
    );
}

#[test]
fn paging_keys_stay_unbound_on_the_lock_screen_outside_editing() {
    // Complements the in-module `paging_keys_stay_unbound_in_every_editing_mode`:
    // the lock screen has no vault list, so PageUp/PageDown/Home/End must stay
    // inert when no credential field is focused instead of leaking the
    // unlocked list-movement bindings.
    for key in ["pageup", "pagedown", "home", "end"] {
        let mut value = ctx(key);
        value.screen = Screen::Locked;
        assert_eq!(
            classify_key(&value),
            UiAction::None,
            "locked/{key} must not move a list selection"
        );

        // A failed login must not bind the paging keys either; only `r` is
        // gated by `login_failed`.
        value.login_failed = true;
        assert_eq!(classify_key(&value), UiAction::None, "locked/retry/{key}");
    }
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
fn separator_falls_back_to_dash_for_unknown_values() {
    // The documented cycle is "-" -> "." -> "_" -> "" -> "-". A hand-edited
    // or legacy value outside that set must land on "-" through the `_` arm
    // in `apply_generator_key` (keys.rs:72), rather than being kept or cleared.
    let mut settings = Settings::default();
    for unknown in ["x", "::", "unknown"] {
        settings.passphrase_generator.separator = unknown.into();
        apply_generator_key(&mut settings, GeneratorOption::Separator);
        assert_eq!(
            settings.passphrase_generator.separator, "-",
            "unknown separator {unknown:?} must fall back to '-'"
        );

        // After the fallback the next press re-enters the normal cycle.
        apply_generator_key(&mut settings, GeneratorOption::Separator);
        assert_eq!(
            settings.passphrase_generator.separator, ".",
            "the fallback value must be the cycle's '-' state"
        );
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
fn vault_filter_sort_and_generator_navigation_keys() {
    assert_eq!(classify_key(&ctx("t")), UiAction::CycleFilter);
    assert_eq!(classify_key(&ctx("s")), UiAction::CycleSort);
    assert_eq!(
        classify_key(&ctx("n")),
        UiAction::SetPanel(Panel::Generator)
    );
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
fn alt_single_character_physical_key_without_key_char_is_inserted_while_editing() {
    // `typed_text` falls back to a one-character physical `key` when no glyph
    // is reported, so Alt+S with `key_char: None` still inserts "s" in every
    // text-editing mode. A composed `key_char` is not required by the guard.
    let mut value = ctx("s");
    value.key_char = None;
    value.modifiers.alt = true;

    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("s".into()));

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText("s".into())
    );

    value.editing_settings = false;
    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), UiAction::InsertAuthText("s".into()));

    // The same keystroke in a command panel stays inert: Alt never leaks a
    // printable physical key into a vault or generator command.
    value.editing_auth = false;
    value.screen = Screen::Unlocked;
    value.panel = Panel::Vault;
    assert_eq!(classify_key(&value), UiAction::None);
    value.panel = Panel::Generator;
    assert_eq!(classify_key(&value), UiAction::None);

    // A multi-character key name has no printable fallback and stays inert
    // even while editing, which is the other half of the guard's contract.
    value.key = "backspace";
    value.panel = Panel::Vault;
    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), UiAction::None);
}

#[test]
fn space_key_name_inserts_a_space() {
    let mut value = ctx("space");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText(" ".into()));
}

#[test]
fn audit_shortcut_reports_missing_report_with_a_dedicated_action() {
    let mut value = ctx("g");
    assert_eq!(classify_key(&value), UiAction::OpenAudit);

    value.has_audit_report = false;
    assert_eq!(
        classify_key(&value),
        UiAction::AuditUnavailable,
        "'g' must still respond when no report exists"
    );
    assert_ne!(
        classify_key(&value),
        UiAction::None,
        "an inert key is the bug this fallback fixes"
    );

    // The fallback is local to that shortcut; other vault keys stay available.
    value.key = "y";
    assert_eq!(classify_key(&value), UiAction::CopyTotp);
}

#[test]
fn audit_unavailable_shortcut_is_case_insensitive_and_panel_scoped() {
    let mut value = ctx("g");
    value.has_audit_report = false;

    // Shift / Caps Lock spellings fold to the same `g` binding.
    for (key, key_char) in [("G", None), ("g", Some("G"))] {
        value.key = key;
        value.key_char = key_char;
        assert_eq!(
            classify_key(&value),
            UiAction::AuditUnavailable,
            "{key}/{key_char:?}"
        );
    }

    // The fallback belongs to the vault panel only; the audit panel keeps its
    // own `g` binding back to the vault regardless of report availability.
    value.key_char = None;
    value.panel = Panel::Audit;
    assert_eq!(classify_key(&value), UiAction::SetPanel(Panel::Vault));
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
fn confirmed_query_accepts_printable_text_without_restarting_search() {
    let mut value = ctx("a");
    // Without a confirmed query a plain character stays inert, as before.
    assert_eq!(classify_key(&value), UiAction::None);

    // A confirmed query is editable with the same insertable-text rule as
    // search mode (keys.rs vault fallback), mirroring BackspaceQuery.
    value.query_nonempty = true;
    assert_eq!(classify_key(&value), UiAction::InsertQueryText("a".into()));

    // `/` keeps starting a *fresh* search instead of appending a slash.
    value.key = "/";
    assert_eq!(classify_key(&value), UiAction::StartSearch);

    // Backspace keeps its existing confirmed-query action.
    value.key = "backspace";
    assert_eq!(classify_key(&value), UiAction::BackspaceQuery);
}

#[test]
fn confirmed_query_text_insertion_keeps_command_and_cursor_keys() {
    let mut value = ctx("x");
    value.query_nonempty = true;
    for (key, expected) in [
        ("l", UiAction::Lock),
        ("t", UiAction::CycleFilter),
        ("s", UiAction::CycleSort),
        ("f", UiAction::ToggleFavorite),
        ("y", UiAction::CopyTotp),
        ("p", UiAction::CopySelectedPassword),
        ("u", UiAction::CopySelectedUsername),
        ("g", UiAction::OpenAudit),
        ("n", UiAction::SetPanel(Panel::Generator)),
        ("c", UiAction::SetPanel(Panel::Settings)),
        ("up", UiAction::MoveSelection(-1)),
        ("down", UiAction::MoveSelection(1)),
        ("pageup", UiAction::MoveSelectionPage(-1)),
        ("home", UiAction::MoveSelectionToEdge(SelectionEdge::First)),
        ("escape", UiAction::quit_or_warn()),
        // Control/function/cursor names are never text, even with a query.
        ("enter", UiAction::None),
        ("left", UiAction::None),
        ("f1", UiAction::None),
    ] {
        value.key = key;
        assert_eq!(classify_key(&value), expected, "confirmed/{key}");
    }

    // Uppercase layout glyphs and IME compositions are appended verbatim.
    value.key = "a";
    value.key_char = Some("A");
    assert_eq!(classify_key(&value), UiAction::InsertQueryText("A".into()));
    value.key = "unknown";
    value.key_char = Some("日本語");
    assert_eq!(
        classify_key(&value),
        UiAction::InsertQueryText("日本語".into())
    );
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

#[test]
fn generator_navigation_and_generation_keys() {
    let mut value = ctx("n");
    value.panel = Panel::Generator;
    assert_eq!(classify_key(&value), UiAction::SetPanel(Panel::Vault));
    value.key = "h";
    assert_eq!(classify_key(&value), UiAction::GeneratePassphrase);
    value.key = "y";
    assert_eq!(classify_key(&value), UiAction::CopyPassword);
}

#[test]
fn settings_navigation_and_field_selection_keys() {
    use crate::ui::state::SettingsField;

    let mut value = ctx("c");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::SetPanel(Panel::Vault));
    value.key = "1";
    assert_eq!(
        classify_key(&value),
        UiAction::EditSettingsField(SettingsField::ServerUrl)
    );
    value.key = "2";
    assert_eq!(
        classify_key(&value),
        UiAction::EditSettingsField(SettingsField::Email)
    );
    value.key = "-";
    assert_eq!(classify_key(&value), UiAction::AdjustThreshold(-1));
}

#[test]
fn settings_editing_keeps_every_letter_as_text() {
    let mut value = ctx("w");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::SaveSettings);
    value.editing_settings = true;
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText("w".into()),
        "typing w in a URL must not save the settings"
    );
    for key in ["c", "l", "d"] {
        value.key = key;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertSettingsText(key.into()),
            "{key} must be plain text while editing a settings field"
        );
    }
    value.key = "enter";
    assert_eq!(classify_key(&value), UiAction::FinishSettingsEdit);
}

#[test]
fn settings_editing_backspace_maps_to_backspace_settings() {
    let mut value = ctx("backspace");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::None);

    value.editing_settings = true;
    assert_eq!(classify_key(&value), UiAction::BackspaceSettings);
}

#[test]
fn auth_editing_digits_and_enter_are_text_and_confirmation() {
    let mut value = ctx("1");
    value.screen = Screen::Locked;
    assert_eq!(
        classify_key(&value),
        UiAction::EditAuthField(AuthField::ServerUrl)
    );
    value.editing_auth = true;
    for key in ["1", "2", "3", "4", "5"] {
        value.key = key;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertAuthText(key.into()),
            "{key} selects a field only outside editing mode"
        );
    }
    value.key = "enter";
    assert_eq!(
        classify_key(&value),
        UiAction::FinishAuthEdit,
        "Enter confirms the field; authentication is a separate action"
    );
}

#[test]
fn auth_editing_keeps_l_m_r_as_text() {
    let mut value = ctx("l");
    value.screen = Screen::Locked;

    // Outside editing these keys keep their lock-screen bindings: `l` has no
    // vault to lock here, `m` opens the demo vault and `r` needs a failure.
    assert_eq!(classify_key(&value), UiAction::None);
    value.key = "m";
    assert_eq!(classify_key(&value), UiAction::OpenDemoVault);
    value.key = "r";
    assert_eq!(classify_key(&value), UiAction::None);
    value.login_failed = true;
    assert_eq!(classify_key(&value), UiAction::RetryLogin);

    // While editing an auth field the same keys are plain text (keys.rs
    // auth-editing branch), even after a failed login, so a client id, secret
    // or password may contain them.
    value.editing_auth = true;
    for key in ["l", "m", "r"] {
        value.key = key;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertAuthText(key.into()),
            "{key} must be inserted while editing an auth field"
        );
    }

    // Confirmation is still a dedicated action, not a character.
    value.key = "enter";
    assert_eq!(classify_key(&value), UiAction::FinishAuthEdit);
}

#[test]
fn generator_and_settings_save_discard_keys() {
    let mut value = ctx("w");
    value.panel = Panel::Generator;
    assert_eq!(classify_key(&value), UiAction::SaveSettings);
    value.key = "d";
    assert_eq!(classify_key(&value), UiAction::DiscardSettings);

    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::DiscardSettings);
    value.key = "w";
    assert_eq!(classify_key(&value), UiAction::SaveSettings);
}

#[test]
fn audit_focus_action_carries_the_item_id() {
    // A mouse click supplies a real server id. The typed action must keep it
    // byte-for-byte so the dispatcher can select exactly that audited row.
    let clicked = UiAction::FocusAuditItem("item-42/é".into());
    match &clicked {
        UiAction::FocusAuditItem(id) => {
            assert_eq!(id.as_str(), "item-42/é");
            assert_ne!(id.as_str(), AUDIT_SELECTED_ROW_SENTINEL);
            assert_ne!(id.as_str(), QUIT_OR_WARN_SENTINEL);
        }
        other => panic!("expected FocusAuditItem, got {other:?}"),
    }

    // The keyboard commands put the two reserved sentinels into the same
    // id-carrying variant; only the constructors know which is which.
    match (
        UiAction::focus_selected_audit_row(),
        UiAction::quit_or_warn(),
    ) {
        (UiAction::FocusAuditItem(row), UiAction::FocusAuditItem(exit)) => {
            assert_eq!(row.as_str(), AUDIT_SELECTED_ROW_SENTINEL);
            assert_eq!(exit.as_str(), QUIT_OR_WARN_SENTINEL);
            assert_ne!(row, exit);
            assert_ne!(row.as_str(), "item-42/é");
        }
        other => panic!("expected two sentinels, got {other:?}"),
    }
}

#[test]
fn global_keys_are_scoped_without_ambiguous_bindings() {
    for screen in [Screen::Locked, Screen::Unlocked] {
        for panel in [
            Panel::Vault,
            Panel::Audit,
            Panel::Generator,
            Panel::Settings,
        ] {
            let mut base = ctx("x");
            base.screen = screen;
            base.panel = panel;

            // `l` locks from every unlocked panel; the lock screen has no
            // vault to lock and therefore keeps the key inert.
            base.key = "l";
            let expected = if screen == Screen::Unlocked {
                UiAction::Lock
            } else {
                UiAction::None
            };
            assert_eq!(classify_key(&base), expected, "{screen:?}/{panel:?}");

            // Save/discard belong only to the settings-owning panels; elsewhere
            // the same keys must stay inert instead of dispatching another
            // global action.
            let owns_settings =
                screen == Screen::Unlocked && matches!(panel, Panel::Settings | Panel::Generator);
            for key in ["w", "d"] {
                base.key = key;
                let action = classify_key(&base);
                assert!(
                    if owns_settings {
                        matches!(action, UiAction::SaveSettings | UiAction::DiscardSettings)
                    } else {
                        action == UiAction::None
                    },
                    "{screen:?}/{panel:?}/{key} -> {action:?}"
                );
            }

            // While a settings field is being edited, no key may escape into a
            // global action; all of them become text or editing commands.
            base.panel = Panel::Settings;
            base.editing_settings = true;
            for key in ["w", "d", "l", "c", "1", "2"] {
                base.key = key;
                let action = classify_key(&base);
                assert!(
                    !matches!(
                        action,
                        UiAction::SaveSettings
                            | UiAction::DiscardSettings
                            | UiAction::Lock
                            | UiAction::SetPanel(_)
                            | UiAction::Authenticate
                    ),
                    "{key} escaped editing: {action:?}"
                );
            }
        }
    }
}

#[test]
fn audit_panel_has_up_down_enter_keyboard_path() {
    let mut value = ctx("up");
    value.panel = Panel::Audit;
    assert_eq!(classify_key(&value), UiAction::MoveSelection(-1));
    value.key = "down";
    assert_eq!(classify_key(&value), UiAction::MoveSelection(1));
    value.key = "enter";
    assert_eq!(classify_key(&value), UiAction::focus_selected_audit_row());
    value.key = "g";
    assert_eq!(classify_key(&value), UiAction::SetPanel(Panel::Vault));
    value.key = "l";
    assert_eq!(classify_key(&value), UiAction::Lock);
    value.key = "x";
    assert_eq!(classify_key(&value), UiAction::None);
}

#[test]
fn reserved_audit_and_quit_sentinels_do_not_collide_with_item_ids() {
    assert_ne!(AUDIT_SELECTED_ROW_SENTINEL, QUIT_OR_WARN_SENTINEL);
    assert_eq!(
        UiAction::focus_selected_audit_row(),
        UiAction::FocusAuditItem(AUDIT_SELECTED_ROW_SENTINEL.to_string())
    );
    assert_eq!(
        UiAction::quit_or_warn(),
        UiAction::FocusAuditItem(QUIT_OR_WARN_SENTINEL.to_string())
    );
    assert_ne!(
        UiAction::focus_selected_audit_row(),
        UiAction::FocusAuditItem("item-42".into())
    );
}

#[test]
fn escape_uses_the_warn_first_sentinel_outside_editing_modes() {
    for screen in [Screen::Locked, Screen::Unlocked] {
        for panel in [
            Panel::Vault,
            Panel::Audit,
            Panel::Generator,
            Panel::Settings,
        ] {
            let mut value = ctx("escape");
            value.screen = screen;
            value.panel = panel;
            assert_eq!(
                classify_key(&value),
                UiAction::quit_or_warn(),
                "{screen:?}/{panel:?}"
            );
        }
    }

    // Editing modes keep their own confirm/finish behaviour.
    let mut value = ctx("escape");
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(classify_key(&value), UiAction::FinishSettingsEdit);
    value.screen = Screen::Locked;
    value.editing_auth = true;
    value.editing_settings = false;
    assert_eq!(classify_key(&value), UiAction::FinishAuthEdit);
    value.screen = Screen::Unlocked;
    value.editing_auth = false;
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::FinishSearch);
}

#[test]
fn audit_enter_does_not_leak_into_other_panels() {
    for panel in [Panel::Vault, Panel::Generator, Panel::Settings] {
        let mut value = ctx("enter");
        value.panel = panel;
        assert_eq!(classify_key(&value), UiAction::None, "{panel:?}");
    }
}

#[test]
fn settings_threshold_accepts_shift_key_aliases() {
    // Generator aliases are covered by `generator_keys_map_to_typed_options`;
    // these are the remaining `=`/`_` branches in the settings panel.
    let mut value = ctx("=");
    value.panel = Panel::Settings;
    assert_eq!(classify_key(&value), UiAction::AdjustThreshold(1));
    value.key = "_";
    assert_eq!(classify_key(&value), UiAction::AdjustThreshold(-1));
}

#[test]
fn alt_guard_suppresses_keys_without_generated_text_while_editing() {
    let mut value = ctx("backspace");
    value.searching = true;
    value.modifiers.alt = true;
    assert_eq!(classify_key(&value), UiAction::None);

    value.key = "arrowleft";
    assert_eq!(classify_key(&value), UiAction::None);

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    value.key = "backspace";
    assert_eq!(classify_key(&value), UiAction::None);

    value.editing_settings = false;
    value.screen = Screen::Locked;
    value.editing_auth = true;
    value.key = "enter";
    assert_eq!(classify_key(&value), UiAction::None);

    // A printable layout character satisfies the guard and stays as text.
    value.screen = Screen::Unlocked;
    value.editing_auth = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    value.key = "w";
    value.key_char = Some("w");
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText("w".into())
    );
}

#[test]
fn alt_outside_editing_stays_inert_even_with_printable_text() {
    let mut value = ctx("s");
    value.key_char = Some("ß");
    value.modifiers.alt = true;
    assert_eq!(classify_key(&value), UiAction::None);

    value.panel = Panel::Settings;
    value.key = "w";
    value.key_char = Some("w");
    assert_eq!(classify_key(&value), UiAction::None);

    value.screen = Screen::Locked;
    assert_eq!(classify_key(&value), UiAction::None);
}

#[test]
fn empty_key_char_falls_back_to_the_physical_key() {
    use crate::ui::keys::GeneratorOption;

    let mut value = ctx("a");
    value.key_char = Some("");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("a".into()));

    // Command matching must also fall back when `key_char` carries no glyph.
    value.searching = false;
    value.panel = Panel::Generator;
    value.key = "1";
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::Lowercase)
    );

    // A multi-character key name is still not printable text.
    value.key = "backspace";
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::BackspaceSearch);
}

#[test]
fn multi_character_key_char_falls_back_to_the_physical_key() {
    use crate::ui::keys::GeneratorOption;

    // IME can report a multi-character composition in `key_char` while the
    // physical key still names a command. `command_key` filters by character
    // count, so such text must not suppress the physical-key command.
    let mut value = ctx("1");
    value.key_char = Some("日本語");
    value.panel = Panel::Settings;
    assert_eq!(
        classify_key(&value),
        UiAction::EditSettingsField(crate::ui::state::SettingsField::ServerUrl),
        "multi-character key_char must not block the physical-key command"
    );

    value.panel = Panel::Generator;
    value.key = "+";
    value.key_char = Some("かな文字");
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::LengthUp)
    );

    // Lock-screen commands use the same fallback.
    value.screen = Screen::Locked;
    value.key = "m";
    value.key_char = Some("かな文字");
    assert_eq!(classify_key(&value), UiAction::OpenDemoVault);

    // A single-character key_char still wins over the physical key.
    value.screen = Screen::Unlocked;
    value.panel = Panel::Generator;
    value.key = "y";
    value.key_char = Some("Y");
    assert_eq!(classify_key(&value), UiAction::CopyPassphrase);
}

#[test]
fn command_modifiers_are_suppressed_in_every_editing_mode() {
    // Ctrl, Cmd/Windows and Fn are platform shortcuts: editing text never
    // gives them priority, not even when a printable key_char is present.
    for modifiers in [
        KeyModifiers {
            control: true,
            ..Default::default()
        },
        KeyModifiers {
            platform: true,
            ..Default::default()
        },
        KeyModifiers {
            function: true,
            ..Default::default()
        },
    ] {
        let mut value = ctx("a");
        value.key_char = Some("a");
        value.modifiers = modifiers;

        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(classify_key(&value), UiAction::None, "auth/{modifiers:?}");

        value.editing_auth = false;
        value.screen = Screen::Unlocked;
        value.searching = true;
        assert_eq!(classify_key(&value), UiAction::None, "search/{modifiers:?}");

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        assert_eq!(
            classify_key(&value),
            UiAction::None,
            "settings/{modifiers:?}"
        );
    }

    // Ctrl+Alt stays suppressed when it produced no glyph.
    let mut value = ctx("a");
    value.key_char = None;
    value.modifiers = KeyModifiers {
        control: true,
        alt: true,
        ..Default::default()
    };
    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), UiAction::None, "auth/ctrl-alt");
    value.editing_auth = false;
    value.screen = Screen::Unlocked;
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::None, "search/ctrl-alt");
    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(classify_key(&value), UiAction::None, "settings/ctrl-alt");

    // Even with a glyph, an additional Cmd/Fn modifier wins over AltGr.
    value.key_char = Some("a");
    for modifiers in [
        KeyModifiers {
            control: true,
            alt: true,
            platform: true,
            ..Default::default()
        },
        KeyModifiers {
            control: true,
            alt: true,
            function: true,
            ..Default::default()
        },
    ] {
        value.modifiers = modifiers;
        assert_eq!(classify_key(&value), UiAction::None, "{modifiers:?}");
    }
}

#[test]
fn space_key_inserts_a_space_in_all_editing_modes() {
    let mut value = ctx("space");

    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText(" ".into()));

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText(" ".into())
    );

    value.panel = Panel::Vault;
    value.editing_settings = false;
    value.screen = Screen::Locked;
    value.editing_auth = true;
    assert_eq!(classify_key(&value), UiAction::InsertAuthText(" ".into()));

    // A layout-provided space wins, and an empty `key_char` still falls back
    // to the `space` key name in every mode.
    value.key_char = Some(" ");
    assert_eq!(classify_key(&value), UiAction::InsertAuthText(" ".into()));
    value.key_char = Some("");
    assert_eq!(classify_key(&value), UiAction::InsertAuthText(" ".into()));

    value.key_char = Some(" ");
    value.editing_auth = false;
    value.screen = Screen::Unlocked;
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText(" ".into()));
    value.key_char = Some("");
    assert_eq!(classify_key(&value), UiAction::InsertSearchText(" ".into()));

    value.searching = false;
    value.panel = Panel::Settings;
    value.editing_settings = true;
    value.key_char = Some(" ");
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText(" ".into())
    );
    value.key_char = Some("");
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSettingsText(" ".into())
    );
}

#[test]
fn caps_lock_glyphs_keep_lowercase_vault_and_lock_commands_bound() {
    // GPUI lowercases `key` but reports the typed glyph in `key_char`. With
    // Caps Lock a plain letter press reports an uppercase glyph, which must
    // not disable the lowercase command bindings.
    for (glyph, expected) in [
        ("L", UiAction::Lock),
        ("T", UiAction::CycleFilter),
        ("S", UiAction::CycleSort),
        ("F", UiAction::ToggleFavorite),
        ("P", UiAction::CopySelectedPassword),
        ("U", UiAction::CopySelectedUsername),
        ("G", UiAction::OpenAudit),
        ("N", UiAction::SetPanel(Panel::Generator)),
        ("C", UiAction::SetPanel(Panel::Settings)),
        ("Y", UiAction::CopyTotp),
    ] {
        let mut value = ctx("y");
        value.key_char = Some(glyph);
        assert_eq!(classify_key(&value), expected, "vault/{glyph}");
    }

    // The physical key spelling is folded too, for platforms that leave the
    // uppercase letter in `key` when no glyph is reported.
    let mut value = ctx("M");
    value.screen = Screen::Locked;
    assert_eq!(classify_key(&value), UiAction::OpenDemoVault);
    value.key = "R";
    value.login_failed = true;
    assert_eq!(classify_key(&value), UiAction::RetryLogin);
}

#[test]
fn caps_lock_glyphs_keep_generator_and_settings_commands_bound() {
    let mut value = ctx("y");
    value.panel = Panel::Generator;
    for (glyph, expected) in [
        ("N", UiAction::SetPanel(Panel::Vault)),
        ("L", UiAction::Lock),
        ("P", UiAction::GeneratePassword),
        ("H", UiAction::GeneratePassphrase),
        ("W", UiAction::SaveSettings),
        ("D", UiAction::DiscardSettings),
    ] {
        value.key_char = Some(glyph);
        assert_eq!(classify_key(&value), expected, "generator/{glyph}");
    }
    // Shifted symbols are not letters; their existing aliases stay intact.
    value.key_char = Some("+");
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::LengthUp)
    );
    value.key_char = Some("_");
    assert_eq!(
        classify_key(&value),
        UiAction::Generator(GeneratorOption::LengthDown)
    );

    value.panel = Panel::Settings;
    for (glyph, expected) in [
        ("C", UiAction::SetPanel(Panel::Vault)),
        ("L", UiAction::Lock),
        ("D", UiAction::DiscardSettings),
        ("W", UiAction::SaveSettings),
        ("I", UiAction::AdjustIdleLock(1)),
        ("U", UiAction::AdjustIdleLock(-1)),
    ] {
        value.key_char = Some(glyph);
        assert_eq!(classify_key(&value), expected, "settings/{glyph}");
    }

    value.panel = Panel::Audit;
    for (glyph, expected) in [
        ("G", UiAction::SetPanel(Panel::Vault)),
        ("L", UiAction::Lock),
    ] {
        value.key_char = Some(glyph);
        assert_eq!(classify_key(&value), expected, "audit/{glyph}");
    }
}

#[test]
fn caps_lock_uppercase_glyphs_are_inserted_verbatim_in_text_fields() {
    // GPUI lowercases the physical `key` under Caps Lock but reports the typed
    // glyph in `key_char`. Command matching folds ASCII case, while the text
    // insertion path must keep the uppercase glyph exactly as typed.
    for glyph in ["A", "M", "L", "Z"] {
        let ascii = glyph.to_ascii_lowercase();
        let mut value = ctx(&ascii);
        value.key_char = Some(glyph);

        value.searching = true;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertSearchText(glyph.into()),
            "search/{glyph} must stay uppercase"
        );

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertSettingsText(glyph.into()),
            "settings/{glyph} must stay uppercase"
        );

        value.panel = Panel::Vault;
        value.editing_settings = false;
        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertAuthText(glyph.into()),
            "auth/{glyph} must stay uppercase"
        );
    }

    // Even when the physical key also carries an uppercase letter, insertion
    // prefers the glyph and never lowercases layout-provided text.
    let mut value = ctx("A");
    value.key_char = Some("A");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("A".into()));

    // With no glyph at all, the physical key is inserted exactly as reported;
    // that is the documented difference from the glyph path above.
    value.key_char = None;
    value.key = "a";
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("a".into()));
}

#[test]
fn case_folding_preserves_copy_password_and_copy_passphrase() {
    let mut value = ctx("y");
    value.panel = Panel::Generator;

    // Plain lowercase `y` still copies the password.
    assert_eq!(classify_key(&value), UiAction::CopyPassword);

    // Uppercase from `key_char` (Shift+Y, or a Caps Lock press) keeps its
    // distinct passphrase binding instead of collapsing into CopyPassword.
    value.key_char = Some("Y");
    assert_eq!(classify_key(&value), UiAction::CopyPassphrase);

    // Uppercase carried by `key` alone keeps the same distinction.
    value.key_char = None;
    value.key = "Y";
    assert_eq!(classify_key(&value), UiAction::CopyPassphrase);

    // Under Caps Lock, Shift+Y produces a lowercase glyph; that still selects
    // CopyPassword, so both copy bindings remain reachable.
    value.key = "y";
    value.key_char = Some("y");
    assert_eq!(classify_key(&value), UiAction::CopyPassword);
}

#[test]
fn case_folding_does_not_rewrite_non_ascii_or_multi_character_glyphs() {
    // `ß` has no ASCII uppercase form and IME text is multi-character; both
    // must keep their existing edit-mode behaviour after the ASCII-only fold.
    let mut value = ctx("s");
    value.key_char = Some("ß");
    value.searching = true;
    assert_eq!(classify_key(&value), UiAction::InsertSearchText("ß".into()));

    value.key_char = Some("日本語");
    assert_eq!(
        classify_key(&value),
        UiAction::InsertSearchText("日本語".into())
    );
}

#[test]
fn function_key_names_are_never_inserted_while_editing() {
    // A backend may echo the key name into `key_char` (F1 -> "F1"). The single
    // character text path must reject that multi-character string in every
    // editing mode, with and without Alt.
    for (key, key_char) in [
        ("f1", Some("F1")),
        ("f1", Some("f1")),
        ("f1", None),
        ("F1", Some("F1")),
        ("f2", Some("F2")),
        ("f12", Some("F12")),
        ("f1", Some("\u{f1}")),
    ] {
        let mut value = ctx(key);
        value.key_char = key_char;

        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(
            classify_key(&value),
            UiAction::None,
            "auth/{key}/{key_char:?}"
        );

        value.editing_auth = false;
        value.screen = Screen::Unlocked;
        value.searching = true;
        assert_eq!(
            classify_key(&value),
            UiAction::None,
            "search/{key}/{key_char:?}"
        );

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        assert_eq!(
            classify_key(&value),
            UiAction::None,
            "settings/{key}/{key_char:?}"
        );

        value.modifiers.alt = true;
        assert_eq!(
            classify_key(&value),
            UiAction::None,
            "settings/alt/{key}/{key_char:?}"
        );
    }
}

#[test]
fn multi_character_key_char_still_inserts_genuine_compositions() {
    // Regression guard for the Alt + multi-character fallback: limiting
    // `typed_text` to a single glyph must not drop IME commits.
    for (key, key_char) in [("unknown", "日本語"), ("s", "かな文字")] {
        let mut value = ctx(key);
        value.key_char = Some(key_char);

        value.screen = Screen::Locked;
        value.editing_auth = true;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertAuthText(key_char.into())
        );

        value.editing_auth = false;
        value.screen = Screen::Unlocked;
        value.searching = true;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertSearchText(key_char.into())
        );

        value.searching = false;
        value.panel = Panel::Settings;
        value.editing_settings = true;
        value.modifiers.alt = true;
        assert_eq!(
            classify_key(&value),
            UiAction::InsertSettingsText(key_char.into())
        );
    }
}
