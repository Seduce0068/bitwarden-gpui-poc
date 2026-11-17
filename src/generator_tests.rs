#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::generator::*;

#[test]
fn alphabet_follows_the_enabled_classes() {
    let all = PasswordSettings::default();
    assert_eq!(
        all.alphabet().chars().count(),
        LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len()
    );
    let digits_only = PasswordSettings {
        lowercase: false,
        uppercase: false,
        digits: true,
        symbols: false,
        ..PasswordSettings::default()
    };
    assert_eq!(digits_only.alphabet(), DIGITS);
    let none = PasswordSettings {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
        ..PasswordSettings::default()
    };
    assert!(none.alphabet().is_empty());
    assert_eq!(none.generate(), Err(GeneratorError::InvalidSettings));
}

#[test]
fn avoid_ambiguous_removes_only_the_listed_characters() {
    let settings = PasswordSettings {
        avoid_ambiguous: true,
        symbols: false,
        ..PasswordSettings::default()
    };
    let pool = settings.alphabet();
    for ch in AMBIGUOUS {
        assert!(!pool.contains(*ch), "{ch} should be gone");
    }
    assert!(pool.contains('a') && pool.contains('Z') && pool.contains('5'));
    assert_eq!(
        pool.chars().count(),
        LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() - 6
    );
}

#[test]
fn generated_passwords_respect_the_settings() {
    let settings = PasswordSettings {
        length: 32,
        avoid_ambiguous: true,
        ..PasswordSettings::default()
    };
    let pool = settings.alphabet();
    for _ in 0..64 {
        let password = settings.generate().unwrap();
        assert_eq!(password.chars().count(), 32);
        assert!(password.chars().all(|c| pool.contains(c)));
    }
}

#[test]
fn zero_length_is_rejected() {
    let settings = PasswordSettings {
        length: 0,
        ..PasswordSettings::default()
    };
    assert_eq!(settings.generate(), Err(GeneratorError::InvalidSettings));
}

#[test]
fn passwords_are_not_all_the_same() {
    let settings = PasswordSettings::default();
    let first = settings.generate().unwrap();
    let mut distinct = std::collections::HashSet::new();
    for _ in 0..32 {
        distinct.insert(settings.generate().unwrap());
    }
    assert!(distinct.len() > 30, "only {} distinct", distinct.len());
    assert!(distinct.contains(&first) || distinct.len() == 32);
}

#[test]
fn passphrases_use_words_and_the_separator() {
    let settings = PassphraseSettings {
        words: 5,
        separator: ".".to_string(),
        capitalize: false,
        include_number: false,
    };
    let phrase = settings.generate().unwrap();
    let parts: Vec<&str> = phrase.split('.').collect();
    assert_eq!(parts.len(), 5);
    assert!(parts.iter().all(|part| WORDS.contains(part)));
}

#[::core::prelude::v1::test]
fn empty_separator_concatenates_words() {
    let settings = PassphraseSettings {
        words: 3,
        separator: String::new(),
        capitalize: false,
        include_number: false,
    };
    let phrase = settings.generate().unwrap();
    // Three words joined with no separator; each word is still in WORDS.
    assert!(phrase.len() >= 9, "{phrase}");
    assert!(
        WORDS.iter().any(|word| phrase.starts_with(word)),
        "{phrase}"
    );
}

#[test]
fn passphrases_capitalize_and_append_a_digit() {
    let settings = PassphraseSettings {
        words: 3,
        separator: "-".to_string(),
        capitalize: true,
        include_number: true,
    };
    let phrase = settings.generate().unwrap();
    let last = phrase.chars().last().unwrap();
    assert!(last.is_ascii_digit(), "{phrase}");
    let body = &phrase[..phrase.len() - 1];
    for part in body.split('-') {
        let first = part.chars().next().unwrap();
        assert!(first.is_uppercase(), "{part}");
    }
    assert_eq!(settings.words, body.split('-').count());
}

#[test]
fn zero_words_is_rejected() {
    let settings = PassphraseSettings {
        words: 0,
        ..PassphraseSettings::default()
    };
    assert_eq!(settings.generate(), Err(GeneratorError::InvalidSettings));
}

#[test]
fn word_list_is_clean_and_prefix_free_enough() {
    assert!(!WORDS.is_empty(), "empty word list");
    let mut sorted: Vec<&str> = WORDS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), WORDS.len(), "duplicate words");
    assert!(WORDS.iter().all(|word| {
        !word.is_empty() && word.len() >= 3 && word.chars().all(|c| c.is_ascii_lowercase())
    }));
}

#[test]
fn entropy_and_strength_buckets() {
    assert_eq!(entropy_bits(0, 10), 0.0);
    assert_eq!(entropy_bits(1, 10), 0.0);
    assert_eq!(entropy_bits(2, 0), 0.0);
    // 64 symbols * 16 chars = 96 bits.
    assert!((entropy_bits(64, 16) - 96.0).abs() < 1e-9);

    // Exact thresholds belong to the upper bucket.
    assert_eq!(Strength::from_bits(39.9), Strength::Weak);
    assert_eq!(Strength::from_bits(40.0), Strength::Fair);
    assert_eq!(Strength::from_bits(63.9), Strength::Fair);
    assert_eq!(Strength::from_bits(64.0), Strength::Good);
    assert_eq!(Strength::from_bits(89.9), Strength::Good);
    assert_eq!(Strength::from_bits(90.0), Strength::Strong);
    assert_eq!(Strength::from_bits(10.0), Strength::Weak);
    assert_eq!(Strength::from_bits(50.0), Strength::Fair);
    assert_eq!(Strength::from_bits(70.0), Strength::Good);
    assert_eq!(Strength::from_bits(200.0), Strength::Strong);
    assert_eq!(Strength::Weak.score(-10.0), 0, "negative bits clamp to 0");
    assert_eq!(Strength::Weak.score(0.0), 0);
    assert_eq!(Strength::Fair.score(64.0), 50, "64/128 maps to 50");
    assert_eq!(Strength::Strong.score(128.0), 100);
    assert_eq!(Strength::Good.score(1000.0), 100);
    assert_eq!(Strength::Good.label(), "良い");
}

#[test]
fn settings_entropy_tracks_length_and_classes() {
    let settings = PasswordSettings {
        length: 16,
        ..PasswordSettings::default()
    };
    let full = password_entropy(&settings);
    let fewer = password_entropy(&PasswordSettings {
        symbols: false,
        ..settings.clone()
    });
    assert!(full > fewer);
    let longer = password_entropy(&PasswordSettings {
        length: 32,
        ..settings
    });
    assert!((longer - full * 2.0).abs() < 1e-9);
}

#[test]
fn passphrase_entropy_follows_word_count() {
    let base = PassphraseSettings {
        words: 4,
        include_number: false,
        ..PassphraseSettings::default()
    };
    let with_number = PassphraseSettings {
        include_number: true,
        ..base.clone()
    };
    let more_words = PassphraseSettings {
        words: 6,
        ..base.clone()
    };
    assert!(passphrase_entropy(&with_number) > passphrase_entropy(&base));
    assert!(passphrase_entropy(&more_words) > passphrase_entropy(&base));
}

#[test]
fn random_index_respects_the_bound() {
    for bound in [1u16, 2, 10, 62, 256, 994] {
        for _ in 0..256 {
            let value = random_index(bound).unwrap();
            assert!(value < bound, "{value} >= {bound}");
        }
    }
    assert_eq!(random_index(0), Err(GeneratorError::InvalidSettings));
}

#[test]
fn error_messages_are_present() {
    assert!(!GeneratorError::RandomUnavailable.message().is_empty());
    assert!(!GeneratorError::InvalidSettings.message().is_empty());
}

#[test]
fn settings_round_trip_through_json() {
    let settings = PasswordSettings::default();
    let json = serde_json::to_string(&settings).unwrap();
    let back: PasswordSettings = serde_json::from_str(&json).unwrap();
    assert_eq!(settings, back);
    let phrase = PassphraseSettings::default();
    let json = serde_json::to_string(&phrase).unwrap();
    let back: PassphraseSettings = serde_json::from_str(&json).unwrap();
    assert_eq!(phrase, back);
}
