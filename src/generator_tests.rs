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
fn generated_passwords_include_every_enabled_class() {
    // Every non-empty combination of the four classes, with and without the
    // ambiguous-character filter, must contribute at least one character.
    for mask in 1u8..=0b1111 {
        for avoid_ambiguous in [false, true] {
            let settings = PasswordSettings {
                length: 12,
                lowercase: mask & 0b0001 != 0,
                uppercase: mask & 0b0010 != 0,
                digits: mask & 0b0100 != 0,
                symbols: mask & 0b1000 != 0,
                avoid_ambiguous,
            };
            let classes = [
                (settings.lowercase, LOWERCASE),
                (settings.uppercase, UPPERCASE),
                (settings.digits, DIGITS),
                (settings.symbols, SYMBOLS),
            ];
            for _ in 0..64 {
                let password = settings.generate().unwrap();
                let chars: Vec<char> = password.chars().collect();
                assert_eq!(chars.len(), 12);
                for (enabled, class) in classes {
                    let present = chars.iter().any(|c| class.contains(*c));
                    assert_eq!(
                        present, enabled,
                        "{password} / mask {mask:04b} / avoid_ambiguous {avoid_ambiguous}"
                    );
                }
                assert!(chars.iter().all(|c| settings.alphabet().contains(*c)));
            }
        }
    }
}

#[test]
fn a_length_smaller_than_the_class_count_is_rejected() {
    let settings = PasswordSettings {
        length: 3,
        ..PasswordSettings::default()
    };
    assert_eq!(settings.generate(), Err(GeneratorError::InvalidSettings));
    let one_class = PasswordSettings {
        length: 1,
        lowercase: true,
        uppercase: false,
        digits: false,
        symbols: false,
        ..PasswordSettings::default()
    };
    assert!(one_class.generate().is_ok());
}

#[test]
fn generated_passwords_are_diverse_and_well_formed() {
    let settings = PasswordSettings::default();
    let pool = settings.alphabet();
    let first = settings.generate().unwrap();
    // Deterministic invariants for the first draw: it is a real password
    // under these settings, not an unrelated sample behind a short circuit.
    assert_eq!(first.chars().count(), settings.length);
    assert!(first.chars().all(|c| pool.contains(c)));

    let mut distinct = std::collections::HashSet::new();
    for _ in 0..32 {
        distinct.insert(settings.generate().unwrap());
    }
    // This is a diversity check, not a collision-free guarantee.
    assert!(distinct.len() > 30, "only {} distinct", distinct.len());
    assert!(distinct.iter().all(|password| {
        password.chars().count() == settings.length && password.chars().all(|c| pool.contains(c))
    }));
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

#[test]
fn empty_separator_concatenates_words() {
    let settings = PassphraseSettings {
        words: 3,
        separator: String::new(),
        capitalize: false,
        include_number: false,
    };
    // With a prefix-free list the concatenation has exactly one possible
    // parse; prefix matching must recover all three words.
    for _ in 0..32 {
        let phrase = settings.generate().unwrap();
        let mut rest = phrase.as_str();
        let mut parsed = Vec::new();
        while !rest.is_empty() {
            let word = WORDS
                .iter()
                .find(|word| rest.starts_with(**word))
                .unwrap_or_else(|| panic!("unparsable fragment in {phrase}: {rest}"));
            parsed.push(*word);
            rest = &rest[word.len()..];
        }
        assert_eq!(parsed.len(), 3, "{phrase}");
        assert!(parsed.iter().all(|word| WORDS.contains(word)), "{phrase}");
    }
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
fn word_list_is_clean_and_prefix_free() {
    assert!(WORDS.len() > 1024, "only {} words", WORDS.len());
    let mut sorted: Vec<&str> = WORDS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), WORDS.len(), "duplicate words");
    assert!(WORDS.iter().all(|word| {
        !word.is_empty() && word.len() >= 3 && word.chars().all(|c| c.is_ascii_lowercase())
    }));
    for first in WORDS {
        for second in WORDS {
            assert!(
                first == second || !second.starts_with(first),
                "{first} is a prefix of {second}"
            );
        }
    }
}

#[test]
fn default_passphrase_is_not_weak() {
    let settings = PassphraseSettings::default();
    let bits = passphrase_entropy(&settings);
    assert!(bits >= 40.0, "default passphrase has only {bits} bits");
    assert_ne!(
        Strength::from_bits(bits),
        Strength::Weak,
        "default passphrase is Weak at {bits} bits"
    );
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
fn every_strength_bucket_has_its_own_label() {
    // The four label branches are part of the detail pane's contract
    // (generator.rs:278-286); a missing branch must not fall back to another
    // bucket's text.
    for (bits, expected) in [
        (f64::from(WEAK_BITS) - 0.1, Strength::Weak),
        (f64::from(WEAK_BITS), Strength::Fair),
        (63.9, Strength::Fair),
        (64.0, Strength::Good),
        (89.9, Strength::Good),
        (90.0, Strength::Strong),
    ] {
        assert_eq!(
            Strength::from_bits(bits).label(),
            expected.label(),
            "{bits}"
        );
    }
    assert_eq!(Strength::Weak.label(), "弱い");
    assert_eq!(Strength::Fair.label(), "ふつう");
    assert_eq!(Strength::Good.label(), "良い");
    assert_eq!(Strength::Strong.label(), "強い");
}

#[test]
fn password_entropy_uses_the_shared_alphabet() {
    let settings = PasswordSettings {
        length: 16,
        ..PasswordSettings::default()
    };
    let expected = entropy_bits(
        LOWERCASE.len() + UPPERCASE.len() + DIGITS.len() + SYMBOLS.len(),
        settings.length,
    );
    assert!((password_entropy(&settings) - expected).abs() < 1e-9);
    let symbols_only = PasswordSettings {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: true,
        ..settings
    };
    assert!((password_entropy(&symbols_only) - entropy_bits(SYMBOLS.len(), 16)).abs() < 1e-9);
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
fn digit_only_ambiguity_filter_uses_the_real_eight_symbol_alphabet() {
    // With only digits enabled, `avoid_ambiguous` removes `0` and `1` and the
    // real pool has eight symbols. The meter must use that actual size, not
    // silently widen it to the audit's ten-symbol PIN model.
    let settings = PasswordSettings {
        length: 12,
        lowercase: false,
        uppercase: false,
        digits: true,
        symbols: false,
        avoid_ambiguous: true,
    };
    assert_eq!(settings.alphabet(), "23456789");
    assert_eq!(settings.alphabet().chars().count(), 8);
    let bits = password_entropy(&settings);
    assert!((bits - entropy_bits(8, 12)).abs() < 1e-9, "{bits}");
    assert_eq!(bits, 36.0, "12 * log2(8) is exact");
    assert_eq!(Strength::from_bits(bits), Strength::Weak);

    // Documented known constraint: the audit still assumes ten symbols, so it
    // reports 40 bits for the same length and the two surfaces disagree. This
    // is deliberately not "fixed" by overstating the drawn pool.
    assert_eq!(crate::health::estimate_entropy("234567892345"), 40);
    assert_eq!(
        Strength::from_bits(crate::health::estimate_entropy("234567892345") as f64),
        Strength::Fair
    );

    // Without the filter the pre-existing alignment holds: the full pool is
    // ten symbols and the rounded 39.86… bits reach the same 40-bit boundary.
    let unfiltered = PasswordSettings {
        avoid_ambiguous: false,
        ..settings
    };
    assert_eq!(unfiltered.alphabet().chars().count(), 10);
    assert_eq!(password_entropy(&unfiltered), 40.0);
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
fn avoid_ambiguous_is_reflected_in_the_entropy_estimate() {
    let full = PasswordSettings {
        length: 20,
        ..PasswordSettings::default()
    };
    let filtered = PasswordSettings {
        avoid_ambiguous: true,
        ..full.clone()
    };
    // The estimated pool must shrink by exactly the six removed characters.
    assert_eq!(
        full.alphabet().chars().count() - filtered.alphabet().chars().count(),
        6
    );
    assert!(password_entropy(&filtered) < password_entropy(&full));
    let expected = entropy_bits(filtered.alphabet().chars().count(), filtered.length);
    assert!((password_entropy(&filtered) - expected).abs() < 1e-9);
}

#[test]
fn passphrase_entropy_covers_all_four_flag_combinations() {
    let base = PassphraseSettings {
        words: 4,
        separator: "-".into(),
        capitalize: false,
        include_number: false,
    };
    let word_bits = entropy_bits(WORDS.len(), base.words);
    assert!((passphrase_entropy(&base) - word_bits).abs() < 1e-9);

    let capitalized = PassphraseSettings {
        capitalize: true,
        ..base.clone()
    };
    assert!((passphrase_entropy(&capitalized) - (word_bits + 4.0)).abs() < 1e-9);

    let numbered = PassphraseSettings {
        include_number: true,
        ..base.clone()
    };
    assert!((passphrase_entropy(&numbered) - (word_bits + (10.0f64).log2())).abs() < 1e-9);

    let both = PassphraseSettings {
        capitalize: true,
        include_number: true,
        ..base
    };
    assert!((passphrase_entropy(&both) - (word_bits + 4.0 + (10.0f64).log2())).abs() < 1e-9);
    assert!(passphrase_entropy(&both) > passphrase_entropy(&capitalized));
    assert!(passphrase_entropy(&both) > passphrase_entropy(&numbered));
}

#[test]
fn random_index_respects_the_bound() {
    for bound in [1u16, 2, 10, 62, 256, WORDS.len() as u16] {
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

#[test]
fn missing_generator_fields_are_filled_from_defaults() {
    // Both settings structs carry `#[serde(default)]` (generator.rs:31-33,
    // 120-123), so a hand-edited settings file that omits fields still yields
    // a usable generator configuration instead of a parse failure.
    let password: PasswordSettings = serde_json::from_str("{}").unwrap();
    assert_eq!(password, PasswordSettings::default());
    let passphrase: PassphraseSettings = serde_json::from_str("{}").unwrap();
    assert_eq!(passphrase, PassphraseSettings::default());

    // A partial object keeps what it supplies and fills every sibling.
    let partial_password: PasswordSettings =
        serde_json::from_str(r#"{"length":32,"avoid_ambiguous":true}"#).unwrap();
    assert_eq!(partial_password.length, 32);
    assert!(partial_password.avoid_ambiguous);
    assert!(partial_password.lowercase);
    assert!(partial_password.uppercase);
    assert!(partial_password.symbols);

    let partial_passphrase: PassphraseSettings =
        serde_json::from_str(r#"{"words":6,"separator":"_"}"#).unwrap();
    assert_eq!(partial_passphrase.words, 6);
    assert_eq!(partial_passphrase.separator, "_");
    assert!(partial_passphrase.capitalize);
    assert!(!partial_passphrase.include_number);
}
