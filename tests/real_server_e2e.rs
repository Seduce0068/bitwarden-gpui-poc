//! Opt-in end-to-end check against a real Bitwarden-compatible server.
//!
//! This test is `#[ignore]` by default because it needs a throwaway test
//! account on a reachable server. To run it, set the credentials in the
//! environment and pass `--ignored`:
//!
//! ```bash
//! export E2E_SERVER_URL=http://127.0.0.1:8222
//! export E2E_CLIENT_ID=user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
//! export E2E_CLIENT_SECRET=...
//! export E2E_EMAIL=e2e@example.com
//! export E2E_MASTER_PASSWORD=...
//! export E2E_EXPECTED_ITEM_NAME=...   # optional: exact login item name
//! export E2E_EXPECTED_PASSWORD=...    # optional: exact decrypted password
//! export E2E_EXPECTED_TOTP=...        # optional: exact TOTP secret
//! cargo test --test real_server_e2e -- --ignored --nocapture
//! ```
//!
//! When the test is explicitly executed (`--ignored` or `--include-ignored`)
//! but any *required* variable is missing or empty, the test fails and names
//! the offending variable instead of reporting a false success.
//!
//! The test account must contain at least one login with a decryptable
//! password and a decryptable TOTP secret; these are asserted after import.
//! The three `E2E_EXPECTED_*` variables are optional: when one is set and
//! non-empty, the decrypted item name, password or TOTP secret of at least one
//! login must equal it exactly. When it is unset or empty, only the original
//! non-empty checks apply, so an existing account can be reused without
//! publishing its fixture values in the environment.
//!
//! No credentials are stored in this file or in the repository.

#![allow(clippy::expect_used, clippy::panic)]

use bitwarden_gpui_poc::auth::{authenticate_with_timeout, unlock_and_import, AuthConfig};
use bitwarden_gpui_poc::totp::{code_at, now_unix};
use bitwarden_gpui_poc::vault_sync::{is_undecryptable_totp, UNDECRYPTABLE_PASSWORD};
use openwarden::SecretString;
use std::time::Duration;

/// Returns the value, or the reason it cannot be used (`missing` / `empty`).
fn env_state(name: &str) -> Result<String, &'static str> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err("empty"),
        Err(_) => Err("missing"),
    }
}

#[tokio::test]
#[ignore = "requires a real server and test credentials via E2E_* environment variables"]
async fn real_server_login_sync_and_unlock() {
    let names = [
        "E2E_SERVER_URL",
        "E2E_CLIENT_ID",
        "E2E_CLIENT_SECRET",
        "E2E_EMAIL",
        "E2E_MASTER_PASSWORD",
    ];
    let mut values = Vec::new();
    let mut problems = Vec::new();
    for name in names {
        match env_state(name) {
            Ok(value) => values.push(value),
            Err(reason) => problems.push(format!("{name} ({reason})")),
        }
    }
    assert!(
        problems.is_empty(),
        "this ignored test was executed (--ignored or --include-ignored), \
         so unusable credentials are a failure: {}",
        problems.join(", ")
    );
    let server_url = values[0].clone();
    let client_id = values[1].clone();
    let client_secret = values[2].clone();
    let email = values[3].clone();
    let master_password = values[4].clone();

    let config = AuthConfig {
        server_url,
        client_id,
        client_secret: SecretString::from(client_secret),
        email,
        master_password: SecretString::from(master_password),
    };

    let authenticated =
        authenticate_with_timeout(&config, "e2e-device-000000000001", Duration::from_secs(60))
            .await
            .expect("real server login must succeed with valid test credentials");

    assert!(
        !authenticated.from_cache,
        "a successful live sync must not be tagged as a cache restore"
    );

    let vault = smol::unblock(move || unlock_and_import(authenticated))
        .await
        .expect("decryption and import must succeed with the test vault");

    // A successful HTTP 200 is not enough: an empty or wholly undecryptable
    // vault must fail so that regressions in sync/import cannot pass as green.
    assert!(
        !vault.items.is_empty(),
        "real sync returned an empty vault; check the E2E test account"
    );
    let logins: Vec<_> = vault.items.iter().filter_map(|item| item.login()).collect();
    assert!(
        !logins.is_empty(),
        "real sync returned no login items; check the E2E test account"
    );
    assert!(
        logins
            .iter()
            .any(|(_, password, _, _)| !password.is_empty() && *password != UNDECRYPTABLE_PASSWORD),
        "no login password decrypted; E2E must verify real decrypted fields"
    );
    assert!(
        logins.iter().any(|(_, _, totp, _)| {
            !totp.is_empty() && !is_undecryptable_totp(totp) && code_at(totp, now_unix()).is_ok()
        }),
        "no usable TOTP secret decrypted; E2E must verify real TOTP fields"
    );

    // Optional known-value checks. A set (non-empty) expectation must match a
    // decrypted field exactly; an unset one keeps the checks above unchanged
    // so an existing E2E account does not have to expose its fixture values.
    let expected_name = std::env::var("E2E_EXPECTED_ITEM_NAME")
        .ok()
        .filter(|value| !value.is_empty());
    let expected_password = std::env::var("E2E_EXPECTED_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    let expected_totp = std::env::var("E2E_EXPECTED_TOTP")
        .ok()
        .filter(|value| !value.is_empty());

    match (&expected_name, &expected_password, &expected_totp) {
        (Some(name), Some(password), Some(totp)) => {
            // All three values were supplied: require one single login item
            // that carries all of them, so a field mix-up between different
            // items cannot pass as green.
            assert!(
                vault.items.iter().any(|item| {
                    item.name.as_str() == name.as_str()
                        && item.login().is_some_and(|(_, actual_pw, actual_totp, _)| {
                            actual_pw == password.as_str() && actual_totp == totp.as_str()
                        })
                }),
                "E2E_EXPECTED_* values must belong to the same decrypted login item"
            );
        }
        _ => {
            // Backwards compatible: each supplied value is checked on its own.
            if let Some(name) = &expected_name {
                assert!(
                    vault
                        .items
                        .iter()
                        .any(|item| item.login().is_some() && item.name.as_str() == name.as_str()),
                    "E2E_EXPECTED_ITEM_NAME was set but no decrypted login item matched"
                );
            }
            if let Some(password) = &expected_password {
                assert!(
                    logins
                        .iter()
                        .any(|(_, actual, _, _)| *actual == password.as_str()),
                    "E2E_EXPECTED_PASSWORD was set but no decrypted login password matched"
                );
            }
            if let Some(totp) = &expected_totp {
                assert!(
                    logins
                        .iter()
                        .any(|(_, _, actual, _)| *actual == totp.as_str()),
                    "E2E_EXPECTED_TOTP was set but no decrypted login TOTP secret matched"
                );
            }
        }
    }

    eprintln!(
        "E2E OK: loaded {} items ({} logins) from the real server",
        vault.items.len(),
        logins.len()
    );
}
