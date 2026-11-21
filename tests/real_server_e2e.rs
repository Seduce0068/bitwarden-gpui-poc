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
//! cargo test --test real_server_e2e -- --ignored --nocapture
//! ```
//!
//! When the test is explicitly executed (`--ignored` or `--include-ignored`)
//! but any variable is missing or empty, the test fails and names the
//! offending variable instead of reporting a false success.
//!
//! The test account must contain at least one login with a decryptable
//! password and a decryptable TOTP secret; these are asserted after import.
//!
//! The test account must contain at least one login with a decryptable
//! password and a decryptable TOTP secret; these are asserted after import.
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
    eprintln!(
        "E2E OK: loaded {} items ({} logins) from the real server",
        vault.items.len(),
        logins.len()
    );
}
