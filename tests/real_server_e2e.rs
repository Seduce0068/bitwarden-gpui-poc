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
//! No credentials are stored in this file or in the repository.

#![allow(clippy::expect_used, clippy::panic)]

use bitwarden_gpui_poc::auth::{authenticate_with_timeout, unlock_and_import, AuthConfig};
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

    eprintln!(
        "E2E OK: loaded {} items from the real server",
        vault.items.len()
    );
}
