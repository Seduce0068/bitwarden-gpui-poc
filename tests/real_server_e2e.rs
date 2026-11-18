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
//! No credentials are stored in this file or in the repository.

#![allow(clippy::expect_used)]

use bitwarden_gpui_poc::auth::{authenticate_with_timeout, unlock_and_import, AuthConfig};
use openwarden::SecretString;
use std::time::Duration;

fn required(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::test]
#[ignore = "requires a real server and test credentials via E2E_* environment variables"]
async fn real_server_login_sync_and_unlock() {
    let (
        Some(server_url),
        Some(client_id),
        Some(client_secret),
        Some(email),
        Some(master_password),
    ) = (
        required("E2E_SERVER_URL"),
        required("E2E_CLIENT_ID"),
        required("E2E_CLIENT_SECRET"),
        required("E2E_EMAIL"),
        required("E2E_MASTER_PASSWORD"),
    )
    else {
        eprintln!("E2E_* environment variables are not set; nothing to verify");
        return;
    };

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
