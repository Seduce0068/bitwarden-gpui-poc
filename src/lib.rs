//! `bitwarden-gpui-poc`: a personal Bitwarden/Vaultwarden client built on
//! GPUI (`gpui-kit`).
//!
//! The crate is split so that everything that can be tested without a window
//! (the vault model, password generation, TOTP display, vault auditing,
//! settings, and the clipboard policy), plus reusable GPUI view helpers
//! (`ui`, including the app state), lives in this library, while
//! `src/main.rs` only starts the application.
//!
//! Key modules:
//! - [`model`] / [`vault_sync`]: vault data and the bridge from `openwarden`
//! - [`auth`] / [`cache`]: login orchestration and best-effort offline restore
//!   from the encrypted sync cache when `/api/sync` fails
//! - [`generator`] / [`words`]: password and passphrase generation
//! - [`totp`] / [`health`]: RFC 6238 codes and the vault health audit
//! - [`settings`]: persisted configuration
//! - [`ui`]: GPUI view state, input handling and rendering

#![forbid(unsafe_code)]

pub mod auth;
pub mod cache;
pub mod generator;
pub mod health;
pub mod model;
pub(crate) mod private_file;
pub mod settings;
pub mod totp;
pub mod ui;
pub mod vault_sync;
pub mod words;
