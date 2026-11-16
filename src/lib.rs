//! `bitwarden-gpui-poc`: a personal Bitwarden/Vaultwarden client built on
//! GPUI (`gpui-kit`).
//!
//! The crate is split so that everything that can be tested without a window
//! (the vault model, password generation, TOTP display, vault auditing,
//! settings, and the clipboard policy), plus reusable GPUI view helpers
//! (`ui`, including the app state), lives in this library, while
//! `src/main.rs` only starts the application.

pub mod auth;
pub mod cache;
pub mod generator;
pub mod health;
pub mod model;
pub mod settings;
pub mod totp;
pub mod ui;
pub mod vault_sync;
