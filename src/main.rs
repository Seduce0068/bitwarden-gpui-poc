//! Bitwarden/Vaultwarden client PoC built with GPUI (`gpui-kit`).
//!
//! The UI renders a [`Vault`] from the library crate: filtering, sorting and
//! searching all go through [`Vault::view`], so the same logic is exercised by
//! both the window and the tests. Login/sync/decrypt are handled by the
//! `auth` and `vault_sync` modules.

#![forbid(unsafe_code)]

use bitwarden_gpui_poc::ui::app::BitwardenApp;
use gpui_kit::*;

fn main() {
    let app = gpui_kit::application();
    app.run(|cx: &mut App| {
        gpui_kit::init(cx);

        cx.on_window_closed(|cx, _window_id| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let bounds = Bounds::centered(None, size(px(980.0), px(640.0)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("Bitwarden GPUI PoC".into()),
                ..Default::default()
            }),
            focus: true,
            show: true,
            app_id: Some("bitwarden-gpui-poc".to_string()),
            ..Default::default()
        };

        if gpui_kit::open_window(options, cx, |window, cx| {
            let view = cx.new(BitwardenApp::new);
            let focus_handle = view.read(cx).focus_handle.clone();
            focus_handle.focus(window, cx);
            view
        })
        .is_err()
        {
            eprintln!("ウィンドウを開けませんでした");
            return;
        }

        cx.activate(true);
    });
}
