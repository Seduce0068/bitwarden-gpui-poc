//! Application entry point for the Bitwarden/Vaultwarden GPUI PoC.
//!
//! All UI state and behaviour live in `bitwarden_gpui_poc::ui`; this binary
//! only creates the window and starts the event loop.

#![forbid(unsafe_code)]

use bitwarden_gpui_poc::ui::app::BitwardenApp;
use gpui_kit::*;

fn main() {
    let app = gpui_kit::application();
    app.run(|cx: &mut App| {
        gpui_kit::init(cx);

        // The unsaved-settings gate lives in `Window::on_window_should_close`
        // below: GPUI documents `on_window_closed` as running after the window
        // is no longer accessible, so the app entity cannot be read here.
        // This observer only performs the final quit once the close actually
        // went through.
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

        if let Err(error) = gpui_kit::open_window(options, cx, |window, cx| {
            let view = cx.new(BitwardenApp::new);
            // Gate the WM close request while the window and the app entity
            // are still alive. Returning false cancels the close, which keeps
            // `on_window_closed` (and therefore `cx.quit()`) from firing while
            // settings are unsaved. A weak handle avoids a window <-> entity
            // reference cycle.
            let weak_view = view.downgrade();
            window.on_window_should_close(cx, move |_window, cx| {
                weak_view
                    .update(cx, |app, cx| app.allow_window_close(cx))
                    .unwrap_or(true)
            });
            let focus_handle = view.read(cx).focus_handle.clone();
            focus_handle.focus(window, cx);
            view
        }) {
            eprintln!("ウィンドウを開けませんでした: {error:?}");
            // No window exists, so `on_window_closed` can never fire.
            cx.quit();
            return;
        }

        cx.activate(true);
    });
}
