# bitwarden-gpui-poc

Bitwarden / Vaultwarden の個人 vault 向けクライアントを [GPUI](https://www.gpui.rs/)（`gpui-kit`）で実装する PoC。

## 目的

- GPUI で Bitwarden クライアント UI を構築できるか検証する
- Rust クレート [`openwarden`](https://crates.io/crates/openwarden) を vault API/暗号層として利用する構成を試す

## 現状

- ロック画面 / vault 一覧の UI スケルトン（モックデータ）
- 実際のログイン・同期・復号は未接続（`openwarden` 統合は今後の作業）

## ビルド

```bash
cd work/bitwarden-gpui-poc
cargo check
cargo run
```

Linux では Wayland/X11 と GPU ドライバが必要です（`gpui-kit` / wgpu 経由）。

## 既知の制約

- openwarden は v0.1 の早期実装（個人 vault 向け、組織/2FA/一部 item type 未対応、roadmap 参照）
- セキュリティ上の配慮（OS keyring 連携、クリップボード自動消去、ロック時のメモリ保護など）は未実装
- 本番利用を意図したものではありません
