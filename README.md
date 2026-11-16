# bitwarden-gpui-poc

Bitwarden / Vaultwarden の個人 vault 向けクライアントを
[GPUI](https://gpui.rs)（`gpui-kit`）で実装する PoC。

## 目的

- GPUI で Bitwarden クライアント UI を構築できるか検証する
- Rust クレート [`openwarden`](https://crates.io/crates/openwarden) を vault API/暗号層として利用する構成を試す

## 現状

- `src/lib.rs`: vault モデル、パスワード / passphrase 生成、TOTP（RFC 6238）、健全性監査、設定の永続化を提供。すべて単体テスト付き
- `src/main.rs`: GPUI によるロック画面と、一覧 / 監査 / 生成 / 設定の4パネル
- 一覧のフィルタ・ソート・検索は `Vault::view()` に委譲しており、テストと同じロジックを通る
- TOTP は実際の6桁コードを生成し、1秒ごとのカウントダウンを表示する
- 設定は `~/.config/bitwarden-gpui-poc/settings.json` に保存する（パスワードや鍵は保存しない）
- モックデータには5種類すべての item kind（ログイン / メモ / カード / ID / SSH鍵）を含む
- 生成結果はクリップボードにコピーでき、30秒後に以前の内容へ自動復元される（ロック時も即復元）
- ロック画面で Personal API key とマスターパスワードを入力し、`openwarden`
  による実ログイン・同期・復号を試せる（認証情報が未入力ならモック vault）
- KDF 計算は blocking thread で実行し、待機中も UI は操作できる

## 画面と操作

| キー | 動作 |
| --- | --- |
| `1`〜`5` | サーバーURL / メール / Client ID / Client Secret / パスワードを編集（ロック画面） |
| `Enter` | 認証情報でログイン（未入力ならモック vault を開く） |
| `↑` / `↓` | 項目を選択 |
| `f` | お気に入りを切り替え |
| `t` | フィルタを切り替え |
| `s` | 並び順を切り替え |
| `/` | 検索（Enter / Esc で確定） |
| `y` | 選択項目の TOTP コードをコピー（30秒で復元） |
| `g` | 健全性監査パネル（再押しで戻る） |
| `n` | パスワード生成パネル |
| `c` | 設定パネル |
| `l` | ロック |
| `Esc` | 終了 |

生成パネルでは `1`〜`7` で文字種・オプションを切り替え、
`+` / `-` で長さと単語数、`,` で区切り文字を変更します。
`p` でパスワード、`h` で passphrase を生成します。
`y` でパスワード、`Y`（Shift+y）で passphrase をクリップボードにコピーします。

設定パネルでは `1` / `2` でサーバーURL とメールを編集し、`Enter` で確定します。
`+` / `-` で監査閾値を調整すると即座に再監査され、`w` で保存します。

## ビルドと検証

```bash
cd work/bitwarden-gpui-poc
cargo fmt --check
cargo check
cargo test
cargo clippy -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo run
```

Linux では Wayland/X11 と GPU ドライバが必要です（`gpui-kit` / wgpu 経由）。

## 既知の制約

- openwarden は v0.1 の早期実装（個人 vault 向け、組織/2FA/一部 item type 未対応、roadmap 参照）
- セキュリティ上の配慮（OS keyring 連携、クリップボード自動消去、ロック時のメモリ保護など）は未実装
- 実ログイン時はログイン項目のみを変換し、他 kind はモックデータのまま
- device identifier は固定値であり、インストールごとの一意性は未保証
- 本番利用を意図したものではありません
