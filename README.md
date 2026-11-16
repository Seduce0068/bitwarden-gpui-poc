# bitwarden-gpui-poc

Bitwarden / Vaultwarden の個人 vault 向けクライアントを
[GPUI](https://gpui.rs)（`gpui-kit`）で実装する PoC。

## 目的

- GPUI で Bitwarden クライアント UI を構築できるか検証する
- Rust クレート [`openwarden`](https://crates.io/crates/openwarden) を vault API/暗号層として利用する構成を試す

## 現状

- `src/lib.rs`: vault モデル、パスワード / passphrase 生成、TOTP（RFC 6238）、健全性監査、設定の永続化を提供。すべて単体テスト付き
- `src/ui/`: アプリ状態（`app.rs`）、アクション（`actions.rs`）、認証フロー
  （`auth.rs`）、キー入力（`input.rs`）、モックデータ（`mock.rs`）、GPUI 描画
  （`render.rs`）、純粋判定ロジックとそのテスト（`logic.rs` / `timing.rs`）、
  画面状態の型（`model.rs`）、パネル描画ヘルパー（`panels.rs`）
- `src/main.rs`: アプリケーションの起動のみ
- 一覧のフィルタ・ソート・検索は `Vault::view()` に委譲しており、テストと同じロジックを通る
- TOTP は実際の6桁コードを生成し、1秒ごとのカウントダウンを表示する
- 設定は `XDG_CONFIG_HOME` 配下（既定は `~/.config`）の
  `bitwarden-gpui-poc/settings.json` に保存する（パスワードや鍵は保存しない）
- モックデータには5種類すべての item kind（ログイン / メモ / カード / ID / SSH鍵）を含む
- 生成結果はクリップボードにコピーでき、30秒後に以前の内容へ自動復元される（ロック時も即復元）
- ロック画面で Personal API key とマスターパスワードを入力し、`openwarden`
  による実ログイン・同期・復号を試せる（認証情報が未入力ならモック vault）
- KDF 計算は blocking thread で実行し、待機中も UI は操作できる
- ログイン全体に 30 秒のタイムアウトを設定し、失敗時は `r` で再試行できる
- 実ログインではログイン項目の名前 / username / URI を復号して表示する。
  パスワードと TOTP 秘密は復号せず、有無と長さのマーカーのみ保持する
- `src/cache.rs` に、暗号化済みアイテムを含む平文 JSON キャッシュを実装済み
  （キーは保存しない、ファイルは 0600 で作成）。ただし openwarden 0.1.0 の
  API 制約で認証フローからはまだ接続していない

## 画面と操作

| キー | 動作 |
| --- | --- |
| `1`〜`5` | サーバーURL / メール / Client ID / Client Secret / パスワードを編集（ロック画面） |
| `Enter` | 認証情報でログイン（未入力ならモック vault を開く） |
| `r` | ログイン失敗時に再試行 |
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

マウスでも操作できます。一覧の行をクリックすると選択でき、ヘッダーの
`[一覧]` / `[監査]` / `[生成]` / `[設定]` ボタンでパネルを切り替えられます。

生成パネルでは `1`〜`7` で文字種・オプションを切り替え、
`+` / `-` で長さと単語数、`,` で区切り文字を変更します。
`p` でパスワード、`h` で passphrase を生成します。
`y` でパスワード、`Y`（Shift+y）で passphrase をクリップボードにコピーします。

設定パネルでは `1` / `2` でサーバーURL とメールを編集し、`Enter` で確定します。
`+` / `-` で監査閾値を調整すると即座に再監査され、`w` で保存します。

## ビルドと検証

```bash
cd work/bitwarden-gpui-poc
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo run
```

Linux では Wayland/X11 と GPU ドライバが必要です（`gpui-kit` / wgpu 経由）。

## CI

`.github/workflows/ci.yml` から共通ワークフロー
`Seduce0068/workflows/.github/workflows/rust-gates.yml@v1` を呼び出します。
fmt → check → test → clippy → `cargo audit` のゲートを実行します。
clippy では加えて `unwrap_used` / `expect_used` / `panic` を deny します。
監査は脆弱性検出時に失敗し、unmaintained の warning は失敗させません。

変更履歴は [CHANGELOG.md](CHANGELOG.md) を参照してください。

## 既知の制約

- openwarden は v0.1 の早期実装（個人 vault 向け、組織/2FA/一部 item type 未対応）
- セキュリティ上の配慮のうち、OS keyring 連携と完全なロック時メモリ保護は未実装
- クリップボードは30秒で復元し、ロック時にも復元するが、アプリ強制終了時は復元できない
- 5分間無操作すると自動ロックする（マウス・キー操作で最終操作時刻を更新）
- 実ログイン時はログイン項目のみを変換し、他 kind はモックデータのまま
- device identifier は固定値であり、インストールごとの一意性は未保証
- 構造化ログ・メトリクス・監視は未実装
- 本番利用を意図したものではありません
