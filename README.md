# bitwarden-gpui-poc

Bitwarden / Vaultwarden の個人 vault 向けクライアントを
[GPUI](https://gpui.rs)（`gpui-kit`）で実装する PoC。

## 目的

- GPUI で Bitwarden クライアント UI を構築できるか検証する
- Rust クレート [`openwarden`](https://crates.io/crates/openwarden) を
  vault API/暗号層として利用する構成を試す

いずれも PoC として実装し、Linux 上での起動と単体テストで確認済みです。
設計判断は [ADR](docs/adr/adr-20261116-openwarden-integration.md) に記録しています。

## 現状

- `src/lib.rs`: vault モデル、パスワード / passphrase 生成、TOTP（RFC 6238）、
  健全性監査、設定の永続化を提供。すべて単体テスト付き
- `src/ui/`: アプリ状態（`app.rs`）、Vault ビュー状態（`vault_view.rs`）、
  アクション（`actions.rs`）、認証フロー
  （`login_flow.rs`）と認証状態（`auth_state.rs`）、クリップボード状態
  （`clipboard.rs`）、キー入力（`input.rs`）、
  モックデータ（`mock.rs`）、GPUI 描画（`render.rs`）、純粋判定ロジック（`logic.rs`）、
  キー分類（`keys.rs`）、時刻判定（`timing.rs`）、TOTP 表示状態
  （`totp_state.rs`）、画面状態の型（`state.rs`）、パネル描画ヘルパー
  （`panels.rs`）
- `src/words.rs`: passphrase 用の単語リスト
- 単体テストは `#[path]` で別ファイルに分割:
  `src/model_tests.rs` / `src/health_tests.rs` /
  `src/generator_tests.rs` / `src/auth_tests.rs` /
  `src/totp_tests.rs` / `src/cache_tests.rs` /
  `src/settings_tests.rs` / `src/vault_sync_tests.rs` /
  `src/ui/keys_tests.rs`
- `src/main.rs`: アプリケーションの起動のみ
- 一覧のフィルタ・ソート・検索は `Vault::view()` に委譲しており、テストと同じロジックを通る
- TOTP は実際の6桁コードを生成し、1秒ごとのカウントダウンを表示する
- 設定は `XDG_CONFIG_HOME` 配下（既定は `~/.config`）の
  `bitwarden-gpui-poc/settings.json` に保存する（パスワードや鍵は保存しない）
- 認証入力と TOTP 表示の秘密は `Zeroizing<String>` で保持し、ロック時に消去する
- vault 項目や設定の `Debug` 出力はパスワード / メール / 個人情報をマスクする
- モックデータには5種類すべての item kind（ログイン / メモ / カード / ID / SSH鍵）を含む
- 生成結果はクリップボードにコピーでき、設定ファイルで指定した秒数
  （既定30秒）後に以前の内容へ自動復元される（ロック時も即復元）
- ロック画面で Personal API key とマスターパスワードを入力し、`openwarden`
  による実ログイン・同期・復号を試せる（モック vault は `m` で明示的に開く）
- KDF 計算は blocking thread で実行し、待機中も UI は操作できる
- ログイン全体にタイムアウトを設定し（設定ファイルで指定、既定30秒）、失敗時は `r` で再試行できる
- 実ログインではログイン項目の名前 / username / URI を復号して表示する。
  パスワードは復号せず空のまま保持し、TOTP は設定の有無のみをマーカーとして
  保持する（値自体は復号しない）
- `src/cache.rs` に、暗号化済みアイテムを含む平文 JSON キャッシュを実装済み
  （キーは保存しない、ファイルは 0600 で作成）。ただし openwarden 0.1.0 の
  API 制約で認証フローからはまだ接続していない

## 画面と操作

| キー | 動作 |
| --- | --- |
| `1`〜`5` | サーバーURL / メール / Client ID / Client Secret / パスワードを編集（ロック画面） |
| `Enter` | 認証情報でログイン（常に実認証を試行） |
| `m` | モック vault を開く（デモ専用） |
| `r` | ログイン失敗時に再試行 |
| `↑` / `↓` | 項目を選択 |
| `f` | お気に入りを切り替え |
| `t` | フィルタを切り替え |
| `s` | 並び順を切り替え |
| `/` | 検索（Enter / Esc で確定） |
| `y` | 選択項目の TOTP コードをコピー（設定した秒数で復元、既定30秒） |
| `g` | 健全性監査パネル（監査結果があるときのみ、再押しで戻る） |
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
`+` / `-` で監査閾値、`i` / `u` で自動ロック時間（1〜60分）を調整し、`w` で保存します。

## ビルドと検証

Rust 1.88 以上が必要です（`Cargo.toml` の `rust-version`）。

```bash
cd work/bitwarden-gpui-poc
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo audit
markdownlint README.md CHANGELOG.md docs/index.md \
  docs/adr/index.md docs/adr/log.md docs/adr/*.md docs/review-report.md
cargo run
```

Linux では Wayland/X11 と GPU ドライバが必要です（`gpui-kit` / wgpu 経由）。

## CI

`.github/workflows/ci.yml` から共通ワークフロー
`Seduce0068/workflows/.github/workflows/rust-gates.yml@v1` を呼び出します。
fmt → check → test → clippy → `cargo audit` → doc のゲートを実行します。
clippy の `unwrap_used` / `expect_used` / `panic` /
`undocumented_unsafe_blocks` deny は `Cargo.toml` の `[lints.clippy]` で
一元管理しています（unsafe は crate root の `forbid` でも禁止）。
監査は脆弱性検出時に失敗し、unmaintained の warning は失敗させません。

## ライセンス

[AGPL-3.0-or-later](LICENSE)（[GNU 公式文書](https://www.gnu.org/licenses/agpl-3.0.txt)）。

設計記録・レビュー結果は [docs/index.md](docs/index.md)、
変更履歴は [CHANGELOG.md](CHANGELOG.md) を参照してください。

## 既知の制約

- openwarden は v0.1 の早期実装（個人 vault 向け、組織/2FA/一部 item type 未対応）
- OS keyring 連携は未実装。秘密は zeroize で最終バッファを消去するが、
  文字列の再確保で生じた旧コピーまでは保証しない
- コピーしたクリップボードは設定ファイルの `clipboard_restore_seconds`
  で指定した秒数（既定30秒）後に復元し、ロック時にも復元するが、
  アプリ強制終了時は復元できない
- 無操作で自動ロックする（既定5分、設定パネルの `i`/`u` で1〜60分に調整可能）
- 実ログイン時はログイン項目のみを変換し、他 kind はモックデータのまま
- パスワードと TOTP シークレットは機密のため検索対象外（監査での有無判定には使用）
- ログインのタイムアウトは設定ファイルの `login_timeout_seconds` で変更可能（既定30秒）
- device identifier は固定値であり、インストールごとの一意性は未保証
- 構造化ログ・メトリクス・監視は未実装
- 本番利用を意図したものではありません
