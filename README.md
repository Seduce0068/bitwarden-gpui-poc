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
  （`login_flow.rs` / `login_generation.rs`）と認証状態（`auth_state.rs`）、
  クリップボード状態
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
- TOTP は RFC 6238 のコード（otpauth URI の `digits` 指定に従う、既定6桁）、
  または Steam の可変長コードを生成し、
  1秒ごとのカウントダウンを表示する
- 設定は `XDG_CONFIG_HOME` 配下（既定は `~/.config`）の
  `bitwarden-gpui-poc/settings.json` に保存する（パスワードや鍵は保存しない）
- 認証入力と TOTP 表示の秘密は `Zeroizing<String>` で保持し、ロック時に消去する
- vault 項目や設定の `Debug` 出力はパスワード / メール / 個人情報をマスクする
- モックデータには5種類すべての item kind（ログイン / メモ / カード / ID / SSH鍵）を含む
- 生成結果はクリップボードにコピーでき、コピー元を読み取れた場合は
  設定ファイルで指定した秒数（既定30秒）後に以前の内容へ自動復元される
  （ロック時も即復元。読み取れなかった場合は復元しない）
- 設定は `settings.json` のスキーマ v1 に従う（下記「設定ファイル」を参照）
- ロック画面で Personal API key（Client ID / Client Secret）とマスターパスワードを
  入力し、`openwarden` による実ログイン・同期・復号を試せる。`Enter` は常に実認証
  であり、モック vault は `m` で明示的に開く
- API key はセッショントークン取得に使う。マスターパスワードはメールアドレスと
  KDF パラメータから復号鍵 `MasterKey` を導出するために使い、設定ファイルには
  保存しない
- KDF 計算と同期データの復号は blocking thread で実行し、待機中も UI は操作できる
- ログインのタイムアウトは認証（prelogin / API key ログイン / sync）から
  KDF による復号鍵導出までを対象とし（設定ファイルで指定、既定30秒）、
  失敗時は `r` で再試行できる。タイムアウト後の vault 復号・取り込みは対象外
- 実ログインではログイン項目の名前 / username / URI に加え、パスワードと
  TOTP シークレットも復号してメモリ上のモデルへ保持する。パスワードは
  監査の強度判定にのみ使い、UI には桁数だけを表示して平文は出さない。
  TOTP は `digits` 指定に従うコードまたは Steam の可変長コード生成に使い、
  シークレット自体は
  表示・コピーしない。実ログイン後は一覧で `p` / `u` / `y` により
  復号済みパスワード / ユーザー名 / TOTP コードをコピーできる
  （実サーバーでの `p` / `u` / `y` の動作確認は未実施）
- **実サーバー E2E は成功**（2026-11-21/22、ローカル Vaultwarden 1.30.2）。
  openwarden 0.1.1 の `Client::sync_body()` で生 body を取得し、既存の
  PascalCase 正規化を本番認証経路へ接続した。opt-in テスト
  （`tests/real_server_e2e.rs`）は実ログイン・sync・復号・取り込みまでを
  検証する。2026-11-22 に kiri 上の Vaultwarden に対して再実行し、
  復号済みパスワードと TOTP コードの検証まで含めて 1 passed を確認済み。
  ただし UI のコピー操作 `p` / `u` / `y` の実サーバー確認は未実施
- `src/cache.rs` に、暗号化済みアイテムを含む平文 JSON キャッシュを実装済み
  （鍵素材は保存しない、ファイルは 0600 で作成）。取得時刻から 7 日で期限切れ。
  読み出しは同期失敗時の復元経路へ接続済み。0.1.1 で生 body が取得できる
  ようになったが、書き出しは接続しない方針（ADR の再裁定を参照）。
  したがって現行ビルドは新規キャッシュを作成せず、バージョン付きキャッシュ
  の 7 日期限判定は旧ビルドが書き出したファイルにも適用される。ただし
  旧ビルドの無印キャッシュは best-effort で許可されるため、期限切れでも
  復元対象になり得る（ADR を参照）

## 実サーバー接続と注意事項

初期設定の手順は次のとおりです。

1. 接続先の Web vault で Personal API key（Client ID / Client Secret）を取得する。
   Vaultwarden の場合、API key 機能が有効である必要がある（有効化手順は
   使用するバージョンに依存するため、ここでは未確認として扱う）。
2. ロック画面で `1`〜`5` からサーバーURL / メール / Client ID / Client Secret /
   マスターパスワードを入力する。`3`〜`5` はメモリ上の認証状態に保持され
   `settings.json` には保存されない。`1` / `2` は設定の共有項目を直接編集するため、
   保存する場合は設定パネルで `w` を押す（`d` で破棄可能）。
3. `Enter` で実認証を試行する。失敗時は `r` で再試行できる。

注意事項:

- API key は vault データの読み取りに加え、アカウントの権限範囲に応じた
  操作が可能になり得る。**実運用アカウントではなく、テスト専用のアカウントを
  使用すること**。専用アカウントには本来の秘密データ以外を置かないこと。
- Client Secret とマスターパスワードは画面入力後もプロセス内存在し、
  ログイン成功時に消去する（`Debug` 出力でもマスクされる）。ただし入力画面は
  共有環境の肩越し閲覧を避けること。
- 復号したパスワードと TOTP シークレットの平文は UI へ表示しない。
  パスワードは監査に使用し、TOTP は `digits` 指定に従うコードまたは
  Steam の可変長コード生成に使用する。Vault パネルでは `p` で復号済みパスワード、`u` でユーザー名、
  `y` で TOTP コードをクリップボードへコピーできる（既定30秒で復元）。
  復号不能・空値・ログイン項目以外ではコピーせず理由を表示する。
  実ログイン後も同じ操作が使えるが、実サーバーでの `p` / `u` / `y` の
  動作確認は未実施

### opt-in E2E の実行

ローカルサーバーは Docker 互換 CLI の `kiri` で起動できます（Docker でも可）。

```bash
echo "--- Vaultwarden 起動（kiri） ---"
kiri pull vaultwarden/server:1.30.2
kiri run --detach --name vw-e2e \
  --env DOMAIN=http://127.0.0.1:8222 \
  --volume /tmp/vw-e2e-data:/data \
  --publish 127.0.0.1:8222:80 \
  vaultwarden/server:1.30.2

echo "--- テスト実行（認証情報はローカルの環境変数で渡す） ---"
export E2E_SERVER_URL=http://127.0.0.1:8222
export E2E_EMAIL='テストアカウントのメール'
export E2E_CLIENT_ID='user.<ユーザー UUID>'
export E2E_CLIENT_SECRET='テストアカウントの API key'
export E2E_MASTER_PASSWORD='テストアカウントのマスターパスワード'
cargo test --test real_server_e2e -- --ignored --nocapture
```

テストアカウントには、復号可能なパスワードと TOTP シークレットを持つ
ログイン項目を 1 件以上登録してください。API key は Web vault のアカウント
設定、または `POST /api/accounts/api-key` で取得できます。誤アカウントや誤復号を
検出したい場合は `E2E_EXPECTED_ITEM_NAME` / `E2E_EXPECTED_PASSWORD` /
`E2E_EXPECTED_TOTP` に既知値を設定すると照合されます（未設定なら必須では
ありません）。実行後は `kiri rm -f vw-e2e` でコンテナを破棄してください。

### 同期キャッシュ

オフライン復元用の `sync-cache.json` の仕様は次のとおりです。

- 保存先: `$XDG_CACHE_HOME/bitwarden-gpui-poc/sync-cache.json`
  （未設定時は `$HOME/.cache/bitwarden-gpui-poc/sync-cache.json`）。
  旧設定ディレクトリ配下のファイルは読み取り専用のフォールバック
- 有効期限: バージョン付きキャッシュは取得時刻から 7 日で、期限切れは
  復元に使わず理由を表示する（現行ビルドは書き出さないため、対象は
  既存ファイル）。ただし旧ビルドの無印キャッシュは best-effort で
  許可され、期限切れでも復元対象になり得る
- フィールド: `version`（スキーマ版数）、`user_id`、`server_url`、
  `body`（暗号化済み同期 JSON の生バイト）、`created_at`（Unix 秒）
- `profile.key` / `privateKey` は保存前に除去し、復号鍵・マスターパスワード・
  API 秘密は書き出さない
- 読み出しのみ本番経路へ接続済み。書き出しは ADR の裁定により未接続

## 画面と操作

| キー | 動作 |
| --- | --- |
| `1`〜`5` | サーバーURL / メール / Client ID / Client Secret / パスワードを編集（ロック画面） |
| `Enter` | 認証情報でログイン（常に実認証を試行） |
| `m` | モック vault を開く（デモ専用） |
| `r` | ログイン失敗時に再試行 |
| `↑` / `↓` | 項目を選択 |
| `PageUp` / `PageDown` | 一覧／監査をページ単位で移動 |
| `Home` / `End` | 一覧／監査の先頭／末尾へ移動 |
| `F1` | フォーカス復帰の案内を表示 |
| `f` | お気に入りを切り替え |
| `t` | フィルタを切り替え |
| `s` | 並び順を切り替え |
| `/` | 検索（Enter / Esc で確定） |
| `y` | 選択項目の TOTP コードをコピー（設定した秒数で復元、既定30秒） |
| `p` | 選択項目のパスワードをコピー（ログイン項目のみ、復号済みの場合） |
| `u` | 選択項目のユーザー名をコピー（ログイン項目のみ） |
| `g` | 健全性監査パネル（監査結果があるときのみ、再押しで戻る） |
| `n` | パスワード生成パネル |
| `c` | 設定パネル |
| `l` | ロック |
| `w` | 設定 / 生成パネルの変更を保存 |
| `d` | 設定 / 生成パネルの未保存変更を破棄 |
| `Esc` | 終了（編集中は入力を確定。キャンセルではない） |

実ログイン後のログイン項目でも `p` / `u` / `y` は同様に動作する（実サーバー
での動作確認は未実施）。

マウスでも操作できます。一覧の行をクリックすると選択でき、ヘッダーの
`[一覧]` / `[監査]` / `[生成]` / `[設定]` ボタンでパネルを切り替えられます。

生成パネルでは `1`〜`7` で文字種・オプションを切り替え、
`+` / `-` で長さと単語数、`,` で区切り文字を変更します。
`p` でパスワード、`h` で passphrase を生成します。
`y` でパスワード、`Y`（Shift+y）で passphrase をクリップボードにコピーします。
設定変更は `w` で保存、`d` で破棄できます。

設定パネルでは `1` / `2` でサーバーURL とメールを編集し、`Enter` で確定します。
`+` / `-` で監査閾値、`i` / `u` で自動ロック時間（1〜60分）、`3` / `4` で
ログインタイムアウト、`5` / `6` でクリップボード復元秒数を調整し、`w` で保存します。

### 設定ファイル

`settings.json` は XDG 設定ディレクトリ（既定は `~/.config/bitwarden-gpui-poc/`）
に保存されます。パスワードや API key は保存されません。スキーマ v1 の
フィールドと既定値は次のとおりです（手編集時は型と範囲に注意）。

下表のドット区切りは JSON のネストを表すパスであり、キー名そのものでは
ありません。たとえば `password_generator.length` は
`{"password_generator": {"length": 20}}` のように保存されます。

| JSON パス | 型 | 既定値 | 範囲・説明 |
| --- | --- | --- | --- |
| `schema_version` | number | `1` | 将来版は破棄。欠落は legacy(0) |
| `server_url` | string | `https://vault.bitwarden.com` | 最大 2048 文字 |
| `email` | string | `""` | 最大 254 文字 |
| `device_id` | string | `""` | UUID v4。初回ログイン時に生成・永続化 |
| `password_generator.length` | number | `20` | 4〜128 |
| `password_generator.lowercase` | bool | `true` | `a-z` を含める |
| `password_generator.uppercase` | bool | `true` | `A-Z` を含める |
| `password_generator.digits` | bool | `true` | `0-9` を含める |
| `password_generator.symbols` | bool | `true` | `!@#$%^&*` を含める |
| `password_generator.avoid_ambiguous` | bool | `false` | 紛らわしい文字を除外 |
| `passphrase_generator.words` | number | `4` | 2〜20 |
| `passphrase_generator.separator` | string | `"-"` | 単語区切り |
| `passphrase_generator.capitalize` | bool | `true` | 単語を大文字開始に |
| `passphrase_generator.include_number` | bool | `false` | 数字を 1 桁追加 |
| `thresholds.weak_bits` | number | `40` | 1〜200（推定エントロピー） |
| `thresholds.stale_days` | number | `365` | 1〜3650（更新からの日数） |
| `idle_lock_seconds` | number | `300` | 60〜3600（1〜60 分） |
| `login_timeout_seconds` | number | `30` | 1〜3600 |
| `clipboard_restore_seconds` | number | `30` | 1〜3600 |

`schema_version` は文字列や整数浮動小数の将来版も拒否します。欠落や不正な
型、および明示的な `0` / `0.0` は legacy(0) として扱い、保存時に現行版へ
昇格します。

数値は型として表現できる範囲外の値がクランプされ、負数・小数など型として
表現できない値は既定値へ置き換えられます。`server_url` / `email` の上限は
認証時だけでなく、設定ファイルの読み込み時にも適用されます。
ファイル全体の上限は 1 MiB です。

## ビルドと検証

Rust 1.95 以上が必要です（`Cargo.toml` の `rust-version`）。

```bash
# このリポジトリのルートで実行
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo audit
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo deny check
markdownlint README.md CHANGELOG.md todo.md 'docs/**/*.md'
cargo run
```

シークレットスキャンは [Betterleaks](https://github.com/betterleaks/betterleaks) を
pre-commit フックとして使います。初回のみ次を実行してください:

```bash
# pre-commit は PEP 668 対応のため uv tool または pipx で導入する
uv tool install pre-commit
# betterleaks 本体はリリースバイナリを ~/.local/bin に配置済みであること
pre-commit install
```

CI でも最終ゲートとして作業ツリーと Git 履歴を走査します（バージョンは
1.10.1 に固定）。`pre-commit autoupdate` でフックを更新する場合は
`.github/workflows/ci.yml` の `BETTERLEAKS_VERSION` も同時に更新してください。

Linux では Wayland/X11 と GPU ドライバが必要です（`gpui-kit` / wgpu 経由）。

Kubuntu 2026.04 での導入例（未検証のため環境に応じて調整してください）:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev \
  libwayland-dev libxkbcommon-dev
# mise を利用する場合（rust-version 1.95 以上）
mise use rust@1.95
```

## CI

`.github/workflows/ci.yml` から共通ワークフロー
`Seduce0068/workflows/.github/workflows/rust-gates.yml@v1` を呼び出します。
fmt → check → test → clippy → `cargo audit` → doc → `cargo deny check` →
markdownlint → Betterleaks（dir と git 履歴）のゲートを実行します。
markdownlint は CI で
`markdownlint-cli@0.50.0` に固定しています。
clippy の `unwrap_used` / `expect_used` / `panic` /
`undocumented_unsafe_blocks` deny は `Cargo.toml` の `[lints.clippy]` で
一元管理しているため、ローカルコマンドでは `-D clippy::<lint>` の個別指定は
行いません（unsafe は crate root の `forbid` でも禁止）。
監査は脆弱性検出時に失敗し、unmaintained の warning は失敗させません。

変更を送る前に、上記のローカルゲートを同じ順序で実行してください。
CI の結果は GitHub の Actions タブで確認できます（`master` は `origin/master`
を追跡しています）。

## 依存のセキュリティ更新

`Cargo.toml` の `gpui-kit` / `openwarden` は `=` でピンしています。これは
gpui-kit の API を固定する明示的な判断であり、ピンを外して解決範囲を広げる
ことはしません。脆弱性が公表された場合は、次の手順で迅速に更新します。

1. `cargo audit` と公表情報（RUSTSEC / GitHub Advisory）で該当クレートと
   影響範囲を確認する
2. 安全なバージョンを特定し、`Cargo.toml` の `=` ピンをそのバージョンへ
   書き換える（現行は openwarden 0.1.1 / gpui-kit 0.9.1）
3. `cargo update -p <crate> --precise <安全なバージョン>` でロックファイルを
   更新する
4. 次のゲートを順に実行する:

   ```bash
   cargo fmt --all -- --check
   cargo check --all-targets --locked
   cargo test --all-targets --locked
   cargo clippy --all-targets --locked -- -D warnings
   cargo audit
   cargo deny check
   ```

5. API 変更があればコードを追従させ、CHANGELOG の `[Unreleased]` と
   openwarden の場合は ADR も更新する

gpui-kit のマイナー更新で API が壊れる場合は、ピン解除ではなく移行作業として
別途対応します。

## ツール版の管理

CI（`.github/workflows/ci.yml`）と pre-commit で共通して使うツールの版は、
次の場所で管理します。

| ツール | CI | pre-commit |
| --- | --- | --- |
| betterleaks | `BETTERLEAKS_VERSION` = 1.10.1 | `rev`（pre-commit config） |
| cargo-deny | `cargo install --version 0.21.0` | — |
| markdownlint-cli | `npm install --global markdownlint-cli@0.50.0` | — |

Betterleaks は CI 起動時に pre-commit の `rev` と一致するか検査し、ずれがあれば
ゲートを失敗させます。他の固定ツールも CI が README の記載と突き合わせ、
片方だけの更新を検出します。最新版の確認は週次の依存監査時に行い、
更新する場合は CI と README の両方を同じ版へ変更してください。

## ドキュメント

- 設計記録・レビュー結果: [docs/index.md](docs/index.md)
- ADR とその更新履歴: [docs/adr/index.md](docs/adr/index.md)
- 変更履歴: [CHANGELOG.md](CHANGELOG.md)

変更を加えたコミットでは、[CHANGELOG.md](CHANGELOG.md) の `## [Unreleased]`
に差分を積み、ADR に影響する場合は
[docs/adr/log.md](docs/adr/log.md) へ `## YYYY-MM-DD` 形式で追記します。

## ライセンス

[AGPL-3.0-or-later](LICENSE)（[GNU 公式文書](https://www.gnu.org/licenses/agpl-3.0.txt)）。

## 既知の制約

- openwarden は v0.1 の早期実装（個人 vault 向け、組織/2FA/一部 item type 未対応）
- OS keyring 連携は未実装。秘密は zeroize で最終バッファを消去するが、
  文字列の再確保で生じた旧コピーまでは保証しない
- コピーしたクリップボードは設定ファイルの `clipboard_restore_seconds`
  で指定した秒数（既定30秒）後に復元し、ロック時にも復元するが、
  アプリ強制終了時は復元できない。コピー元の内容が読めなかった場合
  （空／文字列以外）も復元せず、コピーした内容が残る
- 無操作で自動ロックする（既定5分、設定パネルの `i`/`u` で1〜60分に調整可能）
- 実ログイン時はログイン項目のみを変換し、他 kind は一覧に表示されない
  （PoC の既知制約。モックデータは `m` で開いた場合のみ表示）
- パスワードと TOTP シークレットは機密のため検索対象外（監査での有無判定には使用）
- ログインのタイムアウトは設定ファイルの `login_timeout_seconds` で変更可能（既定30秒）
- 実ログイン時は link-local アドレス / クラウドメタデータホスト / DNS 解決先の
  link-local IP を拒否するが、openwarden 0.1.1 がリダイレクトを追従しないため
  リダイレクト先の検査と DNS rebinding 後の IP ピン留めは未対応
- 構造化ログ・メトリクス・監視は未実装
- 本番利用を意図したものではありません
