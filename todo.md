---
type: Todo
title: "bitwarden-gpui-poc プロジェクトTODO"
description: "bitwarden-gpui-poc 固有のタスク。クロスレビュー派生タスクを含む。横断タスクはグローバルTODOへ。"
tags:
  - todo
  - tasks
  - review
  - "bitwarden-gpui-poc"
generated:
    by: opencode
    at: "2026-11-17T20:11:47+09:00"
verified:
    by: "dsh-agent (lead)"
    at: "2026-11-18T20:25:50+09:00"
status: current
stale_after: "2027-05-17T21:04:43+09:00"
---

## 進行中

なし。クロスレビューは修正を行わない（read-only）方針で実施した。

## 未着手

### 優先度 高

なし（2026-11-18 時点、第10弾で1件完了）。

### 優先度 中

- [ ] Vaultwarden の sync JSON が PascalCase の場合に openwarden が解析できない
      問題を解消 — 根拠 `tests/real_server_e2e.rs`,
      `docs/adr/adr-20261116-openwarden-integration.md` / 重大度 medium
  - ローカル Vaultwarden 1.30.2 では API key 認証と `/api/sync` の HTTP 200 まで
    到達したが、レスポンスが `Profile` / `Ciphers` 等の PascalCase で、
    openwarden 0.1.0 の `SyncWire`（camelCase 要求）がパースに失敗。
    対応方針: camelCase を返すサーバーバージョンへ固定するか、取り込み前に
    camelCase へ正規化する層を追加する。
  - 進捗（第26弾）: `parse_sync` に再帰的なキー正規化を追加しキャッシュ経路は
    解析可能に（278 passed、R4 指摘 3 件反映）。ただし実サーバーで E2E を
    再実行しても認証経路は失敗。openwarden の `Client::sync()` が内部で
    `from_json` を呼び正規化を通らないため。上流対応または自前 HTTP
    クライアント化が必要で、未解決として残す。

### 優先度 低

- [ ] `unlock_detail` の日本語 prefix/suffix 文字列依存を構造化 detail へ置換 — 根拠
      `src/error.rs:408-415,435-441` / R1-ST02-F6 / 重大度 low
- [ ] `PartialEq for AppError` が表示文のみで比較し boxed cause を無視する点を見直す — 根拠
      `src/error.rs:343-349,245-248` / R2-ER01-F2, R5-AP01-F2 / 重大度 low
- [ ] `error.rs` の auth/settings への逆依存（循環）を解消 — 根拠 `src/error.rs:367,448`,
      `src/auth.rs:21` / R1-AR02-F1 / 重大度 low
- [ ] 階層別エラー型の別名を実型または AppError 一本へ統一 — 根拠 `src/vault_sync.rs:62`,
      `src/generator.rs:28`, `src/totp.rs:89` / R1-AR01-F4 / 重大度 low
- [ ] `generator::WORDS` の再エクスポートを削除し公開パスを一本化 — 根拠 `src/generator.rs:10`,
      `src/lib.rs:24,32` / R1-AR01-F5 / 重大度 low
- [ ] ジェネレータ設定のキー文字列の往復を型付き enum へ — 根拠 `src/ui/keys.rs:276-285`,
      `src/ui/actions.rs:118-122` / R1-AR03-F1, R5-AP02-F1 / 重大度 low
- [ ] `KeyAction` とマウス由来 `SelectRow` の境界を明確化（リネームまたは分離） — 根拠
      `src/ui/keys.rs:68-70`, `src/ui/render.rs:99-104` / R1-AR03-F2 / 重大度 low
- [ ] 監査レポート欠如時のフォールバック判定を `effective_panel` に一本化 — 根拠 `src/ui/logic.rs:37-47`,
      `src/ui/app.rs:243`, `src/ui/render.rs:317-320` / R1-AR03-F3 / 重大度 low
- [ ] `visible_items` と選択 index 計算を `VaultViewState` へ集約し `next_index` を本番化 —
      根拠 `src/ui/app.rs:197-201,247-267`, `src/ui/vault_view.rs:50-52,112-124` /
      R1-AR03-F4, R4-TS02-F1 / 重大度 low
- [ ] ServerUrl/Email の共有フィールド編集を `Settings` 側へ集約 — 根拠
      `src/ui/actions.rs:76-94`, `src/ui/login_flow.rs:184-202` / R1-AR03-F5 / 重大度
      low
- [ ] 未使用 `has_credentials` と矛盾する doc を削除または実ゲート化 — 根拠 `src/ui/logic.rs:7-15`,
      `src/ui/login_flow.rs:61-69` / R1-AR03-F6, R1-ST03-F4 / 重大度 low
- [ ] クリップボード復元手続きを単一サービスへ集約し lock 経路の status を整合 — 根拠
      `src/ui/clipboard.rs:3-4`, `src/ui/actions.rs:56-62`,
      `src/ui/app.rs:161-164` / R1-AR03-F7 / 重大度 low
- [ ] クリップボード復元秒数／ログインタイムアウトを GUI 編集可能化 — 根拠 `src/ui/panels.rs:250-255`,
      `src/ui/keys.rs:299-311` / R1-ST03-F6 / 重大度 low
- [ ] `revision_date` パース失敗の 0 フォールバックを明示的な未設定値へ — 根拠
      `src/vault_sync.rs:161,358` / R2-ER02-F2, R3-DI01-F1 / 重大度 low
- [ ] 名前ソートを検索と同じ NFKD 正規化へ — 根拠 `src/model.rs:859-863`, `src/model.rs:25` /
      R3-IV03-F3 / 重大度 low
- [ ] TOTP `Code` の `PartialEq` が code 値を無視する点をテスト意図に合わせる — 根拠
      `src/totp.rs:22-25` / R3-DI01-F3 / 重大度 low
- [ ] `login_generation` の「トークン消費」テストを実消費へ — 根拠
      `src/ui/login_generation.rs:75-82` / R4-TS02-F2 / 重大度 low
- [ ] テストの空振り分岐／値捨てをアサーションへ — 根拠 `src/model_tests.rs:253-257`,
      `src/health_tests.rs:336-339`, `src/generator_tests.rs:75-85` /
      R1-ST04-F1〜F3 / 重大度 low
- [ ] `InsecureUri` 判定の先頭 Cf 文字バイパスを inspection に追加 — 根拠 `src/health.rs:513`,
      `src/model.rs:36` / R3-IV03-F1 / 重大度 low

## 完了

- [x] UX 文言と CI 設定の小規模修正（2026-11-20・第28弾）
  - 根拠: `src/ui/panels.rs:172`, `src/ui/actions.rs:11-24`,
    `.github/dependabot.yml:6`, `.github/workflows/ci.yml:25` / 重大度 low 6件
  - 設定パネルの dead hint 修正、復元秒数の設定値表示、TOTP 空一覧の文言、
    未生成時の通知、Dependabot の Actions 追跡、cargo-deny の exact 固定と
    `cargo doc --locked`。
  - 検証: fmt / check / test（279 passed）/ clippy / doc / gitleaks /
    YAML / markdownlint 成功。
  - R4 指摘 2 件を反映（生成値への「復号」文言誤用、空一覧と未選択の区別）。
- [x] `settings.json` のスキーマを README へ文書化（2026-11-20・第27弾）
  - 根拠: `README.md:38-39,178-184`, `src/settings.rs:260-281` /
    R2-CF01-F3 / 重大度 medium
  - 全フィールドの型・既定値・クランプ範囲を表形式で追加。
  - 検証: markdownlint / `bash -n` 成功（ドキュメントのみ）。
  - R4 指摘 2 件を反映（数値のクランプと型失敗フォールバックの区別、
    文字列上限が認証時に適用される点）。
- [x] 低優先度のレビュー指摘を整理（2026-11-20・第25弾）
  - 根拠: `docs/index.md:6`, `src/ui/app.rs:64-68`, `.github/workflows/ci.yml:21`,
    `.gitignore:1`, `src/model.rs:693` / 重大度 low 5件
  - 索引の superseded 明記、設定パス未取得の誤案内解消、MSRV 1.88 の CI
    検証、秘密ファイルの ignore、未使用 `Vault.unlocked` の削除。
  - 検証: fmt / check / test（274 passed）/ clippy / doc / gitleaks /
    YAML / markdownlint 成功。
  - R4 指摘 4 件を反映。MSRV は 1.88 では依存がビルド不能なため、
    Runtime Proof（1.88/1.92/1.93/1.94 失敗・1.95 成功）に基づき
    Cargo.toml・CI・README を 1.95 へ統一。OKF status は `deprecated` に修正。
- [x] 選択項目のパスワード／ユーザー名をコピー可能化（2026-11-20・第24弾）
  - 根拠: `src/ui/keys.rs:321`, `src/ui/app.rs:333` / R1-FG-ui, R4-VU-ui /
    重大度 medium
  - Vault パネルの `p` / `u` でコピー。復号不能・空値・非ログイン項目は
    拒否し理由を表示。判定を純粋関数化してテスト。
  - 検証: fmt / check / test（274 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。
  - R4 指摘 2 件を反映（README の安全性記述、キー割当と分岐のテスト）。
    併せて flaky だった環境変数テストに ENV_LOCK を追加。
- [x] CI にシークレットスキャンを追加（2026-11-20・第23弾）
  - 根拠: `.github/workflows/ci.yml:24` / R3-AU-ops, R3-DE-ops /
    重大度 medium
  - gitleaks 8.28.0 を pre-commit 主軸・CI 最終ゲートで導入。テスト
    フィクスチャの誤検知を解消し、ローカルで 0 件を確認。
  - 検証: YAML パース / `bash -n` / gitleaks dir+git 0 件 / markdownlint 成功。
  - R4 指摘 6 件を反映（空振りアサーション、履歴スキャン、Go 要件、
    非推奨サブコマンド、checksum 検証、target/ 除外）。
- [x] キャッシュ読込にサイズ上限を追加（2026-11-20・第22弾）
  - 根拠: `src/cache.rs:207-215` / R3-IV-core, R3-DE-core / 重大度 medium
  - 生ボディ 8 MiB・ファイル 64 MiB の上限を保存／読込双方で適用。
    専用 `CacheTooLarge` により設定ファイルの上限と誤表示しない。
  - 検証: fmt / check / test（272 passed）/ clippy / doc / markdownlint 成功。
  - R4 指摘 4 件を反映（JSON 膨張、エラー文言、境界テスト、UI 文言テスト）。
- [x] opt-in E2E が認証情報未設定時に成功扱いになる問題を修正（2026-11-20・第21弾）
  - 根拠: `tests/real_server_e2e.rs:44-47` / R1-AR-tests, R3-AU-tests /
    重大度 medium
  - 明示実行時に `E2E_*` の欠落／空値を検出して失敗し、不足変数名を表示。
  - 検証: fmt / check / test（269 passed）/ clippy / markdownlint 成功。
  - R4 指摘 2 件を反映（不足変数名の列挙、文言とドキュメントの整合）。
- [x] キャッシュの有効期限と取得時刻を追加（2026-11-19・第20弾）
  - 根拠: `src/cache.rs:29-35` / R4-DR02-F2, R5-VU02-F2 / 重大度 medium
  - `SyncCache.created_at`（Unix 秒、`#[serde(default)]`）と 7 日の
    `MAX_CACHE_AGE_SECS` を追加。期限切れは `CacheExpired` として分類し
    ステータスへ表示。旧ビルドの無印キャッシュは best-effort で許可。
  - 検証: fmt / check / test（269 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件をすべて反映（CHANGELOG 記録、serde 往復・文言の
    結合テスト、旧 JSON キー欠落テスト、ADR ログの日付見出し）。
- [x] デバイス ID 失敗時に `r` 再試行が進まない問題を修正（2026-11-18・第16弾で解消）
  - 根拠: `src/ui/login_flow.rs:78-87` / R2-ER03-F3 / 重大度 medium
  - 第16弾で失敗時に `set_login_failed(true)` と「r で再試行」案内を追加し、
    未保存 ID を破棄して再試行時に再生成するよう変更済み。重複項目をクローズ。
- [x] 復号失敗 URI が `NoUri` として誤報告される問題を修正（2026-11-18・第19弾）
  - 根拠: `src/vault_sync.rs:123-125`, `src/health.rs:508-511` /
    R2-ER02-F1, R5-VU02-F1 / 重大度 medium
  - NUL 前置の `UNDECRYPTABLE_URI` センチネルを追加し、監査は
    `UriUninspectable`（低）を報告。真に URI が無い場合の `NoUri` と区別。
  - 検証: fmt / check / test（265 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件をすべて反映（producer 側テスト、Finding 網羅、
    NUL センチネルが `mask_uri` で実 URI 風に表示される問題、doc/ADR ログ）。
- [x] `from_cache` を UI ステータスへ反映（2026-11-18・第18弾）
  - 根拠: `src/auth.rs:616` / R1-ST02-F1, R4-DR01-F1 / 重大度 medium
  - `LoginResult::Vault` に `from_cache` を持たせ、キャッシュ復元時は
    「オフラインキャッシュから復元。最新でない可能性があります」を表示。
    モック経路には警告を出さない。
  - 検証: fmt / check / test（263 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー5件: 4件を反映（旧 doc comment、ADR の見出し整理、
    ADR ログ追記、todo 更新）。1件は「伝播自体の自動テスト」を要するが、
    GPUI test-support が未有効で `finish_login` を直接検証できないため
    採用せず。伝播3行は親がコードを読んで確認（Runtime Proof）。
- [x] 暗号化キャッシュ writer の方針を決定（2026-11-18・第17弾）
  - 根拠: `src/auth.rs:583-589` / R2-ST01-F2, R2-FG01-F1 / 重大度 medium
  - 決定: PoC では読み取り専用を維持し writer は接続しない。上流
    openwarden 0.1.0 の `Client::sync()` が解析済み `SyncData` のみ返し、
    `Session::access_token` が private、`SyncData` フィールドが `pub(crate)`
    であることをローカル展開ソースで確認（Runtime Proof）。独自 HTTP
    クライアント化は攻撃面の拡大に見合わないと裁定し、再検討トリガを
    ADR に明記。実装変更なし。
  - R4 独立レビュー6件を反映（上流の行番号、MD032、verified 日時、
    初期 Decision との緊張、log の重複、Decision 見出しの分散）。
- [x] `ensure_device_id` の保存失敗を呼び出し側へ伝える（2026-11-18・第16弾）
  - 根拠: `src/settings.rs:298-306` / R2-ER01-F1, R3-DI02-F1 / 重大度 medium
  - 保存失敗時に未保存の ID を破棄して再試行可能化。乱数生成・保存の失敗を
    それぞれ `RandomUnavailableCause` / `SettingsSaveCause` として返し、
    cause チェーンを保持。UI は `r で再試行` を案内。
  - 検証: fmt / check / test（262 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー2件を反映（再試行フラグ欠落、io エラーの cause 喪失）。
- [x] 復元不可時のクリップボード通知を実態へ整合（2026-11-18・第15弾）
  - 根拠: `src/ui/actions.rs:51` / R5-VU01-F1 / 重大度 medium
  - `ui::logic::clipboard_copy_status` を追加し、コピー元を読めない場合は
    復元を約束せず「コピーした内容はそのまま残ります」と明示。
    README の機能説明・既知の制約も条件付き記述へ更新。
  - 検証: fmt / check / test（261 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件をすべて反映（README 欠落、テストの脆弱な否定
    アサーション、秘密残存の注意喚起、todo 未更新）。
  - 併記されていた強制終了時復元は README の既知制約として維持（OS の
    clipboard 永続化が必要で PoC 範囲外）。カード全桁表示は第10弾で修正済み。
- [x] キャッシュ読込エラーの一律「破損」表示を分類別へ（2026-11-18・第14弾）
  - 根拠: `src/cache.rs:282-291` / R2-ER02-F3, R5-VU02-F3 / 重大度 medium
  - `cached_sync_for_detailed` が分類済みエラーを返し、`cache_error_message`
    が NotFound / ReadFailed / ParseFailed / VersionMismatch / Mismatch /
    TooLarge / Other を区別。`cache_restore_failure` がその理由を同期失敗
    ステータスへ反映。未知バリアントは「破損」と呼ばない。
  - 検証: fmt / check / test（260 passed、+3）/ clippy / doc /
    markdownlint すべて成功。
  - R4 独立レビュー4件をすべて反映（コメント矛盾、分類ロジックの二重化、
    未知バリアントのテスト欠落、rustdoc リンク不整合）。
- [x] ドキュメント lint を全 docs へ拡大し CI ゲート化（2026-11-18・第13弾）
  - 根拠: `README.md:127-128`, `.github/workflows/ci.yml:24-28` /
    R1-AR04-F2, R1-ST05-F6, R4-CI01-F2 / 重大度 medium ほか low 1件
  - `markdownlint README.md CHANGELOG.md todo.md 'docs/**/*.md'` に統一し、
    CI `extra_gates` で `markdownlint-cli@0.50.0` を導入・実行。
    README のローカルゲートから `-D clippy::<lint>` 重複を削除し
    `cargo deny check` を追加、順序を CI と一致させた。
  - 検証: `bash -n`（README コマンドブロック）、指定 markdownlint コマンド、
    CI YAML のパース、すべて成功。
  - R4 独立レビュー4件を反映（順序矛盾・版固定の明記・文言限定）。
    npm の利用可能性は共通ワークフロー既定ランナー `ubuntu-24.04` に
    よるもので未検証（提供側 README で確認）。共通ワークフロー自体への
    markdownlint ゲート追加は他リポジトリ変更となるため見送り。
- [x] README / ADR / 調査レポートを現行実装へ整合（2026-11-18・第12弾）
  - 根拠: `README.md:50-52,79-81` / R1-ST05-F1, R5-DC01-F1 ほか6件
  - パスワード / TOTP の実復号、キャッシュ read 接続・write 未接続、
    device identifier の UUID v4 永続化、ADR の verified 日時を反映。
    docs/index に cross-review-findings への導線を追加し、古い
    draft / 進行中マーカーを確定状態（調査レポートは superseded）へ更新。
    CHANGELOG の 0.1.0 節と「全残タスク完了」に解消済み注記を追加。
  - R4 独立レビュー5件をすべて反映（調査レポートの陳腐化4点、
    README の「未検証」表現の整理）。
  - 検証: markdownlint（全ドキュメント）成功。コード変更なしのため
    fmt / check / test / clippy / doc は前イテレーションの結果を維持。
- [x] `From<AppError>` の catch-all を廃し無関係な失敗の誤分類を防ぐ（2026-11-18・第11弾）
  - 根拠: `src/error.rs:403,443,468` / R1-AR02-F2, R1-ST02-F2, R5-AP01-F1 /
    重大度 medium
  - `AppError` と `AuthError` / `UnlockError` / `SettingsLoadError` に `Other`
    を追加。未知の失敗は「予期しないエラーが発生しました」または元メッセージを
    保持し、同期／復号キー／設定ファイル読み込みへの誤ラベル化を解消。
    `cache_error_message` の同種 catch-all も修正。
  - 検証: fmt / check / test（257 passed、+2）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件のうち3件を採用（`SettingsLoadError::Other` の文言破棄、
    空振りテスト、assert_ne による回帰検出不足）。1件は却下: `PartialEq` への
    discriminant 比較は「Cause 保持バリアントはプレーン版と等価」という
    既存の明示設計（`src/error.rs:344-346`）と既存テスト5件に反するため。
- [x] カード番号の末尾抽出を空白区切り非依存にし全桁表示を防ぐ（2026-11-18・第10弾）
  - 根拠: `src/ui/app.rs:342-346` / R1-ST03-F1, R3-AU03-F2 / 重大度 high
  - `ui::logic::card_last_four` を追加し、非 ASCII 数字を除いた末尾最大4桁のみ表示。
    区切りあり／なし／ハイフン／全角数字混入／4桁未満／空文字のテストを追加。
  - 検証: `cargo fmt --all -- --check` / `cargo check --all-targets --locked` /
    `cargo test --all-targets --locked`（255 passed、+1）/ `cargo clippy --all-targets
    --locked -- -D warnings -D clippy::unwrap_used -D clippy::expect_used
    -D clippy::panic` / `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
    / `markdownlint CHANGELOG.md todo.md` すべて成功。
  - R4 独立レビューの低指摘3件（4桁未満の扱いの説明、CHANGELOG 文言、
    過去完了ログの矛盾）は doc/ログを修正して解消。
- [x] 残り3タスクを依存関係付きチーム並列で完結（2026-11-18）
  - 共通 `AppError` と `source()` チェーン、cache の parse/redact/serialize 分離
  - link-local: メタデータホスト・DNS 解決先 IP・埋め込みリテラルを拒否
  - UI モジュールの過剰な pub を整理（114箇所、テスト専用は `#[cfg(test)]`）
  - 未解決（既知制約）: リダイレクト先検査と DNS rebinding 防止は openwarden
    0.1.0 の公開 API では不可能なため未対応。README に明記。
- [x] エージェントチームによる3タスク並列対応・第8弾（2026-11-18）
  - Dependabot（cargo 週次）/ deny.toml / CI の cargo deny check を追加
  - sha2 直接依存は SSH fingerprint で使用中と確認し維持（古い記述を修正）
  - 同期失敗時に暗号化キャッシュから復元する経路を auth 層へ接続（writer は未接続）
  - テスト属性を `#[test]` に統一（69箇所）。shadowing で不可な3ファイルは理由を明記
  - ルート担当: `## [Unreleased]` 運用と ADR ログ追記ルールを README に明記
  - ルート修正: プライベート項目への rustdoc リンクを通常表記へ変更
- [x] エージェントチームによる4タスク並列対応・第7弾（2026-11-18）
  - デバイス ID を UUID v4 で永続化し再ログイン / 再同期で再利用
  - SSH 公開鍵から SHA-256 fingerprint を再計算して照合
  - 選択解除の全経路を `deselect_and_rewind()` に集約
  - 辞書パスワードの長さ上限を定数化し境界をテスト
  - ルート担当: README の bash コマンド例を `bash -n` で検証
  - 整理: カード末尾4桁マスキングは当時「既存実装で充足」と判断したが、
    2026-11-18 の全体レビューで非区切り番号の全桁露出が判明し、
    `ui::logic::card_last_four` へ置換して修正した（第10弾）
  - 却下: 「再コピーで deadline を延長しない」は TH1 修正（毎回再取得）と
    矛盾するため採用せず
- [x] エージェントチームによる4タスク並列対応・第6弾（2026-11-18）
  - 実ログインで password / TOTP を実復号し、監査に対象外件数を明示
  - F1 でフォーカスを復帰（既存キー分類には影響しない）
  - 選択行を ">" マーカーでも表示
  - TOTP 失敗文言を TotpError::message() に統一
  - ルート担当: README のドキュメント導線 / コントリビューション / Kubuntu 例
  - 既知制約: 復号失敗時の NUL ステータストークンはパスワード欄に保持
- [x] エージェントチームによる4タスク並列対応・第5弾（2026-11-18）
  - アンロック遷移の状態リセットを共通化（enter_unlocked / reset_input_state）
  - メール・認証入力の長さ上限（UTF-8 境界で切り詰め）
  - 監査 / 生成 / 設定パネルに縦スクロールを追加
  - `Finding::InsecureUri` にマスク済み URI のみを格納
  - ルート担当: ADR 索引へ log.md 導線、README のゲート順序を統一
- [x] エージェントチームによる4タスク並列対応・第4弾（2026-11-18）
  - 部分成功の保持とエラー系統別の案内分岐（vault_sync / login_flow）
  - キーガード分岐のテスト（keys_tests / auth_state / clipboard）
  - 検索の NFKD 正規化・空名除外・Cf 文字拒否（model / auth）
  - キャッシュの XDG_CACHE_HOME 移動（cache）
  - ルート担当: idle_lock_due の checked_duration_since 化
  - 正規化は自作テーブルを廃し `unicode-normalization` クレートへ委譲
- [x] エージェントチームによる4タスク並列対応・第3弾（2026-11-18）
  - 機密の Zeroizing 化（model / ui state / login_flow ほか機械的追従）
  - 日付時刻パースの堅牢化（うるう年・RFC3339 オフセット・checked 算術）
  - 設定スキーマバージョン（現行 1 / 未知バージョンの安全な拒否）
  - テスト名とアサーションの整合（TOTP / クランプ / canary 非漏洩）
  - ルート担当: README の実接続手順・API key 注意、ADR を現行実装へ更新
- [x] エージェントチームによる4タスク並列対応（2026-11-18）
  - パスワード生成とエントロピー推定を整合（generator / health / words）
  - 同期データの重複排除・revision 検証・監査ログ（vault_sync）
  - 1秒 ticker のドリフト解消（Timer::at + 純粋 deadline 計算）
  - ウィンドウ生成失敗時に cx.quit()（main.rs、ルートが担当）
- [x] エージェントチームによる3タスク並列対応（2026-11-18）
  - 最終操作時刻の更新（src/ui/login_flow.rs）
  - 監査誤判定の修正（src/health.rs / health_tests.rs）
  - 設定読み込みの堅牢化（src/settings.rs / settings_tests.rs / generator.rs）
  - 未着手: 破損ファイルのタイムスタンプ付き退避は別タスクとして残す。
- [x] 復号処理を UI スレッドからオフロード（2026-11-18）
  - `smol::unblock` で `unlock_and_import` をブロッキングプールへ移動。
  - `LoginResult` で認証失敗 / 復号失敗 / 成功を区別し、UI 側は結果適用のみ。
  - 敵対的レビューで機能回帰なしと判定。残存: 実行中の unblock ジョブは
    generation ではキャンセルされない（結果の適用のみ破棄）。コードに明記。
- [x] 監査ボタンとキー状態を整合（2026-11-18）
  - `effective_panel()` でレポート未生成時の Audit 遷移を Vault に戻し、
    描画と `KeyContext.panel` の不一致を解消。
  - 実ログイン成功時に `refresh_audit()` を呼ぶようにした。
- [x] クリップボードの連続コピーを修正（2026-11-18）
  - 毎回コピー直前の内容を保存し、復元時にその内容を書き戻す。
  - 読み取り失敗時は空文字で上書きせず no-op。復元時にステータス更新。
  - 状態遷移を純粋関数化し、連続コピー / 未読取 / 未保留のケースをテスト。
- [x] 設定の真実源を `Settings` に一本化（2026-11-18）
  - `server_url` / `email` / 生成設定のミラーを廃止し、全読み書きを
    `Settings` へ直接化。`sync_settings_from_ui()` と
    `GeneratorState::from_settings()` を削除。
  - `GeneratorState` は生成結果のみを保持し、lock() でクリア。
  - 敵対的レビューで機能バグなしと判定。配線レベルのテスト欠如と
    権限範囲（apply_generator_key が &mut Settings を受け取る点）は残存。
- [x] 修飾キーと IME 入力を扱う（2026-11-18）
  - `KeyModifiers` / `key_char` を `KeyContext` へ追加。Ctrl/Cmd/Fn は常に
    除外、Alt は編集中に文字が生成された場合のみ許可。
  - Shift 文字は `key_char` 経由で判定し、既知 P0 の Shift+Y を解消。
  - 挿入アクションを文字列単位へ変更し、IME 確定文字を一括挿入。
  - 敵対的レビューの High 2件（Shift+Y / Alt 由来文字）を修正。
  - 未確認: IME 確定を Enter で行う環境の keystroke 実態はローカル資料が
    無く検証していない。
- [x] パネル切替時に入力モードをクリア（2026-11-17）
  - `BitwardenApp::set_panel()` に集約し、設定編集 / 認証フィールド /
    検索状態を必ず解除。マウスのパネルボタンも同じ経路を通る。
  - Esc が「キャンセルではなく確定」である旨を README と設定パネルの
    ヘルプに明記。
- [x] 一時ファイルを一意名＋適切な権限で管理（2026-11-17）
  - `tempfile::NamedTempFile` を再利用（create_new / 0600 / RAII 後始末 /
    atomic persist）。既存ファイルの権限も 0600 に是正。
  - 親ディレクトリ fsync は best-effort（rename 成功後の失敗を保存失敗と
    報告しない）。ベアな相対パスの扱いを修正。
  - 敵対的レビューで指摘された相対パス潜伏バグ・テストの形骸化を修正。
  - 残る制約: 既存親ディレクトリの権限是正は行わない／強制終了時は一時
    ファイルが残り得る。
- [x] 非同期ログインに試行世代を導入（2026-11-17）
  - `src/ui/login_generation.rs` の純粋トークンで spawn 時に採番し、
    `finish_login` が現行トークン一致時のみ適用。重複コールバックも破棄。
  - lock / モック解除 / 新しいログイン / 検証失敗 / 認証値変更で無効化。
  - 敵対的レビューの指摘 2 件を修正（検証失敗時の残存、認証値変更の無効化）。
- [x] `Settings::sanitized()` で `Thresholds` をクランプ（2026-11-17）
  - `weak_bits` を 1..=200、`stale_days` を 1..=3650 に丸め、
    手編集ファイルを `load_detailed()` で読み込む経路の回帰テストを追加。
- [x] `todo.md` をプロジェクト内へ配置（2026-11-17）
- [x] 5ラウンドの全体クロスレビュー（25エージェント、約169件の生指摘）を実施。
- [x] 重複クラスタ 16 を吸収し、妥当性を Runtime Proof で裏付け。
- [x] 誤検知／過大評価／既に対処済み 5件（V1〜V5）を却下。

## メモ

- グローバルTODO: `~/.config/opencode/todo.md`（複数プロジェクト横断のタスク用）。
- 詳細な生指摘は [docs/cross-review-findings.md](docs/cross-review-findings.md) を参照。
- 本レビューは修正を行わない（read-only）方針。エージェントは
  `read` / `grep` / `glob` のみを使用（r4-render が読み取り専用 ls を1回実行した
  自己申告あり。ファイル変更・ビルド・テスト・git 操作はなし）。
- 途中終了したエージェント（r1-ops / r1-security / r1-correctness / r1-ops-retry）は
  観点を分割した代理エージェントで回収済み。
- 性能・スケール上の指摘（UI フリーズ、ticker ドリフト、バイナリサイズ等）は
  測定を行っていないため、機能バグとは区別して扱う。
- 外部クレート（openwarden / gpui / smol）の内部動作に関する指摘は
  依存クレートを読んでいないため推測として明示している。

### 2026-11-18 コンボ実行（swarm-project-review + swarm-todo-discovery）

- 起動エージェント: 合計 98 体（1 回目 53 体 = R1 9 + R2 12 + R3 12 +
  R4 11 + R5 9、2 回目 45 体 = R2〜R5 44 + R1-ST01 リトライ 1）。
  1 回目は出力が保存上限を超過したため R1 のみ回収し R2〜R5 を
  コンパクト出力で再実行した。R1-ST01 は 1 回リトライして回収。
  R4-OB02 / R5-DC02 はモデル出力がスキーマに適合せず「未調査」として
  記録した（担当範囲は他担当が一部カバー）。プロファイル: 無制限
  （hy4-flash-free）、深度 1、並列度 9〜12 担当／ラウンド。
- 検出 162 件（R1 44 件 + R2〜R5 118 件）を重複排除・Runtime Proof で
  吸収し、上記 44 件を todo 化。重複元は `duplicate_of` として破棄。
- 却下（意図的な設計／既知制約／事実と不一致）:
  - `ensure_device_id` の保存失敗握り潰しは「次回呼び出しで再試行」と
    コメントに明記された意図（`src/settings.rs:290-291`）だが、実際には
    ID が有効になるため再試行経路が無い。上記「中」で採用。
  - 環境変数テストのロック漏れ（`src/cache_tests.rs:194,295`）は
    `ENV_LOCK` が既に存在するため却下。
  - ジェネレータ長のオーバーフロー／大量確保 DoS は
    `Settings::sanitized()` が 4..=128 / 2..=20 にクランプし、
    `src/ui/keys.rs:26-27` も同じ上限のため却下。
  - `schema_version` 欠落／型不一致を現行版とみなす挙動は
    legacy 互換として明記（`src/settings.rs:7-10,358-363`）するため却下。
  - `AuthConfig` の `Debug` が認証情報を露出する指摘は、
    両秘密が `SecretString`（Debug マスク）であるため却下。
  - `deny.toml` の `unmaintained = "workspace"` と
    `multiple-versions = "warn"` はコメント付きの意図的な方針のため却下。
  - zxcvbn 未使用は `src/health.rs:8-10` に明記済みのため却下。
  - クリップボード連続コピーで直前の秘密が復元される挙動は
    `src/ui/clipboard.rs:20-25,105-111` で設計・テスト済みのため却下。
  - `authenticate()` が設定タイムアウトを無視する指摘は、
    UI が `authenticate_with_timeout` へ設定値を渡すため
    （`src/ui/login_flow.rs:89-95`）却下。
  - ログイン再試行時に前回タスクがキャンセルされない点は
    `src/ui/login_flow.rs:101-103` に既知制約として明記済みのため却下。
- speculative / 要判断（TODO 化せず候補として保持）:
  - 監査パネルの TOTP カバレッジ 0 除算（`src/ui/panels.rs:37-42`）——
    `totp_coverage()` の実装未確認。
  - クリップボード復元期限 `Instant` 加算のオーバーフロー
    （`src/ui/clipboard.rs:31`）—— 設定が 1..=3600 にクランプされるため
    実害なし。
  - Unicode Cf リストの固定（Unicode 16.0）—— 将来文字の検出は未検証。
  - 設定ファイルが FIFO で起動停止する可能性、並列初期化の端末 ID 競合、
    `rust-toolchain.toml` 未固定、edition 2024 未移行。
