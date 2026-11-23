---
type: Report
title: "全体敵対的レビュー結果"
description: "v0.1.0 / 137 passed 時点の3観点レビューと修正結果（現状は README / ADR）"
tags:
  - review
  - security
  - architecture
  - operations
generated:
  by: "dsh-agent (lead)"
  at: "2026-11-17T01:48:58+09:00"
verified:
  by: "dsh-agent (lead)"
  at: "2026-11-21T04:49:12+09:00"
status: "approved"
stale_after: "2027-05-21T04:49:12+09:00"
---

## 概要

3観点のサブエージェント（security / arch / ops）を並列起動し、
`src/` 全体と設定・CI・ドキュメントをレビューした。
結果は Critical 0 / High 1 / Medium 8 / Low 3（修正対象の列挙12件）。
見送り・未実装は4件を別節に列挙する（合計16件）。
High の1件と、即対応可能な Medium/Low を修正した。
「対応済み（追記）」は集計後の追加確認で対応済みの項目を再掲したもので、
上記の件数には含めない。

注: 本レポートは v0.1.0 / 137 passed 時点のスナップショットである。
現行の実装・テスト件数は README / ADR / CHANGELOG を参照。

## 検出と対応

### High（修正済み）

- **設定画面の入力が確定時に失われる**（arch #1）
  - 当時 `BitwardenApp` が `server_url` / `email` と `settings.server_url` /
    `settings.email` の二重状態を持ち、確定時の `sync_settings_from_ui()`
    が古い前者で上書きしていた。
  - 真実源を `Settings` の `server_url` / `email` へ統一し、設定パネルと
    ロック画面が同じ経路を通すよう修正した（当時は `BitwardenApp` の
    フィールドへ統一していたが、その後 `Settings` へ一本化）。

### Medium（修正済み）

- 認証情報が編集中に平文表示される（security #1）: `auth_row` を常時マスクに変更
- 設定・キャッシュが umask 依存の権限で保存される（security #3 / ops #6）:
  `private_file::write_private` を新設し、Unix で 0700 / 0600 を明示
- タグ push 時に CI が起動しない（ops #7）: `on.push.tags: ['v*']` を追加
- `openwarden = "0.1"` が 0.1.x 全体に解決される（ops #8）: 当時 `=0.1.0` に
  ピン。現行は `=0.1.1`（`=` ピン自体は維持）
- キャッシュが「暗号化済み」と誤記述（ops #5 / ops #9）:
  「暗号化済みアイテムを含む平文 JSON」に修正し、0600 を明記
- `auth ↔ cache` の循環依存（arch #2）: `SyncCacheError` を `cache.rs` へ移動
- ドメインコードの陳腐化コメント: 実装に合わせて修正（ID 重複を解消し、
  セキュリティ方針項目側へ統一）
- `finish_login` の一部エラーパスで再試行案内が出ない（親レビュー）:
  全エラーパスで `login_failed = true` を設定

### Low（修正済み）

- ライブラリに `#![forbid(unsafe_code)]` が無い（security #11）: 追加
- `~/.config` 表記が `XDG_CONFIG_HOME` を考慮していない（ops #13）: README を修正
- roadmap へのリンクが無い（ops #16）: 曖昧な記述を削除

### 見送り・未実装（理由を記録）

- 構造化ログ・メトリクスの導入（ops #2）: 調査の結果、`tracing 0.1.44` は
  推移依存として既に lock にあるが、実際の出力には lock 未登録の
  `tracing-subscriber`（追加の推移依存を伴う）が必要。現在のログ出力は
  起動時エラー1箇所のみで、共通指示の「依存追加は最小限の方針」に従い
  見送った。代わりに起動時エラーへ `Debug` 詳細を追加した。
- repository / homepage フィールド（ops #10）: 当時はリモート URL が未確認
  だったため見送ったが、2026-11-21 に public リポジトリ
  `Seduce0068/bitwarden-gpui-poc` を作成・push 済み。現在は `Cargo.toml` に
  `repository` を設定している（`homepage` は repository と重複するため
  cargo の警告に従い未設定）。
- テスト・型の整理残り（arch #3 / #5 / #8 / #11 の一部）: 設計変更を伴い、
  PoC の目的（GPUI + openwarden の構成検証）に直接寄与しないため見送り。
- 全推移依存のライセンス互換性の法的評価: `cargo metadata` で棚卸しした結果、
  MPL-2.0 が 3 件（`cbindgen` / `dwrote` / `option-ext`）含まれることを確認。
  いずれも GPUI / wgpu 系の推移依存で、AGPL-3.0-or-later との具体的な
  互換性判断は専門家の確認が必要なためここでは断定しない。

### 対応済み（追記・上記集計外）

集計後に追加で確認・対応した項目を再掲する（件数には含めない）。
設定のエラー通知（ops #1）、キャッシュのエラー区別（ops #3）、atomic 書き込み
（ops #4）、モック解除の分離（security #4）、入力検証（security #5 / #6）、
クリップボード復元（security #7）、URI マスク（security #10）、アイドルロック
（security #9）、自動ロック判定の純粋化、入力経路の統一（arch #4）、認証の
ドメイン層移動（arch #6）、選択の ID 化（arch #7）、モジュール名衝突の解消
（arch #8）、テスト専用ハックの削除（arch #9）、タイマー判定の純粋化
（arch #10）、MSRV / 依存固定理由の記録（ops #14 / #15）、clippy 設定の
一元化（ops #11）、LICENSE 追加、パスフレーズ単語リストの分離、秘密の
`zeroize` 化（security #2、AuthState / TOTP 表示 / 再確保の旧コピーは
zeroize 側の制約で保証外）、TOTP シークレットの検索除外、各種 `Debug`
出力（Vault 項目 / GeneratorState / Settings / Identity / URI）のマスキング。

## 検証

当時の修正後に以下を実行し、すべて成功した（スナップショット）:

- `cargo fmt --all -- --check`
- `cargo check --all-targets --locked`
- `cargo test --all-targets --locked`（当時 137 passed。現行件数は
  todo.md の各イテレーション完了記録を参照。当時は並列 /
  `--test-threads=1` の両方で同一結果、flaky なし）
- `cargo clippy --all-targets --locked -- -D warnings -D clippy::unwrap_used
  -D clippy::expect_used -D clippy::panic`
- `cargo audit`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
- `markdownlint README.md CHANGELOG.md docs/index.md docs/adr/*.md
  docs/review-report.md`
- CI YAML のパース
- `cargo build` 後のバイナリ起動（Wayland ネイティブ、エラー出力なしで安定稼働）

## 判定

High はすべて解消し、マージブロックは存在しない（当時時点）。
見送り項目は PoC の既知の制約として文書化済み。
構造化ログの見送り根拠は本レポートが唯一の出典とし、ADR 側から参照する。
