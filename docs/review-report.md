---
type: Report
title: "全体敵対的レビュー結果"
description: "bitwarden-gpui-poc v0.1.0 に対するセキュリティ・アーキテクチャ・運用の3観点レビューと修正結果"
tags:
  - review
  - security
  - architecture
  - operations
generated:
  by: "dsh-agent (lead)"
  at: "2026-11-17T01:48:58+09:00"
status: "approved"
stale_after: "2027-05-17T01:48:58+09:00"
---

## 概要

3観点のサブエージェント（security / arch / ops）を並列起動し、
`src/` 全体と設定・CI・ドキュメントをレビューした。
結果は Critical 0 / High 1 / Medium 16 / Low 18。
High の1件と、即対応可能な Medium/Low を修正した。

## 検出と対応

### High（修正済み）

- **設定画面の入力が確定時に失われる**（arch #1）
  - `BitwardenApp` が `server_url` / `email` と `settings.server_url` /
    `settings.email` の二重状態を持ち、設定パネルは後者を編集する一方、
    確定時の `sync_settings_from_ui()` が古い前者で上書きしていた。
  - 真実源を `self.server_url` / `self.email` に統一し、
    `settings_panel` がそれらを表示・編集するよう修正した。

### Medium（修正済み）

- 認証情報が編集中に平文表示される（security #1）: `auth_row` を常時マスクに変更
- 設定・キャッシュが umask 依存の権限で保存される（security #3 / ops #6）:
  `private_file::write_private` を新設し、Unix で 0700 / 0600 を明示
- タグ push 時に CI が起動しない（ops #7）: `on.push.tags: ['v*']` を追加
- `openwarden = "0.1"` が 0.1.x 全体に解決される（ops #8）: `=0.1.0` にピン
- キャッシュが「暗号化済み」と誤記述（ops #5 / ops #9）:
  「暗号化済みアイテムを含む平文 JSON」に修正し、0600 を明記
- `auth ↔ cache` の循環依存（arch #2）: `SyncCacheError` を `cache.rs` へ移動
- ドメインコードの陳腐化コメント（arch #6 / security #11）: 実装に合わせて修正
- `finish_login` の一部エラーパスで再試行案内が出ない（親レビュー）:
  全エラーパスで `login_failed = true` を設定

### Low（修正済み）

- ライブラリに `#![forbid(unsafe_code)]` が無い（security #11）: 追加
- `~/.config` 表記が `XDG_CONFIG_HOME` を考慮していない（ops #13）: README を修正
- roadmap へのリンクが無い（ops #16）: 曖昧な記述を削除

### 見送り（理由を記録）

- `Settings::load()` / `cache::load()` のサイレントエラー握りつぶし
  （ops #1 / #3）: エラー型と UI 通知経路の設計変更を伴うため、
  PoC では README の既知の制約として開示するにとどめる。
- 構造化ログ・メトリクスの導入（ops #2）: 新規依存 `tracing` が必要で、
  事前承認が必要になるため今回は見送り。「未実装」を README に追記した。
- 秘密の `zeroize` 化（security #2）: 新規依存が必要なため見送り。
- アイドル自動ロック（security #9）とクリップボード期限の単調時計化
  （security #7）は、その後のラウンドで新規依存なしに実装した。
- God Object の部分状態分割、UI 状態遷移の Effect パターン化、
  モジュール名衝突の解消、`selected` の ID ベース管理など
  （arch #3〜#11, security #4〜#6 / #8 / #10,
  ops #4 / #10〜#12 / #14 / #15）:
  いずれも設計変更または新規依存を伴い、PoC の目的（GPUI + openwarden の
  構成検証）に直接寄与しないため見送り。

## 検証

修正後に以下を実行し、すべて成功した:

- `cargo fmt --all -- --check`
- `cargo check --all-targets --locked`
- `cargo test --all-targets --locked`（82 passed）
- `cargo clippy --all-targets --locked -- -D warnings -D clippy::unwrap_used
  -D clippy::expect_used -D clippy::panic`
- `cargo audit`
- `markdownlint README.md CHANGELOG.md docs/adr/*.md docs/review-report.md`
- CI YAML のパース

## 判定

High はすべて解消し、マージブロックは存在しない。
見送り項目は PoC の既知の制約として文書化済み。
