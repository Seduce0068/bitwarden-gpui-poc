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

### 見送り・未実装（理由を記録）

- 構造化ログ・メトリクスの導入（ops #2）: 新規依存 `tracing` が必要で、
  事前承認が必要なため未実装。「未実装」を README に追記した。
- 秘密の `zeroize` 化（security #2）: 新規依存が必要なため未実装。
- repository / homepage フィールド（ops #10）: リモート URL が未確認のため
  断定せず追加していない（push 先確定後に設定する）。
- テスト・型の整理残り（arch #3 / #5 / #8 / #11 の一部）: 設計変更を伴い、
  PoC の目的（GPUI + openwarden の構成検証）に直接寄与しないため見送り。

### 対応済み（追記）

設定のエラー通知（ops #1）、キャッシュのエラー区別（ops #3）、atomic 書き込み
（ops #4）、モック解除の分離（security #4）、入力検証（security #5 / #6）、
クリップボード復元（security #7）、URI マスク（security #10）、アイドルロック
（security #9）、自動ロック判定の純粋化、入力経路の統一（arch #4）、認証の
ドメイン層移動（arch #6）、選択の ID 化（arch #7）、モジュール名衝突の解消
（arch #8）、テスト専用ハックの削除（arch #9）、タイマー判定の純粋化
（arch #10）、MSRV / 依存固定理由の記録（ops #14 / #15）、clippy 設定の
一元化（ops #11）、LICENSE 追加、パスフレーズ単語リストの分離。

## 検証

修正後に以下を実行し、すべて成功した:

- `cargo fmt --all -- --check`
- `cargo check --all-targets --locked`
- `cargo test --all-targets --locked`（117 passed）
- `cargo clippy --all-targets --locked -- -D warnings -D clippy::unwrap_used
  -D clippy::expect_used -D clippy::panic`
- `cargo audit`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
- `markdownlint README.md CHANGELOG.md docs/index.md docs/adr/*.md
  docs/review-report.md`
- CI YAML のパース
- `cargo build` 後のバイナリ起動（Wayland ネイティブ、エラー出力なしで安定稼働）

## 判定

High はすべて解消し、マージブロックは存在しない。
見送り項目は PoC の既知の制約として文書化済み。
