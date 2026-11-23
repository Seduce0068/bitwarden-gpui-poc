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
    at: "2026-11-21T06:07:00+09:00"
status: current
stale_after: "2027-05-17T21:04:43+09:00"
---

## 進行中

swarm コンボ（swarm-project-review → swarm-todo-discovery → swarm-coding）の
イテレーション 1 が完了。第46弾の実装と検証結果を下記に反映済み。

## 未着手

### 中優先度

- [ ] **数字パスワード＋'?'＋テキスト＋'@' の URL マスクを修正** —
  根拠 `src/cache.rs:265-277` / X05 / 中

### 低優先度

- [ ] **auth 前方変換の discriminant をテスト** — X02 / 低
- [ ] **cache 権限/バージョン、server/parse の優先順位をテスト** —
  X06 / 低
- [ ] **comparison_key の Cf 除去を検討** — X09 / 低
- [ ] **空白のみ TOTP の監査矛盾を修正** — X11 / 低
- [ ] **空一覧でキーヒントを残す** — X14 / 低
