---
type: ADR
title: "openwarden を vault API/暗号層として採用"
description: "Bitwarden GPUI PoC の実 vault 接続に openwarden 0.1 を採用する決定と統合設計"
tags:
  - bitwarden
  - openwarden
  - vault
  - crypto
generated:
  by: "dsh-agent (lead)"
  at: "2026-11-16T23:49:40+09:00"
status: "draft"
stale_after: "2027-05-16T23:49:40+09:00"
---

## Context

Bitwarden GPUI PoC は現在モックデータのみを表示している。
プロジェクトの目的は GPUI で Bitwarden クライアント UI を構築し、
`openwarden` を vault API/暗号層として使う構成を検証することにある。

`openwarden` 0.1.0 の公開 API をローカルソースで確認した結果は次のとおり。

- `ServerUrls`: `self_hosted(base)`, `bitwarden_us()`, `bitwarden_eu()`
- `Client`: `prelogin(email) -> Kdf`, `login_api_key(&ApiKey) -> Session`,
  `sync(&Session) -> SyncData`
- `Session`: `kdf()`, `protected_key()`
- `SyncData`: `user_id()`, `protected_key()` と内部の同期データを保持
- `Vault`: `unlock(&MasterKey, ...)`, `apply_sync(SyncData)`, `logins()`,
  `totp()`, `folders()` などを提供

重要な制約として、`openwarden` 0.1.0 のログイン API は Personal API key のみ。
ただし復号には `MasterKey::derive(password, email, kdf, policy)` が必要であり、
API key はセッショントークン取得にしか使えない。したがって実利用では
API key とマスターパスワードの両方の入力が必要になる。

## Decision

`openwarden` 0.1.0 を vault API/暗号層として採用する。
UI は直接 `openwarden` を触らず、lib クレートに統合層を置く。

1. `auth` モジュール（新設）: サーバー URL、API key、マスターパスワードを
   受け取り、`prelogin` → `login_api_key` → `sync` を実行して `Session` と
   `SyncData` を返す
2. `vault_sync` モジュール（新設）: `MasterKey::derive` と `Vault::unlock` で
   復号キーを作り、`apply_sync(SyncData)` の後に `logins()` / `folders()` 等
   から既存の `model::Vault` / `VaultItem` へ変換する
3. `src/main.rs`: ロック画面から API key とマスターパスワードを入力させ、
   統合層を非同期で呼ぶ。認証情報は `Settings` に保存しない

## Consequences

正の影響:

- 暗号処理を自作せずに済み、既存の TOTP / URI マッチング実装も再利用できる
- 復号後に `model::Vault` へ変換するため、UI とテストのロジックは変わらない

負の影響:

- API key とマスターパスワードの入力画面、非同期同期処理を新設する必要がある
- KDF は CPU/メモリを多く使うため blocking thread での実行が必要
- `Vault::logins()` はログイン項目のみを返すため、他 kind の変換は別途設計する

## Alternatives

暗号処理と API クライアントを自前実装する案は、暗号学的な誤実装リスクが
高く採用しない。`bitwarden-cli` などの外部プロセスへ委譲する案は、
インストール済みバイナリへの依存とプロセス間通信が増えるため採用しない。

## Implementation Plan

1. `auth` モジュールの骨格とエラー型を追加する
2. `SyncData` から `model::Vault` への変換関数のテストを先に書く
3. ロック画面に API key とマスターパスワードの入力欄を追加する
4. KDF を blocking thread で実行し、同期結果を一覧に反映する

## Status

Self-reviewed by agent at 2026-11-16T23:49:40+09:00.

## Links

- [openwarden (crates.io)](https://crates.io/crates/openwarden)
- [GPUI](https://gpui.rs)
