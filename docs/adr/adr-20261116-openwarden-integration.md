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
status: "approved"
verified:
  by: "dsh-agent (lead)"
  at: "2026-11-18T21:28:00+09:00"
stale_after: "2027-05-18T21:28:00+09:00"
---

## Context

Bitwarden GPUI PoC は当初モックデータのみを表示していた。
プロジェクトの目的は GPUI で Bitwarden クライアント UI を構築し、
`openwarden` を vault API/暗号層として使う構成を検証することにある。
本 ADR はその統合設計を記録し、実装完了時にステータスを更新した。

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
4. `cache` モジュール（新設）: 暗号化済み同期 body を保持し、`/api/sync`
   失敗時に auth 層がオフライン復元する。書き出しは未接続で読み取り専用の
   復元に限る（後述「Decision Update (2026-11-18)」を参照）

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

キャッシュの feature ゲート／削除も検討した。しかし `openwarden` 0.1.0 は
`SyncData::from_json` を公開しており、同期失敗時の復元経路は接続可能である。
テスト専用のまま残すより復元を接続する方が目的に合うため、削除は採用しない。
書き込み側だけは下記のとおり API 制約で接続できない。

## Implementation Plan

1. `auth` モジュールの骨格とエラー型を追加する — 完了
2. `SyncData` から `model::Vault` への変換関数のテストを先に書く — 完了
3. ロック画面に API key とマスターパスワードの入力欄を追加する — 完了
4. KDF を blocking thread で実行し、同期結果を一覧に反映する — 完了

## Implementation Result

`auth` / `vault_sync` の2モジュールと UI 接続を実装し、`cargo test` は
全件成功している（件数はコミットごとに増加するため固定値は記載しない）。
ロック画面の `Enter` は常に実認証を試行し、モック vault は `m` で明示的に
開く。認証成功後は `authenticate` → `unlock_and_import`（復号・同期データ
取り込みは blocking thread）→ `import_logins_with_audit` の順で実 vault を
読み込み、UI スレッドでは結果の適用のみを行う。

実サーバー接続の検証（2026-11-19、ローカル Vaultwarden）:
`tests/real_server_e2e.rs`（opt-in、`E2E_*` 環境変数＋`--ignored`）を追加。
ローカル Vaultwarden 1.30.2 に対して API key 認証、`/api/sync` の HTTP 200
までは到達した。ただし同サーバーが返す sync JSON は `Profile` / `Ciphers`
等の PascalCase で、openwarden 0.1.0 の `SyncWire`（`#[serde(rename_all =
"camelCase")]`、`profile` / `ciphers` を要求）と不一致のため復号前の
パースに失敗した。認証経路自体の動作は確認できたが、E2E は未成功。

2026-11-20 の対応: `vault_sync::parse_sync` が PascalCase キーを camelCase へ
再帰的に正規化するようになり、キャッシュ経由の sync ボディは解析可能に
なった（単体テストで確認）。ただし生の認証経路は openwarden の
`Client::sync()` が内部で `SyncData::from_json` を呼ぶため、この正規化を
通らず E2E は引き続き未成功。実サーバー接続の完了には上流の対応、または
トークンを自前管理する HTTP クライアントの導入が必要。

未解決事項: 実サーバーへの接続テストは上記の case 互換性が未解消のため完了していない。
ログイン項目以外の kind はまだ model に変換されない。パスワードと TOTP
シークレットは復号してメモリ上のモデルに保持するが、UI へは平文を出さず、
監査と TOTP コード生成に限定して使用する。
device identifier は UUID v4 を生成して永続化し、再ログイン / 再同期で
同じ値を再利用する。
API key はテスト専用アカウントで使用すること（権限範囲の注意は README 参照）。

オフラインキャッシュについて: `src/cache.rs` の読み込み・検証を認証フローへ
接続した。`authenticate_inner` は `Client::sync()` が失敗した場合、
`cache::cached_sync_for` でプラットフォームのキャッシュディレクトリ
（旧設定ディレクトリは読み取り専用フォールバック）から暗号化済み body を
読み出し、サーバー URL を照合して `SyncData` に戻す。復号には生セッションの
protected key を使うため、キャッシュは鍵素材を一切提供しない
（保存前に `profile.key` / `privateKey` を除去済み）。復元したかどうかは
`AuthenticatedVault::from_cache` に記録する。

ただし書き込み側は接続していない。`openwarden` 0.1.0 の `Client::sync()` は
解析済み `SyncData` のみ返して raw body を公開せず、`Session::access_token`
も private、`SyncData` のフィールドも `pub(crate)` である。したがって
ログインフローから `SyncCache::from_body` に渡す body を取得できず、
`save_default` を呼ぶ本番経路が無い。キャッシュファイルが存在するのは
旧リリースが書いた既存ファイル、または外部から配置した場合に限られる。
初回からオフライン（キャッシュなし）の場合は従来どおり `AuthError::Sync` を
返す。キャッシュが存在するのに使えない場合は、破損・読込失敗・
バージョン不一致・サーバー不一致の別をステータスへ表示する。
書き込みを有効化するには openwarden 側の API 拡張（sync body の公開）または
独自 HTTP クライアントとトークン管理が必要である。

`from_cache` はログイン成功ステータスへ反映され、復元データが最新でない
可能性を利用者に通知する。

オフライン復元の未解決点: 同期失敗時には新しい user id が得られないため
キャッシュのアカウント照合ができず、同一サーバーの別アカウントのキャッシュを
読んでも検出できない（鍵が一致しないため復号側で失敗する）。
キャッシュには取得時刻（Unix 秒）と 7 日間の有効期限を設けた。期限切れは
復元に使わず理由を表示する。旧ビルドの無印キャッシュは best-effort で
許可する（writer が未接続のため全既存ファイルが該当する）。
鍵ローテーション後は復号できない。

## Decision Update (2026-11-18): キャッシュ writer は PoC では接続しない

**決定**: オフラインキャッシュは読み取り専用の best-effort 復元として維持し、
書き込み経路（`SyncCache::from_body` → `save_default`）は本 PoC では接続しない。

**根拠（Runtime Proof）**: ローカルに展開された `openwarden 0.1.0` の
`src/client.rs` を確認した。`Client::sync()`（:418）は解析済み `SyncData` のみを
返し、`Session::access_token`（:129）は private、`SyncData` のフィールド
（:252-256）は `pub(crate)` で、生の `/api/sync` body を外部から取得する
公開 API は存在しない。

**裁定**: 独自 HTTP クライアントとトークン管理を追加して body を自前取得する
案は、認証・トークン処理の重複と攻撃面の拡大を伴い、PoC 目的（GPUI UI と
openwarden 統合の検証）に見合わないため採用しない。既定値は「現状維持」。

**再検討のトリガ**: 以下を満たしたときにのみ見直す。

1. openwarden が raw body または `Session` のトークンアクセサを公開する
   （例: `SyncData::raw_body()` / `Session::access_token()`）。
2. 実サーバー（Vaultwarden）との E2E 検証で、オフライン復元の価値が
   独自 HTTP 実装の保守コストを上回ると測定された場合。

## Status

Self-reviewed by agent at 2026-11-17T00:27:33+09:00.
Cache restore wiring re-reviewed against the current implementation at
2026-11-18T03:44:54+09:00.
Writer policy decided at 2026-11-18T21:28:00+09:00 (keep read-only; revisit on
upstream API expansion or measured E2E need).

## Links

- [openwarden (crates.io)](https://crates.io/crates/openwarden)
- [GPUI](https://gpui.rs)

## Decision Update (2026-11-21): 階層別エラー型の別名を維持する

`SyncError` / `SyncCacheError` / `CacheLoadError` / `GeneratorError` /
`TotpError` はすべて `AppError` の `pub type` 別名である。これらは
「層ごとの意味的なラベル」として残し、独立 enum へ戻さない。

根拠: 実体は単一の `AppError` で、`Display` / `PartialEq` / `Error::source()`
は共通化済み。独立 enum に戻すには各境界で `From` 変換とメッセージの
二重管理が発生し、PoC の目的に見合わない。型システムで層を区別する
必要が生じた場合は、newtype 化を ADR 改訂として別途検討する。
