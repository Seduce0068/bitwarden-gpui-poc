---
type: ADR
title: "openwarden を vault API/暗号層として採用"
description: "openwarden 0.1.1（当初 0.1.0）を vault API/暗号層として採用する決定と統合設計"
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
  at: "2026-11-21T04:49:12+09:00"
stale_after: "2027-05-18T21:28:00+09:00"
---

## Context

Bitwarden GPUI PoC は当初モックデータのみを表示していた。
プロジェクトの目的は GPUI で Bitwarden クライアント UI を構築し、
`openwarden` を vault API/暗号層として使う構成を検証することにある。
本 ADR はその統合設計を記録し、実装完了時にステータスを更新した。

`openwarden` 0.1.0 の公開 API をローカルソースで確認した結果は次のとおり
（当時の記録。現行は 0.1.1）。

- `ServerUrls`: `self_hosted(base)`, `bitwarden_us()`, `bitwarden_eu()`
- `Client`: `prelogin(email) -> Kdf`, `login_api_key(&ApiKey) -> Session`,
  `sync(&Session) -> SyncData`
- `Session`: `kdf()`, `protected_key()`
- `SyncData`: `user_id()`, `protected_key()` と内部の同期データを保持
- `Vault`: `unlock(&MasterKey, ...)`, `apply_sync(SyncData)`, `logins()`,
  `totp()`, `folders()` などを提供

重要な制約として、`openwarden` のログイン API（0.1.0 / 0.1.1 ともに）は
Personal API key のみ。
ただし復号には `MasterKey::derive(password, email, kdf, policy)` が必要であり、
API key はセッショントークン取得にしか使えない。したがって実利用では
API key とマスターパスワードの両方の入力が必要になる。

## Decision

`openwarden` 0.1.1（当初 0.1.0）を vault API/暗号層として採用する。
UI は直接 `openwarden` を触らず、lib クレートに統合層を置く。

1. `auth` モジュール（新設）: サーバー URL、API key、マスターパスワードを
   受け取り、`prelogin` → `login_api_key` → `sync_body`（0.1.1。0.1.0 では
   `sync`）を実行して `Session` と同期 body を返す
2. `vault_sync` モジュール（新設）: PascalCase 正規化と重複 id の集約を行い、
   `apply_sync(SyncData)` の後に `logins()` / `folders()` 等から既存の
   `model::Vault` / `VaultItem` へ変換する。復号キー (`MasterKey::derive`)
   と `Vault::unlock` は現在 `auth` モジュールが担当する
3. `src/main.rs`: ロック画面から API key とマスターパスワードを入力させ、
   統合層を非同期で呼ぶ。認証情報は `Settings` に保存しない
4. `cache` モジュール（新設）: 暗号化済み同期 body を保持し、同期 body の
   取得・解析失敗時に auth 層がオフライン復元する。書き出しは未接続で読み取り専用の
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

キャッシュの feature ゲート／削除も検討した。しかし `openwarden` は
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

実サーバー接続の検証（履歴、2026-11-19）:
`tests/real_server_e2e.rs`（opt-in、`E2E_*` 環境変数＋`--ignored`）を追加し、
ローカル Vaultwarden 1.30.2 に対して API key 認証、`/api/sync` の HTTP 200
まで到達した。同サーバーが返す sync JSON は `Profile` / `Ciphers` 等の
PascalCase で、当時の openwarden 0.1.0 の `SyncWire`（`#[serde(rename_all =
"camelCase")]`）と不一致のため復号前のパースに失敗していた。

2026-11-20 の対応: `vault_sync::parse_sync` が PascalCase キーを camelCase へ
再帰的に正規化するようになり、キャッシュ経由の sync ボディは解析可能に
なった（単体テストで確認）。当時は生の認証経路が `Client::sync()` の内部
パースを通るため、E2E はまだ成功していなかった。

2026-11-21 の完了: openwarden 0.1.1 が `Client::sync_body()` で生 body を
公開したため、`src/auth.rs` の認証経路から取得した body へ同じ正規化を
適用した。実サーバー E2E は成功し、ログイン・sync・復号・取り込みまでを
検証する（テスト件数はコミットごとに変わるため固定値は記載しない）。
ただし opt-in E2E は UI のコピー
操作を含まないため、`p` / `u` / `y` の実サーバー確認は未実施である。

未解決事項: ログイン項目以外の kind はまだ model に変換されない。
パスワードと TOTP シークレットは復号してメモリ上のモデルに保持するが、
UI へは平文を出さず、監査と TOTP コード生成に限定して使用する。
device identifier は UUID v4 を生成して永続化し、再ログイン / 再同期で
同じ値を再利用する。
API key はテスト専用アカウントで使用すること（権限範囲の注意は README 参照）。

オフラインキャッシュについて: `src/cache.rs` の読み込み・検証を認証フローへ
接続した。`authenticate_inner` は `sync_body()` の失敗、または取得した body の
パース失敗時に `cache::cached_sync_for_detailed` でプラットフォームのキャッシュ
ディレクトリ（旧設定ディレクトリは読み取り専用フォールバック）から暗号化済み
body を読み出し、サーバー URL を照合して `SyncData` に戻す。復号には
生セッションの protected key を使うため、キャッシュは鍵素材を一切提供しない
（保存前に `profile.key` / `privateKey` を除去済み）。復元したかどうかは
`AuthenticatedVault::from_cache` に記録する。

書き込み側は接続していない。0.1.0 では `Client::sync()` が解析済み
`SyncData` のみ返し、`Session::access_token` も private だったため raw body
を取得できなかった。0.1.1 では `sync_body()` が公開され、`src/auth.rs` は
本番認証経路でこれを取得するが、取得した body を `SyncCache::from_body` /
`save_default` へ渡す経路は存在しない（後述の再裁定を参照）。
キャッシュファイルが存在するのは旧リリースが書いた既存ファイル、または
外部から配置した場合に限られる。初回からオフライン（キャッシュなし）の
場合は従来どおり `AuthError::Sync` を返す。キャッシュが存在するのに使えない
場合は、破損・読込失敗・バージョン不一致・サーバー不一致の別を
ステータスへ表示する。

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

再検討トリガー#1は 0.1.1 の `Client::sync_body()` 公開により発動済みである。
方針の変更の有無は後節で再裁定する。

## Decision Update (2026-11-21): 再検討トリガー#1の発動と再裁定

**発動**: openwarden 0.1.1 が `Client::sync_body()` を公開し、
`src/auth.rs` の `authenticate_inner` が本番認証経路で生 body を取得している。
2026-11-18 に定めた「raw body が公開されたら見直す」というトリガー#1は
発動済みである。

**再裁定**: writer は接続せず、**現状維持**とする。

- 生 body は認証経路で直接 `parse_sync` へ渡り、E2E は成功している。
  キャッシュ書き込みがなくても初回オンラインの復元経路は成立する。
- かつて `SyncCache::from_body` の redact が camelCase のみを除去し、
  PascalCase の `Key` / `PrivateKey` が残存するリスクがあったが、
  2026-11-21 に大小文字・区切り文字を問わず除去するよう修正済み
  （`src/cache.rs:151-179`、回帰テスト `src/cache_tests.rs:134-166`）。
  このリスクは writer 現状維持の根拠には使わない。
- トリガー#2（オフライン復元の価値が実装コストを上回る実測）を
  まだ満たしていない。PoC の目的は GPUI UI と openwarden 統合の検証であり、
  暗号化キャッシュの書き込み経路を追加する利点が未測定である。

**再検討の条件**: オフライン復元の価値が実測で示された時点で接続の要否を
再度判断する。今回はコードを変更せず、判断のみを記録する。

## Decision Update (2026-11-21): 階層別エラー型の別名を維持する

`SyncError` / `SyncCacheError` / `CacheLoadError` / `GeneratorError` /
`TotpError` はすべて `AppError` の `pub type` 別名である。これらは
「層ごとの意味的なラベル」として残し、独立 enum へ戻さない。

根拠: 実体は単一の `AppError` で、`Display` / `PartialEq` / `Error::source()`
は共通化済み。独立 enum に戻すには各境界で `From` 変換とメッセージの
二重管理が発生し、PoC の目的に見合わない。型システムで層を区別する
必要が生じた場合は、newtype 化を ADR 改訂として別途検討する。

## Decision Update (2026-11-21): 残る既知制約の再評価

3 体の調査エージェントと親の Runtime Proof で、残る 5 件を再評価した。
いずれも現状維持とし、コード変更は行わない。

- 他 item kind の実データ取り込み: openwarden 0.1.1 は非 login の
  decryptor も暗号文アクセサも公開しない（`SyncData.ciphers` は
  `pub(crate)`、`item_key()` は非公開）。PoC 側のモデルと UI は
  5 kind 分すべて用意済みだが、上流 API 追加が前提。モック維持とする。
- リダイレクト先検査: openwarden の `Client::new` は
  `redirect(Policy::none())` を設定しており追従自体が無効。検査対象が
  存在しないため追加しない。DNS rebinding の TOCTOU は README に
  開示済みで、IP ピン留めはトランスポート差し替えが必要なため範囲外。
- OS keyring: `keyring` crate 4.2.0 は成熟しているが、Linux では
  Secret Service / D-Bus 依存が増え、「認証情報を永続化しない」という
  現行の脅威モデルを変更する。PoC では zeroize と既知制約の開示を継続。
- 構造化ログ: 見送りの根拠は [全体敵対的レビュー結果](../review-report.md)
  の「見送り・未実装」に一本化した（依存追加の是非と代替手段の詳細は同節を
  参照）。ここでは重複記述しない。
- 上流 changelog 監視: 0.2 は未公開で [Unreleased] も空。Dependabot の
  cargo 週次が exact pin の更新 PR を作成し release notes を付けるため、
  専用自動化は不要。

再評価トリガー: openwarden が非 login の decryptor を公開した時点で、
他 kind の取り込みを再検討する。

## Status

Self-reviewed by agent at 2026-11-17T00:27:33+09:00.
Cache restore wiring re-reviewed against the current implementation at
2026-11-18T03:44:54+09:00.

Final decisions recorded in this ADR:

- 2026-11-18T21:28:00+09:00 — writer は接続せず読み取り専用を維持。
- 2026-11-21T04:49:12+09:00 — `sync_body` 公開で再検討トリガー#1が発動したが、
  オフライン復元の実測が無いため現状維持を再確認。
- 2026-11-21 — 階層別エラー型は `AppError` の alias として維持。
- 2026-11-21 — 残る既知制約 5 件は現状維持（本文の再評価節を参照）。

## Links

- [openwarden (crates.io)](https://crates.io/crates/openwarden)
- [GPUI](https://gpui.rs)
