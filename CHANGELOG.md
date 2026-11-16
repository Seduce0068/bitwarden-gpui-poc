# Changelog

このファイルは [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) の形式に従う。

## [Unreleased]

## [0.1.0] - 2026-11-17

### Added

- GPUI によるロック画面と vault 一覧、監査 / 生成 / 設定の各パネル
- 一覧のフィルタ・ソート・検索（lib の `Vault::view()` に委譲）
- TOTP の実コード生成、1秒ごとのカウントダウン、クリップボードコピー
- パスワード / passphrase 生成と強度表示
- 30秒後にクリップボードを復元する仕組み（ロック時も即復元）
- `openwarden` による実ログイン・同期・復号（API key + マスターパスワード）
- ログインの30秒タイムアウトと `r` キーによる再試行
- 設定の JSON 永続化（サーバーURL / メール / 生成設定 / 監査閾値）
- 暗号化済み同期データのオフラインキャッシュ（キーは保存しない）
- 一覧行のクリックとヘッダーのパネル切替ボタンによるマウス操作
- 共通ワークフローへの CI 委譲と `cargo audit` ゲート
- ADR: `docs/adr/adr-20261116-openwarden-integration.md`

### Changed

- UI を独自モックデータから lib の `model::Vault` に接続
- 実ログイン時にログイン項目の名前 / username / URI を復号して表示
- UI の状態型とパネル描画を `src/ui/` に分割
- 検証コマンドを CI ゲート（`--all-targets --locked`、`-D warnings`）と統一

### Security

- 認証情報は `SecretString` で保持し、`Debug` 出力に漏らさない
- キャッシュ保存前に `profile.key` / `privateKey` を除去し、マスターパスワードのオフライン推測を防止
- パスワードと TOTP 秘密は復号してモデルに保持しない
- ロック時に認証情報・生成結果・監査結果をメモリから消去

### Known limitations

- 実サーバーへの接続テストは認証情報がないため未実施
- ログイン以外の item kind はモックデータのまま
- キャッシュは openwarden 0.1.0 の API 制約で認証フローに未接続
- OS keyring 連携と完全なロック時メモリ保護は未実装
