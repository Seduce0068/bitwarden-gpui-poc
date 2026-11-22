# ADR 変更ログ

## 2026-11-23

- オフライン復元を client_id 由来のアカウント照合へ更新し、
  ADR 本文の「照合不能」記述を是正
- 認証の絶対デッドラインタイムアウト、機密フィールドの Zeroizing 化、
  TOTP の otpauth 非 ASCII ラベル対応を記録
- エラー分類列挙（`AppError` の層別バリアントとモジュール別名）を
  現行実装に合わせて更新

## 2026-11-22

- シークレットスキャンを Gitleaks から Betterleaks v1.10.1 へ置換
  （pre-commit 主軸・CI 最終ゲートの構成は維持）
- 残タスク・全体レビューの第50〜63弾を通し、監査 UI の WCAG 対応、
  設定／キャッシュ／同期の堅牢化とテスト追加を実施
- 複数文字・単文字英数字セパレータの passphrase 監査対応は回帰のため却下

## 2026-11-21

- openwarden 0.1.1 の `sync_body` を接続し、PascalCase 正規化を本番経路へ適用。
  実サーバー E2E が成功
- 階層別エラー型の別名を維持する決定を記録
- From 変換 impl を型定義側へ移し、error.rs の逆依存を解消
- writer 再検討トリガー#1（raw sync body の公開）の発動を記録し、
  現状維持を再裁定（redact 修正は完了済みで、判断根拠には使わない）

## 2026-11-20

- `vault_sync::parse_sync` が PascalCase の sync JSON キーを camelCase へ
  正規化。キャッシュ経由のボディは解析可能になったが、当時は生認証経路が
  `Client::sync()` の内部パースを通るため E2E は未成功

## 2026-11-19

- 実サーバー E2E の opt-in テストを追加。ローカル Vaultwarden 1.30.2 で
  認証・sync HTTP 200 まで到達したが、sync JSON の PascalCase と
  openwarden の camelCase パーサーの不一致を確認
- キャッシュに取得時刻と 7 日の有効期限を追加（旧ファイルは best-effort で許可）

## 2026-11-18

- 復号失敗 URI を `NoUri` ではなく検査対象外として報告するよう監査を更新
- `from_cache` をログイン成功ステータスへ反映し、復元データの鮮度を通知
- オフラインキャッシュ writer の方針を決定（PoC では読み取り専用を維持、
  上流 API 拡張または実測された E2E 必要性が出た時のみ再検討）
- エージェントチームによる並列対応（5ラウンド）の実装記録を追記
- 監査・設定読み込み・生成・同期・ticker の挙動変更を反映
- Unicode 正規化を `unicode-normalization` クレートへ委譲した旨を記録
- 本ログへの導線を `index.md` に追加
- 暗号層 → UI の往復（パスワード / TOTP 実復号）を実装した旨を記録
- デバイス識別子の永続化を記録
- 同期失敗時の暗号化キャッシュ復元を接続した旨を追記
- 共通エラー型と link-local 検証の拡張、UI の可視性整理を記録
- 実接続と API key の注意を README に追記し、本 ADR の実装結果を更新

## 2026-11-17

- `adr-20261116-openwarden-integration.md` を approved に更新
- 実装結果と未解決事項を追記
- オフラインキャッシュが openwarden 0.1.0 の API 制約で接続不可である旨を追記
- `index.md` に上位のドキュメント一覧への導線を追加

## 2026-11-16

- `adr-20261116-openwarden-integration.md` を追加
