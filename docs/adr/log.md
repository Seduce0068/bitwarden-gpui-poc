# ADR 変更ログ

## 2026-11-18

- エージェントチームによる並列対応（5ラウンド）の実装記録を追記
- 監査・設定読み込み・生成・同期・ticker の挙動変更を反映
- Unicode 正規化を `unicode-normalization` クレートへ委譲した旨を記録
- 本ログへの導線を `index.md` に追加
- 暗号層 → UI の往復（パスワード / TOTP 実復号）を実装した旨を記録
- デバイス識別子の永続化を記録
- 同期失敗時の暗号化キャッシュ復元を接続した旨と writer 未接続の理由を追記
- 実接続と API key の注意を README に追記し、本 ADR の実装結果を更新

## 2026-11-17

- `adr-20261116-openwarden-integration.md` を approved に更新
- 実装結果と未解決事項を追記
- オフラインキャッシュが openwarden 0.1.0 の API 制約で接続不可である旨を追記
- `index.md` に上位のドキュメント一覧への導線を追加

## 2026-11-16

- `adr-20261116-openwarden-integration.md` を追加
