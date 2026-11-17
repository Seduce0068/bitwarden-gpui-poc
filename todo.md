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
  at: "2026-11-18T03:50:45+09:00"
status: current
stale_after: "2027-05-17T21:04:43+09:00"
---

## 進行中

なし。クロスレビューは修正を行わない（read-only）方針で実施した。

## 未着手

### 優先度: 中

- [ ] エラー型を集約し source チェーンを保持する
  - 根拠: E5
  - File: src/auth.rs:182-190, src/vault_sync.rs:45, src/cache.rs:71-105, src/totp.rs:117
  - 現状: 6ファイルに分散、source() 未実装、String 化で原因チェーンが切れる。
  - 受け入れ条件: 共通 AppError（#[from]）または `Box<dyn Error>` で source 保持、
    キャッシュは parse/redact/serialize で別バリアント。

### 優先度: 低

- [ ] link-local 検証を解決先 IP・リダイレクト先まで拡張する（S9-01 / TH5 / API2）
- [ ] デッドコード・過剰な pub を整理する（A7 / A10）

## 完了

- [x] エージェントチームによる3タスク並列対応・第8弾（2026-11-18）
  - Dependabot（cargo 週次）/ deny.toml / CI の cargo deny check を追加
  - sha2 直接依存は SSH fingerprint で使用中と確認し維持（古い記述を修正）
  - 同期失敗時に暗号化キャッシュから復元する経路を auth 層へ接続（writer は未接続）
  - テスト属性を `#[test]` に統一（69箇所）。shadowing で不可な3ファイルは理由を明記
  - ルート担当: `## [Unreleased]` 運用と ADR ログ追記ルールを README に明記
  - ルート修正: プライベート項目への rustdoc リンクを通常表記へ変更
- [x] エージェントチームによる4タスク並列対応・第7弾（2026-11-18）
  - デバイス ID を UUID v4 で永続化し再ログイン / 再同期で再利用
  - SSH 公開鍵から SHA-256 fingerprint を再計算して照合
  - 選択解除の全経路を `deselect_and_rewind()` に集約
  - 辞書パスワードの長さ上限を定数化し境界をテスト
  - ルート担当: README の bash コマンド例を `bash -n` で検証
  - 整理: カード末尾4桁マスキングは既存実装で充足（再実装不要）
  - 却下: 「再コピーで deadline を延長しない」は TH1 修正（毎回再取得）と
    矛盾するため採用せず
- [x] エージェントチームによる4タスク並列対応・第6弾（2026-11-18）
  - 実ログインで password / TOTP を実復号し、監査に対象外件数を明示
  - F1 でフォーカスを復帰（既存キー分類には影響しない）
  - 選択行を ">" マーカーでも表示
  - TOTP 失敗文言を TotpError::message() に統一
  - ルート担当: README のドキュメント導線 / コントリビューション / Kubuntu 例
  - 既知制約: 復号失敗時の NUL ステータストークンはパスワード欄に保持
- [x] エージェントチームによる4タスク並列対応・第5弾（2026-11-18）
  - アンロック遷移の状態リセットを共通化（enter_unlocked / reset_input_state）
  - メール・認証入力の長さ上限（UTF-8 境界で切り詰め）
  - 監査 / 生成 / 設定パネルに縦スクロールを追加
  - `Finding::InsecureUri` にマスク済み URI のみを格納
  - ルート担当: ADR 索引へ log.md 導線、README のゲート順序を統一
- [x] エージェントチームによる4タスク並列対応・第4弾（2026-11-18）
  - 部分成功の保持とエラー系統別の案内分岐（vault_sync / login_flow）
  - キーガード分岐のテスト（keys_tests / auth_state / clipboard）
  - 検索の NFKD 正規化・空名除外・Cf 文字拒否（model / auth）
  - キャッシュの XDG_CACHE_HOME 移動（cache）
  - ルート担当: idle_lock_due の checked_duration_since 化
  - 正規化は自作テーブルを廃し `unicode-normalization` クレートへ委譲
- [x] エージェントチームによる4タスク並列対応・第3弾（2026-11-18）
  - 機密の Zeroizing 化（model / ui state / login_flow ほか機械的追従）
  - 日付時刻パースの堅牢化（うるう年・RFC3339 オフセット・checked 算術）
  - 設定スキーマバージョン（現行 1 / 未知バージョンの安全な拒否）
  - テスト名とアサーションの整合（TOTP / クランプ / canary 非漏洩）
  - ルート担当: README の実接続手順・API key 注意、ADR を現行実装へ更新
- [x] エージェントチームによる4タスク並列対応（2026-11-18）
  - パスワード生成とエントロピー推定を整合（generator / health / words）
  - 同期データの重複排除・revision 検証・監査ログ（vault_sync）
  - 1秒 ticker のドリフト解消（Timer::at + 純粋 deadline 計算）
  - ウィンドウ生成失敗時に cx.quit()（main.rs、ルートが担当）
- [x] エージェントチームによる3タスク並列対応（2026-11-18）
  - 最終操作時刻の更新（src/ui/login_flow.rs）
  - 監査誤判定の修正（src/health.rs / health_tests.rs）
  - 設定読み込みの堅牢化（src/settings.rs / settings_tests.rs / generator.rs）
  - 未着手: 破損ファイルのタイムスタンプ付き退避は別タスクとして残す。
- [x] 復号処理を UI スレッドからオフロード（2026-11-18）
  - `smol::unblock` で `unlock_and_import` をブロッキングプールへ移動。
  - `LoginResult` で認証失敗 / 復号失敗 / 成功を区別し、UI 側は結果適用のみ。
  - 敵対的レビューで機能回帰なしと判定。残存: 実行中の unblock ジョブは
    generation ではキャンセルされない（結果の適用のみ破棄）。コードに明記。
- [x] 監査ボタンとキー状態を整合（2026-11-18）
  - `effective_panel()` でレポート未生成時の Audit 遷移を Vault に戻し、
    描画と `KeyContext.panel` の不一致を解消。
  - 実ログイン成功時に `refresh_audit()` を呼ぶようにした。
- [x] クリップボードの連続コピーを修正（2026-11-18）
  - 毎回コピー直前の内容を保存し、復元時にその内容を書き戻す。
  - 読み取り失敗時は空文字で上書きせず no-op。復元時にステータス更新。
  - 状態遷移を純粋関数化し、連続コピー / 未読取 / 未保留のケースをテスト。
- [x] 設定の真実源を `Settings` に一本化（2026-11-18）
  - `server_url` / `email` / 生成設定のミラーを廃止し、全読み書きを
    `Settings` へ直接化。`sync_settings_from_ui()` と
    `GeneratorState::from_settings()` を削除。
  - `GeneratorState` は生成結果のみを保持し、lock() でクリア。
  - 敵対的レビューで機能バグなしと判定。配線レベルのテスト欠如と
    権限範囲（apply_generator_key が &mut Settings を受け取る点）は残存。
- [x] 修飾キーと IME 入力を扱う（2026-11-18）
  - `KeyModifiers` / `key_char` を `KeyContext` へ追加。Ctrl/Cmd/Fn は常に
    除外、Alt は編集中に文字が生成された場合のみ許可。
  - Shift 文字は `key_char` 経由で判定し、既知 P0 の Shift+Y を解消。
  - 挿入アクションを文字列単位へ変更し、IME 確定文字を一括挿入。
  - 敵対的レビューの High 2件（Shift+Y / Alt 由来文字）を修正。
  - 未確認: IME 確定を Enter で行う環境の keystroke 実態はローカル資料が
    無く検証していない。
- [x] パネル切替時に入力モードをクリア（2026-11-17）
  - `BitwardenApp::set_panel()` に集約し、設定編集 / 認証フィールド /
    検索状態を必ず解除。マウスのパネルボタンも同じ経路を通る。
  - Esc が「キャンセルではなく確定」である旨を README と設定パネルの
    ヘルプに明記。
- [x] 一時ファイルを一意名＋適切な権限で管理（2026-11-17）
  - `tempfile::NamedTempFile` を再利用（create_new / 0600 / RAII 後始末 /
    atomic persist）。既存ファイルの権限も 0600 に是正。
  - 親ディレクトリ fsync は best-effort（rename 成功後の失敗を保存失敗と
    報告しない）。ベアな相対パスの扱いを修正。
  - 敵対的レビューで指摘された相対パス潜伏バグ・テストの形骸化を修正。
  - 残る制約: 既存親ディレクトリの権限是正は行わない／強制終了時は一時
    ファイルが残り得る。
- [x] 非同期ログインに試行世代を導入（2026-11-17）
  - `src/ui/login_generation.rs` の純粋トークンで spawn 時に採番し、
    `finish_login` が現行トークン一致時のみ適用。重複コールバックも破棄。
  - lock / モック解除 / 新しいログイン / 検証失敗 / 認証値変更で無効化。
  - 敵対的レビューの指摘 2 件を修正（検証失敗時の残存、認証値変更の無効化）。
- [x] `Settings::sanitized()` で `Thresholds` をクランプ（2026-11-17）
  - `weak_bits` を 1..=200、`stale_days` を 1..=3650 に丸め、
    手編集ファイルを `load_detailed()` で読み込む経路の回帰テストを追加。
- [x] `todo.md` をプロジェクト内へ配置（2026-11-17）
- [x] 5ラウンドの全体クロスレビュー（25エージェント、約169件の生指摘）を実施。
- [x] 重複クラスタ 16 を吸収し、妥当性を Runtime Proof で裏付け。
- [x] 誤検知／過大評価／既に対処済み 5件（V1〜V5）を却下。

## メモ

- グローバルTODO: `~/.config/opencode/todo.md`（複数プロジェクト横断のタスク用）。
- 詳細な生指摘は [docs/cross-review-findings.md](docs/cross-review-findings.md) を参照。
- 本レビューは修正を行わない（read-only）方針。エージェントは
  `read` / `grep` / `glob` のみを使用（r4-render が読み取り専用 ls を1回実行した
  自己申告あり。ファイル変更・ビルド・テスト・git 操作はなし）。
- 途中終了したエージェント（r1-ops / r1-security / r1-correctness / r1-ops-retry）は
  観点を分割した代理エージェントで回収済み。
- 性能・スケール上の指摘（UI フリーズ、ticker ドリフト、バイナリサイズ等）は
  測定を行っていないため、機能バグとは区別して扱う。
- 外部クレート（openwarden / gpui / smol）の内部動作に関する指摘は
  依存クレートを読んでいないため推測として明示している。
