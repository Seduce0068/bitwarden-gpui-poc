---
type: Report
title: "全体クロスレビュー検出事項（蓄積用）"
description: "修正なしのエージェントチームによる5ラウンドの全体クロスレビュー検出事項と、第6ラウンドでの重複・妥当性吸収結果"
tags:
  - review
  - cross-review
  - findings
generated:
  by: "dsh-agent (lead)"
  at: "2026-11-17T19:25:00+09:00"
status: "in-progress"
stale_after: "2027-05-17T19:25:00+09:00"
---

## 概要

プロジェクト全体（src/ 約8,200行 + docs/ + CI + Cargo.toml）に対し、
修正を行わない（read-only）エージェントチームで多観点クロスレビューを実施する。
ラウンド1〜5で検出事項を蓄積し、ラウンド6で重複統合・妥当性評価を行い
todo（タスクボード）へ追加する。

## 進捗

- ラウンド1: 完了（8エージェント、約57件、重複クラスタ7）
- ラウンド2: 完了（5エージェント、35件、新規クラスタ8）
- ラウンド3: 完了（5エージェント、32件、新規クラスタ10）
- ラウンド4: 完了（5エージェント、22件、新規クラスタ8）
- ラウンド5: 完了（5エージェント、23件、新規クラスタ7＋妥当性逆検証）
- ラウンド6（統合）: 進行中

## 検出事項

### ラウンド1

使用エージェント: r1-arch / r1-tests / r1-corr-crypto（完了）、
r1-ops-retry / r1-sec-secrets / r1-sec-input / r1-corr-state（実行中）。
r1-security / r1-ops / r1-correctness は途中終了したため、
観点を分割した代理エージェントで再起動した。

#### r1-arch（アーキテクチャ / 設計、10件）

- **[A1] [High] 設定の真実源統一がミラー方式に留まり、ロック画面の編集が永続化されない**
  - File: src/ui/app.rs:12-13,40-43,134 / src/ui/actions.rs:53-63 /
    src/ui/input.rs:57-60 / src/ui/login_flow.rs:89-106
  - 真実源を `self.server_url`/`email` に統一したと記録されるが、`Settings` 側にも残り
    `sync_settings_from_ui()` が双方向ミラー。同期は FinishSettingsEdit/save_settings 時のみ。
    ロック画面の ServerUrl/Email 編集は `self` のみ更新するため `w` 保存せず再起動すると失われる。
    `lock()` が generator を settings から再構築するためジェネレータ設定も巻き戻る。
  - Remediation: Settings を単一真実源にするか、全編集経路が通る単一 update_settings コマンドを設ける。
  - Confidence: high
- **[A2] [Medium] 非同期ログインに試行世代が無く、完了順が最終状態を決める**
  - File: src/ui/login_flow.rs:25-53,56-87 / src/auth.rs:294-300
  - 再試行連打時に古い試行の結果が新しい試行を上書きし得る（GPUI 下での再現は未検証）。
  - Remediation: login_generation を導入し不一致結果を破棄、またはキャンセルトークン。
  - Confidence: medium
- **[A3] [Medium] VaultViewState の純粋 API がデッド化し BitwardenApp に同一ロジックが重複**
  - File: src/ui/vault_view.rs:49-137 / src/ui/app.rs:121-206 / src/ui/input.rs:120-125
  - Remediation: app 側を VaultViewState メソッドへ委譲。
  - Confidence: high
- **[A4] [Medium] cache モジュールが本番コードから完全に孤立**
  - File: src/cache.rs:70-200 / src/lib.rs:21 / docs/adr/adr-20261116-openwarden-integration.md:93-97
  - cache の修正（エラー区別/atomic/0600）は到達不能コードに対して行われた形。
  - Remediation: auth 層から SyncCache へ接続するか、feature ゲート/削除して ADR と整合。
  - Confidence: high
- **[A5] [Medium] ADR の Implementation Result が現行実装と不一致（74件/モック挙動）**
  - File: docs/adr/adr-20261116-openwarden-integration.md:82-91,99-101
  - 現行は 137 passed、Enter 常に実ログイン、明示的デモキー。
  - Remediation: 現行のテスト件数・挙動へ更新し verified を更新。
  - Confidence: high
- **[A6] [Medium] openwarden 型が model の公開 API に漏出し =0.1.0 ピンがドメイン層へ伝播**
  - File: src/model.rs:101-109,352-355,581-594 / Cargo.toml:20-21 / ADR:44-45
  - Remediation: model 側に自前型を定義し vault_sync 境界で変換。
  - Confidence: high
- **[A7] [Low] 未使用状態・デッド API・過剰な pub**
  - File: src/model.rs:501-503 / src/vault_sync.rs:156-160 /
    src/ui/logic.rs:11-13 / src/ui/auth_state.rs:46-48 /
    src/lib.rs:20-30 / src/auth.rs:78
  - Vault::unlocked が未読、has_credentials がテスト専用、全モジュール pub、SyncCacheError 再エクスポート。
  - Confidence: high
- **[A8] [Low] 設定値クランプが Settings と ui::logic に分散し sanitized() は thresholds を検証しない**
  - File: src/settings.rs:101-114 / src/ui/logic.rs:35-68
  - Confidence: high（T1 と重複）
- **[A9] [Low] デバイス ID 固定と再同期経路の欠如（ADR 記載済みの設計負債が残存）**
  - File: src/ui/login_flow.rs:35-38,70-80 / ADR:89-97
  - Confidence: high
- **[A10] [Info] *_tests.rs を #[path] で読み込む配置は既知の見送り項目**
  - File: src/auth.rs:308-310 等 / docs/review-report.md:68-69
  - Confidence: high

#### r1-tests（テストの質、13件）

- **[T1] [High] Settings::sanitized() が thresholds をクランプせず手編集 JSON で健全性監査を無効化できる**
  - File: src/settings.rs:106-114 / src/health.rs:201-218 / src/settings_tests.rs:51-88
  - `{"thresholds":{"weak_bits":0,"stale_days":999999}}` がそのまま採用され audit が無効化される。
  - Remediation: sanitize テストに thresholds の壊れた値を追加し 1..=200 / 1..=3650 に丸まることを検証。
  - Confidence: high（A8 と重複）
- **[T2] [Medium] Settings::save() が sanitized() を通さず保存経路の検証テストが無い**
  - File: src/settings.rs:150-154 / src/settings_tests.rs:15-37
  - Confidence: medium
- **[T3] [Medium] ファイル系テストが固定 temp パスを使用し並列実行・再実行で衝突しうる**
  - File: src/cache_tests.rs:16-18 等 / src/settings_tests.rs:17,78,92 等 / src/private_file.rs:71,85
  - Remediation: PID + 乱数を含む一意ディレクトリ + Drop 削除のフィクスチャを導入。
  - Confidence: high（実際のフレーキー発生確率は低い）
- **[T4] [Medium] now_unix_is_plausible は 2100 年以降に必ず失敗する時間爆弾**
  - File: src/totp_tests.rs:167-173 / src/totp.rs:178-182
  - Confidence: high
- **[T5] [Medium] passwords_are_not_all_the_same の2つ目のアサーションが実質機能しない**
  - File: src/generator_tests.rs:73-83
  - `distinct.len()==32` により `first` 検証が無効化、確率的で決定的でない。
  - Confidence: high
- **[T6] [Medium] otpauth URI の境界値（digits=0/period=0/未知アルゴリズム）が未検証**
  - File: src/totp_tests.rs:9-82 / src/totp.rs:57-64,153-166
  - Confidence: medium
- **[T7] [Medium] debug_output_does_not_leak_secrets がクライアントシークレットの値を検証していない**
  - File: src/auth_tests.rs:82-87 / 同:5-13
  - Remediation: client_secret を固有値に変え non-leak を assert。
  - Confidence: high
- **[T8] [Low] parse_revision が月ごとの日数・うるう年を検証せず不正日付を別の日として解釈**
  - File: src/vault_sync.rs:118-129 / src/vault_sync_tests.rs:24-38
  - Confidence: high
- **[T9] [Low] 認証のタイムアウト／ネットワーク由来のエラー分岐が実質未検証**
  - File: src/auth_tests.rs:129-166 / src/auth.rs:170-306
  - Confidence: medium
- **[T10] [Low] ロック処理の統合シーケンス（復元＋秘密消去＋状態初期化）が未検証**
  - File: src/ui/app.rs:129-147 / src/ui/auth_state.rs:115-198 /
    src/ui/totp_state.rs:55-108 / src/ui/clipboard.rs:58-83
  - Confidence: medium
- **[T11] [Low] キー分類のガード分岐（has_audit_report=false / query_nonempty=false）が未検証**
  - File: src/ui/keys_tests.rs:107-120,143-156 / src/ui/keys.rs:248,252
  - Confidence: high
- **[T12] [Info] test-spec（トレーサビリティ）ドキュメントが無い**
  - File: docs/review-report.md:89-104 / docs/index.md / 本书
  - Confidence: high
- **[T13] [Info] #[::core::prelude::v1::test] と #[test] が混在**
  - File: ほぼ全テストファイル
  - Confidence: medium
- 補足（推測）: matches_query が大文字 needle を想定しない契約 / cache_tests が暗号化済みアイテム保持を未検証。

#### r1-corr-crypto（TOTP / 生成 / 健全性、8件）

- **[C1] [Medium] 単語リストが prefix-free でなく、区切りなし設定で単語境界が崩れる**
  - File: src/words.rs:3-5,212,406,774-775
  - `"pine"`/`"pineapple"` 等。separator="" で 4単語が3単語に見え、エントロピー過大評価。
  - Confidence: high
- **[C2] [Medium] デフォルト4単語パスフレーズが 39.8 bit で Weak 判定される**
  - File: src/generator.rs:290-296,131-140 / src/words.rs
  - 994語×4 = 39.83 bit < 40.0 閾値。既定が常に Weak。
  - Remediation: words=5 以上または語リスト拡張 + 回帰テスト。
  - Confidence: high
- **[C3] [Medium] パスワード生成が選択した文字種ごとの最低1文字を保証しない**
  - File: src/generator.rs:105-115
  - Confidence: medium（仕様がコメントからの推測）
- **[C4] [Medium] 不正な TOTP シークレットが「設定済み」として集計され coverage が過大**
  - File: src/health.rs:359-361 / src/totp.rs:120-123
  - `is_valid_secret()` が未利用。
  - Confidence: high
- **[C5] [Medium] starts_with("password") が長いランダムパスワードまで共通パスワードと誤判定**
  - File: src/health.rs:330-333
  - qwerty 側には len<=12 上限があるのに password 側は無制限。
  - Confidence: high
- **[C6] [Medium] 空パスワードのログインが WeakPassword として報告されない**
  - File: src/health.rs:405-415
  - Confidence: medium
- **[C7] [Low] カード番号が空の項目に「URI 未設定」という無関係な finding**
  - File: src/health.rs:420-422,44-45
  - Confidence: high
- **[C8] [Low] 失敗した TOTP の Tick が無期限に fresh とみなされる**
  - File: src/totp.rs:153-166
  - Confidence: medium（UI ライフサイクル未確認）
- 補足: RFC 6238 ベクタ・30秒境界・Base32・コード長（6/8/Steam5）・clock skew はテスト充実、
  追加不具合なし。draw_below の rejection sampling も正しい。

#### r1-sec-input（入力検証 / 認証 / 依存、8件）

- **[S9-01] [Medium] link-local 遮断が IP リテラルのみで DNS 名による SSRF バイパス**
  - File: src/auth.rs:104
  - `Host::Domain` は常に false。`169.254.169.254.nip.io` 等が検査をすり抜ける。
  - Confidence: medium（コード事実は高、脅威モデルは割り引き）
- **[S9-02] [Low] VaultItem.notes が Debug でマスクされずに露出**
  - File: src/model.rs:278
  - 外側の VaultItem は derive(Debug) のまま。notes は自由入力で秘密が入りうる。
  - Confidence: high
- **[S9-03] [Low] メール検証が C0 制御文字を許容**
  - File: src/auth.rs:82
  - `is_whitespace` は NUL/\x01/\x7f を通す。長さ上限も無い。
  - Confidence: high
- **[S9-04] [Low] 認証情報・URL・検索クエリに長さ上限が無い**
  - File: src/ui/login_flow.rs:89 等
  - 無制限 push、sanitized() は数値のみ clamp。
  - Confidence: high
- **[S9-05] [Low] 設定検証失敗時に login_failed が立たず再試行キーが無効**
  - File: src/ui/login_flow.rs:27 / src/ui/keys.rs:163
  - レビュー報告の「全エラーパスで設定」の取りこぼし。
  - Confidence: high
- **[S9-06] [Low] 秘密の平文 String 中間コピーが zeroize 対象外**
  - File: src/ui/login_flow.rs:15
  - `auth_config()` が `.to_string()` で平文一時 String を生成。
  - Confidence: high
- **[S9-07] [Low] openwarden の復号失敗が login_item で握りつぶされる**
  - File: src/vault_sync.rs:76
  - folders_from は伝播するが login_item は .ok()/unwrap_or_default() で吸収。
  - Confidence: high
- **[S9-08] [Low] タイムアウト／連打で KDF の unblock がキャンセルされず多重実行（推測）**
  - File: src/auth.rs:298
  - smol::unblock のキャンセルセマンティクス未検証。
  - Confidence: low
- 補足: forbid(unsafe_code)、clippy deny、= ピン、cargo audit、CI @v1 は方針どおりで残存問題なし。

#### r1-corr-state（状態遷移 / 同期 / 非同期、7件）

- **[C9-1] [High] 遅延ログイン完了がロック／モック遷移を上書きするレース**
  - File: src/ui/login_flow.rs:39-52,70-80 / src/ui/keys.rs:162,243
  - Enter 開始後に m でモック、l でロックしても、遅延 finish_login が screen を確認せず
    Screen::Unlocked と view.vault を設定 → ロック保証の破綻。
  - Remediation: 試行 ID を導入し finish_login で現行 ID 一致・screen==Locked・認証値未変更を検証。
  - Confidence: high（A2 と重複、より具体的）
- **[C9-2] [Medium] 実ログイン成功時に refresh_audit が欠落し監査画面を開けない**
  - File: src/ui/login_flow.rs:70-80 / src/ui/keys.rs:248
  - unlock_mock は refresh_audit() を呼ぶが finish_login は呼ばない。実ログイン後は
    audit_report=None のまま → g キーが OpenAudit を返さない。
  - Confidence: high
- **[C9-3] [Medium] unlock_and_import を UI スレッドで同期実行しフリーズする**
  - File: src/ui/login_flow.rs:70 / src/auth.rs:213-234,241-242
  - 全アイテム復号が cx.update 内で同期実行。auth.rs のコメントと矛盾。規模は未計測。
  - Confidence: high
- **[C9-4] [Medium] ログイン成功時に last_activity が更新されず即アイドルロック**
  - File: src/ui/login_flow.rs:70-80 / src/settings.rs:108 / src/ui/input.rs:36
  - 60秒閾値 + 30秒認証で Unlocked 直後に残り30秒 → 自動ロック。
  - Confidence: high
- **[C9-5] [Low] validate_config 失敗時に login_failed が立たず r 再試行が無効**
  - File: src/ui/login_flow.rs:27-31 / src/ui/keys.rs:163
  - S9-05 と同一。
  - Confidence: high
- **[C9-6] [Info] オフラインキャッシュが UI／同期フローに一切接続されていない**
  - File: src/cache.rs:70-89,178-199
  - A4 と同一。
  - Confidence: high（未接続の事実）/ medium（意図は未確認）
- **[C9-7] [Info] キャッシュ保存時にキー除去後の JSON を apply_sync できるか未検証**
  - File: src/cache.rs:62-64,94-106
  - redact_profile_keys の再シリアライズ後に復元できるかは未確認。
  - Confidence: low
- 補足: idle_lock_due 境界、evaluate_tick の AutoLock 優先、move_selection、adjust_* クランプ、
  write_private の atomic rename、clipboard.due は問題なし。

#### r1-ops-build（ビルド / CI / リリース / ドキュメント、2件）

- **[O1] [Low] README 内で cargo audit と doc ゲートの順序が矛盾**
  - File: README.md:110 と README.md:97-98
  - CI 節は `...clippy → cargo audit → doc`、検証ブロックは `clippy → doc → audit`。
  - Confidence: high
- **[O2] [Info] review-report の description が初回版 v0.1.0 のまま（現在 0.1.101）**
  - File: docs/review-report.md:4 / Cargo.toml:3 / CHANGELOG.md:7
  - 意図的な可能性があり断定避ける。
  - Confidence: medium
- 整合確認: 版、MSRV(1.88)、ライセンス(AGPL-3.0-or-later)、CI タグトリガー/uses/@v1/permissions、
  依存ピン理由、review-report 検証節。未検証: Cargo.lock、再利用ワークフロー実体、git タグ/リモート、依存の実 MSRV。

#### r1-sec-secrets（秘密情報のライフサイクル、8件）

- **[S1] [Medium] ログイン成功後もマスターパスワードと API 秘密が AuthState に残存する**
  - File: src/ui/auth_state.rs:106-112 / src/ui/login_flow.rs:70-80
  - finish_login 成功時に auth.clear_secrets() を呼ばず、Zeroizing とはいえ平文が最大3600秒生存。
  - Confidence: high
- **[S2] [Medium] Vault 内の平文パスワード／TOTP シークレットがロック時に zeroize されず解放される**
  - File: src/model.rs:218-222 / src/ui/app.rs:131
  - ItemData::Login の password/totp が通常 String、Vault::new() で drop するだけ。
  - Confidence: high
- **[S3] [Medium] write_private の暫定ファイルが既存権限を継承し 0600 保証が穴になる**
  - File: src/private_file.rs:38-45
  - mode(0o600) は新規作成時のみ。既存 .tmp の権限を変更せず rename する。
  - Confidence: high
- **[S4] [Medium] カード番号の表示マスキングが空白区切りに依存し完全 PAN が出る可能性**
  - File: src/ui/render.rs:71 / src/ui/app.rs:279 / src/model.rs:378
  - rsplit(' ') 依存。実データ形式は未確認。
  - Confidence: medium
- **[S5] [Medium] mask_uri が表示のみに適用され検索 haystack は URI 全文**
  - File: src/model.rs:13-27,369
  - トークン等をクエリに入力して項目を特定できる検索オラクル。マスキング方針と矛盾。
  - Confidence: high
- **[S6] [Low] 生成パスワード／パスフレーズが zeroize されず drop される**
  - File: src/ui/state.rs:62-64 / src/ui/app.rs:134
  - `Option<String>` で Debug マスキングのみ。
  - Confidence: high
- **[S7] [Low] クリップボード復元バッファが平文 String で保持される**
  - File: src/ui/clipboard.rs:12,52
  - Confidence: high
- **[S8] [Low] restore_seconds がここでは clamp されず 0 でも次 tick まで秘密が残る**
  - File: src/ui/clipboard.rs:34-45 / src/settings.rs:110
  - 通常経路では clamp されるため影響限定的。
  - Confidence: high
- 却下候補: AuthConfig の derive(Debug) は SecretString が redacted のため漏れではない /
  UnlockError detail も openwarden Error が秘密を保持しない設計のため漏えい経路と認めない。

#### r1-ops-runtime（実行時運用、6件）

- **[O7-a] [Medium] ウィンドウ生成失敗時に終了せず GUI ユーザーへ通知されない**
  - File: src/main.rs:36-47
  - open_window 失敗時に eprintln + return のみ、cx.quit() が無く on_window_closed も発火しない推測。
  - Confidence: medium（ループ残留は推測、emit 自体は明実）
- **[O7-b] [Medium] 権限モードが新規作成時のみ適用され既存ディレクトリ／tmp ファイルが緩いまま**
  - File: src/private_file.rs:29-45
  - DirBuilder::mode/OpenOptions::mode は作成時のみ。既存 0755 ディレクトリ／0644 tmp を是正しない。
    S3 と重複。
  - Confidence: high
- **[O7-c] [Medium] 健全性診断の閾値がサニタイズされず破損設定が虚偽のレポートを生む**
  - File: src/settings.rs:106-113 / src/health.rs:202-209
  - T1/A8 と同一。
  - Confidence: high
- **[O7-d] [Low] Settings にスキーマバージョンがなく形式変更時に設定が黙って既定値へ戻る**
  - File: src/settings.rs:13-15,135-137 / src/cache.rs:56-57
  - キャッシュ側は VERSION/VersionMismatch で検出しており非対称。
  - Confidence: high
- **[O7-e] [Low] rename 後に親ディレクトリを fsync していない（原子性はあるがクラッシュ永続性が未保証）**
  - File: src/private_file.rs:48-52
  - Confidence: high（POSIX 意味論）
- **[O7-f] [Low] idle_lock_due が duration_since のパニックにさらされる**
  - File: src/ui/timing.rs:8-10
  - 通常は Instant の単調性で起きないが、逆行時にパニック。
  - Confidence: high（机制的には明実、実害は推測）

**ラウンド1 小計**: 8エージェント、約57件（重複含む）。
完了エージェント: r1-arch / r1-tests / r1-corr-crypto / r1-sec-input /
r1-corr-state / r1-ops-build / r1-sec-secrets / r1-ops-runtime。
途中終了: r1-ops / r1-security / r1-correctness / r1-ops-retry（分割再起動で回収済み）。
主要重複クラスタ: 設定真実源(A1)、cache未接続(A4/C9-6)、thresholds未クランプ(A8/T1/O7-c)、
ログインレース(A2/C9-1)、login_failed漏れ(S9-05/C9-5)、tmp権限(S3/O7-b)、private_file fsync(O7-e)。

### ラウンド2

使用エージェント: r2-uiux（完了）、r2-threat / r2-data / r2-quality / r2-concurrency（実行中）。

#### r2-uiux（UI/UX / 操作性 / 状態フィードバック、7件）

- **[U1] [High] 設定編集中に Generator へ遷移すると全キーが無効になる（デッドキー）**
  - File: src/ui/keys.rs:189-192 / src/ui/input.rs:90-93
  - editing=Some が残ったまま SetPanel(Generator) → 全キー None、Esc も効かずマウス必須。
  - Remediation: SetPanel 時に editing=None を挟む等。
  - Confidence: high
- **[U2] [High] 無選択時に TOTP が先頭項目へフォールバックし、何をコピーしたか通知しない**
  - File: src/ui/actions.rs:10-24,40-45
  - selected_id=None で y を押すと visible.first() のコードがコピーされ、対象名が出ない。
  - Remediation: 未選択時はコピーせず案内、成功時に対象名を明記。
  - Confidence: high
- **[U3] [Medium] 未生成時のコピーキーが完全に沈黙する**
  - File: src/ui/input.rs:103-112
  - ヘルプは y/Y 案内だが last_* が None のと status 更新なし。TOTP と一貫性欠く。
  - Confidence: high
- **[U4] [Medium] ロック画面のヘルプと実キーが矛盾（モーダル時の Esc／m／r）**
  - File: src/ui/render.rs:65 / src/ui/keys.rs:152-157
  - 編集中 Esc は FinishAuthEdit で終了しない。m/r がヘルプ行に無い。
  - Confidence: high
- **[U5] [Medium] 検索を確定してもクエリが残り一括クリア手段が無い**
  - File: src/ui/vault_view.rs:135-149 / src/ui/keys.rs:251-252
  - finish_search は searching=false のみ。解除は Backspace 連打しかない。
  - Confidence: high
- **[U6] [Medium] 監査パネルに操作ヘルプが無く、戻るつもりの Esc が終了する**
  - File: src/ui/panels.rs:11-66 / src/ui/keys.rs:183-188
  - 見切りはウィンドウ依存の推測。
  - Confidence: medium
- **[U7] [Medium] クリップボード復元完了が通知されない**
  - File: src/ui/actions.rs:44 / src/ui/app.rs:91-94 / src/ui/clipboard.rs:35-44
  - 複数回コピーすると restore は最初の内容のまま期限だけ延びる。
  - Confidence: high

#### r2-concurrency（並行処理 / 非同期 / 時間依存、7件）

- **[P1-a] [High] 認証成功後の復号・vault 変換が UI スレッドを同期実行する**
  - File: src/ui/login_flow.rs:70 / src/auth.rs:229-233 / src/vault_sync.rs:161-163
  - C9-3 と同一。停止時間は vault 規模依存で未測定。
  - Confidence: high
- **[P1-b] [Medium] タイムアウトの race が smol::unblock の KDF を停止できない**
  - File: src/auth.rs:256-261,298-300
  - S9-08 と同一。smol 内部動作が絡むため明示。
  - Confidence: medium
- **[P2-a] [Medium] 1秒 ticker が固定レートでなく累積ドリフトする**
  - File: src/ui/app.rs:69-70
  - `Timer::after(1s)` → 処理 → `Timer::after(1s)` で実間隔が 1秒＋処理時間。
  - Remediation: Timer::at(deadline) または経過時間を evaluate_tick へ渡す。
  - Confidence: high
- **[P2-b] [Medium] ログイン予算が KDF 時間を含み、再試行が同じ失敗を繰り返す**
  - File: src/auth.rs:237,248-261
  - 30秒予算が prelogin+login+sync+KDF 全体。実 KDF 時間は未測定。
  - Confidence: medium
- **[P2-c] [Low] TOTP が未表示でも毎秒 cx.notify() が発火する**
  - File: src/ui/app.rs:85-98
  - GPUI 内部動作が絡む。
  - Confidence: medium
- **[P2-d] [Low] 再コピーで復元 deadline が延長され復元内容は初回のまま固定される**
  - File: src/ui/clipboard.rs:34-44
  - U7 と同一（コード上確定）。
  - Confidence: high
- **[P3] [Low] ログイン future が view 消滅後も完了まで走り続ける**
  - File: src/ui/login_flow.rs:39-52
  - .detach() した future は WeakEntity 消滅後も認証を実行。GPUI executor 挙動が絡む。
  - Confidence: medium
- 補足（発見扱いしない）: Cargo.lock の smol は 2.0.2 のみ、last_activity 更新経路統一、
  cx.spawn の AuthConfig は Send 満たす。

#### r2-data（データ整合性 / シリアライズ / パース、7件）

- **[D1] [Medium] 部分的なネスト JSON が settings 全体のデフォルト化を招く**
  - File: src/settings.rs:14-23 / src/generator.rs:44-45,119-120
  - ネスト型に serde(default) が無く、1フィールド手編集で ParseFailed → load() が
    unwrap_or_default() し server_url/email/thresholds まで既定値に戻る。
  - Confidence: high
- **[D2] [Medium] 同期アイテムの password/totp 置換が健全性診断・TOTP 表示と乖離**
  - File: src/vault_sync.rs:96-106 / src/health.rs:342-345,357-361 / src/ui/actions.rs:31
  - password を空、totp を "available" マーカーに変換 → audit が弱い/再利用を検出不可、
    TOTP 覆盖率が過大、code_at("available") がエラー。C4 と関連。
  - Confidence: high（UI 結果は grep 推測）
- **[D3] [Medium] sanitized() が thresholds をクランプせず監査を無効化しうる**
  - File: src/settings.rs:106-114 / src/health.rs:202-209,438-442
  - T1/A8/O7-c と同一。
  - Confidence: high
- **[D4] [Low] parse_revision が不正な月日を正規化し TZ/時刻を捨てる**
  - File: src/vault_sync.rs:118-140 / src/health.rs:438
  - 2024-02-30 → 03-01、+09:00 を捨てて約9時間ずれ、1970年前が Stale 判定から漏れる。T8 と関連。
  - Confidence: high
- **[D5] [Medium] エントロピー推定のプールが生成ロジックと対応せず過大評価**
  - File: src/health.rs:235-253 / src/generator.rs:19,285-287 / src/ui/panels.rs:108
  - 記号 +33 / 非ASCII +100 だが生成側 SYMBOLS は8文字・非ASCII 無し。判定が矛盾。
  - Confidence: medium
- **[D6] [Low] 同期取り込みが ID 重複を排除しない**
  - File: src/vault_sync.rs:161-164,54-66
  - push のため同一 id が重複行に。openwarden 側の重複除去は未確認。
  - Confidence: medium
- **[D7] [Low] 検索 haystack がマスク表示と別値を持ち URI 内の秘密が検索可能**
  - File: src/model.rs:357-370,13-27
  - S5 と同一。URL 検索の正当性もあり意図確認が必要。
  - Confidence: low-medium

#### r2-threat（脅威モデリング / 信頼境界、7件）

- **[TH1] [High] 連続コピーでクリップボード復元バッファが更新されず先の秘密が復元される**
  - File: src/ui/clipboard.rs:34-45
  - 秘密Aコピー→期限前に秘密Bコピー→B期限後 restore() でバッファに残る秘密Aが書き戻る。
    U7/P2-d と同一。
  - Confidence: high
- **[TH2] [Medium] カード番号のマスキングがスペース区切りに依存し PAN 全体が画面に出る**
  - File: src/ui/app.rs:276-280 / src/model.rs haystacks()
  - S4 と同一。
  - Confidence: high
- **[TH3] [Medium] 監査 Finding が生 URI を保持し Debug 出力でマスクを迂回**
  - File: src/health.rs:37-41,57-59,99-129
  - InsecureUri{uri} は生 URI 保持、マスクは message() 表示時のみ。Finding/Report は derive(Debug)。
  - Remediation: 格納時に mask_uri 済み文字列、または手動 Debug。
  - Confidence: high
- **[TH4] [Medium] revisionDate の年上限がなく悪意サーバー応答で算術オーバーフロー**
  - File: src/vault_sync.rs:118-141
  - "9223372036854775807-01-01" で days_from_civil がオーバーフロー。dev panic / release ラップ。
    openwarden が文字列を渡すかは未確認。
  - Confidence: medium
- **[TH5] [Medium] link-local 遮断が IP リテラルのみで DNS 名／リダイレクトで迂回**
  - File: src/auth.rs:104-125,154-157
  - S9-01 と同一。
  - Confidence: medium
- **[TH6] [Medium] 同期データに完全性検証・監査ログがなく改ざんを検出できない**
  - File: src/vault_sync.rs:43-46,152-165 / src/cache.rs:191-200
  - 署名・ハッシュ・revision 単調性・変更監査ログが皆無。cache の未配線も指摘（A4/C9-6 と重複）。
  - Confidence: high
- **[TH7] [Low] 予測可能な一時文件名と symlink 追随で任意ファイル破壊**
  - File: src/private_file.rs:13-20,37-46
  - 固定 `.<name>.tmp` + create(true).truncate(true) で symlink ターゲットを破壊。
    0700/0600 は symlink 攻撃を防がない。
  - Remediation: ランダム名 + create_new(true) + 可能なら O_NOFOLLOW。
  - Confidence: medium
- 補足（件数外）: login_item の "available" マーカーで code_at が失敗する機能バグ（D2 と同一）。

#### r2-quality（コード品質 / 保守性、7件）

- **[Q1] [Medium] lock() に auth_config() の doc が付いている（コピペ残り）**
  - File: src/ui/app.rs:128-129 / src/ui/login_flow.rs:11
  - Confidence: high
- **[Q2] [High] TOTP は「blank」ではなく "available" マーカーを格納している**
  - File: src/vault_sync.rs:72-73,102-104 / src/model.rs:220
  - doc と実装が矛盾、code_at が base32 として解釈し不正コード/失敗。D2/TH 補足と同一。
  - Confidence: high
- **[Q3] [Medium] カード番号が空だと Finding::NoUri（URI 未設定）と報告される**
  - File: src/health.rs:420-422
  - C7 と同一。
  - Confidence: high
- **[Q4] [Medium] BackspaceSearch と BackspaceQuery が同一処理＋片方の doc が誤り**
  - File: src/ui/keys.rs:68-73 / src/ui/input.rs:78-89
  - Confidence: high
- **[Q5] [Low] ヘルプ文言に復元秒数 30 がハードコードされ設定値と乖離する**
  - File: src/ui/panels.rs:152-154 / src/settings.rs:31,110
  - Confidence: high
- **[Q6] [Medium] sanitized() が doc と異なり監査閾値をクランプしない**
  - File: src/settings.rs:102-113 / src/ui/logic.rs:43-67
  - T1/A8/O7-c/D3 と同一。
  - Confidence: high
- **[Q7] [Low] テスト属性の表記ゆれと広範な #[allow]**
  - File: src/ui/timing.rs:45-50,68,85 他多数
  - T13 と同一。
  - Confidence: medium
- 補足: A3 との重複を避け visible_items 等の重複は意図的に除外。

**ラウンド2 小計**: 5エージェント、35件（重複含む）。
新規の主要クラスタ: デッドキー(U1)、TOTP 無選択フォールバック(U2)、ticker ドリフト(P2-a)、
部分的ネスト JSON(D1)、同期マーカー乖離(D2/Q2/TH補足)、監査FindingのDebug漏れ(TH3)、
年オーバーフロー(TH4)、symlink 追随(TH7)。
既知クラスとの重複: thresholds(T1/A8/O7-c/D3/Q6)、clipboard復元(U7/P2-d/TH1)、
カードPAN(S4/TH2)、URIマスク(S5/D7)、link-local(S9-01/TH5)、cache未接続(A4/C9-6/TH6)。

### ラウンド3

使用エージェント: r3-docs / r3-supply / r3-i18n / r3-errors / r3-regression（いずれも完了）。

#### r3-docs（ドキュメント形式 / 整合性、5件）

- **[DOC1] [Medium] README の cd 例がリポジトリルート基準で失敗し内部作業階層も露出**
  - File: README.md:91
  - `cd work/bitwarden-gpui-poc` はリポジトリ内に存在せず（glob 確認）、コピペで失敗。
    ローカル固有階層 `default-workspace/work/` も公開想定 README に載っている。
  - Remediation: cd 行を削除するかリポジトリ直下実行手順に修正。
  - Confidence: high
- **[DOC2] [Low] ADR 索引が同ディレクトリの log.md を列挙していない**
  - File: docs/adr/index.md:3-6
  - Confidence: high
- **[DOC3] [Low] README のライセンス節に無関係なドキュメント導線が混在**
  - File: README.md:116-121
  - Confidence: high
- **[DOC4] [Info] stale_after の算定基準が ADR とレビューレポートで不一致**
  - File: docs/review-report.md:17 / docs/adr/adr-20261116-openwarden-integration.md:17
  - ADR は verified 基準、レポートは generated 基準。
  - Confidence: high
- **[DOC5] [Low] README 行118が markdownlint MD013 閾値を超える可能性（推測）**
  - File: README.md:118
  - markdownlint は read-only のため未検証。
  - Confidence: low

#### r3-supply（依存関係 / サプライチェーン、6件）

- **[DEP1] [Low] Dependabot / Renovate の設定が無い**
  - File: .github/ 全体（ci.yml のみ）
  - cargo audit は有効だが自動修正 PR が届かず手動依存。
  - Confidence: high
- **[DEP2] [Low] cargo deny によるライセンス／重複バージョンのゲートが無い**
  - File: .github/workflows/ci.yml:23-24 / docs/review-report.md:70-73
  - AGPL 配布時の通知義務対応が属人化。
  - Confidence: high（設定欠如）/ medium（法的義務詳細）
- **[DEP3] [Info] getrandom が 0.2 / 0.3 / 0.4 の3系統で共存**
  - File: Cargo.lock:1996-2033,4651
  - Linux ネイティブでは実害なし（推測）、WASM 対応時に制約。
  - Confidence: high（共存事実）/ low（実害）
- **[DEP4] [Info] 暗号系クレートのメジャー混在（sha2 0.10/0.11 ほか）**
  - File: Cargo.lock:6117-6136,101-121,918-936
  - 直接依存 sha2 0.11.1 は openwarden と一致。バイナリサイズ/ビルド時間増。
  - Confidence: high
- **[DEP5] [Info] Cargo.lock に rust-version が無く MSRV 整合性を静的確認できない**
  - File: Cargo.lock:1-3 / Cargo.toml:5
  - 検証手段は Rust 1.88 での実ビルドに限られる。
  - Confidence: high（記載なし）/ medium（CI 提案）
- **[DEP6] [Info] ネイティブ暗号実装（aws-lc / cmake）の利用が設計記録に無い**
  - File: Cargo.lock:546-566 / ADR:69-73
  - aws-lc-sys 0.47.0 が cc/cmake 経由で C ビルド。ADR に記載なし。
  - Confidence: medium
- 確認済み: 直接依存9件の lock 解決バージョン整合、git/path source 0件、yanked 痕跡なし、
  build.rs 0件、proc-macro は推移のみ、license と LICENSE 本文整合。

#### r3-i18n（日本語文言 / 一貫性、7件）

- **[I1] [Medium] Enter/Esc のヘルプが画面ごとに文言・表記とも不統一**
  - File: src/ui/app.rs:45-46 / src/ui/render.rs:65 / src/ui/panels.rs:237 / src/ui/login_flow.rs:120
  - Confidence: high
- **[I2] [Medium] TOTP 表示エラーが「コード生成失敗」で原因が分からない**
  - File: src/ui/totp_state.rs:48-51 / src/totp.rs:96-100
  - TotpError 側の具体的メッセージを捨てている。Q2/D2 と関連。
  - Confidence: high
- **[I3] [Medium] 設定画面の「ログイン制限」が何を制限するか分からない**
  - File: src/ui/panels.rs:225 / README.md:47,134
  - login_timeout_seconds を「ログイン制限」と表示、README は「タイムアウト」。
  - Confidence: high
- **[I4] [Low] 認証エラー文に英語ネットワーク用語が混在**
  - File: src/auth.rs:57-58
  - loopback / link-local がそのまま出る。
  - Confidence: medium
- **[I5] [Low] 同じ機能が「モック」と「デモ」で呼び分けされている**
  - File: src/ui/app.rs:45-46,145 / README.md:45,61 / src/ui/keys.rs:46
  - Confidence: medium
- **[I6] [Low] README で passphrase とパスフレーズが混在**
  - File: README.md:17,27,80,81 / src/ui/panels.rs:120,139
  - Confidence: high
- **[I7] [Low] パスフレーズ区切りに Rust のデバッグ表記が露出**
  - File: src/ui/panels.rs:144-146
  - `{:?}` で `"-"` と引用符付き表示、未設定時 `""` で「区切りなし」と分からない。
  - Confidence: high

#### r3-errors（エラー処理の網羅性、7件）

- **[E1] [High] 一時ファイルの後始末が write/flush 失敗時に欠落**
  - File: src/private_file.rs:43-57
  - rename 失敗時のみ tmp 削除。write_all/flush/sync_all の早期 return では
    `.sync-cache.json.tmp` に平文 JSON が残存。
  - Remediation: RAII ガードで全エラーパス削除。
  - Confidence: high
- **[E2] [Medium] クリップボード復元が元データ不在時に空文字列で上書き**
  - File: src/ui/clipboard.rs:36-53
  - restore=None のとき unwrap_or_default() が空文字を書き込み元内容を破壊。
  - Confidence: high
- **[E3] [Medium] フォルダ名1件の復号失敗でボールト全体を破棄（部分成功の扱い）**
  - File: src/vault_sync.rs:55-57
  - folder_name の Err を ? で即返し。名前 None は "(名前なし)" で継続するのと一貫しない。
  - Confidence: high
- **[E4] [Medium] 再試行不能な復号失敗にも「r で再試行」を案内**
  - File: src/ui/login_flow.rs:81-84
  - UnlockError 系は認証情報変更なしでは成功しないのに再試行ループに誘導。
  - Confidence: high
- **[E5] [Medium] エラー型の Source チェーン欠如・文字列化・定義分散**
  - File: src/auth.rs:182-190 / src/vault_sync.rs:45 /
    src/cache.rs:71,88,96,105 / src/totp.rs:117
  - 6ファイルに分散、source() 未実装、String 化でチェーン切断。
  - Confidence: medium
- **[E6] [Low] TOTP エラーが詳細パネルで「コード生成失敗」に平坦化**
  - File: src/ui/totp_state.rs:48-51 / src/ui/actions.rs:33-35
  - I2 と同一。copy_totp は error.message() を表示するのに画面別で別文言。
  - Confidence: high
- **[E7] [Low] 非同期ログイン結果の UI 適用失敗が .ok() で破棄**
  - File: src/ui/login_flow.rs:43-48
  - GPUI update が Err を返す条件は未検証。
  - Confidence: medium
- 補足: cache::load() の .ok() もあるが本番・テスト双方から未呼び出しのため報告せず。

#### r3-regression（テストが固定した挙動 / 回帰リスク、7件）

- **[R1] [High] TOTP の等価性テストが「コードを比較しない」ことを検証していない**
  - File: src/totp_tests.rs:132-145 / src/totp.rs:22-26
  - 同一 secret の比較のみで、異なる secret で同じ period/remaining の等価性を検証せず。
    code 値比較を回帰させても検出不能。
  - Confidence: high
- **[R2] [Medium] next_index_clamps_at_the_ends が下端しか通っていない**
  - File: src/ui/vault_view.rs:177-187（実装 98-109）
  - 上限クランプ未検証。
  - Confidence: high
- **[R3] [Medium] generator_keys_toggle_options_and_clamp_lengths が clamp を検証していない**
  - File: src/ui/keys_tests.rs:86-105（実装 src/ui/keys.rs:18-25）
  - ±1 ステップのみで境界 128/20/4/2 を通らない。
  - Confidence: high
- **[R4] [Medium] word_list_is_clean_and_prefix_free_enough が prefix を検証していない**
  - File: src/generator_tests.rs:144-154
  - 重複・空・小文字・長さのみ、starts_with 検査なし。C1 と関連。
  - Confidence: medium
- **[R5] [Medium] invalidate() の再計算強制が同一コードのため検出不能**
  - File: src/ui/totp_state.rs:69-85（実装 28-30,41-52）
  - R1 の PartialEq 問題と相まってキャッシュ残存を検出できない。
  - Confidence: high
- **[R6] [Medium] クリップボードの「初回のみ保存／復元」分岐が未テスト**
  - File: src/ui/clipboard.rs:34-55,58-82
  - E2/TH1 と関連。GPUI App が必要で直接テストしにくい。
  - Confidence: high
- **[R7] [Low] AuthState の ServerUrl/Email 無視分岐が未テスト**
  - File: src/ui/auth_state.rs:79-102,127-159
  - Confidence: high

**ラウンド3 小計**: 5エージェント、32件（重複含む）。
新規主要クラスタ: README cd 例失敗(DOC1)、Dependabot/cargo deny 欠如(DEP1/DEP2)、
一時ファイル残存(E1)、クリップボード空上書き(E2)、部分成功の破棄(E3)、再試行不能案内(E4)、
エラー型の分散(E5)、文言不統一(I1〜I7)、テスト主張と検証の乖離(R1〜R5)。
既知重複: TOTP 平坦化(I2/E6)、TOTP マーカー(Q2/D2)、prefix(C1/R4)、clipboard(U7/P2-d/TH1/E2/R6)。

### ラウンド4

使用エージェント: r4-fs（完了）、r4-crypto / r4-invariants / r4-render / r4-release（実行中）。

#### r4-fs（ファイルシステム / パス / 永続化、4件）

- **[FS1] [Medium] 固定の temp ファイル名による同時書き込み競合**
  - File: src/private_file.rs:37,39,52
  - 2インスタンス同時保存で同じ temp を truncate、先の rename が temp を消し後の rename が
    NotFound 失敗または内容混在。単一インスタンス化・ロックなし。E1（クラッシュ残存）とは別。
  - Remediation: temp 名に PID/乱数、またはロック／単一インスタンス化。
  - Confidence: high
- **[FS2] [Medium] 読み込み前にファイルサイズ上限が無く巨大 JSON で OOM**
  - File: src/settings.rs:128 / src/cache.rs:153
  - read_to_string / read が無制限に展開。D1 の前段の問題。
  - Confidence: high
- **[FS3] [Medium] 破損設定ファイルの退避・回復経路が無く次回保存で失われる**
  - File: src/settings.rs:141-143,150-154
  - ParseFailed/ReadFailed でも unwrap_or_default のみ、次回 save で上書きし回復不能。
  - Confidence: high
- **[FS4] [Low] 同期キャッシュが XDG_CACHE_HOME ではなく config_dir に設定と同居**
  - File: src/cache.rs:109-111 / src/settings.rs:116-119
  - dotfiles 管理・バックアップ対象に取り込まれるリスク。機能バグではない。
  - Confidence: medium

#### r4-release（リリース準備 / オンボーディング、6件）

- **[REL1] [Medium] 実サーバー接続が未検証であることが README に伝わらない**
  - File: README.md:44-45,123-137 / CHANGELOG.md:741 / review-report.md:104
  - 実ログイン可能なように読めるが実サーバー接続テストは未実施と裏側にのみ記載。
  - Confidence: high
- **[REL2] [Medium] バージョン番号のインフレと CHANGELOG 粒度**
  - File: CHANGELOG.md:7-23 / Cargo.toml:3 / ci.yml:8
  - 0.1.1〜0.1.101 が全て同日、大半がドキュメント微修正。タグ乱立は推測。
  - Confidence: high（差分は明確）/ タグ乱立は推測
- **[REL3] [Medium] Vaultwarden 接続の初期設定手順が無い**
  - File: README.md:3,59-60,86-104
  - Client ID/Secret の取得先、URL 形式、モックとの違いが無く初回ログインに到達できない。
  - Confidence: medium
- **[REL4] [Low] CI が green であることの証明・バッジへの導線が無い**
  - File: README.md:106-114 / review-report.md:91-104
  - リモート未設定でバッジを作れない事情はある。
  - Confidence: medium
- **[REL5] [Low] コントリビューション / issue・PR の導線が無い**
  - File: README.md:120-121
  - CONTRIBUTING/COPYRIGHT/NOTICE/.github テンプレートは存在せず（glob 確認）。
  - Confidence: high
- **[REL6] [Low] ビルド時のシステム依存・ツールチェーン導入方法が未記載**
  - File: README.md:86-104
  - apt 開発パッケージと mise による Rust 導入例が無い。必要パッケージの特定は未確認。
  - Confidence: low

#### r4-crypto（暗号プロトコル / 乱数 / KDF、3件）

- **[CR1] [Low] SSH 公開鍵の fingerprint が未検証のまま表示される**
  - File: src/model.rs:159-160 / src/ui/app.rs:282 / src/ui/mock.rs:111
  - 提供値をそのまま表示、公開鍵との整合性・署名検証なし。現状モック経路のみ。
  - Confidence: medium
- **[CR2] [Low] パスフレーズ語選択のサイレントフォールバックがエントロピー保証を隠す**
  - File: src/generator.rs:156-157
  - unwrap_or("word") は到達不能だが不変条件が暗黙化。WORDS.len() as u16 は 65536 語以上でラップ。
  - Confidence: high
- **[CR3] [Info] sha2 直接依存が未使用で推移依存と重複**
  - File: Cargo.toml:26
  - src/ 全体で sha2 参照なし、openwarden が推移依存で保持。
  - Confidence: high
- 確認して誤検知除外: email 小文字化(openwarden normalize_email)、KDF 政策上下限、
  prelogin/session 不整合、Base32 処理、rejection sampling。暗号本体に新規欠陥なし。

#### r4-invariants（状態の不変条件、4件）

- **[INV1] [Medium] パネル切替が編集中／検索中フラグをクリアせず直積不変が破れる**
  - File: src/ui/input.rs:90-93 / src/ui/keys.rs:173-180,189-192 / src/ui/render.rs:242-279
  - マウスの SetPanel が panel のみ更新。Generator での editing_settings 全キー None（U1）に加え、
    searching=true 残存で全パネルのキーが検索文字として吸われる（U5 の query 残存とは別件）。
  - Remediation: SetPanel 共通化で editing=None かつ searching=false を強制。
  - Confidence: high
- **[INV2] [Medium] アンロック処理が編集・検索・選択以外の表示状態をクリアせず矛盾状態を作れる**
  - File: src/ui/login_flow.rs:109-124,70-87 / src/ui/app.rs:129-147
  - lock() は全リセットするが unlock_mock/finish_login は vault/panel/screen/selected_id のみ。
    Screen::Unlocked かつ auth.field=Some / editing=Some のデッド状態が残存。
  - Confidence: medium（到達性は限定的）
- **[INV3] [Low] 選択解除経路ごとに scroll offset の扱いが一貫しない**
  - File: src/ui/app.rs:201-204 / src/ui/input.rs:115-125 / src/ui/vault_view.rs:139-149
  - cycle_filter/revalidate は先頭スクロールするが CycleSort/StartSearch/push/pop_query はしない。
  - Confidence: medium
- **[INV4] [Low] dangling な selected_id のとき ToggleFavorite だけが先頭項目を書き換える**
  - File: src/ui/app.rs:208-225,233-241 / src/ui/actions.rs:10-25
  - 現行 UI からは dangling に到達しないため推測。U2 とは書き込みの有無で別件。
  - Confidence: low

#### r4-render（GPUI 描画 / イベント、5件）

- **[UI1] [Medium] 修飾キーが無視され Ctrl/Cmd ショートカットが通常キーとして扱われる**
  - File: src/ui/input.rs:19-30 / src/ui/keys.rs:146-170
  - KeyContext に modifiers が無く keystroke.key のみ判定。Ctrl+C が "c"（設定遷移）と解釈され
    gpui-base の Copy アクションと競合、Ctrl+V で 'v' 挿入、Ctrl+L でロック誘発。
  - Remediation: modifiers を追加し control/platform/alt 付きを除外。
  - Confidence: high
- **[UI2] [Medium] 文字入力が keystroke.key を参照し key_char を落とす（IME／非US配列）**
  - File: src/ui/input.rs:22 / src/ui/keys.rs:147-155
  - gpui-pre 0.3.12 の Keystroke は key と key_char を分保持。日本語 IME 確定文字や
    Option+S の "ß" が入力されない。
  - Remediation: 挿入系で key_char を優先。
  - Confidence: high（Keystroke 定義をローカル確認）
- **[UI3] [Medium] フォーカスが起動時のみ設定され Tab で外れるとキーボード操作が復帰不能**
  - File: src/main.rs:38-39 / src/ui/app.rs:56 / src/ui/render.rs:328-329
  - focus_handle は既定 tab_stop: false。Tab でフォーカスが移動するとルートの on_key_down が届かず
    Esc 含む全キーが無効に。
  - Confidence: medium（GPUI フォーカス走査に依存、前提事実はソース確認）
- **[UI4] [Low] 生成／設定パネルにスクロールが無くウィンドウ縮小時に内容がクリップ**
  - File: src/ui/panels.rs:105-156,190-239
  - 固定行数 .child() のみで overflow 指定なし。一覧だけ uniform_list を使い不整合。
  - Confidence: high
- **[UI5] [Low] 一覧内容変更時にスクロール位置がリセットされない経路がある**
  - File: src/ui/input.rs:115-125 / src/ui/vault_view.rs:140-149
  - INV3 と同一。GPUI クランプ動作が絡むため推測含み。
  - Confidence: medium
- 補足: render エージェントがディレクトリ確認のため読み取り専用 ls を1回実行（自己申告、
  ファイル変更・ビルド・テスト・git 操作なし）。指摘はコード根拠付き。

### ラウンド5

使用エージェント: r5-threads（完了）、r5-validity / r5-inputs / r5-api / r5-gaps（実行中）。

#### r5-threads（スレッド安全性 / 並列実行、1件）

- **[TH1] [Medium] write_private の決定的一時ファイル名により同一パスへの並行書き込みが競合**
  - File: src/private_file.rs:14-20,37-52
  - FS1 と同一。現状 UI スレッド経由のみで顕在化しない（実害は推測）。
  - Confidence: medium
- 確認: static/OnceLock/lazy_static/Mutex/RwLock/Atomic*/set_var/set_current_dir/
  thread::spawn は src 全体に無し、
  テスト間の環境変数・cwd・乱数シード共有なし、cx.spawn クロージャは Send 適合。
  データ競合パターンなし（--test-threads 差分は read-only のため未検証）。

#### r5-inputs（入力エッジケース / 境界値、6件）

- **[ED1] [Low] 検索が Unicode 正規化を行わず NFC/NFD・全角/半角の等価文字が一致しない**
  - File: src/model.rs:399-403,568-575,650-665
  - to_lowercase() は正規化しないため "café"(NFC) と "cafe\u{0301}"(NFD)、"ABC" と "ＡＢＣ" が不一致。
    duplicate_names のキー生成も同様。既知の「小文字前提」とは別の未正規化の問題。
  - Confidence: high
- **[ED2] [Low] 空白のみの client_secret / master_password が検証を通過する**
  - File: src/auth.rs:142,151（対比 136-146）
  - 他フィールドは trim().is_empty() だが秘密は is_empty() のみ。空白のみで validate_config が Ok。
  - Confidence: high
- **[ED3] [Low] メール検証がゼロ幅文字・RTL オーバーライドを許容する**
  - File: src/auth.rs:82-99
  - is_whitespace は U+200B/U+202E/U+FEFF（Cf 系）を通す。表示と識別子の食い違い。S9-03 とは別カテゴリ。
  - Confidence: high
- **[ED4] [Low] settings.json の型混乱が 1 フィールドで全設定を失わせる**
  - File: src/settings.rs:135-137,141-143
  - 型違反/過度なネストで ParseFailed → unwrap_or_default で全破棄。D1 と近いが型混在を含む。
  - Confidence: high
- **[ED5] [Low] sanitized() が Thresholds をクランプせず極端な閾値が残る**
  - File: src/settings.rs:106-114
  - 既知 thresholds クラス（T1/A8/O7-c/D3/Q6）。
  - Confidence: high
- **[ED6] [Low] 空名・空白のみの複数項目が「重複名」として誤検出される**
  - File: src/model.rs:650-665
  - trim().to_lowercase() キーが "" になりグループ化。Unnamed Finding と二重ノイズ。
  - Confidence: high
- 補足: otpauth 不正パラメータは openwarden 側実装で独自経路なし。

#### r5-gaps（全体盲点、7件）

- **[G1] [High] 非同期ログインに世代管理がなく古い結果が vault を上書きする**
  - File: src/ui/login_flow.rs:39-52,61-80 / src/ui/input.rs:38-40
  - A2/C9-1 と同一。認証待ち中に m/l/Enter/r が受け付けられ競合。
  - Confidence: high（制御フローは確定、再現実行は未実施）
- **[G2] [High] 実ログイン後は監査レポートが作られず作ってもパスワード検査が黙ってスキップされる**
  - File: src/ui/login_flow.rs:70-86 / src/ui/app.rs:287-293 /
    src/health.rs:405-415 / src/ui/keys.rs:248
  - C9-2 と一部重複（refresh_audit 欠落）が、実 vault の password が常に空で
    audit がスキップされ「問題なし」と誤信させる点が新規。
  - Confidence: high
- **[G3] [Medium] ヘッダー[監査]ボタンが一覧表示のままキーだけ監査パネル扱いにして操作を死なせる**
  - File: src/ui/render.rs:249-260,302-305 / src/ui/keys.rs:183-188
  - audit_report=None でも SetPanel(Audit) を発行。描画は一覧へフォールバックするが
    KeyContext.panel は Audit のままで全 navigational キーが None。
  - Confidence: high
- **[G4] [Medium] 設定編集中の Esc が「終了」ではなく「中途入力の確定」として扱われる**
  - File: src/ui/keys.rs:216-223 / src/ui/input.rs:57-61 / README.md:73
  - FinishSettingsEdit が sync_settings_from_ui() を呼び、w 未押しでも中途文字列が反映。
    README は Esc=終了とのみ。U1 とは別のメンタルモデルズレ。
  - Confidence: medium-high
- **[G5] [Low] 一覧の選択行が背景色のみで示されスクリーンリーダーと色覚の両方で判別不能**
  - File: src/ui/render.rs:85-90 / src/ui/panels.rs:248-261
  - 他情報はテキスト化されているのに選択状態だけ抜け落ちている。
  - Confidence: medium（GPUI accessibility API の有無は未確認）
- **[G6] [Low] ログインタイムアウト時に KDF の blocking タスクが残存し連続リトライで蓄積する可能性**
  - File: src/auth.rs:256-262,294-300 / src/ui/login_flow.rs:38-52
  - P1-b/S9-08/G6 と同一。smol のキャンセル挙動は推測で実行検証していない。
  - Confidence: low
- **[G7] [Medium] 実 vault のパスワードを取り出す経路が無く PoC の暗号層→UI が未検証**
  - File: src/vault_sync.rs:96-106 / src/ui/keys.rs:247 /
    src/ui/actions.rs:10-38 / README.md:48-50
  - password は常に空、y は TOTP のみ。復号して UI に渡す操作が存在しない。
    API key の権限範囲・専用アカウント利用の倫理的注意も ADR/README に無い。
  - Confidence: medium-high（欠如は確定、PoC 目的上の要否は解釈を含む）

#### r5-validity（既知指摘の妥当性逆検証、7件）

- **[V1] [Info] SSH 公開鍵／fingerprint の Debug 生出力は意図された公開データ**
  - File: src/model.rs:198-205
  - 判定: 誤検知。public_key/fingerprint は公開情報、実際の秘密 private_key は [redacted] 済み。
  - Confidence: high
- **[V2] [Info] client_id が Zeroizing でない／ロック時に保持されるのは設計意図**
  - File: src/ui/auth_state.rs:18,104-112 / src/ui/render.rs:39-44
  - 判定: 誤検知。client_id は公開 ID、client_secret/master_password は Zeroizing で担保。
  - Confidence: high
- **[V3] [Low] Zeroizing の「再確保前コピー」は既知の型制約であり過大評価**
  - File: src/ui/auth_state.rs:12-14 / docs/review-report.md:85-86
  - 判定: 既に対処済み（既知制約）。Vec/String ベースでは回避不可、作り替えは過剰修正。
  - Confidence: high
- **[V4] [Low] クリップボード復元バッファが平文 String なのはライフサイクル上安全**
  - File: src/ui/clipboard.rs:12,48-55 / src/ui/app.rs:130
  - 判定: 誤検知／既に対処済み。restore はコピー「前」の元内容で秘密ではない。
    lock() が必ず restore() を呼ぶ。※ただし E2/TH1 の連続コピー問題は別件で有効。
  - Confidence: high
- **[V5] [Info] unwrap_or("") は直下の空文字検証で実害なし**
  - File: src/auth.rs:218-225
  - 判定: 誤検知。直後に is_empty() 検査あり。
  - Confidence: high
- **[V6] [Medium] カード詳細の rsplit(' ') は非スペース区切りで完全 PAN を表示しうる**
  - File: src/ui/app.rs:276-280 / src/model.rs:376-380 / src/model_tests.rs:285
  - 判定: 実害あり（潜在／到達経路未確認）。S4/TH2 の裏付け。
  - Confidence: medium
- **[V7] [Medium] Finding::InsecureUri の Debug は生 URI 保持でマスク別経路漏れ**
  - File: src/health.rs:19-20,37-41,57-59 / src/ui/panels.rs:62
  - 判定: 実害あり（潜在／出力経路未確認）。TH3 の裏付け。構造化ログ追加時に即漏れる。
  - Confidence: medium
- 総括: 誤検知/過大評価/対処済み5件、見落とし裏付け2件。

#### r5-api（外部 API の誤用 / 契約の取り違え、2件）

- **[API1] [High] openwarden の has_totp フラグを TOTP シークレットとして downstream に渡している**
  - File: src/vault_sync.rs:101-105 / src/totp.rs:114-117 /
    src/actions.rs:24-37 / src/ui/app.rs:261-265
  - has_totp は真偽値、generate() は復号済み文字列を要求。"available" マーカーで
    実ログイン後の code_at/copy_totp が常に失敗、password も空で audit が機能しない。
    D2/Q2/G2 と同一の取り違えだが API 契約の観点から再確認。
  - Confidence: high
- **[API2] [Medium] link-local 検証が設定 URL 文字列のみで openwarden 側の HTTP 計算を考慮していない**
  - File: src/auth.rs:104-125,154-158,277-293
  - リダイレクト追従・DNS 解決先を制御せず、検証スコープが到達先に及ばない。S9-01/TH5 と同一。
  - Confidence: low（openwarden のリダイレクト挙動は推測）

**ラウンド5 小計**: 5エージェント、23件（重複含む）。
新規主要クラスタ: Unicode 未正規化(ED1)、空白のみ秘密(ED2)、Cf文字(ED3)、
監査ボタン状態不整合(G3)、Esc セマンティクス(G4)、アクセシビリティ(G5)、
PoC ラウンドトリップ未検証(G7)。
妥当性逆検証: 誤検知/過大評価/対処済み5件(V1〜V5)を却下、見落とし裏付け2件(V6/V7)。
全5ラウンド合計: 25エージェント、約169件（重複・却下含む）。

**ラウンド4 小計**: 5エージェント、22件（重複含む）。
新規主要クラスタ: temp 名競合(FS1)、ファイルサイズ上限欠如(FS2)、破損設定の回復経路(FS3)、
実接続未検証の伝達(REL1)、Vaultwarden 初期設定手順(REL3)、Ctrl/IME キー処理(UI1/UI2)、
フォーカス復帰不能(UI3)、パネル不変(INV1/INV2)。
暗号本体に新規欠陥なし（CR3 の sha2 未使用は軽微）。既知重複: scroll(INV3/UI5)、
SetPanel(U1/INV1)、TOTP マーカー、権限/tmp/スキーマ(S3/TH7/E1/O7-d 等)。

## 統合結果（ラウンド6）

### 実施内容

5ラウンド（25エージェント、約169件の生指摘）を横断し、同一箇所・同一原因の
指摘をクラスタ化して統合した。さらに r5-validity の逆検証と、
親エージェントによる Runtime Proof（現行ソースの直接確認）で妥当性を評価した。

### 妥当性評価

却下（r5-validity により誤検知／過大評価／既に対処済みと判定）:

- V1: SSH 公開鍵・fingerprint の Debug 生出力 → 公開情報であり private_key は redacted 済み
- V2: client_id が Zeroizing でない → 公開 ID であり設計意図、client_secret 等は担保済み
- V3: Zeroizing の再確保前コピー → 既知の型制約として review-report に記録済み
- V4: クリップボード復元バッファが平文 String → コピー前の元内容で秘密ではない
  （※連続コピーで先の秘密が復元される E2/TH1 は別件として有効）
- V5: unwrap_or("") → 直下の is_empty() 検査で実害なし

Runtime Proof（親が現行ソースを直接確認し、指摘を裏付け）:

- vault_sync.rs:101-105: password が空文字、totp が "available" マーカー → D2/Q2/API1/G2 裏付け
- settings.rs:106-114: sanitized() に thresholds の代入なし → T1/A8/O7-c/D3/Q6/ED5 裏付け
- health.rs:405-415: `if !password.is_empty()` ガード → 空パスワードが監査除外される（C6/G2 裏付け）
- totp_state.rs:46-51: エラー表示が "コード生成失敗" 固定 → I2/E6 裏付け
- private_file.rs:14-20: 一時名が `.{name}.tmp` 固定 → FS1/TH1/S3/TH7 裏付け
- input.rs:90-93: SetPanel が panel のみ更新 → U1/INV1 裏付け

### 主要重複クラスタ（吸収済み）

| 統合項目 | 元指摘 ID | 件数 |
| --- | --- | --- |
| 同期マーカーによる秘密欠落 | D2, Q2, API1, G2, C4, TH 補足 | 6 |
| 監査閾値の未クランプ | T1, A8, O7-c, D3, Q6, ED5 | 6 |
| ログイン非同期レース／世代管理欠如 | A2, C9-1, G1, P3, E7 | 5 |
| 一時ファイル（権限・競合・残存・symlink） | S3, O7-b, TH7, E1, FS1, TH1, O7-e | 7 |
| クリップボード連続コピー | U7, P2-d, TH1, E2, R6 | 5 |
| 設定真実源の二重状態 | A1, INV2 | 2 |
| パネル切替フラグ残存／デッドキー | U1, INV1, U4, G4 | 4 |
| cache 未配線 | A4, C9-6, C9-7, TH6 | 4 |
| TOTP エラー平坦化 | I2, E6, C8 | 3 |
| カード PAN マスキング | S4, TH2, V6 | 3 |
| 監査 Finding の生 URI | TH3, V7 | 2 |
| link-local 検証の迂回 | S9-01, TH5, API2 | 3 |
| 単語リスト prefix | C1, R4 | 2 |
| 日付パース（月日・TZ・オーバーフロー） | T8, D4, TH4 | 3 |
| テスト属性混在 | T13, Q7 | 2 |
| スクロール位置の一貫性 | INV3, UI5 | 2 |

### 成果物

統合後の対応項目をリポジトリルートの `todo.md` へ追加した（OKF 形式、
優先度 高／中／低）。詳細な生指摘は本ファイルのラウンド1〜5を参照。
