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
  at: "2026-11-17T23:18:32+09:00"
status: current
stale_after: "2027-05-17T21:04:43+09:00"
---

## 進行中

なし。クロスレビューは修正を行わない（read-only）方針で実施した。

## 未着手

### 優先度: 高

- [ ] 実ログイン時に同期マーカーではなく復号済みシークレットをモデルへ渡す
  - 根拠: D2 / Q2 / API1 / G2（Runtime Proof 裏付け）
  - File: src/vault_sync.rs:101-105, src/totp.rs:114-117, src/ui/actions.rs:24-37
  - 現状: password が空文字、totp が `"available"` マーカー。TOTP コピーが常に失敗し、
    監査もパスワードを検査対象外として扱うため「問題なし」と誤信させる。
  - 受け入れ条件: 実ログイン後に TOTP コピーが成功し、監査サマリーがパスワード検査
    対象外件数を明示する（またはオンデマンド復号で実際に検査する）。
- [ ] 設定の真実源を一本化する
  - 根拠: A1（Runtime Proof 裏付け）
  - File: src/ui/app.rs:12-13,40-43,134, src/ui/actions.rs:53-63, src/ui/login_flow.rs:89-106
  - 現状: `self.server_url/email` と `settings` の双方向ミラー。ロック画面の編集が
    `w` 保存なしで失われ、lock() が generator を settings から再構築し巻き戻る。
  - 受け入れ条件: Settings を単一真実源にするか、全編集経路が通る単一更新コマンドを設ける。
- [ ] パネル切替時に editing/searching フラグをクリアしデッドキーを解消する
  - 根拠: U1 / INV1（Runtime Proof 裏付け）/ U4 / G4
  - File: src/ui/input.rs:90-93, src/ui/keys.rs:189-192, src/ui/render.rs:242-279
  - 現状: 設定編集中にマウスで他パネルへ移ると全キーが無効になり、
    searching 残存で他パネルのキーが検索文字として吸われる。
  - 受け入れ条件: SetPanel を共通遷移へ集約し editing=None / searching=false を強制。
    Esc のセマンティクス（確定 vs キャンセル）を README と画面に明記。
- [ ] 修飾キーと IME 入力を正しく扱う
  - 根拠: UI1 / UI2
  - File: src/ui/input.rs:19-30, src/ui/keys.rs:146-170
  - 現状: KeyContext に modifiers が無く Ctrl+C が "c"（設定遷移）と解釈され
    gpui-base の Copy と競合。key_char を落とすため日本語 IME 確定文字が入力されない。
  - 受け入れ条件: control/platform/alt 付きキーを判定から除外し、挿入系で
    keystroke.key_char を優先する。

### 優先度: 中

- [ ] クリップボードの連続コピー時の復元バッファを修正する
  - 根拠: U7 / P2-d / E2 / R6（V4 は誤検知だが連続コピーは別件で有効）
  - File: src/ui/clipboard.rs:34-55, src/ui/actions.rs:44, src/ui/app.rs:91-94
  - 現状: 2回目以降 restore を保存せず期限だけ延長するため、先の秘密が復元され、
    元データ不在時は空文字で上書きする。復元完了も通知されない。
  - 受け入れ条件: 毎回現在のクリップボードを保存するか単一秘密のみ追跡し、
    restore=None なら上書きしない。復元時にステータス更新。
- [ ] ヘッダー[監査]ボタンとキー状態を整合させる
  - 根拠: G3 / C9-2
  - File: src/ui/render.rs:249-260,302-305, src/ui/keys.rs:183-188, src/ui/login_flow.rs:70-86
  - 現状: audit_report=None でも SetPanel(Audit) が発行され、描画は一覧へ
    フォールバックするが KeyContext.panel は Audit のままで操作が死ぬ。
    実ログインは refresh_audit() を呼ばない。
  - 受け入れ条件: レポート存在時のみ遷移、またはフォールバック時に panel を Vault へ戻す。
- [ ] unlock_and_import を UI スレッドからオフロードする
  - 根拠: C9-3 / P1-a
  - File: src/ui/login_flow.rs:70, src/auth.rs:213-234
  - 現状: 全アイテムの復号が cx.update 内で同期実行され、アイテム数に比例して
    UI と 1秒 ticker が停止する（auth.rs のコメントと矛盾）。
  - 受け入れ条件: smol::unblock 等でオフロードし、UI スレッドでは結果の代入のみ。
- [ ] ログイン成功時に last_activity と監査を更新する
  - 根拠: C9-4 / C9-2
  - File: src/ui/login_flow.rs:70-86
  - 現状: 60秒閾値＋30秒認証だと Unlocked 直後に自動ロック。監査も None のまま。
  - 受け入れ条件: 成功ブランチで last_activity を更新し監査を生成（対象外件数を表示）。
- [ ] 監査関連の誤判定を修正する（空パスワード・不正 TOTP・カード番号）
  - 根拠: C4 / C6 / C7 / Q3 / D2
  - File: src/health.rs:330-333,357-361,405-422
  - 現状: 空パスワードが WeakPassword として報告されず、不正 TOTP が設定済みとして
    カウントされ、カード番号空に「URI 未設定」を出す。starts_with("password") が
    長い高エントロピー値まで誤判定（qwerty 側には上限があるのに不整合）。
  - 受け入れ条件: is_valid_secret() を利用、カード専用 Finding を追加、
    password _PREFIX 判定に長さ上限を設ける。
- [ ] 設定ファイルの読み込みを堅牢化する
  - 根拠: D1 / ED4 / FS2 / FS3
  - File: src/settings.rs:128-154, src/generator.rs:44-45,119-120
  - 現状: ネスト型の serde(default) 欠如・型混在・巨大ファイルで 1フィールドの
    問題が全設定の既定値化を招き、破損ファイルは退避されず次回保存で失われる。
  - 受け入れ条件: ネスト型に serde(default)、フィールド単位のフォールバック、
    サイズ上限、破損ファイルのタイムスタンプ付き退避。
- [ ] パスワード生成とエントロピー推定を整合させる
  - 根拠: C1 / C2 / C3 / D5 / R4
  - File: src/generator.rs:105-115,131-140,285-296, src/health.rs:235-253, src/words.rs
  - 現状: 選択クラスの最低1文字保証なし、デフォルト4語で 39.8bit（Weak 判定）、
    prefix を持つ単語が separator="" で境界を崩す、推定プール（+33/+100）が
    生成ロジック（SYMBOLS 8文字）と食い違う。
  - 受け入れ条件: 各クラス最低1文字、デフォルト語数見直し、prefix-free 化または
    テスト名の修正、推定プールを生成側と共有。
- [ ] 機密の zeroize 範囲を拡大する
  - 根拠: S1 / S2 / S6
  - File: src/ui/auth_state.rs:106-112, src/model.rs:218-222,
    src/ui/state.rs:62-64, src/ui/app.rs:129-147
  - 現状: ログイン成功後も AuthState に秘密が残存、ItemData::Login の
    password/totp が通常 String でロック時に消去されず drop される、
    last_password/last_passphrase も平文 `Option<String>`。
  - 受け入れ条件: 成功時に clear_secrets()、暗号化対象フィールドを Zeroizing 化、
    生成結果も Zeroizing に変更。（V3 の再確保前コピーは既知制約として除外）
- [ ] 1秒 ticker のドリフトを解消する
  - 根拠: P2-a / P2-c
  - File: src/ui/app.rs:69-98
  - 現状: Timer::after(1s) の繰り返しで実間隔が 1秒＋処理時間。TOTP 未表示でも
    毎秒 notify() が発火する。
  - 受け入れ条件: Timer::at(deadline) または経過時間を evaluate_tick へ渡す。
    表示対象がある場合のみ invalidate。
- [ ] 部分成功と再試行案内を区別する
  - 根拠: E3 / E4
  - File: src/vault_sync.rs:55-57, src/ui/login_flow.rs:81-84
  - 現状: フォルダ名1件の復号失敗でボールト全体を破棄（名前 None は継続するのに
    一貫しない）。UnlockError 系なのに「r で再試行」を案内する。
  - 受け入れ条件: 復号失敗もプレースホルダで継続、エラー種別ごとに案内を分岐。
- [ ] エラー型を集約し source チェーンを保持する
  - 根拠: E5
  - File: src/auth.rs:182-190, src/vault_sync.rs:45, src/cache.rs:71-105, src/totp.rs:117
  - 現状: 6ファイルに分散、source() 未実装、String 化で原因チェーンが切れる。
  - 受け入れ条件: 共通 AppError（#[from]）または `Box<dyn Error>` で source 保持、
    キャッシュは parse/redact/serialize で別バリアント。
- [ ] 依存更新・ライセンスゲートを自動化する
  - 根拠: DEP1 / DEP2
  - File: .github/（ci.yml のみ）, Cargo.toml:26
  - 現状: cargo audit は有効だが Dependabot/Renovate と cargo deny が無い。
    sha2 直接依存は未使用で openwarden の推移依存と重複。
  - 受け入れ条件: .github/dependabot.yml（cargo 週次）、deny.toml と
    extra_gates への cargo deny check、未使用 sha2 の削除。
- [ ] 実接続とオンボーディングの情報を README に反映する
  - 根拠: REL1 / REL3 / DOC1 / A5
  - File: README.md:44-45,86-104,123-137, docs/adr/adr-20261116-openwarden-integration.md:82-91
  - 現状: 実サーバー接続テスト未実施が README に無く、Vaultwarden の API key 取得
    手順も無い。README の `cd work/bitwarden-gpui-poc` 例はリポジトリ内に無いパス。
    ADR は 74件/モック挙動のまま陳腐化。
  - 受け入れ条件: 既知の制約と初期設定手順を追記、cd 例を修正、ADR を現行実装へ更新。
- [ ] API key の権限範囲と専用アカウント利用の注意を明記する
  - 根拠: G7
  - File: README.md, docs/adr/adr-20261116-openwarden-integration.md
  - 現状: 実 vault のパスワードを復号して UI に渡す経路が無く、PoC の
    「暗号層→UI」ラウンドトリップが未検証。テストアカウント利用の注意も無い。
  - 受け入れ条件: オンデマンド復号＋既存クリップボード復元を再利用するか、
    ADR に検証範囲の限定を明記。README に権限範囲と専用アカウントの注意を追記。
- [ ] 同期データの完全性検証と重複排除を追加する
  - 根拠: D6 / TH6
  - File: src/vault_sync.rs:43-46,152-165
  - 現状: 署名・ハッシュ・revision 単調性・変更監査ログが皆無。同一 ID の
    cipher が重複行になり remove が両方削除する。
  - 受け入れ条件: import 時に ID を HashSet で追跡、revision 単調性を検証、
    変更監査ログを記録（秘密は除去）。
- [ ] cache モジュールを本番フローへ接続するか削除する
  - 根拠: A4 / C9-6 / C9-7 / TH6
  - File: src/cache.rs:70-200, src/lib.rs:21, src/auth.rs:272-306
  - 現状: cache の読み書き・検証が cache_tests.rs からしか呼ばれず、
    オフライン復元や同期失敗時のキャッシュ活用が行われない。ADR と乖離。
  - 受け入れ条件: auth 層から SyncCache へ接続するか feature ゲート／削除し、
    ADR と実装を一致させる。
- [ ] 日付時刻パースを堅牢化する
  - 根拠: T8 / D4 / TH4
  - File: src/vault_sync.rs:118-141
  - 現状: 月1..=12/日1..=31 のみ検証し 2024-02-30 を 03-01 に正規化、
    TZ オフセットを捨てる、極端な年で算術オーバーフロー。
  - 受け入れ条件: 月ごとの日数とうるう年を検証、RFC3339 オフセットを解釈、
    checked_mul/add で None を返す。
- [ ] テストの主張とアサーションを整合させる
  - 根拠: R1 / R2 / R3 / R5 / T5 / T7
  - File: src/totp_tests.rs:132-145, src/ui/vault_view.rs:177-187,
    src/ui/keys_tests.rs:86-105, src/generator_tests.rs:73-83, src/auth_tests.rs:82-87
  - 現状: 「コードを比較しない」「両端でクランプ」「clamp を検証」といった
    テスト名に対し、実際のアサーションが主張を検証していない。
    client_secret の非漏洩も未検証。
  - 受け入れ条件: 異なる secret での等価性、上限クランプ、境界値、
    固有値の非漏洩を明示アサート。
- [ ] キーガード分岐のテストを追加する
  - 根拠: T11 / R7 / R6
  - File: src/ui/keys_tests.rs:107-120,143-156, src/ui/auth_state.rs:79-102,
    src/ui/clipboard.rs:34-55
  - 現状: has_audit_report=false、query_nonempty=false、ServerUrl/Email の
    no-op、copy() の初回のみ保存分岐が未検証。
  - 受け入れ条件: 各ガード分岐を通すテストを追加し、クリップボード分岐は
    App 非依存の純粋関数へ切り出して検証。
- [ ] 検索の Unicode 正規化と空名の扱いを修正する
  - 根拠: ED1 / ED6 / ED2 / ED3
  - File: src/model.rs:399-403,650-665, src/auth.rs:82-99,142,151
  - 現状: NFC/NFD・全角/半角が一致しない、空名が重複名として誤検出、
    空白のみの秘密が検証を通過、Cf 系文字（ゼロ幅・RTL）がメールを通過。
  - 受け入れ条件: NFC/NFKC 正規化、空キーの分组除外、秘密も trim().is_empty()、
    Cf 系を明示拒否。
- [ ] 実ログイン・モック遷移時の状態クリアを共通化する
  - 根拠: INV2
  - File: src/ui/login_flow.rs:109-124,70-87, src/ui/app.rs:129-147
  - 現状: lock() は全リセットするが unlock_mock/finish_login は
    vault/panel/screen/selected_id のみで、auth.field/editing/searching が残存。
  - 受け入れ条件: enter_unlocked() 等の共通関数で lock() と同じリセットを適用。

### 優先度: 低

- [ ] 起動失敗時に cx.quit() を呼び GUI 通知する（O7-a）
- [ ] 設定にスキーマバージョンを追加する（O7-d）
- [ ] 同期キャッシュを XDG_CACHE_HOME 配下へ移す（FS4）
- [ ] デバイス ID を永続化し再同期経路を追加する（A9）
- [ ] 監査パネル・生成／設定パネルにスクロールを追加する（U6 / UI4）
- [ ] 選択行をテキストマーカーでも示す（アクセシビリティ、G5）
- [ ] フォーカスを Tab で外れても復帰可能にする（UI3）
- [ ] 選択解除経路のスクロール処理を共通化する（INV3 / UI5）
- [ ] idle_lock_due を checked_duration_since に変更する（O7-f）
- [ ] 再コピーで deadline を延長しない／内容を更新する（P2-d、中にも関連）
- [ ] エントロピー閾値と `starts_with("password")` の長さ上限を整理する（C5、中にも関連）
- [ ] メール長上限と認証入力の長さ上限を設ける（S9-03 / S9-04）
- [ ] SSH fingerprint を公開鍵から再計算して検証する（CR1）
- [ ] エラー表示を TotpError::message() に合わせる（I2 / E6）
- [ ] カード番号マスキングを数字抽出＋末尾4桁に統一する（S4 / TH2 / V6）
- [ ] Finding::InsecureUri にマスク済み URI を格納する（TH3 / V7）
- [ ] link-local 検証を解決先 IP・リダイレクト先まで拡張する（S9-01 / TH5 / API2）
- [ ] README のゲート順序とドキュメントの記述を揃える（O1 / DOC4）
- [ ] ADR 索引に log.md への導線を追加する（DOC2）
- [ ] README のライセンス節からドキュメント導線を分離する（DOC3）
- [ ] バージョン運用を見直し [Unreleased] を導入する（REL2）
- [ ] CI バッジ／コントリビューション導線を整備する（REL4 / REL5）
- [ ] Kubuntu 向け apt 開発パッケージと mise 導入例を追記する（REL6）
- [ ] テスト属性を `#[test]` に統一し allow の理由を明記する（T13 / Q7）
- [ ] デッドコード・過剰な pub を整理する（A7 / A10）
- [ ] コマンド例を bash 構文で統一し検証する（共通指示 §10）
- [ ] 変更時に docs/adr/log.md を `## YYYY-MM-DD` 形式で追記する（共通指示 §8）

## 完了

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
