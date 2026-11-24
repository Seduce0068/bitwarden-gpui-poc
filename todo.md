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

なし（第150弾で 3 件すべてを完了）。

## 完了

- [x] 第150弾（16 担当・94 回目）の指摘 3 件を完結（2026-11-24）
  - esc/return エイリアス正規化、separator 案内の不可視判定、
    matches_page 折り目タイブレーク、README 上限を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1294 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第149弾（16 担当・93 回目）の指摘 5 件を完結（2026-11-24）
  - 秒単位 status の対象ラベル、separator 上限、
    XDG ENV_LOCK 共有、mark-only Unnamed、再利用 visible_key を修正。
  - validate 優先順位、live Session 抽出をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1289 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第148弾（16 担当・92 回目）の指摘 6 件を完結（2026-11-24）
  - mark-only 名前の UI 空判定、アイドルロック doc、
    device_id null、権限/パース優先順位を修正・テスト。
  - フォールバック破損伝播、Strength::score 小数丸めをテスト。
  - CHANGELOG に第147弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1280 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第147弾（16 担当・91 回目）の指摘 2 件を完結（2026-11-24）
  - Unicode 結合文字混入パスワードの characterization をテスト。
  - CHANGELOG に第145〜146弾を反映。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1275 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第146弾（16 担当・90 回目）の指摘 3 件を完結（2026-11-24）
  - COMMON 完全一致の装飾変種、非 blank クエリ×他ソート、
    ADR redact 行参照を修正・テスト。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1272 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第145弾（16 担当・89 回目）の指摘 5 件を完結（2026-11-24）
  - host 確定後の `?@` 誤マスク、空認証フィールドの
    編集中マーカーを修正。
  - 数値オーバーフロー、連番 PIN、to_text 分岐、
    mark-only TOTP、Steam 表記を修正・テスト。
  - CHANGELOG に第144弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1267 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第144弾（16 担当・88 回目）の指摘 5 件を完結（2026-11-24）
  - unlock_detail 3系統、ゼロ幅のみメール、空フォルダ id、
    wire 非整数、Steam 期限警告を修正・テスト。
  - CHANGELOG 第142〜143弾、Betterleaks 版検査の厳密化を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1259 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第143弾（16 担当・87 回目）の指摘 3 件を完結（2026-11-24）
  - 範囲外 URI match wire、空文字 id dedup、LoginUri Debug、
    非 name haystack、全角数字サフィックスの非対称をテスト。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1255 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第142弾（16 担当・86 回目）の指摘 3 件を完結（2026-11-24）
  - 数字パスワード＋'=' の bare authority マスク、
    numeric_password_colon ガード、余白付き数値 advisory を修正・テスト。
  - CHANGELOG に第138〜141弾を反映。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1249 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第141弾（16 担当・85 回目）の指摘 3 件を完結（2026-11-24）
  - IPv6＋ポート＋パスのクエリ '@' 誤判定、確定クエリ再編集案内、
    ADR redact 行参照を修正。
  - 数字コロン判定を authority 部分へ限定。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1246 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第140弾（16 担当・84 回目）の指摘 3 件を完結（2026-11-24）
  - 検索編集中 Backspace 案内を追加。
  - Argon2id 全パラメータ、Session kdf 伝播、
    bare authority 深さ上限、cache 行参照を修正・テスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1243 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第139弾（16 担当・83 回目）の指摘 7 件を完結（2026-11-24）
  - bare authority の第2 '?' マスク、BlockedServerUrl status、
    数字コア 0bit、PageUp 案内、ADR verified を修正。
  - SAW_KDF フレーキー、生成 boolean、Zs 再利用、
    監査コメントを修正・テスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1240 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第138弾（16 担当・82 回目）の指摘 6 件を完結（2026-11-24）
  - bare authority の '=' マスク漏れ、F1 視覚フィードバック、
    空一覧キー案内、auth 行参照／doc を修正。
  - ネスト '#' 共存、avoid_ambiguous 境界をテスト。
  - CHANGELOG に第134〜137弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1234 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第137弾（16 担当・81 回目）の指摘 5 件を完結（2026-11-24）
  - Zs の WIDE_POOL 計上、ADR の本番アンロック手順を修正。
  - メールオクテット境界、server_url 型不一致、権限/サイズ
    優先順位、SYMBOLS 外記号をテスト。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1229 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第136弾（16 担当・80 回目）の指摘 6 件を完結（2026-11-24）
  - 監査タブ idle 更新、health の Unicode 空白/Cc 扱い、
    README の同期 body 表現を修正。
  - unlock_and_import 本番形状、URL マルチバイト、
    非文字列 profile.id 全型、設定 1/2 キーをテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1224 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第135弾（16 担当・79 回目）の指摘 4 件を完結（2026-11-24）
  - ADR の暗号化済み body 誤記述を修正。
  - settings.json 0600、未知キー破棄、非文字列 profile.id、
    分数秒終端子、マルチバイトサイズ境界をテスト。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1218 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第134弾（16 担当・78 回目）の指摘 6 件を完結（2026-11-24）
  - ADR ログ 11-24 節の重複、キャッシュ特殊ファイル／資格情報
    永続化の既知制約を修正・記録。
  - profile.id 型不一致、ルートキー衝突、steam:// 表示、
    手構築 server_url 平文をテスト。
  - CHANGELOG に第132〜133弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1213 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第133弾（16 担当・77 回目）の指摘 4 件を完結（2026-11-24）
  - is_sensitive_param_key 部分一致、save の非 sync ボディ、
    BASE64 5文字、数字 COMMON 到達不能をテスト。
  - ADR ログに 2026-11-24 を追記。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1209 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第132弾（16 担当・76 回目）の指摘 7 件を完結（2026-11-24）
  - passphrase 不可視文字、監査 status 重複、
    クエリ内 scheme-less ユーザー情報を修正。
  - 設定上限 doc、Debug リダクタ、小文字 protected_key、
    フォルダのみのボルトをテスト。
  - CHANGELOG 第129〜131弾、ADR redact 行参照を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1205 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第131弾（16 担当・75 回目）の指摘 7 件を完結（2026-11-24）
  - protected key の Zeroizing 化、SecureNote 桁数、
    監査 F1 固定フッタ、README ゲート順序を修正。
  - メタデータ host 全件、Infinity スキーマ、config_dir 写像、
    負リビジョン Clipped、重複フォルダ復号不能、
    Filter/SortKey 既定値をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1197 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第130弾（16 担当・74 回目）の指摘 3 件を完結（2026-11-24）
  - is_key_separator 全ファミリをテスト、旧バージョンの
    VersionMismatch 扱い（version 欠落はデフォルト 0）、
    ADR redact 行参照を修正。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1188 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第129弾（16 担当・73 回目）の指摘 7 件を完結（2026-11-24）
  - お気に入り解除 status、不可視文字桁数、F1 固定フッタ、
    非ASCII区切りキー redaction を修正。
  - catch-all ParseFailedCause、upsert 減方向、サブドメイン照合をテスト。
  - CHANGELOG に第127〜128弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1186 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第128弾（16 担当・72 回目）の指摘 5 件を完結（2026-11-24）
  - estimate_entropy の不可視文字扱い、編集キー案内、
    README ゲート一覧を修正。
  - RFC3339 小文字、非オブジェクト profile、非ASCII区切りをテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1179 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第127弾（16 担当・71 回目）の指摘 7 件を完結（2026-11-24）
  - comparison_key の trim 順序、adjust_idle_lock の端数保持、
    不可視クエリのキー分類を修正。
  - ensure_device_id 不正 id、ItemKind wire 数値、
    Cf/Cc に守られた空白をテスト。
  - CHANGELOG 第125〜126弾、ADR コピー機能を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1172 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第126弾（16 担当・70 回目）の指摘 3 件を完結（2026-11-24）
  - 空白/Cf パスワードの再利用登録、スキーマ -0.0／小数指数、
    ネスト '#' 副条件と本物フラグメントを修正・テスト。
  - 空監査 Home/End の指摘は既に修正済みで却下。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1167 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第125弾（16 担当・69 回目）の指摘 6 件を完結（2026-11-24）
  - 空白パスワード桁数表示、編集中 n キー案内、auth/ADR 行参照を修正。
  - 曖昧 '#' fail-closed、PascalCase URI match、URI マーカー偽物、
    to_text 種別ラベル、now_unix 時計追従をテスト。
  - CHANGELOG に第124弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1163 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第124弾（16 担当・68 回目）の指摘 7 件を完結（2026-11-24）
  - 実フラグメント区切りとネスト '#' の判別、不可視 URI の
    NoUri 判定、auth 行参照を修正。
  - load_advisories 構文エラー、mixed_kinds doc、
    監査 arrow ページキー、不正 otpauth URI をテスト。
  - CHANGELOG に第121〜123弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1156 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第123弾（16 担当・67 回目）の指摘 5 件を完結（2026-11-24）
  - 空監査レポート Enter 案内、ネスト URL の '#' パスワード
    マスク、field decryptor doc を修正。
  - select_index/id の TOTP 非失効、AltGr 関数キーをテスト。
  - 調査レポート件数 25→33 を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1150 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第122弾（16 担当・66 回目）の指摘 6 件を完結（2026-11-24）
  - TOTP コピー復号不可判定、不可視クエリ案内、
    分／秒アイドルロック定数導出を修正。
  - 重複フォルダ id、SSH 非 ASCII blob、非既定 period、
    調査レポート件数を修正・テスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1146 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第121弾（16 担当・65 回目）の指摘 7 件を完結（2026-11-24）
  - 編集中の生成設定案内、keys_tests 行参照、CHANGELOG 件数を修正。
  - UUID variant/大文字救済、0600 権限、created_at 下限、
    安定ソート、空 base64、finding 数値をテスト。
  - CHANGELOG に第118〜120弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1139 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第120弾（16 担当・64 回目）の指摘 5 件を完結（2026-11-24）
  - UI キー案内、auth/settings/model 行参照、WEAK_BITS/TotpError doc、
    CHANGELOG 過去件数、README 直接遷移を修正。
  - 現行スキーマ陽文ケースをテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1129 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第119弾（16 担当・63 回目）の指摘 7 件を完結（2026-11-24）
  - 空 user_id 照合 fail-open、設定 TOCTOU 記録、
    行参照、custom weak_bits doc を修正。
  - 生成／設定パネル直接遷移キー、VaultItem 既定値、
    空 folder_id、再サニタイズをテスト。
  - CHANGELOG の過去テスト件数を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1127 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第118弾（16 担当・62 回目）の指摘 6 件を完結（2026-11-24）
  - limits doc、空 profile.id、空フォルダ名、folder_id 欠落、
    has_usable_totp／password_entropy doc、UI 行参照を修正・テスト。
  - CHANGELOG に第117弾を反映。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1116 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第117弾（16 担当・61 回目）の指摘 4 件を完結（2026-11-24）
  - 空一覧 Up/Down 反馈、F1 大小文字正規化、
    cycle_filter vacuous テストを修正。
  - TOTP カバレッジ 0/0 行をテスト。
  - CHANGELOG に第115〜116弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1115 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第116弾（16 担当・60 回目）の指摘 6 件を完結（2026-11-24）
  - 空一覧の Home/End 反馈、count-only status の誤案内を修正。
  - KdfPolicy::default 成功経路、BlockedServerUrl 入口、
    special mode bits、server_url verbatim、空パスワード監査、
    空白付き名検索、不可視判定同一性をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1113 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第115弾（16 担当・59 回目）の指摘 6 件を完結（2026-11-24）
  - client_secret 一時値の零化、duplicate_names の共有キー、
    確定クエリ空時の案内を修正。
  - KDF 上限ガード、TOTP 失効シグナル、otpauth matches_secret、
    パディング名のキー共有をテスト。
  - CHANGELOG に第113〜114弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1104 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第114弾（16 担当・58 回目）の指摘 4 件を完結（2026-11-24）
  - 不可視 email の分類、恒真境界、監査ログ実経路、
    mark-only クエリの可視性ルールを修正・テスト。
  - 全角数字、Cc の TOTP/Unnamed 経路をテスト。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1099 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第113弾（16 担当・57 回目）の指摘 6 件を完結（2026-11-23）
  - AuthError catch-all 網羅、at_is_in_query 恒真式、comparison_key Cc
    除去、mark-only 内部空白、CHANGELOG 第112弾を修正。
  - hex デコード、parse_sync 空ボディ、埋め込み Cc、
    語サフィックス 3 文字境界をテスト。
  - 起動エージェント: 17 体（補充探索 16 + 実装 1）。
  - 検証: fmt / check / test（1094 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第112弾（16 担当・56 回目）の指摘 8 件を完結（2026-11-23）
  - UI Cc 判定、選択解除時 TOTP クリア、カード番号の不可視判定、
    http:/ 単一スラッシュ検出を修正。
  - Argon2id KDF、大文字メール、埋め込み不可視文字、
    userinfo/authority 境界、data 必須、Cc 結合経路をテスト。
  - 同期 doc と恒真アサーション、README 矛盾、CHANGELOG を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1088 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第111弾（16 担当・55 回目）の指摘 6 件を完結（2026-11-23）
  - 数値パスワード＋'/' マスク、model の Cc 判定、
    確定クエリ案内、ADR redact 行参照を修正。
  - KDF 成功経路、不可視 server_url、ensure_device_id 早期リターン、
    4/5桁ポート境界をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1076 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第110弾（16 担当・54 回目）の指摘 6 件を完結（2026-11-23）
  - 監査 status の内部 ID／Cf 名、確定クエリ再編集案内、
    arrow キー、master_password の不可視判定を修正。
  - nested IPv6 authority、fingerprint trim、start_search の
    filter/sort 保持、同期間 tick.at 不変をテスト。
  - CHANGELOG 第107〜109弾、ADR ログを反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1071 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第109弾（16 担当・53 回目）の指摘 7 件を完結（2026-11-23）
  - 監査行ラベルの Cf 名プレースホルダ、数値パスワード＋?key=value
    の URL マスク、client_id/secret の trim→クランプ、
    Cf 認証情報、監査の Cf 空名を修正。
  - IPv4-compatible メタデータ IP、小数秒 dedup、
    expires_within 境界をテスト。
  - README/ADR のキャッシュ定義を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1058 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第108弾（16 担当・52 回目）の指摘 6 件を完結（2026-11-23）
  - クランプ境界の feedback、調整 status への値表示、
    検索ヘッダの不可視クエリを修正。
  - server_url trim、Updated revisions 下流効果、不可視判定統一、
    Cf TOTP、steam/otpauth 監査をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1048 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第107弾（16 担当・51 回目）の指摘 8 件を完結（2026-11-23）
  - コピー／生成 status の未保存マーカー、Cf のみ TOTP のコピー判定、
    クランプ境界の生成キーを修正。
  - URL マスクのユーザー名ハードコード、混合クラス 40bit 境界、
    ハイフン位置、u32 幅超過、Cf 検索、TOTP Debug を修正・テスト。
  - 同一ホスト重複 URI、steam://、1〜2桁 grouped をテスト。
  - CHANGELOG に第105〜106弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1037 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第106弾（16 担当・50 回目）の指摘 6 件を完結（2026-11-23）
  - 数字パスワード＋'?'＋テキスト＋'@' の URL マスク、
    空一覧の主要キー案内、comparison_key の Cf 除去、
    空白のみ TOTP の未設定扱いを修正。
  - UnlockError 前方変換の discriminant、権限/バージョンと
    server/parse の優先順位をテスト。
  - CI の cargo-deny README 突き合わせを修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1022 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第105弾（16 担当・49 回目）の指摘 6 件を完結（2026-11-23）
  - 空名行選択 status、F キー範囲外の non-text 判定を修正。
  - catch-all 変換、config_dir None、SettingsLoadError source、
    Mc 空白名、埋め込み NUL をテスト。
  - auth_tests 行参照を現行位置へ修正。
  - README の cargo-deny コマンド、CHANGELOG 第104弾を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1015 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第104弾（16 担当・48 回目）の指摘 8 件を完結（2026-11-23）
  - IPv4-mapped メタデータ IP、Windows ACL 主張、TOTP 理由遅延、
    空監査 status、キーボード選択 status、Vault キー一覧を修正。
  - Detail 前方変換、現行/将来 device_id、スカラー root、
    EISDIR、期限切れ primary、オフセット短縮形、
    U+0345 doc、空白名プレースホルダ、10桁 grouped をテスト。
  - CHANGELOG に第103弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（1006 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第103弾（16 担当・47 回目）の指摘 7 件を完結（2026-11-23）
  - email の trim→クランプ、二重括弧、非 link-local メタデータ IP、
    Windows 権限制約、created_at 契約を修正・記録。
  - 空名プレースホルダ、複数 URI 選択、検索中ヒント、
    TOTP 逆時刻、Mn/Me 空名、SSH public_key を修正・テスト。
  - boolean スカラ、負→負 Updated、複数フォルダ id をテスト。
  - CHANGELOG に第101〜102弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（996 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第102弾（16 担当・46 回目）の指摘 6 件を完結（2026-11-23）
  - スキーム無し authority の数字パスワード、Unicode/full-width 空白
    link-local URL、ParseFailed バリアント固定を修正・テスト。
  - 設定パネルの端数秒、TOTP/URI の Cf 空判定、通常行クリック status、
    Updated の id 差し替え、全ペイロード型検証を修正・テスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（979 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第101弾（16 担当・45 回目）の指摘 7 件を完結（2026-11-23）
  - all-same の前後装飾、数字のみ userinfo マスク、Cf-only 重複名を修正。
  - 検索中行クリック status、copy 判定の Cf、ページキー、
    他ソート index を修正・テスト。
  - UnlockFailedCause strip、空 source、ENV_LOCK、パディング将来版、
    区切り文字、falsy 非 null、非ログイン Unnamed/Stale、
    40bit 境界をテスト。
  - CHANGELOG に第100弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（971 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    （dir＋git 履歴）すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第100弾（16 担当・44 回目）の指摘 7 件を完結（2026-11-23）
  - 辞書パスワードの末尾装飾、一覧 Cf 空 username、
    詳細行の二重区切り、同期サイズエラー文言を修正。
  - SettingsLoadError::Other、metadata 失敗、複数 IPv6、
    非パディング base64 末尾ビット、length 境界、
    全記号連続をテスト。
  - cross-review の email 記述、CHANGELOG 第97〜99弾を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（958 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第99弾（16 担当・43 回目）の指摘 7 件を完結（2026-11-23）
  - 一覧行の空 username を "-" 表示、自動ロックを分＋残秒表示に修正。
  - email 大文字の既知制約、Cf 全21範囲、client_id trim、
    クランプ永続化、default_path 安定性、URL 共存マスク、
    digit→symbol→語装飾をテスト。
  - sync 上限定数を limits へ集約し、cache↔vault_sync の循環依存を解消。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（948 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第98弾（16 担当・42 回目）の指摘 8 件を完結（2026-11-23）
  - live sync ボディに 8MiB 上限、クランプ境界の誤告知、
    認証編集中ヒントの重複を修正。
  - 辞書パスワードの先頭装飾、host 引数、4要素超ハイフン、
    ensure_device_id ガード、型違反 ParseFailedCause、
    非ゼロ user key、MatchOptions 伝播を修正・テスト。
  - ADR 行参照、cross-review agent 数、ADR ログを修正。
  - CHANGELOG に第95〜96弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（938 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第97弾（16 担当・41 回目）の指摘 5 件を完結（2026-11-23）
  - all-same の末尾記号バイパス、入力 status のマーカー、
    TOTP 上限動的化を修正。
  - 復号済みアイテム到達、device_id 救済、空白付き将来版、
    redact 往復後の復号、行参照 53 件を修正・テスト。
  - identity/card haystack、ItemData 型違反をテスト。
  - CHANGELOG に第95〜96弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（926 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第96弾（16 担当・40 回目）の指摘 7 件を完結（2026-11-23）
  - all-same の大小混在、入力開始 status の未保存マーカー、
    TOTP 上限の動的化を修正。
  - save_default の legacy 不変、サイズ/バージョン優先順位、
    Unicode tiebreak、非既定メタデータ往復、NoFolder 選択、
    非30秒/非6桁 TOTP 表示をテスト。
  - settings_tests 行参照 32 件、README 期限説明を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（919 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第95弾（16 担当・39 回目）の指摘 8 件を完結（2026-11-23）
  - 数値PIN の 1000bit クランプ、IPv4-compatible IPv6 の
    既知制約、非10進 IPv4 全体ホスト、トップレベル u64 型不一致、
    schema bool/null、期限ガード優先順位、サイズ境界をテスト。
  - cache の pretty 展開による上限非整合を doc 化。
  - vault_sync 行参照 40 箇所、重複 id 更新、favorite_count を修正・テスト。
  - CHANGELOG に第93〜94弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（911 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第94弾（16 担当・38 回目）の指摘 6 件を完結（2026-11-23）
  - 確定クエリの Alt/AltGr、行クリック index 契約、SSRF 非10進
    埋め込みリテラルの既知制約、入れ子 URL の '@' 混在マスク、
    同期注入シーム不在の doc 化を修正。
  - 有効 device_id 往復、マルチバイト境界、1000bit、大文字 +1bit
    をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（901 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第93弾（16 担当・37 回目）の指摘 7 件を完結（2026-11-23）
  - 監査の all_same と辞書 prefix バイパス、IPv4-mapped IPv6、
    userinfo SSRF、TooLarge/未来スキーマの save ガードを修正・テスト。
  - 監査パネルの n/c 導線、設定編集中ヒント、検索中＋クエリ非空、
    Generator editing_settings、SshKey フィルタをテスト。
  - cache/vault_sync の doc を実態へ修正。
  - CHANGELOG に第91〜92弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（891 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第92弾（16 担当・36 回目）の指摘 7 件を完結（2026-11-23）
  - キャッシュ save 前に profile.key/privateKey を除去。
  - PreloginCause 変換、サイズ境界、server/user 不一致優先順位、
    除外/適格同 revision、配列以外 ciphers/folders、複数 URI、
    Favorites＋クエリ、rejection sampling、重複 URI をテスト。
  - is_non_text_key_name の全列挙をテスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（880 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第91弾（16 担当・35 回目）の指摘 7 件を完結（2026-11-23）
  - 検索確定後クエリのエッジケース、AuthError status_message、
    サイズ超過のフォールバック拒否、ParseFailedCause source、
    存在しない folderId、年 0000/9999、Filter::Kind(SecureNote)、
    ジェネレータ shuffle をテスト。
  - CHANGELOG に第90弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（866 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第90弾（16 担当・34 回目）の指摘 7 件を完結（2026-11-23）
  - 検索確定後のクエリ文字追加、PageUp 固定10行の明記、
    認証編集中 l/m/r の挿入を修正・テスト。
  - UnlockError Display/source、same_json_type 全型、pop_shared_char、
    非数値 type、フィルタ＋クエリ AND、kind_counts をテスト。
  - passphrase の恒偽 join チェックを削除。
  - CHANGELOG 第87〜89弾、review-report の件数参照を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（858 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第89弾（16 担当・33 回目）の指摘 6 件を完結（2026-11-23）
  - F1 等のキー名が編集モードで文字挿入される問題を修正し、
    監査パネルの F1 重複を解消。
  - dedup の除外判定に type != 1 を追加、URL マスクの
    '/' + '?'/'#'/'&' を修正。
  - UnlockError PartialEq 特性、Clipped/Ignored の old_revision=0、
    README のキャッシュ期限説明を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（846 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第88弾（16 担当・32 回目）の指摘 5 件を完結（2026-11-23）
  - Vault 一覧ヘッダから監査専用の Enter 案内を除去し、
    Alt + 物理キーの契約を doc/テストで整合。
  - resolve_host 失敗、巨大 float 飽和、読み取り不能ファイル置換、
    キャッシュ save のサイズ検証、パスワード内 '/'、
    空 folders の恒真アサーション、Updated old_revision=0 を修正・テスト。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（831 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第87弾（16 担当・31 回目）の指摘 6 件を完結（2026-11-23）
  - 空一覧で行選択キーを出さない共通ヘルパを一覧ヘッダへ配線。
  - parse 失敗 URL の第2防壁、File::open エラー、既定 server_url、
    末尾区切り、マルチバイト前進、±00:00、除外行同値、
    混在キャピタライズをテスト。matches_page コメントを修正。
  - CHANGELOG に第85〜86弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（822 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第86弾（16 担当・30 回目）の指摘 5 件を完結（2026-11-23）
  - 先頭スラッシュ付き scheme-less authority のマスク、
    Settings::save の親ディレクトリ自動作成を修正・テスト。
  - PascalCase 重複 folder、非オブジェクト要素、RecentlyModified
    タイブレークをテスト。health doc の自己矛盾、
    cross-review/ADR ログの記録を是正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（811 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第85弾（16 担当・29 回目）の指摘 8 件を完結（2026-11-23）
  - 監査行クリック時の選択/スクロール同期、status の行名表示、
    Caps Lock の挿入文字を修正・テスト。
  - generator 型逆依存、入れ子非オブジェクト、Profile.Id 欠落、
    パスワード内 '='、Clipped の暗号文、PascalCase＋除外行、
    既定ポート、CardData 有効期限、非ASCII大文字をテスト。
  - CHANGELOG に第84弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（806 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第84弾（16 担当・28 回目）の指摘 6 件を完結（2026-11-23）
  - 監査未生成時の g キーに理由 status を表示。
  - '&' を含む nested userinfo、pair_start==0、復元のエラー分類、
    folders 早期リターン、"(名前なし)"、trim 後 email 上限、
    空 email Debug を修正・テスト。
  - mask_uri doc、CHANGELOG 第82〜83弾、ADR エラー分類を更新。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（795 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第83弾（16 担当・27 回目）の指摘 8 件を完結（2026-11-23）
  - 大文字スキームとクエリ内 `://` の URL マスク、除外行が重複で
    勝つ問題、folders の重複 id を修正。
  - ';' を含む userinfo、大文字パスフレーズ、逆変換、
    MissingProtectedKey、同一 id、favorite false、
    ソート済み select_id、空白 TOTP をテスト。
  - KNOWN 一覧を本番定数へ集約し、装置 ID writer の契約を固定。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（787 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第82弾（16 担当・26 回目）の指摘 8 件を完結（2026-11-23）
  - Caps Lock 時のキーコマンドを ASCII 大小折り上げで維持し、
    y/Y のコピー先区別を raw glyph で保持。
  - 監査未生成タブ、AuthError 順方向、恒真アサーション、
    スキーム無し authority、';' 区切り、制御文字エスケープ、
    mask_uri フラグメント、複数 URI 監査を修正・テスト。
  - TOTP の 2100 年上限を是正し、期間境界のコピー整合を検証。
  - CHANGELOG に第81弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（771 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第81弾（16 担当・25 回目）の指摘 7 件を完結（2026-11-23）
  - 検索→監査遷移の status を実際の選択行と整合させた。
  - プロトコル相対 URL のマスク、NotFound/CacheParse、
    混在 URI のリスト置換、ZeroizingText Deref/AsRef、
    upsert/remove の重複 id、非 ASCII 数字 PIN、InvalidCause source
    をテスト。
  - 行参照、UNDECRYPTABLE_URI の doc、CHANGELOG 第79〜80弾、
    ADR 本文 Profile.Id 照合を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（758 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第80弾（16 担当・24 回目）の指摘 6 件を完結（2026-11-23）
  - URL マスクに深さ上限を追加し、本文 Profile.Id との照合を実装。
  - sync_fallback の汎用合成、UTF-8 境界、device_id サニタイズ、
    username-only userinfo、非オブジェクト JSON、SSH コメント省略、
    fingerprint 伝播、空白カード番号をテスト。
  - VaultItem::new doc、model_tests の行参照、review-report の
    stale_after を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（748 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第79弾（16 担当・23 回目）の指摘 7 件を完結（2026-11-23）
  - Separator 未知値、有効 TOTP→空欄切替、期限の飽和、非 ASCII ポート、
    favorite/notes 既定値、base64 1バイト剰余、VaultItem Debug をテスト。
  - DNS 再チェック／from_cache の注入シーム不在、health 依存、
    duplicate_names 未配線を既知制約として doc 化。
  - CHANGELOG 第77〜78弾と ADR verified メタデータを更新。
  - TOTP カウントダウン凍結の指摘は 1 秒 ticker の invalidate を
    Runtime Proof として却下（メモ参照）。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（737 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第78弾（16 担当・22 回目）の指摘 7 件を完結（2026-11-23）
  - ロック画面非編集時のページキー無効、埋め込み link-local の
    他ラベル、手編集ジェネレータのクランプ、KNOWN キー逆方向、
    hostname 特殊文字、URI match wire 0/2/4、名前 trim、
    SSH 公開情報、NoUri、COMMON 38件をテスト。
  - README のキー一覧と ADR Status を更新。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（730 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第77弾（16 担当・21 回目）の指摘 8 件を完結（2026-11-23）
  - 生成パネルの F1 重複、ロック status の区切り残存、
    ページ移動キーのヒントを修正。
  - device ID の読込時サニタイズ、final write 失敗、IPv6 不正分岐、
    ネスト URL userinfo、NUL マーカー、U+0345 冪等、
    UriMatch 実照合、algorithm 不正値、再利用 3件をテスト。
  - 行参照を現行位置へ修正、CHANGELOG 第75〜76弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（720 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第76弾（16 担当・20 回目）の指摘 7 件を完結（2026-11-23）
  - Vault/Audit に PageUp/PageDown/Home/End を追加、生成ヒントに
    F1 を追加、pop_query のマルチバイトと不正 secret 切替をテスト。
  - host-less URL、cache 汎用文言、load_advisories の ReadFailed、
    型不一致、非 ASCII キー、空 vault をテスト。
  - `comparison_key` を冪等化し、生成器の ambiguous 既知制約を doc 化。
  - cache_tests の固定 temp パスを tempfile 化し行参照を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（708 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第75弾（16 担当・19 回目）の指摘 7 件を完結（2026-11-23）
  - 監査選択消滅時のスクロール target 破棄を修正。
  - 入れ子 cause、sync_cause 破棄、KDF 拒否実経路、IPv6 片括弧、
    空 URI、ZeroizingText Display、未知 type をテスト。
  - 固定 temp パスを tempfile 化し、注入シーム doc の根拠を是正。
  - ADR ログ 2026-11-23 と CHANGELOG 第73〜74弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（689 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第74弾（16 担当・18 回目）の指摘 10 件を完結（2026-11-23）
  - `next_index_in` のオーバーフロー、編集モード別の遷移 status、
    フィルタ/ソートの status、未生成コピーの未保存マーカーを修正。
  - マルチバイト UTF-8 の上限境界、SyncDetail 往復、hostname 正規化、
    read_bounded の消費量、URI マーカーの match_type、folder_id と
    match_enum、エントロピー丸め、Steam 数字コードをテスト。
  - I/O と RNG の注入シーム不在を既知制約として doc 化。
  - ADR のアカウント照合記述を更新。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（679 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第73弾（16 担当・17 回目）の指摘 11 件を完結（2026-11-23）
  - キャッシュ復元へ client_id 由来のアカウント照合を追加。
  - IPv6 host の URL マスク、set_panel の検索解除、閾値変更 status、
    adjust_seconds のオーバーフロー、空監査の案内を修正。
  - auth / settings / cache / sync / model / health の残りテストと
    上限定数の limits 集約を実施。
  - CHANGELOG に第71〜72弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（665 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第72弾（16 担当・16 回目）の指摘 7 件を完結（2026-11-23）
  - URL userinfo マスクの '@' 共存・unescaped '?'/'#' 問題を修正。
  - パネル遷移／行クリック／BackspaceQuery の status 残留を解消し、
    VaultViewState の契約をテスト。
  - デフォルト timeout テストの妥当化、limits 定数、未来スキーマの
    device_id 型違反、File::open の非 NotFound、監査テキスト描画をテスト。
  - CHANGELOG 0.1.0 の E2E 注記と README の TOTP 桁数を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（647 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第71弾（16 担当・15 回目）の指摘 10 件を完結（2026-11-23）
  - TOTP 非 ASCII ガードを otpauth URI に合わせて狭隘化し、
    digits/period 境界をテスト。
  - URL マスクの資格情報キー拡張と authority 内 '?'/'#' の修正、
    クランプ定数の limits 集約、TOTP 失敗理由の区別表示、
    0件検索確定の専用文面を修正。
  - auth / settings / vault_sync / model の残りテストと
    doc の矛盾を修正。CHANGELOG 第69〜70弾と README の
    schema_version 0/0.0 記述を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（637 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第70弾（16 担当・14 回目）の指摘 11 件を完結（2026-11-23）
  - 非 ASCII TOTP secret のパニック防止、AltGr 由来文字の挿入、
    閾値変更時の status 上書き、認証確定後の m/r 案内を修正。
  - タイムアウト退避、schema_version 0.0、未来版 device_id 救済、
    legacy fallback、非ログイン除外、Zeroizing 化、カード haystack、
    base64、Severity ラベルをテスト／修正。
  - limits 定数を UI クランプへ集約、clippy/doc/secret の
    統合時エラーを解消。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（624 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第69弾（16 担当・13 回目）の指摘 9 件を完結（2026-11-23）
  - 認証の絶対デッドラインタイムアウト、カード番号・コード・notes の
    Zeroizing 化、設定読み取りの TOCTOU 共通化とゼロ幅定数集約を修正。
  - パネル間遷移の誤案内、選択スクロール契約、Timeout 往復、
    validate_config 優先順位、二重エンコード、save 失敗、
    同 revision の先頭保持、SSH key_type をテスト。
  - CHANGELOG に第67〜68弾を反映し RUSTSEC 重複を整理。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（602 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第68弾（16 担当・12 回目）の指摘 11 件を完結（2026-11-23）
  - 自動ロック時の案内揃え、0件時の詳細行非表示、i/u の分表記、
    複数文字 key_char、invalidate/clear の契約を UI 側で修正・テスト。
  - ApplySyncFailedCause 往復、settings の非オブジェクト入力、URL マスク、
    負 revision、serde 往復、match_enum、未来 revision をコア側でテスト。
  - `matches_query` の trim と NFKD doc を修正。
  - cross-review 小計と CHANGELOG の注記を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（589 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第67弾（16 担当・11 回目）の指摘 11 件を完結（2026-11-23）
  - 監査未選択 Enter の未保存マーカー、生成 y/Y の案内、
    `TotpState::clear()` と Alt+文字のテストを追加。
  - `Some(Kdf)` 経路、trim 空判定、設定上限/default_path、
    cache の parse 失敗と値なしパラメータ、同期の欠落分岐、
    model の trim/padding/serde 既定値、監査コメントを処理。
  - CHANGELOG に第65〜66弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（570 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第66弾（16 担当・10 回目）の指摘 10 件を完結（2026-11-23）
  - `VaultItem` の Debug で notes をマスク、`is_common_password` の
    完全一致/接頭辞分岐を分離、InsecureUri のバックスラッシュ正規化を追加。
  - auth / settings / cache / sync / model / health / UI の残りテストと
    既知制約の doc 明記を追加。start_search を本番共通ヘルパへ集約。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（552 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第65弾（16 担当・9 回目）の指摘 10 件を完結（2026-11-23）
  - Settings の Debug で server_url をマスク、cache の
    パラメータ名/二重エンコードの秘密マスクを修正。
  - 監査スクロールのリセット、TOTP 有効→無効遷移、可視リスト下の選択、
    auth / settings / cache / sync / model の残りテストを追加。
  - comparison_key と検索ヒントの doc を実態へ修正し、
    ImportAudit 破棄などを既知制約として記録。
  - CHANGELOG に第64弾を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（538 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第64弾（16 担当・8 回目）の指摘 12 件を完結（2026-11-23）
  - URL マスクのフラグメント/エンコード済み入れ子 URL、
    `is_common_password` の文字数ベース判定を修正。
  - auth / settings / cache / sync / model / health / UI の残りテストを
    追加し、SSH fingerprint の現状を doc に明記。
  - CHANGELOG 第60〜63弾と ADR ログ 2026-11-22 を反映。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（524 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第63弾（16 担当・7 回目）の指摘 10 件を完結（2026-11-22）
  - 同期の内部 id 開示排除と復号済み name/username の直接検証、
    `unlock_and_import` の4分岐をテスト可能にする注入シーム、
    SSRF の実 DNS 経路の決定的テストを追加。
  - email 先頭 Cf (U+200B..U+200F) の正規化、device ID 大文字 variant の
    決定的テスト、URL フラグメント/入れ子 URL の秘密マスク、
    read_bounded のエラー分類、model のマスキング/タイブレーク、
    監査レポートのタイブレーク、TOTP grouped() の桁数を処理。
  - UI は生成/設定パネルのスクロールを「マウス／ホイールのみ」と明記、
    編集中ステータスの後始末、cycle_filter 全段、
    is_text_cursor_key 全名をテストで固定。
  - CHANGELOG の gitleaks 表記に Betterleaks 置換を注記。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（506 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第62弾（16 担当・6 回目）の指摘 9 件を完結（2026-11-22）
  - `sanitized()` の email Cf 正規化を UI 入力経路と統一。
    cache Debug の URL クエリ秘密マスク、TOCTOU 境界ヘルパー、
    Vault 同期の内部 id 開示排除、UI の未保存マーカーと監査スクロール、
    各种残りテストを追加・修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（480 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第61弾（16 担当・5 回目）の指摘 10 件を完結（2026-11-22）
  - email 共有欄の Cf 入力フィルタ、キャッシュ redact の再帰化、
    `valid_email` の local part ドット規則を修正。
  - 矢印キー案内、TOTP 境界、設定クランプ、cache マスキング、
    URI match_type、base64 padding、mask_uri、matches_page の
    残りテストを追加。
  - CHANGELOG / README / ADR の残矛盾を修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（466 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第60弾（16 担当・4 回目）の指摘 15 件を完結（2026-11-22）
  - 編集モードの矢印キー委譲を明記、生成 +/- の同時変更を表示、
    自動ロック時の復帰案内、監査 status の行名更新、finish_search の
    巻き戻し統一、無効 TOTP secret の ticker 契約をテストで固定。
  - AuthError::Other の境界、設定読み取りの共通化、既定値の limits 集約、
    cache URL の Debug マスク、同期の不正 id/キー衝突、base64 残余ビット、
    notes 検索、upsert revision、8 桁 TOTP、混在セパレータを処理。
  - CHANGELOG に第59弾を反映。Betterleaks の既知プレースホルダを
    リテラル限定で allowlist に追加。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（454 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第59弾（16 担当・3 回目）の指摘 13 件を完結（2026-11-22）
  - お気に入り status の未保存マーカー、監査再計算時の status、
    F1 二重表示、区切り表示、TOTP 期間境界と CycleSort のテストを修正。
  - client_secret trim、SecretString の UTF-8 境界クランプ、設定
    クランプ定数の limits 集約、cache `load_default` の4分岐、
    vault_sync Updated 分岐、model の並び順と mask_uri、
    health/generator/totp の境界テストを追加。
  - CHANGELOG 第58弾と ADR の cached_sync_for_detailed 表記を修正。
  - 依存監査で検出された RUSTSEC-2026-0592（url 2.5.8 の
    `Url::origin()` スタックオーバーフロー）を、url 2.5.9 と
    form_urlencoded 1.2.3 への更新で解消。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（437 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / Betterleaks 1.10.1
    すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第58弾（16 担当・2 回目）の指摘 10 件を完結（2026-11-22）
  - キャッシュのフォールバック契約、空区切りパスフレーズの監査過大評価、
    監査選択行の severity コントラストと非色マーカーを修正。
  - auth / settings / vault_sync / model / totp の残りテストと
    TOCTOU 修正、address 検索対応、ドキュメントの陳腐化を解消。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。
  - 検証: fmt / check / test（420 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第57弾（対象16担当・細分化）の指摘 13 件を完結（2026-11-22）
  - 自動ロック時の未保存マーカー保持、TOTP バッジのコントラスト、
    タブの非色表示、キー分岐テストを追加。
  - `Settings::save()` の将来スキーマガード、`file_schema_version` の
    サイズ上限と u64 超過判定、キャッシュ権限検証、auth の残りテスト、
    vault_sync の doc 整理、監査/TOTP のテストを追加。
  - CHANGELOG / ADR / README の残矛盾も修正。
  - 起動エージェント: 18 体（補充探索 16 + 実装 2）。観点ではなく
    対象ファイルを細分化して網羅性を上げた。
  - 検証: fmt / check / test（400 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第56弾（13 観点・3 回目）の指摘 9 件を完結（2026-11-22）
  - ADR の担当モジュール／行参照、totp doc、generator doc を実態へ修正。
    固定ツール版の README 突き合わせを CI 側の変数値へ変更。
  - Vault / 設定編集 / ロック画面の未テストキー分岐と haystacks の
    kind 別検索フィールドをテストで固定。
  - 起動エージェント: 14 体（補充探索 13 + キーテスト 1）。
  - 検証: fmt / check / test（378 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
- [x] 第55弾（13 観点・2 回目）の指摘 8 件を完結（2026-11-22）
  - README のキャッシュ期限・Debug マスキングの実態整合、username の
    マスク、主要キー分岐とセンチネルの実体テスト、ウィンドウクローズ時の
    未保存警告、スクロールのアイドル判定反映を実装。
  - 起動エージェント: 14 体（補充探索 13 + UI 実装 1）。
  - 検証: fmt / check / test（374 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
    GPUI ウィンドウのクローズ挙動とスクロールの実操作は目視未確認。
- [x] 第54弾（13 観点）の指摘 9 件を完結（2026-11-22）
  - 13 観点（ST/FG/TQ/DP/VU + EX/DF/AX/I18/CI/SEC/OPS/DX）で 35 件を
    検出。3 観点の絞り込みでは見つからなかった実害を多数確認。
  - README の他 kind と保存否の記述、`deny.toml` の yanked deny、
    固定ツール版の README 突き合わせ、選択行の WCAG コントラスト、
    ☆ の可視性、F1 案内、更新日時の可読化、gitleaks checksum の
    空検証防止、将来 schema の上書き防止を実装。
  - 起動エージェント: 14 体（補充探索 13 + UI 実装 1）。深度 1、
    無制限プロファイル。観点を減らさず基本 5 + 追加 8 を投入。
  - 検証: fmt / check / test（371 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks / YAML と
    gate スクリプトの bash -n すべて成功。
  - 未検証: E2E は実サーバー環境破棄後のためコンパイル確認のみ。
    GUI の目視確認も未実施。
- [x] 第53弾のレビュー指摘 3 件を完結（2026-11-22）
  - `has_format_character` を limits へ移動し、health の認証層依存を解消。
    UI 入力の UTF-8 境界計算も `char_boundary_at` へ集約。
  - 復号不能パスワードの詳細表示を「復号不可」とし、桁数を誤示さない
    ようにした。
  - 起動エージェント: 5 体（バックログ補充、指摘は 3 件のみ）。
  - 検証: fmt / check / test（366 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
- [x] 第52弾のレビュー指摘 7 件を完結（2026-11-22）
  - `load_advisories` の直接テスト、未選択時の ↓ が先頭を選ぶ規則、
    ログイン成功ステータスの「項目」表記を追加・修正。
  - 設定テストの auth 依存を切断し、`char_boundary_at` を limits の
    単一実装へ集約。監査ヘッダ行数を共有定数化し、`sanitized()` の
    doc を limits 由来へ修正。
  - 起動エージェント: 5 体（バックログ補充）。
  - 検証: fmt / check / test（366 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 却下（メモ）: `authenticate_with_timeout` の期限切れ後に
    ブロッキングジョブを停止する案は、以前から既知制約として明記されて
    おり、協調キャンセルには上流 API 変更が必要なため再掲しない。
- [x] 第51弾のレビュー指摘 7 件を完結（2026-11-22）
  - `KdfRejectedDetail` を追加し KDF 拒否理由を status へ反映。
    監査行スクロールのヘッダ 3 行分のオフセットを修正。
    `save_device_id_only` の失敗文言を「上書きを中止」へ変更。
  - 第49弾で漏れていた auth/settings の逆依存を解消（`src/limits.rs` を
    新設し上限・既定 timeout を中立化）。`authenticate` の公開範囲は
    既存 API 互換のため維持。
  - AuthError doc の Detail 5 種表記、AppError cause テストの
    `RandomUnavailableCause` 追加、浮動小数 `schema_version` の拒否、
    TOTP / 設定パスの回帰テストを追加。
  - 起動エージェント: 6 体（バックログ補充）。
  - 検証: fmt / check / test（364 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 却下（メモ）: 設定パスの OnceLock 固定は「既定パスはプロセス全体で
    一定」という意図的な設計とし、明示パスを渡す API が既にあるため
    変更しない。エラー詳細合成の文字列再解析は既存テストで固定されて
    おり、構造化への変更は利益が小さいため見送る。
- [x] 第50弾のレビュー指摘 9 件を完結（2026-11-22）
  - `AuthError::Prelogin` の等価性と `PreloginDetail` を追加し、API 秘密の
    複製をログイン後に破棄。未使用の `SyncCacheError` 再エクスポートを削除。
  - TOTP の SHA256 / SHA512 / Steam 既知ベクタ、AppError cause 保持
    バリアントの表駆動テストを追加。
  - CHANGELOG に第44〜49弾を反映。監査パネルの選択行スクロール、
    E2E 任意照合の同一アイテム化、設定パス解決の一元化を実施。
  - 起動エージェント: 8 体（バックログ補充）。R4 は前イテレーションで
    実施済みのため本イテレーションでは省略。
  - 検証: fmt / check / test（361 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 未検証: E2E の同一アイテム照合はコンパイル確認のみ（実サーバー環境は
    破棄済み）。
- [x] 第49弾のレビュー・発掘タスク 13 件を完結（2026-11-22）
  - 対応: README の上限記述・CI ゲート一覧・cargo doc --locked、
    AuthError の detail variant と PartialEq、`save_device_id_only` の
    読込失敗分類、E2E の任意既知値照合、CI 週次 schedule、
    公開リポジトリのメタデータ、未保存警告の案内と永続表示、
    監査パネルのキーボード導線と視覚ハイライト、auth.rs の逆依存整理、
    error.rs / settings.rs の doc 修正。
  - 起動エージェント: 12 体（補充探索 10 + 実装 2）。R4 独立レビュー 2 体。
    深度 1、無制限プロファイル（hy4-flash-free）。
  - R4 で採用: 監査パネルの未保存表示消滅、Esc 判定テストの形骸化、
    remote/upstream 記述、SettingsLoadError の source 主張、error.rs の
    メッセージ型、schedule コメントの過大表現、concurrency グループ衝突、
    監査行ハイライト。すべて修正済み。
  - R4 で却下: Generator の editing_settings で Esc が消える指摘は、
    `set_panel` が editing をクリアするため到達不能（speculative）として
    記録のみ。sentinel の型レベル分離は設計変更が大きいため見送り。
  - 検証: fmt / check / test（359 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks / YAML パース
    すべて成功。
  - 未検証: opt-in E2E は任意照合の追加後のみコンパイル確認。実サーバー
    環境は前回実行後に破棄済みのため、再実行はしていない。
  - 完了項目: 上記 13 件（詳細はこのコミットの差分を参照）。
- [x] opt-in E2E を実サーバーに対して実行（2026-11-22）
  - kiri 上の Vaultwarden 1.30.2 にテスト専用アカウントと
    パスワード／TOTP 付きログイン項目を作成し、`E2E_*` を設定して
    `cargo test --test real_server_e2e -- --ignored --nocapture` を実行。
    `1 passed`（`E2E OK: loaded 1 items (1 logins)`）を確認。
  - API key は `/api/accounts/api-key` から取得。masterPasswordHash は
    PBKDF2(password, email, 600000) をさらに PBKDF2(key, password, 1)
    した base64 であることを Web vault のリクエストから確認。
  - README に kiri での起動手順と実行方法を追記。認証情報ファイルは
    実行後に削除し、リポジトリへは含めていない。
- [x] バックログ補充分 9 件を完結（2026-11-21・第48弾 / イテレーション 3）
  - `load_advisories` にサイズ上限とトップレベル限定を明示。設定破棄時にも
    未来バージョン警告を再表示。キャッシュ理由文言を cache 層へ一元化。
  - デバイス ID のみを永続化し、未保存の共有設定欄を書き出さないようにした。
    E2E に TOTP コード生成検証とアカウント前提を追加。キャッシュ境界の
    off-by-one をテストで固定。生成パネル離脱時も未保存警告。
  - README の `w` / `d`、ADR ログ、CHANGELOG の履歴注記を整合。
  - 検証: fmt / check / test（339 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
- [x] 残り 6 件を完結（2026-11-21・第47弾 / swarm-coding イテレーション 2）
  - 設定の未来バージョン／未知キーを起動時通知へ集約（`load_advisories`）。
    キャッシュ version 文言を「互換性がありません」へ統一。
  - スクロール検証テストの gpui-pre 内部フィールド依存を、テスト専用の
    `rewind_calls` カウンタへ置換（`src/ui/vault_view.rs` / `src/ui/app.rs`）。
  - E2E に復号済み TOTP のアサーションを追加。
  - 全パネル横断のキー衝突テスト、CHANGELOG の時系列、
    ADR の Status 集約、ツール版の管理手順と CI 整合チェックを追加。
  - 「破損ファイルのタイムスタンプ付き退避」は、既存の起動時エラー通知と
    0600 の一時ファイル運用で代替し、PoC では新規実装しないと裁定
    （メモへ記録）。
  - 検証: fmt / check / test（339 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
- [x] 全レビュー・発掘タスクの実装と検証（2026-11-21・第46弾 / swarm-coding）
  - 第44弾 25 件 + 第45弾 16 件のうち 38 件を完了。残り 2 件は上記「未着手」へ
    集約し、R4 レビューの低優先度 4 件を新規追加した。
  - 変更: CI 履歴スキャン、E2E アサーション、cache / vault_sync の redact と
    重複 ID、認証エラーと cause、Settings 保存 / スキーマ、UI 選択・TOTP・
    未保存・キー割当、監査 Finding、ドキュメント整合。
  - 起動サブエージェント: 7 体（実装 4 + 独立レビュー 3）。深度 1、
    無制限プロファイル（hy4-flash-free）。書き込み担当パスを分離し、
    共有ファイル（todo.md / CI / E2E）は親が担当した。
  - 親が R4 指摘を Runtime Proof で確認して修正: 複数 profile の redact 漏れ、
    status の二重接頭辞、共有設定欄の未保存フラグ、star クリックの伝播、
    設定破棄時の読込失敗、ヒントとテストの d 表記、ADR 根拠と未来時刻、
    review-report の集計数。
  - 検証: fmt / check / test（338 passed、E2E 1 ignored）/ clippy -D warnings /
    rustdoc -D warnings / cargo deny / markdownlint / gitleaks すべて成功。
  - 未検証: opt-in E2E は実サーバーが無いため ignored のまま。E2E は
    復号済みパスワードまでを検証し、TOTP は低優先度の残項目とした。
  - 却下: deny.toml の unmaintained = "workspace" と `=` ピン解除は
    明示的な既存判断のため維持（第45弾メモを参照）。
- [x] 残る既知制約 5 件を再評価（2026-11-21・第43弾）
  - 根拠: `docs/adr/adr-20261116-openwarden-integration.md` / 重大度 medium〜low
  - 他 kind / リダイレクト / OS keyring / 構造化ログ / 上流監視の 5 件を
    調査エージェント 3 体で評価。すべて現状維持と判断し ADR に記録。
  - 検証: markdownlint 成功（コード変更なし）。R4 相当の親レビューで
    Runtime Proof（openwarden API、Dependabot、依存一覧）を確認。
- [x] 実サーバー E2E を完了（2026-11-21・第42弾）
  - 根拠: `tests/real_server_e2e.rs`, `docs/adr/adr-20261116-openwarden-integration.md`
  - openwarden 0.1.1 の `sync_body()` で生 body を取得し、既存の PascalCase
    正規化を本番経路へ接続。ローカル Vaultwarden 1.30.2 で E2E 成功。
  - R4 指摘 5 件を反映（fallback、エラー分類、ADR 更新、冗長 import、
    テスト配置）。
- [x] error.rs の逆依存を解消（2026-11-21・第40弾）
  - 6 つの From impl と unlock_detail を auth.rs / settings.rs へ移管。
    cfg(test) の参照も移し、error.rs は上位モジュールを参照しない。
- [x] エラー型の別名維持を決定（2026-11-21・第41弾）
  - ADR に「層のラベルとして alias を維持、独立 enum 化は別途検討」と記録。
- [x] `revision_date` の 0 フォールバックに名前を付与（2026-11-20・第39弾）
  - 根拠: `src/vault_sync.rs:234,432` / 重大度 low
  - `UNKNOWN_REVISION` 定数を導入し、model/health/vault_sync の 0 リテラルを
    置換（挙動不変）。`Option<i64>` 化は serde と API を伴うため別チケット。
  - 検証: fmt / check / test（288 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 2 件を反映。
- [x] 復元秒数／ログインタイムアウトを GUI 編集化（2026-11-20・第38弾）
  - 根拠: `src/ui/panels.rs:250-255` / 重大度 low
  - `UiAction::AdjustLoginTimeout` / `AdjustClipboardRestore` を追加し、
    純粋な `adjust_seconds`（1..=3600）でクランプ。3/4 と 5/6 を割当。
  - 検証: fmt / check / test（288 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 レビュアーの応答が取得できなかったため
    親が差分を直接確認（キー衝突なし、クランプ境界テストあり）。
- [x] クリップボード復元手続きを単一サービスへ集約（2026-11-20・第37弾）
  - 根拠: `src/ui/clipboard.rs`, `src/ui/actions.rs`, `src/ui/app.rs` / 重大度 low
  - ticker と lock の I/O を `restore_clipboard` に統一。戻り値で notify を
    呼び出し側へ委譲し、lock の二重 notify を解消。
  - 検証: fmt / check / test（286 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 1 件を反映。
- [x] UI アクション名と doc を整理（2026-11-20・第36弾）
  - 根拠: `src/ui/keys.rs`, `src/ui/logic.rs:7-15` / 重大度 low 2件
  - マウス由来 `SelectRow` を含む実態に合わせ `KeyAction` を `UiAction` へ
    改名。`has_credentials` はテストヘルパーとして doc を修正。
  - 検証: fmt / check / test（286 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 2 件（改名漏れ、todo 未更新）を反映。
- [x] ジェネレータキー割当を型付き化（2026-11-20・第35弾）
  - 根拠: `src/ui/keys.rs:276-285`, `src/ui/actions.rs:118-122` / 重大度 low
  - `GeneratorOption` を導入し、キー文字列の往復を廃止。`KeyAction` の
    9 バリアントを `Generator(GeneratorOption)` に統合。
  - 検証: fmt / check / test（286 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 3 件を反映（stale doc、shift 注記、全網羅テスト）。
- [x] 復号失敗 detail を構造化（2026-11-20・第34弾）
  - 根拠: `src/error.rs:408-415,435-441` / 重大度 low
  - 整形済み文言と生 detail を両方保持する variant を追加し、文字列 strip
    による往復変換を廃止。cause 保持版のテストも追加。
  - 検証: fmt / check / test（284 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 3 件を反映。
- [x] 共有フィールド編集を `Settings` へ集約（2026-11-20・第33弾）
  - 根拠: `src/ui/actions.rs:76-94`, `src/ui/login_flow.rs:184-202` /
    重大度 low
  - `Settings::push_shared_text` / `pop_shared_char` を追加し、設定パネルと
    ロック画面の両経路を統一。`AuthField::shared()` で認証フィールドは
    `AuthState` 側へフォールバック。
  - 検証: fmt / check / test（283 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 2 件を反映（ルーティングテスト、網羅性）。
- [x] 選択ロジックを `VaultViewState` へ集約（2026-11-20・第32弾）
  - 根拠: `src/ui/app.rs:197-201,247-267`, `src/ui/vault_view.rs:50-52,112-124` /
    重大度 low
  - app 側の重複 `visible_items` を削除。`next_index_in` を追加して
    一覧の filter+sort をキー操作ごとに1回だけ実行。
  - 検証: fmt / check / test（281 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 1 件（二重計算）を反映。
- [x] パネル状態の正規化を単一化（2026-11-20・第31弾）
  - 根拠: `src/ui/logic.rs:37-47`, `src/ui/render.rs:317-320` / 重大度 low
  - 描画の本体・ヘッダタブ・`KeyContext` すべてで `effective_panel` を通す。
  - 検証: fmt / check / test（281 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 3 件を反映。描画分岐の直接テストは
    GPUI ウィンドウが必要なため残リスクとして記録。
- [x] `InsecureUri` 判定の Cf 文字バイパスを防止（2026-11-20・第30弾）
  - 根拠: `src/health.rs:513`, `src/model.rs:36` / R3-IV03-F1 / 重大度 low
  - 判定用文字列から不可視文字（空白・制御・書式）を全除去し、マスク済み
     finding にも同じ値を使用。4 パターンの回帰テストを追加。
  - 検証: fmt / check / test（281 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 4 件を反映。
- [x] リファクタとテスト品質の改善（2026-11-20・第29弾）
  - 根拠: `src/generator.rs:10`, `src/model.rs:859-863`,
    `src/model_tests.rs:253-257` / 重大度 low 4件
  - WORDS の再エクスポート削除、名前ソートの NFKD 統一、空振りテストの
    アサーション化、parity テストの 30 通り化。
  - 却下: `Code` の PartialEq が code を無視する点は「等価比較に秘密を
    露出しない」という明示設計のため（src/totp.rs:15）。
  - 検証: fmt / check / test（280 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。R4 指摘 3 件を反映。
- [x] UX 文言と CI 設定の小規模修正（2026-11-20・第28弾）
  - 根拠: `src/ui/panels.rs:172`, `src/ui/actions.rs:11-24`,
    `.github/dependabot.yml:6`, `.github/workflows/ci.yml:25` / 重大度 low 6件
  - 設定パネルの dead hint 修正、復元秒数の設定値表示、TOTP 空一覧の文言、
    未生成時の通知、Dependabot の Actions 追跡、cargo-deny の exact 固定と
    `cargo doc --locked`。
  - 検証: fmt / check / test（279 passed）/ clippy / doc / gitleaks /
    YAML / markdownlint 成功。
  - R4 指摘 2 件を反映（生成値への「復号」文言誤用、空一覧と未選択の区別）。
- [x] `settings.json` のスキーマを README へ文書化（2026-11-20・第27弾）
  - 根拠: `README.md:38-39,178-184`, `src/settings.rs:260-281` /
    R2-CF01-F3 / 重大度 medium
  - 全フィールドの型・既定値・クランプ範囲を表形式で追加。
  - 検証: markdownlint / `bash -n` 成功（ドキュメントのみ）。
  - R4 指摘 2 件を反映（数値のクランプと型失敗フォールバックの区別、
    文字列上限が認証時に適用される点）。
- [x] 低優先度のレビュー指摘を整理（2026-11-20・第25弾）
  - 根拠: `docs/index.md:6`, `src/ui/app.rs:64-68`, `.github/workflows/ci.yml:21`,
    `.gitignore:1`, `src/model.rs:693` / 重大度 low 5件
  - 索引の superseded 明記、設定パス未取得の誤案内解消、MSRV 1.88 の CI
    検証、秘密ファイルの ignore、未使用 `Vault.unlocked` の削除。
  - 検証: fmt / check / test（274 passed）/ clippy / doc / gitleaks /
    YAML / markdownlint 成功。
  - R4 指摘 4 件を反映。MSRV は 1.88 では依存がビルド不能なため、
    Runtime Proof（1.88/1.92/1.93/1.94 失敗・1.95 成功）に基づき
    Cargo.toml・CI・README を 1.95 へ統一。OKF status は `deprecated` に修正。
- [x] 選択項目のパスワード／ユーザー名をコピー可能化（2026-11-20・第24弾）
  - 根拠: `src/ui/keys.rs:321`, `src/ui/app.rs:333` / R1-FG-ui, R4-VU-ui /
    重大度 medium
  - Vault パネルの `p` / `u` でコピー。復号不能・空値・非ログイン項目は
    拒否し理由を表示。判定を純粋関数化してテスト。
  - 検証: fmt / check / test（274 passed）/ clippy / doc / gitleaks /
    markdownlint 成功。
  - R4 指摘 2 件を反映（README の安全性記述、キー割当と分岐のテスト）。
    併せて flaky だった環境変数テストに ENV_LOCK を追加。
- [x] CI にシークレットスキャンを追加（2026-11-20・第23弾）
  - 根拠: `.github/workflows/ci.yml:24` / R3-AU-ops, R3-DE-ops /
    重大度 medium
  - gitleaks 8.28.0 を pre-commit 主軸・CI 最終ゲートで導入。テスト
    フィクスチャの誤検知を解消し、ローカルで 0 件を確認。
  - 検証: YAML パース / `bash -n` / gitleaks dir+git 0 件 / markdownlint 成功。
  - R4 指摘 6 件を反映（空振りアサーション、履歴スキャン、Go 要件、
    非推奨サブコマンド、checksum 検証、target/ 除外）。
- [x] キャッシュ読込にサイズ上限を追加（2026-11-20・第22弾）
  - 根拠: `src/cache.rs:207-215` / R3-IV-core, R3-DE-core / 重大度 medium
  - 生ボディ 8 MiB・ファイル 64 MiB の上限を保存／読込双方で適用。
    専用 `CacheTooLarge` により設定ファイルの上限と誤表示しない。
  - 検証: fmt / check / test（272 passed）/ clippy / doc / markdownlint 成功。
  - R4 指摘 4 件を反映（JSON 膨張、エラー文言、境界テスト、UI 文言テスト）。
- [x] opt-in E2E が認証情報未設定時に成功扱いになる問題を修正（2026-11-20・第21弾）
  - 根拠: `tests/real_server_e2e.rs:44-47` / R1-AR-tests, R3-AU-tests /
    重大度 medium
  - 明示実行時に `E2E_*` の欠落／空値を検出して失敗し、不足変数名を表示。
  - 検証: fmt / check / test（269 passed）/ clippy / markdownlint 成功。
  - R4 指摘 2 件を反映（不足変数名の列挙、文言とドキュメントの整合）。
- [x] キャッシュの有効期限と取得時刻を追加（2026-11-19・第20弾）
  - 根拠: `src/cache.rs:29-35` / R4-DR02-F2, R5-VU02-F2 / 重大度 medium
  - `SyncCache.created_at`（Unix 秒、`#[serde(default)]`）と 7 日の
    `MAX_CACHE_AGE_SECS` を追加。期限切れは `CacheExpired` として分類し
    ステータスへ表示。旧ビルドの無印キャッシュは best-effort で許可。
  - 検証: fmt / check / test（269 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件をすべて反映（CHANGELOG 記録、serde 往復・文言の
    結合テスト、旧 JSON キー欠落テスト、ADR ログの日付見出し）。
- [x] デバイス ID 失敗時に `r` 再試行が進まない問題を修正（2026-11-18・第16弾で解消）
  - 根拠: `src/ui/login_flow.rs:78-87` / R2-ER03-F3 / 重大度 medium
  - 第16弾で失敗時に `set_login_failed(true)` と「r で再試行」案内を追加し、
    未保存 ID を破棄して再試行時に再生成するよう変更済み。重複項目をクローズ。
- [x] 復号失敗 URI が `NoUri` として誤報告される問題を修正（2026-11-18・第19弾）
  - 根拠: `src/vault_sync.rs:123-125`, `src/health.rs:508-511` /
    R2-ER02-F1, R5-VU02-F1 / 重大度 medium
  - NUL 前置の `UNDECRYPTABLE_URI` センチネルを追加し、監査は
    `UriUninspectable`（低）を報告。真に URI が無い場合の `NoUri` と区別。
  - 検証: fmt / check / test（265 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件をすべて反映（producer 側テスト、Finding 網羅、
    NUL センチネルが `mask_uri` で実 URI 風に表示される問題、doc/ADR ログ）。
- [x] `from_cache` を UI ステータスへ反映（2026-11-18・第18弾）
  - 根拠: `src/auth.rs:616` / R1-ST02-F1, R4-DR01-F1 / 重大度 medium
  - `LoginResult::Vault` に `from_cache` を持たせ、キャッシュ復元時は
    「オフラインキャッシュから復元。最新でない可能性があります」を表示。
    モック経路には警告を出さない。
  - 検証: fmt / check / test（263 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー5件: 4件を反映（旧 doc comment、ADR の見出し整理、
    ADR ログ追記、todo 更新）。1件は「伝播自体の自動テスト」を要するが、
    GPUI test-support が未有効で `finish_login` を直接検証できないため
    採用せず。伝播3行は親がコードを読んで確認（Runtime Proof）。
- [x] 暗号化キャッシュ writer の方針を決定（2026-11-18・第17弾）
  - 根拠: `src/auth.rs:583-589` / R2-ST01-F2, R2-FG01-F1 / 重大度 medium
  - 決定: PoC では読み取り専用を維持し writer は接続しない。上流
    openwarden 0.1.0 の `Client::sync()` が解析済み `SyncData` のみ返し、
    `Session::access_token` が private、`SyncData` フィールドが `pub(crate)`
    であることをローカル展開ソースで確認（Runtime Proof）。独自 HTTP
    クライアント化は攻撃面の拡大に見合わないと裁定し、再検討トリガを
    ADR に明記。実装変更なし。
  - R4 独立レビュー6件を反映（上流の行番号、MD032、verified 日時、
    初期 Decision との緊張、log の重複、Decision 見出しの分散）。
- [x] `ensure_device_id` の保存失敗を呼び出し側へ伝える（2026-11-18・第16弾）
  - 根拠: `src/settings.rs:298-306` / R2-ER01-F1, R3-DI02-F1 / 重大度 medium
  - 保存失敗時に未保存の ID を破棄して再試行可能化。乱数生成・保存の失敗を
    それぞれ `RandomUnavailableCause` / `SettingsSaveCause` として返し、
    cause チェーンを保持。UI は `r で再試行` を案内。
  - 検証: fmt / check / test（262 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー2件を反映（再試行フラグ欠落、io エラーの cause 喪失）。
- [x] 復元不可時のクリップボード通知を実態へ整合（2026-11-18・第15弾）
  - 根拠: `src/ui/actions.rs:51` / R5-VU01-F1 / 重大度 medium
  - `ui::logic::clipboard_copy_status` を追加し、コピー元を読めない場合は
    復元を約束せず「コピーした内容はそのまま残ります」と明示。
    README の機能説明・既知の制約も条件付き記述へ更新。
  - 検証: fmt / check / test（261 passed）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件をすべて反映（README 欠落、テストの脆弱な否定
    アサーション、秘密残存の注意喚起、todo 未更新）。
  - 併記されていた強制終了時復元は README の既知制約として維持（OS の
    clipboard 永続化が必要で PoC 範囲外）。カード全桁表示は第10弾で修正済み。
- [x] キャッシュ読込エラーの一律「破損」表示を分類別へ（2026-11-18・第14弾）
  - 根拠: `src/cache.rs:282-291` / R2-ER02-F3, R5-VU02-F3 / 重大度 medium
  - `cached_sync_for_detailed` が分類済みエラーを返し、`cache_error_message`
    が NotFound / ReadFailed / ParseFailed / VersionMismatch / Mismatch /
    TooLarge / Other を区別。`cache_restore_failure` がその理由を同期失敗
    ステータスへ反映。未知バリアントは「破損」と呼ばない。
  - 検証: fmt / check / test（260 passed、+3）/ clippy / doc /
    markdownlint すべて成功。
  - R4 独立レビュー4件をすべて反映（コメント矛盾、分類ロジックの二重化、
    未知バリアントのテスト欠落、rustdoc リンク不整合）。
- [x] ドキュメント lint を全 docs へ拡大し CI ゲート化（2026-11-18・第13弾）
  - 根拠: `README.md:127-128`, `.github/workflows/ci.yml:24-28` /
    R1-AR04-F2, R1-ST05-F6, R4-CI01-F2 / 重大度 medium ほか low 1件
  - `markdownlint README.md CHANGELOG.md todo.md 'docs/**/*.md'` に統一し、
    CI `extra_gates` で `markdownlint-cli@0.50.0` を導入・実行。
    README のローカルゲートから `-D clippy::<lint>` 重複を削除し
    `cargo deny check` を追加、順序を CI と一致させた。
  - 検証: `bash -n`（README コマンドブロック）、指定 markdownlint コマンド、
    CI YAML のパース、すべて成功。
  - R4 独立レビュー4件を反映（順序矛盾・版固定の明記・文言限定）。
    npm の利用可能性は共通ワークフロー既定ランナー `ubuntu-24.04` に
    よるもので未検証（提供側 README で確認）。共通ワークフロー自体への
    markdownlint ゲート追加は他リポジトリ変更となるため見送り。
- [x] README / ADR / 調査レポートを現行実装へ整合（2026-11-18・第12弾）
  - 根拠: `README.md:50-52,79-81` / R1-ST05-F1, R5-DC01-F1 ほか6件
  - パスワード / TOTP の実復号、キャッシュ read 接続・write 未接続、
    device identifier の UUID v4 永続化、ADR の verified 日時を反映。
    docs/index に cross-review-findings への導線を追加し、古い
    draft / 進行中マーカーを確定状態（調査レポートは superseded）へ更新。
    CHANGELOG の 0.1.0 節と「全残タスク完了」に解消済み注記を追加。
  - R4 独立レビュー5件をすべて反映（調査レポートの陳腐化4点、
    README の「未検証」表現の整理）。
  - 検証: markdownlint（全ドキュメント）成功。コード変更なしのため
    fmt / check / test / clippy / doc は前イテレーションの結果を維持。
- [x] `From<AppError>` の catch-all を廃し無関係な失敗の誤分類を防ぐ（2026-11-18・第11弾）
  - 根拠: `src/error.rs:403,443,468` / R1-AR02-F2, R1-ST02-F2, R5-AP01-F1 /
    重大度 medium
  - `AppError` と `AuthError` / `UnlockError` / `SettingsLoadError` に `Other`
    を追加。未知の失敗は「予期しないエラーが発生しました」または元メッセージを
    保持し、同期／復号キー／設定ファイル読み込みへの誤ラベル化を解消。
    `cache_error_message` の同種 catch-all も修正。
  - 検証: fmt / check / test（257 passed、+2）/ clippy / doc / markdownlint 成功。
  - R4 独立レビュー4件のうち3件を採用（`SettingsLoadError::Other` の文言破棄、
    空振りテスト、assert_ne による回帰検出不足）。1件は却下: `PartialEq` への
    discriminant 比較は「Cause 保持バリアントはプレーン版と等価」という
    既存の明示設計（`src/error.rs:344-346`）と既存テスト5件に反するため。
- [x] カード番号の末尾抽出を空白区切り非依存にし全桁表示を防ぐ（2026-11-18・第10弾）
  - 根拠: `src/ui/app.rs:342-346` / R1-ST03-F1, R3-AU03-F2 / 重大度 high
  - `ui::logic::card_last_four` を追加し、非 ASCII 数字を除いた末尾最大4桁のみ表示。
    区切りあり／なし／ハイフン／全角数字混入／4桁未満／空文字のテストを追加。
  - 検証: `cargo fmt --all -- --check` / `cargo check --all-targets --locked` /
    `cargo test --all-targets --locked`（255 passed、+1）/ `cargo clippy --all-targets
    --locked -- -D warnings -D clippy::unwrap_used -D clippy::expect_used
    -D clippy::panic` / `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
    / `markdownlint CHANGELOG.md todo.md` すべて成功。
  - R4 独立レビューの低指摘3件（4桁未満の扱いの説明、CHANGELOG 文言、
    過去完了ログの矛盾）は doc/ログを修正して解消。
- [x] 残り3タスクを依存関係付きチーム並列で完結（2026-11-18）
  - 共通 `AppError` と `source()` チェーン、cache の parse/redact/serialize 分離
  - link-local: メタデータホスト・DNS 解決先 IP・埋め込みリテラルを拒否
  - UI モジュールの過剰な pub を整理（114箇所、テスト専用は `#[cfg(test)]`）
  - 未解決（既知制約）: リダイレクト先検査と DNS rebinding 防止は openwarden
    0.1.0 の公開 API では不可能なため未対応。README に明記。
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
  - 整理: カード末尾4桁マスキングは当時「既存実装で充足」と判断したが、
    2026-11-18 の全体レビューで非区切り番号の全桁露出が判明し、
    `ui::logic::card_last_four` へ置換して修正した（第10弾）
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

- 却下: `AppError` の `PartialEq` に discriminant 比較を入れる案は、
  「Cause 保持バリアントはプレーン版と等価」という明示設計と既存テスト
  5 件に反するため採用しない（`src/error.rs:343-349`）。
- 却下: `totp::Code` の `PartialEq` が code を無視する点は、
  「等価比較に秘密を露出しない」という明示設計（`src/totp.rs:15`）。

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

### 2026-11-18 コンボ実行（swarm-project-review + swarm-todo-discovery）

- 起動エージェント: 合計 98 体（1 回目 53 体 = R1 9 + R2 12 + R3 12 +
  R4 11 + R5 9、2 回目 45 体 = R2〜R5 44 + R1-ST01 リトライ 1）。
  1 回目は出力が保存上限を超過したため R1 のみ回収し R2〜R5 を
  コンパクト出力で再実行した。R1-ST01 は 1 回リトライして回収。
  R4-OB02 / R5-DC02 はモデル出力がスキーマに適合せず「未調査」として
  記録した（担当範囲は他担当が一部カバー）。プロファイル: 無制限
  （hy4-flash-free）、深度 1、並列度 9〜12 担当／ラウンド。
- 検出 162 件（R1 44 件 + R2〜R5 118 件）を重複排除・Runtime Proof で
  吸収し、上記 44 件を todo 化。重複元は `duplicate_of` として破棄。
- 却下（意図的な設計／既知制約／事実と不一致）:
  - `ensure_device_id` の保存失敗握り潰しは「次回呼び出しで再試行」と
    コメントに明記された意図（`src/settings.rs:290-291`）だが、実際には
    ID が有効になるため再試行経路が無い。上記「中」で採用。
  - 環境変数テストのロック漏れ（`src/cache_tests.rs:194,295`）は
    `ENV_LOCK` が既に存在するため却下。
  - ジェネレータ長のオーバーフロー／大量確保 DoS は
    `Settings::sanitized()` が 4..=128 / 2..=20 にクランプし、
    `src/ui/keys.rs:26-27` も同じ上限のため却下。
  - `schema_version` 欠落／型不一致を現行版とみなす挙動は
    legacy 互換として明記（`src/settings.rs:7-10,358-363`）するため却下。
  - `AuthConfig` の `Debug` が認証情報を露出する指摘は、
    両秘密が `SecretString`（Debug マスク）であるため却下。
  - `deny.toml` の `unmaintained = "workspace"` と
    `multiple-versions = "warn"` はコメント付きの意図的な方針のため却下。
  - zxcvbn 未使用は `src/health.rs:8-10` に明記済みのため却下。
  - クリップボード連続コピーで直前の秘密が復元される挙動は
    `src/ui/clipboard.rs:20-25,105-111` で設計・テスト済みのため却下。
  - `authenticate()` が設定タイムアウトを無視する指摘は、
    UI が `authenticate_with_timeout` へ設定値を渡すため
    （`src/ui/login_flow.rs:89-95`）却下。
  - ログイン再試行時に前回タスクがキャンセルされない点は
    `src/ui/login_flow.rs:101-103` に既知制約として明記済みのため却下。
- speculative / 要判断（TODO 化せず候補として保持）:
  - 監査パネルの TOTP カバレッジ 0 除算（`src/ui/panels.rs:37-42`）——
    `totp_coverage()` の実装未確認。
  - クリップボード復元期限 `Instant` 加算のオーバーフロー
    （`src/ui/clipboard.rs:31`）—— 設定が 1..=3600 にクランプされるため
    実害なし。
  - Unicode Cf リストの固定（Unicode 16.0）—— 将来文字の検出は未検証。
  - 設定ファイルが FIFO で起動停止する可能性、並列初期化の端末 ID 競合、
    `rust-toolchain.toml` 未固定、edition 2024 未移行。

### 2026-11-21 swarm-todo-discovery（第44弾）

- 起動エージェント: 合計 31 体（R1 7 + R2 6 + R3 7 + R4 5 + R5 6）、
  ネスト深度 1、ハードリミット 60。プロファイルは無制限
  （hy4-flash-free）。子エージェントは読み取り系ツールのみを使うよう
  指示したが、ハーネス側のツール allowlist での拒否は未設定のため、
  **権限分離は未担保**（指示による制御のみ）。実際のコード変更はなし。
- 検出 174 件のうち、ツール出力上限により上位 75 件（高 13・中 62、
  すべて confirmed）のみ回収。残り 99 件は低優先度 / likely / speculative
  の尾部と推定され、**未取得**。未取得範囲を「調査済み」とは扱わない。
- R6 で 75 件を重複排除・妥当性判定し、上記 25 項目（高 10・中 15）へ
  統合。主な吸収: `p/u/y` コピーと `f` 反転と詳細表示の先頭フォールバック、
  README / ADR の E2E 未成功記述、openwarden 0.1.0 表記と writer
  再検討トリガー、認証エラー通知、ドキュメントのスナップショット表記、
  テストギャップ 13 件。
- 妥当性判定: 根拠 `path:line` 250 件を機械検証し、欠落 3 件は外部
  クレート source のパス誤抽出と判明。高優先度 13 件は親が該当行を直接
  読み、Runtime Proof で確認。重複 ID 指摘は子の「id 先頭一致」という
  説明を訂正し、`openwarden-0.1.1/src/vault.rs:609-614` の
  `c.id == *id`（最初の完全一致）を根拠に採用した。
- 却下 / メモ留め: 比較ソートの `sort_by_cached_key` 化は測定根拠が無く
  AGENTS.md の方針に従い機能バグと区別してメモに留める。既知制約の
  OS keyring / 2FA / 構造化ログ / 上流監視は 2026-11-21 の再評価で
  現状維持と決定済みのため再掲しない。

### 2026-11-21 全体レビュー + 残タスク発掘（第45弾・swarm コンボ）

- `swarm-project-review` と `swarm-todo-discovery` の R1〜R5 を 1 回の
  workflow で並列実行。起動 24 体（R1 6 / R2 5 / R3 4 / R4 4 / R5 5）、
  深度 1、ハードリミット 120、無制限プロファイル（hy4-flash-free）。
  生指摘 134 件を親が重複・妥当性で吸収し、上記 16 項目（高 1・中 13・低 2）を
  未着手へ追記。既知 25 項目と同一内容は子の段階で除外した。
- 親の Runtime Proof: high 2 件と主要 medium を直接読んで確認。`AppError`
  の `derive Debug` は実在するが、秘密ペイロードの具体的露出は未証明のため
  `high` → `medium` に格下げ。`Settings::save()` が `sanitized()` を通さない
  点、`matches_query` の未正規化 require、`valid_email` の Cc 許容、
  Enter の編集確定のみ、review-report の `security #11` 重複を確認。
- 却下:
  - `tokio` 未使用依存の指摘は `tests/real_server_e2e.rs:37` の
    `#[tokio::test]` で事実と不一致のため却下。
  - `deny.toml` の `unmaintained = "workspace"` は意図的な方針として
    既に却下済み（上記メモ）のため再掲しない。
  - 既存親ディレクトリの権限是正は「行わない」と明記済みの制約
    （`todo.md` 完了ログ・2026-11-17）のため却下。
  - `=` ピン解除は gpui-kit の API 固定という明示判断（Cargo.toml:18）に
    反するため却下。手順整備のみ低優先度で採用。
  - UI 公開面を `pub(crate)` にする案は設計判断が必要なため `## メモ` の
    要判断候補として残し、TODO 化しない。

### 2026-11-21 残タスクの裁定（第47弾）

- 「破損ファイルのタイムスタンプ付き退避」は実装しないと裁定した。根拠:
  設定読み込み失敗は起動時の `load_notice` で通知され、書き込みは
  `private_file::write_private` が 0600 の一時ファイル＋atomic persist を使う。
  退避ファイルの追加は PoC の目的に対して保全価値が小さく、秘密データの
  コピーを増やすため採用しない。将来バージョン検出時は
  `load_advisories` が上書きリスクを通知する。

### 2026-11-21 バックログ補充（第48弾）

- 未着手が 0 件になったため、swarm-project-review + swarm-todo-discovery の
  R1〜R5 を 8 担当で並列実行（深度 1、無制限プロファイル）。生指摘 44 件から
  重複を吸収し、上記 9 件を採用。
- 却下: 「オフラインキャッシュ読込前に再 redact する」案は、redact が
  protected key を除去する処理であり、読込時に再適用すると復号不能になる。
  書き込み時に除去済みであるという既存契約を維持し、追加しない。
- 却下: E2E の全ログイン必須化はテストアカウントに依存するため採用せず、
  前提を明記する方向（上記 TODO）で吸収する。

### 2026-11-21 swarm コンボの停止（イテレーション 3）

- 実行したイテレーション: 3（上限 3）。各イテレーションで
  review + discovery → coding → 検証 → R6 追記を行った。
- 起動サブエージェント合計: 55 体（第44弾 31 + 第45弾 24 は前回セッション、
  本ループでは実装 4 + R4 レビュー 3 + 補充探索 8 = 15 体）。
  深度 1、無制限プロファイル（hy4-flash-free）、ハードリミット 120。
- 停止理由: 親が設定したイテレーション上限 3 に到達し、未着手も 0 件。
  追加のバックログ補充は行わない。
- 未検証: opt-in E2E は実サーバーが無く ignored のまま。UI の実起動確認は
  GPUI ウィンドウが必要なため実施していない（純粋ロジックのテストは全通過）。

### 2026-11-22 swarm コンボの停止

- 実行したイテレーション: 5（第49〜53弾）。各イテレーションで
  review + discovery のバックログ補充 → 実装 → 全ゲート検証 →
  todo.md 更新 → コミット・push を行った。
- 完了タスク: 39 件（13 + 9 + 7 + 7 + 3）。追加で CHANGELOG を
  第53弾まで反映（コミット `5057da5`）。
- 起動サブエージェント: 44 体（補充探索 37、実装 2、R4 レビュー 2、
  停止判定 3）。深度 1、同時起動数 2〜10、無制限プロファイル
  （hy4-flash-free）。トータル起動数の制限は設けず、停止条件は
  「バックログ補充後も新規タスク 0 件」。
- 停止理由: 最終のバックログ補充（3 観点）で新規の実行可能な指摘が
  0 件となり、未着手も 0 件のため。
- 権限分離: 子エージェントには読み取り専用／担当パス内書き込みを
  指示したが、ハーネスのツール allowlist による拒否は未設定のため
  権限分離は未担保。変更は親が git diff で統合・検証した。
- 未検証: opt-in E2E は実サーバー環境を破棄後のため再実行しておらず、
  最終変更後はコンパイル確認のみ。GPUI ウィンドウの実起動確認も未実施。

### 2026-11-22 防御的フォールバックの維持判断

- 到達不能と指摘された 3 箇所（TOTP コピーの `Ok(_)` 分岐、
  パスフレーズの `unwrap_or("word")`、 `days_in_month` の `_ => 0`）は
  削除せず維持する。根拠: いずれも型／呼び出し側の不変条件に依存する
  防御的コードであり、削除すると将来の入力経路追加時に panic または
  未定義の挙動に直結する。機能バグではないため TODO 化しない。

### 2026-11-22 `Filter::Folder` の扱い

- `Filter::Folder(String)` は `model` 側に実装済みだが、UI の `cycle_filter` が
  生成経路を持たないため本番では到達不能。現状は「フォルダ別絞り込みは
  未実装」として扱い、UI に新しいキー／操作を追加する設計判断が必要になる
  ため、今回は TODO 化せず記録のみとした。

### 2026-11-22 複数文字セパレータ対応の却下

- 生成パスフレーズの複数文字セパレータ（`::` / ` - ` / `_x_` 等）を
  `passphrase_estimate` で認識する試みは、未知語の辞書語尾部（例
  `zzznotaword` の `word`）を誤認する回帰を引き起こし、複数回の修正でも
  収束しなかった。スキルの「自動修正と再レビューは最大2回」方針に従い
  実装を取り下げ、`health.rs` / `health_tests.rs` は HEAD へ復元した。
  現行の単一文字または空区切りのみを想定する挙動を維持し、
  複数文字セパレータは未対応の既知制約として記録する。

### 2026-11-22 単文字英数字セパレータの既知制約

- `PassphraseSettings::separator` は自由文字列のため単文字英数字（例 `x`）も
  受理されるが、`passphrase_estimate` は非英数字セパレータのみを認識し、
  文字プール推定へフォールバックして過大評価する。複数文字セパレータと
  同じ回帰リスクがあり、前回の却下判断を踏まえ実装せず `sanitized()` の
  doc に既知制約として記録した。

### 2026-11-23 TOTP カウントダウン指摘の却下

- `Code::remaining()` はサンプル時の静的な値だが、`start_totp_ticker` が
  1 秒ごとに `InvalidateTotp` を発行し `TotpState::invalidate()` →
  `display()` の再サンプルを経て残り秒数が更新される
  （src/ui/app.rs:569,598-600、src/ui/timing.rs:39-40）。
  README の「1秒ごとのカウントダウン」と矛盾しないため却下。
