---
type: Report
title: "残タスク・機能追加案の調査レポート"
description: "エージェントチームによる5パスの調査と6回目の統合で得た残タスク・機能追加案の優先度付き一覧"
tags:
  - investigation
  - roadmap
  - remaining-tasks
  - bitwarden
  - gpui
generated:
  by: "dsh-agent (lead)"
  at: "2026-11-17T21:01:35+09:00"
verified:
  by: "dsh-agent (lead)"
  at: "2026-11-17T21:01:35+09:00"
status: "draft"
stale_after: "2027-05-17T21:01:35+09:00"
---

## 概要

未知の残タスク・機能追加案を洗い出すため、エージェントチームを10体起動して
調査した。観点を変えた5パスの調査で42件の候補を収集し、6回目のパスで
重複を吸収して34件へ統合、さらに保持した25件を2体のエージェントと
親エージェントの Runtime Proof で検証した。

結果は keep 25件 / defer 8件 / reject 1件。優先度は
P0 4件 / P1 7件 / P2 19件 / P3 4件。
検証では31件が confirmed、2件が partially-confirmed だった。

## 調査方法

- パス1: ソースコードの未実装・スタブ・ギャップ（lib 側 / UI 側） — 2体
- パス2: ドキュメント・レビュー・ADR の未解決事項の再評価 — 1体
- パス3: 上流 Bitwarden / 他クライアントとの機能比較（Web 調査） — 2体
- パス4: セキュリティ・堅牢性の残タスク（敵対的視点） — 1体
- パス5: 依存クレートの鮮度と新 API による可能性（Web 調査） — 1体
- パス6: 重複吸収・妥当性判定・優先度付け — 1体
- 検証: 保持候補のエビデンス確認（ローカル / Web 一次情報） — 2体

6回目の統合では dedup_key と内容類似で重複をマージした。
主な吸収: offline-cache 3→1、2FA/組織 3→1、os-keyring 2→1、
login-race 2→1、item-kind 2→1、license 2→1。

## P0: 最優先（今すぐ対応）

### Shift+Y が Linux で発火せず password がコピーされる

- 根拠: `src/ui/keys.rs:199-200`、`src/ui/input.rs:22`、`README.md:81`
- `classify_key` は `"Y"` を見るが、`input.rs` は `event.keystroke.key` のみを渡す。
  Linux の GPUI はキーを小文字化し Shift 文字を `key_char` に保持するため、
  `"Y"` 分岐は到達不能。README が案内する passphrase コピーができず、
  直前に生成した password が誤ってコピーされる。
- 対処: `key_char` または `modifiers.shift` を `KeyContext` へ渡して判定する。

### Space キーがいずれのテキスト入力にも入らない

- 根拠: `src/ui/input.rs:22`、`src/ui/keys.rs:147-148,152-157,173-179,215-223`
- 入力は `key.chars().count() == 1` の場合のみ挿入されるが、Linux の GPUI は
  Space をキー名 `"space"`（5文字）として渡す。結果、空白を含むマスターパスワード
  では実ログインが不能で、複数語の検索もできない。
- 対処: `key_char` を使う、または `"space"` を空白文字へ明示的に変換する。

### 実ログイン成功後に監査レポートが生成されない

- 根拠: `src/ui/login_flow.rs:70-85`、`109-113`、`src/ui/keys.rs:248`、`README.md:69,76`
- モックを開く `unlock_mock` は `refresh_audit()` を呼ぶが、実認証の
  `finish_login` は呼ばない。実ログイン後は `audit_report` が None のままで、
  `g` キーも `[監査]` ボタンも静かに機能しない。
- 対処: `finish_login` の成功時に `refresh_audit()` を呼ぶ。

### ログイン試行の再入・世代管理欠如

- 根拠: `src/ui/login_flow.rs:25-53,56-87`、`src/ui/keys.rs:159-163,243`、`src/ui/app.rs:14`
- 認証は `.detach()` で非同期実行されるが、試行中フラグも世代番号も無い。
  待機中の再 Enter で並行ログインが走り、開始直後の `l` ロックや `m` モック
  遷移を遅延完了が上書きする。ロック保証の破綻につながる。
- 対処: in-flight ガードと試行世代番号を導入し、古い完了を破棄する。

## P1: 短期

- オフラインキャッシュの認証フロー接続
  - 根拠: `src/cache.rs:70-106,178-182`、`src/auth.rs:293`
  - 根拠: `docs/adr/adr-20261116-openwarden-integration.md:93-97`
- 実サーバー（Vaultwarden）接続の E2E 検証
  - 根拠: `docs/adr/adr-20261116-openwarden-integration.md:89`、`README.md:12`
- link-local 遮断が DNS 名をすり抜ける（SSRF）
  - 根拠: `src/auth.rs:104-125,154-157`
- ログイン成功後も秘密が AuthState に残存
  - 根拠: `src/ui/login_flow.rs:56-87`、`src/ui/auth_state.rs:104-112`
- 予測可能な `.tmp` 名とシンボリックリンク追従
  - 根拠: `src/private_file.rs:14-20,37-45,52-57`
- Debug／詳細表示のマスキング漏れ
  - 根拠: `src/model.rs:185-195,278-294,378-381`、`src/ui/app.rs:276-280`
- `Settings::sanitized()` が thresholds をクランプしない
  - 根拠: `src/settings.rs:106-114,127-137`、`src/health.rs:201-218`

補足:

- キャッシュは `from_body` / `load_detailed` / `save` が実装済みだが、
  認証フローからの呼び出しがゼロ（read / write 双方とも未接続）。
  `client.sync()` は生 body を返さず、`Session::access_token` も private。
- SSRF は `url.host()` が `Host::Domain` のとき常に false を返すため、
  `169.254.169.254.nip.io` 等の DNS 名でバイパスできる。
- `clear_secrets()` は `lock()` からのみ呼ばれ、`finish_login` の成功パスで
  呼ばれない。zeroize の限界（既知制約）とは別の具体的な呼び出し漏れ。

## P2: 中長期（保持）

### UI・機能

- 選択項目の詳細が1行に圧縮され kind 固有情報が非表示
  - 根拠: `src/ui/app.rs:233-284`、`src/ui/render.rs:203-212`
- 監査指摘から該当アイテムへジャンプできない
  - 根拠: `src/ui/panels.rs:11-67`、`src/ui/app.rs:287-293`
- ログイン項目の URI を開く／コピーする操作が無い
  - 根拠: `src/ui/app.rs:266-271`、`src/ui/keys.rs:41-116`
- 入力行がマウスでフォーカスできない
  - 根拠: `src/ui/panels.rs:69-84,158-188,265-304`、`README.md:75-76`
- パネル間のキーボード直接移動がマウスと非対称
  - 根拠: `src/ui/keys.rs:183-238`、`src/ui/render.rs:237-284`
- 設定パネルの「n キーで編集」ヒントが dead hint
  - 根拠: `src/ui/panels.rs:216-219`、`src/ui/keys.rs:225-237,249`
- 他 item kind を実データへ変換
  - 根拠: `README.md:41,132`
  - 根拠: `docs/adr/adr-20261116-openwarden-integration.md:67,90`

### 運用・ドキュメント・依存

- 構造化ログを認証フローへ限定導入（見送り理由の再評価）
  - 根拠: `README.md:136`、`docs/review-report.md:49-50,60-64`
- device identifier をインストールごとに一意化
  - 根拠: `README.md:135`、`docs/adr/adr-20261116-openwarden-integration.md:91`
- MPL-2.0 推移依存と AGPL-3.0 の互換性評価を決着
  - 根拠: `docs/review-report.md:70-73`
  - 根拠: `Cargo.lock:851-866,1462-1471,4671-4674`
- ADR の Implementation Result を現行実装へ更新
  - 根拠: `docs/adr/adr-20261116-openwarden-integration.md:82-91`、`README.md:60`
- gpui-kit 0.10.0 への更新
  - 根拠: `Cargo.toml:18-19`
  - 根拠: [gpui-kit v0.10.0](https://github.com/longbridge/gpui-kit/releases/tag/v0.10.0)
- README の cargo audit / doc 順序の矛盾を解消
  - 根拠: `README.md:97-98,110`
- 依存更新監視を自動化
  - 根拠: `Cargo.toml:18-21`
  - 根拠: [crates.io index](https://raw.githubusercontent.com/rust-lang/crates.io-index/master/gp/ui/gpui-kit)

## 見送り・却下

- defer: OS keyring 連携
  - PoC 目的への直結が弱く high effort。秘密残存とキャッシュ配線を先に解消。
- defer: KDF の smol::unblock をキャンセル不能
  - 再現未検証。実接続 E2E で遅いサーバーの再現を確認してから判断。
- defer: 復号・vault 変換の UI スレッド同期実行
  - 停止時間が未計測。E2E で実 vault 規模の所要時間を計測してから判断。
- defer: 2FA / 組織 vault のアップストリーム追従
  - 上流未実装で 0.1.0 が最新。0.2 の changelog 監視へ組み込む。
- defer: openwarden の書き込み API 未利用
  - high effort。read 側の完全接続と実接続検証を先に片付ける。
- defer: repository / homepage メタデータ
  - git remote 空・upstream 未設定で値が確定しない。
- defer: テスト・型の整理残り
  - 設計変更を伴う型境界再設計は PoC 目的に直結しない。
- defer: Searchable Select 等の UI 採用
  - 前提となる gpui-kit 0.10.0 更新の検証が未完了。
- reject: 秘密の平文一時コピーが zeroize 対象外
  - 既知制約の再掲で新規価値なし。具体的な呼び出し漏れ項目へ吸収。

## 妥当性の吸収（6回目の統合と検証で訂正された点）

- オフラインキャッシュ: 統合時は「read 側は配線済み、未接続は write 側のみ、
  ADR の『sync body 未公開』前提は陳腐化」としていた。しかし検証エージェントと
  親の Runtime Proof で、`cache::load` / `save` / `from_body` の callers が
  `cache.rs` 外にゼロであること、`client.sync()` が生 body を返さず
  `access_token` も private であることを確認した。
  よって「read / write 双方とも未接続、ADR の結論は維持」へ訂正した。
- gpui-kit 0.10.0: 統合時の「破壊的変更は2件」はリリースノート上3件目
  （`gpui-fast` の `IntoElement`）があり literal には不正確。
  ただし標準の `gpui-pre` には無影響で、本 PoC への影響評価は変わらない。
  更新後の fmt / check / test / clippy / 実起動検証は未実施。

## 検証

候補25件に対する2エージェントの検証結果は confirmed 31件 /
partially-confirmed 2件（上記の訂正2件）だった。
親エージェントは P0 4件について `src/ui/keys.rs`、`src/ui/input.rs`、
`src/ui/login_flow.rs` を直接読み、根拠を確認した（Runtime Proof）。
また訂正点について `src/vault_sync.rs`、`src/cache.rs`、`src/auth.rs` と
`src` 全体の参照検索で裏取りした。
`cargo test --all-targets --locked` は137件成功（検証エージェントが確認）。

## 参照

- [設計記録・レビュー結果](index.md)
- [openwarden 統合 ADR](adr/adr-20261116-openwarden-integration.md)
- [全体敵対的レビュー結果](review-report.md)
- [openwarden (crates.io)](https://crates.io/crates/openwarden)
- [gpui-kit v0.10.0 Release Notes](https://github.com/longbridge/gpui-kit/releases/tag/v0.10.0)
