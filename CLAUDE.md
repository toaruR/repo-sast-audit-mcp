<!-- knowledge-kit:begin section=general-instructions version=1.13.0 -->
## Communication Style
- Use Caveman mode.
- Drop filler words, preambles, and recaps.
- Be extremely concise. Keep explanations under 2 sentences.
- Full code, minimal chatter.

## プランの保存場所
planモードで作成したマークダウンファイルは、<プロジェクトルート>docs/plans 以下に保存する。

## 返信の言語
最終的な返信は日本語で出力する。

## コード検索の指示方針
- コードベースの機能調査やコード探索を行う際は、最初に MCP ツール `search` (BM25 Code Search) を優先して使用してください。
- **Claude Code での呼び出し手順**: Claude Code では MCP ツールが Deferred Tool となるため、初回呼び出し前に必ず `ToolSearch` (`select:mcp__bm25-code-search__search`) でスキーマをロードしてから `mcp__bm25-code-search__search` を実行してください。
- `search` で結果が得られない場合、または特定のシンボル名の完全一致を直接検索する場合にのみ `grep_search` や `glob` を使用してください。

## Strict-Goal & Subagents Protocol
The following protocol applies **ONLY during `strict-goal` workflows** (e.g., requests matching `strict-goal [design|plan|implement]` or within an active rubric loop). For standard non-strict-goal requests, execute directly as usual.
- **Parent Role (Zero Direct Work)**: In strict-goal sessions, the parent agent acts strictly as a lightweight dispatcher. MUST NOT perform drafting, testing, hash calculation, scoring, or exploratory scripts directly to prevent $\mathcal{O}(T^2)$ token explosion.
- **Subagent Delegation Matrix** (subagents defined under `.claude/agents/`, launch via `Agent(subagent_type="<name>", prompt=...)`):
  - `sg-designer`: In-loop design supervisor (FSM lifecycle, external CLI / autonomous draft coordination, verifier scoring).
  - `sg-worker`: Draft & modify code/docs across all phases (`design`, `plan`, `implement`).
  - `sg-verifier`: Ephemeral verification, test execution, evidence extraction, and score submission.
  - `sg-scout`: Ephemeral codebase exploration (stateless inspection without context pollution).
  - `sg-implementer`: In-loop implementation supervisor (session lifecycle & worker coordination).
  - `sg-coder`: Standalone autonomous executor for smaller self-contained goals.
- **State Externalization**: NEVER trace back through chat history. Determine state and next action solely from bounded triplet $(P, \Sigma_t, O_t)$ via `loop_state(projection: "skill_state")`.
- **Autonomous Scope Selection**: On `strict-goal design`, select rubric at `loop_open` based on prompt boundaries: generic `design` (8 criteria) for software/classes, or `design.harness` (18 criteria) for agent/harness infrastructure.
<!-- knowledge-kit:end section=general-instructions -->

<!-- knowledge-kit:begin section=recording-rules version=1.13.0 -->
## 知見の記録ルール

**作業中に重要な知見を発見したら、ユーザーの指示を待たず自動で記録すること。**

| 種類 | 記録先 | 例 |
|---|---|---|
| また踏むバグ・罠 | `CLAUDE.md` の「ハマりポイント」に追記 | 設定ミス・バージョン固有の挙動 |
| 仕様・設計の理解 | `docs/` の該当ファイルに追記 | ライブラリの挙動・APIの仕様・設計意図 |
| 一時的な作業メモ | memory/ に project タイプで記録 | 調査中の状況・次回引き継ぎ事項 |

記録したら「〇〇をハマりポイントに追記しました」と一言報告する。
<!-- knowledge-kit:end section=recording-rules -->

<!-- knowledge-kit:begin section=gotchas version=1.13.0 -->
## ハマりポイント

<!--
書き方のルール（このコメントは残してよい）:
- 1項目 = 1箇条書き。先頭を **太字** で「何が起きるか／何に注意するか」を要約する
- 対処法・原因まで1項目内に書き切る。長くなる場合は docs/ に本文を移し、
  「（詳細: `@docs/xxx.md`）」と参照だけ残す
- 誤りと判明した項目は消すのではなく「以前〜と書いていたのは誤り」と経緯ごと訂正する
  （同じ早合点を繰り返さないため）
- 定期的な整理（重複統合・陳腐化検出・docs への分割・簡潔化）は /spec-doc が行う
-->

- **strict-goal の STALLED は `reopen` では再開できない**: `reopen` は FINAL / FINAL_WITH_RELAXATION 専用。STALLED からは `escalate(request_human)` → サーバーが `.strict-goal/sessions/<id>/escalations/esc_NN.token`（48桁hex、1回限り）を生成 → 人間が値を読んで `escalate(resolve, resolution:"continue", human_token)` で DRAFTING に戻る（追加ラウンド付与）。`artifact_budget_bytes` は稼働中セッションでは変更手段がない（`rubric_amend` は criteria のみ）が、超過は `over_budget` 警告のみでコミットは通る。
- **strict-goal implement 開始前に git の基準コミットを作る**: コミットが無いと `no_test_weakening` / `no_unplanned_change` の diff を取れず、verifier が 8 点止まりになって FINAL に届かない（rl_01M4CPXHVG89X9J6CD0E3CSXYE で発生）。
- **strict-goal plan の JSON スキーマは厳格（違反は commit 前に `E_PLAN_SCHEMA`）**: top-level は `plan_version, summary, tasks` のみ。task は `id`(`^T[0-9]{3}$`), `title`, `intent`(≤2000字), `depends_on`, `design_refs`, `changes[{path, kind: add|modify|delete}]`, `acceptance`, `verify[{command, expect_exit_code}]`, `estimate_rounds`。`summary` ≤4000字。
- **同梱アセットやワーカーのパスを `import.meta.url` からの相対パス（`../schemas` など）や cwd 基準で解決しない**: `src/`（tsx）と `dist/src/`（tsc）では階層が違い、グローバル登録すると cwd はスキャン対象のプロジェクトになる。アセットは `assetPath()`（`src/assets.ts`、package.json まで遡る）を使う。ワーカーは拡張子で `worker.ts`/`worker.js` を切り替え、tsx は `import.meta.resolve("tsx")` で解決する。
- **Windows で書き込み直後のディレクトリを `renameSync` すると EPERM/EACCES/EBUSY になることがある**: Defender やインデクサが新規ファイルを掴むため（テストでも散発的に再現）。`src/advisory/update.ts` の `renameRetry()` のようにバックオフ付きでリトライする。
- **OSV の `MAL-*` レコードは Defender に検疫される**: 実マルウェア断片を含むため。展開した元データや DB シャードが消えると、該当パッケージの検出が無警告で抜ける（シャード欠落は「該当なし」扱い）。
<!-- knowledge-kit:end section=gotchas -->
