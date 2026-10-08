<!-- knowledge-kit:begin section=agents-entry version=1.13.0 -->
# AGENTS.md

## 最重要: CLAUDE.md を必ず先に読むこと
このプロジェクトのすべてのルール（メモリーシステム・プランの保存場所・開発規約など）は **`CLAUDE.md` がプライマリです。**
タスクを開始する前に `CLAUDE.md` を読み、その指示に従ってください。

## Skills
- `.claude/skills/` および `.agents/skills/` ディレクトリ配下に、特定のタスク（コミットなど）を実行するための詳細な手順やルールが `SKILL.md`（Markdown 形式）で定義されています。Claude Code・Codex CLI はこれらを自動的に発見します。これらのタスクを依頼された、もしくは実行する際は、必ず事前に対応する `SKILL.md` を読み込み、その指示や手順に従ってください。
- Detailed instructions and rules for executing specific tasks (such as committing) are defined as `SKILL.md` files (Markdown) under the `.claude/skills/` and `.agents/skills/` directories. Claude Code and Codex CLI discover these automatically. When you are asked to perform these tasks or need to execute them, make sure to read the corresponding `SKILL.md` beforehand and follow its instructions.

## Strict-Goal & Subagents Protocol
The following protocol applies **ONLY during `strict-goal` workflows** (e.g., requests matching `strict-goal [design|plan|implement]` or within an active rubric loop). For standard non-strict-goal requests, execute directly as usual.
- **Parent Role (Zero Direct Work)**: In strict-goal sessions, the parent agent acts strictly as a lightweight dispatcher. MUST NOT perform drafting, testing, hash calculation, scoring, or exploratory scripts directly to prevent $\mathcal{O}(T^2)$ token explosion.
- **Subagent Delegation Matrix** (subagents defined under `.agents/agents/`):
  - `sg-designer`: In-loop design supervisor (FSM lifecycle, external CLI / autonomous draft coordination, verifier scoring).
  - `sg-worker`: Draft & modify code/docs across all phases (`design`, `plan`, `implement`).
  - `sg-verifier`: Ephemeral verification, test execution, evidence extraction, and score submission.
  - `sg-scout`: Ephemeral codebase exploration (stateless inspection without context pollution).
  - `sg-implementer`: In-loop implementation supervisor (session lifecycle & worker coordination).
  - `sg-coder`: Standalone autonomous executor for smaller self-contained goals.
- **State Externalization**: NEVER trace back through chat history. Determine state and next action solely from bounded triplet $(P, \Sigma_t, O_t)$ via `loop_state(projection: "skill_state")`.
- **Autonomous Scope Selection**: On `strict-goal design`, select rubric at `loop_open` based on prompt boundaries: generic `design` (8 criteria) for software/classes, or `design.harness` (18 criteria) for agent/harness infrastructure.
<!-- knowledge-kit:end section=agents-entry -->
