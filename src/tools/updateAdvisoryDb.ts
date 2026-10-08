import { ENV, readEnv } from "../constants.js";
import { validateInput } from "../contracts.js";
import { makeErrorEnvelope, makeResultEnvelope } from "../envelope.js";
import { McpError, isRetryable, type ErrorCode } from "../errors.js";
import { DB_ECOSYSTEMS, assertReplaceableDb, updateAdvisoryDb, type DbEcosystem, type UpdateOptions, type UpdateProgress, type UpdateResult } from "../advisory/update.js";
import type { DumpTransport } from "../net/osvClient.js";

type UpdateState = "idle" | "running" | "completed" | "failed";

export interface UpdaterDeps {
  /** Advisory DB directory (defaults to SAST_AUDIT_MCP_ADVISORY_DB). */
  dbPath?: string;
  networkAllowed?: () => boolean;
  transport?: DumpTransport;
}

/** One update at a time per server; the build runs in the background and is polled via action "status". */
export class AdvisoryDbUpdater {
  private state: UpdateState = "idle";
  private options: UpdateOptions | undefined;
  private progress: UpdateProgress | undefined;
  private result: UpdateResult | undefined;
  private error: { code: ErrorCode; message: string } | undefined;
  private startedAt: string | undefined;
  private finishedAt: string | undefined;
  private running: Promise<void> | undefined;

  constructor(private readonly deps: UpdaterDeps = {}) {}

  /** Resolves when the current update (if any) settles; for tests. */
  async settled(): Promise<void> {
    await this.running;
  }

  start(opts: UpdateOptions): boolean {
    if (this.state === "running") return false;
    const net = this.deps.networkAllowed ?? (() => ["1", "true"].includes(readEnv(ENV.ALLOW_NETWORK) ?? ""));
    if (!net()) throw new McpError("E_NETWORK_DISABLED", "network access disabled (set SAST_AUDIT_MCP_ALLOW_NETWORK=1)");
    const dir = this.deps.dbPath ?? readEnv(ENV.ADVISORY_DB);
    if (dir === undefined || dir === "") throw new McpError("E_ADVISORY_DB_MISSING", "no advisory database path configured");
    assertReplaceableDb(dir);

    this.state = "running";
    this.options = opts;
    this.progress = undefined;
    this.result = undefined;
    this.error = undefined;
    this.startedAt = new Date().toISOString();
    this.finishedAt = undefined;
    const deps = {
      onProgress: (p: UpdateProgress) => {
        this.progress = p;
      },
      ...(this.deps.transport ? { transport: this.deps.transport } : {}),
    };
    this.running = updateAdvisoryDb(dir, opts, deps).then(
      (r) => {
        this.result = r;
        this.state = "completed";
      },
      (e: unknown) => {
        // Message stays generic unless it is one of ours; raw errors may carry paths.
        this.error = e instanceof McpError ? { code: e.code, message: e.message } : { code: "E_INTERNAL", message: "advisory DB update failed" };
        this.state = "failed";
      },
    ).finally(() => {
      this.finishedAt = new Date().toISOString();
    });
    return true;
  }

  status(): Record<string, unknown> {
    const out: Record<string, unknown> = { state: this.state };
    if (this.options) out["options"] = { ecosystems: [...this.options.ecosystems], includeMalware: this.options.includeMalware };
    if (this.progress) out["progress"] = { ...this.progress };
    if (this.startedAt) out["startedAt"] = this.startedAt;
    if (this.finishedAt) out["finishedAt"] = this.finishedAt;
    if (this.result) out["result"] = { ...this.result };
    if (this.error) out["error"] = { ...this.error, retryable: isRetryable(this.error.code) };
    return out;
  }
}

/** update_advisory_db: action "start" (default) begins a rebuild unless one is running; "status" only reports. */
export function updateAdvisoryDbTool(updater: AdvisoryDbUpdater, args: unknown) {
  try {
    const v = validateInput("update_advisory_db", args ?? {});
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    const a = (args ?? {}) as { action?: "start" | "status"; ecosystems?: DbEcosystem[]; includeMalware?: boolean };
    let started = false;
    if ((a.action ?? "start") === "start") {
      started = updater.start({ ecosystems: a.ecosystems ?? [...DB_ECOSYSTEMS], includeMalware: a.includeMalware ?? true });
    }
    return makeResultEnvelope({ ...updater.status(), started });
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL", "internal error");
  }
}
