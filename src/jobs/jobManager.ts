import { Worker } from "node:worker_threads";
import { ENV, readEnv } from "../constants.js";
import type { Finding } from "../findings/identity.js";
import { riskRating, riskScore } from "../scoring.js";
import type { RunSpec, WorkerDone, WorkerMessage, WorkerProgress } from "./worker.js";
import { createHash } from "node:crypto";
import { CANCEL_DRAIN_MS, DEFAULT_OPTIONS, JOB_KEEP, LIMITS, MAX_QUEUED, MAX_RUNNING } from "../constants.js";
import { McpError, type ErrorCode } from "../errors.js";
import type { Warning } from "../pipeline/warnings.js";
import { CancelController, type Clock } from "./cancelController.js";
import { TERMINAL_STATES, type JobState } from "./stateMachine.js";

/** Legacy launcher result shape (T002 skeleton); only filesScanned is read. */
export interface StubResult {
  filesScanned: number;
  threadId: number;
  osvCalls: number;
}

export interface Progress {
  filesScanned: number;
  bytesScanned: number;
  findingsSoFar: number;
}

export interface Summary {
  total: number;
  bySeverity: Record<string, number>;
  byScanner: Record<string, number>;
  riskScore: number;
  riskRating: string;
  truncated: boolean;
}

export type LaunchResult = Partial<Omit<WorkerDone, "type">> & { filesScanned?: number };

export type StubState = JobState;

export interface Job {
  scanId: string;
  repoPath: string;
  requestKey: string;
  readonly state: JobState;
  readonly error?: ErrorCode | undefined;
  warnings: Warning[];
  /** Findings generation: starts at 0, +1 per findings commit, frozen once terminal. */
  generation: number;
  readonly cancelRequested: boolean;
  readonly durationMs: number;
  progress: Progress;
  findings: Finding[];
  truncated: boolean;
  summary?: Summary;
  strictLimits: boolean;
  /**
   * Records the worker thread id that ran the scan so T002 can verify thread isolation
   * (worker threadId differs from the main thread). Internal only: must never appear in
   * tool outputs (get_scan_status, findings, reports).
   */
  stubResult?: StubResult;
  /** Resolves once the job reached a terminal state. */
  done: Promise<void>;
}

export interface StubStatus {
  error?: ErrorCode | undefined;
  scanId: string;
  state: JobState;
  progress: Progress;
  cancelRequested: boolean;
  truncated: boolean;
  summary?: Summary | undefined;
}

/** Normalized scan request (design 3.2); everything that feeds the requestKey. */
export interface ScanRequest {
  scanners: readonly string[];
  options: Record<string, unknown>;
  dbManifestSha256: string;
  rulesetHash: string;
  serverVersion: string;
}

export interface SubmitResult {
  job: Job;
  reused: boolean;
}

/** Runs one admitted job; the default launcher starts the skeleton stub Worker. */
export type Launcher = (
  repoPath: string,
  spec?: RunSpec,
  onProgress?: (p: WorkerProgress) => void,
  signal?: AbortSignal,
) => Promise<LaunchResult>;

export function buildSummary(findings: readonly Finding[], truncated: boolean): Summary {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byScanner: Record<string, number> = { dependency: 0, secret: 0, static: 0, config: 0 };
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byScanner[f.scanner] = (byScanner[f.scanner] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byScanner, riskScore: riskScore(findings), riskRating: riskRating(findings), truncated };
}

export const ALL_SCANNERS = ["dependency", "secret", "static", "config"] as const;

export const DEFAULT_REQUEST: ScanRequest = {
  scanners: ALL_SCANNERS,
  options: DEFAULT_OPTIONS as unknown as Record<string, unknown>,
  dbManifestSha256: "",
  rulesetHash: "",
  serverVersion: "0.1.0",
};

function canon(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canon);
  if (v !== null && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) o[k] = canon(x);
    }
    return o;
  }
  return v;
}

/** SHA-256 hex of {repoRealPath, sorted scanners, options with defaults, DB manifest sha256, rulesetHash, serverVersion}. */
export function computeRequestKey(repoRealPath: string, req: ScanRequest): string {
  const payload = canon({
    repoRealPath,
    scanners: [...req.scanners].sort(),
    options: req.options,
    dbManifestSha256: req.dbManifestSha256,
    rulesetHash: req.rulesetHash,
    serverVersion: req.serverVersion,
  });
  return createHash("sha256").update(JSON.stringify(payload), "utf8").digest("hex");
}

function workerLauncher(repoPath: string, spec?: RunSpec, onProgress?: (p: WorkerProgress) => void, signal?: AbortSignal): Promise<LaunchResult> {
  return new Promise<LaunchResult>((resolve, reject) => {
    const abortFlag = new SharedArrayBuffer(4);
    const worker = new Worker(new URL("./worker.ts", import.meta.url), {
      execArgv: ["--import", "tsx"],
      workerData: { ...(spec ?? { scanners: ALL_SCANNERS, options: DEFAULT_OPTIONS }), repoPath, abortFlag },
    });
    // Abort: raise the shared flag (the worker polls it); a worker that does not drain is terminated.
    signal?.addEventListener(
      "abort",
      () => {
        Atomics.store(new Int32Array(abortFlag), 0, 1);
        setTimeout(() => void worker.terminate(), CANCEL_DRAIN_MS).unref();
      },
      { once: true },
    );
    let got = false;
    worker.on("message", (msg: WorkerMessage) => {
      if (msg.type === "progress") onProgress?.(msg);
      else {
        got = true;
        resolve(msg);
      }
    });
    worker.once("error", (e) => reject(e));
    worker.once("exit", () => {
      if (!got) reject(new Error("worker exited without result"));
    });
  });
}

// Job registry: submit steps 5-7 (reuse, capacity, create) of design 3.2; lifecycle via CancelController.
export class JobManager {
  private readonly jobs = new Map<string, Job>();
  private readonly ctls = new Map<string, CancelController>();
  private readonly resolvers = new Map<string, () => void>();
  private readonly settled = new Set<string>();
  private readonly pendingStart: Array<{ job: Job; start: () => void }> = [];
  private readonly finished: string[] = [];
  private counter = 0;
  private running = 0;

  constructor(private readonly launcher: Launcher = workerLauncher) {}

  private queuedCount(): number {
    return this.pendingStart.length;
  }

  private clockFor(getJob: () => Job): Clock {
    return {
      now: () => Date.now(),
      setTimeout: (fn, ms) => {
        const h = setTimeout(() => {
          fn();
          this.settle(getJob());
        }, ms);
        h.unref();
        return h;
      },
      clearTimeout: (h) => clearTimeout(h as NodeJS.Timeout),
    };
  }

  /** Once a job is terminal: record it as finished, evict old ones, resolve job.done. */
  private settle(job: Job): void {
    if (!TERMINAL_STATES.includes(job.state) || this.settled.has(job.scanId)) return;
    this.settled.add(job.scanId);
    this.finished.push(job.scanId);
    this.evict();
    this.resolvers.get(job.scanId)?.();
  }

  /** Steps 5-7: reuse, capacity, create. Throws E_LIMIT_EXCEEDED when the queue is full. */
  submitRequest(repoPath: string, req: ScanRequest = DEFAULT_REQUEST, force = false, warnings: Warning[] = [], dbPath?: string): SubmitResult {
    const requestKey = computeRequestKey(repoPath, req);
    if (!force) {
      for (const j of this.jobs.values()) {
        if (j.requestKey === requestKey && (j.state === "queued" || j.state === "running")) {
          return { job: j, reused: true };
        }
      }
    }
    if (this.running >= MAX_RUNNING && this.queuedCount() >= MAX_QUEUED) {
      throw new McpError("E_LIMIT_EXCEEDED", "job queue is full");
    }
    this.counter += 1;
    const scanId = `S-${requestKey.slice(0, 12)}-${this.counter}`;
    const limits = (req.options["limits"] ?? {}) as Record<string, unknown>;
    const timeoutMs = typeof limits["timeoutMs"] === "number" ? limits["timeoutMs"] : LIMITS.timeoutMs.default;
    const holder: { job?: Job } = {};
    const ctl = new CancelController({ clock: this.clockFor(() => holder.job as Job), timeoutMs });
    const job: Job = {
      scanId,
      repoPath,
      requestKey,
      warnings,
      progress: { filesScanned: 0, bytesScanned: 0, findingsSoFar: 0 },
      findings: [],
      truncated: false,
      strictLimits: req.options["strictLimits"] === true,
      generation: 0,
      done: Promise.resolve(),
      get state() {
        return ctl.state;
      },
      get error() {
        return ctl.error;
      },
      get cancelRequested() {
        return ctl.cancelRequested;
      },
      get durationMs() {
        return ctl.durationMs;
      },
    };
    holder.job = job;
    this.jobs.set(scanId, job);
    this.ctls.set(scanId, ctl);
    job.done = new Promise<void>((resolve) => {
      this.resolvers.set(scanId, resolve);
      const start = (): void => {
        this.running += 1;
        ctl.start();
        const spec: RunSpec = { repoPath, scanners: req.scanners, options: req.options, dbPath: dbPath ?? (readEnv(ENV.ADVISORY_DB) || undefined) };
        this.launcher(
          repoPath,
          spec,
          (p) => {
            if (p.filesScanned >= job.progress.filesScanned) {
              job.progress = { filesScanned: p.filesScanned, bytesScanned: p.bytesScanned, findingsSoFar: p.findingsSoFar };
            }
          },
          ctl.abortController.signal,
        )
          .then(
            (res) => this.finish(job, ctl, res),
            () => ctl.workerFailed(),
          )
          .finally(() => {
            this.running -= 1;
            this.settle(job);
            this.pendingStart.shift()?.start();
          });
      };
      if (this.running < MAX_RUNNING) start();
      else this.pendingStart.push({ job, start });
    });
    return { job, reused: false };
  }

  private finish(job: Job, ctl: CancelController, res: LaunchResult): void {
    if (job.state !== "running") return; // late output after a terminal state is dropped
    if (res.threadId !== undefined) job.stubResult = { filesScanned: res.filesScanned ?? 0, threadId: res.threadId, osvCalls: 0 };
    const findings = res.findings ?? [];
    const filesScanned = res.filesScanned ?? job.progress.filesScanned;
    job.progress = { filesScanned, bytesScanned: res.bytesScanned ?? job.progress.bytesScanned, findingsSoFar: findings.length };
    if (res.capHit === true && job.strictLimits) {
      ctl.strictCap();
      if (job.state !== "running") return;
    }
    job.findings = findings;
    job.truncated = res.truncated === true;
    if (res.warnings) job.warnings = [...job.warnings, ...res.warnings];
    job.summary = buildSummary(findings, job.truncated);
    ctl.workerEnded();
  }

  /**
   * cancel_scan: queued jobs cancel at once, running jobs start draining, terminal jobs are a no-op
   * (answered here, before any transition).
   */
  cancel(scanId: string): { state: JobState; cancelRequested: boolean } | undefined {
    const job = this.jobs.get(scanId);
    const ctl = this.ctls.get(scanId);
    if (!job || !ctl) return undefined;
    if (!TERMINAL_STATES.includes(job.state)) {
      const i = this.pendingStart.findIndex((p) => p.job === job);
      if (i >= 0) this.pendingStart.splice(i, 1);
      ctl.cancel();
      this.settle(job);
    }
    return { state: job.state, cancelRequested: job.cancelRequested };
  }

  /** Drops the oldest finished jobs beyond JOB_KEEP. */
  private evict(): void {
    while (this.finished.length > JOB_KEEP) {
      const id = this.finished.shift();
      if (id !== undefined) {
        this.jobs.delete(id);
        this.ctls.delete(id);
        this.resolvers.delete(id);
        this.settled.delete(id);
      }
    }
  }

  getJob(scanId: string): Job | undefined {
    return this.jobs.get(scanId);
  }

  /** Records one findings commit: generation +1 while the job is not terminal. */
  commitFindings(scanId: string): number | undefined {
    const job = this.jobs.get(scanId);
    if (!job) return undefined;
    if (!TERMINAL_STATES.includes(job.state)) job.generation += 1;
    return job.generation;
  }

  /** Skeleton entry point kept for the stub server/tests. */
  submit(repoPath: string): Job {
    return this.submitRequest(repoPath).job;
  }

  getStatus(scanId: string): StubStatus | undefined {
    const job = this.jobs.get(scanId);
    if (!job) return undefined;
    return {
      scanId,
      state: job.state,
      progress: { ...job.progress },
      cancelRequested: job.cancelRequested,
      truncated: job.truncated,
      summary: job.summary,
      error: job.error,
    };
  }
}
