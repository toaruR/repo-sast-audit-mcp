import { CANCEL_DRAIN_MS } from "../constants.js";
import type { ErrorCode } from "../errors.js";
import { transition, type JobEvent, type JobState, type TransitionJob } from "./stateMachine.js";

export interface Clock {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface CancelControllerOptions {
  clock: Clock;
  timeoutMs: number;
  abortController?: AbortController;
}

type Pending = "cancel" | "timeout" | undefined;

// Drives transition() for one job (design sections 3.2/3.3/6). First processed event wins.
export class CancelController {
  readonly abortController: AbortController;
  private readonly clock: Clock;
  private readonly timeoutMs: number;
  private job: TransitionJob = { state: "queued" };
  private pending: Pending;
  private startedAt = 0;
  private endedAt = 0;
  private timeoutHandle: unknown;
  private drainHandle: unknown;
  private aborted = false;
  cancelRequested = false;

  constructor(opts: CancelControllerOptions) {
    this.clock = opts.clock;
    this.timeoutMs = opts.timeoutMs;
    this.abortController = opts.abortController ?? new AbortController();
  }

  get state(): JobState {
    return this.job.state;
  }

  get error(): ErrorCode | undefined {
    return this.job.error;
  }

  get durationMs(): number {
    if (this.job.state === "queued") return 0;
    return (this.isTerminal() ? this.endedAt : this.clock.now()) - this.startedAt;
  }

  private isTerminal(): boolean {
    return this.job.state !== "queued" && this.job.state !== "running";
  }

  private abort(): void {
    if (this.aborted) return;
    this.aborted = true;
    this.abortController.abort();
  }

  private finish(event: JobEvent): void {
    this.job = transition(this.job, event);
    this.endedAt = this.clock.now();
    this.clearTimers();
  }

  private clearTimers(): void {
    if (this.timeoutHandle !== undefined) this.clock.clearTimeout(this.timeoutHandle);
    if (this.drainHandle !== undefined) this.clock.clearTimeout(this.drainHandle);
    this.timeoutHandle = undefined;
    this.drainHandle = undefined;
  }

  /** queued + slot -> running; arms the timeout timer. */
  start(): void {
    this.job = transition(this.job, "slot");
    this.startedAt = this.clock.now();
    this.timeoutHandle = this.clock.setTimeout(() => this.onTimeout(), this.timeoutMs);
  }

  private beginDrain(kind: "cancel" | "timeout"): void {
    this.pending = kind;
    this.abort();
    if (this.timeoutHandle !== undefined) this.clock.clearTimeout(this.timeoutHandle);
    this.timeoutHandle = undefined;
    this.drainHandle = this.clock.setTimeout(() => {
      if (this.job.state === "running") {
        this.finish(kind === "cancel" ? "cancelDrainExpired" : "timeoutDrainExpired");
      }
    }, CANCEL_DRAIN_MS);
  }

  private onTimeout(): void {
    this.timeoutHandle = undefined;
    if (this.job.state !== "running" || this.pending) return;
    this.beginDrain("timeout");
  }

  cancel(): void {
    if (this.isTerminal()) return;
    this.cancelRequested = true;
    if (this.job.state === "queued") {
      this.job = transition(this.job, "cancel");
      this.startedAt = this.endedAt = this.clock.now();
      return;
    }
    if (this.pending) return;
    this.beginDrain("cancel");
  }

  /** Worker finished its work (or drained after abort). */
  workerEnded(): void {
    if (this.job.state !== "running") return;
    if (this.pending === "cancel") this.finish("cancelDrained");
    else if (this.pending === "timeout") this.finish("timeoutDrained");
    else this.finish("done");
  }

  workerFailed(): void {
    if (this.job.state !== "running" || this.pending) return;
    this.finish("internalError");
  }

  strictCap(): void {
    if (this.job.state !== "running" || this.pending) return;
    this.finish("strictCap");
  }
}
