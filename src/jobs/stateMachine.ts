import type { ErrorCode } from "../errors.js";

export type JobState = "queued" | "running" | "completed" | "failed" | "cancelled" | "timed_out";

export type JobEvent =
  | "slot"
  | "cancel"
  | "done"
  | "internalError"
  | "strictCap"
  | "cancelDrained"
  | "cancelDrainExpired"
  | "timeoutDrained"
  | "timeoutDrainExpired";

export const ALL_STATES: readonly JobState[] = ["queued", "running", "completed", "failed", "cancelled", "timed_out"];
export const ALL_EVENTS: readonly JobEvent[] = ["slot", "cancel", "done", "internalError", "strictCap", "cancelDrained", "cancelDrainExpired", "timeoutDrained", "timeoutDrainExpired"];
export const TERMINAL_STATES: readonly JobState[] = ["completed", "failed", "cancelled", "timed_out"];

export interface TransitionJob {
  state: JobState;
  error?: ErrorCode;
}

// Design section 6 table (complete 6-row table). Pure: returns a new object, never mutates input.
export function transition(job: TransitionJob, event: JobEvent): TransitionJob {
  const next = (state: JobState, error?: ErrorCode): TransitionJob => ({ ...job, state, error });
  if (job.state === "queued") {
    if (event === "slot") return next("running");
    if (event === "cancel") return next("cancelled", "E_CANCELLED");
  } else if (job.state === "running") {
    if (event === "done") return next("completed");
    if (event === "internalError") return next("failed", "E_INTERNAL");
    if (event === "strictCap") return next("failed", "E_LIMIT_EXCEEDED");
    if (event === "cancelDrained" || event === "cancelDrainExpired") return next("cancelled", "E_CANCELLED");
    if (event === "timeoutDrained" || event === "timeoutDrainExpired") return next("timed_out", "E_TIMEOUT");
  }
  throw new Error(`invalid transition: ${job.state} + ${event}`);
}

// Late worker output after a terminal state is dropped: the job is returned unchanged.
export function acceptOutput<T extends TransitionJob>(job: T, apply: (job: T) => T): T {
  return TERMINAL_STATES.includes(job.state) ? job : apply(job);
}
