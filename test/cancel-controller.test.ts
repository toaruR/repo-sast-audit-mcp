import { test } from "node:test";
import assert from "node:assert";
import { CANCEL_DRAIN_MS, PER_FILE_BUDGET_MS } from "../src/constants.js";
import { CancelController, type Clock } from "../src/jobs/cancelController.js";

class FakeClock implements Clock {
  t = 0;
  scheduled = 0;
  private seq = 0;
  private timers = new Map<number, { at: number; fn: () => void }>();
  now(): number {
    return this.t;
  }
  setTimeout(fn: () => void, ms: number): unknown {
    this.scheduled += 1;
    const id = ++this.seq;
    this.timers.set(id, { at: this.t + ms, fn });
    return id;
  }
  clearTimeout(h: unknown): void {
    this.timers.delete(h as number);
  }
  get pending(): number {
    return this.timers.size;
  }
  advance(ms: number): void {
    const target = this.t + ms;
    for (;;) {
      let best: [number, { at: number; fn: () => void }] | undefined;
      for (const e of this.timers) if (e[1].at <= target && (!best || e[1].at < best[1].at)) best = e;
      if (!best) break;
      this.timers.delete(best[0]);
      this.t = best[1].at;
      best[1].fn();
    }
    this.t = target;
  }
}

function setup(timeoutMs = 120000, workerEndsAt?: number) {
  const clock = new FakeClock();
  const c = new CancelController({ clock, timeoutMs });
  c.start();
  // Stub worker: ends by itself at workerEndsAt after the start (if given).
  if (workerEndsAt !== undefined) clock.setTimeout(() => c.workerEnded(), workerEndsAt);
  return { clock, c };
}

test("T-08 A (F-09a): cancel at t=0 with a worker that ends at PER_FILE_BUDGET_MS => state cancelled, durationMs 2000", () => {
  const { clock, c } = setup(120000, PER_FILE_BUDGET_MS);
  c.cancel();
  clock.advance(10000);
  assert.strictEqual(c.state, "cancelled");
  assert.strictEqual(c.error, "E_CANCELLED");
  assert.strictEqual(c.durationMs, 2000);
});

test("T-08 B (F-09a): cancel with a hung worker => state cancelled, durationMs 3000, error E_CANCELLED", () => {
  const { clock, c } = setup();
  c.cancel();
  clock.advance(10000);
  assert.strictEqual(c.state, "cancelled");
  assert.strictEqual(c.durationMs, CANCEL_DRAIN_MS);
  assert.strictEqual(c.durationMs, 3000);
  assert.strictEqual(c.error, "E_CANCELLED");
});

test("T-08 C (F-09): hung worker, no cancel, timeoutMs 120000 => state timed_out, durationMs 123000, error E_TIMEOUT", () => {
  const { clock, c } = setup(120000);
  clock.advance(122999);
  assert.strictEqual(c.state, "running");
  clock.advance(1000000);
  assert.strictEqual(c.state, "timed_out");
  assert.strictEqual(c.durationMs, 123000);
  assert.strictEqual(c.error, "E_TIMEOUT");
});

test("cancel on a queued job => cancelled immediately with no timer scheduled", () => {
  const clock = new FakeClock();
  const c = new CancelController({ clock, timeoutMs: 120000 });
  c.cancel();
  assert.strictEqual(c.state, "cancelled");
  assert.strictEqual(c.error, "E_CANCELLED");
  assert.strictEqual(clock.scheduled, 0);
  assert.strictEqual(clock.pending, 0);
});

test("cancel and strictCap processed in the same tick => state cancelled (cancel first)", () => {
  const { clock, c } = setup();
  c.cancel();
  c.strictCap();
  clock.advance(CANCEL_DRAIN_MS);
  assert.strictEqual(c.state, "cancelled");
  assert.strictEqual(c.error, "E_CANCELLED");
});

test("cancel calls AbortController.abort() exactly once and signal.aborted is true afterwards", () => {
  const clock = new FakeClock();
  const ac = new AbortController();
  let calls = 0;
  const orig = ac.abort.bind(ac);
  ac.abort = (reason?: unknown) => {
    calls += 1;
    orig(reason);
  };
  const c = new CancelController({ clock, timeoutMs: 120000, abortController: ac });
  c.start();
  c.cancel();
  c.cancel();
  clock.advance(10000);
  assert.strictEqual(calls, 1);
  assert.strictEqual(ac.signal.aborted, true);
});
