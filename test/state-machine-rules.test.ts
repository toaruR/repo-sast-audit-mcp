import { test } from "node:test";
import assert from "node:assert";
import {
  ALL_EVENTS,
  ALL_STATES,
  acceptOutput,
  transition,
  type JobEvent,
  type JobState,
  type TransitionJob,
} from "../src/jobs/stateMachine.js";

test("running + cancel drained (and + CANCEL_DRAIN_MS expiry after cancel) => cancelled with error E_CANCELLED", () => {
  for (const ev of ["cancelDrained", "cancelDrainExpired"] as const) {
    const r = transition({ state: "running" }, ev);
    assert.strictEqual(r.state, "cancelled");
    assert.strictEqual(r.error, "E_CANCELLED");
  }
});

test("running + timeout drained (and + CANCEL_DRAIN_MS expiry after timeout) => timed_out with error E_TIMEOUT", () => {
  for (const ev of ["timeoutDrained", "timeoutDrainExpired"] as const) {
    const r = transition({ state: "running" }, ev);
    assert.strictEqual(r.state, "timed_out");
    assert.strictEqual(r.error, "E_TIMEOUT");
  }
});

test("every (state,event) pair outside the 6-row table throws, including every pair from a terminal state (loop over all states x all events)", () => {
  const allowed = new Set<string>([
    "queued:slot",
    "queued:cancel",
    "running:done",
    "running:internalError",
    "running:strictCap",
    "running:cancelDrained",
    "running:cancelDrainExpired",
    "running:timeoutDrained",
    "running:timeoutDrainExpired",
  ]);
  let throwing = 0;
  for (const s of ALL_STATES) {
    for (const e of ALL_EVENTS) {
      const job: TransitionJob = { state: s };
      if (allowed.has(`${s}:${e}`)) {
        assert.doesNotThrow(() => transition(job, e), `${s}+${e}`);
      } else {
        assert.throws(() => transition(job, e), `${s}+${e}`);
        throwing += 1;
      }
    }
  }
  assert.strictEqual(throwing, ALL_STATES.length * ALL_EVENTS.length - allowed.size);
});

test("transition does not mutate its input (deep-equal before and after)", () => {
  const job = { state: "running" as JobState, extra: { n: 1 } };
  const before = structuredClone(job);
  transition(job, "done");
  assert.deepStrictEqual(job, before);
});

test("a second event applied after the first on the same job is rejected (first wins)", () => {
  const first = transition({ state: "running" }, "cancelDrained");
  assert.strictEqual(first.state, "cancelled");
  for (const e of ALL_EVENTS as readonly JobEvent[]) {
    assert.throws(() => transition(first, e));
  }
});

test("late output after a terminal state is dropped with no state change", () => {
  const job = transition({ state: "running" }, "timeoutDrained");
  const out = acceptOutput(job, () => ({ state: "completed" as JobState }));
  assert.strictEqual(out, job);
  assert.strictEqual(out.state, "timed_out");
  assert.strictEqual(out.error, "E_TIMEOUT");
});
