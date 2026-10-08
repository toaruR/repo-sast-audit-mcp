import { test } from "node:test";
import assert from "node:assert";
import { ERROR_CODES } from "../src/errors.js";
import { transition } from "../src/jobs/stateMachine.js";

test("table: queued+slot", () => {
  const r = transition({ state: "queued" }, "slot");
  assert.strictEqual(r.state, "running");
  assert.strictEqual(r.error, undefined);
});

test("table: queued+cancel", () => {
  const r = transition({ state: "queued" }, "cancel");
  assert.strictEqual(r.state, "cancelled");
  assert.strictEqual(r.error, "E_CANCELLED");
});

test("table: running+done", () => {
  const r = transition({ state: "running" }, "done");
  assert.strictEqual(r.state, "completed");
  assert.strictEqual(r.error, undefined);
});

test("table: running+internalError", () => {
  const r = transition({ state: "running" }, "internalError");
  assert.strictEqual(r.state, "failed");
  assert.strictEqual(r.error, "E_INTERNAL");
});

test("table: running+strictCap", () => {
  const r = transition({ state: "running" }, "strictCap");
  assert.strictEqual(r.state, "failed");
  assert.strictEqual(r.error, "E_LIMIT_EXCEEDED");
});

test("error catalogue", () => {
  const expected = [
    "E_ADVISORY_DB_INVALID", "E_ADVISORY_DB_MISSING", "E_CANCELLED", "E_CURSOR_STALE",
    "E_INTERNAL", "E_INVALID_INPUT", "E_LIMIT_EXCEEDED", "E_NETWORK_DISABLED",
    "E_NOT_FOUND", "E_OUTPUT_DIR_UNSAFE", "E_PATH_TRAVERSAL", "E_PERMISSION_DENIED",
    "E_RULE_INVALID", "E_SCAN_NOT_COMPLETE", "E_TIMEOUT", "E_WRITE_FAILED",
  ].sort();
  assert.deepStrictEqual(Object.keys(ERROR_CODES).sort(), expected);
  assert.strictEqual(Object.keys(ERROR_CODES).length, 16);
});
