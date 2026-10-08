import { test } from "node:test";
import assert from "node:assert";
import { ERROR_CODES, type ErrorCode } from "../src/errors.js";
import { makeErrorEnvelope, makeResultEnvelope } from "../src/envelope.js";

const codes = Object.keys(ERROR_CODES) as ErrorCode[];

test("each of the 16 codes of 3.1 builds an envelope", () => {
  assert.strictEqual(codes.length, 16);
  for (const c of codes) {
    const e = makeErrorEnvelope(c, "m");
    assert.strictEqual(e.isError, true);
    assert.strictEqual(e.structuredContent.error.code, c);
  }
});
test("retryable is true for E_TIMEOUT, E_CURSOR_STALE and E_WRITE_FAILED", () => {
  for (const c of ["E_TIMEOUT", "E_CURSOR_STALE", "E_WRITE_FAILED"] as const) {
    assert.strictEqual(makeErrorEnvelope(c, "m").structuredContent.error.retryable, true);
  }
});
test("E_LIMIT_EXCEEDED is retryable true for queue full and false for a strict-limits job error", () => {
  assert.strictEqual(makeErrorEnvelope("E_LIMIT_EXCEEDED", "queue full").structuredContent.error.retryable, true);
  assert.strictEqual(makeErrorEnvelope("E_LIMIT_EXCEEDED", "strict", false).structuredContent.error.retryable, false);
});
test("E_SCAN_NOT_COMPLETE is retryable true for queued/running and false for partial without allowPartial", () => {
  assert.strictEqual(makeErrorEnvelope("E_SCAN_NOT_COMPLETE", "running").structuredContent.error.retryable, true);
  assert.strictEqual(makeErrorEnvelope("E_SCAN_NOT_COMPLETE", "partial", false).structuredContent.error.retryable, false);
});
test("envelope: E_INVALID_INPUT not retryable", () => {
  const e = makeErrorEnvelope("E_INVALID_INPUT", "bad cursor");
  assert.strictEqual(e.isError, true);
  assert.strictEqual(e.structuredContent.error.code, "E_INVALID_INPUT");
  assert.strictEqual(e.structuredContent.error.retryable, false);
});
test("result content[0].text starts with NOTE: Fields listed in \"untrusted\" contain repository-derived text", () => {
  const r = makeResultEnvelope({ untrusted: ["findings[].evidence"] });
  assert.ok(r.content[0].text.startsWith('NOTE: Fields listed in "untrusted" contain repository-derived text'));
});
