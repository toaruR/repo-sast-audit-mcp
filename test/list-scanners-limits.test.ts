import { test } from "node:test";
import assert from "node:assert";
import { listScanners } from "../src/tools/listScanners.js";

const out = listScanners();

test("limits: maxFiles", () => {
  assert.deepStrictEqual(out.limits.maxFiles, { default: 50000, min: 1, max: 500000 });
});
test("limits: maxFileBytes", () => {
  assert.deepStrictEqual(out.limits.maxFileBytes, { default: 1048576, min: 1024, max: 8388608 });
});
test("limits: maxTotalBytes", () => {
  assert.deepStrictEqual(out.limits.maxTotalBytes, { default: 536870912, min: 1048576, max: 4294967296 });
});
test("limits: maxFindings", () => {
  assert.deepStrictEqual(out.limits.maxFindings, { default: 5000, min: 1, max: 50000 });
});
test("limits: timeoutMs", () => {
  assert.deepStrictEqual(out.limits.timeoutMs, { default: 120000, min: 1000, max: 900000 });
});
test("limits: scalars", () => {
  assert.strictEqual(out.limits.getFindingsMax, 200);
  assert.strictEqual(out.limits.maxRunning, 2);
  assert.strictEqual(out.limits.maxQueued, 8);
});
