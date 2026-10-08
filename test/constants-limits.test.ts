import { test } from "node:test";
import assert from "node:assert";
import { LIMITS } from "../src/constants.js";

test("limits: maxFiles", () => {
  assert.deepStrictEqual(LIMITS.maxFiles, { default: 50000, min: 1, max: 500000 });
});
test("limits: maxFileBytes", () => {
  assert.deepStrictEqual(LIMITS.maxFileBytes, { default: 1048576, min: 1024, max: 8388608 });
});
test("limits: maxTotalBytes", () => {
  assert.deepStrictEqual(LIMITS.maxTotalBytes, { default: 536870912, min: 1048576, max: 4294967296 });
});
test("limits: maxFindings", () => {
  assert.deepStrictEqual(LIMITS.maxFindings, { default: 5000, min: 1, max: 50000 });
});
test("limits: timeoutMs", () => {
  assert.deepStrictEqual(LIMITS.timeoutMs, { default: 120000, min: 1000, max: 900000 });
});
test("limits: waitMs", () => {
  assert.deepStrictEqual(LIMITS.waitMs, { default: 0, min: 0, max: 30000 });
});
