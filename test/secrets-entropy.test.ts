import { test } from "node:test";
import assert from "node:assert";
import { scanSecrets, shannonMilli } from "../src/scanners/secret.js";

const HI = ["kJ8dP2xQ9vL4mZ7wR1tY6uN3bC5hG0aS", "Zx9Qm2Lp7Rt4Vb8Nc3Hd6Jf1Ks5Wg0Ya", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"];

test("T-03 entropy above threshold", () => {
  assert.ok(shannonMilli("kJ8dP2xQ9vL4mZ7wR1tY6uN3bC5hG0aS") > 4000);
});
test("T-03 hex uniform", () => {
  assert.strictEqual(shannonMilli("0123456789abcdef".repeat(2)), 4000);
});
test("T-03 hex mixed", () => {
  assert.strictEqual(shannonMilli("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"), 3906);
});
test("T-03 repeated char", () => {
  assert.strictEqual(shannonMilli("a".repeat(20)), 0);
});
test("generic rule fires", () => {
  for (const v of HI) {
    const r = scanSecrets("a.ts", `token = "${v}"`);
    assert.strictEqual(r.length, 1, v);
    assert.strictEqual(r[0]?.ruleId, "SEC-GENERIC-HIGH-ENTROPY");
  }
});
test("generic rule silent", () => {
  assert.strictEqual(scanSecrets("a.ts", 'token = "aaaaaaaaaaaaaaaaaaaa"').length, 0);
});
