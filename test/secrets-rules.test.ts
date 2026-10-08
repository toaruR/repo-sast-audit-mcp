import { test } from "node:test";
import assert from "node:assert";
import { scanSecrets } from "../src/scanners/secret.js";

const ids = (line: string): string[] => scanSecrets("a.ts", line).map((m) => m.ruleId);

test("SEC-AWS-ACCESS-KEY-ID matches AKIA followed by 16 chars and not AKIA followed by 15 chars", () => {
  assert.deepStrictEqual(ids("k = AKIAABCDEFGHIJKLMNOP"), ["SEC-AWS-ACCESS-KEY-ID"]);
  assert.deepStrictEqual(ids("k = AKIAABCDEFGHIJKLMNO"), []);
});

test("SEC-AWS-ACCESS-KEY-ID matches ASIA followed by 16 chars", () => {
  assert.deepStrictEqual(ids("k = ASIAABCDEFGHIJKLMNOP"), ["SEC-AWS-ACCESS-KEY-ID"]);
});

test('SEC-PRIVATE-KEY matches a -----BEGIN RSA PRIVATE KEY----- line', () => {
  assert.deepStrictEqual(ids("-----BEGIN RSA PRIVATE KEY-----"), ["SEC-PRIVATE-KEY"]);
});

test("SEC-PRIVATE-KEY does not match -----BEGIN PUBLIC KEY-----", () => {
  assert.deepStrictEqual(ids("-----BEGIN PUBLIC KEY-----"), []);
});

test("SEC-GITHUB-TOKEN matches a ghp_ token of 36 chars and not a ghp_ value of 10 chars", () => {
  assert.deepStrictEqual(ids("t=ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"), ["SEC-GITHUB-TOKEN"]);
  assert.deepStrictEqual(ids("t=ghp_aB3dE5gH7j"), []);
});

test("SEC-AWS-ACCESS-KEY-ID finding column is the 1-based offset of the key start (key at offset 18 => column 19)", () => {
  const line = "x".repeat(17) + " AKIAABCDEFGHIJKLMNOP";
  assert.strictEqual(line.indexOf("AKIA"), 18);
  const r = scanSecrets("a.ts", line);
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0]?.column, 19);
  assert.strictEqual(r[0]?.line, 1);
});
