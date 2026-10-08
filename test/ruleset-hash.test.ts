import { test } from "node:test";
import assert from "node:assert";
import { parseRules, type Rule } from "../src/scanners/rules.js";
import { rulesetHash } from "../src/scanners/rulesetHash.js";

function mk(id: string, pattern: string): Record<string, unknown> {
  return {
    id, title: id, languages: ["any"], pattern, severity: "low", confidence: "low", cwe: "CWE-1",
    tests: { shouldMatch: ["foo"], shouldNotMatch: ["bar"] },
  };
}
const A = mk("STA-A-001", "foo");
const B = mk("STA-B-001", "fo+");
const V = { secret: "1", static: "1" };
const load = (...r: Record<string, unknown>[]): Rule[] => parseRules({ rules: r });

test("rulesetHash is 64 lowercase hex chars", () => {
  assert.match(rulesetHash(load(A, B), V), /^[0-9a-f]{64}$/);
});

test("rulesetHash is identical for two different rule file orders", () => {
  assert.strictEqual(rulesetHash(load(A, B), V), rulesetHash(load(B, A), { static: "1", secret: "1" }));
});

test("rulesetHash changes when one rule pattern changes", () => {
  assert.notStrictEqual(rulesetHash(load(A, B), V), rulesetHash(load(A, mk("STA-B-001", "fo*")), V));
});

test("rulesetHash changes when a scanner version changes", () => {
  assert.notStrictEqual(rulesetHash(load(A, B), V), rulesetHash(load(A, B), { ...V, static: "2" }));
});
