import { test } from "node:test";
import assert from "node:assert";
import { loadRules, parseRules } from "../src/scanners/rules.js";
import { McpError } from "../src/errors.js";

function rule(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "STA-TEST-001",
    title: "test rule",
    languages: ["javascript"],
    pattern: String.raw`\beval\s*\(`,
    severity: "high",
    confidence: "medium",
    cwe: "CWE-95",
    tests: { shouldMatch: ["eval(x)"], shouldNotMatch: ["evaluate(x)"] },
    ...over,
  };
}
const file = (...rules: Record<string, unknown>[]): unknown => ({ rules });
const invalid = (e: unknown): boolean => e instanceof McpError && e.code === "E_RULE_INVALID";

test("a valid rule loads", () => {
  assert.strictEqual(parseRules(file(rule())).length, 1);
});

test("shipped rules file loads", () => {
  loadRules();
});

test("rule whose shouldMatch sample does not match", () => {
  const r = rule({ tests: { shouldMatch: ["nothing here"], shouldNotMatch: ["x"] } });
  assert.throws(() => parseRules(file(r)), invalid);
});

test("rule whose shouldNotMatch sample matches", () => {
  const r = rule({ tests: { shouldMatch: ["eval(x)"], shouldNotMatch: ["eval(y)"] } });
  assert.throws(() => parseRules(file(r)), invalid);
});

test("section 11 RE2-only row: lookaround pattern is rejected", () => {
  const r = rule({ pattern: "eval(?=\\()", tests: { shouldMatch: ["eval("], shouldNotMatch: ["x"] } });
  assert.throws(() => parseRules(file(r)), invalid);
});

test("section 11 RE2-only row: backreference pattern is rejected", () => {
  const r = rule({ pattern: "(a)\\1", tests: { shouldMatch: ["aa"], shouldNotMatch: ["x"] } });
  assert.throws(() => parseRules(file(r)), invalid);
});

test("unknown key in a rule is rejected (zod strict)", () => {
  assert.throws(() => parseRules(file(rule({ extra: 1 }))), invalid);
});

test("rule id longer than RULEID_MAX (64) is rejected", () => {
  assert.throws(() => parseRules(file(rule({ id: "A".repeat(65) }))), invalid);
  assert.strictEqual(parseRules(file(rule({ id: "A".repeat(64) }))).length, 1);
});

test("negativePattern suppresses a match", () => {
  const r = rule({
    negativePattern: "safe",
    tests: { shouldMatch: ["eval(x)"], shouldNotMatch: ["eval(safe)"] },
  });
  assert.strictEqual(parseRules(file(r)).length, 1);
});
