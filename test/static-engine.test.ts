import { test } from "node:test";
import assert from "node:assert";
import { parseRules, ruleFires } from "../src/scanners/rules.js";
import { scanStatic } from "../src/scanners/static.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { PER_FILE_BUDGET_MS, LINE_MAX } from "../src/constants.js";

function mk(id: string, pattern: string, languages: string[], match: string, nomatch: string): Record<string, unknown> {
  return {
    id, title: id, languages, pattern, severity: "high", confidence: "medium", cwe: "CWE-1",
    tests: { shouldMatch: [match], shouldNotMatch: [nomatch] },
  };
}

test("T-24 (F-10): rule (a+)+$ on a 100000-char a line followed by ! completes without hang (RE2 linear)", () => {
  const rules = parseRules({ rules: [mk("STA-REDOS-001", "(a+)+$", ["any"], "aaa", "bbb")] });
  const rule = rules[0]!;
  const line = "a".repeat(100000) + "!";
  const t0 = Date.now();
  assert.strictEqual(ruleFires(rule, line), false);
  const w = new Warnings();
  scanStatic("x.js", `${line}\n`, rules, w);
  assert.ok(Date.now() - t0 < 5000);
});

test("T-24 (F-10): fake clock past PER_FILE_BUDGET_MS => W_RULE_TIMEBUDGET count 1 and the scan completes", () => {
  const rules = parseRules({ rules: [mk("STA-A-001", "foo", ["any"], "foo", "bar")] });
  let calls = 0;
  const now = (): number => (calls++ === 0 ? 0 : PER_FILE_BUDGET_MS + 1);
  const w = new Warnings();
  const out = scanStatic("a.js", "foo\nfoo\nfoo\n", rules, w, { now });
  assert.strictEqual(w.count("W_RULE_TIMEBUDGET"), 1);
  assert.ok(out.length < 3);
});

test("section 11 LINE_MAX row: a line of 5001 chars is skipped with W_MINIFIED_SKIPPED count 1", () => {
  const rules = parseRules({ rules: [mk("STA-A-001", "foo", ["any"], "foo", "bar")] });
  const w = new Warnings();
  const out = scanStatic("a.js", `foo\n${"a".repeat(LINE_MAX - 3)}foo${"b"}\nfoo`, rules, w);
  assert.strictEqual(w.count("W_MINIFIED_SKIPPED"), 1);
  assert.deepStrictEqual(out.map((m) => m.line), [1, 3]);
});

test("a rule restricted to languages [javascript] does not run on a .py file", () => {
  const rules = parseRules({ rules: [mk("STA-A-001", "foo", ["javascript"], "foo", "bar")] });
  const w = new Warnings();
  assert.strictEqual(scanStatic("a.py", "foo\n", rules, w).length, 0);
  const js = scanStatic("a.js", "x foo\n", rules, w);
  assert.deepStrictEqual(js.map((m) => [m.line, m.column]), [[1, 3]]);
});
