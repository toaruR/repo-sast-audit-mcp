import { test } from "node:test";
import assert from "node:assert";
import { execFileSync } from "node:child_process";
import { riskRatingByScore, riskScore, riskScoreFromRaw10, type Scored } from "../src/scoring.js";

const mk = (sev: Scored["severity"], conf: Scored["confidence"], n: number): Scored[] =>
  Array.from({ length: n }, () => ({ severity: sev, confidence: conf }));

test("T-02 rounding boundaries", () => {
  assert.strictEqual(riskScoreFromRaw10(94), 9);
  assert.strictEqual(riskScoreFromRaw10(95), 10);
  // 6*4 + 10*7 = 94 ; 1*4 + 13*7 = 95
  assert.strictEqual(riskScore([...mk("low", "low", 6), ...mk("low", "medium", 10)]), 9);
  assert.strictEqual(riskScore([...mk("low", "low", 1), ...mk("low", "medium", 13)]), 10);
});

test("T-02 rounding boundaries 59/60", () => {
  assert.strictEqual(riskScoreFromRaw10(594), 59);
  assert.strictEqual(riskScoreFromRaw10(595), 60);
});

test("T-02 low floor", () => {
  const s = riskScore([{ severity: "low", confidence: "low" }]);
  assert.strictEqual(s, 1);
  assert.strictEqual(riskRatingByScore(s), "low");
});

test("T-02 zero", () => {
  assert.strictEqual(riskScore([]), 0);
  const s = riskScore([{ severity: "info", confidence: "high" }]);
  assert.strictEqual(s, 0);
  assert.strictEqual(riskRatingByScore(s), "none");
});

test("T-02 critical/medium", () => {
  assert.strictEqual(riskScore([{ severity: "critical", confidence: "medium" }]), 18);
});

test("T-02 section 8 script", () => {
  const out = execFileSync(process.execPath, ["test/fixtures/n.cjs", "docs/design-repo-sast-audit-mcp.md"], { encoding: "utf8" });
  const expected = [
    "A cancelled 2000",
    "B cancelled 3000",
    "C timed_out 123000",
    "score 0 none | 1 low | 9 low | 10 medium | 29 medium | 30 high | 59 high | 60 critical | 100 critical",
    "raw10 94 9 | 95 10 | 294 29 | 295 30 | 594 59 | 595 60",
    "cvss 9 critical | 8.9 high | 7 high | 6.9 medium | 4 medium | 3.9 low | 0.1 low | 0 info",
  ];
  const lines = out.trim().split(/\r?\n/);
  assert.strictEqual(lines.length, expected.length);
  expected.forEach((l, i) => assert.strictEqual(lines[i], l));
});
