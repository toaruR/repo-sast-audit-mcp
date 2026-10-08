import { test } from "node:test";
import assert from "node:assert";
import type { Finding } from "../src/findings/identity.js";
import { sortFindings } from "../src/findings/sort.js";
import { truncateTopK } from "../src/findings/truncate.js";

function f(i: number, severity: Finding["severity"] = "medium"): Finding {
  return {
    id: `F-${String(i).padStart(16, "0")}`,
    ruleId: "R",
    scanner: "static",
    title: "t",
    severity,
    confidence: "high",
    cwe: [],
    location: { path: `p${i}.js`, line: 1, column: 1 },
    evidence: "e",
    message: "m",
    remediation: "r",
    fingerprint: "0".repeat(32),
    occurrence: 1,
  };
}

function shuffle<T>(a: readonly T[], seed: number): T[] {
  const out = [...a];
  let s = seed;
  for (let i = out.length - 1; i > 0; i--) {
    s = (s * 1664525 + 1013904223) >>> 0;
    const j = s % (i + 1);
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}

const sevs = ["info", "low", "medium", "high", "critical"] as const;
const ten = Array.from({ length: 10 }, (_, i) => f(i, sevs[i % 5]));

test("T-06 unit (F-08): maxFindings=3 on a 10-finding list keeps the first 3 in 5.3 order", () => {
  const r = truncateTopK(ten, 3);
  assert.deepStrictEqual(r.findings.map((x) => x.id), sortFindings(ten).slice(0, 3).map((x) => x.id));
});

test("truncated is true when findings were dropped", () => {
  assert.strictEqual(truncateTopK(ten, 3).truncated, true);
});

test("truncated is false when the list has <= K findings", () => {
  assert.strictEqual(truncateTopK(ten, 10).truncated, false);
  assert.strictEqual(truncateTopK(ten, 50).truncated, false);
  assert.strictEqual(truncateTopK(ten, 50).findings.length, 10);
});

test("a new finding replaces the current minimum only when strictly higher in 5.3 order", () => {
  const r = truncateTopK([f(1, "low"), f(2, "low"), f(3, "high")], 2);
  assert.deepStrictEqual(r.findings.map((x) => x.id), [f(3).id, f(1).id]);
});

test("a finding equal in order to the minimum does not replace it", () => {
  const a = f(1, "low");
  const same = { ...a };
  const r = truncateTopK([f(0, "high"), a, same], 2);
  assert.strictEqual(r.findings[1], a);
  assert.strictEqual(r.truncated, true);
});

test("result is identical for shuffled input orders", () => {
  const ref = JSON.stringify(truncateTopK(ten, 4));
  for (let i = 0; i < 50; i++) assert.strictEqual(JSON.stringify(truncateTopK(shuffle(ten, i + 3), 4)), ref);
});
