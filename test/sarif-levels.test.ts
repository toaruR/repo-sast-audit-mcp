import { test } from "node:test";
import assert from "node:assert";
import type { Finding } from "../src/findings/identity.js";
import { buildSarif } from "../src/report/sarif.js";
import type { Severity } from "../src/scoring.js";

function finding(severity: Severity, over: Partial<Finding> = {}): Finding {
  return {
    id: "F-0123456789abcdef",
    ruleId: "STA-X-001",
    scanner: "static",
    title: "t",
    severity,
    confidence: "high",
    cwe: ["CWE-1"],
    location: { path: "src/a.js", line: 1, column: 1 },
    evidence: "e",
    message: "m",
    remediation: "r",
    fingerprint: "0".repeat(32),
    occurrence: 1,
    ...over,
  };
}

test("sarif version: the SARIF document produced by src/report/sarif.ts for any scan has top-level version === \"2.1.0\"", () => {
  assert.strictEqual(buildSarif([], "0.1.0").version, "2.1.0");
  assert.strictEqual(buildSarif([finding("low")], "0.1.0").version, "2.1.0");
});

const cases: Array<[Severity, string]> = [
  ["critical", "error"],
  ["high", "error"],
  ["medium", "warning"],
  ["low", "note"],
  ["info", "note"],
];
for (const [sev, level] of cases) {
  test(`severity to level: a finding with severity "${sev}" => results[0].level === "${level}"`, () => {
    assert.strictEqual(buildSarif([finding(sev)], "0.1.0").runs[0]?.results[0]?.level, level);
  });
}
