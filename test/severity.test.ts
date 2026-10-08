import { test } from "node:test";
import assert from "node:assert";
import { resolveSeverity, riskRating, severityFromCvss } from "../src/scoring.js";

test("T-02 CVSS boundary 8.9/9", () => {
  assert.strictEqual(severityFromCvss(8.9), "high");
  assert.strictEqual(severityFromCvss(9), "critical");
});

test("T-02 CVSS boundary 0.1/0", () => {
  assert.strictEqual(severityFromCvss(0.1), "low");
  assert.strictEqual(severityFromCvss(0), "info");
});

test("no CVSS score: label CRITICAL/HIGH/MODERATE/LOW maps to critical/high/medium/low", () => {
  const m = (label: string) => resolveSeverity({ label }, "high").severity;
  assert.deepStrictEqual(["CRITICAL", "HIGH", "MODERATE", "LOW"].map(m), ["critical", "high", "medium", "low"]);
});

test("no CVSS score and no label => medium, confidence lowered one step", () => {
  assert.deepStrictEqual(resolveSeverity({}, "high"), { severity: "medium", confidence: "medium" });
});

test("by_worst: critical/medium finding (raw10 175, by_score medium) => riskRating high", () => {
  assert.strictEqual(riskRating([{ severity: "critical", confidence: "medium" }]), "high");
});

test("by_worst: critical finding with confidence low (raw10 100) => riskRating stays medium (by_worst none)", () => {
  assert.strictEqual(riskRating([{ severity: "critical", confidence: "low" }]), "medium");
});
