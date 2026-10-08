import { test } from "node:test";
import assert from "node:assert";
import type { Finding } from "../src/findings/identity.js";
import { buildSarif } from "../src/report/sarif.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-0123456789abcdef",
    ruleId: "STA-X-001",
    scanner: "static",
    title: "t",
    severity: "high",
    confidence: "medium",
    cwe: ["CWE-95"],
    location: { path: "src/a/b.js", line: 7, column: 3 },
    evidence: "e",
    message: "m",
    remediation: "r",
    fingerprint: "ab".repeat(16),
    occurrence: 1,
    ...over,
  };
}

const first = (fs: Finding[], v = "0.1.0") => buildSarif(fs, v).runs[0]!;

test("artifact uri: finding at path \"src/a/b.js\" => results[0].locations[0].physicalLocation.artifactLocation.uri === \"src/a/b.js\" (relative, no absolute prefix)", () => {
  const uri = first([finding()]).results[0]?.locations[0]?.physicalLocation.artifactLocation.uri;
  assert.strictEqual(uri, "src/a/b.js");
  assert.ok(!/^(?:\/|[A-Za-z]:|file:)/.test(uri ?? ""));
});

test("region: finding line 7 column 3 => region.startLine === 7 and region.startColumn === 3", () => {
  const r = first([finding()]).results[0]?.locations[0]?.physicalLocation.region;
  assert.strictEqual(r?.startLine, 7);
  assert.strictEqual(r?.startColumn, 3);
});

test("fingerprint: results[0].partialFingerprints.primary === finding.fingerprint", () => {
  const f = finding();
  assert.strictEqual(first([f]).results[0]?.partialFingerprints.primary, f.fingerprint);
});

test("rules list: for findings with ruleIds [A,B,A] => tool.driver.rules ids deepEqual [\"A\",\"B\"] (exactly the used ruleIds, no duplicates)", () => {
  const fs = [finding({ ruleId: "A" }), finding({ ruleId: "B" }), finding({ ruleId: "A" })];
  assert.deepStrictEqual(first(fs).tool.driver.rules.map((r) => r.id), ["A", "B"]);
  assert.strictEqual(first(fs).results.length, 3);
});

test("driver version: tool.driver.version === serverVersion (same string list_scanners returns)", () => {
  assert.strictEqual(first([finding()], "9.8.7").tool.driver.version, "9.8.7");
});

test("properties: results[0].properties has keys confidence, cwe and scanner equal to the finding values", () => {
  const f = finding();
  const p = first([f]).results[0]?.properties;
  assert.deepStrictEqual(p, { confidence: f.confidence, cwe: f.cwe, scanner: f.scanner });
});
