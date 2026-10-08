import { test } from "node:test";
import assert from "node:assert";
import type { Finding } from "../src/findings/identity.js";
import type { JobState } from "../src/jobs/stateMachine.js";
import { getFindings, type FindingsSource } from "../src/tools/getFindings.js";

const SID = "S-3f9a1c2b7d4e-1";

const SEVS = ["critical", "high", "medium", "low", "info"] as const;
const SCANNERS = ["dependency", "secret", "static", "config"] as const;

function finding(i: number): Finding {
  const hex = i.toString(16).padStart(16, "0");
  return {
    id: `F-${hex}`, ruleId: `RULE-${i % 3}`, scanner: SCANNERS[i % 4] as Finding["scanner"], title: "t",
    severity: SEVS[i % 5] as Finding["severity"], confidence: "high",
    cwe: [`CWE-${i % 2 === 0 ? 79 : 89}`], location: { path: `${i % 2 === 0 ? "src" : "lib"}/f${i}.js`, line: 1, column: 1 },
    evidence: `e${i}`, message: "m", remediation: "r", fingerprint: hex.padStart(32, "0"), occurrence: 1,
  };
}

function source(state: JobState = "completed", count = 250): FindingsSource {
  const job = { scanId: SID, state, findings: Array.from({ length: count }, (_, i) => finding(i)), generation: 0 };
  return { getJob: (id) => (id === SID ? job : undefined) };
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };

test("limit 201 => E_INVALID_INPUT (no clamp); limit 200 => isError false and findings.length <= 200", () => {
  const bad = getFindings(source(), { scanId: SID, limit: 201 }) as Env;
  assert.strictEqual(bad.isError, true);
  assert.strictEqual(bad.structuredContent["error"].code, "E_INVALID_INPUT");
  const ok = getFindings(source(), { scanId: SID, limit: 200 }) as Env;
  assert.notStrictEqual(ok.isError, true);
  assert.ok(ok.structuredContent["findings"].length <= 200);
  assert.strictEqual(ok.structuredContent["findings"].length, 200);
});

test("unknown scanId => E_NOT_FOUND", () => {
  const r = getFindings(source(), { scanId: "S-000000000000-9" }) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_NOT_FOUND");
});

test("filter keys combine as AND (minSeverity + scanners)", () => {
  const r = getFindings(source(), { scanId: SID, limit: 200, filter: { minSeverity: "high", scanners: ["static"] } }) as Env;
  const fs = r.structuredContent["findings"] as Finding[];
  assert.ok(fs.length > 0);
  for (const f of fs) {
    assert.ok(f.severity === "critical" || f.severity === "high");
    assert.strictEqual(f.scanner, "static");
  }
  const expected = Array.from({ length: 250 }, (_, i) => finding(i)).filter(
    (f) => (f.severity === "critical" || f.severity === "high") && f.scanner === "static",
  ).length;
  assert.strictEqual(r.structuredContent["total"], expected);
});

test("values within one filter list combine as OR (ruleIds)", () => {
  const r = getFindings(source(), { scanId: SID, limit: 200, filter: { ruleIds: ["RULE-0", "RULE-1"] } }) as Env;
  const fs = r.structuredContent["findings"] as Finding[];
  assert.ok(fs.some((f) => f.ruleId === "RULE-0"));
  assert.ok(fs.some((f) => f.ruleId === "RULE-1"));
  assert.ok(fs.every((f) => f.ruleId !== "RULE-2"));
});

test("total equals the count after filtering", () => {
  const r = getFindings(source(), { scanId: SID, limit: 5, filter: { pathPrefix: "src/", cwe: ["CWE-79"] } }) as Env;
  assert.strictEqual(r.structuredContent["total"], 125);
  assert.strictEqual(r.structuredContent["findings"].length, 5);
  assert.ok(r.structuredContent["nextCursor"] !== null);
  const none = getFindings(source(), { scanId: SID, filter: { pathPrefix: "nope/" } }) as Env;
  assert.strictEqual(none.structuredContent["total"], 0);
  assert.strictEqual(none.structuredContent["nextCursor"], null);
});

test("complete is false in non-completed states and true in completed", () => {
  for (const st of ["queued", "running", "failed", "cancelled", "timed_out"] as const) {
    const r = getFindings(source(st, 3), { scanId: SID }) as Env;
    assert.strictEqual(r.structuredContent["complete"], false, st);
  }
  const r = getFindings(source("completed", 3), { scanId: SID }) as Env;
  assert.strictEqual(r.structuredContent["complete"], true);
  const noEv = getFindings(source("completed", 3), { scanId: SID, includeEvidence: false }) as Env;
  assert.strictEqual(noEv.structuredContent["findings"][0].evidence, "");
});
