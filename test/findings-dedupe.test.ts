import { test } from "node:test";
import assert from "node:assert";
import { dedupeFindings, type DedupeItem } from "../src/findings/dedupe.js";

let n = 0;
function f(over: Partial<DedupeItem> = {}): DedupeItem {
  n++;
  return {
    id: `F-${String(n).padStart(16, "0")}`,
    ruleId: "R-B",
    scanner: "static",
    title: "t",
    severity: "medium",
    confidence: "medium",
    cwe: ["CWE-79"],
    location: { path: "src/a.js", line: 5, column: 1 },
    evidence: "e",
    message: "m",
    remediation: "r",
    fingerprint: "0".repeat(32),
    occurrence: 1,
    ...over,
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

test("two findings with the same id merge into one", () => {
  const a = f({ id: "F-aaaaaaaaaaaaaaaa" });
  const b = f({ id: "F-aaaaaaaaaaaaaaaa" });
  assert.strictEqual(dedupeFindings([a, b]).length, 1);
});

test("same scanner+path+line with intersecting CWE sets merge, keeping the highest severity", () => {
  const out = dedupeFindings([
    f({ ruleId: "R-B", severity: "low", confidence: "high", cwe: ["CWE-79", "CWE-80"] }),
    f({ ruleId: "R-C", severity: "critical", confidence: "low", cwe: ["CWE-80"] }),
  ]);
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0]?.severity, "critical");
  assert.strictEqual(out[0]?.confidence, "high");
});

test("the merged finding keeps the lowest ruleId and lists the others in relatedRuleIds", () => {
  const out = dedupeFindings([
    f({ ruleId: "R-C", cwe: ["CWE-1"] }),
    f({ ruleId: "R-A", cwe: ["CWE-1"] }),
    f({ ruleId: "R-B", cwe: ["CWE-1", "CWE-2"] }),
  ]);
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0]?.ruleId, "R-A");
  assert.deepStrictEqual(out[0]?.relatedRuleIds, ["R-B", "R-C"]);
});

test("same location with disjoint CWE sets are not merged", () => {
  const out = dedupeFindings([f({ cwe: ["CWE-1"] }), f({ ruleId: "R-C", cwe: ["CWE-2"] })]);
  assert.strictEqual(out.length, 2);
});

test("online and offline findings for the same package merge into the offline one", () => {
  const pkg = { ecosystem: "npm", name: "lodash", version: "4.17.15" };
  const off = f({ scanner: "dependency", ruleId: "DEP-OSV-ADVISORY", advisoryId: "GHSA-1", package: pkg, cwe: [], location: { path: "package-lock.json", line: 1, column: 1 } });
  const on = f({ scanner: "dependency", ruleId: "DEP-OSV-ADVISORY", advisoryId: "GHSA-1", package: pkg, online: true, cwe: [], location: { path: "package-lock.json", line: 2, column: 1 } });
  const out = dedupeFindings([on, off]);
  assert.deepStrictEqual(out.map((x) => x.id), [off.id]);
  assert.strictEqual("online" in (out[0] as object), false);
  assert.strictEqual(dedupeFindings([on]).length, 1);
});

test("dedupe result is identical for 100 shuffled input orders", () => {
  const list = [
    f({ ruleId: "R-C", cwe: ["CWE-1"] }),
    f({ ruleId: "R-A", cwe: ["CWE-1", "CWE-3"] }),
    f({ ruleId: "R-D", cwe: ["CWE-3"], severity: "high" }),
    f({ location: { path: "x.js", line: 1, column: 1 }, cwe: ["CWE-9"] }),
    f({ location: { path: "y.js", line: 1, column: 1 }, cwe: [] }),
  ];
  const ref = JSON.stringify(dedupeFindings(list));
  for (let i = 0; i < 100; i++) assert.strictEqual(JSON.stringify(dedupeFindings(shuffle(list, i + 7))), ref);
});
