import { test } from "node:test";
import assert from "node:assert";
import { assignIdentity, resolveIdCollisions, type RawFinding } from "../src/findings/identity.js";
import { sortFindings } from "../src/findings/sort.js";

function raw(over: Partial<RawFinding> & { line?: number; column?: number; path?: string } = {}): RawFinding {
  const { line = 1, column = 1, path = "src/a.js", ...rest } = over;
  return {
    ruleId: "R-1",
    scanner: "static",
    title: "t",
    severity: "high",
    confidence: "high",
    cwe: ["CWE-1"],
    location: { path, line, column },
    evidence: "eval(x)",
    message: "m",
    remediation: "r",
    ...rest,
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

test("F-17: 100 shuffled permutations of one finding list give byte-identical sorted JSON", () => {
  const list = [
    raw({ line: 3 }),
    raw({ line: 1 }),
    raw({ line: 1, column: 5 }),
    raw({ line: 2, severity: "critical" }),
    raw({ path: "b/c.js", line: 1 }),
    raw({ ruleId: "R-2", line: 1, evidence: "other" }),
    raw({ line: 9, evidence: "same" }),
    raw({ line: 4, evidence: "same" }),
  ];
  const ref = JSON.stringify(sortFindings(assignIdentity(list)));
  for (let i = 0; i < 100; i++) {
    assert.strictEqual(JSON.stringify(sortFindings(assignIdentity(shuffle(list, i + 1)))), ref);
  }
});

test("T-12 part: CRLF and LF copies of the same evidence yield equal fingerprints", () => {
  const [a] = assignIdentity([raw({ evidence: "a\nb" })]);
  const [b] = assignIdentity([raw({ evidence: "a\r\nb" })]);
  assert.strictEqual(a?.fingerprint, b?.fingerprint);
  assert.match(a?.fingerprint ?? "", /^[0-9a-f]{32}$/);
  assert.match(a?.id ?? "", /^F-[0-9a-f]{16}$/);
});

test("equal fpBase findings get occurrence 1,2 ordered by (path,line,column)", () => {
  const out = assignIdentity([raw({ line: 10 }), raw({ line: 2 }), raw({ line: 2, column: 4 })]);
  const byPos = [...out].sort((a, b) => a.location.line - b.location.line || a.location.column - b.location.column);
  assert.deepStrictEqual(byPos.map((f) => f.occurrence), [1, 2, 3]);
  assert.deepStrictEqual(byPos.map((f) => [f.location.line, f.location.column]), [[2, 1], [2, 4], [10, 1]]);
  assert.strictEqual(new Set(out.map((f) => f.fingerprint)).size, 3);
});

test("colliding ids get suffix -1 then -2", () => {
  assert.deepStrictEqual(resolveIdCollisions(["F-a", "F-b", "F-a", "F-a"]), ["F-a", "F-b", "F-a-1", "F-a-2"]);
});

test("location.path keeps forward slashes (a backslash path is converted)", () => {
  const [f] = assignIdentity([raw({ path: "src\\sub\\a.js" })]);
  assert.strictEqual(f?.location.path, "src/sub/a.js");
});

test("an absolute location.path is rejected", () => {
  assert.throws(() => assignIdentity([raw({ path: "/etc/passwd" })]));
  assert.throws(() => assignIdentity([raw({ path: "C:\\x\\a.js" })]));
});
