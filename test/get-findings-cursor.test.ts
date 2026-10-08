import { test } from "node:test";
import assert from "node:assert";
import type { Finding } from "../src/findings/identity.js";
import { getFindings, type FindingsSource } from "../src/tools/getFindings.js";
import { decodeCursor, encodeCursor } from "../src/tools/cursor.js";
import { validateOutput } from "../src/contracts.js";

const SID = "S-3f9a1c2b7d4e-1";
const CUR_GEN3 = "Uy0zZjlhMWMyYjdkNGUtMTozOjUw";
const CUR_GEN4 = "Uy0zZjlhMWMyYjdkNGUtMTo0OjUw";

function finding(i: number): Finding {
  const hex = i.toString(16).padStart(16, "0");
  return {
    id: `F-${hex}`, ruleId: "STA-JS-EVAL-001", scanner: "static", title: "t", severity: "high", confidence: "high",
    cwe: ["CWE-95"], location: { path: `src/f${String(i).padStart(4, "0")}.js`, line: 1, column: 1 }, evidence: `e${i}`,
    message: "m", remediation: "r", fingerprint: hex.padStart(32, "0"), occurrence: 1,
  };
}

function source(generation: number, count = 120) {
  const job = { scanId: SID, state: "running" as const, findings: Array.from({ length: count }, (_, i) => finding(i)), generation };
  const src: FindingsSource = { getJob: (id) => (id === SID ? job : undefined) };
  return { src, job };
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };

test("cursor Uy0zZjlhMWMyYjdkNGUtMTozOjUw at generation 3 returns findings 50..99", () => {
  assert.strictEqual(encodeCursor({ scanId: SID, generation: 3, offset: 50 }), CUR_GEN3);
  assert.deepStrictEqual(decodeCursor(CUR_GEN3), { scanId: SID, generation: 3, offset: 50 });
  const { src } = source(3);
  const r = getFindings(src, { scanId: SID, cursor: CUR_GEN3 }) as Env;
  assert.strictEqual(r.isError, undefined);
  const ids = (r.structuredContent["findings"] as Finding[]).map((f) => f.id);
  assert.strictEqual(ids.length, 50);
  assert.strictEqual(ids[0], finding(50).id);
  assert.strictEqual(ids[49], finding(99).id);
});

test("T-04 (F-08b): cursor Uy0zZjlhMWMyYjdkNGUtMTozOjUw (generation 3) sent after a commit raised the generation to 4 => E_CURSOR_STALE with retryable true", () => {
  const { src } = source(4);
  const r = getFindings(src, { scanId: SID, cursor: CUR_GEN3 }) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_CURSOR_STALE");
  assert.strictEqual(r.structuredContent["error"].retryable, true);
});

test("get_findings with no cursor (limit 50) at generation 4 returns isError false and nextCursor Uy0zZjlhMWMyYjdkNGUtMTo0OjUw; that cursor returns findings 50..99", () => {
  const { src } = source(4);
  const r = getFindings(src, { scanId: SID }) as Env;
  assert.notStrictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["nextCursor"], CUR_GEN4);
  assert.strictEqual(r.structuredContent["findings"].length, 50);
  assert.ok(validateOutput("get_findings", r.structuredContent).valid);
  const r2 = getFindings(src, { scanId: SID, cursor: r.structuredContent["nextCursor"] }) as Env;
  assert.strictEqual(r2.isError, undefined);
  const ids = (r2.structuredContent["findings"] as Finding[]).map((f) => f.id);
  assert.strictEqual(ids[0], finding(50).id);
  assert.strictEqual(ids[49], finding(99).id);
});

test("cursor that is not base64url => E_INVALID_INPUT", () => {
  const { src } = source(4);
  for (const c of ["!!not base64url!!", "Uy0zZjlh+/==", "Uy0zZjlhMWMyYjdkNGUtMTo0OjUw=="]) {
    const r = getFindings(src, { scanId: SID, cursor: c }) as Env;
    assert.strictEqual(r.isError, true, c);
    assert.strictEqual(r.structuredContent["error"].code, "E_INVALID_INPUT", c);
  }
});

test("cursor that does not have 3 parts => E_INVALID_INPUT", () => {
  const { src } = source(4);
  for (const text of [`${SID}:4`, `${SID}:4:50:1`, `${SID}:x:50`]) {
    const c = Buffer.from(text).toString("base64url");
    const r = getFindings(src, { scanId: SID, cursor: c }) as Env;
    assert.strictEqual(r.structuredContent["error"].code, "E_INVALID_INPUT", text);
  }
});

test("cursor for another scanId => E_INVALID_INPUT", () => {
  const { src } = source(4);
  const c = encodeCursor({ scanId: "S-aaaaaaaaaaaa-2", generation: 4, offset: 50 });
  const r = getFindings(src, { scanId: SID, cursor: c }) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_INVALID_INPUT");
});
