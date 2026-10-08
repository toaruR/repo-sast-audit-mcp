import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { createAjv, validateInput } from "../src/contracts.js";

const SID = "S-3f9a1c2b7d4e-1";

test('T-15: schemas/defs.json compiles in ajv 8 with $id "d"', () => {
  const defs = JSON.parse(readFileSync(new URL("../schemas/defs.json", import.meta.url), "utf8")) as { $id: string };
  assert.strictEqual(defs.$id, "d");
  const ajv = createAjv();
  assert.ok(ajv.getSchema("d"));
  const sev = ajv.compile({ $ref: "d#/Sev" });
  assert.ok(sev("high"));
  assert.ok(!sev("urgent"));
});

test('scan_repository input rejects unknown top-level key "foo"', () => {
  assert.ok(validateInput("scan_repository", { repoPath: "/x" }).valid);
  const r = validateInput("scan_repository", { repoPath: "/x", foo: 1 });
  assert.ok(!r.valid);
  assert.strictEqual(r.errors[0]?.keyword, "additionalProperties");
});

test("scan_repository input accepts options.limits.maxFiles=500000 and rejects 500001 (x-limit max)", () => {
  assert.ok(validateInput("scan_repository", { repoPath: "/x", options: { limits: { maxFiles: 500000 } } }).valid);
  assert.ok(!validateInput("scan_repository", { repoPath: "/x", options: { limits: { maxFiles: 500001 } } }).valid);
});

test("scan_repository input rejects options.limits.maxFiles=0 (x-limit min 1)", () => {
  assert.ok(!validateInput("scan_repository", { repoPath: "/x", options: { limits: { maxFiles: 0 } } }).valid);
});

test("get_scan_status and cancel_scan inputs accept scanId S-3f9a1c2b7d4e-1 and reject S-xyz", () => {
  for (const t of ["get_scan_status", "cancel_scan"] as const) {
    assert.ok(validateInput(t, { scanId: SID }).valid);
    assert.ok(!validateInput(t, { scanId: "S-xyz" }).valid);
  }
});

test("get_findings limit bounds: 201 invalid (keyword maximum), 200 valid", () => {
  const bad = validateInput("get_findings", { scanId: SID, limit: 201 });
  assert.ok(!bad.valid);
  assert.strictEqual(bad.errors[0]?.keyword, "maximum");
  assert.ok(validateInput("get_findings", { scanId: SID, limit: 200 }).valid);
});

test("waitMs uses its x-limit range", () => {
  assert.ok(validateInput("scan_repository", { repoPath: "/x", waitMs: 30000 }).valid);
  assert.ok(!validateInput("scan_repository", { repoPath: "/x", waitMs: 30001 }).valid);
});
