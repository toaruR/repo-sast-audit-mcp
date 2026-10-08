import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ENV, STALE_DAYS } from "../src/constants.js";
import { validateOutput } from "../src/contracts.js";
import { listScanners, listScannersTool } from "../src/tools/listScanners.js";

delete process.env[ENV.ADVISORY_DB];
delete process.env[ENV.ALLOW_NETWORK];
delete process.env[ENV.DB_STALE_DAYS];
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-ls-")));
const DAY = 86400000;
const NOW = Date.parse("2026-10-01T12:00:00Z");

function dbWithAge(days: number): string {
  const d = fs.mkdtempSync(path.join(base, "db-"));
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt: new Date(NOW - days * DAY).toISOString() }));
  return d;
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };

test("output validates against the 3.6 schema", () => {
  const out = listScanners();
  const v = validateOutput("list_scanners", out);
  assert.ok(v.valid, JSON.stringify(v.errors));
  const env = listScannersTool({}) as unknown as Env;
  assert.strictEqual(env.isError, undefined);
  assert.ok(validateOutput("list_scanners", env.structuredContent).valid);
});

test("list_scanners: non-empty input: arguments {\"x\":1} returns isError true, E_INVALID_INPUT and retryable false (the same call with {} succeeds)", () => {
  const bad = listScannersTool({ x: 1 }) as unknown as Env;
  assert.strictEqual(bad.isError, true);
  assert.strictEqual(bad.structuredContent["error"].code, "E_INVALID_INPUT");
  assert.strictEqual(bad.structuredContent["error"].retryable, false);
  assert.strictEqual((listScannersTool({}) as unknown as Env).isError, undefined);
});

test("scanners array has 4 entries dependency, secret, static, config", () => {
  const s = listScanners().scanners;
  assert.deepStrictEqual(s.map((x) => x.id), ["dependency", "secret", "static", "config"]);
  assert.deepStrictEqual(s.map((x) => x.requiresAdvisoryDb), [true, false, false, false]);
  assert.ok(s.every((x) => x.ruleCount >= 1 && x.enabledByDefault));
});

test("networkAllowed is false when VULN_MCP_ALLOW_NETWORK is unset", () => {
  assert.strictEqual(listScanners().networkAllowed, false);
  process.env[ENV.ALLOW_NETWORK] = "1";
  try {
    assert.strictEqual(listScanners().networkAllowed, true);
  } finally {
    delete process.env[ENV.ALLOW_NETWORK];
  }
});

test("advisoryDb.present is false when no DB exists", () => {
  assert.deepStrictEqual(listScanners().advisoryDb, { present: false });
  assert.deepStrictEqual(listScanners({ advisoryDbPath: path.join(base, "nope") }).advisoryDb, { present: false });
});

test("advisoryDb.stale is true when DB age is STALE_DAYS+1", () => {
  const stale = listScanners({ advisoryDbPath: dbWithAge(STALE_DAYS + 1), now: NOW }).advisoryDb;
  assert.strictEqual(stale.present, true);
  assert.strictEqual(stale.ageDays, STALE_DAYS + 1);
  assert.strictEqual(stale.stale, true);
  const fresh = listScanners({ advisoryDbPath: dbWithAge(STALE_DAYS), now: NOW }).advisoryDb;
  assert.strictEqual(fresh.stale, false);
});
