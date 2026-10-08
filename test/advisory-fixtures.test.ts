import { test } from "node:test";
import assert from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAdvisoryDb } from "../src/advisory/db.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { scanDependencies } from "../src/scanners/dependency.js";
import { createHash } from "node:crypto";
import { buildAdvisoryDb } from "./fixtures/advisory-db.js";
import { npmLockfile, requirementsTxt } from "./fixtures/lockfiles.js";

function db(): string {
  const dir = mkdtempSync(join(tmpdir(), "advfix-"));
  buildAdvisoryDb(dir);
  return dir;
}

function shard(dir: string, eco: string, name: string): { contentSha256: string; advisories: unknown[] } {
  return JSON.parse(readFileSync(join(dir, eco, `${name}.json`), "utf8")) as { contentSha256: string; advisories: unknown[] };
}

test("fixture manifest.json has schemaVersion 1 and a generatedAt", () => {
  const m = JSON.parse(readFileSync(join(db(), "manifest.json"), "utf8")) as { schemaVersion: number; generatedAt: string };
  assert.strictEqual(m.schemaVersion, 1);
  assert.ok(Number.isFinite(Date.parse(m.generatedAt)));
});

test("lodash shard contentSha256 matches its advisories content", () => {
  const s = shard(db(), "npm", "lodash");
  assert.strictEqual(s.contentSha256, createHash("sha256").update(JSON.stringify(s.advisories)).digest("hex"));
});

test("requests shard contentSha256 matches its advisories content", () => {
  const s = shard(db(), "PyPI", "requests");
  assert.strictEqual(s.contentSha256, createHash("sha256").update(JSON.stringify(s.advisories)).digest("hex"));
});

test("lodash 4.17.15 advisory has CVSS 7.4", async () => {
  const w = new Warnings();
  const d = loadAdvisoryDb(db(), { warnings: w });
  const f = await scanDependencies([{ rel: "package-lock.json", content: npmLockfile("p", [{ name: "lodash", version: "4.17.15" }]) }], { db: d, warnings: w });
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0]?.cvss?.score, 7.4);
  assert.strictEqual(f[0]?.severity, "high");
});

test("requests 2.19.0 is affected by the requests advisory", async () => {
  const w = new Warnings();
  const d = loadAdvisoryDb(db(), { warnings: w });
  const f = await scanDependencies([{ rel: "requirements.txt", content: requirementsTxt([{ name: "requests", version: "2.19.0" }]) }], { db: d, warnings: w });
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0]?.advisoryId, "GHSA-x84v-xcm2-53pg");
  assert.strictEqual(f[0]?.location.line, 1);
});

test("the fixture loads through src/advisory/db.ts with 0 warnings", () => {
  const w = new Warnings();
  const d = loadAdvisoryDb(db(), { warnings: w });
  d.lookup("npm", "lodash");
  d.lookup("PyPI", "requests");
  assert.deepStrictEqual(w.list(), []);
  assert.strictEqual(d.stale, false);
});
