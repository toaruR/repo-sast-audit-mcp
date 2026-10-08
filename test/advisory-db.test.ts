import { test } from "node:test";
import assert from "node:assert";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { STALE_DAYS, SHARD_LRU } from "../src/constants.js";
import { ageDays, loadAdvisoryDb, shardHash } from "../src/advisory/db.js";
import { Warnings } from "../src/pipeline/warnings.js";

function makeDb(generatedAt: string): string {
  const dir = mkdtempSync(join(tmpdir(), "advdb-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt }));
  return dir;
}

function writeShard(dir: string, eco: string, name: string, advisories: unknown[], hash?: string): void {
  mkdirSync(join(dir, eco), { recursive: true });
  writeFileSync(
    join(dir, eco, `${encodeURIComponent(name)}.json`),
    JSON.stringify({ contentSha256: hash ?? shardHash(advisories), advisories }),
  );
}

const GEN = "2026-09-01T00:00:00Z";

test("T-20 (F-05b): DB generatedAt STALE_DAYS+1 days old => W_ADVISORY_DB_STALE count 1", () => {
  const w = new Warnings();
  const now = Date.parse(GEN) + (STALE_DAYS + 1) * 86400000;
  loadAdvisoryDb(makeDb(GEN), { warnings: w, now, staleDays: STALE_DAYS });
  assert.strictEqual(w.count("W_ADVISORY_DB_STALE"), 1);
});

test("T-03 stale boundary 30", () => {
  const w = new Warnings();
  const db = loadAdvisoryDb(makeDb(GEN), { warnings: w, now: "2026-10-01T23:59:59Z", staleDays: STALE_DAYS });
  assert.strictEqual(db.ageDays, 30);
  assert.strictEqual(w.count("W_ADVISORY_DB_STALE"), 0);
});

test("T-03 stale boundary 31", () => {
  const w = new Warnings();
  const db = loadAdvisoryDb(makeDb(GEN), { warnings: w, now: "2026-10-02T00:00:00Z", staleDays: STALE_DAYS });
  assert.strictEqual(db.ageDays, 31);
  assert.strictEqual(w.count("W_ADVISORY_DB_STALE"), 1);
});

test("T-34 (F-05c) part: shard with wrong contentSha256 => W_ADVISORY_DB_INVALID_SHARD count 1 and shard ignored", () => {
  const dir = makeDb(GEN);
  writeShard(dir, "npm", "lodash", [{ id: "X-1" }], "0".repeat(64));
  const w = new Warnings();
  const db = loadAdvisoryDb(dir, { warnings: w, now: GEN });
  assert.deepStrictEqual(db.lookup("npm", "lodash"), []);
  db.lookup("npm", "lodash");
  assert.strictEqual(w.count("W_ADVISORY_DB_INVALID_SHARD"), 1);
});

test("a valid shard is returned", () => {
  const dir = makeDb(GEN);
  writeShard(dir, "npm", "lodash", [{ id: "X-1" }]);
  const db = loadAdvisoryDb(dir, { warnings: new Warnings(), now: GEN });
  assert.deepStrictEqual(db.lookup("npm", "lodash"), [{ id: "X-1" }]);
});

test("ageDays floor", () => {
  const g = Date.parse("2026-09-01T00:00:00Z");
  assert.strictEqual(ageDays(g, Date.parse("2026-10-01T23:59:59Z")), 30);
  assert.strictEqual(ageDays(g, Date.parse("2026-10-02T00:00:00Z")), 31);
  const now = g + 12345678;
  assert.strictEqual(ageDays(g, now), Math.floor((now - g) / 86400000));
});

test("loading more than SHARD_LRU (256) shards keeps at most 256 resident", () => {
  const db = loadAdvisoryDb(makeDb(GEN), { warnings: new Warnings(), now: GEN });
  for (let i = 0; i < SHARD_LRU + 44; i++) db.lookup("npm", `pkg-${i}`);
  assert.ok(db.residentShards() <= SHARD_LRU);
  assert.strictEqual(db.residentShards(), SHARD_LRU);
});

test("missing and invalid manifests raise coded errors", () => {
  const empty = mkdtempSync(join(tmpdir(), "advdb-"));
  assert.throws(() => loadAdvisoryDb(empty, { warnings: new Warnings() }), { code: "E_ADVISORY_DB_MISSING" });
  writeFileSync(join(empty, "manifest.json"), "{nope");
  assert.throws(() => loadAdvisoryDb(empty, { warnings: new Warnings() }), { code: "E_ADVISORY_DB_INVALID" });
});
