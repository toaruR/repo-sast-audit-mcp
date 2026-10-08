import { test } from "node:test";
import assert from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { loadAdvisoryDb } from "../src/advisory/db.js";
import { updateAdvisoryDb } from "../src/advisory/update.js";
import { zipEntries, zipRead } from "../src/advisory/zip.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { AdvisoryDbUpdater, updateAdvisoryDbTool } from "../src/tools/updateAdvisoryDb.js";
import { validateOutput } from "../src/contracts.js";

/** Minimal zip writer (CRC left 0; the reader does not check it). */
function makeZip(files: Record<string, string>, deflate = true): Buffer {
  const locals: Buffer[] = [];
  const cens: Buffer[] = [];
  let off = 0;
  for (const [name, text] of Object.entries(files)) {
    const nameBuf = Buffer.from(name);
    const raw = Buffer.from(text);
    const data = deflate ? deflateRawSync(raw) : raw;
    const loc = Buffer.alloc(30);
    loc.writeUInt32LE(0x04034b50, 0);
    loc.writeUInt16LE(deflate ? 8 : 0, 8);
    loc.writeUInt32LE(data.length, 18);
    loc.writeUInt32LE(raw.length, 22);
    loc.writeUInt16LE(nameBuf.length, 26);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(deflate ? 8 : 0, 10);
    cen.writeUInt32LE(data.length, 20);
    cen.writeUInt32LE(raw.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt32LE(off, 42);
    locals.push(loc, nameBuf, data);
    cens.push(cen, nameBuf);
    off += 30 + nameBuf.length + data.length;
  }
  const cenBuf = Buffer.concat(cens);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(Object.keys(files).length, 8);
  eocd.writeUInt16LE(Object.keys(files).length, 10);
  eocd.writeUInt32LE(cenBuf.length, 12);
  eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cenBuf, eocd]);
}

const adv = (id: string, eco: string, name: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ id, affected: [{ package: { ecosystem: eco, name }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }] }], ...extra });

const DUMPS: Record<string, Buffer> = {
  npm: makeZip({
    "GHSA-b.json": adv("GHSA-b", "npm", "left-pad"),
    "GHSA-a.json": adv("GHSA-a", "npm", "left-pad"),
    "MAL-1.json": adv("MAL-1", "npm", "evil"),
    "GHSA-w.json": adv("GHSA-w", "npm", "gone", { withdrawn: "2026-01-01T00:00:00Z" }),
    "broken.json": "{not json",
  }),
  PyPI: makeZip({ "PYSEC-1.json": adv("PYSEC-1", "PyPI", "requests") }, false),
};
const transport = async (url: string) => {
  const eco = decodeURIComponent(url.split("/").at(-2)!);
  const z = DUMPS[eco];
  if (!z) throw new Error("no dump");
  return z;
};

const sc = (r: { structuredContent: unknown }) => r.structuredContent as Record<string, unknown>;

function dbDir(): string {
  return join(mkdtempSync(join(tmpdir(), "sast-upd-")), "db");
}

test("zip reader: lists entries and reads stored and deflated data", () => {
  for (const deflate of [true, false]) {
    const z = makeZip({ "a.json": "{\"x\":1}", "b.txt": "hello" }, deflate);
    const es = zipEntries(z);
    assert.deepStrictEqual(es.map((e) => e.name), ["a.json", "b.txt"]);
    assert.strictEqual(zipRead(z, es[1]!).toString(), "hello");
  }
  assert.throws(() => zipEntries(Buffer.from("not a zip at all, definitely not")), /end of central directory/);
});

test("update builds a DB that loadAdvisoryDb accepts; shards sorted by id; withdrawn and unparsable skipped", async () => {
  const dir = dbDir();
  const r = await updateAdvisoryDb(dir, { ecosystems: ["npm", "PyPI"], includeMalware: true }, { transport });
  assert.deepStrictEqual({ advisories: r.advisories, shards: r.shards, unparsable: r.unparsable }, { advisories: 4, shards: 3, unparsable: 1 });
  const w = new Warnings();
  const db = loadAdvisoryDb(dir, { warnings: w });
  assert.deepStrictEqual(db.lookup("npm", "left-pad").map((a) => a.id), ["GHSA-a", "GHSA-b"]);
  assert.deepStrictEqual(db.lookup("PyPI", "requests").map((a) => a.id), ["PYSEC-1"]);
  assert.deepStrictEqual(db.lookup("npm", "gone"), []);
  assert.strictEqual(w.list().length, 0);
});

test("includeMalware false drops MAL-* records", async () => {
  const dir = dbDir();
  await updateAdvisoryDb(dir, { ecosystems: ["npm"], includeMalware: false }, { transport });
  assert.deepStrictEqual(loadAdvisoryDb(dir, { warnings: new Warnings() }).lookup("npm", "evil"), []);
  assert.strictEqual(JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")).includeMalware, false);
});

test("an existing DB is replaced and no tmp/old directories remain", async () => {
  const dir = dbDir();
  await updateAdvisoryDb(dir, { ecosystems: ["npm", "PyPI"], includeMalware: true }, { transport });
  await updateAdvisoryDb(dir, { ecosystems: ["npm"], includeMalware: true }, { transport });
  assert.ok(!existsSync(join(dir, "PyPI")));
  assert.deepStrictEqual(readdirSync(join(dir, "..")), ["db"]);
});

test("a failed download keeps the previous DB and removes the tmp directory", async () => {
  const dir = dbDir();
  await updateAdvisoryDb(dir, { ecosystems: ["npm"], includeMalware: true }, { transport });
  const before = readFileSync(join(dir, "manifest.json"), "utf8");
  await assert.rejects(updateAdvisoryDb(dir, { ecosystems: ["Go"], includeMalware: true }, { transport }));
  assert.strictEqual(readFileSync(join(dir, "manifest.json"), "utf8"), before);
  assert.deepStrictEqual(readdirSync(join(dir, "..")), ["db"]);
});

test("a non-empty directory without a valid manifest is refused with E_OUTPUT_DIR_UNSAFE", async () => {
  const dir = dbDir();
  mkdirSync(dir);
  writeFileSync(join(dir, "precious.txt"), "keep");
  await assert.rejects(updateAdvisoryDb(dir, { ecosystems: ["npm"], includeMalware: true }, { transport }), { code: "E_OUTPUT_DIR_UNSAFE" });
  assert.strictEqual(readFileSync(join(dir, "precious.txt"), "utf8"), "keep");
});

test("tool: network disabled => E_NETWORK_DISABLED; missing path => E_ADVISORY_DB_MISSING", () => {
  const off = updateAdvisoryDbTool(new AdvisoryDbUpdater({ dbPath: dbDir(), networkAllowed: () => false }), {});
  assert.strictEqual(sc(off)["error"] && (sc(off)["error"] as { code: string }).code, "E_NETWORK_DISABLED");
  const nopath = updateAdvisoryDbTool(new AdvisoryDbUpdater({ dbPath: "", networkAllowed: () => true }), {});
  assert.strictEqual((sc(nopath)["error"] as { code: string }).code, "E_ADVISORY_DB_MISSING");
  const bad = updateAdvisoryDbTool(new AdvisoryDbUpdater(), { ecosystems: ["RubyGems"] });
  assert.strictEqual((sc(bad)["error"] as { code: string }).code, "E_INVALID_INPUT");
});

test("tool: start runs in background, a second start while running is not started, status reports completion", async () => {
  const u = new AdvisoryDbUpdater({ dbPath: dbDir(), networkAllowed: () => true, transport });
  const first = updateAdvisoryDbTool(u, { ecosystems: ["npm"] });
  assert.strictEqual(sc(first)["started"], true);
  assert.strictEqual(sc(first)["state"], "running");
  const second = updateAdvisoryDbTool(u, {});
  assert.strictEqual(sc(second)["started"], false);
  await u.settled();
  const done = updateAdvisoryDbTool(u, { action: "status" });
  assert.strictEqual(sc(done)["state"], "completed");
  assert.strictEqual((sc(done)["result"] as { shards: number }).shards, 2);
  assert.ok(validateOutput("update_advisory_db", sc(done)).valid);
});

test("tool: a failed update reports state failed with a generic error", async () => {
  const u = new AdvisoryDbUpdater({ dbPath: dbDir(), networkAllowed: () => true, transport });
  updateAdvisoryDbTool(u, { ecosystems: ["Go"] });
  await u.settled();
  const st = sc(updateAdvisoryDbTool(u, { action: "status" }));
  assert.strictEqual(st["state"], "failed");
  assert.deepStrictEqual(st["error"], { code: "E_INTERNAL", message: "advisory DB update failed", retryable: false });
  assert.ok(validateOutput("update_advisory_db", st).valid);
});
