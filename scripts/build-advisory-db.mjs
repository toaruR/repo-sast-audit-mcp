#!/usr/bin/env node
// Build the offline advisory DB (manifest.json + <ecosystem>/<name>.json shards)
// from extracted OSV dumps (https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip).
//
// usage: node scripts/build-advisory-db.mjs <outDir> <extractedOsvDir>...
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

// Ecosystems produced by src/scanners/lockfiles.ts.
const ECOSYSTEMS = new Set(["npm", "PyPI", "crates.io", "Go", "Maven"]);

// Must match safeSegment() and shardHash() in src/advisory/db.ts.
const safeSegment = (s) => encodeURIComponent(s).replace(/\./g, "%2E");
const shardHash = (advisories) => createHash("sha256").update(JSON.stringify(advisories)).digest("hex");

const [outArg, ...inputs] = process.argv.slice(2);
if (outArg === undefined || inputs.length === 0) {
  console.error("usage: node scripts/build-advisory-db.mjs <outDir> <extractedOsvDir>...");
  process.exit(2);
}
const outDir = resolve(outArg);
const tmpDir = `${outDir}.tmp`;

// Pass 1: index "<ecosystem>\n<name>" -> advisory files (keeps memory flat).
const index = new Map();
let files = 0;
let skipped = 0;
for (const dir of inputs) {
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const path = join(dir, f);
    let adv;
    try {
      adv = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      skipped++;
      continue;
    }
    if (adv.withdrawn !== undefined) continue;
    files++;
    for (const aff of adv.affected ?? []) {
      const eco = aff.package?.ecosystem;
      const name = aff.package?.name;
      if (!ECOSYSTEMS.has(eco) || typeof name !== "string") continue;
      const key = `${eco}\n${name}`;
      const list = index.get(key) ?? [];
      if (!list.includes(path)) list.push(path);
      index.set(key, list);
    }
  }
}

// Pass 2: write one shard per package, sorted by id for reproducible hashes.
rmSync(tmpDir, { recursive: true, force: true });
mkdirSync(tmpDir, { recursive: true });
const made = new Set();
for (const [key, paths] of index) {
  const [eco, name] = key.split("\n");
  const advisories = paths
    .map((p) => JSON.parse(readFileSync(p, "utf8")))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const ecoDir = join(tmpDir, safeSegment(eco));
  if (!made.has(ecoDir)) {
    mkdirSync(ecoDir, { recursive: true });
    made.add(ecoDir);
  }
  writeFileSync(join(ecoDir, `${safeSegment(name)}.json`), JSON.stringify({ contentSha256: shardHash(advisories), advisories }));
}
writeFileSync(
  join(tmpDir, "manifest.json"),
  JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), source: "osv.dev", advisories: files, shards: index.size }, null, 2),
);

rmSync(outDir, { recursive: true, force: true });
renameSync(tmpDir, outDir);
console.log(`advisories=${files} shards=${index.size} unparsable=${skipped} -> ${outDir}`);
