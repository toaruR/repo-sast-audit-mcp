import { test } from "node:test";
import assert from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PEAK_RSS_MIB, PERF_TARGET_S } from "../src/constants.js";
import { loadAdvisoryDb } from "../src/advisory/db.js";
import { createOsvClient, type OsvClient } from "../src/net/osvClient.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { buildLocationIndex, lineOf, scanDependencies } from "../src/scanners/dependency.js";
import { parseLockfile, type LockPackage } from "../src/scanners/lockfiles.js";

function bigLockfile(p: number): string {
  const parts = ['{\n  "name": "big",\n  "lockfileVersion": 3,\n  "packages": {\n'];
  for (let i = 0; i < p; i++) {
    parts.push(
      `    "node_modules/pkg-${i}": {\n      "version": "1.0.${i}",\n      "resolved": "https://registry.invalid/pkg-${i}.tgz",\n      "integrity": "sha512-abcdefghijklmnop${i}"\n    }${i === p - 1 ? "" : ","}\n`,
    );
  }
  parts.push("  }\n}\n");
  return parts.join("");
}

function pkgs(n: number): LockPackage[] {
  return Array.from({ length: n }, (_, i) => ({
    ecosystem: "npm",
    name: `pkg-${i}`,
    version: `1.0.${i}`,
    line: i + 1,
    path: "package-lock.json",
    confidence: "high" as const,
  }));
}

/** Median wall time of the one-pass index build (lockfile text -> Map<"name@version", firstLine>). */
function bestTime(n: number, reps: number): number {
  const text = bigLockfile(n);
  const w = new Warnings();
  const times: number[] = [];
  for (let r = 0; r < reps; r++) {
    const t0 = performance.now();
    buildLocationIndex(parseLockfile("package-lock.json", text, w));
    times.push(performance.now() - t0);
  }
  times.sort((x, y) => x - y);
  return times[Math.floor(times.length / 2)] ?? 0; // median: robust against GC spikes
}

function emptyDb(w: Warnings) {
  const dir = mkdtempSync(join(tmpdir(), "perfdb-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt: "2026-10-01T00:00:00Z" }));
  return loadAdvisoryDb(dir, { warnings: w, now: "2026-10-01T00:00:00Z" });
}

test("T-07 (F-15) index linearity", () => {
  bestTime(10000, 3); // warm-up
  // Quadratic behaviour gives ~16; retry only to absorb scheduler/GC noise around the linear 4.
  let best = Infinity;
  for (let attempt = 0; attempt < 3 && best > 4.5; attempt++) {
    const small = bestTime(10000, 9);
    const large = bestTime(40000, 9);
    best = Math.min(best, large / Math.max(small, 0.001));
  }
  assert.ok(best <= 4.5, `ratio ${best}`);
});

let content = "";
let scanSeconds = Infinity;

test("T-07 max-size lockfile time", async () => {
  content = bigLockfile(40000);
  const w = new Warnings();
  const db = emptyDb(w);
  const t0 = performance.now();
  const findings = await scanDependencies([{ rel: "package-lock.json", content }], { db, warnings: w });
  scanSeconds = (performance.now() - t0) / 1000;
  assert.strictEqual(findings.length, 0);
  assert.ok(scanSeconds <= PERF_TARGET_S, `scan took ${scanSeconds}s`);
});

test("T-07 max-size lockfile memory", () => {
  const mib = process.memoryUsage().rss / 1048576;
  assert.ok(content.length > 0 && Number.isFinite(scanSeconds));
  assert.ok(mib <= PEAK_RSS_MIB, `rss ${mib} MiB`);
});

test("a package missing from the index gets line 1", () => {
  const index = buildLocationIndex(pkgs(3));
  assert.strictEqual(lineOf(index, "pkg-2", "1.0.2"), 3);
  assert.strictEqual(lineOf(index, "nope", "9.9.9"), 1);
});

test("parseLockfile on the big lockfile yields 40000 packages", () => {
  assert.strictEqual(parseLockfile("package-lock.json", bigLockfile(40000), new Warnings()).length, 40000);
});

test("online=false: the OSV client is never constructed (spy count 0)", async () => {
  let constructed = 0;
  const w = new Warnings();
  await scanDependencies([{ rel: "package-lock.json", content: bigLockfile(3) }], {
    db: emptyDb(w),
    warnings: w,
    online: false,
    createClient: () => {
      constructed++;
      return { query: async () => [] } as OsvClient;
    },
  });
  assert.strictEqual(constructed, 0);
});

test("online=true with network allowed: the OSV client (fake transport) is called once per unique package", async () => {
  const bodies: string[] = [];
  const w = new Warnings();
  const content2 = bigLockfile(3);
  const findings = await scanDependencies(
    [
      { rel: "package-lock.json", content: content2 },
      { rel: "sub/package-lock.json", content: content2 },
    ],
    {
      db: undefined,
      warnings: w,
      online: true,
      createClient: () =>
        createOsvClient({
          networkAllowed: () => true,
          transport: async (b) => {
            bodies.push(b);
            const { name } = JSON.parse(b) as { name: string };
            return name === "pkg-1" ? { vulns: [{ id: "OSV-1", summary: "bad" }] } : { vulns: [] };
          },
        }),
    },
  );
  assert.strictEqual(bodies.length, 3);
  assert.deepStrictEqual(
    bodies.map((b) => Object.keys(JSON.parse(b)).sort()),
    [0, 1, 2].map(() => ["ecosystem", "name", "version"]),
  );
  assert.strictEqual(findings.length, 2); // pkg-1 in both lockfiles
  assert.ok(findings.every((f) => f.online === true && f.advisoryId === "OSV-1"));
});
