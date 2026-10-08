import { test } from "node:test";
import assert from "node:assert";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAdvisoryDb, shardHash, type Advisory } from "../src/advisory/db.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { matchPackages, scanDependencies } from "../src/scanners/dependency.js";
import type { LockPackage } from "../src/scanners/lockfiles.js";

const GEN = "2026-10-01T00:00:00Z";

function db(eco: string, name: string, advisories: Advisory[], warnings: Warnings) {
  const dir = mkdtempSync(join(tmpdir(), "depdb-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt: GEN }));
  mkdirSync(join(dir, eco), { recursive: true });
  writeFileSync(
    join(dir, eco, `${encodeURIComponent(name)}.json`),
    JSON.stringify({ contentSha256: shardHash(advisories), advisories }),
  );
  return loadAdvisoryDb(dir, { warnings, now: GEN });
}

const lockfile = (version: string) =>
  [
    "{",
    '  "name": "x",',
    '  "lockfileVersion": 3,',
    '  "packages": {',
    '    "node_modules/lodash": {',
    `      "version": "${version}"`,
    "    }",
    "  }",
    "}",
    "",
  ].join("\n");

const ADV: Advisory = {
  id: "GHSA-test-0001",
  summary: "Prototype pollution",
  severity: [{ type: "CVSS_V3", score: 7.4 }],
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
};

async function run(version: string, advisories: Advisory[]) {
  const w = new Warnings();
  const d = db("npm", "lodash", advisories, w);
  const findings = await scanDependencies([{ rel: "package-lock.json", content: lockfile(version) }], { db: d, warnings: w });
  return { findings, w };
}

test("T-34 (F-05c) part: lockfile version abc vs semver range => W_UNCOMPARABLE_VERSION count 1 and no finding", async () => {
  const { findings, w } = await run("abc", [ADV]);
  assert.strictEqual(findings.length, 0);
  assert.strictEqual(w.count("W_UNCOMPARABLE_VERSION"), 1);
});

test("lodash 4.17.15 with CVSS 7.4 gives severity high", async () => {
  const { findings } = await run("4.17.15", [ADV]);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0]?.severity, "high");
  assert.deepStrictEqual(findings[0]?.cvss, { score: 7.4, version: "3" });
});

test("the DEP-OSV-ADVISORY finding for lodash 4.17.15 (item A1) has location.path package-lock.json and location.line 6", async () => {
  const { findings } = await run("4.17.15", [ADV]);
  assert.deepStrictEqual(findings[0]?.location, { path: "package-lock.json", line: 6, column: 1 });
});

test("ruleId is DEP-OSV-ADVISORY and evidence equals <eco>:<name>@<version>", async () => {
  const { findings } = await run("4.17.15", [ADV]);
  assert.strictEqual(findings[0]?.ruleId, "DEP-OSV-ADVISORY");
  assert.strictEqual(findings[0]?.evidence, "npm:lodash@4.17.15");
  assert.strictEqual(findings[0]?.scanner, "dependency");
});

test("remediation equals Upgrade lodash to >= <lowest fixed>", async () => {
  const { findings } = await run("4.17.15", [ADV]);
  assert.strictEqual(findings[0]?.remediation, "Upgrade lodash to >= 4.17.21");
  assert.strictEqual(findings[0]?.package?.fixedIn, "4.17.21");
});

test("an advisory with no fixed version gives remediation No fixed version is known", async () => {
  const noFix: Advisory = {
    ...ADV,
    affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }],
  };
  const { findings } = await run("4.17.15", [noFix]);
  assert.strictEqual(findings[0]?.remediation, "No fixed version is known");
});

test("fixed versions are not reported", async () => {
  const { findings } = await run("4.17.21", [ADV]);
  assert.strictEqual(findings.length, 0);
});

test("PEP 440 and Maven ranges are compared with ecosystem rules", () => {
  const w = new Warnings();
  const pyAdv: Advisory = {
    id: "PYSEC-1",
    affected: [{ package: { ecosystem: "PyPI", name: "requests" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] }] }],
  };
  const mvAdv: Advisory = {
    id: "GHSA-mv",
    affected: [{ package: { ecosystem: "Maven", name: "g:a" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0-beta9" }, { fixed: "2.15.0" }] }] }],
  };
  const mk = (ecosystem: string, name: string, version: string): LockPackage => ({ ecosystem, name, version, line: 1, path: "f", confidence: "medium" });
  const py = db("PyPI", "requests", [pyAdv], w);
  assert.strictEqual(matchPackages([mk("PyPI", "requests", "2.19.0")], py, w).length, 1);
  assert.strictEqual(matchPackages([mk("PyPI", "requests", "2.20.0")], py, w).length, 0);
  assert.strictEqual(matchPackages([mk("PyPI", "requests", "2.20.0rc1")], py, w).length, 1);
  const mv = db("Maven", "g:a", [mvAdv], w);
  assert.strictEqual(matchPackages([mk("Maven", "g:a", "2.14.1")], mv, w).length, 1);
  assert.strictEqual(matchPackages([mk("Maven", "g:a", "2.15.0")], mv, w).length, 0);
  assert.strictEqual(matchPackages([mk("Maven", "g:a", "1.9")], mv, w).length, 0);
  assert.strictEqual(w.count("W_UNCOMPARABLE_VERSION"), 0);
});
