import { test } from "node:test";
import assert from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Warnings } from "../src/pipeline/warnings.js";
import { scanConfig } from "../src/scanners/config.js";
import { loadRules } from "../src/scanners/rules.js";
import { scanSecrets } from "../src/scanners/secret.js";
import { scanStatic } from "../src/scanners/static.js";
import {
  AWS_KEY,
  PLANTED_JS,
  PLANTED_MARKERS,
  PLANTED_PY,
  buildClean,
  buildPlantedJs,
  buildPlantedPy,
  type Planted,
} from "./fixtures/build.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "fixb-"));
}

function files(root: string, rel = ""): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(root, rel)).sort()) {
    const r = rel === "" ? name : `${rel}/${name}`;
    if (statSync(join(root, r)).isDirectory()) out.push(...files(root, r));
    else out.push(r);
  }
  return out;
}

function treeHash(root: string): string {
  const h = createHash("sha256");
  for (const f of files(root)) h.update(f).update("\0").update(readFileSync(join(root, f))).update("\0");
  return h.digest("hex");
}

/** Runs the non-dependency scanners over the tree: "ruleId|path|line[|column]" strings. */
function detect(root: string): string[] {
  const rules = loadRules();
  const out: string[] = [];
  for (const rel of files(root)) {
    const content = readFileSync(join(root, rel), "utf8");
    for (const m of scanSecrets(rel, content)) out.push(`${m.ruleId}|${rel}|${m.line}|${m.column}`);
    for (const m of scanStatic(rel, content, rules, new Warnings())) out.push(`${m.ruleId}|${rel}|${m.line}|${m.column}`);
    for (const m of scanConfig(rel, content)) out.push(`${m.ruleId}|${rel}|${m.line}|${m.column}`);
  }
  return out;
}

function check(root: string, planted: readonly Planted[], depLine: string): void {
  const got = detect(root).map((s) => s.split("|").slice(0, 3).join("|")).sort();
  const nonDep = planted.filter((p) => p.ruleId !== "DEP-OSV-ADVISORY");
  const want = nonDep.map((p) => `${p.ruleId}|${p.path}|${p.line}`).sort();
  assert.deepStrictEqual(got, want);
  const dep = planted.find((p) => p.ruleId === "DEP-OSV-ADVISORY");
  assert.ok(dep);
  const text = readFileSync(join(root, dep.path), "utf8").split("\n")[dep.line - 1] ?? "";
  assert.ok(text.includes(depLine), `dependency line: ${text}`);
}

test("planted-js builder output has the 10 listed (ruleId,path,line) positions", () => {
  const root = tmp();
  buildPlantedJs(root);
  assert.strictEqual(PLANTED_JS.length, 10);
  check(root, PLANTED_JS, '"version": "4.17.15"');
  assert.ok(readFileSync(join(root, "package-lock.json"), "utf8").split("\n")[4]?.includes("node_modules/lodash"));
});

test("planted-py builder output has the 9 listed positions", () => {
  const root = tmp();
  buildPlantedPy(root);
  assert.strictEqual(PLANTED_PY.length, 9);
  check(root, PLANTED_PY, "requests==2.19.0");
});

test("clean builder output contains none of the planted markers", () => {
  const root = tmp();
  buildClean(root);
  assert.deepStrictEqual(detect(root), []);
  for (const f of files(root)) {
    const text = readFileSync(join(root, f), "utf8");
    for (const m of PLANTED_MARKERS) assert.ok(!text.includes(m), `${f} contains ${m}`);
  }
});

test("planted-js .env has the AKIA key at line 2 column 19", () => {
  const root = tmp();
  buildPlantedJs(root);
  const hits = scanSecrets(".env", readFileSync(join(root, ".env"), "utf8"));
  assert.strictEqual(hits.length, 1);
  assert.deepStrictEqual([hits[0]?.ruleId, hits[0]?.line, hits[0]?.column, hits[0]?.raw], ["SEC-AWS-ACCESS-KEY-ID", 2, 19, AWS_KEY]);
});

test("planted-py keys/test.pem has the BEGIN PRIVATE KEY line at line 1", () => {
  const root = tmp();
  buildPlantedPy(root);
  const hits = scanSecrets("keys/test.pem", readFileSync(join(root, "keys", "test.pem"), "utf8"));
  assert.deepStrictEqual(hits.map((h) => [h.ruleId, h.line]), [["SEC-PRIVATE-KEY", 1]]);
});

test("two builder runs produce byte-identical trees", () => {
  for (const build of [buildPlantedJs, buildPlantedPy, buildClean]) {
    const a = tmp();
    const b = tmp();
    build(a);
    build(b);
    assert.deepStrictEqual(files(a), files(b));
    assert.strictEqual(treeHash(a), treeHash(b));
  }
});
