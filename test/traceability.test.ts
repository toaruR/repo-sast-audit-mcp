import { test } from "node:test";
import assert from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ERROR_CODES } from "../src/errors.js";

interface CheckIds {
  sectionLines(text: string, start: string, end: string): string[];
  firstCells(lines: string[]): string[];
  designIds(text: string): string[];
  collectTitles(dir: string): string[];
  idInTitles(id: string, titles: string[]): boolean;
}

const nodeRequire = createRequire(import.meta.url);
const checker = nodeRequire("./fixtures/check-ids.cjs") as CheckIds;

const TEST_DIR = fileURLToPath(new URL(".", import.meta.url));
const DESIGN = fileURLToPath(new URL("../docs/design-repo-vuln-report-mcp.md", import.meta.url));
const CHECK_IDS = join(TEST_DIR, "fixtures", "check-ids.cjs");
const SELF = "traceability.test.ts";

const design = readFileSync(DESIGN, "utf8");
const titles = checker.collectTitles(TEST_DIR);

function otherTestSources(): string[] {
  return readdirSync(TEST_DIR)
    .filter((n) => n.endsWith(".test.ts") && n !== SELF)
    .map((n) => readFileSync(join(TEST_DIR, n), "utf8"));
}

test("T-14 E_* and W_* codes covered", () => {
  const sources = otherTestSources();
  const eCodes = Object.keys(ERROR_CODES);
  assert.strictEqual(eCodes.length, 16);
  const eUncovered = eCodes.filter((c) => !sources.some((s) => s.includes(c)));
  assert.deepStrictEqual(eUncovered, []);

  const section = [...checker.sectionLines(design, "## 4.", "## 5."), ...checker.sectionLines(design, "## 9.", "## 10.")].join("\n");
  const wCodes = [...new Set(section.match(/W_[A-Z_]+/g) ?? [])];
  assert.ok(wCodes.length > 0);
  const wUncovered = wCodes.filter((c) => !sources.some((s) => s.includes(c)));
  assert.deepStrictEqual(wUncovered, []);
});

test("test ids and failure-mode ids present", () => {
  const ids = checker.designIds(design);
  const tIds = ids.filter((i) => i.startsWith("T-"));
  const fIds = ids.filter((i) => i.startsWith("F-"));
  assert.strictEqual(tIds.length, 35);
  assert.strictEqual(fIds.length, 31);
  assert.deepStrictEqual(tIds.filter((i) => !checker.idInTitles(i, titles)), []);
  assert.deepStrictEqual(fIds.filter((i) => !checker.idInTitles(i, titles)), []);
  // an id followed by a lowercase letter or digit does not satisfy the shorter id
  assert.strictEqual(checker.idInTitles("F-02", ["T-19 (F-02a): x"]), false);
  assert.strictEqual(checker.idInTitles("T-01", ["T-010 x"]), false);
  assert.strictEqual(checker.idInTitles("F-02", ["T-19 (F-02): x"]), true);
});

const GOALS = { G1: "T-01", G2: "T-12", G3: "T-13", G4: "T-11", G5: "T-08", G6: "T-12" };

test("goals map", () => {
  assert.deepStrictEqual(GOALS, { G1: "T-01", G2: "T-12", G3: "T-13", G4: "T-11", G5: "T-08", G6: "T-12" });
  for (const t of Object.values(GOALS)) assert.ok(checker.idInTitles(t, titles), `${t} not in any test title`);
});

interface MapEntry {
  mechanism: string;
  tests: string[];
  residual?: string;
}

test("section 11 rows covered", () => {
  const cells = checker.firstCells(checker.sectionLines(design, "## 11.", "Out of scope"));
  // design v1.3 lists 28 mechanisms (the plan text said 19); the count is pinned so a table edit is noticed
  assert.strictEqual(cells.length, 28);
  const map = JSON.parse(readFileSync(join(TEST_DIR, "fixtures", "section11-map.json"), "utf8")) as MapEntry[];
  assert.deepStrictEqual(new Set(map.map((m) => m.mechanism)), new Set(cells));
  assert.strictEqual(map.length, cells.length);
  for (const e of map) {
    if (e.tests.length > 0) {
      for (const sub of e.tests) assert.ok(titles.some((t) => t.includes(sub)), `${e.mechanism}: no test title contains "${sub}"`);
    } else {
      assert.ok(typeof e.residual === "string" && e.residual.startsWith("RESIDUAL:") && e.residual.length > "RESIDUAL:".length, `${e.mechanism}: needs tests or RESIDUAL`);
    }
  }
});

function titleFile(ids: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "chkids-"));
  writeFileSync(join(dir, "x.test.ts"), ids.map((id) => `test("${id} case", () => {});`).join("\n") + "\n");
  return dir;
}

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CHECK_IDS, ...args], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("check-ids.cjs self-test", () => {
  const ids = checker.designIds(design);
  assert.strictEqual(ids.length, 66);

  const partial = run([DESIGN, titleFile(ids.filter((i) => i !== "F-14a"))]);
  assert.strictEqual(partial.status, 1);
  assert.deepStrictEqual(partial.stdout.split("\n").filter((l) => l !== ""), ["MISSING: F-14a"]);

  const full = run([DESIGN, titleFile(ids)]);
  assert.strictEqual(full.status, 0);
  assert.strictEqual(full.stdout, "OK: 66 ids found\n");

  const none = run([]);
  assert.strictEqual(none.status, 2);
  assert.ok(none.stderr.startsWith("ERROR:"));

  const bad = run([join(TEST_DIR, "no-such-design.md"), TEST_DIR]);
  assert.strictEqual(bad.status, 2);
  assert.ok(bad.stderr.startsWith("ERROR:"));
});
