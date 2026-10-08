import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { CURSOR_MAX, GET_FINDINGS_MAX, GLOB_LEN, GLOB_N, PATHPREFIX_MAX, PATH_MAX, RULEID_MAX } from "../src/constants.js";

const load = (n: string): any => JSON.parse(readFileSync(new URL(`../schemas/${n}`, import.meta.url), "utf8"));

test("T-15 schema numbers equal 2.2 constants", () => {
  const tools = load("tools.json");
  const defs = load("defs.json");
  const gf = tools.get_findings.input.properties;
  assert.strictEqual(gf.cursor.maxLength, CURSOR_MAX);
  assert.strictEqual(gf.limit.maximum, GET_FINDINGS_MAX);
  assert.strictEqual(gf.filter.properties.pathPrefix.maxLength, PATHPREFIX_MAX);
  assert.strictEqual(tools.scan_repository.input.properties.repoPath.maxLength, PATH_MAX);
  // generate_report is added by a later schema task; compare outputDir as soon as it exists.
  if (tools.generate_report) {
    assert.strictEqual(tools.generate_report.input.properties.outputDir.maxLength, PATH_MAX);
  }
  assert.strictEqual(defs.Fnd.properties.ruleId.maxLength, RULEID_MAX);
  assert.strictEqual(defs.Globs.items.maxLength, GLOB_LEN);
  assert.strictEqual(defs.Globs.maxItems, GLOB_N);
});
