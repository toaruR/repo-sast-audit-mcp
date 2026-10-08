import { test } from "node:test";
import assert from "node:assert";
import { existsSync } from "node:fs";
import path from "node:path";
import { PACKAGE_ROOT, assetPath } from "../src/assets.js";
import { DEFAULT_RULES_FILE } from "../src/scanners/rules.js";

test("PACKAGE_ROOT is the directory holding package.json, independent of cwd", () => {
  assert.ok(existsSync(path.join(PACKAGE_ROOT, "package.json")));
  assert.strictEqual(path.basename(PACKAGE_ROOT) === "src" || path.basename(PACKAGE_ROOT) === "dist", false);
});

test("bundled assets resolve under PACKAGE_ROOT", () => {
  assert.strictEqual(DEFAULT_RULES_FILE, assetPath("rules", "rules.json"));
  for (const p of [DEFAULT_RULES_FILE, assetPath("schemas", "tools.json"), assetPath("schemas", "defs.json")]) assert.ok(existsSync(p), p);
});
