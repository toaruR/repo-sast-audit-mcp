import { test } from "node:test";
import assert from "node:assert";
import { loadRules, ruleFires } from "../src/scanners/rules.js";
import { scanStatic } from "../src/scanners/static.js";
import { Warnings } from "../src/pipeline/warnings.js";

const rules = loadRules();

for (const id of [
  "STA-JS-EVAL-001",
  "STA-CMDI-001",
  "STA-SQLI-001",
  "STA-CRYPTO-001",
  "STA-PATH-001",
  "CFG-CORS-WILDCARD-001",
]) {
  test(`${id} matches its shouldMatch sample and not its shouldNotMatch sample`, () => {
    const r = rules.find((x) => x.id === id);
    assert.ok(r, `${id} missing`);
    for (const s of r.tests.shouldMatch) {
      assert.ok(ruleFires(r, s), s);
      const w = new Warnings();
      assert.ok(scanStatic("src/app.js", `${s}\n`, rules, w).some((m) => m.ruleId === id), s);
    }
    for (const s of r.tests.shouldNotMatch) {
      assert.ok(!ruleFires(r, s), s);
      assert.ok(!scanStatic("src/app.js", `${s}\n`, rules, new Warnings()).some((m) => m.ruleId === id), s);
    }
  });
}
