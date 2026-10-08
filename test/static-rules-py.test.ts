import { test } from "node:test";
import assert from "node:assert";
import { loadRules, ruleFires } from "../src/scanners/rules.js";
import { scanStatic } from "../src/scanners/static.js";
import { Warnings } from "../src/pipeline/warnings.js";

const rules = loadRules();

const FILES: Record<string, string> = {
  "STA-DESER-PY-001": "app.py",
  "STA-PY-CMDI-001": "app.py",
  "STA-DESER-PY-002": "app.py",
  "CFG-DEBUG-ENABLED-001": "settings.py",
  "CFG-GHA-PULL-REQUEST-TARGET-001": ".github/workflows/ci.yml",
  "CFG-GHA-SCRIPT-INJECTION-001": ".github/workflows/ci.yml",
};

for (const [id, file] of Object.entries(FILES)) {
  test(`${id} matches its shouldMatch sample and not its shouldNotMatch sample`, () => {
    const r = rules.find((x) => x.id === id);
    assert.ok(r, `${id} missing`);
    for (const s of r.tests.shouldMatch) {
      assert.ok(ruleFires(r, s), s);
      assert.ok(scanStatic(file, `${s}\n`, rules, new Warnings()).some((m) => m.ruleId === id), s);
    }
    for (const s of r.tests.shouldNotMatch) {
      assert.ok(!ruleFires(r, s), s);
      assert.ok(!scanStatic(file, `${s}\n`, rules, new Warnings()).some((m) => m.ruleId === id), s);
    }
  });
}
