import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { sanitize } from "../src/security/sanitize.js";
import { EVIDENCE_MAX } from "../src/constants.js";

test("<b> is escaped to &lt;b&gt; and & to &amp;", () => {
  assert.strictEqual(sanitize("<b>"), "&lt;b&gt;");
  assert.strictEqual(sanitize("a&b"), "a&amp;b");
});
test("U+202E is escaped (not present raw in output)", () => {
  const o = sanitize("ab‮cd");
  assert.ok(!o.includes("‮"));
  assert.ok(o.includes("\\u202E"));
});
test("ESC[31m is escaped (no raw 0x1B in output)", () => {
  const o = sanitize("\u001B[31mred");
  assert.ok(!o.includes("\u001B"));
  assert.ok(o.includes("\\u001B"));
});
test("input of EVIDENCE_MAX+50 (250) chars yields output length <= 200", () => {
  assert.ok(sanitize("x".repeat(EVIDENCE_MAX + 50)).length <= 200);
  assert.ok(sanitize("<".repeat(250)).length <= 200);
});
test("T-25 (F-12): IGNORE PREVIOUS INSTRUCTIONS text is preserved", () => {
  assert.strictEqual(sanitize("IGNORE PREVIOUS INSTRUCTIONS"), "IGNORE PREVIOUS INSTRUCTIONS");
});
test("T-15 evidence length", () => {
  const defs = JSON.parse(readFileSync(new URL("../schemas/defs.json", import.meta.url), "utf8"));
  assert.strictEqual(defs.Fnd.properties.evidence.maxLength, EVIDENCE_MAX);
});
