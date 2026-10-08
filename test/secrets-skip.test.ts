import { test } from "node:test";
import assert from "node:assert";
import { RE2 } from "re2-wasm";
import { SECRET_PATTERNS, GENERIC_SOURCE, scanSecrets } from "../src/scanners/secret.js";

const HI = "kJ8dP2xQ9vL4mZ7wR1tY6uN3bC5hG0aS";

test('a quoted value containing "example" or "your_" produces 0 findings', () => {
  assert.strictEqual(scanSecrets("a.ts", `token = "example${HI}"`).length, 0);
  assert.strictEqual(scanSecrets("a.ts", `token = "your_${HI}"`).length, 0);
});

test('a "${X}" placeholder value produces 0 findings', () => {
  assert.strictEqual(scanSecrets("a.ts", 'token = "${SOME_SECRET_ENV_VARIABLE_X}"').length, 0);
});

test("a high-entropy token inside a file named .env.example produces 0 findings", () => {
  assert.strictEqual(scanSecrets("cfg/.env.example", `token = "${HI}"`).length, 0);
  assert.strictEqual(scanSecrets(".env", `token = "${HI}"`).length, 1);
});

test("a 100000-char single line holding an AKIA key is scanned in SECRET_WINDOW_BYTES (4096) windows and the key is found", () => {
  const key = " AKIAABCDEFGHIJKLMNOP ";
  for (const pos of [50_000, 4096 - 10, 3840 - 5]) {
    const line = "x".repeat(pos) + key + "x".repeat(100_000 - pos - key.length);
    assert.strictEqual(line.length, 100_000);
    const r = scanSecrets("min.js", line);
    assert.strictEqual(r.length, 1, `pos ${pos}`);
    assert.strictEqual(r[0]?.column, pos + 2);
  }
});

test("secret patterns contain no lookaround or backreference (all compile with re2-wasm)", () => {
  const sources = [...SECRET_PATTERNS.map((r) => r.pattern), GENERIC_SOURCE];
  for (const s of sources) {
    assert.ok(!/\(\?<?[=!]/.test(s), s);
    assert.ok(!/\\[1-9]/.test(s), s);
    assert.doesNotThrow(() => new RE2(s, "u"));
  }
});
