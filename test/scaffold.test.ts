import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { DEP_MAX } from "../src/constants.js";

const pkg = JSON.parse(readFileSync("package.json", "utf8")) as {
  type: string;
  engines: { node: string };
  dependencies: Record<string, string>;
};

test("T001: exactly 9 runtime deps with major pins", () => {
  assert.deepStrictEqual(pkg.dependencies, {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "fast-xml-parser": "^4.0.0",
    ignore: "^5.0.0",
    picomatch: "^4.0.0",
    "re2-wasm": "^1.0.0",
    semver: "^7.0.0",
    "smol-toml": "^1.0.0",
    yaml: "^2.0.0",
    zod: "^3.0.0",
  });
  assert.strictEqual(Object.keys(pkg.dependencies).length, 9);
});

test("T001: engines, module type, DEP_MAX", () => {
  assert.strictEqual(pkg.engines.node, ">=20.11 <23");
  assert.strictEqual(pkg.type, "module");
  assert.strictEqual(DEP_MAX, 9);
});

test("T001: tsconfig strict true", () => {
  const ts = JSON.parse(readFileSync("tsconfig.json", "utf8")) as { compilerOptions: { strict: boolean } };
  assert.strictEqual(ts.compilerOptions.strict, true);
});
