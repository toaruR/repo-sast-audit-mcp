import { test } from "node:test";
import assert from "node:assert";
import { parseLockfile } from "../src/scanners/lockfiles.js";
import { Warnings } from "../src/pipeline/warnings.js";

const NPM = [
  "{",
  '  "name": "x",',
  '  "lockfileVersion": 3,',
  '  "packages": {',
  '    "node_modules/lodash": {',
  '      "version": "4.17.15",',
  '      "resolved": "https://example.invalid/lodash.tgz"',
  "    }",
  "  }",
  "}",
  "",
].join("\n");

function run(rel: string, content: string) {
  const w = new Warnings();
  return { pkgs: parseLockfile(rel, content, w), w };
}

test("package-lock.json yields name lodash, version 4.17.15, line 6", () => {
  const { pkgs } = run("package-lock.json", NPM);
  assert.deepStrictEqual(
    pkgs.map((p) => [p.ecosystem, p.name, p.version, p.line]),
    [["npm", "lodash", "4.17.15", 6]],
  );
});

test("yarn.lock yields name, version and 1-based line of the entry", () => {
  const y = '# yarn lockfile v1\n\n\nlodash@^4.17.15, lodash@^4.17.0:\n  version "4.17.15"\n  resolved "x"\n';
  const { pkgs } = run("yarn.lock", y);
  assert.deepStrictEqual(pkgs.map((p) => [p.name, p.version, p.line]), [["lodash", "4.17.15", 4]]);
  const s = run("yarn.lock", '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n');
  assert.deepStrictEqual(s.pkgs.map((p) => [p.name, p.version, p.line]), [["@scope/pkg", "1.2.3", 1]]);
});

test("pnpm-lock.yaml yields name, version and 1-based line of the entry", () => {
  const p = "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.15:\n    resolution: {integrity: sha512-x}\n    dev: false\n\n  /@scope/pkg@1.0.0(react@18.0.0):\n    dev: false\n";
  const { pkgs } = run("pnpm-lock.yaml", p);
  assert.deepStrictEqual(
    pkgs.map((q) => [q.name, q.version, q.line]),
    [
      ["lodash", "4.17.15", 5],
      ["@scope/pkg", "1.0.0", 9],
    ],
  );
});

test("poetry.lock yields name, version and 1-based line of the entry", () => {
  const t = '# generated\n\n[[package]]\nname = "requests"\nversion = "2.19.0"\n\n[metadata]\nlock-version = "2.0"\n';
  const { pkgs } = run("poetry.lock", t);
  assert.deepStrictEqual(pkgs.map((q) => [q.ecosystem, q.name, q.version, q.line]), [["PyPI", "requests", "2.19.0", 3]]);
});

test("Cargo.lock yields name, version and 1-based line of the entry", () => {
  const t = 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.100"\n\n[[package]]\nname = "tokio"\nversion = "1.0.0"\n';
  const { pkgs } = run("Cargo.lock", t);
  assert.deepStrictEqual(
    pkgs.map((q) => [q.ecosystem, q.name, q.version, q.line]),
    [
      ["crates.io", "serde", "1.0.100", 3],
      ["crates.io", "tokio", "1.0.0", 7],
    ],
  );
});

test("T-17 (F-05): package-lock.json cut after version:4.17.15 => 0 packages, W_LOCKFILE_MALFORMED count 1, no E_INTERNAL", () => {
  const cut = NPM.slice(0, NPM.indexOf('"4.17.15"') + '"4.17.15"'.length);
  const { pkgs, w } = run("package-lock.json", cut);
  assert.strictEqual(pkgs.length, 0);
  assert.strictEqual(w.count("W_LOCKFILE_MALFORMED"), 1);
});
