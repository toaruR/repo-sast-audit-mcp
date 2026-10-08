import { test } from "node:test";
import assert from "node:assert";
import { LOCKFILE_MAX_BYTES } from "../src/constants.js";
import { checkLockfilesMissing, parseLockfile } from "../src/scanners/lockfiles.js";
import { Warnings } from "../src/pipeline/warnings.js";

function run(rel: string, content: string) {
  const w = new Warnings();
  return { pkgs: parseLockfile(rel, content, w), w };
}

test("requirements.txt name==1.2.3 pin yields name, version and line", () => {
  const { pkgs, w } = run("requirements.txt", "# c\nrequests==2.19.0\n");
  assert.deepStrictEqual(pkgs.map((p) => [p.ecosystem, p.name, p.version, p.line, p.confidence]), [
    ["PyPI", "requests", "2.19.0", 2, "high"],
  ]);
  assert.strictEqual(w.count("W_UNPINNED_REQUIREMENT"), 0);
});

test("T-33 (F-05): requirements.txt requests>=2 => W_UNPINNED_REQUIREMENT count 1 and 0 packages", () => {
  const { pkgs, w } = run("requirements.txt", "requests>=2\n");
  assert.strictEqual(pkgs.length, 0);
  assert.strictEqual(w.count("W_UNPINNED_REQUIREMENT"), 1);
});

test("go.sum yields name, version and line", () => {
  const g = "example.com/m v1.2.3 h1:abc=\nexample.com/m v1.2.3/go.mod h1:def=\n";
  const { pkgs } = run("go.sum", g);
  assert.deepStrictEqual(pkgs.map((p) => [p.ecosystem, p.name, p.version, p.line]), [
    ["Go", "example.com/m", "v1.2.3", 1],
  ]);
});

test("pom.xml literal dependency yields name, version and line", () => {
  const x = [
    "<project>",
    "  <dependencies>",
    "    <dependency>",
    "      <groupId>org.apache.logging.log4j</groupId>",
    "      <artifactId>log4j-core</artifactId>",
    "      <version>2.14.1</version>",
    "    </dependency>",
    "    <dependency>",
    "      <groupId>a</groupId><artifactId>b</artifactId><version>${v}</version>",
    "    </dependency>",
    "  </dependencies>",
    "</project>",
  ].join("\n");
  const { pkgs } = run("pom.xml", x);
  assert.deepStrictEqual(pkgs.map((p) => [p.ecosystem, p.name, p.version, p.line]), [
    ["Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", 3],
  ]);
});

test("T-33 (F-05): package.json-only repo => W_LOCKFILE_MISSING count 1", () => {
  const w = new Warnings();
  checkLockfilesMissing(["package.json", "src/a.js"], w);
  assert.strictEqual(w.count("W_LOCKFILE_MISSING"), 1);
  const w2 = new Warnings();
  checkLockfilesMissing(["package.json", "package-lock.json"], w2);
  assert.strictEqual(w2.count("W_LOCKFILE_MISSING"), 0);
});

test("lockfile larger than LOCKFILE_MAX_BYTES (16777216) is skipped with a warning", () => {
  const big = "# " + "x".repeat(LOCKFILE_MAX_BYTES) + "\n";
  const { pkgs, w } = run("Cargo.lock", big);
  assert.strictEqual(pkgs.length, 0);
  assert.strictEqual(w.count("W_FILE_TOO_LARGE"), 1);
});
