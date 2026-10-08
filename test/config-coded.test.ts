import { test } from "node:test";
import assert from "node:assert";
import { scanConfig } from "../src/scanners/config.js";

test("CFG-DOCKER-ROOT-001 fires on a Dockerfile without USER at line 1", () => {
  const r = scanConfig("Dockerfile", "FROM node:20\nRUN npm ci\n");
  assert.deepStrictEqual(r.map((m) => [m.ruleId, m.line]), [["CFG-DOCKER-ROOT-001", 1]]);
});

test("CFG-DOCKER-ROOT-001 does not fire on a Dockerfile with USER nonroot", () => {
  assert.deepStrictEqual(scanConfig("Dockerfile", "FROM node:20\nUSER nonroot\n"), []);
});

test("CFG-DOCKER-ROOT-001 fires when the last USER is root", () => {
  const r = scanConfig("app/Dockerfile", "FROM x\nUSER app\nUSER root\n");
  assert.deepStrictEqual(r.map((m) => m.line), [3]);
});

test("CFG-ENV-COMMITTED-001 fires on a committed .env at line 1 column 1", () => {
  const r = scanConfig(".env", "A=1\n");
  assert.deepStrictEqual(r.map((m) => [m.ruleId, m.line, m.column]), [["CFG-ENV-COMMITTED-001", 1, 1]]);
});

test("CFG-ENV-COMMITTED-001 does not fire on .env.example", () => {
  assert.deepStrictEqual(scanConfig(".env.example", "A=1\n"), []);
});
