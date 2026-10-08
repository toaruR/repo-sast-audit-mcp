import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { npmLockfile, requirementsTxt } from "./lockfiles.js";

// Planted fixture trees (design section 10). Builders are pure functions of their input: same
// call, byte-identical tree. All text is LF.

export interface Planted {
  ruleId: string;
  path: string;
  line: number;
  /** Weighted contribution W*M10 (section 10 table). */
  weight: number;
  column?: number;
}

export const AWS_KEY = "AKIAZ7QW3RT5YU2MNB4K";
export const API_SECRET_VALUE = "kJ8dP2xQ9vL4mZ7wR1tY6uN3bC5hG0aS";

export const PLANTED_JS: readonly Planted[] = [
  { ruleId: "CFG-CORS-WILDCARD-001", path: "src/app.js", line: 7, weight: 40 },
  { ruleId: "STA-JS-EVAL-001", path: "src/app.js", line: 10, weight: 70 },
  { ruleId: "STA-CMDI-001", path: "src/app.js", line: 11, weight: 70 },
  { ruleId: "STA-SQLI-001", path: "src/app.js", line: 14, weight: 70 },
  { ruleId: "STA-CRYPTO-001", path: "src/app.js", line: 16, weight: 40 },
  { ruleId: "STA-PATH-001", path: "src/app.js", line: 18, weight: 16 },
  { ruleId: "DEP-OSV-ADVISORY", path: "package-lock.json", line: 6, weight: 100 },
  { ruleId: "SEC-AWS-ACCESS-KEY-ID", path: ".env", line: 2, column: 19, weight: 250 },
  { ruleId: "CFG-ENV-COMMITTED-001", path: ".env", line: 1, column: 1, weight: 28 },
  { ruleId: "CFG-DOCKER-ROOT-001", path: "Dockerfile", line: 1, weight: 40 },
];

export const PLANTED_PY: readonly Planted[] = [
  { ruleId: "STA-DESER-PY-001", path: "app.py", line: 4, weight: 100 },
  { ruleId: "STA-PY-CMDI-001", path: "app.py", line: 7, weight: 70 },
  { ruleId: "STA-DESER-PY-002", path: "app.py", line: 10, weight: 70 },
  { ruleId: "SEC-GENERIC-HIGH-ENTROPY", path: "config.py", line: 2, weight: 70 },
  { ruleId: "CFG-DEBUG-ENABLED-001", path: "settings.py", line: 3, weight: 28 },
  { ruleId: "DEP-OSV-ADVISORY", path: "requirements.txt", line: 1, weight: 100 },
  { ruleId: "SEC-PRIVATE-KEY", path: "keys/test.pem", line: 1, weight: 250 },
  { ruleId: "CFG-GHA-PULL-REQUEST-TARGET-001", path: ".github/workflows/ci.yml", line: 3, weight: 16 },
  { ruleId: "CFG-GHA-SCRIPT-INJECTION-001", path: ".github/workflows/ci.yml", line: 9, weight: 100 },
];

/** Strings that must appear in no clean tree. */
export const PLANTED_MARKERS: readonly string[] = [
  AWS_KEY,
  API_SECRET_VALUE,
  "BEGIN PRIVATE KEY",
  "eval(",
  "pickle.loads",
  "yaml.load(",
  "os.system",
  "createHash",
  "Allow-Origin",
  "DEBUG = True",
  "pull_request_target",
  "4.17.15",
  "2.19.0",
];

function put(root: string, rel: string, text: string): void {
  const abs = join(root, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, text, "utf8");
}

const lines = (...l: string[]): string => l.join("\n") + "\n";

export function buildPlantedJs(root: string): void {
  put(
    root,
    "src/app.js",
    lines(
      "// planted-js sample application (fixture)",
      'const express = require("express");',
      'const fs = require("fs");',
      'const { exec } = require("child_process");',
      'const crypto = require("crypto");',
      "const app = express();",
      'app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });',
      "",
      'app.get("/run", (req, res) => {',
      "  const r = eval(req.query.expr);",
      '  exec("ls " + req.query.dir);',
      "  res.send(String(r));",
      "});",
      'db.query("SELECT * FROM users WHERE id = " + req.query.id);',
      "",
      'const h = crypto.createHash("md5").update("x").digest("hex");',
      "",
      "fs.readFileSync(req.query.file);",
      "app.listen(3000);",
    ),
  );
  put(root, ".env", lines("# planted-js environment", `AWS_ACCESS_KEY_ID=${AWS_KEY}`));
  put(root, "Dockerfile", lines("FROM node:20", "WORKDIR /app", "COPY . .", 'CMD ["node", "src/app.js"]'));
  put(root, "package.json", lines("{", '  "name": "planted-js",', '  "version": "1.0.0"', "}"));
  put(root, "package-lock.json", npmLockfile("planted-js", [{ name: "lodash", version: "4.17.15" }]));
}

export function buildPlantedPy(root: string): void {
  put(
    root,
    "app.py",
    lines(
      "import os",
      "import pickle",
      "import yaml",
      'obj = pickle.loads(open("data.bin", "rb").read())',
      "",
      "def run(name):",
      '    os.system("ls " + name)',
      "",
      "def load(text):",
      "    data = yaml.load(text)",
      "    return data",
    ),
  );
  put(root, "config.py", lines("# planted-py configuration", `API_SECRET = "${API_SECRET_VALUE}"`));
  put(root, "settings.py", lines("# planted-py settings", "import os", "DEBUG = True"));
  put(root, "requirements.txt", requirementsTxt([{ name: "requests", version: "2.19.0" }]));
  put(
    root,
    "keys/test.pem",
    lines(
      "-----BEGIN PRIVATE KEY-----",
      "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvTq3m1fXr0Qb",
      "pL9wHc2xYyJ1sD5kN8uVfE3aGhO6tRz4WqPb7XnMiC0dBeAjS1lKoUv9TyZx",
      "-----END PRIVATE KEY-----",
    ),
  );
  put(
    root,
    ".github/workflows/ci.yml",
    lines(
      "name: ci",
      "on:",
      "  pull_request_target:",
      "    branches: [main]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: echo "${{ github.event.issue.title }}"',
    ),
  );
}

export function buildClean(root: string): void {
  put(root, "README.md", lines("# clean", "", "A fixture tree without planted issues."));
  put(root, "src/index.js", lines('console.log("hello");'));
  put(root, "app.py", lines("import json", "", "def load(text):", "    return json.loads(text)"));
  put(root, "Dockerfile", lines("FROM node:20", "USER node", 'CMD ["node", "src/index.js"]'));
  put(root, "package.json", lines("{", '  "name": "clean",', '  "version": "1.0.0"', "}"));
  put(root, "package-lock.json", npmLockfile("clean", [{ name: "left-pad", version: "1.3.0" }]));
}
