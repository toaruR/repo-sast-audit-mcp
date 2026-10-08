import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { McpError } from "./errors.js";
import { JobManager } from "./jobs/jobManager.js";
import { loadRules } from "./scanners/rules.js";
import { rulesetHash } from "./scanners/rulesetHash.js";
import { SCANNER_VERSIONS } from "./tools/listScanners.js";
import { createServer } from "./server.js";

// Startup self-test (design 4.3, F-14a): a bad rule file means no tool is ever served (exit 2).
// Optional argv[2] = rule file path (defaults to rules/rules.json).
let hash: string;
try {
  const rules = process.argv[2] !== undefined ? loadRules(process.argv[2]) : loadRules();
  hash = rulesetHash(rules, SCANNER_VERSIONS);
} catch (e) {
  const code = e instanceof McpError ? e.code : "E_RULE_INVALID";
  const msg = e instanceof Error ? e.message : "unknown error";
  process.stderr.write(`${code}: ${msg}\n`);
  process.exit(2);
}

const server = createServer(new JobManager(), { rulesetHash: hash });
await server.connect(new StdioServerTransport());

process.stdin.on("close", () => process.exit(0));
process.stdin.on("end", () => process.exit(0));
