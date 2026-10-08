import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { TOOL_NAMES, type ToolName } from "./contracts.js";
import { McpError } from "./errors.js";
import { makeErrorEnvelope } from "./envelope.js";
import { JobManager } from "./jobs/jobManager.js";
import { assertNoSecrets } from "./security/assertNoSecrets.js";
import { generateReport } from "./tools/generateReport.js";
import { getFindings } from "./tools/getFindings.js";
import { listScannersTool } from "./tools/listScanners.js";
import { scanRepository } from "./tools/scan.js";
import { cancelScan, getScanStatus } from "./tools/status.js";

export const SERVER_VERSION = "0.1.0";

type ToolResult = Record<string, unknown>;
export type ToolHandler = (args: unknown) => ToolResult | Promise<ToolResult>;

export interface ServerDeps {
  rulesetHash?: string;
  serverVersion?: string;
  /** Log sink (one line, no newline). Defaults to stderr. */
  log?: (line: string) => void;
  /** Test hook: replaces individual tool handlers. */
  handlers?: Partial<Record<ToolName, ToolHandler>>;
}

const DESCRIPTIONS: Record<ToolName, string> = {
  scan_repository: "Start a read-only scan of a local repository (async; poll get_scan_status).",
  get_scan_status: "Get the state, progress and summary of a scan.",
  cancel_scan: "Cancel a queued or running scan.",
  get_findings: "Page through the findings of a scan.",
  generate_report: "Write md/json/sarif reports of a finished scan.",
  list_scanners: "List scanners, ruleset hash, advisory DB state and limits.",
};

function readSchemas(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(`../schemas/${name}`, import.meta.url), "utf8")) as Record<string, unknown>;
}

/** Inlines {"$ref":"d#/X"} so MCP clients see self-contained input schemas. */
function deref(node: unknown, defs: Record<string, unknown>): unknown {
  if (Array.isArray(node)) return node.map((n) => deref(n, defs));
  if (node !== null && typeof node === "object") {
    const o = node as Record<string, unknown>;
    const ref = o["$ref"];
    if (typeof ref === "string" && ref.startsWith("d#/")) return deref(defs[ref.slice(3)], defs);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(o)) out[k] = deref(v, defs);
    return out;
  }
  return node;
}

function listedTools(): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
  const defs = readSchemas("defs.json");
  const tools = readSchemas("tools.json") as Record<string, { input: unknown }>;
  return TOOL_NAMES.map((name) => ({
    name,
    description: DESCRIPTIONS[name],
    inputSchema: deref(tools[name]?.input, defs) as Record<string, unknown>,
  }));
}

/** Log line holding only tool name, error code, counts, ruleIds and relative paths. */
function describe(name: string, res: ToolResult): string {
  const sc = res["structuredContent"] as Record<string, unknown> | undefined;
  if (res["isError"] === true) {
    const code = (sc?.["error"] as { code?: string } | undefined)?.code ?? "E_INTERNAL";
    return `tool=${name} error=${code}`;
  }
  const parts = [`tool=${name}`];
  if (sc) {
    if (typeof sc["state"] === "string") parts.push(`state=${sc["state"]}`);
    if (typeof sc["total"] === "number") parts.push(`total=${sc["total"]}`);
    const files = sc["files"];
    if (Array.isArray(files)) parts.push(`files=${files.length}`);
    const findings = sc["findings"];
    if (Array.isArray(findings)) {
      for (const f of findings as Array<{ ruleId?: string; location?: { path?: string } }>) {
        parts.push(`finding=${f.ruleId ?? "?"}@${f.location?.path ?? "?"}`);
      }
    }
  }
  return parts.join(" ");
}

export function createServer(manager: JobManager = new JobManager(), deps: ServerDeps = {}): Server {
  const server = new Server(
    { name: "repo-vuln-report-mcp", version: deps.serverVersion ?? SERVER_VERSION },
    { capabilities: { tools: {} } },
  );
  const toolDeps = {
    ...(deps.rulesetHash !== undefined ? { rulesetHash: deps.rulesetHash } : {}),
    ...(deps.serverVersion !== undefined ? { serverVersion: deps.serverVersion } : {}),
  };
  const log =
    deps.log ??
    ((line: string) => {
      process.stderr.write(`${line}\n`);
    });

  const handlers: Record<ToolName, ToolHandler> = {
    scan_repository: (a) => scanRepository(manager, a, toolDeps),
    get_scan_status: (a) => getScanStatus(manager, a),
    cancel_scan: (a) => cancelScan(manager, a),
    get_findings: (a) => getFindings(manager, a),
    generate_report: (a) => generateReport(manager, a, toolDeps),
    list_scanners: (a) => listScannersTool(a, deps.serverVersion !== undefined ? { serverVersion: deps.serverVersion } : {}),
    ...deps.handlers,
  };

  server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: listedTools() }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    if (!(TOOL_NAMES as readonly string[]).includes(name)) {
      return makeErrorEnvelope("E_INVALID_INPUT", `unknown tool ${name.slice(0, 64)}`);
    }
    let res: ToolResult;
    try {
      res = await handlers[name as ToolName](req.params.arguments ?? {});
    } catch (e) {
      // Tool output stays a generic envelope; the original error is kept as cause and its name/code logged.
      const err = new McpError("E_INTERNAL", "internal error", { cause: e });
      res = makeErrorEnvelope(err.code, err.message);
      safeLog(log, `internal_error tool=${name} cause=${causeTag(e)}`);
    }
    try {
      const line = describe(name, res);
      assertNoSecrets(line);
      log(line);
    } catch (e) {
      // A closed stderr (EPIPE / destroyed stream) must not break a tool call; anything else is an internal error.
      if (!isStreamClosed(e)) {
        res = makeErrorEnvelope("E_INTERNAL", "internal error");
      }
    }
    return res;
  });

  return server;
}

function errCodeOf(e: unknown): string | undefined {
  return typeof e === "object" && e !== null && typeof (e as { code?: unknown }).code === "string" ? (e as { code: string }).code : undefined;
}

function isStreamClosed(e: unknown): boolean {
  const c = errCodeOf(e);
  return c === "EPIPE" || c === "ERR_STREAM_DESTROYED";
}

/** Name/code only: never message text, which may carry sensitive data. */
function causeTag(e: unknown): string {
  const name = e instanceof Error ? e.name : typeof e;
  return `${name}${errCodeOf(e) ? `:${errCodeOf(e)}` : ""}`;
}

function safeLog(log: (line: string) => void, line: string): void {
  try {
    log(line);
  } catch (e) {
    if (!isStreamClosed(e)) throw e;
  }
}
