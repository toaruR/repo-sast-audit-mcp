import { ENV, GET_FINDINGS_MAX, LIMITS, MAX_QUEUED, MAX_RUNNING, readEnv } from "../constants.js";
import { validateInput } from "../contracts.js";
import { makeErrorEnvelope, makeResultEnvelope } from "../envelope.js";
import { McpError } from "../errors.js";
import { loadAdvisoryDb } from "../advisory/db.js";
import { DEFAULT_REQUEST } from "../jobs/jobManager.js";
import { Warnings } from "../pipeline/warnings.js";
import { loadRules } from "../scanners/rules.js";
import { rulesetHash } from "../scanners/rulesetHash.js";

export const SCANNER_VERSIONS = { config: "1.0.0", dependency: "1.0.0", secret: "1.0.0", static: "1.0.0" } as const;

/** Rules implemented in code rather than in rules/rules.json. */
const CODED_RULES = { dependency: 1, secret: 4, config: 2, static: 0 } as const;

export interface ListScannersDeps {
  serverVersion?: string;
  /** Advisory DB directory (defaults to VULN_MCP_ADVISORY_DB). */
  advisoryDbPath?: string;
  now?: number | string | Date;
  rulesFile?: string;
}

export interface ListScannersOutput {
  serverVersion: string;
  rulesetHash: string;
  scanners: Array<{ id: string; version: string; ruleCount: number; enabledByDefault: boolean; requiresAdvisoryDb: boolean }>;
  advisoryDb: { present: boolean; generatedAt?: string; ageDays?: number; stale?: boolean };
  networkAllowed: boolean;
  limits: {
    maxFiles: { default: number; min: number; max: number };
    maxFileBytes: { default: number; min: number; max: number };
    maxTotalBytes: { default: number; min: number; max: number };
    maxFindings: { default: number; min: number; max: number };
    timeoutMs: { default: number; min: number; max: number };
    getFindingsMax: number;
    maxRunning: number;
    maxQueued: number;
  };
}

function advisoryDbInfo(deps: ListScannersDeps): ListScannersOutput["advisoryDb"] {
  const dir = deps.advisoryDbPath ?? readEnv(ENV.ADVISORY_DB);
  if (dir === undefined || dir === "") return { present: false };
  try {
    const db = loadAdvisoryDb(dir, deps.now === undefined ? { warnings: new Warnings() } : { warnings: new Warnings(), now: deps.now });
    return { present: true, generatedAt: db.generatedAt, ageDays: db.ageDays, stale: db.stale };
  } catch (e) {
    if (!(e instanceof McpError)) throw e;
    return { present: false };
  }
}

/** The list_scanners result object (design 3.6). */
export function listScanners(deps: ListScannersDeps = {}): ListScannersOutput {
  const rules = loadRules(deps.rulesFile);
  const cfgRules = rules.filter((r) => r.id.startsWith("CFG-")).length;
  const count = {
    dependency: CODED_RULES.dependency,
    secret: CODED_RULES.secret,
    static: rules.length - cfgRules + CODED_RULES.static,
    config: cfgRules + CODED_RULES.config,
  };
  const net = readEnv(ENV.ALLOW_NETWORK);
  const lim = (l: { default: number; min: number; max: number }) => ({ default: l.default, min: l.min, max: l.max });
  return {
    serverVersion: deps.serverVersion ?? DEFAULT_REQUEST.serverVersion,
    rulesetHash: rulesetHash(rules, SCANNER_VERSIONS),
    scanners: (["dependency", "secret", "static", "config"] as const).map((id) => ({
      id,
      version: SCANNER_VERSIONS[id],
      ruleCount: count[id],
      enabledByDefault: true,
      requiresAdvisoryDb: id === "dependency",
    })),
    advisoryDb: advisoryDbInfo(deps),
    networkAllowed: net === "1" || net === "true",
    limits: {
      maxFiles: lim(LIMITS.maxFiles),
      maxFileBytes: lim(LIMITS.maxFileBytes),
      maxTotalBytes: lim(LIMITS.maxTotalBytes),
      maxFindings: lim(LIMITS.maxFindings),
      timeoutMs: lim(LIMITS.timeoutMs),
      getFindingsMax: GET_FINDINGS_MAX,
      maxRunning: MAX_RUNNING,
      maxQueued: MAX_QUEUED,
    },
  };
}

/** list_scanners tool wrapper: input must be {} (E_INVALID_INPUT otherwise). */
export function listScannersTool(args: unknown, deps: ListScannersDeps = {}) {
  try {
    const v = validateInput("list_scanners", args ?? {});
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    return makeResultEnvelope(listScanners(deps) as unknown as Record<string, unknown>);
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL", "internal error");
  }
}
