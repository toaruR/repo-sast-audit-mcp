export interface Limit { default: number; min: number; max: number }

export const LIMITS = {
  maxFiles: { default: 50000, min: 1, max: 500000 },
  maxFileBytes: { default: 1048576, min: 1024, max: 8388608 },
  maxTotalBytes: { default: 536870912, min: 1048576, max: 4294967296 },
  maxFindings: { default: 5000, min: 1, max: 50000 },
  timeoutMs: { default: 120000, min: 1000, max: 900000 },
  waitMs: { default: 0, min: 0, max: 30000 },
} as const satisfies Record<string, Limit>;

export const STALE_DAYS_LIMIT: Limit = { default: 30, min: 1, max: 3650 };

export const DEFAULT_OPTIONS = {
  strictLimits: false,
  online: false,
  symlinkPolicy: "skip",
  respectGitignore: true,
  includeGlobs: [] as string[],
  excludeGlobs: [] as string[],
  limits: {
    maxFiles: LIMITS.maxFiles.default,
    maxFileBytes: LIMITS.maxFileBytes.default,
    maxTotalBytes: LIMITS.maxTotalBytes.default,
    maxFindings: LIMITS.maxFindings.default,
    timeoutMs: LIMITS.timeoutMs.default,
  },
} as const;

export const DEFAULT_FORCE = false;
export const GLOB_N = 50;
export const GLOB_LEN = 256;
export const PATHPREFIX_MAX = 1024;
export const GET_FINDINGS_MAX = 200;
export const CURSOR_MAX = 256;
export const GET_FINDINGS_DEFAULT_LIMIT = 50;
export const GET_FINDINGS_DEFAULT_INCLUDE_EVIDENCE = true;
export const REPORT_DEFAULTS = {
  formats: ["md", "json"],
  allowWriteInsideTarget: false,
  allowPartial: false,
  includeEvidence: true,
} as const;
export const REPORT_FORMATS = ["md", "json", "sarif"] as const;
export const PATH_MAX = 4096;
export const RULEID_MAX = 64;
export const PERF_TARGET_S = 20;
export const MAX_RUNNING = 2;
export const MAX_QUEUED = 8;
export const JOB_KEEP = 20;
export const MAX_DEPTH = 64;
export const LINE_MAX = 5000;
export const LOCKFILE_MAX_BYTES = 16777216;
export const PER_FILE_BUDGET_MS = 2000;
export const CANCEL_DRAIN_MS = 3000;
export const EVIDENCE_MAX = 200;
export const STALE_DAYS = 30;
export const BINARY_PROBE_BYTES = 8192;
export const SECRET_WINDOW_BYTES = 4096;
export const ABORT_CHECK_LINES = 1000;
export const SHARD_LRU = 256;
export const SECRET_MIN_LEN = 20;
export const HEX_MIN_LEN = 32;
export const ENT_ALNUM_MILLI = 4000;
export const ENT_HEX_MILLI = 3200;
export const REDACT_PREFIX = 4;
export const LEAK_SUBSTR = 5;
export const DEP_MAX = 9;
export const PEAK_RSS_MIB = 400;

export const ENV = {
  ALLOWED_ROOTS: "VULN_MCP_ALLOWED_ROOTS",
  OUTPUT_ROOT: "VULN_MCP_OUTPUT_ROOT",
  ALLOW_NETWORK: "VULN_MCP_ALLOW_NETWORK",
  FIXED_TIME: "VULN_MCP_FIXED_TIME",
  ADVISORY_DB: "VULN_MCP_ADVISORY_DB",
  DB_STALE_DAYS: "VULN_MCP_DB_STALE_DAYS",
} as const;

export function readEnv(name: string): string | undefined {
  return process.env[name];
}

export const TOOL_DEFAULTS = {
  force: DEFAULT_FORCE,
  getFindings: {
    limit: GET_FINDINGS_DEFAULT_LIMIT,
    includeEvidence: GET_FINDINGS_DEFAULT_INCLUDE_EVIDENCE,
  },
  generateReport: {
    formats: [...REPORT_DEFAULTS.formats],
    allowWriteInsideTarget: REPORT_DEFAULTS.allowWriteInsideTarget,
    allowPartial: REPORT_DEFAULTS.allowPartial,
    includeEvidence: REPORT_DEFAULTS.includeEvidence,
  },
};
