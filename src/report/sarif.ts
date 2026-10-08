import type { Finding } from "../findings/identity.js";
import type { Severity } from "../scoring.js";

export const SARIF_VERSION = "2.1.0";
export const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
export const SARIF_TOOL_NAME = "repo-sast-audit-mcp";

export type SarifLevel = "error" | "warning" | "note";

const LEVELS: Record<Severity, SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** Design 7: critical,high -> error; medium -> warning; low,info -> note. */
export function sarifLevel(severity: Severity): SarifLevel {
  return LEVELS[severity];
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn: number };
    };
  }>;
  partialFingerprints: { primary: string };
  properties: { confidence: string; cwe: string[]; scanner: string };
}

export interface SarifRule {
  id: string;
  shortDescription: { text: string };
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: { driver: { name: string; version: string; rules: SarifRule[] } };
    results: SarifResult[];
  }>;
}

/** SARIF 2.1.0 log for the findings, in the given order; rules are the used ruleIds in order of first use. */
export function buildSarif(findings: readonly Finding[], serverVersion: string): SarifLog {
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = findings.map((f) => {
    if (!rules.has(f.ruleId)) rules.set(f.ruleId, { id: f.ruleId, shortDescription: { text: f.title } });
    return {
      ruleId: f.ruleId,
      level: sarifLevel(f.severity),
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.location.path },
            region: { startLine: f.location.line, startColumn: f.location.column },
          },
        },
      ],
      partialFingerprints: { primary: f.fingerprint },
      properties: { confidence: f.confidence, cwe: f.cwe, scanner: f.scanner },
    };
  });
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{ tool: { driver: { name: SARIF_TOOL_NAME, version: serverVersion, rules: [...rules.values()] } }, results }],
  };
}

export function renderSarif(findings: readonly Finding[], serverVersion: string): string {
  return JSON.stringify(buildSarif(findings, serverVersion), null, 2) + "\n";
}
