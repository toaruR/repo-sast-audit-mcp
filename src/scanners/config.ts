import type { Confidence, Severity } from "../scoring.js";
import { isExampleEnvFile } from "./secret.js";

export interface ConfigMatch {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  line: number;
  column: number;
}

function baseName(rel: string): string {
  return (rel.split(/[\\/]/).pop() ?? "").toLowerCase();
}

export function isDockerfile(rel: string): boolean {
  const b = baseName(rel);
  return b === "dockerfile" || b.startsWith("dockerfile.") || b.endsWith(".dockerfile");
}

export function isCommittedEnv(rel: string): boolean {
  const b = baseName(rel);
  if (b !== ".env" && !b.startsWith(".env.") && !b.endsWith(".env")) return false;
  if (isExampleEnvFile(rel)) return false;
  return !/\.(?:sample|template|dist)$/.test(b);
}

function dockerRoot(content: string): ConfigMatch | undefined {
  let lastUser: { line: number; value: string } | undefined;
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*USER\s+(\S+)/i.exec(lines[i] ?? "");
    if (m) lastUser = { line: i + 1, value: (m[1] ?? "").split(":")[0] ?? "" };
  }
  const base = {
    ruleId: "CFG-DOCKER-ROOT-001",
    title: "Container runs as root",
    severity: "medium" as const,
    confidence: "high" as const,
    cwe: "CWE-250",
    column: 1,
  };
  if (lastUser === undefined) return { ...base, line: 1 };
  if (lastUser.value === "root" || lastUser.value === "0") return { ...base, line: lastUser.line };
  return undefined;
}

/** Coded (non-JSON) config rules: CFG-DOCKER-ROOT-001 and CFG-ENV-COMMITTED-001. */
export function scanConfig(rel: string, content: string): ConfigMatch[] {
  const out: ConfigMatch[] = [];
  if (isDockerfile(rel)) {
    const d = dockerRoot(content);
    if (d) out.push(d);
  }
  if (isCommittedEnv(rel)) {
    out.push({
      ruleId: "CFG-ENV-COMMITTED-001",
      title: ".env file committed to the repository",
      severity: "medium",
      confidence: "medium",
      cwe: "CWE-540",
      line: 1,
      column: 1,
    });
  }
  return out;
}
