export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Rating = "none" | "low" | "medium" | "high" | "critical";

export interface Scored {
  severity: Severity;
  confidence: Confidence;
}

const W: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
const M10: Record<Confidence, number> = { high: 10, medium: 7, low: 4 };

export function raw10(findings: readonly Scored[]): number {
  let s = 0;
  for (const f of findings) s += W[f.severity] * M10[f.confidence];
  return s;
}

export function riskScoreFromRaw10(raw: number): number {
  return raw === 0 ? 0 : Math.max(1, Math.min(100, Math.floor((raw + 5) / 10)));
}

export function riskScore(findings: readonly Scored[]): number {
  return riskScoreFromRaw10(raw10(findings));
}

export function riskRatingByScore(score: number): Rating {
  if (score < 1) return "none";
  if (score < 10) return "low";
  if (score < 30) return "medium";
  if (score < 60) return "high";
  return "critical";
}

export function severityFromCvss(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

const LABELS: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  LOW: "low",
};

const LOWER_CONF: Record<Confidence, Confidence> = { high: "medium", medium: "low", low: "low" };

export function resolveSeverity(
  input: { score?: number | undefined; label?: string | undefined },
  confidence: Confidence,
): Scored {
  if (typeof input.score === "number" && Number.isFinite(input.score)) {
    return { severity: severityFromCvss(input.score), confidence };
  }
  const mapped = input.label === undefined ? undefined : LABELS[input.label.toUpperCase()];
  if (mapped !== undefined) return { severity: mapped, confidence };
  return { severity: "medium", confidence: LOWER_CONF[confidence] };
}

const RANK: Record<Rating, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function riskRatingByWorst(findings: readonly Scored[]): Rating {
  let r: Rating = "none";
  for (const f of findings) {
    if (f.confidence === "low") continue;
    const c: Rating = f.severity === "critical" ? "high" : f.severity === "high" ? "medium" : "none";
    if (RANK[c] > RANK[r]) r = c;
  }
  return r;
}

export function riskRating(findings: readonly Scored[]): Rating {
  const a = riskRatingByScore(riskScore(findings));
  const b = riskRatingByWorst(findings);
  return RANK[b] > RANK[a] ? b : a;
}
