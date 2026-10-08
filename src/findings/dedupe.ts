import type { Finding } from "./identity.js";
import { sortFindings } from "./sort.js";

/** A finding plus an internal provenance flag; the flag is stripped from the result. */
export type DedupeItem = Finding & { online?: boolean };

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
const CONF_RANK = { low: 0, medium: 1, high: 2 } as const;
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function mergeGroup(group: DedupeItem[]): DedupeItem {
  const sorted = [...group].sort((a, b) => cmp(a.ruleId, b.ruleId) || cmp(a.id, b.id));
  const base = sorted[0] as DedupeItem;
  let severity = base.severity;
  let confidence = base.confidence;
  const cwe = new Set<string>();
  const related = new Set<string>();
  for (const f of sorted) {
    if (SEV_RANK[f.severity] > SEV_RANK[severity]) severity = f.severity;
    if (CONF_RANK[f.confidence] > CONF_RANK[confidence]) confidence = f.confidence;
    for (const c of f.cwe) cwe.add(c);
    for (const r of f.relatedRuleIds ?? []) related.add(r);
    related.add(f.ruleId);
  }
  related.delete(base.ruleId);
  const out: DedupeItem = { ...base, severity, confidence, cwe: [...cwe].sort(cmp) };
  if (related.size > 0) out.relatedRuleIds = [...related].sort(cmp);
  return out;
}

/** Union-find merge of items sharing scanner+path+line with intersecting CWE sets. */
function mergeByLocation(items: DedupeItem[]): DedupeItem[] {
  const parent = items.map((_, i) => i);
  const find = (x: number): number => {
    let r = x;
    while (parent[r] !== r) r = parent[r] as number;
    while (parent[x] !== r) {
      const n = parent[x] as number;
      parent[x] = r;
      x = n;
    }
    return r;
  };
  const union = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb);
  };
  const byKey = new Map<string, number[]>();
  items.forEach((f, i) => {
    const k = `${f.scanner}\n${f.location.path}\n${f.location.line}`;
    const l = byKey.get(k);
    if (l) l.push(i);
    else byKey.set(k, [i]);
  });
  for (const idxs of byKey.values()) {
    const firstByCwe = new Map<string, number>();
    for (const i of idxs) {
      for (const c of (items[i] as DedupeItem).cwe) {
        const j = firstByCwe.get(c);
        if (j === undefined) firstByCwe.set(c, i);
        else union(i, j);
      }
    }
  }
  const groups = new Map<number, DedupeItem[]>();
  items.forEach((f, i) => {
    const r = find(i);
    const l = groups.get(r);
    if (l) l.push(f);
    else groups.set(r, [f]);
  });
  return [...groups.values()].map((g) => (g.length === 1 ? (g[0] as DedupeItem) : mergeGroup(g)));
}

function pkgKey(f: DedupeItem): string | undefined {
  if (!f.package) return undefined;
  return [f.scanner, f.package.ecosystem, f.package.name, f.package.version, f.advisoryId ?? ""].join("\n");
}

/** Dedupe steps 1-3 (design 5.4). Result is independent of input order and sorted by 5.3. */
export function dedupeFindings(input: readonly DedupeItem[]): Finding[] {
  // Step 1: same id.
  const byId = new Map<string, DedupeItem[]>();
  for (const f of sortFindings(input)) {
    const l = byId.get(f.id);
    if (l) l.push(f);
    else byId.set(f.id, [f]);
  }
  const step1: DedupeItem[] = [...byId.values()].map((g) => {
    if (g.length === 1) return g[0] as DedupeItem;
    const online = g.every((x) => x.online === true);
    return { ...mergeGroup(g), online };
  });
  // Step 2: scanner + path + line + CWE intersection.
  const step2 = mergeByLocation(step1);
  // Step 3: online/offline duplicates of the same package; offline wins.
  const hasOffline = new Set<string>();
  for (const f of step2) {
    const k = pkgKey(f);
    if (k !== undefined && f.online !== true) hasOffline.add(k);
  }
  const step3 = step2.filter((f) => {
    const k = pkgKey(f);
    return !(f.online === true && k !== undefined && hasOffline.has(k));
  });
  return sortFindings(
    step3.map((f) => {
      const { online: _online, ...rest } = f;
      void _online;
      return rest as Finding;
    }),
  );
}
