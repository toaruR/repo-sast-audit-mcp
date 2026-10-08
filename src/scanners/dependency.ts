import { createRequire } from "node:module";
import type { Advisory, AdvisoryDb, AdvisoryRange } from "../advisory/db.js";
import type { RawFinding } from "../findings/identity.js";
import type { OsvClient } from "../net/osvClient.js";
import type { Warnings } from "../pipeline/warnings.js";
import { resolveSeverity } from "../scoring.js";
import { lockfileKind, parseLockfile, type LockPackage } from "./lockfiles.js";

// @types/semver is not a dependency; type the two functions used.
const semver = createRequire(import.meta.url)("semver") as {
  valid(v: string): string | null;
  compare(a: string, b: string): number;
};

export const DEP_RULE_ID = "DEP-OSV-ADVISORY";

type Cmp = (a: string, b: string) => number | undefined;

// ---- version comparison -------------------------------------------------

const cmpSemver: Cmp = (a, b) => {
  const x = semver.valid(a);
  const y = semver.valid(b);
  if (x === null || y === null) return undefined;
  return semver.compare(x, y);
};

const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function pep440Key(v: string): number[] | undefined {
  const m =
    /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|a|beta|b|preview|pre|rc|c)[-_.]?(\d*))?(?:(?:-(\d+))|(?:[-_.]?(?:post|rev|r)[-_.]?(\d*)))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+[a-z0-9.]+)?$/.exec(
      v.trim().toLowerCase(),
    );
  if (!m) return undefined;
  const release = (m[2] ?? "0").split(".").map(Number);
  while (release.length > 1 && release[release.length - 1] === 0) release.pop();
  const hasPre = m[3] !== undefined;
  const hasPost = m[5] !== undefined || m[6] !== undefined;
  const hasDev = m[7] !== undefined;
  const pre = hasPre ? [PRE_RANK[m[3] ?? ""] ?? 0, Number(m[4] || 0)] : hasDev && !hasPost ? [-1, 0] : [3, 0];
  const post = hasPost ? Number(m[5] ?? (m[6] || 0)) : -1;
  const dev = hasDev ? Number(m[7] || 0) : Number.MAX_SAFE_INTEGER;
  return [Number(m[1] ?? 0), ...release.map((n) => n), -1, ...pre, post, dev];
}

const cmpPep440: Cmp = (a, b) => {
  const x = pep440Key(a);
  const y = pep440Key(b);
  if (!x || !y) return undefined;
  // Release segments are variable length: compare up to the -1 separator first.
  const sepX = x.indexOf(-1, 1);
  const sepY = y.indexOf(-1, 1);
  if (x[0] !== y[0]) return Math.sign((x[0] ?? 0) - (y[0] ?? 0));
  const rx = x.slice(1, sepX);
  const ry = y.slice(1, sepY);
  for (let i = 0; i < Math.max(rx.length, ry.length); i++) {
    const d = (rx[i] ?? 0) - (ry[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  const tx = x.slice(sepX + 1);
  const ty = y.slice(sepY + 1);
  for (let i = 0; i < tx.length; i++) {
    const d = (tx[i] ?? 0) - (ty[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
};

const MAVEN_QUAL = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

function mavenItems(v: string): Array<number | string> {
  const out: Array<number | string> = [];
  for (const part of v.toLowerCase().split(/[.\-]/)) {
    for (const t of part.match(/\d+|[a-z]+/g) ?? []) {
      if (/^\d+$/.test(t)) out.push(Number(t));
      else out.push(t === "cr" ? "rc" : t === "ga" || t === "final" || t === "release" ? "" : t);
    }
  }
  while (out.length > 1 && (out[out.length - 1] === 0 || out[out.length - 1] === "")) out.pop();
  return out;
}

const cmpMaven: Cmp = (a, b) => {
  if (!/^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(a) || !/^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(b)) return undefined;
  const x = mavenItems(a);
  const y = mavenItems(b);
  const qual = (s: string): number => {
    const i = MAVEN_QUAL.indexOf(s);
    return i >= 0 ? i : MAVEN_QUAL.length + 1;
  };
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i] ?? 0;
    const q = y[i] ?? 0;
    if (typeof p === "number" && typeof q === "number") {
      if (p !== q) return Math.sign(p - q);
    } else if (typeof p === "number") {
      return p === 0 && q === "" ? 0 : 1;
    } else if (typeof q === "number") {
      return q === 0 && p === "" ? 0 : -1;
    } else {
      const d = qual(p) - qual(q);
      if (d !== 0) return Math.sign(d);
      if (qual(p) > MAVEN_QUAL.length) return p < q ? -1 : p > q ? 1 : 0;
    }
  }
  return 0;
};

function comparatorFor(ecosystem: string, rangeType: string): Cmp | undefined {
  if (rangeType === "SEMVER") return cmpSemver;
  if (rangeType !== "ECOSYSTEM") return undefined; // GIT and unknown types are not comparable
  if (ecosystem === "PyPI") return cmpPep440;
  if (ecosystem === "Maven") return cmpMaven;
  return cmpSemver;
}

// ---- advisory matching --------------------------------------------------

type Verdict = "yes" | "no" | "uncomparable";

function inRange(ecosystem: string, range: AdvisoryRange, version: string): Verdict {
  const cmp = comparatorFor(ecosystem, range.type);
  if (!cmp) return "uncomparable";
  const events = range.events;
  const isZero = (s: string): boolean => s === "0";
  const keyed: Array<{ kind: "introduced" | "fixed" | "last_affected"; version: string }> = [];
  for (const e of events) {
    if (e.introduced !== undefined) keyed.push({ kind: "introduced", version: e.introduced });
    else if (e.fixed !== undefined) keyed.push({ kind: "fixed", version: e.fixed });
    else if (e.last_affected !== undefined) keyed.push({ kind: "last_affected", version: e.last_affected });
  }
  let bad = false;
  keyed.sort((a, b) => {
    if (isZero(a.version) || isZero(b.version)) return Number(isZero(b.version)) - Number(isZero(a.version));
    const c = cmp(a.version, b.version);
    if (c === undefined) {
      bad = true;
      return 0;
    }
    return c;
  });
  if (bad) return "uncomparable";
  let affected = false;
  for (const e of keyed) {
    if (e.kind === "introduced") {
      if (e.version === "*" || isZero(e.version)) {
        affected = true;
        continue;
      }
      const c = cmp(version, e.version);
      if (c === undefined) return "uncomparable";
      if (c >= 0) affected = true;
    } else if (e.kind === "fixed") {
      const c = cmp(version, e.version);
      if (c === undefined) return "uncomparable";
      if (c >= 0) affected = false;
    } else {
      const c = cmp(version, e.version);
      if (c === undefined) return "uncomparable";
      if (c > 0) affected = false;
    }
  }
  return affected ? "yes" : "no";
}

function advisoryVerdict(adv: Advisory, pkg: LockPackage): Verdict {
  let sawUncomparable = false;
  for (const aff of adv.affected ?? []) {
    const ap = aff.package;
    if (ap?.name !== undefined && ap.name !== pkg.name) continue;
    if (ap?.ecosystem !== undefined && ap.ecosystem !== pkg.ecosystem) continue;
    if (aff.versions?.includes(pkg.version)) return "yes";
    for (const r of aff.ranges ?? []) {
      const v = inRange(pkg.ecosystem, r, pkg.version);
      if (v === "yes") return "yes";
      if (v === "uncomparable") sawUncomparable = true;
    }
  }
  return sawUncomparable ? "uncomparable" : "no";
}

function lowestFixed(adv: Advisory, pkg: LockPackage): string | undefined {
  let best: string | undefined;
  for (const aff of adv.affected ?? []) {
    const ap = aff.package;
    if (ap?.name !== undefined && ap.name !== pkg.name) continue;
    for (const r of aff.ranges ?? []) {
      const cmp = comparatorFor(pkg.ecosystem, r.type);
      if (!cmp) continue;
      for (const e of r.events) {
        if (e.fixed === undefined) continue;
        const above = cmp(e.fixed, pkg.version);
        if (above === undefined || above <= 0) continue; // only fixes newer than the installed version
        if (best === undefined || (cmp(e.fixed, best) ?? 0) < 0) best = e.fixed;
      }
    }
  }
  return best;
}

function cvssOf(adv: Advisory): { score: number; version: string } | undefined {
  const ds = adv.database_specific?.cvss_score;
  if (typeof ds === "number" && Number.isFinite(ds)) return { score: ds, version: "3" };
  for (const s of adv.severity ?? []) {
    const n = typeof s.score === "number" ? s.score : /^\d+(\.\d+)?$/.test(s.score) ? Number(s.score) : NaN;
    if (Number.isFinite(n)) {
      const t = s.type.toUpperCase();
      return { score: n, version: t.endsWith("V2") ? "2" : t.endsWith("V4") ? "4" : t.endsWith("V3") ? "3" : "unknown" };
    }
  }
  return undefined;
}

export function findingFor(adv: Advisory, pkg: LockPackage): RawFinding {
  const cvss = cvssOf(adv);
  const { severity, confidence } = resolveSeverity(
    { score: cvss?.score, label: adv.database_specific?.severity },
    pkg.confidence,
  );
  const fixed = lowestFixed(adv, pkg);
  const cweRaw = (adv.database_specific as { cwe_ids?: unknown } | undefined)?.cwe_ids;
  const cwe = Array.isArray(cweRaw) ? cweRaw.filter((c): c is string => typeof c === "string" && /^CWE-\d+$/.test(c)) : [];
  const f: RawFinding = {
    ruleId: DEP_RULE_ID,
    scanner: "dependency",
    title: `Vulnerable dependency ${pkg.name}`,
    severity,
    confidence,
    cwe,
    location: { path: pkg.path, line: pkg.line, column: 1 },
    evidence: `${pkg.ecosystem}:${pkg.name}@${pkg.version}`,
    message: adv.summary ?? `${adv.id} affects ${pkg.name}@${pkg.version}`,
    remediation: fixed !== undefined ? `Upgrade ${pkg.name} to >= ${fixed}` : "No fixed version is known",
    advisoryId: adv.id,
    package: { ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version, ...(fixed !== undefined ? { fixedIn: fixed } : {}) },
  };
  if (cvss) f.cvss = cvss;
  return f;
}

export type LocationIndex = Map<string, number>;

/** One pass over the packages: Map<"name@version", firstLine>. O(P). */
export function buildLocationIndex(pkgs: readonly LockPackage[]): LocationIndex {
  const index: LocationIndex = new Map();
  for (const p of pkgs) {
    const k = `${p.name}@${p.version}`;
    if (!index.has(k)) index.set(k, p.line);
  }
  return index;
}

/** O(1) lookup; a package missing from the index gets line 1. */
export function lineOf(index: LocationIndex, name: string, version: string): number {
  return index.get(`${name}@${version}`) ?? 1;
}

export type DependencyFinding = RawFinding & { online?: boolean };

/** Offline matching of packages against the advisory DB. */
export function matchPackages(
  pkgs: readonly LockPackage[],
  db: AdvisoryDb,
  warnings: Warnings,
  index?: LocationIndex,
): RawFinding[] {
  const out: RawFinding[] = [];
  for (const pkg of pkgs) {
    let uncomparable = false;
    const located = index ? { ...pkg, line: lineOf(index, pkg.name, pkg.version) } : pkg;
    for (const adv of db.lookup(pkg.ecosystem, pkg.name)) {
      const v = advisoryVerdict(adv, pkg);
      if (v === "yes") out.push(findingFor(adv, located));
      else if (v === "uncomparable") uncomparable = true;
    }
    if (uncomparable) warnings.add("W_UNCOMPARABLE_VERSION", pkg.path);
  }
  return out;
}

export interface DependencyFile {
  rel: string;
  content: string;
}

export interface DependencyContext {
  db: AdvisoryDb | undefined;
  warnings: Warnings;
  /** Online mode (options.online). The OSV client is only constructed when true. */
  online?: boolean;
  createClient?: () => OsvClient;
}

function osvVulns(resp: unknown): Advisory[] {
  const vulns = (resp as { vulns?: unknown } | null)?.vulns;
  return Array.isArray(vulns) ? (vulns as Advisory[]).filter((v) => typeof v?.id === "string") : [];
}

/**
 * Parses every lockfile in `files` and matches the packages against the DB (no DB: no offline findings).
 * Online mode additionally asks OSV once per unique package, sending only {ecosystem,name,version}.
 */
export async function scanDependencies(
  files: readonly DependencyFile[],
  ctx: DependencyContext,
): Promise<DependencyFinding[]> {
  const out: DependencyFinding[] = [];
  const perFile: Array<{ pkgs: LockPackage[]; index: LocationIndex }> = [];
  for (const f of files) {
    if (lockfileKind(f.rel) === undefined) continue;
    const pkgs = parseLockfile(f.rel, f.content, ctx.warnings);
    const index = buildLocationIndex(pkgs);
    perFile.push({ pkgs, index });
    if (ctx.db) for (const x of matchPackages(pkgs, ctx.db, ctx.warnings, index)) out.push(x);
  }
  if (ctx.online === true && ctx.createClient) {
    const unique = new Map<string, { ecosystem: string; name: string; version: string }>();
    for (const { pkgs } of perFile) {
      for (const p of pkgs) {
        const k = `${p.ecosystem}\n${p.name}\n${p.version}`;
        if (!unique.has(k)) unique.set(k, { ecosystem: p.ecosystem, name: p.name, version: p.version });
      }
    }
    if (unique.size > 0) {
      const keys = [...unique.keys()];
      const responses = await ctx.createClient().query([...unique.values()]);
      const vulnsByKey = new Map<string, Advisory[]>();
      keys.forEach((k, i) => vulnsByKey.set(k, osvVulns(responses[i])));
      for (const { pkgs, index } of perFile) {
        for (const p of pkgs) {
          const located = { ...p, line: lineOf(index, p.name, p.version) };
          for (const adv of vulnsByKey.get(`${p.ecosystem}\n${p.name}\n${p.version}`) ?? []) {
            out.push({ ...findingFor(adv, located), online: true });
          }
        }
      }
    }
  }
  return out;
}
