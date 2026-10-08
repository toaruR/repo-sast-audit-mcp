import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ENV, SHARD_LRU, STALE_DAYS, STALE_DAYS_LIMIT, readEnv } from "../constants.js";
import { McpError } from "../errors.js";
import type { Warnings } from "../pipeline/warnings.js";

export interface AdvisoryEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface AdvisoryRange {
  type: string;
  events: AdvisoryEvent[];
}

export interface Advisory {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: Array<{ type: string; score: string | number }>;
  database_specific?: { severity?: string; cvss_score?: number };
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: AdvisoryRange[];
    versions?: string[];
  }>;
}

const DAY_MS = 86400000;

/** ageDays = floor((now - generatedAt) / 86400000). */
export function ageDays(generatedAt: Date | string | number, now: Date | string | number): number {
  return Math.floor((new Date(now).getTime() - new Date(generatedAt).getTime()) / DAY_MS);
}

/** contentSha256 of a shard = SHA-256 (hex) of JSON.stringify(advisories). */
export function shardHash(advisories: unknown): string {
  return createHash("sha256").update(JSON.stringify(advisories)).digest("hex");
}

export function staleDaysFromEnv(): number {
  const raw = readEnv(ENV.DB_STALE_DAYS);
  if (raw === undefined || !/^\d+$/.test(raw)) return STALE_DAYS;
  const n = Number(raw);
  return n >= STALE_DAYS_LIMIT.min && n <= STALE_DAYS_LIMIT.max ? n : STALE_DAYS;
}

export function currentTime(): number {
  const fixed = readEnv(ENV.FIXED_TIME);
  if (fixed !== undefined) {
    const t = Date.parse(fixed);
    if (Number.isFinite(t)) return t;
  }
  return Date.now();
}

export interface AdvisoryDb {
  generatedAt: string;
  ageDays: number;
  stale: boolean;
  manifestSha256: string;
  /** Advisories of one package; invalid shards are ignored with W_ADVISORY_DB_INVALID_SHARD. */
  lookup(ecosystem: string, name: string): Advisory[];
  residentShards(): number;
}

export interface LoadOptions {
  warnings: Warnings;
  now?: number | string | Date;
  staleDays?: number;
}

function safeSegment(s: string): string {
  return encodeURIComponent(s).replace(/\./g, "%2E");
}

export function loadAdvisoryDb(dir: string, opts: LoadOptions): AdvisoryDb {
  let raw: string;
  try {
    raw = readFileSync(join(dir, "manifest.json"), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new McpError("E_ADVISORY_DB_MISSING", "advisory database manifest not found");
    }
    throw new McpError("E_ADVISORY_DB_INVALID", "advisory database manifest unreadable");
  }
  let manifest: { schemaVersion?: unknown; generatedAt?: unknown };
  try {
    manifest = JSON.parse(raw) as typeof manifest;
  } catch {
    throw new McpError("E_ADVISORY_DB_INVALID", "advisory database manifest is not valid JSON");
  }
  if (
    manifest === null ||
    typeof manifest !== "object" ||
    manifest.schemaVersion !== 1 ||
    typeof manifest.generatedAt !== "string" ||
    !Number.isFinite(Date.parse(manifest.generatedAt))
  ) {
    throw new McpError("E_ADVISORY_DB_INVALID", "advisory database manifest is invalid");
  }
  const generatedAt = manifest.generatedAt;
  const age = ageDays(generatedAt, opts.now ?? currentTime());
  const staleDays = opts.staleDays ?? staleDaysFromEnv();
  const stale = age > staleDays;
  if (stale) opts.warnings.add("W_ADVISORY_DB_STALE");

  const lru = new Map<string, Advisory[]>();
  const lookup = (ecosystem: string, name: string): Advisory[] => {
    const key = `${ecosystem}\n${name}`;
    const hit = lru.get(key);
    if (hit !== undefined) {
      lru.delete(key);
      lru.set(key, hit);
      return hit;
    }
    let advisories: Advisory[] = [];
    const shardId = `${ecosystem}/${name}`;
    let text: string | undefined;
    try {
      text = readFileSync(join(dir, safeSegment(ecosystem), `${safeSegment(name)}.json`), "utf8");
    } catch (e) {
      const c = (e as NodeJS.ErrnoException).code;
      if (c === "ENOENT" || c === "ENOTDIR") {
        text = undefined; // no shard: no advisories
      } else if (c === "EACCES" || c === "EPERM" || c === "EISDIR") {
        opts.warnings.add("W_ADVISORY_DB_INVALID_SHARD", shardId);
      } else {
        throw e;
      }
    }
    if (text !== undefined) {
      try {
        const shard = JSON.parse(text) as { contentSha256?: unknown; advisories?: unknown };
        if (
          !Array.isArray(shard.advisories) ||
          typeof shard.contentSha256 !== "string" ||
          shard.contentSha256 !== shardHash(shard.advisories)
        ) {
          throw new Error("shard hash mismatch");
        }
        advisories = shard.advisories as Advisory[];
      } catch {
        opts.warnings.add("W_ADVISORY_DB_INVALID_SHARD", shardId);
      }
    }
    lru.set(key, advisories);
    while (lru.size > SHARD_LRU) {
      const oldest = lru.keys().next().value;
      if (oldest === undefined) break;
      lru.delete(oldest);
    }
    return advisories;
  };

  return {
    generatedAt,
    ageDays: age,
    stale,
    manifestSha256: createHash("sha256").update(raw).digest("hex"),
    lookup,
    residentShards: () => lru.size,
  };
}
