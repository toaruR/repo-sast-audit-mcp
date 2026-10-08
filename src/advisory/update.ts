import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { McpError } from "../errors.js";
import { downloadOsvDump, type DumpTransport } from "../net/osvClient.js";
import { currentTime, safeSegment, shardHash, type Advisory } from "./db.js";
import { zipEntries, zipRead } from "./zip.js";

/** Ecosystems produced by src/scanners/lockfiles.ts. */
export const DB_ECOSYSTEMS = ["npm", "PyPI", "crates.io", "Go", "Maven"] as const;
export type DbEcosystem = (typeof DB_ECOSYSTEMS)[number];

export interface UpdateOptions {
  ecosystems: readonly DbEcosystem[];
  /** false drops OSV MAL-* records (they embed malware snippets that antivirus tools quarantine). */
  includeMalware: boolean;
}

export interface UpdateProgress {
  phase: "download" | "index" | "write" | "swap";
  ecosystem?: string;
  ecosystemsDone: number;
  ecosystemsTotal: number;
}

export interface UpdateResult {
  generatedAt: string;
  advisories: number;
  shards: number;
  unparsable: number;
}

const YIELD_EVERY = 500;
const tick = () => new Promise<void>((r) => setImmediate(r));
const RENAME_RETRY_MS = 60000;

/** Windows reports EPERM/EACCES/EBUSY while antivirus or the indexer holds a fresh file; retry like graceful-fs. */
async function renameRetry(from: string, to: string): Promise<void> {
  const start = Date.now();
  for (let wait = 50; ; wait = Math.min(wait * 2, 2000)) {
    try {
      renameSync(from, to);
      return;
    } catch (e) {
      const c = (e as NodeJS.ErrnoException).code;
      if (!(c === "EPERM" || c === "EACCES" || c === "EBUSY") || Date.now() - start > RENAME_RETRY_MS) throw e;
      await new Promise((r) => setTimeout(r, wait));
    }
  }
}

/**
 * The target must be absent, empty, or an existing advisory DB (manifest schemaVersion 1);
 * anything else is refused so a mis-set path never gets replaced.
 */
export function assertReplaceableDb(dir: string): void {
  if (!existsSync(dir)) return;
  if (!statSync(dir).isDirectory()) throw new McpError("E_OUTPUT_DIR_UNSAFE", "advisory DB path is not a directory");
  if (readdirSync(dir).length === 0) return;
  try {
    const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as { schemaVersion?: unknown };
    if (m.schemaVersion === 1) return;
  } catch {
    // fall through
  }
  throw new McpError("E_OUTPUT_DIR_UNSAFE", "advisory DB path is a non-empty directory without a valid manifest");
}

/** Downloads OSV dumps and atomically replaces `dir` with a freshly built sharded DB. */
export async function updateAdvisoryDb(
  dirArg: string,
  opts: UpdateOptions,
  deps: { transport?: DumpTransport; onProgress?: (p: UpdateProgress) => void } = {},
): Promise<UpdateResult> {
  const dir = resolve(dirArg);
  assertReplaceableDb(dir);
  const total = opts.ecosystems.length;
  const report = (p: Omit<UpdateProgress, "ecosystemsTotal">) => deps.onProgress?.({ ...p, ecosystemsTotal: total });

  const tmp = mkdtempSync(`${dir}.tmp-`);
  try {
    const ids = new Set<string>();
    let shards = 0;
    let unparsable = 0;
    for (const [done, eco] of opts.ecosystems.entries()) {
      report({ phase: "download", ecosystem: eco, ecosystemsDone: done });
      const zip = await downloadOsvDump(eco, deps.transport);

      // Pass 1: package name -> entry indices (keeps only the zip buffer in memory).
      report({ phase: "index", ecosystem: eco, ecosystemsDone: done });
      const entries = zipEntries(zip).filter((e) => e.name.endsWith(".json"));
      const byName = new Map<string, number[]>();
      for (const [i, e] of entries.entries()) {
        if (i % YIELD_EVERY === 0) await tick();
        let adv: Advisory & { withdrawn?: unknown };
        try {
          adv = JSON.parse(zipRead(zip, e).toString("utf8")) as typeof adv;
        } catch {
          unparsable++;
          continue;
        }
        if (adv.withdrawn !== undefined) continue;
        if (!opts.includeMalware && adv.id.startsWith("MAL-")) continue;
        ids.add(adv.id);
        for (const aff of adv.affected ?? []) {
          const name = aff.package?.name;
          if (aff.package?.ecosystem !== eco || typeof name !== "string") continue;
          const list = byName.get(name) ?? [];
          if (!list.includes(i)) list.push(i);
          byName.set(name, list);
        }
      }

      // Pass 2: one shard per package, sorted by id for reproducible hashes.
      report({ phase: "write", ecosystem: eco, ecosystemsDone: done });
      const ecoDir = join(tmp, safeSegment(eco));
      mkdirSync(ecoDir, { recursive: true });
      let n = 0;
      for (const [name, idx] of byName) {
        if (n++ % YIELD_EVERY === 0) await tick();
        const advisories = idx
          .map((i) => JSON.parse(zipRead(zip, entries[i]!).toString("utf8")) as Advisory)
          .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
        writeFileSync(join(ecoDir, `${safeSegment(name)}.json`), JSON.stringify({ contentSha256: shardHash(advisories), advisories }));
      }
      shards += byName.size;
    }

    const generatedAt = new Date(currentTime()).toISOString();
    writeFileSync(
      join(tmp, "manifest.json"),
      JSON.stringify(
        { schemaVersion: 1, generatedAt, source: "osv.dev", ecosystems: opts.ecosystems, includeMalware: opts.includeMalware, advisories: ids.size, shards },
        null,
        2,
      ),
    );

    report({ phase: "swap", ecosystemsDone: total });
    assertReplaceableDb(dir);
    if (existsSync(dir)) {
      const old = `${dir}.old-${process.pid}-${Date.now()}`;
      await renameRetry(dir, old);
      try {
        await renameRetry(tmp, dir);
      } catch (e) {
        await renameRetry(old, dir); // keep the previous DB usable
        throw e;
      }
      rmSync(old, { recursive: true, force: true });
    } else {
      await renameRetry(tmp, dir);
    }
    return { generatedAt, advisories: ids.size, shards, unparsable };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
