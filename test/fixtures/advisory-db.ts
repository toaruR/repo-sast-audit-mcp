import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { shardHash, type Advisory } from "../../src/advisory/db.js";

// Advisory DB fixture (design 2.2 DB layout): manifest.json + <ecosystem>/<name>.json shards.

export const LODASH_ADVISORY: Advisory = {
  id: "GHSA-p6mc-m468-83gw",
  aliases: ["CVE-2020-8203"],
  summary: "Prototype pollution in lodash",
  database_specific: { severity: "HIGH", cvss_score: 7.4 },
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.19" }] }],
    },
  ],
};

export const REQUESTS_ADVISORY: Advisory = {
  id: "GHSA-x84v-xcm2-53pg",
  aliases: ["CVE-2018-18074"],
  summary: "Insufficiently protected credentials in requests",
  database_specific: { severity: "HIGH", cvss_score: 7.5 },
  affected: [
    {
      package: { ecosystem: "PyPI", name: "requests" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.20.0" }] }],
    },
  ],
};

export interface AdvisoryDbOptions {
  /** Defaults to the current time so the DB is never stale. */
  generatedAt?: string;
}

function writeShard(dir: string, ecosystem: string, name: string, advisories: Advisory[]): void {
  mkdirSync(join(dir, ecosystem), { recursive: true });
  writeFileSync(join(dir, ecosystem, `${encodeURIComponent(name)}.json`), JSON.stringify({ contentSha256: shardHash(advisories), advisories }));
}

/** Writes the lodash (npm) and requests (PyPI) fixture DB into `dir` (must exist). */
export function buildAdvisoryDb(dir: string, opts: AdvisoryDbOptions = {}): void {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt }));
  writeShard(dir, "npm", "lodash", [LODASH_ADVISORY]);
  writeShard(dir, "PyPI", "requests", [REQUESTS_ADVISORY]);
}
