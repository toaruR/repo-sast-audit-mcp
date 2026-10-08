# repo-sast-audit-mcp

> **Status: prototype.** APIs, tool schemas, rule set, and environment variables may change without notice. Not intended for production use.

Fast, read-only static analysis / secret / dependency audit MCP server with SARIF output (stdio, Node `>=20.11 <23`, ESM TypeScript). Design: [docs/design-repo-sast-audit-mcp.md](docs/design-repo-sast-audit-mcp.md). 日本語: [README.ja.md](README.ja.md).
Note: `ajv` is consumed as the MCP SDK's own pinned dependency (hoisted), not declared directly.

## Run

```sh
npm ci
npm run build        # tsc
npm test             # node --import tsx --test test/*.test.ts
npm run typecheck    # tsc --noEmit
npm run lint         # eslint src
node --import tsx src/index.ts [rules.json]   # start the stdio server (dev)
```

`src/index.ts` runs a startup self-test of the rule file (default `rules/rules.json`, optional argv[2]). An invalid rule file prints `E_RULE_INVALID: ...` to stderr and exits with code 2; no tool is served. The server exits 0 when stdin closes. Logs go to stderr and contain only tool name, error code, counts, ruleIds and relative paths.

## Register with an MCP client

Build once, then point the client at `dist/src/index.js` (replace `/path/to/repo-sast-audit-mcp` with your clone). Rules and schemas are resolved from the package root, so the server works from any cwd.

```sh
cd /path/to/repo-sast-audit-mcp && npm ci && npm run build
```

**Recommended: user (global) scope.** With `SAST_AUDIT_MCP_ALLOWED_ROOTS` unset, the only allowed scan root is the server's cwd. Claude Code starts stdio servers in the project directory, so a single global registration is still confined to the current project.

```sh
claude mcp add --scope user repo-sast-audit -- node /path/to/repo-sast-audit-mcp/dist/src/index.js
```

To use the advisory DB and `update_advisory_db`, register with environment variables (`-e` goes after the server name):

```sh
claude mcp add --scope user repo-sast-audit   -e SAST_AUDIT_MCP_ADVISORY_DB=/path/to/advisory-db   -e SAST_AUDIT_MCP_ALLOW_NETWORK=1   -- node /path/to/repo-sast-audit-mcp/dist/src/index.js
```

**Project scope** only when one project needs different settings (e.g. online OSV lookups or a specific advisory DB). Example `.mcp.json` at the project root:

```json
{
  "mcpServers": {
    "repo-sast-audit": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/repo-sast-audit-mcp/dist/src/index.js"],
      "env": {
        "SAST_AUDIT_MCP_ADVISORY_DB": "/path/to/advisory-db",
        "SAST_AUDIT_MCP_ALLOW_NETWORK": "1"
      }
    }
  }
}
```

Clients that do not start servers in the project directory (e.g. Claude Desktop) must set `SAST_AUDIT_MCP_ALLOWED_ROOTS` explicitly (absolute paths, separated by `;` on Windows and `:` elsewhere); otherwise every `repoPath` fails with `E_PATH_TRAVERSAL`.

## Tools (7)

Input/output JSON Schemas: `schemas/tools.json` (+ `schemas/defs.json`), validated with Ajv via `src/contracts.ts`. Every result is `structuredContent`; failures are `isError: true` with `structuredContent.error = { code, message, retryable }`.

| Tool | Input | Output |
|---|---|---|
| `scan_repository` | `repoPath` (required, 1-4096 chars), optional `scanners`, `force`, `strictLimits`, `online`, `symlinkPolicy`, `respectGitignore`, `includeGlobs`, `excludeGlobs`, `limits{maxFiles,maxFileBytes,maxTotalBytes,maxFindings,timeoutMs}`, `waitMs` (0-30000) | `scanId`, `state`, `requestKey`, `reused`, `warnings`, `repoRealPath`. Async: poll `get_scan_status`. |
| `get_scan_status` | `scanId` | `scanId`, `state`, `progress`, `cancelRequested`, `truncated`, `durationMs`, `error`, summary |
| `cancel_scan` | `scanId` | `scanId`, `state`, `cancelRequested` |
| `get_findings` | `scanId`; optional `cursor` (<=256, `[A-Za-z0-9_-]+`), `limit` (1-200, default 50), `includeEvidence` (default true), `filter{minSeverity,scanners,ruleIds,cwe,pathPrefix}` | `scanId`, `state`, `complete`, `total`, `findings`, `nextCursor`, `untrusted` |
| `generate_report` | `scanId`; optional `formats` (`md`,`json`,`sarif`; default `md`,`json`), `outputDir`, `allowWriteInsideTarget` (false), `allowPartial` (false), `includeEvidence` (true) | `scanId`, `outputDir`, `files[{format,path,bytes,sha256}]`, `summary`, `partial` |
| `list_scanners` | none | `serverVersion`, `rulesetHash`, `scanners[{id,version,ruleCount,enabledByDefault,...}]`, `advisoryDb`, `networkAllowed`, `limits` |
| `update_advisory_db` | optional `action` (`start` default, `status`), `ecosystems` (subset of `npm`,`PyPI`,`crates.io`,`Go`,`Maven`; default all), `includeMalware` (default true) | `state` (`idle`,`running`,`completed`,`failed`), `started`, `options`, `progress{phase,ecosystem,ecosystemsDone,ecosystemsTotal}`, `startedAt`, `finishedAt`, `result{generatedAt,advisories,shards,unparsable}`, `error`. Async: poll with `action: "status"`. |

Default limits (min..max): maxFiles 50000 (1..500000), maxFileBytes 1 MiB (1 KiB..8 MiB), maxTotalBytes 512 MiB (1 MiB..4 GiB), maxFindings 5000 (1..50000), timeoutMs 120000 (1000..900000). Scanner concurrency: 2 running, 8 queued, last 20 jobs kept.

## Error codes (`src/errors.ts`; retryable in brackets)

`E_INVALID_INPUT`, `E_PATH_TRAVERSAL`, `E_NOT_FOUND`, `E_PERMISSION_DENIED` (not retryable); `E_LIMIT_EXCEEDED` [retryable for queue full]; `E_TIMEOUT` [retryable]; `E_CANCELLED`, `E_NETWORK_DISABLED`, `E_ADVISORY_DB_MISSING`, `E_ADVISORY_DB_INVALID` (not retryable); `E_SCAN_NOT_COMPLETE` [retryable]; `E_CURSOR_STALE` [retryable]; `E_OUTPUT_DIR_UNSAFE` (not retryable); `E_WRITE_FAILED` [retryable]; `E_RULE_INVALID`, `E_INTERNAL` (not retryable).

## Environment variables (`src/constants.ts`)

| Variable | Purpose |
|---|---|
| `SAST_AUDIT_MCP_ALLOWED_ROOTS` | Allowed scan roots; `repoPath` must resolve inside one of them |
| `SAST_AUDIT_MCP_OUTPUT_ROOT` | Root for report output directories |
| `SAST_AUDIT_MCP_ALLOW_NETWORK` | Enables online OSV lookups and `update_advisory_db` (otherwise `E_NETWORK_DISABLED`) |
| `SAST_AUDIT_MCP_FIXED_TIME` | Fixed clock for reproducible reports |
| `SAST_AUDIT_MCP_ADVISORY_DB` | Path to the offline advisory DB (also the target of `update_advisory_db`) |
| `SAST_AUDIT_MCP_DB_STALE_DAYS` | Advisory DB age (days) after which `W_ADVISORY_DB_STALE` is raised (default 30, 1..3650) |

## Offline advisory DB

Dependency scanning (lockfiles: package-lock, yarn, pnpm, poetry, Cargo, requirements.txt, go.sum, pom.xml, ...) matches against a local sharded advisory DB (manifest plus shards verified by `contentSha256`; invalid shards are ignored with `W_ADVISORY_DB_INVALID_SHARD`; missing/invalid manifest raises `E_ADVISORY_DB_MISSING` / `E_ADVISORY_DB_INVALID`). Network is off by default; fixtures live in `test/fixtures`.

Build or refresh the DB from the [OSV](https://osv.dev) bulk dumps (re-run within `SAST_AUDIT_MCP_DB_STALE_DAYS` to avoid `W_ADVISORY_DB_STALE`):

- **From the MCP client:** call `update_advisory_db` (needs `SAST_AUDIT_MCP_ALLOW_NETWORK=1` and `SAST_AUDIT_MCP_ADVISORY_DB`), then poll `update_advisory_db {"action":"status"}` until `completed` (a full build takes several minutes; npm is ~220 MB). Dumps are processed in memory, nothing but the shards is written to disk. The DB is rebuilt in `<db>.tmp-*` and swapped in only on success, so a failed update keeps the previous DB. The target must be absent, empty, or an existing DB (`manifest.json` with `schemaVersion: 1`); anything else is refused with `E_OUTPUT_DIR_UNSAFE`. `ecosystems` defines the whole new DB (ecosystems not listed are dropped). One update runs at a time per server.
- **From the shell:**

```sh
for e in npm PyPI Go Maven crates.io; do
  mkdir -p osv-src/$e
  curl -sSfL -o $e.zip "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip"
  unzip -q -o $e.zip -d osv-src/$e
done
node scripts/build-advisory-db.mjs /path/to/advisory-db osv-src/*
```

**Antivirus quarantine.** OSV `MAL-*` records (and some GHSA records) embed snippets of real malware, so Microsoft Defender and similar tools may quarantine files in `osv-src/` or in the DB (e.g. `Trojan:NPM/Stealer`, `Trojan:PyPI/ShaiWorm`). These are inert JSON data, but:

- Delete `osv-src/` after a shell build instead of excluding it; it is not needed at runtime (`update_advisory_db` never creates it).
- A quarantined shard in the DB is indistinguishable from "no advisories" (a missing shard is not an error), so detections for that package are silently lost. Check your AV history after builds and full scans.
- If shards get quarantined, either add an AV exclusion scoped to the DB directory only, or rebuild without malware records (`update_advisory_db {"includeMalware": false}`, or drop `MAL-*` files from `osv-src/` before running the script) at the cost of losing malicious-package detection.

## Reports

`generate_report` writes Markdown, JSON and SARIF files plus sha256/bytes per file. Output goes outside the scanned repo unless `allowWriteInsideTarget` is true; unsafe directories raise `E_OUTPUT_DIR_UNSAFE`. Incomplete scans need `allowPartial`, otherwise `E_SCAN_NOT_COMPLETE`.

## Security guarantees

- Read-only on the target repo; symlinks skipped by default; path traversal and out-of-root paths rejected.
- Static rules run on RE2 (linear time) with a per-file time budget; no `child_process`, `vm`, `eval` or dynamic `import()` (enforced by ESLint); fs writes only in `src/report/writer.ts` and `src/advisory/update.ts` (advisory DB directory only); network only in `src/net/osvClient.ts`.
- Secrets are redacted in findings, reports and logs (`assertNoSecrets`); evidence is sanitized (HTML/control/bidi escaped, <=200 chars).
- Finding text is untrusted data (`untrusted: true`), never instructions.
## Error handling
`McpError` accepts an optional `cause` (internal only; never included in tool outputs, reports or envelopes). Catches handle only expected errno codes and rethrow the rest. Unexpected reader close failures (other than `EBADF`) produce `W_PERMISSION_DENIED`; cleanup failures in the report writer surface as `E_WRITE_FAILED` with the original error as `cause`.

## License

[MIT](LICENSE) © 2026 toaruR. Advisory fixtures in `test/fixtures` reference IDs and summaries from the [GitHub Advisory Database](https://github.com/github/advisory-database) (CC-BY 4.0).
