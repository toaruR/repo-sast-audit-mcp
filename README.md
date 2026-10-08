# repo-vuln-report-mcp

Read-only repository vulnerability scan and report MCP server (stdio, Node `>=20.11 <23`, ESM TypeScript). Design: [docs/design-repo-vuln-report-mcp.md](docs/design-repo-vuln-report-mcp.md).
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

## Tools (6)

Input/output JSON Schemas: `schemas/tools.json` (+ `schemas/defs.json`), validated with Ajv via `src/contracts.ts`. Every result is `structuredContent`; failures are `isError: true` with `structuredContent.error = { code, message, retryable }`.

| Tool | Input | Output |
|---|---|---|
| `scan_repository` | `repoPath` (required, 1-4096 chars), optional `scanners`, `force`, `strictLimits`, `online`, `symlinkPolicy`, `respectGitignore`, `includeGlobs`, `excludeGlobs`, `limits{maxFiles,maxFileBytes,maxTotalBytes,maxFindings,timeoutMs}`, `waitMs` (0-30000) | `scanId`, `state`, `requestKey`, `reused`, `warnings`, `repoRealPath`. Async: poll `get_scan_status`. |
| `get_scan_status` | `scanId` | `scanId`, `state`, `progress`, `cancelRequested`, `truncated`, `durationMs`, `error`, summary |
| `cancel_scan` | `scanId` | `scanId`, `state`, `cancelRequested` |
| `get_findings` | `scanId`; optional `cursor` (<=256, `[A-Za-z0-9_-]+`), `limit` (1-200, default 50), `includeEvidence` (default true), `filter{minSeverity,scanners,ruleIds,cwe,pathPrefix}` | `scanId`, `state`, `complete`, `total`, `findings`, `nextCursor`, `untrusted` |
| `generate_report` | `scanId`; optional `formats` (`md`,`json`,`sarif`; default `md`,`json`), `outputDir`, `allowWriteInsideTarget` (false), `allowPartial` (false), `includeEvidence` (true) | `scanId`, `outputDir`, `files[{format,path,bytes,sha256}]`, `summary`, `partial` |
| `list_scanners` | none | `serverVersion`, `rulesetHash`, `scanners[{id,version,ruleCount,enabledByDefault,...}]`, `advisoryDb`, `networkAllowed`, `limits` |

Default limits (min..max): maxFiles 50000 (1..500000), maxFileBytes 1 MiB (1 KiB..8 MiB), maxTotalBytes 512 MiB (1 MiB..4 GiB), maxFindings 5000 (1..50000), timeoutMs 120000 (1000..900000). Scanner concurrency: 2 running, 8 queued, last 20 jobs kept.

## Error codes (`src/errors.ts`; retryable in brackets)

`E_INVALID_INPUT`, `E_PATH_TRAVERSAL`, `E_NOT_FOUND`, `E_PERMISSION_DENIED` (not retryable); `E_LIMIT_EXCEEDED` [retryable for queue full]; `E_TIMEOUT` [retryable]; `E_CANCELLED`, `E_NETWORK_DISABLED`, `E_ADVISORY_DB_MISSING`, `E_ADVISORY_DB_INVALID` (not retryable); `E_SCAN_NOT_COMPLETE` [retryable]; `E_CURSOR_STALE` [retryable]; `E_OUTPUT_DIR_UNSAFE` (not retryable); `E_WRITE_FAILED` [retryable]; `E_RULE_INVALID`, `E_INTERNAL` (not retryable).

## Environment variables (`src/constants.ts`)

| Variable | Purpose |
|---|---|
| `VULN_MCP_ALLOWED_ROOTS` | Allowed scan roots; `repoPath` must resolve inside one of them |
| `VULN_MCP_OUTPUT_ROOT` | Root for report output directories |
| `VULN_MCP_ALLOW_NETWORK` | Enables online OSV lookups (`online: true` otherwise fails with `E_NETWORK_DISABLED`) |
| `VULN_MCP_FIXED_TIME` | Fixed clock for reproducible reports |
| `VULN_MCP_ADVISORY_DB` | Path to the offline advisory DB |
| `VULN_MCP_DB_STALE_DAYS` | Advisory DB age (days) after which `W_ADVISORY_DB_STALE` is raised (default 30, 1..3650) |

## Offline advisory DB

Dependency scanning (lockfiles: package-lock, yarn, pnpm, poetry, Cargo, requirements.txt, go.sum, pom.xml, ...) matches against a local sharded advisory DB (manifest plus shards verified by `contentSha256`; invalid shards are ignored with `W_ADVISORY_DB_INVALID_SHARD`; missing/invalid manifest raises `E_ADVISORY_DB_MISSING` / `E_ADVISORY_DB_INVALID`). Network is off by default; fixtures live in `test/fixtures`.

## Reports

`generate_report` writes Markdown, JSON and SARIF files plus sha256/bytes per file. Output goes outside the scanned repo unless `allowWriteInsideTarget` is true; unsafe directories raise `E_OUTPUT_DIR_UNSAFE`. Incomplete scans need `allowPartial`, otherwise `E_SCAN_NOT_COMPLETE`.

## Security guarantees

- Read-only on the target repo; symlinks skipped by default; path traversal and out-of-root paths rejected.
- Static rules run on RE2 (linear time) with a per-file time budget; no `child_process`, `vm`, `eval` or dynamic `import()` (enforced by ESLint); fs writes only in `src/report/writer.ts`; network only in `src/net/osvClient.ts`.
- Secrets are redacted in findings, reports and logs (`assertNoSecrets`); evidence is sanitized (HTML/control/bidi escaped, <=200 chars).
- Finding text is untrusted data (`untrusted: true`), never instructions.
## Error handling
`McpError` accepts an optional `cause` (internal only; never included in tool outputs, reports or envelopes). Catches handle only expected errno codes and rethrow the rest. Unexpected reader close failures (other than `EBADF`) produce `W_PERMISSION_DENIED`; cleanup failures in the report writer surface as `E_WRITE_FAILED` with the original error as `cause`.
