# repo-sast-audit-mcp

> **ステータス: プロトタイプ。** API・ツールスキーマ・ルールセット・環境変数は予告なく変更されることがあります。本番利用は想定していません。

高速・読み取り専用の静的解析 / シークレット / 依存関係監査 MCP サーバーです。SARIF 出力に対応しています（stdio、Node `>=20.11 <23`、ESM TypeScript）。設計書: [docs/design-repo-sast-audit-mcp.md](docs/design-repo-sast-audit-mcp.md)。English: [README.md](README.md)。
注: `ajv` は直接の依存として宣言せず、MCP SDK が固定している依存（hoist 済み）を利用しています。

## 実行

```sh
npm ci
npm run build        # tsc
npm test             # node --import tsx --test test/*.test.ts
npm run typecheck    # tsc --noEmit
npm run lint         # eslint src
node --import tsx src/index.ts [rules.json]   # stdio サーバーを起動（開発用）
```

`src/index.ts` は起動時にルールファイル（既定は `rules/rules.json`、argv[2] で指定可）を自己テストします。ルールファイルが不正な場合は stderr に `E_RULE_INVALID: ...` を出力して終了コード 2 で終了し、ツールは提供されません。stdin が閉じるとサーバーは終了コード 0 で終了します。ログは stderr に出力され、内容はツール名・エラーコード・件数・ruleId・相対パスのみです。

## MCP クライアントへの登録

一度ビルドしてから、クライアントの起動先を `dist/src/index.js` に設定します（`/path/to/repo-sast-audit-mcp` はクローン先に置き換えてください）。ルールとスキーマはパッケージルートから解決されるため、どの cwd からでも動作します。

```sh
cd /path/to/repo-sast-audit-mcp && npm ci && npm run build
```

**推奨: ユーザー（グローバル）スコープ。** `SAST_AUDIT_MCP_ALLOWED_ROOTS` が未設定の場合、スキャンできるルートはサーバーの cwd だけです。Claude Code は stdio サーバーをプロジェクトディレクトリで起動するので、グローバルに 1 回登録するだけでも、スキャン対象は開いているプロジェクトに限定されます。

```sh
claude mcp add --scope user repo-sast-audit -- node /path/to/repo-sast-audit-mcp/dist/src/index.js
```

アドバイザリ DB と `update_advisory_db` を使う場合は、環境変数を付けて登録します（`-e` はサーバー名の後に置きます）。

```sh
claude mcp add --scope user repo-sast-audit \
  -e SAST_AUDIT_MCP_ADVISORY_DB=/path/to/advisory-db \
  -e SAST_AUDIT_MCP_ALLOW_NETWORK=1 \
  -- node /path/to/repo-sast-audit-mcp/dist/src/index.js
```

**プロジェクトスコープ**は、特定のプロジェクトだけ設定を変えたい場合（オンライン OSV 照会や別のアドバイザリ DB など）に使います。プロジェクトルートの `.mcp.json` の例:

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

サーバーをプロジェクトディレクトリで起動しないクライアント（Claude Desktop など）では、`SAST_AUDIT_MCP_ALLOWED_ROOTS` を明示的に設定する必要があります（絶対パス。区切りは Windows では `;`、それ以外では `:`）。設定しないと、すべての `repoPath` が `E_PATH_TRAVERSAL` になります。

## ツール（7 個）

入出力の JSON Schema は `schemas/tools.json`（と `schemas/defs.json`）にあり、`src/contracts.ts` で Ajv により検証されます。結果はすべて `structuredContent` で返ります。失敗時は `isError: true` となり、`structuredContent.error = { code, message, retryable }` が返ります。

| ツール | 入力 | 出力 |
|---|---|---|
| `scan_repository` | `repoPath`（必須、1〜4096 文字）、任意で `scanners`、`force`、`strictLimits`、`online`、`symlinkPolicy`、`respectGitignore`、`includeGlobs`、`excludeGlobs`、`limits{maxFiles,maxFileBytes,maxTotalBytes,maxFindings,timeoutMs}`、`waitMs`（0〜30000） | `scanId`、`state`、`requestKey`、`reused`、`warnings`、`repoRealPath`。非同期なので `get_scan_status` でポーリングします。 |
| `get_scan_status` | `scanId` | `scanId`、`state`、`progress`、`cancelRequested`、`truncated`、`durationMs`、`error`、summary |
| `cancel_scan` | `scanId` | `scanId`、`state`、`cancelRequested` |
| `get_findings` | `scanId`。任意で `cursor`（256 文字以下、`[A-Za-z0-9_-]+`）、`limit`（1〜200、既定 50）、`includeEvidence`（既定 true）、`filter{minSeverity,scanners,ruleIds,cwe,pathPrefix}` | `scanId`、`state`、`complete`、`total`、`findings`、`nextCursor`、`untrusted` |
| `generate_report` | `scanId`。任意で `formats`（`md`、`json`、`sarif`。既定は `md`、`json`）、`outputDir`、`allowWriteInsideTarget`（false）、`allowPartial`（false）、`includeEvidence`（true） | `scanId`、`outputDir`、`files[{format,path,bytes,sha256}]`、`summary`、`partial` |
| `list_scanners` | なし | `serverVersion`、`rulesetHash`、`scanners[{id,version,ruleCount,enabledByDefault,...}]`、`advisoryDb`、`networkAllowed`、`limits` |
| `update_advisory_db` | 任意で `action`（`start` が既定、`status`）、`ecosystems`（`npm`、`PyPI`、`crates.io`、`Go`、`Maven` の部分集合。既定は全部）、`includeMalware`（既定 true） | `state`（`idle`、`running`、`completed`、`failed`）、`started`、`options`、`progress{phase,ecosystem,ecosystemsDone,ecosystemsTotal}`、`startedAt`、`finishedAt`、`result{generatedAt,advisories,shards,unparsable}`、`error`。非同期なので `action: "status"` でポーリングします。 |

既定の上限（最小..最大）: maxFiles 50000（1..500000）、maxFileBytes 1 MiB（1 KiB..8 MiB）、maxTotalBytes 512 MiB（1 MiB..4 GiB）、maxFindings 5000（1..50000）、timeoutMs 120000（1000..900000）。スキャンの同時実行数は実行中 2・待機 8 で、直近 20 ジョブを保持します。

## エラーコード（`src/errors.ts`。[ ] 内はリトライ可否）

`E_INVALID_INPUT`、`E_PATH_TRAVERSAL`、`E_NOT_FOUND`、`E_PERMISSION_DENIED`（リトライ不可）、`E_LIMIT_EXCEEDED` [キュー満杯時のみリトライ可]、`E_TIMEOUT` [リトライ可]、`E_CANCELLED`、`E_NETWORK_DISABLED`、`E_ADVISORY_DB_MISSING`、`E_ADVISORY_DB_INVALID`（リトライ不可）、`E_SCAN_NOT_COMPLETE` [リトライ可]、`E_CURSOR_STALE` [リトライ可]、`E_OUTPUT_DIR_UNSAFE`（リトライ不可）、`E_WRITE_FAILED` [リトライ可]、`E_RULE_INVALID`、`E_INTERNAL`（リトライ不可）。

## 環境変数（`src/constants.ts`）

| 変数 | 用途 |
|---|---|
| `SAST_AUDIT_MCP_ALLOWED_ROOTS` | スキャンを許可するルート。`repoPath` はこのいずれかの内側に解決される必要があります |
| `SAST_AUDIT_MCP_OUTPUT_ROOT` | レポート出力ディレクトリのルート |
| `SAST_AUDIT_MCP_ALLOW_NETWORK` | オンライン OSV 照会と `update_advisory_db` を有効にします（未設定時は `E_NETWORK_DISABLED`） |
| `SAST_AUDIT_MCP_FIXED_TIME` | 再現可能なレポートのための固定時刻 |
| `SAST_AUDIT_MCP_ADVISORY_DB` | オフラインのアドバイザリ DB のパス（`update_advisory_db` の更新先でもあります） |
| `SAST_AUDIT_MCP_DB_STALE_DAYS` | `W_ADVISORY_DB_STALE` を出すアドバイザリ DB の経過日数（既定 30、1..3650） |

## オフラインのアドバイザリ DB

依存関係スキャン（ロックファイル: package-lock、yarn、pnpm、poetry、Cargo、requirements.txt、go.sum、pom.xml など）は、ローカルのシャード分割されたアドバイザリ DB と照合します（manifest とシャードで構成され、シャードは `contentSha256` で検証されます。不正なシャードは `W_ADVISORY_DB_INVALID_SHARD` を出して無視し、manifest が無い・不正な場合は `E_ADVISORY_DB_MISSING` / `E_ADVISORY_DB_INVALID` になります）。ネットワークは既定で無効です。テスト用フィクスチャは `test/fixtures` にあります。

DB は [OSV](https://osv.dev) の一括ダンプから作成・更新します（`W_ADVISORY_DB_STALE` を避けるため、`SAST_AUDIT_MCP_DB_STALE_DAYS` 以内に再作成してください）。

- **MCP クライアントから:** `update_advisory_db` を呼び出します（`SAST_AUDIT_MCP_ALLOW_NETWORK=1` と `SAST_AUDIT_MCP_ADVISORY_DB` が必要）。その後、`completed` になるまで `update_advisory_db {"action":"status"}` でポーリングします（全エコシステムで数分かかります。npm は約 220 MB）。ダンプはメモリ上で処理し、ディスクに書くのはシャードだけです。DB は `<db>.tmp-*` に作成し、成功した場合にだけ入れ替えるので、更新に失敗しても以前の DB は残ります。更新先は「存在しない」「空」「既存の DB（`manifest.json` が `schemaVersion: 1`）」のいずれかである必要があり、それ以外は `E_OUTPUT_DIR_UNSAFE` で拒否します。`ecosystems` は新しい DB 全体の内容を決めます（指定しなかったエコシステムは消えます）。更新はサーバーごとに同時に 1 つだけ実行されます。
- **シェルから:**

```sh
for e in npm PyPI Go Maven crates.io; do
  mkdir -p osv-src/$e
  curl -sSfL -o $e.zip "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip"
  unzip -q -o $e.zip -d osv-src/$e
done
node scripts/build-advisory-db.mjs /path/to/advisory-db osv-src/*
```

**ウイルス対策ソフトによる検疫。** OSV の `MAL-*` レコード（と一部の GHSA レコード）には実際のマルウェアの断片が含まれるため、Microsoft Defender などが `osv-src/` や DB 内のファイルを検疫することがあります（例: `Trojan:NPM/Stealer`、`Trojan:PyPI/ShaiWorm`）。中身は実行されない JSON データですが、次の点に注意してください。

- シェルで作成した場合は、`osv-src/` を除外設定に入れずに、作成後に削除してください。実行時には不要です（`update_advisory_db` はこのフォルダを作りません）。
- DB 内のシャードが検疫されると、「アドバイザリなし」と区別がつきません（シャードが無いことはエラーにならない）。そのため、そのパッケージの検出が警告なしで抜けます。DB の作成後やフルスキャンの後は、ウイルス対策ソフトの検出履歴を確認してください。
- シャードが検疫された場合は、除外設定を DB ディレクトリだけに絞って追加するか、マルウェアレコードを除いて作り直してください（`update_advisory_db {"includeMalware": false}`、またはスクリプト実行前に `osv-src/` から `MAL-*` を削除）。後者の場合、悪性パッケージの検出はできなくなります。

## レポート

`generate_report` は Markdown、JSON、SARIF の各ファイルを書き出し、ファイルごとに sha256 とバイト数を返します。`allowWriteInsideTarget` が true でない限り、出力先はスキャン対象リポジトリの外になります。安全でないディレクトリは `E_OUTPUT_DIR_UNSAFE` になります。未完了のスキャンには `allowPartial` が必要で、無い場合は `E_SCAN_NOT_COMPLETE` になります。

## セキュリティ上の保証

- 対象リポジトリは読み取り専用です。シンボリックリンクは既定でスキップし、パストラバーサルやルート外のパスは拒否します。
- 静的ルールは RE2（線形時間）で、ファイルごとの時間予算付きで実行します。`child_process`、`vm`、`eval`、動的 `import()` は使いません（ESLint で強制）。fs への書き込みは `src/report/writer.ts` と `src/advisory/update.ts`（アドバイザリ DB ディレクトリのみ）に限られ、ネットワークアクセスは `src/net/osvClient.ts` だけです。
- シークレットは検出結果・レポート・ログで伏せ字にします（`assertNoSecrets`）。evidence はサニタイズされます（HTML・制御文字・bidi 文字をエスケープし、200 文字以下）。
- 検出結果のテキストは信頼できないデータ（`untrusted: true`）として扱い、指示としては扱いません。

## エラー処理

`McpError` は任意で `cause` を受け取ります（内部専用で、ツール出力・レポート・エンベロープには含まれません）。catch では想定した errno コードだけを処理し、それ以外は再スローします。リーダーのクローズ時の想定外の失敗（`EBADF` 以外）は `W_PERMISSION_DENIED` になります。レポートライターの後片付けの失敗は、元のエラーを `cause` に持つ `E_WRITE_FAILED` になります。

## ライセンス

[MIT](LICENSE) © 2026 toaruR。`test/fixtures` のアドバイザリ用フィクスチャは、[GitHub Advisory Database](https://github.com/github/advisory-database)（CC-BY 4.0）の ID と概要を参照しています。
