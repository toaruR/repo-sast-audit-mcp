# 仕様書

本プロジェクト (repo-sast-audit-mcp) の仕様は次を参照:

- [README.md](../README.md): ツール(6種)・入出力・エラーコード・環境変数・起動方法・セキュリティ保証
- [design-repo-sast-audit-mcp.md](design-repo-sast-audit-mcp.md): 詳細設計 (目標G1-G6, 障害モードF-xx, トレードオフ)

## 概要

ローカルリポジトリを読み取り専用でスキャン(静的ルール・秘密情報・依存関係/オフライン助言DB)し、findings を `get_findings` で取得、`generate_report` で JSON/Markdown/SARIF を出力する stdio MCP サーバー。スキャンは非同期 (`scan_repository` → `get_scan_status` ポーリング、`cancel_scan` で中断)。ネットワークは既定で無効。

エラー処理 (`McpError` の `cause`、reader/writer の失敗時の扱い) は [README.md](../README.md) の "Error handling" を参照。
