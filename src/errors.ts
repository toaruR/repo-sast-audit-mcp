// Error catalogue (design 3.1). Value = retryable flag.
export const ERROR_CODES = {
  E_INVALID_INPUT: false,
  E_PATH_TRAVERSAL: false,
  E_NOT_FOUND: false,
  E_PERMISSION_DENIED: false,
  E_LIMIT_EXCEEDED: true, // retryable only for "queue full"; strict-limit job error is not retried by callers
  E_TIMEOUT: true,
  E_CANCELLED: false,
  E_NETWORK_DISABLED: false,
  E_ADVISORY_DB_MISSING: false,
  E_ADVISORY_DB_INVALID: false,
  E_SCAN_NOT_COMPLETE: true,
  E_CURSOR_STALE: true,
  E_OUTPUT_DIR_UNSAFE: false,
  E_WRITE_FAILED: true,
  E_RULE_INVALID: false,
  E_INTERNAL: false,
} as const;

export type ErrorCode = keyof typeof ERROR_CODES;

export function isRetryable(code: ErrorCode): boolean {
  return ERROR_CODES[code];
}

export class McpError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "McpError";
    this.code = code;
  }
}
