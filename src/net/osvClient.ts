import { ENV, readEnv } from "../constants.js";
import type { ErrorCode } from "../errors.js";

export interface OsvPackage {
  ecosystem: string;
  name: string;
  version: string;
}

export type OsvTransport = (body: string) => Promise<unknown>;

export class OsvError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

const OSV_URL = "https://api.osv.dev/v1/query";

function realTransport(): OsvTransport {
  return async (body: string) => {
    const res = await fetch(OSV_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    if (!res.ok) throw new OsvError("E_INTERNAL", `OSV HTTP ${res.status}`);
    return res.json();
  };
}

export function buildRequestBody(pkg: OsvPackage): string {
  return JSON.stringify({ ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version });
}

export interface OsvClient {
  query(pkgs: readonly OsvPackage[]): Promise<unknown[]>;
}

export function createOsvClient(opts: {
  transport?: OsvTransport;
  networkAllowed?: () => boolean;
} = {}): OsvClient {
  let transport = opts.transport;
  const allowed = opts.networkAllowed ?? (() => readEnv(ENV.ALLOW_NETWORK) === "1");
  return {
    async query(pkgs) {
      if (!allowed()) {
        throw new OsvError("E_NETWORK_DISABLED", "network access disabled");
      }
      transport ??= realTransport();
      const out: unknown[] = [];
      for (const p of pkgs) out.push(await transport(buildRequestBody(p)));
      return out;
    },
  };
}
