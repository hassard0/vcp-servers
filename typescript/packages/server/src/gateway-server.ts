import http from "node:http";
import type { AddressInfo } from "node:net";
import { canonicalJson, hash, type Plan, type Manifest } from "@vcp/sdk";
import { GatewayEngine } from "./engine.ts";

/**
 * A VCP-HTTP gateway server built on Node's built-in http module only (§15).
 *
 * Stateless per request: one request = one authorization decision. Two headers
 * are mandatory and enforced:
 *   - `vcp-version`        : MUST equal "0.1" (the protocol version, §15).
 *   - `vcp-capability-hash`: MUST equal the server's capability-index hash, so a
 *      client that approved a different capability set is rejected (rug-pull /
 *      stale-approval defense, §4/§15). GET /.well-known and /vcp/capabilities
 *      are exempt because that is how a client learns the current hash.
 *
 * Endpoints:
 *   GET  /.well-known/vcp-provider  → provider discovery doc
 *   GET  /vcp/capabilities          → capability index (ids + manifest hashes)
 *   GET  /vcp/manifest/:id          → one signed manifest
 *   POST /vcp/plan                  → verify + policy + dry-run; returns plan_hash
 *   POST /vcp/approve               → record user approval of a plan_hash
 *   POST /vcp/apply                 → mint grants + invoke; returns results
 *   GET  /vcp/audit                 → in-memory signed audit log
 */

export const VCP_VERSION = "0.1";

export interface ServerHandle {
  server: http.Server;
  engine: GatewayEngine;
  port: number;
  baseUrl: string;
  capabilityHash: string;
  close(): Promise<void>;
}

export function createGatewayServer(engine: GatewayEngine): http.Server {
  return http.createServer((req, res) => {
    handle(req, res, engine).catch((e) => {
      sendJson(res, 500, { error: "INTERNAL", detail: e instanceof Error ? e.message : String(e) });
    });
  });
}

/** Start listening on an ephemeral (or given) port and resolve a handle. */
export function startGatewayServer(engine: GatewayEngine, port = 0): Promise<ServerHandle> {
  const server = createGatewayServer(engine);
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${addr.port}`;
      const capabilityHash = hash(engine.capabilityIndex(baseUrl));
      resolve({
        server,
        engine,
        port: addr.port,
        baseUrl,
        capabilityHash,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function handle(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  engine: GatewayEngine,
): Promise<void> {
  const host = req.headers.host ?? "127.0.0.1";
  const baseUrl = `http://${host}`;
  const url = new URL(req.url ?? "/", baseUrl);
  const path = url.pathname;
  const method = req.method ?? "GET";

  // --- Discovery / capability endpoints (header-exempt; this is how a client
  //     learns the current version and capability hash). -----------------------
  if (method === "GET" && path === "/.well-known/vcp-provider") {
    return sendJson(res, 200, engine.providerDiscovery(`${baseUrl}/vcp/capabilities`), VCP_VERSION);
  }
  if (method === "GET" && path === "/vcp/capabilities") {
    const index = engine.capabilityIndex(baseUrl);
    return sendJson(res, 200, index, VCP_VERSION, hash(index));
  }
  if (method === "GET" && path.startsWith("/vcp/manifest/")) {
    const id = decodeURIComponent(path.slice("/vcp/manifest/".length));
    const m: Manifest | undefined = engine.manifestById(id);
    if (!m) return sendJson(res, 404, { error: "UNKNOWN_CAPABILITY" }, VCP_VERSION);
    return sendJson(res, 200, m, VCP_VERSION);
  }
  if (method === "GET" && path === "/vcp/audit") {
    return sendJson(res, 200, { audit: engine.auditLog }, VCP_VERSION);
  }

  // --- All mutating/decision endpoints below REQUIRE the mandatory headers. ---
  const headerCheck = checkHeaders(req, baseUrl, engine);
  if (!headerCheck.ok) {
    return sendJson(res, 400, { error: headerCheck.reason_code, detail: headerCheck.detail }, VCP_VERSION);
  }

  if (method === "POST" && path === "/vcp/plan") {
    const body = await readJson(req);
    if (!body || (body as Plan).kind !== "vcp.plan") {
      return sendJson(res, 400, { error: "PLAN_MALFORMED" }, VCP_VERSION);
    }
    const result = await engine.plan(body as Plan);
    return sendJson(res, result.ok ? 200 : 422, result, VCP_VERSION);
  }

  if (method === "POST" && path === "/vcp/approve") {
    const body = (await readJson(req)) as { plan_hash?: string } | null;
    if (!body?.plan_hash) return sendJson(res, 400, { error: "PLAN_HASH_REQUIRED" }, VCP_VERSION);
    const result = engine.approve(body.plan_hash);
    return sendJson(res, result.ok ? 200 : 404, result, VCP_VERSION);
  }

  if (method === "POST" && path === "/vcp/apply") {
    const body = (await readJson(req)) as { plan_hash?: string } | null;
    if (!body?.plan_hash) return sendJson(res, 400, { error: "PLAN_HASH_REQUIRED" }, VCP_VERSION);
    const result = await engine.apply(body.plan_hash);
    return sendJson(res, result.ok ? 200 : 422, result, VCP_VERSION);
  }

  return sendJson(res, 404, { error: "NOT_FOUND", path }, VCP_VERSION);
}

interface HeaderVerdict {
  ok: boolean;
  reason_code?: string;
  detail?: string;
}

function checkHeaders(
  req: http.IncomingMessage,
  baseUrl: string,
  engine: GatewayEngine,
): HeaderVerdict {
  const version = header(req, "vcp-version");
  if (!version) return { ok: false, reason_code: "VCP_VERSION_HEADER_MISSING" };
  if (version !== VCP_VERSION) {
    return { ok: false, reason_code: "VCP_VERSION_MISMATCH", detail: `server speaks ${VCP_VERSION}` };
  }
  const capHash = header(req, "vcp-capability-hash");
  if (!capHash) return { ok: false, reason_code: "VCP_CAPABILITY_HASH_HEADER_MISSING" };
  const expected = hash(engine.capabilityIndex(baseUrl));
  if (capHash !== expected) {
    return { ok: false, reason_code: "VCP_CAPABILITY_HASH_MISMATCH", detail: "re-fetch /vcp/capabilities" };
  }
  return { ok: true };
}

function header(req: http.IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      // §8: bound request size; reject oversized bodies.
      if (size > 1_000_000) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(null);
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve(null);
      }
    });
    req.on("error", reject);
  });
}

/** Send a canonical-JSON response with the mandatory vcp-version header. */
function sendJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
  version = VCP_VERSION,
  capabilityHash?: string,
): void {
  const payload = canonicalJson(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "vcp-version": version,
    ...(capabilityHash ? { "vcp-capability-hash": capabilityHash } : {}),
  });
  res.end(payload);
}
