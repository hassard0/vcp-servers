import { canonicalJson } from "@vcp/sdk";
import { VCP_VERSION } from "./gateway-server.ts";

/**
 * A tiny VCP-HTTP client (fetch-based) used by the demo and tests. It always
 * sends the mandatory `vcp-version` and `vcp-capability-hash` headers on
 * decision endpoints.
 */
export class VcpClient {
  #base: string;
  #capabilityHash?: string;

  constructor(baseUrl: string) {
    this.#base = baseUrl.replace(/\/$/, "");
  }

  async discovery(): Promise<Record<string, unknown>> {
    return this.getJson("/.well-known/vcp-provider");
  }

  /** Fetch the capability index and remember its hash for later headers. */
  async capabilities(): Promise<{ capabilities: Array<Record<string, unknown>> }> {
    const res = await fetch(`${this.#base}/vcp/capabilities`, {
      headers: { "vcp-version": VCP_VERSION },
    });
    this.#capabilityHash = res.headers.get("vcp-capability-hash") ?? undefined;
    return (await res.json()) as { capabilities: Array<Record<string, unknown>> };
  }

  get capabilityHash(): string | undefined {
    return this.#capabilityHash;
  }

  /** Override the capability hash (e.g. to simulate a stale/wrong client). */
  setCapabilityHash(h: string): void {
    this.#capabilityHash = h;
  }

  async plan(plan: unknown): Promise<{ status: number; body: any }> {
    return this.post("/vcp/plan", plan);
  }
  async approve(plan_hash: string): Promise<{ status: number; body: any }> {
    return this.post("/vcp/approve", { plan_hash });
  }
  async apply(plan_hash: string): Promise<{ status: number; body: any }> {
    return this.post("/vcp/apply", { plan_hash });
  }
  async audit(): Promise<{ audit: any[] }> {
    return this.getJson("/vcp/audit") as Promise<{ audit: any[] }>;
  }

  private async getJson(path: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.#base}${path}`, {
      headers: { "vcp-version": VCP_VERSION },
    });
    return (await res.json()) as Record<string, unknown>;
  }

  private async post(path: string, body: unknown): Promise<{ status: number; body: any }> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "vcp-version": VCP_VERSION,
    };
    if (this.#capabilityHash) headers["vcp-capability-hash"] = this.#capabilityHash;
    const res = await fetch(`${this.#base}${path}`, {
      method: "POST",
      headers,
      body: canonicalJson(body),
    });
    return { status: res.status, body: await res.json() };
  }

  /** Low-level POST with custom headers, for negative tests. */
  async rawPost(
    path: string,
    body: unknown,
    headers: Record<string, string>,
  ): Promise<{ status: number; body: any }> {
    const res = await fetch(`${this.#base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: canonicalJson(body),
    });
    return { status: res.status, body: await res.json() };
  }
}
