/**
 * Reaching a server the CUSTOMER runs (MISP, OpenCTI): the one place Argust calls a host a customer typed.
 *
 * adapterFetch (fetch.ts) only ever calls hosts a manifest declares. A self-hosted threat-intelligence platform
 * has no vendor host, so this is the guarded exception, and it is narrow:
 *   - a DNS name only (never an IP literal), with a dot, on port 443, HTTPS with normal certificate checks;
 *   - the name is resolved first and EVERY address must be a public internet address — loopback, private,
 *     link-local (cloud metadata) and reserved ranges are refused;
 *   - the connection is then made to exactly the address that was checked (the lookup is pinned), so a name
 *     that answers differently a moment later (DNS rebinding) cannot move the request inside;
 *   - no redirects are followed, the response is size-capped and timed out.
 * A platform that is only reachable inside the customer's network therefore cannot be connected to hosted Argust.
 */
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { isPublicAddress } from "../blocklist.js";
import { EgressRefused } from "./fetch.js";

export const HOST_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const BLOCKED_SUFFIX = [".local", ".internal", ".localhost", ".lan", ".home", ".corp", ".intranet"];

/** A customer host as configuration: a lower-case public-looking DNS name. Says nothing yet about where it resolves. */
export function validCustomerHost(host: string): boolean {
  const h = host.toLowerCase();
  return HOST_RE.test(h) && isIP(h) === 0 && !BLOCKED_SUFFIX.some((s) => h.endsWith(s)) && h !== "localhost";
}

export interface GuardedResponse { status: number; body: string }
export interface GuardedInit { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal; timeoutMs?: number; maxBytes?: number }

/** Test seam: the resolver and the socket. Production never replaces these. */
export const transport = {
  resolve: async (host: string): Promise<{ address: string; family: number }[]> => dnsLookup(host, { all: true, verbatim: true }),
  send(host: string, address: { address: string; family: number }, path: string, init: GuardedInit): Promise<GuardedResponse> {
    return new Promise((resolve, reject) => {
      const max = init.maxBytes ?? 4 * 1024 * 1024;
      const req = httpsRequest({
        host, servername: host, port: 443, path, method: init.method ?? "GET", headers: init.headers, timeout: init.timeoutMs ?? 15_000, signal: init.signal,
        // Pinned: the socket goes to the address that was vetted, whatever DNS says now.
        lookup: (_h, _o, cb) => (cb as (e: Error | null, a: string, f: number) => void)(null, address.address, address.family),
      }, (res) => {
        const chunks: Buffer[] = []; let size = 0;
        res.on("data", (c: Buffer) => { size += c.length; if (size > max) { req.destroy(new EgressRefused(`response exceeds ${max} bytes`)); return; } chunks.push(c); });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error("timed out")));
      req.on("error", reject);
      req.end(init.body);
    });
  },
};

export async function guardedFetch(host: string, path: string, init: GuardedInit = {}): Promise<GuardedResponse> {
  const h = host.toLowerCase();
  if (!validCustomerHost(h) || !path.startsWith("/")) throw new EgressRefused(`refused egress to ${h}`);
  let addrs: { address: string; family: number }[];
  try { addrs = await transport.resolve(h); } catch { throw new EgressRefused(`${h} does not resolve`); }
  if (!addrs.length || !addrs.every((a) => isPublicAddress(a.address))) throw new EgressRefused(`${h} does not resolve to a public internet address`);
  return transport.send(h, addrs[0]!, path, init);
}
