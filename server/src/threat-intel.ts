/**
 * Threat intelligence: asking the workspace's connected sources (VirusTotal, MISP, OpenCTI) what is known about
 * an indicator. Used by Hunter's `threat_intelligence` skill and by the "Check reputation" button on an alert.
 *
 * Rules that hold whatever the source:
 *  - Only on demand. Argust never sends indicators to a third party by itself; a person or an agent asks.
 *  - Only what may leave: a private or reserved address is never sent anywhere (it means nothing outside and
 *    would tell a third party about the inside of the network); a source is sent only the types it supports.
 *  - No source, no opinion. An indicator nobody has information on is absent from the result — never guessed.
 *  - A source's text is untrusted data. It is length-bounded here and shown, never obeyed.
 *  - Answers are remembered for a while per workspace and source (vendor quotas; the same address in ten
 *    alerts is one lookup). The memory is per instance and bounded; it holds no secrets.
 *  - A failing source does not fail the lookup: the others still answer, and the connection's health shows it.
 */
import { isIP } from "node:net";
import { isPublicAddress } from "./blocklist.js";
import { query, queryAll } from "./db/pool.js";
import * as box from "./secret-box.js";
import { intelAdapter, intelKinds } from "./integrations/registry.js";
import { scrubError } from "./integrations/scrub.js";
import type { IntelAnswer, IntelIndicator, IntelIndicatorType } from "./integrations/types.js";

const TTL_MS = 12 * 3600_000;
const MAX_CACHE = 5000;
const FAILURES_BEFORE_ERROR = 10;
const CALL_TIMEOUT_MS = 45_000;
const sealContext = (id: string, tenantId: string) => `integration:${tenantId}:${id}`;

export interface IntelResult extends IntelAnswer { source: string }
export interface IntelReport {
  /** ok: at least one source was asked. not_configured: the workspace has none. unavailable: every source failed. */
  status: "ok" | "not_configured" | "unavailable";
  sources: { name: string; kind: string; ok: boolean }[];
  results: IntelResult[];
  /** Indicators that were not sent anywhere, and why. */
  skipped: { value: string; reason: "private_address" | "invalid" | "unsupported" }[];
}

const cache = new Map<string, { at: number; answer: IntelAnswer | null }>();
const cacheKey = (tenantId: string, connId: string, i: IntelIndicator) => `${tenantId}|${connId}|${i.type}|${i.value}`;
function remember(key: string, answer: IntelAnswer | null): void {
  if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value as string);
  cache.set(key, { at: Date.now(), answer });
}
/** Test hook. */
export function clearIntelCache(): void { cache.clear(); }

const DOMAIN = /^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const HASH = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const EMAIL = /^[^\s@<>"]{1,64}@[a-z0-9.-]{3,253}$/i;
const CVE = /^CVE-\d{4}-\d{4,7}$/i;

/** What may be sent out, in a canonical form; or why not. */
export function vetIndicator(i: { type: IntelIndicatorType; value: string }): { ok: IntelIndicator } | { skip: "private_address" | "invalid" } {
  const value = String(i.value ?? "").trim();
  if (!value || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) return { skip: "invalid" };
  switch (i.type) {
    case "ip": return isIP(value) === 0 ? { skip: "invalid" } : isPublicAddress(value) ? { ok: { type: "ip", value } } : { skip: "private_address" };
    case "domain": return DOMAIN.test(value) && isIP(value) === 0 ? { ok: { type: "domain", value: value.toLowerCase() } } : { skip: "invalid" };
    case "hash": return HASH.test(value) ? { ok: { type: "hash", value: value.toLowerCase() } } : { skip: "invalid" };
    case "email": return EMAIL.test(value) ? { ok: { type: "email", value: value.toLowerCase() } } : { skip: "invalid" };
    case "cve": return CVE.test(value) ? { ok: { type: "cve", value: value.toUpperCase() } } : { skip: "invalid" };
    case "url": {
      try {
        const u = new URL(value);
        if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) return { skip: "invalid" };
        // A URL on an internal address stays inside, like the address itself.
        if (isIP(u.hostname.replace(/^\[|\]$/g, "")) !== 0 && !isPublicAddress(u.hostname.replace(/^\[|\]$/g, ""))) return { skip: "private_address" };
        return { ok: { type: "url", value } };
      } catch { return { skip: "invalid" }; }
    }
    default: return { skip: "invalid" };
  }
}

export async function hasIntelSource(tenantId: string): Promise<boolean> {
  const kinds = intelKinds();
  if (!kinds.length) return false;
  return (await queryAll("SELECT 1 FROM integration_connections WHERE tenant_id = $1 AND status = 'active' AND kind = ANY($2::text[]) LIMIT 1", [tenantId, kinds])).length > 0;
}

/** Asks every active threat-intelligence connection of this workspace. Tenant-scoped; never throws for a source's failure. */
export async function lookupIndicators(tenantId: string, asked: { type: IntelIndicatorType; value: string }[]): Promise<IntelReport> {
  const report: IntelReport = { status: "not_configured", sources: [], results: [], skipped: [] };
  const kinds = intelKinds();
  const conns = kinds.length ? await queryAll<{ id: string; tenant_id: string; kind: string; name: string; config: Record<string, unknown> | null; secrets_enc: string | null }>(
    "SELECT id, tenant_id, kind, name, config, secrets_enc FROM integration_connections WHERE tenant_id = $1 AND status = 'active' AND kind = ANY($2::text[]) ORDER BY created_at LIMIT 10", [tenantId, kinds],
  ) : [];
  if (!conns.length) return report;

  // The caller's own spelling of each indicator is what the answer carries back (the canonical form is what is sent).
  const wanted: IntelIndicator[] = []; const seen = new Set<string>(); const spelled = new Map<string, string>();
  for (const a of asked.slice(0, 100)) {
    const v = vetIndicator(a);
    if ("skip" in v) { report.skipped.push({ value: String(a.value).slice(0, 200), reason: v.skip }); continue; }
    const k = `${v.ok.type}:${v.ok.value}`;
    if (!seen.has(k)) { seen.add(k); wanted.push(v.ok); spelled.set(k, String(a.value)); }
  }
  const supportedBySome = new Set<string>();

  for (const c of conns) {
    // A row of another workspace can never be here (the query is tenant-bound); checked again all the same.
    if (c.tenant_id !== tenantId) continue;
    const adapter = intelAdapter(c.kind);
    if (!adapter) continue;
    const mine = wanted.filter((i) => adapter.supports.includes(i.type));
    for (const i of mine) supportedBySome.add(`${i.type}:${i.value}`);
    const answers: IntelAnswer[] = []; const toAsk: IntelIndicator[] = [];
    for (const i of mine) {
      const hit = cache.get(cacheKey(tenantId, c.id, i));
      if (hit && Date.now() - hit.at < TTL_MS) { if (hit.answer) answers.push(hit.answer); } else if (toAsk.length < adapter.maxPerCall) toAsk.push(i);
    }
    let ok = true; let secrets: Record<string, string> = {};
    if (toAsk.length) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), CALL_TIMEOUT_MS);
      try {
        const opened = c.secrets_enc ? box.open(c.secrets_enc, "integration-secret", sealContext(c.id, c.tenant_id)) : "{}";
        if (opened === null) throw new Error("stored credentials cannot be decrypted with the current keyring");
        secrets = JSON.parse(opened) as Record<string, string>;
        const got = await adapter.lookup({ id: c.id, tenantId, config: c.config ?? {}, secrets }, toAsk, controller.signal);
        const askedKeys = new Set(toAsk.map((i) => `${i.type}:${i.value}`));
        // A source may only answer what it was asked; its text is bounded here whatever the adapter did.
        const fresh = got.filter((a) => askedKeys.has(`${a.type}:${a.indicator}`)).map((a) => ({ ...a, notes: a.notes ? a.notes.slice(0, 2000) : null }));
        const answered = new Map(fresh.map((a) => [`${a.type}:${a.indicator}`, a]));
        // "Nothing known" is remembered too, so an unknown address is not asked again for every alert.
        // Indicators after a quota stop were not answered either; they are retried after the same wait.
        for (const i of toAsk) remember(cacheKey(tenantId, c.id, i), answered.get(`${i.type}:${i.value}`) ?? null);
        answers.push(...fresh);
        await query("UPDATE integration_connections SET failures = 0, last_success_at = now(), last_error = NULL, updated_at = now() WHERE id = $1 AND tenant_id = $2", [c.id, tenantId]).catch(() => { /* health is best effort */ });
      } catch (error) {
        ok = false;
        const detail = scrubError(error instanceof Error ? error.message : "lookup failed", secrets);
        await query(
          `UPDATE integration_connections SET failures = failures + 1, last_error = $3, updated_at = now(), status = CASE WHEN failures + 1 >= $4 THEN 'error' ELSE status END WHERE id = $1 AND tenant_id = $2`,
          [c.id, tenantId, detail, FAILURES_BEFORE_ERROR],
        ).catch(() => { /* health is best effort */ });
      } finally { clearTimeout(timer); }
    }
    report.sources.push({ name: c.name, kind: c.kind, ok });
    for (const a of answers) report.results.push({ ...a, indicator: spelled.get(`${a.type}:${a.indicator}`) ?? a.indicator, source: adapter.manifest.displayName });
  }
  for (const i of wanted) if (!supportedBySome.has(`${i.type}:${i.value}`)) report.skipped.push({ value: i.value.slice(0, 200), reason: "unsupported" });
  report.status = report.sources.some((s) => s.ok) ? "ok" : "unavailable";
  return report;
}
