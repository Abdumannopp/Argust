/**
 * Live executors: the actions Legion can really carry out, and the checks that run AT THE MOMENT it does.
 *
 * Reaching here already means the policy engine and the workspace's protection settings agreed. These
 * executors do not trust that: each one checks the facts again (plan, address, allowlist), because the
 * world may have changed between "queued" and "running" — and each is built so that doing it twice does
 * no more harm than doing it once, or is refused on the second try.
 *
 * Two can be pre-authorised: block an address for a limited time (Wazuh and the dashboard read the same
 * blocklist) and e-mail the administrators. LIVE_ACTION_IDS (policy/catalog.ts) and the CHECK on
 * tenants.protection_auto_actions list those two. Four more act in the customer's own systems through a
 * response connection (isolate/release a host, disable/restore an account); they are never pre-authorised
 * (RESPONSE_LIVE_ACTION_IDS). Anything else stays simulation-only (actions/simulate.ts).
 */
import { EXECUTABLE_ACTION_IDS } from "../policy/catalog.js";
import { queryAll } from "../db/pool.js";
import * as box from "../secret-box.js";
import { responseAdapter, responseKinds } from "../integrations/registry.js";
import { ResponseRefused, type ResponseAction } from "../integrations/response.js";
import { scrubError } from "../integrations/scrub.js";
import * as blocklist from "../blocklist.js";
import { allows, resolvePlan } from "../plan-limits.js";
import { transaction } from "../db/pool.js";
import { enqueueProtectionNotice } from "../protection-notify.js";
import * as store from "../store.js";

/** The executor looked again and declined. The action ends `failed` with this reason; nothing was done. */
export class LiveRefused extends Error {
  constructor(readonly why: "plan" | "not_public" | "allowlisted" | "full" | "no_recipients" | "no_connector" | "declined", message: string) { super(message); }
}

export type LiveResult = Record<string, unknown> & { did: string };
type Executor = (tenantId: string, input: Record<string, unknown>, ctx: { actionId: string; reason: string | null }) => Promise<LiveResult>;

const EXECUTORS: Record<string, Executor> = {
  "ip.block": async (tenantId, input, ctx) => {
    const ip = String(input.ip);
    const minutes = Number(input.minutes);
    // Automatic protection is a plan feature; a workspace that moved to a smaller plan keeps detection only.
    if (!allows(await resolvePlan(tenantId), "autoBlocking")) throw new LiveRefused("plan", "The plan no longer includes automatic blocking");
    if (!blocklist.isPublicAddress(ip)) throw new LiveRefused("not_public", "Not a public internet address: it is never blocked");
    const settings = await blocklist.getSettings(tenantId);
    if (blocklist.isAllowlisted(settings.allowlist, ip)) throw new LiveRefused("allowlisted", "The address is on the workspace allowlist");
    try {
      const { block, created } = await blocklist.addBlock(tenantId, ip, {
        minutes, userId: null, campaignId: typeof input.campaign_id === "string" ? input.campaign_id : null,
        reason: `Protection (${ctx.actionId.slice(0, 8)}): ${String(input.reason ?? ctx.reason ?? "blocked").slice(0, 400)}`,
      });
      await store.audit({
        tenant_id: tenantId, user_id: null, user_email: null, action: "security.auto_block", resource_type: "ip", resource_id: ip,
        detail: `protection, action ${ctx.actionId}, ${minutes} min`, ip_address: null,
      });
      return { did: created ? "block" : "extend_block", ip, minutes, blocked_until: block.expires_at };
    } catch (e) {
      if (e instanceof blocklist.BlockError) throw new LiveRefused("full", e.message);
      throw e;
    }
  },

  "notify.admins": async (tenantId, input, ctx) => {
    const subject = String(input.subject);
    const queued = await transaction((client) => enqueueProtectionNotice(client, tenantId, `notify:${ctx.actionId}`, {
      kind: "notice", title: subject, facts: [["Alert", String(input.alert_id ?? "—")], ["Sent by", "Legion (protection)"]],
      path: input.alert_id ? `/incident/${encodeURIComponent(String(input.alert_id))}` : "/",
    }));
    // dedupe_key makes a repeat queue nothing, so "0" after a retry is fine; with no mail server it is not "sent".
    return { did: "email_administrators", queued };
  },
};

/**
 * Response in the customer's own system. Reaching here means people approved this exact action (the database
 * refuses a critical action without an approval, and the policy never pre-authorises these). The connector is the
 * workspace's own response connection for that system; with none, or more than one, nothing is done.
 */
async function respondThrough(tenantId: string, action: ResponseAction, target: string, system: string | null, ctx: { actionId: string }): Promise<LiveResult> {
  const kinds = responseKinds().filter((k) => { const a = responseAdapter(k)!; return a.actions.includes(action) && (system === null || a.system === system); });
  const conns = kinds.length ? await queryAll<{ id: string; tenant_id: string; kind: string; name: string; config: Record<string, unknown> | null; secrets_enc: string | null }>(
    "SELECT id, tenant_id, kind, name, config, secrets_enc FROM integration_connections WHERE tenant_id = $1 AND status = 'active' AND kind = ANY($2::text[]) ORDER BY created_at LIMIT 2", [tenantId, kinds]) : [];
  if (!conns.length) throw new LiveRefused("no_connector", "No response connection for this is set up in the workspace (Connect page)");
  if (conns.length > 1) throw new LiveRefused("no_connector", "More than one response connection could do this; Legion does not choose between them");
  const c = conns[0]!;
  if (c.tenant_id !== tenantId) throw new LiveRefused("no_connector", "No response connection for this workspace");
  const adapter = responseAdapter(c.kind)!;
  let secrets: Record<string, string> = {};
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45_000);
  try {
    const opened = c.secrets_enc ? box.open(c.secrets_enc, "integration-secret", `integration:${tenantId}:${c.id}`) : "{}";
    if (opened === null) throw new Error("stored credentials cannot be decrypted with the current keyring");
    secrets = JSON.parse(opened) as Record<string, string>;
    const done = await adapter.respond({ id: c.id, tenantId, config: c.config ?? {}, secrets }, action, target, controller.signal);
    await queryAll("UPDATE integration_connections SET failures = 0, last_success_at = now(), last_error = NULL, updated_at = now() WHERE id = $1 AND tenant_id = $2", [c.id, tenantId]).catch(() => { /* health is best effort */ });
    await store.audit({
      tenant_id: tenantId, user_id: null, user_email: null, action: `security.response.${action}`, resource_type: action.startsWith("host.") ? "host" : "account", resource_id: target.slice(0, 200),
      detail: `through ${adapter.manifest.displayName} (${c.name}), action ${ctx.actionId}`, ip_address: null,
    });
    return { did: done.did, target: done.target, through: adapter.manifest.displayName, connection: c.name };
  } catch (e) {
    if (e instanceof ResponseRefused) throw new LiveRefused("declined", e.message);
    const detail = scrubError(e instanceof Error ? e.message : "response failed", secrets);
    await queryAll("UPDATE integration_connections SET failures = failures + 1, last_error = $3, updated_at = now() WHERE id = $1 AND tenant_id = $2", [c.id, tenantId, detail]).catch(() => { /* health is best effort */ });
    throw new Error(detail);
  } finally { clearTimeout(timer); }
}

EXECUTORS["host.isolate"] = (t, i, ctx) => respondThrough(t, "host.isolate", String(i.host), null, ctx);
EXECUTORS["host.release"] = (t, i, ctx) => respondThrough(t, "host.release", String(i.host), null, ctx);
EXECUTORS["account.disable"] = (t, i, ctx) => respondThrough(t, "account.disable", String(i.account), String(i.system), ctx);
EXECUTORS["account.enable"] = (t, i, ctx) => respondThrough(t, "account.enable", String(i.account), String(i.system), ctx);

export const hasLiveExecutor = (actionId: string): boolean => actionId in EXECUTORS;

export async function executeLive(tenantId: string, actionId: string, input: Record<string, unknown>, ctx: { actionId: string; reason: string | null }): Promise<LiveResult> {
  const fn = EXECUTORS[actionId];
  if (!fn) throw new Error(`no live executor for ${actionId}`);
  return fn(tenantId, input, ctx);
}

// Kept in step with policy/catalog.ts and the database CHECK (protection.test.ts proves it).
export const EXECUTOR_IDS: readonly string[] = Object.keys(EXECUTORS);
if (EXECUTOR_IDS.length !== EXECUTABLE_ACTION_IDS.length || !EXECUTOR_IDS.every((id) => EXECUTABLE_ACTION_IDS.includes(id))) {
  throw new Error("The catalog's executable actions and the live executors disagree");
}
