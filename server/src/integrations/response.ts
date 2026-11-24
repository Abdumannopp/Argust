/**
 * Response connectors: the systems Argust can ACT in — isolate a host through the EDR, suspend an account in the
 * identity provider. This is the only place an adapter changes something in a customer's environment.
 *
 * What keeps that safe:
 *  - A response connection is a SEPARATE connection with its own credential (kind "…_response"). The read-only
 *    connection that brings alerts in can never act: its credential has no such scope and its adapter no such code.
 *  - Nothing here decides anything. Only the action engine calls `respond`, for a request the policy engine
 *    classified as critical (isolate, suspend) — which the database refuses to run without people's approval —
 *    in a workspace whose administrator turned protection on. These actions can never be pre-authorised.
 *  - Every action has its opposite (isolate ↔ release, suspend ↔ restore), and each connection has a list of
 *    hosts or accounts that must never be touched.
 *  - The target is matched exactly. A host name that matches no device, or more than one, is refused: Argust
 *    does not guess which machine to cut off.
 *  - Hosts are fixed per vendor (adapterFetch); a customer cannot point a response at another address.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { CROWDSTRIKE_CLOUDS } from "./crowdstrike.js";
import { graphToken } from "./entra.js";
import { cortexHeaders } from "./cortex.js";
import type { ConnectionContext, IntegrationManifest } from "./types.js";

export const RESPONSE_ACTIONS = ["host.isolate", "host.release", "account.disable", "account.enable"] as const;
export type ResponseAction = (typeof RESPONSE_ACTIONS)[number];

/** The connector looked and declined: nothing was done (no such device, protected target, ambiguous match). */
export class ResponseRefused extends Error {}

export interface ResponseResult { did: string; target: string; ref?: string }

export interface ResponseAdapter {
  manifest: IntegrationManifest & { inbound: null; plane: "tool"; outbound: ["respond"] };
  configSchema: z.ZodType<Record<string, unknown>>;
  secretFields: string[];
  /** What it can do, and in which identity system (account actions name one). */
  actions: readonly ResponseAction[];
  system?: "okta" | "entra" | "google";
  respond(conn: ConnectionContext, action: ResponseAction, target: string, signal: AbortSignal): Promise<ResponseResult>;
}

const HOSTNAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const ACCOUNT = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{3,190}$/;
/** Names that must never be acted on, as the administrator listed them (exact, case-insensitive). */
const neverList = z.array(z.string().trim().min(1).max(200)).max(200).default([]);
const isProtected = (conn: ConnectionContext, target: string) =>
  (Array.isArray(conn.config.never) ? conn.config.never : []).some((n) => String(n).toLowerCase() === target.toLowerCase());

// --- CrowdStrike Falcon: network containment ---------------------------------

async function falconToken(conn: ConnectionContext, host: string, signal: AbortSignal): Promise<string> {
  const res = await adapterFetch(crowdstrikeResponseAdapter.manifest, `https://${host}/oauth2/token`, {
    method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ client_id: String(conn.config.client_id), client_secret: conn.secrets.client_secret ?? "" }).toString(),
  });
  if (res.status !== 201 && res.status !== 200) throw new Error(`CrowdStrike sign-in failed (${res.status}); check the cloud, client id and secret`);
  let token = "";
  try { token = String((JSON.parse(res.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
  if (!token) throw new Error("CrowdStrike sign-in returned no token");
  return token;
}

export const crowdstrikeResponseAdapter: ResponseAdapter = {
  manifest: {
    kind: "crowdstrike_response", displayName: "CrowdStrike Falcon — response", vendor: "CrowdStrike", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: Object.values(CROWDSTRIKE_CLOUDS),
    summary: "Isolates a host from the network (Falcon network containment) and releases it again. Only for an action people approved; never automatic.",
    auth: "A separate Falcon API client with the scopes Hosts: Read and Hosts: Write only; the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({
    cloud: z.enum(Object.keys(CROWDSTRIKE_CLOUDS) as [keyof typeof CROWDSTRIKE_CLOUDS, ...(keyof typeof CROWDSTRIKE_CLOUDS)[]]).default("us-1"),
    client_id: z.string().regex(/^[a-f0-9]{32}$/i, "Falcon API client id (32 hex characters)"),
    never: neverList,
  }),
  secretFields: ["client_secret"],
  actions: ["host.isolate", "host.release"],
  async respond(conn, action, target, signal) {
    if (action !== "host.isolate" && action !== "host.release") throw new ResponseRefused("CrowdStrike cannot do that");
    // The name goes into Falcon's filter language: only a plain host name is ever put there.
    if (!HOSTNAME.test(target)) throw new ResponseRefused("Not a host name Argust can look up exactly");
    if (isProtected(conn, target)) throw new ResponseRefused("This host is on the connection's never-touch list");
    const host = CROWDSTRIKE_CLOUDS[String(conn.config.cloud ?? "us-1") as keyof typeof CROWDSTRIKE_CLOUDS] ?? CROWDSTRIKE_CLOUDS["us-1"];
    const m = crowdstrikeResponseAdapter.manifest;
    const auth = { authorization: `Bearer ${await falconToken(conn, host, signal)}`, accept: "application/json" };
    const found = await adapterFetch(m, `https://${host}/devices/queries/devices/v1?${new URLSearchParams({ filter: `hostname:'${target}'`, limit: "5" })}`, { method: "GET", signal, timeoutMs: 20_000, maxBytes: 256 * 1024, headers: auth });
    if (found.status === 401 || found.status === 403) throw new Error(`CrowdStrike refused the lookup (${found.status}); the API client needs Hosts: Read`);
    if (found.status !== 200) throw new Error(`CrowdStrike answered ${found.status} (device lookup)`);
    let ids: string[] = [];
    try { const r = (JSON.parse(found.body) as { resources?: unknown }).resources; ids = (Array.isArray(r) ? r : []).filter((x): x is string => typeof x === "string" && /^[a-f0-9]{32}$/i.test(x)); } catch { throw new Error("CrowdStrike returned invalid JSON"); }
    if (ids.length === 0) throw new ResponseRefused(`CrowdStrike knows no device named ${target}`);
    if (ids.length > 1) throw new ResponseRefused(`${ids.length} devices are named ${target}; Argust does not guess which one`);
    const name = action === "host.isolate" ? "contain" : "lift_containment";
    const res = await adapterFetch(m, `https://${host}/devices/entities/devices-actions/v2?action_name=${name}`, {
      method: "POST", signal, timeoutMs: 30_000, maxBytes: 256 * 1024, headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify({ ids }),
    });
    if (res.status === 401 || res.status === 403) throw new Error(`CrowdStrike refused the action (${res.status}); the API client needs Hosts: Write`);
    if (res.status !== 202 && res.status !== 200) throw new Error(`CrowdStrike answered ${res.status} (${name})`);
    return { did: action === "host.isolate" ? "isolate_host" : "release_host", target, ref: ids[0] };
  },
};

// --- Okta: suspend an account -------------------------------------------------

const OKTA_DOMAIN = /^[a-z0-9][a-z0-9-]{0,62}\.(?:okta|oktapreview|okta-emea)\.com$/;

export const oktaResponseAdapter: ResponseAdapter = {
  manifest: {
    kind: "okta_response", displayName: "Okta — response", vendor: "Okta", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: ["*.okta.com", "*.oktapreview.com", "*.okta-emea.com"],
    summary: "Suspends a user account (the person cannot sign in; nothing is deleted) and restores it again. Only for an action people approved; never automatic.",
    auth: "A separate API token of an administrator whose role may suspend users (for example a custom role with only that permission); sealed per connection.",
  },
  configSchema: z.strictObject({ domain: z.string().regex(OKTA_DOMAIN, "Your Okta domain, for example acme.okta.com"), never: neverList }),
  secretFields: ["api_token"],
  actions: ["account.disable", "account.enable"],
  system: "okta",
  async respond(conn, action, target, signal) {
    if (action !== "account.disable" && action !== "account.enable") throw new ResponseRefused("Okta cannot do that");
    if (!ACCOUNT.test(target)) throw new ResponseRefused("Not an account name (the sign-in e-mail address is needed)");
    if (isProtected(conn, target)) throw new ResponseRefused("This account is on the connection's never-touch list");
    const step = action === "account.disable" ? "suspend" : "unsuspend";
    const res = await adapterFetch(oktaResponseAdapter.manifest, `https://${String(conn.config.domain)}/api/v1/users/${encodeURIComponent(target)}/lifecycle/${step}`, {
      method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { authorization: `SSWS ${conn.secrets.api_token ?? ""}`, accept: "application/json", "content-type": "application/json" },
    });
    if (res.status === 404) throw new ResponseRefused(`Okta knows no account ${target}`);
    if (res.status === 401 || res.status === 403) throw new Error(`Okta refused the action (${res.status}); the token's administrator may not ${step} users`);
    // Okta answers 400 when the account is not in a state the step applies to (already suspended, deactivated…).
    if (res.status === 400) throw new ResponseRefused(`Okta did not ${step} ${target}: the account is not in a state that allows it (already done, or deactivated)`);
    if (res.status !== 200) throw new Error(`Okta answered ${res.status} (${step})`);
    return { did: action === "account.disable" ? "suspend_account" : "restore_account", target };
  },
};

// --- Microsoft Entra ID: block sign-in for an account -------------------------------

export const entraResponseAdapter: ResponseAdapter = {
  manifest: {
    kind: "entra_response", displayName: "Microsoft Entra ID — response", vendor: "Microsoft", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: ["graph.microsoft.com", "login.microsoftonline.com"],
    summary: "Blocks sign-in for a user account (accountEnabled = false; nothing is deleted) and allows it again. Only for an action people approved; never automatic.",
    auth: "A separate Entra app registration with the application permission User.EnableDisableAccount.All only; the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({ directory_id: z.string().uuid("Directory (tenant) id, a GUID"), client_id: z.string().uuid("Application (client) id, a GUID"), never: neverList }),
  secretFields: ["client_secret"],
  actions: ["account.disable", "account.enable"],
  system: "entra",
  async respond(conn, action, target, signal) {
    if (action !== "account.disable" && action !== "account.enable") throw new ResponseRefused("Entra ID cannot do that");
    if (!ACCOUNT.test(target)) throw new ResponseRefused("Not an account name (the user principal name is needed)");
    if (isProtected(conn, target)) throw new ResponseRefused("This account is on the connection's never-touch list");
    const m = entraResponseAdapter.manifest;
    const token = await graphToken(m, String(conn.config.directory_id), String(conn.config.client_id), conn.secrets.client_secret ?? "", signal);
    const res = await adapterFetch(m, `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(target)}`, {
      method: "PATCH", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ accountEnabled: action === "account.enable" }),
    });
    if (res.status === 404) throw new ResponseRefused(`Entra ID knows no account ${target}`);
    if (res.status === 401 || res.status === 403) throw new Error(`Entra ID refused the action (${res.status}); the app needs User.EnableDisableAccount.All with admin consent, and cannot change an administrator's account`);
    if (res.status !== 204 && res.status !== 200) throw new Error(`Entra ID answered ${res.status}`);
    return { did: action === "account.disable" ? "block_sign_in" : "allow_sign_in", target };
  },
};

// --- SentinelOne: disconnect from network -----------------------------------------

const S1_CONSOLE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export const sentineloneResponseAdapter: ResponseAdapter = {
  manifest: {
    kind: "sentinelone_response", displayName: "SentinelOne — response", vendor: "SentinelOne", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: ["*.sentinelone.net"],
    summary: "Disconnects an endpoint from the network (it still talks to SentinelOne) and reconnects it. Only for an action people approved; never automatic.",
    auth: "A separate API token of a service user whose role may only view endpoints and disconnect/reconnect them; sealed per connection.",
  },
  configSchema: z.strictObject({ console: z.string().regex(S1_CONSOLE, "Your console name: acme for acme.sentinelone.net"), never: neverList }),
  secretFields: ["api_token"],
  actions: ["host.isolate", "host.release"],
  async respond(conn, action, target, signal) {
    if (action !== "host.isolate" && action !== "host.release") throw new ResponseRefused("SentinelOne cannot do that");
    if (!HOSTNAME.test(target)) throw new ResponseRefused("Not a host name Argust can look up exactly");
    if (isProtected(conn, target)) throw new ResponseRefused("This host is on the connection's never-touch list");
    const m = sentineloneResponseAdapter.manifest;
    const base = `https://${String(conn.config.console)}.sentinelone.net/web/api/v2.1`;
    const headers = { authorization: `ApiToken ${conn.secrets.api_token ?? ""}`, accept: "application/json", "content-type": "application/json" };
    const found = await adapterFetch(m, `${base}/agents?${new URLSearchParams({ computerName: target, limit: "5" })}`, { method: "GET", signal, timeoutMs: 20_000, maxBytes: 1024 * 1024, headers });
    if (found.status === 401 || found.status === 403) throw new Error(`SentinelOne refused the lookup (${found.status}); check the token and its role`);
    if (found.status !== 200) throw new Error(`SentinelOne answered ${found.status} (endpoint lookup)`);
    let ids: string[] = [];
    try {
      const d = (JSON.parse(found.body) as { data?: unknown }).data;
      // The API may match more loosely than asked: only an endpoint whose name is exactly this one counts.
      ids = (Array.isArray(d) ? d : []).filter((a): a is { id: string; computerName: string } => !!a && typeof a === "object" && typeof (a as { id?: unknown }).id === "string" && /^\d{5,25}$/.test((a as { id: string }).id) && String((a as { computerName?: unknown }).computerName ?? "").toLowerCase() === target.toLowerCase()).map((a) => a.id);
    } catch { throw new Error("SentinelOne returned invalid JSON"); }
    if (ids.length === 0) throw new ResponseRefused(`SentinelOne knows no endpoint named ${target}`);
    if (ids.length > 1) throw new ResponseRefused(`${ids.length} endpoints are named ${target}; Argust does not guess which one`);
    const step = action === "host.isolate" ? "disconnect" : "connect";
    const res = await adapterFetch(m, `${base}/agents/actions/${step}`, { method: "POST", signal, timeoutMs: 30_000, maxBytes: 256 * 1024, headers, body: JSON.stringify({ filter: { ids } }) });
    if (res.status === 401 || res.status === 403) throw new Error(`SentinelOne refused the action (${res.status}); the token's role may not ${step} endpoints`);
    if (res.status !== 200) throw new Error(`SentinelOne answered ${res.status} (${step})`);
    let affected = 0;
    try { affected = Number((JSON.parse(res.body) as { data?: { affected?: unknown } }).data?.affected ?? 0); } catch { /* below */ }
    if (affected !== 1) throw new Error(`SentinelOne did not confirm the ${step} (affected: ${affected})`);
    return { did: action === "host.isolate" ? "isolate_host" : "release_host", target, ref: ids[0] };
  },
};

// --- Microsoft Defender for Endpoint: isolate machine ------------------------------

const MDE = "api.securitycenter.microsoft.com";

export const defenderResponseAdapter: ResponseAdapter = {
  manifest: {
    kind: "defender_response", displayName: "Microsoft Defender for Endpoint — response", vendor: "Microsoft", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: [MDE, "login.microsoftonline.com"],
    summary: "Isolates a device from the network (it still talks to Defender) and releases it. Only for an action people approved; never automatic.",
    auth: "A separate Entra app registration with the WindowsDefenderATP application permissions Machine.Read.All and Machine.Isolate only; the client secret is sealed per connection.",
  },
  configSchema: z.strictObject({ directory_id: z.string().uuid("Directory (tenant) id, a GUID"), client_id: z.string().uuid("Application (client) id, a GUID"), never: neverList }),
  secretFields: ["client_secret"],
  actions: ["host.isolate", "host.release"],
  async respond(conn, action, target, signal) {
    if (action !== "host.isolate" && action !== "host.release") throw new ResponseRefused("Defender for Endpoint cannot do that");
    // The name goes into an OData filter: only a plain host name is ever put there.
    if (!HOSTNAME.test(target)) throw new ResponseRefused("Not a host name Argust can look up exactly");
    if (isProtected(conn, target)) throw new ResponseRefused("This host is on the connection's never-touch list");
    const m = defenderResponseAdapter.manifest;
    const tokenRes = await adapterFetch(m, `https://login.microsoftonline.com/${encodeURIComponent(String(conn.config.directory_id))}/oauth2/v2.0/token`, {
      method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: String(conn.config.client_id), client_secret: conn.secrets.client_secret ?? "", scope: `https://${MDE}/.default`, grant_type: "client_credentials" }).toString(),
    });
    if (tokenRes.status !== 200) throw new Error(`Microsoft sign-in failed (${tokenRes.status}); check the directory id, application id and client secret`);
    let token = "";
    try { token = String((JSON.parse(tokenRes.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
    if (!token) throw new Error("Microsoft sign-in returned no token");
    const headers = { authorization: `Bearer ${token}`, accept: "application/json", "content-type": "application/json" };
    const found = await adapterFetch(m, `https://${MDE}/api/machines?${new URLSearchParams({ $filter: `computerDnsName eq '${target.toLowerCase()}'`, $top: "5" })}`, { method: "GET", signal, timeoutMs: 20_000, maxBytes: 1024 * 1024, headers });
    if (found.status === 401 || found.status === 403) throw new Error(`Defender refused the lookup (${found.status}); the app needs Machine.Read.All with admin consent`);
    if (found.status !== 200) throw new Error(`Defender answered ${found.status} (device lookup)`);
    let ids: string[] = [];
    try {
      const v = (JSON.parse(found.body) as { value?: unknown }).value;
      ids = (Array.isArray(v) ? v : []).filter((d): d is { id: string } => !!d && typeof d === "object" && /^[a-f0-9]{40}$/i.test(String((d as { id?: unknown }).id ?? "")) && String((d as { computerDnsName?: unknown }).computerDnsName ?? "").toLowerCase() === target.toLowerCase()).map((d) => d.id);
    } catch { throw new Error("Defender returned invalid JSON"); }
    if (ids.length === 0) throw new ResponseRefused(`Defender knows no device named ${target} (it matches the full DNS name)`);
    if (ids.length > 1) throw new ResponseRefused(`${ids.length} devices are named ${target}; Argust does not guess which one`);
    const step = action === "host.isolate" ? "isolate" : "unisolate";
    const res = await adapterFetch(m, `https://${MDE}/api/machines/${ids[0]}/${step}`, {
      method: "POST", signal, timeoutMs: 30_000, maxBytes: 256 * 1024, headers,
      body: JSON.stringify(action === "host.isolate" ? { Comment: "Argust: approved response action", IsolationType: "Full" } : { Comment: "Argust: approved release" }),
    });
    if (res.status === 401 || res.status === 403) throw new Error(`Defender refused the action (${res.status}); the app needs Machine.Isolate with admin consent`);
    if (res.status === 400) throw new ResponseRefused(`Defender did not ${step} ${target}: the device is not in a state that allows it (already done, or an action is pending)`);
    if (res.status !== 201 && res.status !== 200) throw new Error(`Defender answered ${res.status} (${step})`);
    return { did: action === "host.isolate" ? "isolate_host" : "release_host", target, ref: ids[0] };
  },
};

// --- Palo Alto Cortex XDR: isolate endpoint ----------------------------------------

const XDR_FQDN = /^api-[a-z0-9][a-z0-9-]{0,62}\.xdr\.[a-z0-9]{2,10}\.paloaltonetworks\.com$/;

export const cortexResponseAdapter: ResponseAdapter = {
  manifest: {
    kind: "cortex_response", displayName: "Palo Alto Cortex XDR — response", vendor: "Palo Alto Networks", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: ["*.xdr.*.paloaltonetworks.com"],
    summary: "Isolates an endpoint from the network (it still talks to Cortex XDR) and releases it. Only for an action people approved; never automatic.",
    auth: "A separate Cortex XDR API key whose role may only view endpoints and isolate/unisolate them (advanced key recommended); sealed per connection.",
  },
  configSchema: z.strictObject({
    api_host: z.string().toLowerCase().regex(XDR_FQDN, "Your Cortex XDR API host, for example api-acme.xdr.us.paloaltonetworks.com"),
    api_key_id: z.string().regex(/^\d{1,10}$/, "The API key ID (a number)"), key_type: z.enum(["advanced", "standard"]).default("advanced"), never: neverList,
  }),
  secretFields: ["api_key"],
  actions: ["host.isolate", "host.release"],
  async respond(conn, action, target, signal) {
    if (action !== "host.isolate" && action !== "host.release") throw new ResponseRefused("Cortex XDR cannot do that");
    if (!HOSTNAME.test(target)) throw new ResponseRefused("Not a host name Argust can look up exactly");
    if (isProtected(conn, target)) throw new ResponseRefused("This host is on the connection's never-touch list");
    const m = cortexResponseAdapter.manifest;
    const base = `https://${String(conn.config.api_host)}/public_api/v1/endpoints`;
    const call = (path: string, request_data: unknown) => adapterFetch(m, `${base}/${path}/`, {
      method: "POST", signal, timeoutMs: 30_000, maxBytes: 1024 * 1024,
      headers: cortexHeaders(String(conn.config.api_key_id), conn.secrets.api_key ?? "", String(conn.config.key_type ?? "advanced")), body: JSON.stringify({ request_data }),
    });
    const found = await call("get_endpoint", { filters: [{ field: "hostname", operator: "in", value: [target] }], search_from: 0, search_to: 5 });
    if (found.status === 401 || found.status === 403) throw new Error(`Cortex XDR refused the lookup (${found.status}); check the key, its ID, its type and its role`);
    if (found.status !== 200) throw new Error(`Cortex XDR answered ${found.status} (endpoint lookup)`);
    let ids: string[] = [];
    try {
      const e = (JSON.parse(found.body) as { reply?: { endpoints?: unknown } }).reply?.endpoints;
      ids = (Array.isArray(e) ? e : []).filter((x): x is { endpoint_id: string } => !!x && typeof x === "object" && /^[A-Za-z0-9-]{8,64}$/.test(String((x as { endpoint_id?: unknown }).endpoint_id ?? "")) && String((x as { endpoint_name?: unknown }).endpoint_name ?? "").toLowerCase() === target.toLowerCase()).map((x) => x.endpoint_id);
    } catch { throw new Error("Cortex XDR returned invalid JSON"); }
    if (ids.length === 0) throw new ResponseRefused(`Cortex XDR knows no endpoint named ${target}`);
    if (ids.length > 1) throw new ResponseRefused(`${ids.length} endpoints are named ${target}; Argust does not guess which one`);
    const step = action === "host.isolate" ? "isolate" : "unisolate";
    const res = await call(step, { endpoint_id: ids[0] });
    if (res.status === 401 || res.status === 403) throw new Error(`Cortex XDR refused the action (${res.status}); the key's role may not ${step} endpoints`);
    if (res.status !== 200) throw new Error(`Cortex XDR answered ${res.status} (${step})`);
    return { did: action === "host.isolate" ? "isolate_host" : "release_host", target, ref: ids[0] };
  },
};

export const RESPONSE_ADAPTERS: readonly ResponseAdapter[] = [crowdstrikeResponseAdapter, sentineloneResponseAdapter, defenderResponseAdapter, cortexResponseAdapter, oktaResponseAdapter, entraResponseAdapter];
/** The EDR response connections a host action can name with "via" (policy/catalog.ts keeps the same list). */
export const HOST_RESPONSE_KINDS = ["crowdstrike_response", "sentinelone_response", "defender_response", "cortex_response"] as const;
