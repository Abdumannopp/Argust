"use client";

import { useState } from "react";
import { Loader2, ShieldAlert } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import { proposeResponse } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { palette } from "@/lib/theme";

const ACCOUNT = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{3,190}$/;
type Via = "crowdstrike_response" | "sentinelone_response" | "defender_response" | "cortex_response";
const VIAS: Via[] = ["crowdstrike_response", "sentinelone_response", "defender_response", "cortex_response"];
const HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

/**
 * Asking Legion to act in a connected system for this alert's host or account. It only ASKS: the server decides
 * (administrators only, protection on, a response connection present) and a critical action waits for two other
 * administrators. Nothing here runs anything by itself.
 */
export default function ResponseCard({ alertId, target }: { alertId: string; target: string | null }) {
  const { t } = useLanguage();
  const m = t.incident.respond;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState<string | null>(null);
  const [system, setSystem] = useState<"okta" | "entra">("okta");
  const [via, setVia] = useState<"" | Via>("");
  const account = target && ACCOUNT.test(target) ? target : null;
  const host = target && !account && HOST.test(target) ? target : null;

  async function ask(kind: "host" | "account") {
    if (!window.confirm(kind === "host" ? m.confirmIsolate(host!) : m.confirmSuspend(account!))) return;
    setBusy(true); setError(null); setNote(null);
    try {
      const r = kind === "host"
        ? await proposeResponse("host.isolate", via ? { host, via } : { host }, m.reason(alertId))
        : await proposeResponse("account.disable", { account, system }, m.reason(alertId));
      const s = r.action.status;
      setNote(s === "awaiting_approval" ? m.waiting : s === "executed" ? m.executed : s === "failed" ? m.failed(r.action.error ?? "") : s === "denied" ? m.denied : m.other(s));
    } catch (err) { setError(err); } finally { setBusy(false); }
  }

  return (
    <section className="mt-4 lg-surface p-4" data-testid="response-card">
      <div className="flex items-center gap-2 mb-1">
        <ShieldAlert size={14} color={palette.high} />
        <h2 className="text-ink text-sm font-medium">{m.title}</h2>
      </div>
      <p className="text-ink-muted text-xs mb-3">{m.intro}</p>
      <ErrorNotice error={error} />
      {note && <p className="text-ink-soft text-sm mb-3" data-testid="response-note">{note}</p>}
      {!host && !account ? (
        <p className="text-ink-faint text-xs">{m.nothing}</p>
      ) : (
        <>
          {host && (
            <label className="block text-xs text-ink-muted mb-2">
              {m.via}
              <select value={via} onChange={(e) => setVia(e.target.value as "" | Via)} className="ml-2 rounded-lg border border-line bg-canvas px-2 py-1 text-xs text-ink" data-testid="response-via">
                <option value="">{m.viaAuto}</option>
                {VIAS.map((v) => <option key={v} value={v}>{m.vias[v]}</option>)}
              </select>
            </label>
          )}
          {account && (
            <label className="block text-xs text-ink-muted mb-2">
              {m.system}
              <select value={system} onChange={(e) => setSystem(e.target.value as "okta" | "entra")} className="ml-2 rounded-lg border border-line bg-canvas px-2 py-1 text-xs text-ink" data-testid="response-system">
                <option value="okta">{m.systems.okta}</option>
                <option value="entra">{m.systems.entra}</option>
              </select>
            </label>
          )}
          <button onClick={() => ask(host ? "host" : "account")} disabled={busy} className="lg-button-secondary" data-testid="response-ask">
            {busy ? <Loader2 size={13} className="animate-spin" /> : <ShieldAlert size={13} />}
            {host ? m.isolate(host) : m.suspend(account!)}
          </button>
          <p className="text-ink-faint text-[11px] mt-2">{m.undoNote}</p>
        </>
      )}
    </section>
  );
}
