"use client";

import { useCallback, useEffect, useState } from "react";
import { Loader2, Undo2 } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import { ExecutedAction, getExecutedActions, proposeResponse } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { timeAgo } from "@/lib/i18n/format";

import { OPPOSITE, stillInEffect } from "@/lib/response-undo";

/** Releasing a host or restoring an account that Argust isolated or suspended. Administrators only. */
export default function ResponseUndo({ isAdmin }: { isAdmin: boolean }) {
  const { t, locale } = useLanguage();
  const m = t.protection.undo;
  const [list, setList] = useState<ExecutedAction[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setList(stillInEffect((await getExecutedActions()).actions)); } catch { setList([]); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function undo(a: ExecutedAction) {
    const host = a.action_id === "host.isolate";
    const name = String(host ? a.input.host : a.input.account);
    if (!window.confirm(host ? m.confirmRelease(name) : m.confirmRestore(name))) return;
    setBusy(a.id); setError(null); setNote(null);
    try {
      // The same host or account, through the same system the original action named.
      const input = host ? { host: a.input.host, ...(a.input.via ? { via: a.input.via } : {}) } : { account: a.input.account, system: a.input.system };
      const r = await proposeResponse(OPPOSITE[a.action_id as keyof typeof OPPOSITE], input, m.reason(a.id));
      const s = r.action.status;
      setNote(s === "executed" ? m.done : s === "failed" ? m.failed(r.action.error ?? "") : m.other(s));
      await load();
    } catch (err) { setError(err); } finally { setBusy(null); }
  }

  if (list === null || (list.length === 0 && !note)) return null;
  return (
    <section className="lg-surface p-4 mt-4" data-testid="response-undo">
      <h2 className="text-ink text-sm font-semibold">{m.title}</h2>
      <p className="text-ink-muted text-xs mt-1">{m.intro}</p>
      <ErrorNotice error={error} />
      {note && <p className="text-ink-soft text-sm mt-2" data-testid="response-undo-note">{note}</p>}
      {list.length === 0 && <p className="text-ink-faint text-xs mt-2">{m.empty}</p>}
      <ul className="mt-3 space-y-2">
        {list.map((a) => {
          const host = a.action_id === "host.isolate";
          return (
            <li key={a.id} className="lg-surface-soft px-3 py-2.5 flex flex-wrap items-center gap-2">
              <p className="text-ink text-sm min-w-0 flex-1 break-all">
                {host ? m.host(String(a.input.host)) : m.account(String(a.input.account))}
                <span className="text-ink-faint text-[11px]"> · {m.since(timeAgo(a.created_at, locale))}</span>
              </p>
              {isAdmin && (
                <button disabled={busy === a.id} onClick={() => undo(a)} className="lg-button-secondary" data-testid="response-undo-button">
                  {busy === a.id ? <Loader2 size={13} className="animate-spin" /> : <Undo2 size={13} />}
                  {host ? m.release : m.restore}
                </button>
              )}
            </li>
          );
        })}
      </ul>
      <p className="text-ink-faint text-[11px] mt-2">{m.note}</p>
    </section>
  );
}
