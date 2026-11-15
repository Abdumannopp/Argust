"use client";

import { useState } from "react";
import { Loader2, Radar } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import { checkAlertReputation, IntelReport } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { palette } from "@/lib/theme";

const CHIP: Record<IntelReport["results"][number]["verdict"], string> = {
  malicious: "lg-status lg-status-critical", suspicious: "lg-status lg-status-high", benign: "lg-status lg-status-healthy", unknown: "lg-status lg-status-brand",
};

/**
 * What the workspace's threat-intelligence sources know about an alert's source address. Asked only on a click:
 * the address is sent to those sources, so the page never does it by itself. The sources' text is shown as plain text.
 */
export default function ThreatIntelCard({ alertId, hasSourceIp }: { alertId: string; hasSourceIp: boolean }) {
  const { t } = useLanguage();
  const m = t.incident.intel;
  const [report, setReport] = useState<IntelReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function check() {
    setBusy(true); setError(null);
    try { setReport(await checkAlertReputation(alertId)); } catch (err) { setError(err); } finally { setBusy(false); }
  }
  const isPrivate = report?.skipped.some((s) => s.reason === "private_address");

  return (
    <section className="mt-4 lg-surface p-4" data-testid="threat-intel">
      <div className="flex items-center gap-2 mb-1">
        <Radar size={14} color={palette.info} />
        <h2 className="text-ink text-sm font-medium">{m.title}</h2>
      </div>
      <p className="text-ink-muted text-xs mb-3">{m.intro}</p>
      <ErrorNotice error={error} />
      {!hasSourceIp ? (
        <p className="text-ink-faint text-xs">{m.noIndicator}</p>
      ) : (
        <>
          {report && (
            <div className="mb-3 space-y-2" data-testid="threat-intel-result">
              {report.status === "not_configured" && <p className="text-ink-muted text-sm">{m.notConfigured}</p>}
              {report.status === "unavailable" && <p className="text-warning text-sm">{m.unavailable}</p>}
              {report.status === "no_indicator" && <p className="text-ink-muted text-sm">{m.noIndicator}</p>}
              {report.status === "ok" && isPrivate && <p className="text-ink-muted text-sm">{m.privateAddress}</p>}
              {report.status === "ok" && !isPrivate && report.results.length === 0 && <p className="text-ink-muted text-sm">{m.nothingKnown}</p>}
              {report.results.map((r) => (
                <div key={`${r.source}:${r.indicator}`} className="lg-surface-soft px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-ink text-sm font-medium">{r.source}</span>
                    <span className={CHIP[r.verdict]}>{m.verdict[r.verdict]}</span>
                    {r.confidence !== null && <span className="text-ink-faint text-[11px]">{m.confidence(r.confidence)}</span>}
                    <span className="text-ink-faint text-[11px] font-mono">{r.indicator}</span>
                  </div>
                  {r.notes && <p className="text-ink-muted text-xs mt-1 break-words">{r.notes}</p>}
                </div>
              ))}
              {report.status === "ok" && report.sources.filter((s) => !s.ok).map((s) => <p key={s.name} className="text-warning text-xs">{m.failed(s.name)}</p>)}
              {report.results.length > 0 && <p className="text-ink-faint text-[11px]">{m.caution}</p>}
            </div>
          )}
          <button onClick={check} disabled={busy} className="lg-button-secondary" data-testid="threat-intel-check">
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Radar size={13} />}
            {busy ? m.checking : report ? m.again : m.check}
          </button>
        </>
      )}
    </section>
  );
}
