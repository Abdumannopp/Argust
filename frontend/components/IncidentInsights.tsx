"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, Clock, Crosshair, Globe, Link2, ShieldAlert } from "lucide-react";
import { getAlerts, type Alert } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { formatDateTime, timeAgo } from "@/lib/i18n/format";
import { severityColor } from "@/lib/theme";

/**
 * What can be said about an incident from its own alert and the other alerts of this workspace: where it came from and
 * where it went, which MITRE technique it matches, when it happened, and which other alerts share its source or target.
 * Nothing here is invented: a step Argust does not record is not shown.
 */
export default function IncidentInsights({ alert }: { alert: Alert }) {
  const { t, locale } = useLanguage();
  const m = t.incident.insights;
  const [others, setOthers] = useState<Alert[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    setOthers(null); setFailed(false);
    if (!alert.source_ip && !alert.target) { setOthers([]); return; }
    getAlerts().then((all) => { if (live) setOthers(all); }).catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [alert.id, alert.source_ip, alert.target]);

  const related = (others ?? [])
    .filter((a) => a.id !== alert.id && ((alert.source_ip && a.source_ip === alert.source_ip) || (alert.target && a.target === alert.target)))
    .slice(0, 5);
  const technique = alert.mitre_technique?.trim() || null;
  const techniqueId = technique?.match(/T\d{4}/)?.[0] ?? null;
  const techniqueName = techniqueId ? m.techniques[techniqueId] : undefined;
  const happened = alert.occurred_at ?? null;

  return (
    <div className="grid lg:grid-cols-3 gap-4 mt-4" data-testid="incident-insights">
      <section className="lg-surface p-4 min-w-0" aria-labelledby="ii-path">
        <h2 id="ii-path" className="text-ink text-sm font-medium flex items-center gap-2"><Crosshair size={14} />{m.pathTitle}</h2>
        <div className="mt-3 flex items-center gap-2 flex-wrap">
          <div className="lg-surface-soft p-3 min-w-0 flex-1 basis-[120px]">
            <p className="lg-eyebrow flex items-center gap-1"><Globe size={11} />{m.pathFrom}</p>
            <p className="text-ink text-sm font-medium mt-1 break-all">{alert.source_ip ?? m.pathUnknown}</p>
          </div>
          <ArrowRight size={16} className="text-ink-faint shrink-0" aria-hidden />
          <div className="lg-surface-soft p-3 min-w-0 flex-1 basis-[120px]">
            <p className="lg-eyebrow flex items-center gap-1"><Crosshair size={11} />{m.pathTo}</p>
            <p className="text-ink text-sm font-medium mt-1 break-all">{alert.target ?? m.pathUnknown}</p>
          </div>
        </div>
        <p className="text-ink-faint text-[11px] mt-3">{m.pathNote}</p>
      </section>

      <section className="lg-surface p-4 min-w-0" aria-labelledby="ii-mitre">
        <h2 id="ii-mitre" className="text-ink text-sm font-medium flex items-center gap-2"><ShieldAlert size={14} />{m.mitreTitle}</h2>
        {technique ? (
          <div className="lg-surface-soft p-3 mt-3">
            <p className="text-brand-bright text-sm font-semibold">{techniqueId ?? technique}</p>
            <p className="text-ink text-xs mt-0.5 break-words">{techniqueName ?? technique}</p>
          </div>
        ) : (
          <p className="text-ink-faint text-xs mt-3">{m.mitreNone}</p>
        )}
        <h3 className="lg-eyebrow mt-4 flex items-center gap-1"><Clock size={11} />{m.timelineTitle}</h3>
        <ol className="mt-2 space-y-2 border-l border-line pl-3">
          {happened && (
            <li><p className="text-ink text-xs font-medium">{m.happened}</p><p className="text-ink-faint text-[11px]">{formatDateTime(happened, locale)}</p></li>
          )}
          <li><p className="text-ink text-xs font-medium">{m.stored}</p><p className="text-ink-faint text-[11px]">{formatDateTime(alert.created_at, locale)}</p></li>
        </ol>
        <p className="text-ink-faint text-[11px] mt-3">{m.timelineNote}</p>
      </section>

      <section className="lg-surface p-4 min-w-0" aria-labelledby="ii-related">
        <h2 id="ii-related" className="text-ink text-sm font-medium flex items-center gap-2"><Link2 size={14} />{m.relatedTitle}</h2>
        {failed ? (
          <p className="text-ink-faint text-xs mt-3">{m.relatedLoadError}</p>
        ) : others && related.length === 0 ? (
          <p className="text-ink-faint text-xs mt-3">{m.relatedNone}</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {related.map((a) => (
              <li key={a.id} className="lg-surface-soft p-3 flex items-start gap-2 min-w-0">
                <span className="w-2 h-2 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: severityColor[a.severity] }} aria-hidden />
                <div className="min-w-0">
                  <Link href={`/incident/${a.id}`} className="text-ink text-xs font-medium hover:text-brand-bright line-clamp-2 break-words">{a.title}</Link>
                  <p className="text-ink-faint text-[11px] mt-0.5">
                    {t.common.severity[a.severity]} · {timeAgo(a.created_at, locale)} · {alert.source_ip && a.source_ip === alert.source_ip ? m.relatedWhyIp : m.relatedWhyTarget}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
