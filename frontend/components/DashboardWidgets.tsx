"use client";

import Link from "next/link";
import { AlertTriangle, Ban, Layers, Play, ShieldAlert, Sparkles } from "lucide-react";
import type { AttackCampaign, Overview, ThreatCoverage } from "@/lib/api";
import { formatNumber, timeAgo } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { smoothPath, trendOf } from "@/lib/dashboard-math";
import { palette, severityColor } from "@/lib/theme";

/**
 * The dashboard's headline numbers, from GET /overview only. Nothing here is a sample: a number Argust does not
 * have is shown as "none yet", never invented (there is deliberately no "security score").
 */
export function KpiRow({ data }: { data: Overview }) {
  const { t, locale } = useLanguage();
  const k = t.dashboard.kpi;
  const n = (v: number) => formatNumber(v, locale);
  const tr = trendOf(data.activity.total_24h, data.activity.previous_24h);
  const trendText = tr.kind === "up" ? k.trendUp(tr.pct) : tr.kind === "down" ? k.trendDown(tr.pct) : tr.kind === "same" ? k.trendSame : tr.kind === "new" ? k.trendNew : k.trendQuiet;
  // More alerts than before is the direction to watch; fewer is good news.
  const trendColor = tr.kind === "up" || tr.kind === "new" ? palette.high : tr.kind === "down" ? palette.success : palette.inkFaint;
  const cards = [
    { label: k.alerts, value: n(data.activity.total_24h), hint: trendText, hintColor: trendColor, Icon: ShieldAlert, color: palette.brandBright },
    { label: k.campaigns, value: n(data.campaigns_active), hint: data.campaigns_active ? k.campaignsHint : k.campaignsNone, hintColor: undefined, Icon: Layers, color: data.campaigns_active ? palette.high : palette.success },
    { label: k.critical, value: n(data.threats.open.critical), hint: k.criticalHint, hintColor: undefined, Icon: AlertTriangle, color: data.threats.open.critical ? palette.critical : palette.inkFaint },
    { label: k.blocked, value: n(data.blocks_active), hint: data.blocks_active ? k.blockedHint : k.blockedNone, hintColor: undefined, Icon: Ban, color: data.blocks_active ? palette.success : palette.inkFaint },
  ];
  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mb-4" data-testid="kpi-row">
      {cards.map(({ label, value, hint, hintColor, Icon, color }, i) => (
        <div key={label} className="lg-surface lg-interactive lg-enter p-4 min-w-0" style={{ animationDelay: `${i * 40}ms` }}>
          <div className="flex items-center gap-2 text-ink-muted text-xs">
            <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0" style={{ backgroundColor: `${color}1F` }}>
              <Icon size={15} color={color} />
            </span>
            <span className="truncate">{label}</span>
          </div>
          <p className="text-ink text-[28px] leading-none font-semibold tabular-nums mt-3">{value}</p>
          <p className="text-[11px] mt-2 truncate" style={{ color: hintColor ?? palette.inkFaint }}>{hint}</p>
        </div>
      ))}
    </div>
  );
}

// Drawn at about the size it is shown (the card is roughly 400 px wide), so the labels stay readable.
const CHART_W = 420, CHART_H = 190, PAD_X = 6, PAD_TOP = 12, PAD_BOTTOM = 8;

/** Alerts per hour over the last 24 hours, from GET /overview (real counts; the whole axis is shown, empty hours as zero). */
export function ThreatActivity({ data }: { data: Overview }) {
  const { t, locale } = useLanguage();
  const a = t.dashboard.activity;
  const hours = data.activity.hours;
  const max = Math.max(1, ...hours.map((h) => h.count));
  const floor = CHART_H - PAD_BOTTOM;
  const innerW = CHART_W - PAD_X * 2;
  const points = hours.map((h, i) => ({ x: PAD_X + (i / Math.max(1, hours.length - 1)) * innerW, y: PAD_TOP + (1 - h.count / max) * (floor - PAD_TOP) }));
  const line = smoothPath(points, floor);
  const area = points.length > 1 ? `${line} L${points.at(-1)!.x.toFixed(1)},${floor} L${points[0]!.x.toFixed(1)},${floor} Z` : "";
  const time = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" });
  const when = (iso: string) => time.format(new Date(iso));
  const busiest = hours.reduce((best, h) => (h.count > best.count ? h : best), hours[0] ?? { at: new Date().toISOString(), count: 0 });
  const labels = [0, 6, 12, 18, 23].filter((i) => hours[i]);
  return (
    <section className="lg-surface p-5 lg-enter min-w-0" aria-labelledby="activity-title" data-testid="threat-activity">
      <h2 id="activity-title" className="text-ink text-sm font-semibold">{a.title}</h2>
      <p className="text-ink-faint text-xs mt-0.5">{a.subtitle}</p>
      {data.activity.total_24h === 0 ? (
        <p className="text-ink-muted text-xs mt-6 mb-6">{a.empty}</p>
      ) : (
        <>
          <svg viewBox={`0 0 ${CHART_W} ${CHART_H + 24}`} className="w-full mt-4" role="img" aria-label={a.summary(data.activity.total_24h, when(busiest.at), busiest.count)}>
            <defs>
              <linearGradient id="act-line" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="#8CCBFF" /><stop offset="0.5" stopColor="#3978F6" /><stop offset="1" stopColor="#B58BFF" /></linearGradient>
              <linearGradient id="act-area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#3978F6" stopOpacity="0.32" /><stop offset="1" stopColor="#3978F6" stopOpacity="0" /></linearGradient>
            </defs>
            {[0, 1, 2].map((g) => <line key={g} x1={PAD_X} x2={CHART_W - PAD_X} y1={PAD_TOP + (g / 2) * (floor - PAD_TOP)} y2={PAD_TOP + (g / 2) * (floor - PAD_TOP)} stroke={palette.line} strokeWidth="1" strokeDasharray={g === 2 ? undefined : "3 5"} />)}
            {area && <path d={area} fill="url(#act-area)" />}
            <path d={line} fill="none" stroke="url(#act-line)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
            {points.map((p, i) => (
              <g key={hours[i]!.at}>
                <title>{a.point(when(hours[i]!.at), hours[i]!.count)}</title>
                <circle cx={p.x} cy={p.y} r={hours[i]!.at === busiest.at ? 4.5 : 2.5} fill={hours[i]!.at === busiest.at ? "#B58BFF" : "#3978F6"} opacity={hours[i]!.count || hours[i]!.at === busiest.at ? 1 : 0.35} />
              </g>
            ))}
            {labels.map((i) => <text key={i} x={points[i]!.x} y={CHART_H + 17} textAnchor={i === 0 ? "start" : i === hours.length - 1 ? "end" : "middle"} fill={palette.inkFaint} fontSize="11">{when(hours[i]!.at)}</text>)}
          </svg>
        </>
      )}
    </section>
  );
}

/** The Argust AI panel: a way into the Copilot with a first question filled in. It sends nothing by itself. */
export function ArgustAiCard() {
  const { t } = useLanguage();
  const a = t.dashboard.ai;
  return (
    <section className="rounded-[22px] p-5 lg-enter flex flex-col min-w-0 text-white" style={{ background: "linear-gradient(145deg, #1B2350 0%, #231A5C 55%, #4B35C9 130%)", boxShadow: "0 18px 50px rgba(57,120,246,0.18)" }} data-testid="ai-card">
      <span className="w-9 h-9 rounded-full bg-white/10 flex items-center justify-center"><Sparkles size={17} /></span>
      <h2 className="text-lg font-semibold mt-3">{a.title}</h2>
      <p className="text-sm text-white/75 mt-1.5 leading-relaxed">{a.body}</p>
      <Link href={`/copilot?ask=${encodeURIComponent(a.prompt)}`} className="mt-auto pt-4">
        <span className="flex items-center justify-center gap-2 rounded-full bg-white text-[#14123A] text-sm font-semibold py-2.5 hover:bg-white/90 transition-colors" data-testid="ai-cta">
          <Play size={13} fill="currentColor" />{a.cta}
        </span>
      </Link>
      <p className="text-[11px] text-white/55 mt-2 text-center">{a.note}</p>
    </section>
  );
}

/** Linked attacks that are still going: the campaigns Argust recognised, newest activity first. */
export function ActiveCampaigns({ campaigns }: { campaigns: AttackCampaign[] | null }) {
  const { t, locale } = useLanguage();
  const c = t.dashboard.campaignsCard;
  const rules = t.defense.campaigns.rule as Record<string, string>;
  const active = (campaigns ?? []).filter((x) => x.status === "active").slice(0, 3);
  if (campaigns === null) return null;
  return (
    <section className="lg-surface p-5 lg-enter min-w-0" aria-labelledby="camp-title" data-testid="active-campaigns">
      <div className="flex items-center justify-between gap-2">
        <h2 id="camp-title" className="text-ink text-sm font-semibold">{c.title}</h2>
        <Link href="/defense" className="text-brand-bright text-xs hover:underline">{c.all}</Link>
      </div>
      {active.length === 0 ? (
        <p className="text-ink-muted text-xs mt-3">{c.empty}</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {active.map((x) => (
            <li key={x.id}>
              <Link href={x.alert_id ? `/incident/${encodeURIComponent(x.alert_id)}` : "/defense"} className="lg-surface-soft lg-interactive flex items-center gap-3 px-3 py-2.5">
                <Layers size={15} className="text-high shrink-0" color={palette.high} />
                <span className="min-w-0 flex-1">
                  <span className="block text-ink text-sm truncate">{rules[x.rule] ?? x.rule}</span>
                  <span className="block text-ink-faint text-[11px] truncate">{x.subject} · {c.alerts(x.alert_count)} · {timeAgo(x.last_seen, locale)}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** How many of the seven most dangerous attack types Argust can see today (the rest are "blind": the data never arrives). */
export function CoverageCard({ threats }: { threats: ThreatCoverage[] | null }) {
  const { t } = useLanguage();
  const c = t.dashboard.coverage;
  const names = t.defense.coverage.names as Record<string, string>;
  if (threats === null) return null;
  const total = threats.length;
  const blind = threats.filter((x) => x.status === "blind");
  const seen = total - blind.length;
  const R = 40, C = 2 * Math.PI * R;
  return (
    <section className="lg-surface p-5 lg-enter min-w-0" aria-labelledby="cov-title" data-testid="coverage-card">
      <h2 id="cov-title" className="text-ink text-sm font-semibold">{c.title}</h2>
      <p className="text-ink-faint text-xs mt-0.5">{c.subtitle}</p>
      {total === 0 ? (
        <p className="text-ink-muted text-xs mt-3">{c.none}</p>
      ) : (
        <div className="flex items-center gap-4 mt-3">
          <svg viewBox="0 0 100 100" width={92} height={92} role="img" aria-label={c.legend(seen, total)} className="shrink-0 -rotate-90">
            <circle cx="50" cy="50" r={R} fill="none" stroke={palette.line} strokeWidth="10" />
            <circle cx="50" cy="50" r={R} fill="none" stroke="#3978F6" strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(seen / total) * C} ${C}`} />
            <text x="50" y="50" transform="rotate(90 50 50)" textAnchor="middle" dominantBaseline="central" fill={palette.ink} fontSize="20" fontWeight="600">{c.center(seen, total)}</text>
          </svg>
          <div className="min-w-0 text-xs">
            <p className="text-ink-soft">{c.legend(seen, total)}</p>
            {blind.length > 0 && <p className="text-ink-faint mt-1.5 break-words">{c.blindIntro} {blind.map((x) => names[x.threat] ?? x.threat).join(", ")}</p>}
            {blind.length > 0 && <Link href="/defense" className="text-brand-bright hover:underline inline-block mt-1.5">{c.more}</Link>}
          </div>
        </div>
      )}
    </section>
  );
}

/** Open threats by severity as a ring: one segment per severity, the total in the middle, and a legend with counts. */
export function SeverityRing({ data }: { data: Overview }) {
  const { t, locale } = useLanguage();
  const open = data.threats.open;
  const order = ["critical", "high", "medium", "low"] as const;
  const total = order.reduce((s, k) => s + open[k], 0);
  const R = 52, C = 2 * Math.PI * R;
  let offset = 0;
  return (
    <section className="lg-surface p-5 lg-enter" aria-labelledby="sev-ring-title">
      <h2 id="sev-ring-title" className="text-ink text-sm font-semibold">{t.dashboard.severityTitle}</h2>
      {total === 0 ? (
        <p className="text-ink-muted text-xs mt-3">{t.dashboard.severityNone}</p>
      ) : (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-4 mt-4">
          <svg viewBox="0 0 140 140" width={112} height={112} role="img" aria-label={`${total} ${t.dashboard.severityTotal}`} className="shrink-0 -rotate-90">
            <circle cx="70" cy="70" r={R} fill="none" stroke={palette.line} strokeWidth="14" />
            {order.map((k) => {
              const len = (open[k] / total) * C;
              const seg = open[k] ? (
                <circle key={k} cx="70" cy="70" r={R} fill="none" stroke={severityColor[k]} strokeWidth="14"
                  strokeDasharray={`${Math.max(len - 2, 0.01)} ${C}`} strokeDashoffset={-offset} strokeLinecap="butt" />
              ) : null;
              offset += len;
              return seg;
            })}
            <text x="70" y="70" transform="rotate(90 70 70)" textAnchor="middle" dominantBaseline="central" fill={palette.ink} fontSize="26" fontWeight="600">{formatNumber(total, locale)}</text>
          </svg>
          <ul className="flex-1 min-w-[150px] space-y-2 text-xs">
            {order.map((k) => (
              <li key={k} className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: severityColor[k] }} aria-hidden />
                <span className="text-ink-soft flex-1">{t.common.severity[k]}</span>
                <span className="text-ink tabular-nums">{formatNumber(open[k], locale)}</span>
                <span className="text-ink-faint tabular-nums w-10 text-right">{Math.round((open[k] / total) * 100)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
