import { defineMessages } from "../core";

/**
 * The alert dashboard (components/LegionDashboard.tsx). The `alert` group is
 * also used by the incident list and incident details pages, which show the
 * same alert actions and Oracle explanation.
 */
export const dashboard = defineMessages({
  en: {
    welcome: "Welcome back 👋",
    overview: "Argust Security Overview",
    searchPlaceholder: "Search alerts by ID or title",
    empty: "No alerts match this view.",
    kpi: {
      alerts: "Alerts, last 24 h",
      trendUp: (pct: number) => `↑ +${pct}% vs the 24 h before`,
      trendDown: (pct: number) => `↓ −${pct}% vs the 24 h before`,
      trendSame: "Same as the 24 h before",
      trendNew: "Nothing in the 24 h before",
      trendQuiet: "No alerts yet",
      campaigns: "Active campaigns",
      campaignsHint: "Linked attacks still going",
      campaignsNone: "None right now",
      critical: "Critical, open",
      criticalHint: "Look at these first",
      blocked: "Addresses blocked",
      blockedHint: "Blocked right now",
      blockedNone: "None blocked",
    },
    activity: {
      title: "Threat activity",
      subtitle: "Alerts per hour, last 24 hours",
      empty: "No alerts in the last 24 hours.",
      summary: (total: number, busiest: string, count: number) => `${total} alerts in the last 24 hours; busiest hour ${busiest} with ${count}.`,
      point: (when: string, n: number) => `${when}: ${n} ${n === 1 ? "alert" : "alerts"}`,
    },
    ai: {
      title: "Argust AI",
      body: "Ask about your alerts in plain words: what happened, how serious it is, and what to look at first.",
      cta: "Analyze new alerts",
      prompt: "Which of my open alerts should I look at first, and why?",
      note: "You decide what happens next. Nothing is sent until you press Send.",
    },
    campaignsCard: {
      title: "Active campaigns",
      empty: "No linked attacks are going on right now.",
      all: "All campaigns",
      alerts: (n: number) => `${n} ${n === 1 ? "alert" : "alerts"}`,
    },
    coverage: {
      title: "Threat coverage",
      subtitle: "The seven most dangerous attack types",
      center: (seen: number, total: number) => `${seen}/${total}`,
      legend: (seen: number, total: number) => `Argust can see ${seen} of ${total}. Blind: ${total - seen}.`,
      blindIntro: "Blind spots:",
      more: "See what to connect",
      none: "Coverage is not available yet.",
    },
    severityTitle: "Open threats by severity",
    severityTotal: "open",
    severityNone: "Nothing open. Every alert is handled.",
    alertsTitle: "Alerts",
    live: "Live",
    alert: {
      aiConfidence: "AI confidence",
      fullDetails: "Full details",
      investigate: "Investigate",
      resolve: "Resolve",
      askOracle: "Ask Oracle to explain",
      oracleThinking: "Oracle is thinking…",
      otherLanguage: "This explanation is in another language.",
      explainInMyLanguage: "Explain in English",
      explainError: "Oracle couldn't explain this alert.",
      loadError: "Couldn't reach the Argust API. Is the backend running?",
    },
  },
});
