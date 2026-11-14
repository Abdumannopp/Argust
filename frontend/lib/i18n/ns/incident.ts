import { defineMessages } from "../core";

/**
 * Incident details (app/incident/[id]/page.tsx). Alert actions and the Oracle
 * explanation buttons come from `t.dashboard.alert`.
 */
export const incident = defineMessages({
  en: {
    backToAlerts: "Back to alerts",
    loadError: "Couldn't load this incident.",
    statusError: "Couldn't update status.",
    detail: {
      detected: "Detected",
      sourceIp: "Source IP",
      notApplicable: "Not applicable",
      target: "Target",
      notSpecified: "Not specified",
      notClassified: "Not classified",
      confidence: "Detection confidence",
      detectedBy: "Source",
    },
    aiExplanation: "AI explanation",
    intel: {
      title: "Threat intelligence",
      intro: "What your connected sources (VirusTotal, MISP, OpenCTI) know about the source address. Checking sends the address to them, so it happens only when you press the button.",
      check: "Check reputation",
      checking: "Checking…",
      again: "Check again",
      notConfigured: "No threat-intelligence source is connected. An administrator can add VirusTotal, MISP or OpenCTI on the Connect page.",
      unavailable: "No source could be reached. See the connection's status on the Connect page.",
      noIndicator: "This alert has no source address to check.",
      privateAddress: "This is a private (internal) address. It is never sent to an outside service, and outside sources know nothing about it.",
      nothingKnown: "None of your sources has information on this address. That is not proof it is safe.",
      verdict: { malicious: "Malicious", suspicious: "Suspicious", benign: "No detections", unknown: "No verdict" },
      confidence: (n: number) => `confidence ${n}%`,
      failed: (name: string) => `${name} could not be reached.`,
      caution: "A reputation is a hint, not proof: addresses change hands and can be forged. The text below comes from the source and is shown as data.",
    },
    suggestedActions: "Suggested actions",
    suggestedIntro:
      "Rule-based suggestions from the alert pattern — not AI-generated, so you can trust exactly why each one is here.",
    manualNote:
      "These are manual checklist items for now — automated execution (the Vanguard agent) isn't wired up yet.",
  },
});
