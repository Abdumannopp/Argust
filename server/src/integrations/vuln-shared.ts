/**
 * Vulnerability findings from scanners (Tenable, Qualys), in the one shape the rest of Legion already reads.
 *
 * Legion's vulnerability skills recognise a finding by its title: "CVE-… affects <component>" (the form Wazuh's
 * vulnerability detector uses). Scanner findings are written the same way, so exposure_review and
 * vulnerability_analysis see them with no change. A weakness with no CVE keeps the scanner's own name; it is an
 * alert, but not a "vulnerability finding" for those skills.
 */
import { cleanText } from "./shared.js";
import type { Severity } from "../types.js";
import type { Finding } from "./types.js";

const CVE = /^CVE-\d{4}-\d{4,7}$/i;

export interface ScannerVuln {
  scanner: string;
  /** Stable per asset and check: the same weakness on the same asset is one alert, however often it is scanned. */
  id: string;
  name: string;
  cves: string[];
  severity: Severity;
  host: string | null;
  ip: string | null;
  os: string | null;
  firstFound: string | null;
  solution: string | null;
  detail: string | null;
  hasFix: boolean | null;
}

/** "Apache Log4j < 2.15.0 RCE" → "Apache-Log4j-2.15.0-RCE": one token, so the title pattern takes all of it. */
export const componentOf = (name: string): string => cleanText(name, 80).replace(/[^A-Za-z0-9.+_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "component";

export function findingFromScannerVuln(v: ScannerVuln): Finding | null {
  const name = cleanText(v.name, 200);
  if (!v.id || !name) return null;
  const cves = [...new Set(v.cves.map((c) => String(c).toUpperCase()).filter((c) => CVE.test(c)))].slice(0, 20);
  const where = v.host || v.ip || "an asset";
  const title = cves.length ? `${cves[0]} affects ${componentOf(name)} on ${where}` : `${v.scanner}: ${name} on ${where}`;
  return {
    externalId: cleanText(v.id, 200),
    title: cleanText(title, 300),
    severity: v.severity,
    summary: [`${v.scanner}: ${name}`, cves.length > 1 ? `CVEs: ${cves.join(", ")}` : "", v.hasFix === true ? "A fix is available." : v.hasFix === false ? "No fix is available yet." : "", v.solution ? `What to do: ${cleanText(v.solution, 600)}` : "", v.detail ? cleanText(v.detail, 600) : ""].filter(Boolean).join("\n"),
    occurredAt: v.firstFound,
    sourceIp: null,
    target: v.host || v.ip || null,
    mitre: [],
    confidence: 85,
    asset: v.host || v.ip ? { name: (v.host || v.ip)!, ip: v.ip, os: v.os } : null,
  };
}
