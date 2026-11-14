# Integrations — what is built, what is not

Legion takes security data in through **adapters** (`server/src/integrations/`): one file per source, one `register()` call. Every adapter produces the same `Finding`; one shared path stores it (idempotent, tenant-isolated, with mail and realtime). Nothing outside `src/integrations` knows a vendor's format.

| # | Integration | Status | How it connects |
|---|---|---|---|
| 0 | **Wazuh** | built (earlier) | `POST /security-events/webhook`, signed |
| 1 | **Generic JSON webhook** (also Elastic Security, Splunk) | **built, tested with sample payloads** | `POST /security-events/webhook/generic`, signed, JSON |
| 2 | **Syslog / CEF** | **built, tested with sample lines** | `POST /security-events/webhook/cef`, signed, `text/plain` |
| 3a | **Slack** (notification) | **built, tested with a simulated provider** | outbound, incoming-webhook URL |
| 3b | **Jira Cloud** (ticket) | **built, tested with a simulated provider** | outbound, e-mail + API token |
| 3 | **Microsoft Defender XDR** | **built, tested with a simulated Graph** | pull, Entra app, `SecurityAlert.Read.All` |
| 4 | **AWS GuardDuty** | **built, tested with a simulated API; SigV4 checked against AWS's published test vector** | pull, IAM access key (read only) |
| 6 | **Microsoft Azure** (Defender for Cloud) | **built, simulated provider** | pull, Entra app, Reader role |
| 7 | **Google Cloud** (Security Command Center) | **built, simulated provider** | pull, service account (JWT, RS256) |
| 8 | **Okta** (identity: System Log) | **built, simulated provider** | pull, read-only admin API token |
| 9 | **GitHub** (secret / code scanning, Dependabot) | **built, simulated deliveries** | push, X-Hub-Signature-256 per connection |
| 10 | **PagerDuty** (page on-call) | **built, simulated provider** | outbound, Events API v2 (dedup by alert id) |
| 11 | **Microsoft Teams** (channel) | **built, simulated provider** | outbound, Workflows webhook URL |
| 12 | **CrowdStrike Falcon** (EDR) | **built, simulated provider** | pull, API client with *Alerts: Read* only |
| 13 | **SentinelOne** (EDR) | **built, simulated provider** | pull, Viewer API token |
| 14 | **Microsoft Sentinel** (SIEM incidents) | **built, simulated provider** | pull, Entra app, *Microsoft Sentinel Reader* |
| 15 | **AWS Security Hub** (Inspector, Macie, Config, partners) | **built, simulated provider; SigV4** | pull, IAM key or read-only role (external id) |
| 16 | **Elastic Security** on Elastic Cloud | **built, simulated provider** | pull, API key (read alerts) |
| 17 | **Splunk Cloud** (ES notable events) | **built, simulated provider** | pull, authentication token, REST port 8089 |
| 18 | **Cloudflare** (WAF / edge) | **built, simulated provider** | pull, token with *Zone · Analytics · Read* |
| 19 | **Google Workspace** (sign-in security) | **built, simulated provider** | pull, service account, domain-wide delegation, audit read-only scope |
| 20 | **ServiceNow** (incident) | **built, simulated provider** | outbound, *itil* user, one incident per alert |
| 21 | **Opsgenie** (on-call) | **built, simulated provider** | outbound, API integration key (dedup by alias) |
| 5 | Self-managed Elastic / Splunk | through the generic JSON webhook (a Kibana webhook connector / Splunk alert action), because Legion never calls an address a customer typed | |

**Firewalls, IDS and other tools with syslog** (Palo Alto, Fortinet, Check Point, Cisco, Sophos, pfSense, Suricata, Zeek…) connect through **Syslog / CEF** or the **generic JSON webhook**; no vendor-specific code is needed for them.

## Authentication (all push routes)

Same as the Wazuh webhook: a **sensor credential** (Settings → Sensor credentials) signs `timestamp + nonce + raw body` with HMAC-SHA256. The signature is checked on the raw bytes **before** anything is parsed; replays are refused; repeated failures from one address are throttled. The workspace is whatever the credential belongs to — nothing in the body or headers can choose it. Not subject to the subscription gate (late invoices must not drop telemetry).

Headers: `x-legion-key-id`, `x-legion-timestamp`, `x-legion-nonce`, `x-legion-signature` (see `webhook-auth.ts`; `integrations/wazuh/custom-legion.py` is a reference signer).

## Generic JSON webhook

Body: one object, an array, or `{"events":[…]}` (up to 200). First matching field wins:

| Meaning | Fields |
|---|---|
| title (required) | `title`, `name`, `alert_name`, `rule.name`, `kibana.alert.rule.name`, `search_name`, `message`, `description` |
| severity | `severity`, `level`, `priority`, `event.severity`, `kibana.alert.severity`, `kibana.alert.risk_score`, `urgency` — words (low…critical) or numbers (0–10, or 0–100 above 10). Unknown → **medium**, never low |
| id (dedupe) | `id`, `event_id`, `uuid`, `alert_id`, `kibana.alert.uuid`, `sid` — otherwise a hash of the content |
| time | `timestamp`, `@timestamp`, `time`, `occurred_at`, `kibana.alert.start`, `_time` (ignored if before 2000 or in the future) |
| source address | `source_ip`, `src_ip`, `source.ip`, `client.ip`, `src`, `result.src_ip` (only valid IPs) |
| host | `host`, `hostname`, `host.name`, `agent.name`, `dest`, `result.host` |

An event with no title is skipped, never invented.

**Elastic Security:** Kibana → Rules → Actions → *Webhook* connector, POST to the URL above with the rule's alert document as the body; a small signing proxy (or Logstash/Vector with an HMAC step) adds the headers. **Splunk:** *Webhook* alert action, same approach. Neither has been tested against a real Elastic or Splunk instance — only against sample payloads of their documented shape.

## Syslog / CEF

Legion **does not open a syslog port**: an unauthenticated UDP/TCP listener would be a new attack surface. Run a collector you already have (rsyslog `omhttp`, syslog-ng `http()`, Vector, Fluent Bit, Logstash) that batches lines and POSTs them as `text/plain`, one event per line (up to 200 lines of 4 KB).

- **CEF** (with or without a syslog header): `CEF:0|vendor|product|version|signature|name|severity|extension`. Severity 0–3 low, 4–6 medium, 7–8 high, 9–10 critical. Escaped `\|` and `\=` are handled. Used: `src`, `dst`, `dhost`/`shost`, `msg`, `act`, `suser`, `duser`, `rt`/`end`/`start`, `externalId`.
- **Plain syslog** (`<PRI>…`): kept only when syslog severity is *error or worse* (0–3); routine lines are skipped on purpose.

## Safety

- All text is untrusted data: control and bidirectional characters removed, lengths bounded, IPs validated, no field is ever read as an instruction.
- Adapters never throw on hostile input (tested with malformed headers, huge lines, NULs).
- These sources feed detection and — **only if a workspace opted in** ([PROTECTION.md](PROTECTION.md)) — automatic blocking of public addresses. A source address in a log can be forged: confirm from a second source before trusting it.

## Honest limits

- Tested with sample payloads and lines, **not** against real Elastic, Splunk, ArcSight or rsyslog installations.


## Outbound connectors: Slack (notification) and Jira (ticket)

```
 alert stored ──(same DB transaction)──▶ notification_outbox  kind=integration_message
   (ingest)                               one row per (alert, connection), dedupe key
                                                   │  worker: claim ▸ lease ▸ attempt (60 s cap)
                                                   ▼
                              integration-notify.ts ─ opens the connection's sealed secrets
                                                   │
                         ┌─────────────────────────┴──────────────────────────┐
                         ▼                                                    ▼
              slack.ts → hooks.slack.com                    jira.ts → <site>.atlassian.net
                         │                                                    │
        success ─▶ sent (+ ticket key kept)       5xx / 429 / timeout ─▶ retry with backoff (≤ max attempts)
        4xx (revoked, bad login) ─▶ dead letter at once, shown on the connection (last_error, failures)
```

**Set up (customer, administrator):** Settings → Integrations (API: `POST /integrations`).

| | Slack | Jira Cloud |
|---|---|---|
| Create in the vendor | Slack app → *Incoming Webhooks* → add to one channel → copy the URL | Atlassian account (a bot user) → *API token*; note the project key (e.g. `SEC`) |
| `kind` | `slack` | `jira` |
| `config` | `{"min_severity":"high"}` | `{"site":"acme","project_key":"SEC","issue_type":"Task","min_severity":"high"}` (`acme` = acme.atlassian.net) |
| `secrets` | `{"webhook_url":"https://hooks.slack.com/services/…"}` | `{"email":"bot@acme.io","api_token":"…"}` |

Secrets are sealed (AES-256-GCM, bound to the workspace and connection), never returned, never logged, and an error that echoes one is scrubbed before it is stored. `min_severity` defaults to `high`. At most `ALERT_EMAIL_HOURLY_CAP` (default 100) messages per connection per hour.

**SaaS vs self-hosted:** no new environment variables. The Legion server must reach `hooks.slack.com:443` and `*.atlassian.net:443` over HTTPS; on a self-hosted install with an egress firewall, allow exactly those. Legion calls no other host and never a URL a customer typed (redirects are refused, the site is a name, not a URL).

**Health:** the connection shows `last_success_at`, `last_error` and `failures`; after 10 consecutive failures it goes to `error` and stops receiving until resumed. Queue depth, retries and dead letters appear in `/metrics` under the outbox kind `integration_message`.

**Provider downtime:** messages wait in the outbox and are retried with exponential backoff (cap 1 h) up to `NOTIFY_MAX_ATTEMPTS`; then they are dead-lettered, never silently dropped. A revoked Slack webhook or a Jira 401/403/404 is not retried (retrying cannot help). A removed connection drops its pending messages without error; a paused one keeps them until the retry budget ends.

**Tickets are idempotent:** before creating, Legion searches the project for the label `legion-<alert id>`; a retry or a crash after creation finds the first ticket. Jira's search index can lag by seconds, so a retry within that window can, rarely, open a second ticket.

**They cannot act:** these connectors only notify or open tickets. A test fails if an outbound adapter declares a "respond" capability or imports blocklist/action/approval code. The only things Legion can do in a customer's environment remain the two executors in [PROTECTION.md](PROTECTION.md), which need an administrator's opt-in, and everything privileged still waits for a person.

**Verified:** `tests/integrations-outbound.test.ts` (17 tests, simulated Slack/Jira): delivery, filtering by severity, duplicate suppression, markup/mention neutralisation, 503→retry→delivered, 429 retry, revoked webhook dead-lettered with health shown, paused/removed connections, secrets never in responses/URLs/rows/errors, tenant isolation (workspace B's channel never receives A's alerts; A cannot touch B's connection), idempotent tickets.
**Not verified:** a real Slack workspace or Jira Cloud site (only simulated providers), Jira Data Center / Server, Slack bot tokens (only incoming webhooks), 


## Pull connectors: Microsoft Defender XDR and AWS GuardDuty

Added in the dashboard under **Connect → Connections** (administrators), or `POST /integrations`. Polled every 5 minutes by whichever instance holds the lease; ingestion is idempotent, so a repeated poll never doubles an alert. A failing poll backs off (up to 1 h) and, after 10 failures in a row, the connection shows *Stopped after repeated errors* until an administrator resumes it.

| | Defender XDR (`m365`) | GuardDuty (`guardduty`) |
|---|---|---|
| Vendor side | Entra ID → App registration → API permission **SecurityAlert.Read.All** (application) → grant admin consent → create a client secret | IAM user with only the policy below; create an access key |
| `config` | `{"directory_id":"<GUID>","client_id":"<GUID>"}` | `{"regions":["eu-west-1"],"role_arn":"arn:aws:iam::<account>:role/LegionGuardDutyRead","external_id":"…"}` (`role_arn`/`external_id` optional, recommended) |
| `secrets` | `{"client_secret":"…"}` | `{"access_key_id":"…","secret_access_key":"…"}` |
| Hosts Legion calls | `login.microsoftonline.com`, `graph.microsoft.com` | `guardduty.<region>.amazonaws.com`, `sts.amazonaws.com` (with a role) |
| Reads | Graph `security/alerts_v2`, by `lastUpdateDateTime` | detectors → findings by `updatedAt` |

GuardDuty IAM policy (read only): `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings` on `*`.

**Cross-account role (recommended):** put that policy on a role in the customer's account whose trust policy allows Legion's IAM user with a condition `sts:ExternalId = <external_id>`; the stored key then needs only `sts:AssumeRole` on that role. Legion assumes it for 15 minutes per poll (`sts.amazonaws.com`) and never stores the session credentials.

Firewall for self-hosted installs: allow outbound 443 to the hosts above, plus `hooks.slack.com` and `*.atlassian.net` for Slack and Jira. No other environment variable is needed.

**Verified (simulated providers):** field mapping, severity bands, cursor and paging, a paging link to any host but Graph is refused, wrong secret / missing consent / 403 give a clear error that never contains the secret, an outage backs off and recovers, alerts land only in the owning workspace, secrets are sealed and never returned, region names cannot inject hosts (`tests/integrations-cloud.test.ts`).
**Not verified:** a real Entra tenant or AWS account. Limits: a Microsoft alert or GuardDuty finding is stored once by its id (a later update with a **higher** severity raises the existing Legion alert — see "Vendor updates" below; an update never creates a second alert); Defender severity "high" is the top Microsoft level, so Defender alerts are never "critical". Security Hub is built (see below).

## Definition of done: where each item stands

| Item | Status |
|---|---|
| Connectors pass integration tests | yes (simulated providers); in CI as part of `test:security` |
| SaaS and self-hosted configuration documented | yes (this file; egress hosts, no new variables) |
| Secrets protected | sealed per connection, never returned, scrubbed from errors (tested) |
| Tenant isolation verified | yes, for pull, push and outbound (tested) |
| Events correctly correlated | all sources use the same ingestion and campaign correlation (`campaigns.ts`); correlation across vendors is covered by the shared path, not by a vendor-specific test |
| Notification delivery / ticket creation verified | with simulated Slack/Jira; not against real services |
| Failure and recovery tested | provider 5xx/429, revoked credentials, outage then recovery, paused/removed connections |
| No privileged response action without approval | connectors cannot respond (tested); the only executors remain the opt-in ones in PROTECTION.md |
| End-to-end attack investigation demonstration | `tests/e2e-integrations-scenario.test.ts`: Defender XDR (pull) + firewall CEF + Elastic alert for one attacker → one `rapid_chain` campaign → Slack messages and Jira tickets (ticket shown on the alert) → five agents investigate → Vanguard proposes a block → a person approves → simulated, no real block, audit chain verifies (simulated providers) |


**On the alert page** (`/incident/<id>`) a *Sent to* block shows where the alert went and links the Jira ticket (`GET /alerts/:id/deliveries`, tenant-scoped; ticket URLs are only shown when they point to `*.atlassian.net/browse/`).


## More platforms: Azure, Google Cloud, Okta, GitHub, PagerDuty, Teams

All added in **Connect → Connections** (or `POST /integrations`). Same rules as the others: secrets sealed per connection and never returned, egress pinned to the vendor's hosts (a paging link to another host is refused), errors scrubbed of secrets, an outage backs off and recovers, one alert per finding, alerts only in the owning workspace.

| Kind | Vendor side | `config` | `secrets` | Hosts Legion calls |
|---|---|---|---|---|
| `azure` | Entra app registration; **Reader** role on the subscription | `directory_id`, `client_id`, `subscription_id` | `client_secret` | `login.microsoftonline.com`, `management.azure.com` |
| `gcp` | Service account with **Security Center Findings Viewer** on the organisation | `organization_id` (digits) | `service_account_json` (its JSON key) | `oauth2.googleapis.com`, `securitycenter.googleapis.com` |
| `okta` | API token of a **read-only administrator** | `domain` (e.g. `acme.okta.com`) | `api_token` | your `*.okta.com` / `*.oktapreview.com` / `*.okta-emea.com` org only |
| `github` | Repository or organisation **webhook**, content type `application/json`, events: *Secret scanning alerts*, *Code scanning alerts*, *Dependabot alerts* | none | `webhook_secret` (you choose; the same text in GitHub) | none (it calls Legion) |
| `pagerduty` | Service → Integrations → *Events API v2* | `min_severity` (default `critical`) | `routing_key` (32 characters) | `events.pagerduty.com` |
| `teams` | Channel → Workflows → *Post to a channel when a webhook request is received* | `min_severity` (default `high`) | `webhook_url` | the webhook's own Microsoft host (`*.webhook.office.com`, `*.logic.azure.com`, `*.powerplatform.com`) |

**GitHub address:** after saving, the dashboard shows `https://<your-legion>/api/security-events/webhook/github?connection=<id>`. Legion verifies GitHub's `X-Hub-Signature-256` (HMAC-SHA256 of the raw body) in constant time before parsing; an unknown connection, a wrong or missing signature, and a paused connection all answer the same 401 and count as failures for the sender's address. The connection (not the request) decides the workspace. Only *new or reopened* alerts become Legion alerts; closing and fixing do not. A secret-scanning alert records the kind of secret and the repository, **never the secret value**.

**PagerDuty** uses the alert id as `dedup_key`, so PagerDuty itself collapses repeats. **Teams** and **Slack** send alert text as plain text (no mentions, links or markup from an alert).

**Verified (simulated providers/deliveries):** field mapping and severity, paging and cursors, the Google JWT is a valid RS256 signature, SSWS/Bearer auth on the right hosts only, foreign paging links not followed, refused credentials give clear errors without the secret, GitHub signature cases (valid, tampered, missing, wrong secret, unknown/other-workspace/paused connection), PagerDuty dedup and severity, Teams host validation, plain-text cards (`tests/integrations-platforms.test.ts`, 20 tests).
**Not verified:** a real Azure subscription, Google Cloud organisation, Okta org, GitHub repository, PagerDuty service or Teams channel. The Azure, SCC and Okta request shapes follow the vendors' documentation; confirm each against a sandbox account before relying on it. Limits: an Azure alert, SCC finding or Okta event is stored once by its id; Azure lists current alerts and Legion filters by time itself; Okta ingests warnings and errors only; GitHub delivers at least once and failed deliveries are redelivered by GitHub, not queued by Legion.

## EDR, SIEM, cloud, identity, edge and ticketing (second wave)

| Kind | Vendor side | `config` | `secrets` | Hosts Legion calls |
|---|---|---|---|---|
| `crowdstrike` | Falcon → API clients → new client with **Alerts: Read** only | `cloud` (`us-1`, `us-2`, `eu-1`, `us-gov-1`), `client_id` | `client_secret` | that cloud's API host only (`api.crowdstrike.com`, `api.us-2…`, `api.eu-1…`, `api.laggar.gcw…`) |
| `sentinelone` | Service user with the **Viewer** role → API token | `console` (`acme` = acme.sentinelone.net) | `api_token` | `<console>.sentinelone.net` |
| `msentinel` | Entra app registration; **Microsoft Sentinel Reader** on the workspace | `directory_id`, `client_id`, `subscription_id`, `resource_group`, `workspace` | `client_secret` | `login.microsoftonline.com`, `management.azure.com` |
| `securityhub` | IAM policy `securityhub:GetFindings` (on a role assumed with an external id, recommended) | `regions`, `role_arn`, `external_id`, `include_guardduty` (default `false`) | `access_key_id`, `secret_access_key` | `securityhub.<region>.amazonaws.com`, `sts.amazonaws.com` |
| `elastic` | API key with read access to the security alerts (viewer) | `kibana_host` (an Elastic Cloud Kibana host), `space` (default `default`) | `api_key` | `*.kb.<region>.<provider>.elastic-cloud.com` / `.cloud.es.io` / `.elastic.cloud` |
| `splunk` | Authentication token of a user who may search the index; **add Legion's outbound address to Splunk Cloud's REST allow list** | `stack` (`acme` = acme.splunkcloud.com), `index` (default `notable`) | `token` | `<stack>.splunkcloud.com:8089` |
| `cloudflare` | API token with **Zone · Analytics · Read** on the zone | `zone_id`, `min_events` (default 50 per address per hour) | `api_token` | `api.cloudflare.com` |
| `gworkspace` | Service account; Admin console → domain-wide delegation for **`https://www.googleapis.com/auth/admin.reports.audit.readonly`** only | `admin_email` (the administrator Legion acts as) | `service_account_json` | `oauth2.googleapis.com`, `admin.googleapis.com` |
| `servicenow` | Integration user with the **itil** role | `instance` (`acme` = acme.service-now.com), `assignment_group` (sys_id, optional), `min_severity` (default `high`) | `username`, `password` | `<instance>.service-now.com` |
| `opsgenie` | Opsgenie → Integrations → **API** | `region` (`us`/`eu`), `min_severity` (default `high`) | `api_key` | `api.opsgenie.com` / `api.eu.opsgenie.com` |

What each reads, and how repeats are handled:

- **CrowdStrike** — Alerts API v2, by `updated_timestamp`; one Legion alert per composite id. Severity from `severity_name` (or the 1–100 score).
- **SentinelOne** — threats, by `updatedAt`. SentinelOne has no severity field, so Legion derives it: *malicious and not mitigated* → critical, *malicious* → high, *suspicious* → medium.
- **Microsoft Sentinel** — incidents by `lastModifiedTimeUtc`; **closed incidents are skipped**.
- **Security Hub** — ACTIVE findings with workflow NEW or NOTIFIED, by `UpdatedAt`. GuardDuty's own findings are skipped unless `include_guardduty` is true, so a workspace with both connections does not get each GuardDuty finding twice.
- **Elastic** — Kibana detection engine, open alerts by `@timestamp`, `search_after` paging. Only Elastic Cloud hosts are accepted (an internal or typed address is refused when saving — tested).
- **Splunk** — the REST export endpoint, events **indexed** since the last poll (so late events are read once), at most 1 000 per poll; a full page resumes from the last index time. The search is fixed; the index name is checked so it cannot carry SPL.
- **Cloudflare** — the GraphQL Analytics API, blocked or challenged requests **grouped by address per complete UTC hour**: one alert per address per hour with the count (≥ 500 medium, ≥ 5 000 high), never one alert per request. At most 24 hours per poll; the current hour is read in the next poll.
- **Google Workspace** — the login audit: government-backed attack warning (critical), account disabled as hijacked or for a leaked password, suspicious sign-ins (high), risky action blocked, spam (medium), failed sign-in (low). Ordinary sign-ins and sign-outs are skipped. Google returns newest events first, so a long gap is read in six-hour windows, oldest first (up to 10 000 events per window).
- **ServiceNow** — one incident per alert: `correlation_id = legion-<alert id>` is looked up first (the Table API reads the database, so there is no index lag), and the incident number is stored on the message the moment it is created. The incident link is shown on the alert page.
- **Opsgenie** — `alias = legion-<alert id>`, so Opsgenie collapses repeats. Atlassian has announced the end of Opsgenie as a separate product; its alerting API lives on in Jira Service Management.

**Vendor updates (audit A-9):** every pull connector above, and Defender XDR, GuardDuty and Okta, reads by *update* time. When an item Legion already stored comes again with a **higher** severity, the Legion alert is raised to it, a dated line ("The source raised the severity to …") is added to its text, the change is written to the audit log, and dashboards see it at once. A source never **lowers** a severity and never changes an alert's status: closing or downgrading stays a person's decision. Outbound connections are told about the raise once per severity (title prefixed "[Severity raised]"): a connection whose threshold the alert did not reach before — PagerDuty at `critical` when the alert arrived as `medium` — now pages; Jira, ServiceNow, PagerDuty and Opsgenie collapse it onto the ticket or page they already have (the existing Jira ticket's text is not rewritten); Slack and Teams post a second message. **Limit:** a resolved alert that a source raises stays resolved (it is raised, noted and audited, and the connections are told) — reopening is a person's decision.

**Verified (simulated providers):** field mapping and severity, auth header and host of each vendor, cursors and paging, filters sent to each API, only the configured cloud/console/instance/stack is called, refused credentials and outages give clear errors without the secret, Elastic/Splunk/SentinelOne/ServiceNow/CrowdStrike configs refuse a URL or injected text, Cloudflare's hourly grouping and 24-hour cap, Google's delegated JWT (`sub`, read-only scope), ServiceNow one-incident-per-alert and dead-lettering of bad credentials, Opsgenie alias and priority, tenant isolation, an end-to-end CrowdStrike poll through the worker, and the severity-raise rule (`tests/integrations-edr-siem.test.ts`).
**Not verified:** real CrowdStrike, SentinelOne, Sentinel, Security Hub, Elastic Cloud, Splunk Cloud, Cloudflare, Google Workspace, ServiceNow or Opsgenie accounts. The request shapes follow each vendor's API documentation; run each connector once against a sandbox account before relying on it (audit A-1).

Firewall for self-hosted installs: allow outbound 443 to the hosts in the table (and 8089 to `<stack>.splunkcloud.com` for Splunk).

## Threat intelligence: VirusTotal, MISP, OpenCTI

Sources Legion **asks** about an indicator ("what is known about this address?"). They bring in no alerts and
change nothing. Add them on Dashboard → **Connect** like any other connection (administrators only).

| Kind | What you create at the source | Settings | Secret | Hosts Legion calls |
|---|---|---|---|---|
| `virustotal` | A VirusTotal account's API key | — | `api_key` | `www.virustotal.com` |
| `misp` | API key of a **read-only** MISP user | `host` (DNS name of your MISP) | `api_key` | your `host`, port 443 |
| `opencti` | API token of a **read-only** OpenCTI user | `host` (DNS name of your OpenCTI) | `api_token` | your `host`, port 443 |

Where it is used:

- **On an alert** — the incident page has **Threat intelligence → Check reputation** (analysts and administrators).
  It asks about the alert's source address and shows each source's verdict.
- **Hunter's `threat_intelligence` skill** — an AI agent with `intel:read` gets the same answers for addresses,
  domains, URLs, file hashes and e-mail addresses.

How a verdict is reached (each source is shown separately; Legion does not blend them into one score):

| Source | Malicious | Suspicious | No detections / no verdict |
|---|---|---|---|
| VirusTotal | 3 or more security vendors flag it | 1–2 vendors flag it | 10 or more looked and none flagged it → "no detections" |
| MISP | an attribute with this exact value is marked for detection (`to_ids`) | the value is recorded, not marked for detection | not in MISP → no answer |
| OpenCTI | score 70–100 | score 40–69 | lower or no score → "no verdict" (being recorded is not being malicious) |

Rules that cannot be changed:

- **Only on demand.** Legion never sends an indicator to a third party by itself; a person presses the button or
  an agent calls the skill. Every lookup from the dashboard is written to the audit log.
- **Private addresses never leave.** A private, loopback, link-local or reserved address (and a URL on one) is
  not sent to any source.
- **No source, no opinion.** An indicator nobody has information on is "unknown" — never guessed, and never "safe".
- **Your own server, guarded.** MISP and OpenCTI are servers you run, so this is the one place Legion calls a host
  you typed. It must be a DNS name (not an address), on HTTPS port 443 with a valid certificate; the name must
  resolve only to public internet addresses, and Legion connects to exactly the address it checked. Redirects are
  not followed.
- A source's text is untrusted data: bounded, shown as text, never followed as an instruction.
- Each connection's key is sealed and sent only to its own source. Errors are scrubbed of it.

Honest limits:

- **Tested against simulated answers only**, written from each vendor's API documentation — not yet against a real
  VirusTotal account, MISP or OpenCTI server (audit A-1 applies here too).
- A MISP or OpenCTI that is reachable **only inside your network** cannot be connected to hosted Legion.
- VirusTotal's free key allows 4 lookups a minute: one call spends at most 4, and the rest are answered on a later
  call. Answers are remembered for 12 hours per workspace and source (per server instance), so a verdict can be
  up to 12 hours old.
- VirusTotal is not asked about e-mail addresses or CVEs (it has no such lookup). CVEs are not sent to any source.
- A reputation is a hint, not proof: addresses change hands and can be forged in a log.
- Legion does **not** import indicator feeds or match every incoming event against them; it enriches on request.

## One view of every connection (integration engine)

Dashboard → **Connect** → Connections shows, for every connection, whether it works and how fresh it is:

| It says | It means |
|---|---|
| Working | the last attempt succeeded |
| Waiting for its first success | saved, nothing has succeeded yet |
| Failing | the last attempts failed (the error is shown, with the credential removed) |
| Not checked for too long | Legion polls it, and the poll is more than three intervals (at least 15 minutes) late |
| Stopped after repeated errors | 10 failures in a row; an administrator must resume it |
| Paused | an administrator paused it |

Each row also shows its direction (brings alerts in / receives alerts / threat intelligence / acts when people
approve), the alerts that vendor brought in over 24 hours, and for chat and ticket connections how many messages
are still waiting or could not be delivered. **Check now** asks Legion to poll a working connection within a minute.
API: `GET /integrations/health`, `POST /integrations/:id/check` (administrators).

Honest limits: the 24-hour alert count is per vendor, not per connection (two Okta connections share one number).
"Check now" exists only for connections Legion polls; a webhook source is checked by its own next delivery.

## Asset intelligence: one inventory

Dashboard → **Assets** lists servers, endpoints, user accounts and cloud resources from every connected platform.

- **Kind** comes from the platform that reported it: Wazuh → server; CrowdStrike, SentinelOne, Defender → endpoint;
  GuardDuty, Security Hub, Azure, Google Cloud → cloud resource; a SIEM or a webhook does not say → not classified.
  The first platform that knows decides; a later different opinion does not change it.
- **User accounts** come from identity alerts (Okta, Google Workspace): the account the alert is about.
- **One asset, many platforms.** The same name reported by several platforms is one row that lists them all.
- A user account is an asset but not a machine: it does not count against the plan's endpoint limit.

Honest limits: assets are matched **by name, exactly**. `web-1` and `web-1.corp.example.com` are two assets, and an
account is not linked to the laptop its owner uses. Legion learns of an asset only when an alert mentions it — it
does not import the full device or user list from a platform, so a quiet machine is not in the inventory.

## Correlation across platforms

When two or more **different** platforms report the same attacking address — or high/critical alerts on the same
host or account — within 60 minutes, Legion records one campaign (`multi_platform`) and one alert from Hunter that
names the platforms. It is evidence joined, not a verdict: it never triggers automatic blocking.

Honest limits: this is a fixed rule, not a model; it joins alerts that share an **exact** address or name. An attack
whose stages use different addresses and different names in each tool is not joined by this rule (the other
campaign rules in WAZUH.md look at techniques and timing). Legion's own alerts do not count as a platform.

## Response: acting in your systems (people approve first)

Two **response connections** let Legion change something in your environment. They are separate from the
read-only connections, with their own credential:

| Kind | What it can do | What you create | Hosts |
|---|---|---|---|
| `crowdstrike_response` | isolate a host from the network (Falcon containment) and release it | a separate Falcon API client with **Hosts: Read** and **Hosts: Write** only | the Falcon cloud you choose |
| `okta_response` | suspend a user account and restore it (nothing is deleted) | a separate API token of an administrator whose role may only suspend users | your Okta domain |

How one action happens:

1. An administrator turned protection on (Defense page; see PROTECTION.md). Without it nothing live exists.
2. Someone asks: an administrator on the alert's page (**Respond in your systems**), or the Vanguard agent.
3. Isolating a host or suspending an account is **critical**: two administrators — not the one who asked — approve
   that exact action on the Defense page, each with a current two-factor code. The request expires in an hour.
4. Legion looks again (protection still on, the connection present, the target not on the never-touch list),
   finds **exactly one** matching device or account, acts, writes the audit log and tells the administrators.

Rules that cannot be changed:

- These actions can **never** be pre-authorised: no protection mode, policy or setting lets Legion isolate a host or
  suspend an account on its own. The database refuses to store them in a workspace's automatic list.
- No connection, more than one possible connection, no such device, two devices with the name, or a protected
  target: nothing is done, and the request ends "not done" with the reason.
- An action whose outcome is unknown (the worker stopped while doing it) is not retried; the administrators are told.
- Every action has its opposite (`host.release`, `account.enable`). An administrator's own request to undo runs at
  once; a machine's still waits for approval.

Honest limits:

- **Tested against simulated vendor answers only.** Do not rely on it in an incident before trying it on a test
  host and a test account in your own CrowdStrike and Okta.
- Only CrowdStrike (hosts) and Okta (accounts). SentinelOne, Defender for Endpoint, Entra ID and Google Workspace
  accounts are not connected for response: an action for them ends "no response connection".
- Firewall: blocking an address is the existing blocklist, enforced by your Wazuh manager (WAZUH.md). Legion does not
  push rules to Cloudflare or to a network firewall.
- The dashboard button asks to isolate or suspend; releasing and restoring are done through the API
  (`POST /actions` with `host.release` / `account.enable`) or in the vendor's own console.
- Three administrators are needed when a person asks (the asker cannot approve): a team of one or two cannot use
  this by hand. A request from the Vanguard agent needs two.
- Suspending an Okta account does not sign the person out of other systems where they already have a session.

## What Legion can DO in these systems today

Everything above **reads, notifies or opens tickets**, except the two response connections described in "Response: acting in your systems". What Legion can really do: (a) block a public address (enforced by the Wazuh manager's active response) and (b) e-mail administrators — both can be allowed to run on their own, opt-in per workspace ([PROTECTION.md](PROTECTION.md)); (c) isolate or release a host through CrowdStrike and (d) suspend or restore an Okta account — only after people approve each one. Disabling an Entra or Google account, isolating a host through Defender for Endpoint or SentinelOne, changing a Cloudflare rule and similar actions are **simulation only**: they are not built.
