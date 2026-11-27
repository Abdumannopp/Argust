# AI providers: OpenRouter (Claude Haiku 5.5) and Groq

Argust's Oracle explanations and Copilot assistant can use an AI model. This is
**optional**: with no key, both use local, deterministic analysis and **nothing
leaves the server**.

## Setup

Set whichever key you have — the one present is used:

```env
OPENROUTER_API_KEY=sk-or-…     # the recommended provider
OPENROUTER_MODEL=anthropic/claude-haiku-5.5   # the default; any id from openrouter.ai/models

GROQ_API_KEY=gsk-…             # alternative
AI_PROVIDER=                   # if both keys are set: write groq to use Groq
```

OpenRouter gives access to many vendors' models with one key, including **free
models**, so AI can be tried without paying.

Steps:

1. Sign up at [openrouter.ai](https://openrouter.ai/) and get a key.
2. Put it after `OPENROUTER_API_KEY=` in `server/.env`.
3. Restart Argust.
4. Open an alert and click "Oracle".

If it does not work, the server log says why (for example "no credit" or
"unknown model"). Check what is active: `curl http://localhost:8000/health` →
`ai_provider`.

## Two deliberate decisions

**1. OpenRouter + Claude Haiku 5.5 by default.**
With only an OpenRouter key, Argust asks for `anthropic/claude-haiku-5.5`: fast and
inexpensive for explaining alerts. Change it with `OPENROUTER_MODEL`, or set
`OPENROUTER_MODEL=account-default` to send no model (OpenRouter then uses your account's
default). A named model can be retired by OpenRouter one day; AI answers then stop (the
local analysis takes over and the log says "unknown model") until the id is changed.
For Claude models Argust sends no temperature (current Claude models refuse a non-default
one) and allows up to 4,000 output tokens, because their thinking counts toward that limit.

**2. A wrong setting switches AI off — it never falls back to another provider.**
If `AI_PROVIDER=openrouter` is set without an OpenRouter key but a Groq key is
present, many programs would quietly switch to Groq. Argust does not: AI is
switched off and the log says why. The customer **chooses** which company sees
their security data; naming one and sending to another is the worst kind of
mistake. This case is covered by a test.

Also: OpenRouter accepts an `HTTP-Referer` header, but Argust does **not** send
it — it would reveal the customer's internal server address. Only the name
"Argust" is sent.

## AI safety

**AI only advises.** Requests to the provider contain no `tools`/`functions`, so
the model cannot *do* anything: its answer is text a person reads. In the
dashboard, incident page and Copilot, every model answer is labelled
**"AI suggestion"**; text written by Argust's own rules is labelled
**"Argust analysis"**.

| Protection | How |
|---|---|
| Alert text is untrusted data | Only in the user message, inside a fence with a random boundary per request; invisible characters and chat-template tokens are removed |
| Host names, IPs, MITRE IDs, IDs | If the format does not match, the model sees `(non-standard value omitted)` instead |
| Secrets never reach the provider | Passwords, tokens, API keys, JWTs, private keys, credentials in URLs and the server's own secrets become `[REDACTED:…]` before sending |
| Data minimisation | Fields are shortened; **strict mode** replaces IPs, emails and host names with `IP_1`, `HOST_1`… and maps them back in the answer |
| Output | JSON/structure is validated, HTML and images removed, links defanged (`hxxps://x[.]y`), secrets masked, length limited; an answer that echoes the request's own boundary is refused |
| Time and errors | `AI_TIMEOUT_MS`, 256 KB response limit, no redirects; a circuit breaker after repeated failures. Any error returns the deterministic local analysis |
| Organisation control | `GET/PATCH /ai/settings` and the "AI analysis" card in Settings → Profile (administrators only). When off, nothing is sent for agent skills either |
| Audit | `alert.explained` / `copilot.chat` records only the provider, size, number of redacted secrets, timing and error reason — never the prompt, the answer or a key |

**In hosted (SaaS) mode AI is OFF by default** — an organisation's data does not
go to a third party until its administrator turns it on. In self-hosted mode it
is on. Change it with `AI_TENANT_DEFAULT=on|off`.

**A workspace that turns AI on starts in strict mode, hosted or self-hosted** (IPs,
e-mail addresses and host names are replaced before anything is sent). An administrator
can switch strict off for the workspace; the card then warns that real values reach the
provider. (Self-hosted used to start in standard mode; the provider is a third party in
both cases, so strict is now the default everywhere.) **In every mode** credentials,
this server's own secrets, card numbers (Luhn-checked) and bank accounts (IBAN,
mod-97-checked) are removed before anything leaves. Workspaces that had already chosen a mode keep it; those
that never turned AI on started "unchosen" and so start strict (`tenants.ai_data_mode` is
`NULL` until someone chooses). The audit entry for every AI call records the mode used.

Tests: `server/tests/ai-hardening.test.ts` (attack scenarios),
`server/tests/ai-safety.test.ts`.

## Privacy

With a key, the alert title, summary, host names and IP addresses (after the
redaction above) are sent to the chosen provider. That is the operator's
decision; take your obligations to your own customers into account, and sign a
DPA with the provider or use a zero-retention option where available.
