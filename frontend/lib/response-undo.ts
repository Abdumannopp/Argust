import type { ExecutedAction } from "@/lib/api";

export const OPPOSITE = { "host.isolate": "host.release", "account.disable": "account.enable" } as const;
const FAMILY: Record<string, "host" | "account"> = { "host.isolate": "host", "host.release": "host", "account.disable": "account", "account.enable": "account" };

/**
 * What is still isolated or suspended, as far as Argust's own record goes: for each host or account, the newest
 * action Argust carried out. If that is "isolate" or "disable", it is listed with its way back.
 */
export function stillInEffect(actions: ExecutedAction[]): ExecutedAction[] {
  const newest = new Map<string, ExecutedAction>();
  for (const a of [...actions].sort((x, y) => Date.parse(y.created_at) - Date.parse(x.created_at))) {
    const family = FAMILY[a.action_id];
    if (!family || !a.target) continue;
    const key = `${family}:${a.target.toLowerCase()}`;
    if (!newest.has(key)) newest.set(key, a);
  }
  return [...newest.values()].filter((a) => a.action_id in OPPOSITE);
}

