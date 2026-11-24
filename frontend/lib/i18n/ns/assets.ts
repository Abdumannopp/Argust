import { defineMessages, plural } from "../core";

export const assets = defineMessages({
  en: {
    title: "Assets",
    summary: (devices: number, online: number) =>
      `${plural("en", devices, { one: `${devices} device`, other: `${devices} devices` })} · ${online} online`,
    searchPlaceholder: "Search devices by name",
    columns: {
      device: "Device",
      status: "Status",
      risk: "Risk",
      os: "OS",
      ip: "IP address",
    },
    intro: "Servers, endpoints, user accounts and cloud resources from every connected platform, in one list. An asset reported by several platforms appears once.",
    kinds: { all: "All", server: "Servers", endpoint: "Endpoints", user: "Users", cloud: "Cloud", unknown: "Not classified" },
    kind: { server: "Server", endpoint: "Endpoint", user: "User account", cloud: "Cloud resource", unknown: "Not classified" },
    reportedBy: (sources: string) => `Reported by ${sources}`,
    notApplicable: "Not applicable",
    online: "Online",
    offline: "Offline",
    empty: "No devices match this view.",
    loadError: "Couldn't reach the Argust API. Is the backend running?",
  },
});
