import type { Device, Snapshot } from "./types";

const base = "";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(base + path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${path}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

export const api = {
  status: () => get<Record<string, unknown>>("/api/status"),
  summary: () => get<Snapshot>("/api/summary"),
  device: (key: string) => get<Device>(`/api/devices/${encodeURIComponent(key)}`),
  timeline: (buckets = 90) => get<TimelineData>(`/api/timeline?buckets=${buckets}`),
  exposure: () => get<ExposureDetail>("/api/exposure"),
  capabilities: () => get<Record<string, unknown>>("/api/capabilities"),
  stored: () => get<StoredInfo>("/api/stored"),
  sessions: () => get<{ sessions: SessionRow[] }>("/api/sessions"),
  probePolicy: () => get<ProbePolicy>("/api/probe/policy"),

  label: (key: string, body: { label?: string | null; is_mine?: boolean; notes?: string }) =>
    post<{ ok: boolean; device?: Device }>(`/api/devices/${encodeURIComponent(key)}/label`, body),
  probe: (key: string) => post<ProbeResult>(`/api/devices/${encodeURIComponent(key)}/probe`),
  follow: (key: string) => post<{ ok: boolean; note: string }>(`/api/follow/${encodeURIComponent(key)}`),
  unfollow: () => post<{ ok: boolean }>("/api/unfollow"),
  acknowledge: (key: string) => post<{ ok: boolean }>(`/api/alerts/${encodeURIComponent(key)}/acknowledge`),
  purge: (keepLabels = true) => post<{ ok: boolean }>("/api/purge", { keep_labels: keepLabels }),
};

export interface TimelineData {
  start: number; end: number; buckets: number; bucket_seconds: number;
  rows: {
    key: string; label: string; category: string;
    first_bucket: number; last_bucket: number;
    first_seen: number; last_seen: number; packet_count: number; is_tracker: boolean;
  }[];
}

export interface ExposureDetail {
  total: number;
  bands: Record<string, number>;
  rotating: number; stable: number; named: number;
  plaintext_content: number; trackers: number; median_score: number;
  top_reasons: [string, number][];
  with_link_data: number; encrypted_links: number; plaintext_links: number;
  devices: {
    key: string; label: string; category: string;
    score: number; band: string; reasons: string[]; protections: string[];
  }[];
}

export interface StoredInfo {
  database_path?: string;
  size_human?: string;
  counts?: Record<string, number>;
  distinct_addresses?: number;
  oldest_observation?: number | null;
  newest_observation?: number | null;
  retention?: { observation_days: number; session_days: number; max_observations: number };
  note?: string;
}

export interface SessionRow {
  id: number; name: string; started_at: number; ended_at: number | null;
  duration: number; device_count: number; observation_count: number; backend: string;
}

export interface ProbePolicy {
  enabled: boolean;
  allowlist_only: boolean;
  warning: string;
  allowlisted: string[];
}

export interface ProbeResult {
  address: string; success: boolean; duration: number;
  error: string | null; remedy: string | null; warning: string; summary: string;
  device_info: Record<string, string>;
  services: {
    uuid: string; name: string | null;
    characteristics: { uuid: string; name: string | null; properties: string[]; value?: string }[];
  }[];
}

/** WebSocket with automatic reconnection and a visible connection state. */
export function connect(handlers: {
  onSnapshot: (s: Snapshot) => void;
  onMessage: (m: WsMessage) => void;
  onState: (s: "connecting" | "live" | "offline") => void;
}): () => void {
  let socket: WebSocket | null = null;
  let timer: number | undefined;
  let closed = false;
  let backoff = 500;

  const open = () => {
    if (closed) return;
    handlers.onState("connecting");
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    socket = new WebSocket(`${proto}//${location.host}/ws`);

    socket.onopen = () => {
      backoff = 500;
      handlers.onState("live");
    };
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data) as WsMessage;
      if (message.type === "snapshot") handlers.onSnapshot(message as unknown as Snapshot);
      else handlers.onMessage(message);
    };
    socket.onclose = () => {
      if (closed) return;
      handlers.onState("offline");
      timer = window.setTimeout(open, backoff);
      backoff = Math.min(backoff * 2, 8000);
    };
    socket.onerror = () => socket?.close();
  };

  open();
  return () => {
    closed = true;
    window.clearTimeout(timer);
    socket?.close();
  };
}

export type WsMessage =
  | { type: "packet"; at: number; packet: import("./types").PacketRow }
  | { type: "devices"; at: number; devices: Device[]; stats: import("./types").Stats }
  | { type: "alerts"; at: number; alerts: import("./types").Alert[] }
  | { type: "link_event"; at: number; event: import("./types").LinkEventRow }
  | { type: "backend_status"; at: number; status: { state: string; detail: string } }
  | { type: "retired"; at: number; keys: string[] }
  | { type: "merged"; at: number; removed: string[]; links: number }
  | { type: "snapshot"; at: number } & Snapshot;
