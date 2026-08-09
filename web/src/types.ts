export type Category =
  | "phone" | "computer" | "wearable" | "audio" | "tracker" | "beacon"
  | "appliance" | "sensor" | "vehicle" | "medical" | "peripheral"
  | "network" | "unknown";

export type Proximity = "immediate" | "near" | "far" | "distant";
export type Confidence = "certain" | "high" | "medium" | "low";

export interface Evidence { observation: string; weight: number }

export interface Guess {
  label: string;
  confidence: Confidence;
  evidence: Evidence[];
  category: Category;
  vendor: string | null;
  matcher: string;
  score: number;
}

export interface Identification {
  best: Guess | null;
  runners_up: Guess[];
  user_label: string | null;
  display_label: string;
  category: Category;
  is_guess: boolean;
}

export interface Exposure {
  score: number;
  band: "wide open" | "chatty" | "guarded" | "closed";
  material: "glass" | "opaque";
  reasons: string[];
  protections: string[];
}

export interface DecodedField {
  name: string;
  value: unknown;
  offset: number | null;
  length: number | null;
  note: string | null;
}

export interface Decoding {
  protocol: string;
  summary: string;
  fields: DecodedField[];
  english: string;
  category: Category | null;
  tags: string[];
}

export interface ADStructure {
  type_code: number;
  type_name: string;
  data: string;
  offset: number;
  fields: DecodedField[];
  decodings: Decoding[];
}

export interface ParsedAdvertisement {
  advertisement: {
    address: string; timestamp: number; rssi: number | null;
    address_type: string; raw: string; channel: number | null;
    pdu_type: string; phy: string; scan_response: boolean;
    connectable: boolean | null; source: string;
  };
  structures: ADStructure[];
  local_name: string | null;
  tx_power: number | null;
  appearance_name: string | null;
  company_names: string[];
  service_uuids: string[];
  service_names: string[];
  flags: string[];
  trailing: string;
  parse_errors: string[];
  protocols: string[];
}

export interface ByteProfile {
  offset: number; value: number; hex: string;
  distinct: number; volatility: number;
  classification: "stable" | "slow" | "counter" | "volatile";
}

export interface Device {
  key: string;
  address: string;
  address_type: string;
  address_is_rotating: boolean;
  addresses_seen: string[];
  continuity_confidence: number;
  continuity_evidence: string[];
  first_seen: number;
  last_seen: number;
  duration: number;
  packet_count: number;
  rssi: number | null;
  rssi_smoothed: number | null;
  rssi_min: number | null;
  rssi_max: number | null;
  rssi_history: [number, number][];
  proximity: Proximity;
  advertising_rate: number;
  names: string[];
  display_name: string;
  service_uuids: string[];
  service_names: string[];
  company_names: string[];
  appearance_name: string | null;
  tx_power: number | null;
  flags: string[];
  connectable: boolean | null;
  protocols: Record<string, number>;
  tags: Record<string, number>;
  channels: Record<string, number>;
  category: Category;
  is_tracker: boolean;
  is_mine: boolean;
  user_label: string | null;
  notes: string | null;
  sources: string[];
  identification: Identification | null;
  exposure: Exposure;
  radar_angle: number;
  stable_hash: number;
  link_event_count: number;
  encrypted_link_seen: boolean;
  plaintext_link_seen: boolean;
  // present only on the detail endpoint
  english?: string;
  continuity_note?: string;
  last_advertisement?: ParsedAdvertisement | null;
  byte_profiles?: ByteProfile[];
  volatility_summary?: string;
  history?: { session_id: number; session_name: string; first_seen: number; last_seen: number }[];
  link_events?: LinkEventRow[];
}

export interface PacketRow {
  /** Client-assigned arrival sequence, unique within this page's session.
   *  Backends stamp a whole batch of reports with one timestamp, and a static
   *  beacon repeats an identical payload across channels, so timestamp +
   *  address + raw is not unique and cannot serve as a React key. */
  seq?: number;
  t: number;
  device_key: string;
  address: string;
  address_type: string;
  label: string;
  category: Category;
  rssi: number | null;
  channel: number | null;
  pdu_type: string;
  phy: string;
  length: number;
  raw: string;
  protocols: string[];
  summary: string;
  english: string;
  tags: string[];
}

export interface LinkEventRow {
  timestamp: number;
  kind: string;
  address: string | null;
  summary: string;
  detail: Record<string, unknown>;
  encrypted: boolean;
  direction: string | null;
  raw: string;
  device_key?: string | null;
  english?: string;
}

export interface Alert {
  key: string;
  device_key: string;
  level: "info" | "notable" | "attention";
  title: string;
  explanation: string;
  evidence: string[];
  false_positive_note: string;
  raised_at: number;
  sessions_seen: number;
  acknowledged: boolean;
}

export interface Capabilities {
  name: string;
  description: string;
  advertising: boolean;
  extended_advertising: boolean;
  real_mac_addresses: boolean;
  raw_payloads: boolean;
  scan_responses: boolean;
  connection_following: boolean;
  three_channel_advertising: boolean;
  coded_phy: boolean;
  two_m_phy: boolean;
  can_transmit: boolean;
  channel_reporting: boolean;
  caveats: string[];
}

export interface BackendInfo {
  name: string;
  capabilities: Capabilities;
  missing: string[];
  status: { state: string; detail: string; data: Record<string, unknown> };
  running: boolean;
}

export interface Stats {
  started_at: number; uptime: number; packets: number; link_events: number;
  dropped: number; parse_errors: number; devices_seen: number;
  last_packet_at: number | null; packets_per_second: number;
}

export interface Snapshot {
  devices: Device[];
  stats: Stats;
  alerts: Alert[];
  summary: string;
  exposure: ExposureSummary;
  backend: BackendInfo;
  session_id: number | null;
  feed?: PacketRow[];
  link_feed?: LinkEventRow[];
}

export interface ExposureSummary {
  total: number;
  bands: Record<string, number>;
  rotating: number;
  stable: number;
  named: number;
  plaintext_content: number;
  trackers: number;
  median_score: number;
  top_reasons: [string, number][];
  with_link_data: number;
  encrypted_links: number;
  plaintext_links: number;
  devices?: { key: string; label: string; category: Category } & Exposure[];
}
