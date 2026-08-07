import type { Category, Proximity } from "./types";

export const CATEGORY_COLOR: Record<Category, string> = {
  phone: "#4CC2E0",
  computer: "#5B8AD6",
  wearable: "#C77FE0",
  audio: "#E07FB8",
  tracker: "#E0604C",
  beacon: "#E0B84C",
  appliance: "#4CE0A0",
  sensor: "#96E04C",
  vehicle: "#4C6FE0",
  medical: "#E0D24C",
  peripheral: "#4CE0D2",
  network: "#8A9BD6",
  unknown: "#5C6B7D",
};

export const CATEGORY_ORDER: Category[] = [
  "phone", "computer", "wearable", "audio", "peripheral", "appliance",
  "sensor", "medical", "beacon", "tracker", "vehicle", "network", "unknown",
];

/** Radius of each proximity band, as a fraction of the radar's usable radius. */
export const BAND_RADIUS: Record<Proximity, [number, number]> = {
  immediate: [0.05, 0.26],
  near: [0.26, 0.50],
  far: [0.50, 0.74],
  distant: [0.74, 0.97],
};

export const BAND_LABEL: Record<Proximity, string> = {
  immediate: "immediate",
  near: "near",
  far: "far",
  distant: "distant",
};

/** RSSI limits used to position a device *within* its band. */
const BAND_RSSI: Record<Proximity, [number, number]> = {
  immediate: [-55, -20],
  near: [-70, -55],
  far: [-85, -70],
  distant: [-105, -85],
};

/**
 * Where to draw a device along the radius.
 *
 * The band is the honest part; the position inside the band is a smooth
 * interpolation of signal strength so devices drift rather than snapping
 * between four rings. Neither is metres, and the view says so.
 */
export function radialPosition(proximity: Proximity, rssi: number | null): number {
  const [inner, outer] = BAND_RADIUS[proximity];
  if (rssi === null) return outer;
  const [weak, strong] = BAND_RSSI[proximity];
  const t = Math.max(0, Math.min(1, (rssi - weak) / (strong - weak)));
  return outer - t * (outer - inner);
}

export function withAlpha(hex: string, alpha: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}

export function shade(hex: string, amount: number): string {
  const n = parseInt(hex.slice(1), 16);
  const f = (v: number) => Math.max(0, Math.min(255, Math.round(v * amount)));
  return `rgb(${f((n >> 16) & 255)}, ${f((n >> 8) & 255)}, ${f(n & 255)})`;
}

/** Deterministic 0..1 from an integer hash and a salt, for stable jitter. */
export function hashUnit(hash: number, salt: number): number {
  let x = (hash ^ (salt * 0x9e3779b9)) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b) >>> 0;
  return ((x ^ (x >>> 16)) >>> 0) / 4294967296;
}
