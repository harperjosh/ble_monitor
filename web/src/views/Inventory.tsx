import { useMemo, useState } from "react";
import type { Device } from "../types";
import { CATEGORY_COLOR } from "../palette";

type SortKey = "rssi" | "name" | "category" | "rate" | "packets" | "duration" | "exposure";

const COLUMNS: { key: SortKey; label: string; width?: string; right?: boolean }[] = [
  { key: "rssi", label: "signal", width: "5.5em", right: true },
  { key: "name", label: "device" },
  { key: "category", label: "category", width: "8em" },
  { key: "rate", label: "adv/s", width: "5em", right: true },
  { key: "packets", label: "packets", width: "6em", right: true },
  { key: "duration", label: "here for", width: "6em", right: true },
  { key: "exposure", label: "exposure", width: "8em" },
];

export function Inventory({
  devices,
  onSelect,
  selected,
}: {
  devices: Device[];
  onSelect: (key: string) => void;
  selected: string | null;
}) {
  const [sort, setSort] = useState<SortKey>("rssi");
  const [descending, setDescending] = useState(true);
  const [query, setQuery] = useState("");
  const [only, setOnly] = useState<"all" | "trackers" | "rotating" | "open" | "mine">("all");

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let list = devices.filter((d) => {
      if (only === "trackers" && !d.is_tracker) return false;
      if (only === "rotating" && !d.address_is_rotating) return false;
      if (only === "open" && d.exposure.score < 45) return false;
      if (only === "mine" && !d.is_mine) return false;
      if (!needle) return true;
      return `${d.display_name} ${d.address} ${d.names.join(" ")} ${d.service_uuids.join(" ")} ${d.company_names.join(" ")} ${Object.keys(d.protocols).join(" ")}`
        .toLowerCase()
        .includes(needle);
    });
    const value = (d: Device): number | string => {
      switch (sort) {
        case "rssi": return d.rssi_smoothed ?? -127;
        case "name": return d.display_name.toLowerCase();
        case "category": return d.category;
        case "rate": return d.advertising_rate;
        case "packets": return d.packet_count;
        case "duration": return d.duration;
        case "exposure": return d.exposure.score;
      }
    };
    list = [...list].sort((a, b) => {
      const va = value(a), vb = value(b);
      const cmp = typeof va === "string" ? String(va).localeCompare(String(vb)) : (va as number) - (vb as number);
      return descending ? -cmp : cmp;
    });
    return list;
  }, [devices, sort, descending, query, only]);

  const toggle = (key: SortKey) => {
    if (key === sort) setDescending((d) => !d);
    else { setSort(key); setDescending(key !== "name" && key !== "category"); }
  };

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto 1fr", height: "100%" }}>
      <div
        style={{
          display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap",
          padding: "8px 12px", borderBottom: "1px solid var(--line)", background: "var(--panel)",
        }}
      >
        <input
          placeholder="search name, address, service, vendor, protocol"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ flex: 1, minWidth: 240, maxWidth: 460 }}
        />
        {(["all", "trackers", "rotating", "open", "mine"] as const).map((f) => (
          <button key={f} aria-pressed={only === f} onClick={() => setOnly(f)}>
            {f === "open" ? "wide open" : f}
          </button>
        ))}
        <span className="dim tiny num">{rows.length} of {devices.length}</span>
      </div>

      <div className="scroll">
        <table>
          <thead>
            <tr>
              {COLUMNS.map((c) => (
                <th
                  key={c.key}
                  className={sort === c.key ? "sorted" : ""}
                  style={{ width: c.width, textAlign: c.right ? "right" : "left" }}
                  onClick={() => toggle(c.key)}
                >
                  {c.label}{sort === c.key ? (descending ? " ↓" : " ↑") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr
                key={d.key}
                className={selected === d.key ? "selected" : ""}
                onClick={() => onSelect(d.key)}
              >
                <td className="num" style={{ textAlign: "right" }}>{d.rssi_smoothed ?? "—"}</td>
                <td>
                  <span style={{ color: d.user_label ? "var(--signal)" : "var(--ink)" }}>
                    {d.display_name}
                  </span>
                  {d.identification?.is_guess && d.identification.best && (
                    <span className="chip guess" style={{ marginLeft: 6 }}>
                      {d.identification.best.confidence}
                    </span>
                  )}
                  {d.is_tracker && <span className="chip tracker" style={{ marginLeft: 6 }}>tracker</span>}
                  {d.is_mine && <span className="chip good" style={{ marginLeft: 6 }}>mine</span>}
                  <div className="dim tiny mono">
                    {d.address}{d.address_is_rotating ? " ~rotating" : ""}
                    {d.addresses_seen.length > 1 && ` · ${d.addresses_seen.length} addresses linked`}
                  </div>
                </td>
                <td style={{ color: CATEGORY_COLOR[d.category] }}>{d.category}</td>
                <td className="num" style={{ textAlign: "right" }}>{d.advertising_rate.toFixed(1)}</td>
                <td className="num" style={{ textAlign: "right" }}>{d.packet_count}</td>
                <td className="num" style={{ textAlign: "right" }}>{formatDuration(d.duration)}</td>
                <td className={`band-${d.exposure.band.replace(" ", "-")}`}>
                  {d.exposure.band}
                  <span className="dim num"> {d.exposure.score}</span>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={COLUMNS.length} className="dim" style={{ padding: 20 }}>
                Nothing matches.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}
