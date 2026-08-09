import { useMemo, useState } from "react";
import type { PacketRow } from "../types";
import { CATEGORY_COLOR } from "../palette";

/** Every advertisement as it lands. Wireshark, but legible. */
export function Waterfall({
  packets,
  onSelect,
  paused,
  onTogglePause,
}: {
  packets: PacketRow[];
  onSelect: (key: string) => void;
  paused: boolean;
  onTogglePause: () => void;
}) {
  const [filter, setFilter] = useState("");
  // Track the open row by a stable per-packet identity, not its array index —
  // the list is rebuilt newest-first on every incoming packet, so an index
  // would silently point at a different packet a moment after you expand one.
  // The arrival sequence is both stable and unique; content is not, because a
  // controller batches several reports under one timestamp and a static beacon
  // repeats the same payload on all three advertising channels.
  const [expanded, setExpanded] = useState<string | null>(null);
  const rowId = (p: PacketRow) => `${p.seq ?? `${p.t}-${p.address}-${p.raw}`}`;

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const list = needle
      ? packets.filter((p) =>
          `${p.label} ${p.address} ${p.summary} ${p.protocols.join(" ")} ${p.tags.join(" ")}`
            .toLowerCase()
            .includes(needle),
        )
      : packets;
    return list.slice(-400).reverse();
  }, [packets, filter]);

  return (
    <div style={{ display: "grid", gridTemplateRows: "auto 1fr", height: "100%" }}>
      <div
        style={{
          display: "flex", gap: 10, alignItems: "center", padding: "8px 12px",
          borderBottom: "1px solid var(--line)", background: "var(--panel)",
        }}
      >
        <input
          placeholder="filter by device, address, protocol or tag"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ flex: 1, maxWidth: 460 }}
        />
        <button onClick={onTogglePause} aria-pressed={paused}>
          {paused ? "resume" : "pause"}
        </button>
        <span className="dim tiny num">{rows.length} shown · {packets.length} buffered</span>
      </div>

      <div className="waterfall">
        {rows.length === 0 && (
          <div className="pad dim">
            {filter ? "Nothing matches that filter." : "Waiting for packets…"}
          </div>
        )}
        {rows.map((p, i) => {
          const time = new Date(p.t * 1000);
          const id = rowId(p);
          const isOpen = expanded === id;
          return (
            <div key={id}>
              <div
                className={`wf-row${i === 0 && !paused ? " new" : ""}`}
                onClick={() => setExpanded(isOpen ? null : id)}
              >
                <span className="wf-time">
                  {time.toLocaleTimeString([], { hour12: false })}
                </span>
                <span className="wf-rssi">{p.rssi ?? "—"}</span>
                <span className="wf-ch">{p.channel ? `${p.channel}` : ""}</span>
                <span
                  style={{ color: CATEGORY_COLOR[p.category] ?? CATEGORY_COLOR.unknown }}
                  title={p.address}
                >
                  {p.label}
                </span>
                <span>
                  {p.summary}
                  {p.english && <span className="wf-en"> — {p.english}</span>}
                </span>
              </div>
              {isOpen && (
                <div
                  style={{
                    padding: "10px 12px 14px 64px",
                    background: "var(--panel-2)",
                    borderBottom: "1px solid var(--line)",
                    display: "flex", flexDirection: "column", gap: 8,
                  }}
                >
                  <div className="prose">{p.english || "No plain-English decoding for this payload."}</div>
                  <dl style={{ display: "grid", gridTemplateColumns: "10em 1fr", gap: "2px 12px", margin: 0 }}>
                    <dt className="dim">address</dt><dd>{p.address} <span className="dim">({p.address_type})</span></dd>
                    <dt className="dim">pdu</dt><dd>{p.pdu_type} · {p.phy} PHY · {p.length} bytes</dd>
                    <dt className="dim">protocols</dt><dd>{p.protocols.join(", ") || "none decoded"}</dd>
                    {p.tags.length > 0 && (<><dt className="dim">tags</dt><dd>{p.tags.join(", ")}</dd></>)}
                    <dt className="dim">raw</dt>
                    <dd className="mono" style={{ overflowWrap: "anywhere" }}>
                      {p.raw.replace(/(..)/g, "$1 ").trim()}
                    </dd>
                  </dl>
                  <div>
                    <button onClick={() => onSelect(p.device_key)}>open device</button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
