import { useEffect, useState } from "react";
import { api, type TimelineData } from "../api";
import { CATEGORY_COLOR } from "../palette";
import type { Category } from "../types";

/** Who is permanent, who is passing through, who arrived when. */
export function Timeline({ onSelect }: { onSelect: (key: string) => void }) {
  const [data, setData] = useState<TimelineData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api.timeline(120)
        .then((d) => alive && setData(d))
        .catch((e) => alive && setError(String(e)));
    load();
    const timer = window.setInterval(load, 4000);
    return () => { alive = false; window.clearInterval(timer); };
  }, []);

  if (error) return <div className="pad dim">Could not load the timeline: {error}</div>;
  if (!data) return <div className="pad dim">Loading…</div>;
  if (data.rows.length === 0) return <div className="pad dim">Nothing observed yet.</div>;

  const rows = [...data.rows].sort((a, b) => a.first_seen - b.first_seen);
  const span = Math.max(1, data.end - data.start);
  const ticks = 6;

  return (
    <div className="pad">
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--line)" }}>
          <h3 style={{ margin: 0 }}>presence over time</h3>
          <div className="prose tiny" style={{ marginTop: 4 }}>
            Each bar is one device, from when it was first heard to when it was last
            heard. A bar spanning the whole width is something that lives here; a
            short one near the right is someone who just walked past.
          </div>
        </div>

        <div style={{ position: "relative", padding: "18px 14px 8px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
            {Array.from({ length: ticks + 1 }, (_, i) => (
              <span key={i} className="dim tiny num">
                {new Date((data.start + (span * i) / ticks) * 1000)
                  .toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
            ))}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {rows.map((r) => {
              const left = ((r.first_seen - data.start) / span) * 100;
              const width = Math.max(0.6, ((r.last_seen - r.first_seen) / span) * 100);
              const color = CATEGORY_COLOR[r.category as Category] ?? CATEGORY_COLOR.unknown;
              return (
                <div
                  key={r.key}
                  onClick={() => onSelect(r.key)}
                  title={`${r.label} — ${Math.round(r.last_seen - r.first_seen)}s, ${r.packet_count} packets`}
                  style={{
                    display: "grid", gridTemplateColumns: "min(220px, 26%) 1fr 4.5em",
                    gap: 10, alignItems: "center", cursor: "pointer", padding: "1px 0",
                  }}
                >
                  <span
                    style={{
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      fontSize: 11.5, color: r.is_tracker ? CATEGORY_COLOR.tracker : "var(--ink-dim)",
                    }}
                  >
                    {r.label}
                  </span>
                  <span style={{ position: "relative", height: 11, background: "var(--panel-2)" }}>
                    <span
                      style={{
                        position: "absolute", top: 0, bottom: 0,
                        left: `${left}%`, width: `${width}%`,
                        background: color, opacity: 0.85,
                      }}
                    />
                  </span>
                  <span className="dim tiny num" style={{ textAlign: "right" }}>
                    {r.packet_count}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
