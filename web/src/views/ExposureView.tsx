import { useEffect, useState } from "react";
import { api, type ExposureDetail } from "../api";
import { CATEGORY_COLOR } from "../palette";
import type { BackendInfo, Category } from "../types";

const BAND_COLOR: Record<string, string> = {
  "wide open": "#E0604C",
  chatty: "#E0A84C",
  guarded: "#4CC2E0",
  closed: "#4CE0B3",
};

/** The "how much of this is in the clear" answer. */
export function ExposureView({
  onSelect,
  backend,
}: {
  onSelect: (key: string) => void;
  backend: BackendInfo | null;
}) {
  const [data, setData] = useState<ExposureDetail | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () => api.exposure().then((d) => alive && setData(d)).catch(() => {});
    load();
    const timer = window.setInterval(load, 4000);
    return () => { alive = false; window.clearInterval(timer); };
  }, []);

  if (!data) return <div className="pad dim">Loading…</div>;
  if (data.total === 0) return <div className="pad dim">No devices observed yet.</div>;

  const bands = ["wide open", "chatty", "guarded", "closed"];
  const canSeeLinks = backend?.capabilities.connection_following ?? false;

  return (
    <div className="pad grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", alignContent: "start" }}>
      <div className="card" style={{ gridColumn: "1 / -1" }}>
        <h3>how open is this room</h3>
        <div style={{ display: "flex", height: 26, border: "1px solid var(--line-hi)" }}>
          {bands.map((b) => {
            const n = data.bands[b] ?? 0;
            if (!n) return null;
            return (
              <div
                key={b}
                title={`${n} ${b}`}
                style={{
                  flex: n, background: BAND_COLOR[b], opacity: 0.85,
                  display: "grid", placeItems: "center", fontSize: 10,
                  color: "#080B10", fontWeight: 600, minWidth: 0, overflow: "hidden",
                }}
              >
                {n}
              </div>
            );
          })}
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 8, flexWrap: "wrap" }}>
          {bands.map((b) => (
            <span key={b} className="tiny">
              <i style={{ display: "inline-block", width: 8, height: 8, background: BAND_COLOR[b], marginRight: 5 }} />
              <span style={{ color: BAND_COLOR[b] }}>{b}</span>{" "}
              <span className="dim num">{data.bands[b] ?? 0}</span>
            </span>
          ))}
        </div>
        <p className="prose tiny" style={{ marginTop: 10, marginBottom: 0 }}>
          Every device here is broadcasting to anyone who cares to listen. The
          question this view answers is how much each one gives away by doing so:
          a fixed identifier, a readable name, its own state, or actual
          measurements in plain text.
        </p>
      </div>

      <div className="card">
        <h3>identifiers</h3>
        <Stat label="rotate their address" value={data.rotating} total={data.total} good />
        <Stat label="fixed address — trackable indefinitely" value={data.stable} total={data.total} />
        <Stat label="broadcast a readable name" value={data.named} total={data.total} />
        <Stat label="publish readings or content in the clear" value={data.plaintext_content} total={data.total} />
        <Stat label="are item trackers" value={data.trackers} total={data.total} />
      </div>

      <div className="card">
        <h3>what they are giving away</h3>
        {data.top_reasons.length === 0 && <div className="dim tiny">Nothing notable.</div>}
        {data.top_reasons.map(([reason, count]) => (
          <div key={reason} style={{ display: "flex", gap: 10, alignItems: "baseline", padding: "2px 0" }}>
            <span className="num" style={{ color: "var(--warn)", minWidth: "2.4em", textAlign: "right" }}>
              {count}
            </span>
            <span className="prose tiny" style={{ margin: 0 }}>{reason}</span>
          </div>
        ))}
      </div>

      <div className="card">
        <h3>encrypted vs plaintext links</h3>
        {canSeeLinks ? (
          <>
            <Stat label="devices with observed connections" value={data.with_link_data} total={data.total} />
            <Stat label="seen encrypting their connections" value={data.encrypted_links} total={data.total} good />
            <Stat label="seen exchanging plaintext over a connection" value={data.plaintext_links} total={data.total} />
          </>
        ) : (
          <p className="prose tiny" style={{ margin: 0 }}>
            Real encrypted-versus-plaintext statistics need sniffer hardware. This
            capture backend only receives advertising packets, so everything above
            is about what devices <em>broadcast</em>, not what they say to each
            other once connected. Attach a sniffer and this panel fills in.
          </p>
        )}
      </div>

      <div className="card" style={{ gridColumn: "1 / -1", padding: 0 }}>
        <h3 style={{ padding: "12px 14px 8px", margin: 0 }}>every device, most exposed first</h3>
        <div className="scroll" style={{ maxHeight: 460 }}>
          <table>
            <thead>
              <tr>
                <th style={{ width: "5em", textAlign: "right" }}>score</th>
                <th style={{ width: "8em" }}>band</th>
                <th style={{ width: "16em" }}>device</th>
                <th>why</th>
              </tr>
            </thead>
            <tbody>
              {data.devices.map((d) => (
                <tr key={d.key} onClick={() => onSelect(d.key)}>
                  <td className="num" style={{ textAlign: "right", color: BAND_COLOR[d.band] }}>{d.score}</td>
                  <td style={{ color: BAND_COLOR[d.band] }}>{d.band}</td>
                  <td style={{ color: CATEGORY_COLOR[d.category as Category] ?? "var(--ink)" }}>{d.label}</td>
                  <td style={{ whiteSpace: "normal" }} className="prose tiny">
                    {d.reasons.length ? d.reasons.join("; ") : <span className="dim">nothing notable</span>}
                    {d.protections.length > 0 && (
                      <span style={{ color: "var(--signal)" }}> — but it {d.protections.join(" and ")}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, total, good }: { label: string; value: number; total: number; good?: boolean }) {
  const pct = total ? Math.round((value / total) * 100) : 0;
  return (
    <div style={{ padding: "3px 0" }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
        <span className="prose tiny" style={{ margin: 0 }}>{label}</span>
        <span className="num dim">{value} / {total}</span>
      </div>
      <div className="meter" style={{ marginTop: 3 }}>
        <i style={{ width: `${pct}%`, background: good ? "var(--signal)" : "var(--warn)" }} />
      </div>
    </div>
  );
}
