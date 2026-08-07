import { useEffect, useState } from "react";
import { api, type SessionRow, type StoredInfo } from "../api";
import type { Alert, BackendInfo } from "../types";

/** Tracker and persistence alerts, with the evidence and the caveat. */
export function Alerts({ alerts, onSelect }: { alerts: Alert[]; onSelect: (key: string) => void }) {
  const live = alerts.filter((a) => !a.acknowledged);
  if (live.length === 0) return null;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {live.map((a) => (
        <div key={a.key} className={`alert ${a.level}`}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
            <h4>{a.title}</h4>
            <button className="tiny" onClick={() => api.acknowledge(a.key)}>dismiss</button>
          </div>
          <p>{a.explanation}</p>
          <details>
            <summary>evidence</summary>
            <ul className="evidence" style={{ marginTop: 6 }}>
              {a.evidence.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          </details>
          {a.false_positive_note && <div className="fp">{a.false_positive_note}</div>}
          <div><button onClick={() => onSelect(a.device_key)}>open device</button></div>
        </div>
      ))}
    </div>
  );
}

const CAPABILITY_ROWS: [keyof BackendInfo["capabilities"], string][] = [
  ["advertising", "Advertising on channels 37/38/39"],
  ["extended_advertising", "BT5 extended advertising"],
  ["real_mac_addresses", "Real MAC addresses"],
  ["raw_payloads", "Unmodified raw payloads"],
  ["scan_responses", "Scan responses"],
  ["connection_following", "Connection following"],
  ["three_channel_advertising", "All three ad channels at once"],
  ["two_m_phy", "2M PHY"],
  ["coded_phy", "Long-range Coded PHY"],
  ["channel_reporting", "Per-packet channel numbers"],
  ["can_transmit", "Can transmit"],
];

/**
 * What this setup can and cannot see. Rendered verbatim from the backend's own
 * declaration — nothing in the rest of the interface is allowed to imply a
 * capability that reads "no" here.
 */
export function CapabilityPanel({ backend }: { backend: BackendInfo | null }) {
  if (!backend) return null;
  const caps = backend.capabilities;
  return (
    <div className="card">
      <h3>what this setup can see</h3>
      <div style={{ marginBottom: 8 }}>
        <b>{caps.name}</b>
        <div className="dim tiny">{caps.description}</div>
      </div>
      <table style={{ fontSize: 11.5 }}>
        <tbody>
          {CAPABILITY_ROWS.map(([key, label]) => (
            <tr key={key} style={{ cursor: "default" }}>
              <td style={{ whiteSpace: "normal" }}>{label}</td>
              <td style={{ width: "3em", textAlign: "right", color: caps[key] ? "var(--signal)" : "var(--alarm)" }}>
                {caps[key] ? "yes" : "no"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {caps.caveats.length > 0 && (
        <ul className="evidence" style={{ marginTop: 10 }}>
          {caps.caveats.map((c, i) => (
            <li key={i} style={{ borderLeftColor: "var(--warn)" }}>{c}</li>
          ))}
        </ul>
      )}
      {backend.status?.detail && (
        <div className="tiny dim" style={{ marginTop: 8 }}>
          <b>status:</b> {backend.status.detail}
        </div>
      )}
    </div>
  );
}

/** Exactly what is stored, and the one control that destroys it. */
export function StorePanel() {
  const [stored, setStored] = useState<StoredInfo | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [confirming, setConfirming] = useState(false);

  const reload = () => {
    api.stored().then(setStored).catch(() => {});
    api.sessions().then((s) => setSessions(s.sessions)).catch(() => {});
  };
  useEffect(reload, []);

  if (!stored) return null;
  if (stored.note && !stored.counts) {
    return <div className="card"><h3>storage</h3><p className="prose tiny" style={{ margin: 0 }}>{stored.note}</p></div>;
  }

  return (
    <div className="card">
      <h3>what is stored on this machine</h3>
      <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 12px", fontSize: 12 }}>
        <dt className="dim">database</dt><dd className="mono tiny" style={{ overflowWrap: "anywhere" }}>{stored.database_path}</dd>
        <dt className="dim">size</dt><dd className="num">{stored.size_human}</dd>
        <dt className="dim">observations</dt><dd className="num">{stored.counts?.observations ?? 0}</dd>
        <dt className="dim">device records</dt><dd className="num">{stored.counts?.devices ?? 0}</dd>
        <dt className="dim">distinct addresses</dt><dd className="num">{stored.distinct_addresses ?? 0}</dd>
        <dt className="dim">sessions</dt><dd className="num">{stored.counts?.sessions ?? 0}</dd>
        <dt className="dim">retention</dt>
        <dd>packets {stored.retention?.observation_days}d · sessions {stored.retention?.session_days}d</dd>
      </dl>
      <p className="prose tiny" style={{ marginTop: 8 }}>{stored.note}</p>

      {sessions.length > 0 && (
        <details style={{ marginTop: 8 }}>
          <summary>{sessions.length} recorded sessions</summary>
          <table style={{ marginTop: 6, fontSize: 11.5 }}>
            <thead><tr><th>id</th><th>name</th><th>when</th><th style={{ textAlign: "right" }}>devices</th><th style={{ textAlign: "right" }}>packets</th></tr></thead>
            <tbody>
              {sessions.slice(0, 12).map((s) => (
                <tr key={s.id} style={{ cursor: "default" }}>
                  <td className="num">{s.id}</td>
                  <td>{s.name}</td>
                  <td className="dim">{new Date(s.started_at * 1000).toLocaleString()}</td>
                  <td className="num" style={{ textAlign: "right" }}>{s.device_count}</td>
                  <td className="num" style={{ textAlign: "right" }}>{s.observation_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="dim tiny" style={{ marginTop: 6 }}>
            Replay one from the terminal:{" "}
            <span className="mono">blemon scan --backend replay --session-id N</span>
          </div>
        </details>
      )}

      <div className="actions" style={{ marginTop: 12 }}>
        <a className="chip" href="/api/export/devices.json" download>export devices (JSON)</a>
        <a className="chip" href="/api/export/devices.csv" download>CSV</a>
        <a className="chip" href="/api/export/devices.json?redact=true" download>JSON, addresses redacted</a>
      </div>
      <div className="actions" style={{ marginTop: 8 }}>
        {!confirming ? (
          <button onClick={() => setConfirming(true)}>purge everything</button>
        ) : (
          <>
            <button
              style={{ borderColor: "var(--alarm)", color: "var(--alarm)" }}
              onClick={async () => { await api.purge(true); setConfirming(false); reload(); }}
            >
              yes, delete all captured data
            </button>
            <button onClick={() => setConfirming(false)}>cancel</button>
          </>
        )}
      </div>
      {confirming && (
        <div className="tiny dim" style={{ marginTop: 6 }}>
          Your own device labels will be kept. Everything captured is destroyed.
        </div>
      )}
    </div>
  );
}
