import { useEffect, useState } from "react";
import { api, type ProbePolicy, type ProbeResult } from "../api";
import { CATEGORY_COLOR } from "../palette";
import type { BackendInfo, ByteProfile, Device } from "../types";
import { formatDuration } from "./Inventory";

/**
 * Everything known about one device, with the reasoning always visible.
 *
 * The rule the whole panel is built to enforce: a guess must look like a
 * guess. The label carries its confidence, the runners-up are listed, and the
 * evidence behind every candidate is one click away and written in terms of
 * what was actually observed.
 */
export function DeviceDetail({
  deviceKey,
  onClose,
  onFollow,
  backend,
}: {
  deviceKey: string;
  onClose: () => void;
  onFollow: (key: string) => void;
  backend: BackendInfo | null;
}) {
  const [device, setDevice] = useState<Device | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [policy, setPolicy] = useState<ProbePolicy | null>(null);
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [labelDraft, setLabelDraft] = useState("");

  useEffect(() => {
    let alive = true;
    setDevice(null); setError(null); setProbeResult(null); setProbeError(null);
    const load = () =>
      api.device(deviceKey)
        .then((d) => { if (alive) { setDevice(d); setLabelDraft(d.user_label ?? ""); } })
        .catch((e) => alive && setError(String(e)));
    load();
    const timer = window.setInterval(load, 2500);
    api.probePolicy().then((p) => alive && setPolicy(p)).catch(() => {});
    return () => { alive = false; window.clearInterval(timer); };
  }, [deviceKey]);

  if (error) {
    return (
      <aside className="detail">
        <header><h2>Device gone</h2><button onClick={onClose}>close</button></header>
        <div className="body prose">
          This device is no longer in the live view — it stopped advertising and was
          retired. Its history is still in the database.
        </div>
      </aside>
    );
  }
  if (!device) return <aside className="detail"><div className="body dim">Loading…</div></aside>;

  const ident = device.identification;
  const canFollow = backend?.capabilities.connection_following ?? false;
  const canProbe = policy?.enabled ?? false;
  const probeBlocked = canProbe && policy?.allowlist_only && !device.is_mine;

  return (
    <aside className="detail">
      <header>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h2 style={{ color: CATEGORY_COLOR[device.category] }}>{device.display_name}</h2>
          <div className="tiny dim mono">
            {device.address} · {device.address_type.replace(/_/g, " ")}
            {device.address_is_rotating && " · rotating"}
          </div>
          <div style={{ marginTop: 5, display: "flex", gap: 5, flexWrap: "wrap" }}>
            <span className="chip">{device.category}</span>
            {ident?.is_guess && ident.best && (
              <span className="chip guess">{ident.best.confidence} confidence</span>
            )}
            {!ident?.is_guess && <span className="chip good">your label</span>}
            {device.is_tracker && <span className="chip tracker">tracker</span>}
            {device.is_mine && <span className="chip good">mine</span>}
            <span className={`chip band-${device.exposure.band.replace(" ", "-")}`}>
              {device.exposure.band}
            </span>
          </div>
        </div>
        <button onClick={onClose}>close</button>
      </header>

      <div className="body">
        {device.english && <p className="prose" style={{ margin: 0 }}>{device.english}</p>}

        {/* ---- identification ------------------------------------------- */}
        <section className="card">
          <h3>why we think this</h3>
          {!ident?.best && <div className="dim tiny">Nothing matched. This device is unidentified.</div>}
          {ident?.best && (
            <>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                <b>{ident.best.label}</b>
                <span className="dim tiny">
                  {ident.best.confidence} · {Math.round(ident.best.score * 100)}% · via {ident.best.matcher}
                </span>
              </div>
              <ul className="evidence">
                {ident.best.evidence.map((e, i) => <li key={i}>{e.observation}</li>)}
              </ul>
              {ident.runners_up.length > 0 && (
                <details style={{ marginTop: 10 }}>
                  <summary>it could also be {ident.runners_up.length} other things</summary>
                  <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 10 }}>
                    {ident.runners_up.map((g, i) => (
                      <div key={i}>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span>{g.label}</span>
                          <span className="dim tiny">{g.confidence} · {Math.round(g.score * 100)}%</span>
                        </div>
                        <ul className="evidence">
                          {g.evidence.slice(0, 3).map((e, j) => <li key={j}>{e.observation}</li>)}
                        </ul>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </>
          )}
          <div className="actions" style={{ marginTop: 12 }}>
            <input
              value={labelDraft}
              placeholder="disagree? name it yourself"
              onChange={(e) => setLabelDraft(e.target.value)}
              style={{ flex: 1, minWidth: 160 }}
            />
            <button onClick={() => api.label(device.key, { label: labelDraft || null })}>
              save
            </button>
            <button
              aria-pressed={device.is_mine}
              onClick={() => api.label(device.key, { is_mine: !device.is_mine })}
            >
              {device.is_mine ? "mine ✓" : "this is mine"}
            </button>
          </div>
          <div className="dim tiny" style={{ marginTop: 5 }}>
            Your label overrides the guess and persists across sessions.
          </div>
        </section>

        {/* ---- signal ---------------------------------------------------- */}
        <section className="card">
          <h3>signal and behaviour</h3>
          <Sparkline history={device.rssi_history} />
          <dl style={{ marginTop: 8 }}>
            <dt>proximity</dt>
            <dd>{device.proximity} <span className="dim">({device.rssi_smoothed ?? "?"} dBm, range {device.rssi_min ?? "?"} to {device.rssi_max ?? "?"})</span></dd>
            <dt>advertising rate</dt><dd className="num">{device.advertising_rate.toFixed(2)} /s</dd>
            <dt>packets</dt><dd className="num">{device.packet_count}</dd>
            <dt>here for</dt><dd>{formatDuration(device.duration)}</dd>
            {device.tx_power !== null && <><dt>TX power</dt><dd className="num">{device.tx_power} dBm</dd></>}
            {device.appearance_name && <><dt>appearance</dt><dd>{device.appearance_name}</dd></>}
            {device.connectable !== null && <><dt>connectable</dt><dd>{device.connectable ? "yes" : "no"}</dd></>}
            {Object.keys(device.channels).length > 0 && (
              <><dt>channels</dt><dd className="num">{Object.entries(device.channels).map(([c, n]) => `${c}:${n}`).join("  ")}</dd></>
            )}
          </dl>
        </section>

        {/* ---- exposure -------------------------------------------------- */}
        <section className="card">
          <h3>exposure — {device.exposure.band} ({device.exposure.score}/100)</h3>
          {device.exposure.reasons.length > 0 && (
            <ul className="evidence">
              {device.exposure.reasons.map((r, i) => <li key={i}>It {r}.</li>)}
            </ul>
          )}
          {device.exposure.protections.length > 0 && (
            <ul className="evidence" style={{ marginTop: 8 }}>
              {device.exposure.protections.map((r, i) => (
                <li key={i} style={{ borderLeftColor: "var(--signal-d)" }}>In its favour, it {r}.</li>
              ))}
            </ul>
          )}
        </section>

        {/* ---- continuity ------------------------------------------------ */}
        <section className="card">
          <h3>identity over time</h3>
          <p className="prose tiny" style={{ margin: 0 }}>{device.continuity_note}</p>
          {device.addresses_seen.length > 1 && (
            <>
              <div style={{ marginTop: 8 }} className="tiny">
                <b>{device.addresses_seen.length} addresses</b> linked at{" "}
                <b>{Math.round(device.continuity_confidence * 100)}%</b> confidence — an
                inference, not a certainty:
              </div>
              <div className="mono tiny dim" style={{ marginTop: 4 }}>
                {device.addresses_seen.join("  ")}
              </div>
              <ul className="evidence" style={{ marginTop: 8 }}>
                {device.continuity_evidence.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </>
          )}
          {device.history && device.history.length > 0 && (
            <div className="tiny" style={{ marginTop: 10 }}>
              Seen in {device.history.length} recorded session
              {device.history.length === 1 ? "" : "s"}:{" "}
              <span className="dim">
                {device.history.slice(0, 5).map((h) => h.session_name).join(", ")}
              </span>
            </div>
          )}
        </section>

        {/* ---- decode ---------------------------------------------------- */}
        {device.last_advertisement && (
          <section className="card">
            <h3>latest advertisement</h3>
            {device.last_advertisement.structures.map((s, i) => (
              <div key={i} style={{ marginBottom: 10 }}>
                <div className="tiny">
                  <span className="dim mono">0x{s.type_code.toString(16).padStart(2, "0").toUpperCase()}</span>{" "}
                  <b>{s.type_name}</b>{" "}
                  <span className="dim">[{s.data.length / 2} bytes]</span>
                </div>
                <dl style={{ marginTop: 3 }}>
                  {s.fields.map((f, j) => (
                    <div key={j} style={{ display: "contents" }}>
                      <dt>{f.name}</dt>
                      <dd>
                        {formatValue(f.value)}
                        {f.note && <span className="dim"> — {f.note}</span>}
                      </dd>
                    </div>
                  ))}
                </dl>
                {s.decodings.map((d, j) => (
                  <div key={j} style={{ marginTop: 6, borderLeft: "2px solid var(--signal-d)", paddingLeft: 9 }}>
                    <div style={{ color: "var(--signal)" }}>{d.summary}</div>
                    {d.english && <p className="prose tiny" style={{ margin: "3px 0 0" }}>{d.english}</p>}
                    {d.fields.length > 0 && (
                      <details style={{ marginTop: 5 }}>
                        <summary>fields</summary>
                        <dl style={{ marginTop: 4 }}>
                          {d.fields.map((f, k) => (
                            <div key={k} style={{ display: "contents" }}>
                              <dt>{f.name}</dt>
                              <dd>
                                {formatValue(f.value)}
                                {f.note && <span className="dim"> — {f.note}</span>}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </details>
                    )}
                    {d.tags.length > 0 && (
                      <div className="tiny dim" style={{ marginTop: 4 }}>{d.tags.join(" · ")}</div>
                    )}
                  </div>
                ))}
              </div>
            ))}
            {device.last_advertisement.parse_errors.map((e, i) => (
              <div key={i} className="tiny" style={{ color: "var(--warn)" }}>! {e}</div>
            ))}
          </section>
        )}

        {/* ---- raw bytes -------------------------------------------------- */}
        {device.byte_profiles && device.byte_profiles.length > 0 && (
          <section className="card">
            <h3>raw bytes — which ones change</h3>
            <p className="prose tiny" style={{ marginTop: 0 }}>{device.volatility_summary}</p>
            <div className="hex">
              {device.byte_profiles.map((p) => (
                <b key={p.offset} className={`b-${p.classification}`} title={`offset ${p.offset} · ${p.classification} · ${p.distinct} distinct values`}>
                  {p.hex}{" "}
                </b>
              ))}
            </div>
            <div className="tiny dim" style={{ marginTop: 8, display: "flex", gap: 12, flexWrap: "wrap" }}>
              <span className="b-stable">stable = identifier</span>
              <span className="b-counter">counter</span>
              <span className="b-slow">changes slowly</span>
              <span className="b-volatile">changes constantly = nonce, crypto or a live reading</span>
            </div>
            <button
              style={{ marginTop: 8 }}
              onClick={() => navigator.clipboard?.writeText(
                (device.byte_profiles ?? []).map((p: ByteProfile) => p.hex).join(""),
              )}
            >
              copy raw hex
            </button>
          </section>
        )}

        {/* ---- link events ------------------------------------------------ */}
        {device.link_events && device.link_events.length > 0 && (
          <section className="card">
            <h3>connection traffic</h3>
            {device.link_events.slice(-40).map((e, i) => (
              <div key={i} style={{ padding: "3px 0", borderBottom: "1px solid var(--line)" }}>
                <div className="tiny">
                  <span className="dim mono">
                    {new Date(e.timestamp * 1000).toLocaleTimeString([], { hour12: false })}
                  </span>{" "}
                  <span className="dim">{e.kind}</span>{" "}
                  <span style={{ color: e.encrypted ? "var(--muted)" : "var(--signal)" }}>{e.summary}</span>
                </div>
              </div>
            ))}
          </section>
        )}

        {/* ---- actions ----------------------------------------------------- */}
        <section className="card">
          <h3>actions</h3>
          <div className="actions">
            <button disabled={!canFollow} onClick={() => onFollow(device.key)}>
              aim the sniffer at this device
            </button>
            <button
              disabled={!canProbe || probeBlocked || probing}
              onClick={async () => {
                setProbing(true); setProbeError(null);
                try { setProbeResult(await api.probe(device.key)); }
                catch (e) { setProbeError(String(e)); }
                finally { setProbing(false); }
              }}
            >
              {probing ? "probing…" : "probe (transmits)"}
            </button>
          </div>
          {!canFollow && (
            <div className="dim tiny" style={{ marginTop: 6 }}>
              Following a connection needs sniffer hardware — a host adapter cannot
              hop the data channels.
            </div>
          )}
          {!canProbe && (
            <div className="dim tiny" style={{ marginTop: 6 }}>
              Active probing is off. Start the service with <span className="mono">--allow-probe</span> to enable it.
            </div>
          )}
          {probeBlocked && (
            <div className="tiny" style={{ marginTop: 6, color: "var(--warn)" }}>
              Allowlist mode is on and this device is not marked as yours. Mark it as
              mine above to allow probing it.
            </div>
          )}
          {canProbe && !probeBlocked && (
            <div className="tiny" style={{ marginTop: 6, color: "var(--warn)" }}>{policy?.warning}</div>
          )}
          {probeError && <div className="tiny" style={{ marginTop: 6, color: "var(--alarm)" }}>{probeError}</div>}
          {probeResult && (
            <div style={{ marginTop: 10 }}>
              <div className="tiny">{probeResult.summary}</div>
              {Object.entries(probeResult.device_info).length > 0 && (
                <dl style={{ marginTop: 6 }}>
                  {Object.entries(probeResult.device_info).map(([k, v]) => (
                    <div key={k} style={{ display: "contents" }}><dt>{k}</dt><dd>{v}</dd></div>
                  ))}
                </dl>
              )}
              <details style={{ marginTop: 8 }}>
                <summary>{probeResult.services.length} services</summary>
                {probeResult.services.map((s) => (
                  <div key={s.uuid} style={{ marginTop: 6 }}>
                    <div className="tiny"><b>{s.name || s.uuid}</b> <span className="dim mono">{s.uuid}</span></div>
                    {s.characteristics.map((c) => (
                      <div key={c.uuid} className="tiny dim" style={{ paddingLeft: 12 }}>
                        {c.name || c.uuid} <span className="mono">{c.properties.join(",")}</span>
                        {c.value && <span style={{ color: "var(--signal)" }}> = {c.value}</span>}
                      </div>
                    ))}
                  </div>
                ))}
              </details>
            </div>
          )}
        </section>
      </div>
    </aside>
  );
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "none";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function Sparkline({ history }: { history: [number, number][] }) {
  if (history.length < 2) return <div className="dim tiny">Not enough readings yet.</div>;
  const w = 240, h = 40;
  const values = history.map(([, r]) => r);
  const min = Math.min(...values, -100);
  const max = Math.max(...values, -30);
  const points = history.map(([, r], i) => {
    const x = (i / (history.length - 1)) * w;
    const y = h - ((r - min) / Math.max(1, max - min)) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const last = history[history.length - 1][1];
  return (
    <svg className="sparkline" viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none">
      <polyline points={`0,${h} ${points.join(" ")} ${w},${h}`} fill="rgba(76,224,179,.08)" stroke="none" />
      <polyline points={points.join(" ")} fill="none" stroke="var(--signal)" strokeWidth="1.2" />
      <circle
        cx={w}
        cy={h - ((last - min) / Math.max(1, max - min)) * h}
        r="2.5"
        fill="var(--signal)"
      />
    </svg>
  );
}
