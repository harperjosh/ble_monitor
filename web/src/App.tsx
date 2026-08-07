import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, connect } from "./api";
import { Alerts, CapabilityPanel, StorePanel } from "./components/Panels";
import { City } from "./views/City";
import { DeviceDetail } from "./views/DeviceDetail";
import { ExposureView } from "./views/ExposureView";
import { Inventory } from "./views/Inventory";
import { Radar } from "./views/Radar";
import { Timeline } from "./views/Timeline";
import { Waterfall } from "./views/Waterfall";
import type { Alert, BackendInfo, Device, PacketRow, Stats } from "./types";

type Tab = "radar" | "city" | "waterfall" | "timeline" | "inventory" | "exposure" | "about";

const TABS: { id: Tab; label: string }[] = [
  { id: "radar", label: "radar" },
  { id: "city", label: "city" },
  { id: "waterfall", label: "waterfall" },
  { id: "timeline", label: "timeline" },
  { id: "inventory", label: "inventory" },
  { id: "exposure", label: "exposure" },
  { id: "about", label: "setup" },
];

const FEED_CAP = 1200;

export default function App() {
  const [tab, setTab] = useState<Tab>("radar");
  const [devices, setDevices] = useState<Map<string, Device>>(new Map());
  const [feed, setFeed] = useState<PacketRow[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [backend, setBackend] = useState<BackendInfo | null>(null);
  const [summary, setSummary] = useState("");
  const [link, setLink] = useState<"connecting" | "live" | "offline">("connecting");
  const [selected, setSelected] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  // Packets arrive at radio rate. Buffer them in a ref and flush to state a few
  // times a second, so an incoming packet does not re-render the whole app
  // hundreds of times per second (and copy the whole feed array each time).
  const feedBuffer = useRef<PacketRow[]>([]);

  useEffect(() => {
    return connect({
      onState: setLink,
      onSnapshot: (s) => {
        setDevices(new Map(s.devices.map((d) => [d.key, d])));
        // Only the initial snapshot carries the feed; the periodic sweep
        // snapshot omits it. Guarding here stops the live waterfall from being
        // wiped to empty every 10 seconds.
        if (s.feed) {
          feedBuffer.current = [];
          setFeed(s.feed);
        }
        setAlerts(s.alerts);
        setStats(s.stats);
        setBackend(s.backend);
        setSummary(s.summary);
      },
      onMessage: (m) => {
        switch (m.type) {
          case "packet":
            if (!pausedRef.current) {
              feedBuffer.current.push(m.packet);
            }
            break;
          case "devices":
            setStats(m.stats);
            setDevices((prev) => {
              const next = new Map(prev);
              for (const d of m.devices) next.set(d.key, d);
              return next;
            });
            break;
          case "retired":
            setDevices((prev) => {
              const next = new Map(prev);
              for (const k of m.keys) next.delete(k);
              return next;
            });
            break;
          case "merged":
            setDevices((prev) => {
              const next = new Map(prev);
              for (const k of m.removed) next.delete(k);
              return next;
            });
            break;
          case "alerts":
            setAlerts(m.alerts);
            break;
          case "backend_status":
            setBackend((b) => (b ? { ...b, status: { ...b.status, ...m.status } } : b));
            if (m.status.detail) setToast(m.status.detail);
            break;
        }
      },
    });
  }, []);

  // Flush the packet buffer into feed state at ~5 Hz. One re-render per flush
  // instead of one per packet.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (feedBuffer.current.length === 0) return;
      const incoming = feedBuffer.current;
      feedBuffer.current = [];
      setFeed((f) => {
        const merged = f.concat(incoming);
        return merged.length > FEED_CAP ? merged.slice(-FEED_CAP) : merged;
      });
    }, 200);
    return () => window.clearInterval(timer);
  }, []);

  // The room summary is cheap and only changes on the sweep, so poll it rather
  // than recomputing device statistics in the browser on every packet.
  useEffect(() => {
    const timer = window.setInterval(() => {
      api.summary().then((s) => { setSummary(s.summary); setBackend(s.backend); }).catch(() => {});
    }, 10_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 6000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const list = useMemo(
    () => [...devices.values()].sort((a, b) => (b.rssi_smoothed ?? -127) - (a.rssi_smoothed ?? -127)),
    [devices],
  );

  const unacked = useMemo(() => alerts.filter((a) => !a.acknowledged), [alerts]);

  const follow = useCallback(async (key: string) => {
    try {
      const res = await api.follow(key);
      setToast(res.note);
    } catch (e) {
      setToast(String(e));
    }
  }, []);

  const canFollow = backend?.capabilities.connection_following ?? false;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">ble<span>-monitor</span></div>
        <nav className="tabs">
          {TABS.map((t) => (
            <button key={t.id} aria-pressed={tab === t.id} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        <div className="spacer" />
        {stats && (
          <div className="readouts">
            <span><b>{devices.size}</b> devices</span>
            <span><b>{stats.packets_per_second}</b> pkt/s</span>
            <span><b>{stats.packets}</b> total</span>
            {unacked.length > 0 && (
              <span style={{ color: "var(--alarm)" }}>
                <b style={{ color: "var(--alarm)" }}>
                  {unacked.length}
                </b>{" "}
                alerts
              </span>
            )}
          </div>
        )}
        <div className="link-state">
          <i className={`dot ${link}`} />
          {link}
        </div>
      </header>

      <main>
        {tab === "radar" && (
          <Radar devices={list} onSelect={setSelected} selected={selected} />
        )}
        {tab === "city" && (
          <City
            devices={list}
            onSelect={setSelected}
            onFollow={follow}
            selected={selected}
            canFollow={canFollow}
          />
        )}
        {tab === "waterfall" && (
          <Waterfall
            packets={feed}
            onSelect={setSelected}
            paused={paused}
            onTogglePause={() => setPaused((p) => !p)}
          />
        )}
        {tab === "timeline" && <Timeline onSelect={setSelected} />}
        {tab === "inventory" && (
          <Inventory devices={list} onSelect={setSelected} selected={selected} />
        )}
        {tab === "exposure" && <ExposureView onSelect={setSelected} backend={backend} />}
        {tab === "about" && (
          <div className="pad grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", alignContent: "start" }}>
            <div className="card" style={{ gridColumn: "1 / -1" }}>
              <h3>the room right now</h3>
              <p className="prose" style={{ marginTop: 0 }}>{summary}</p>
            </div>
            <CapabilityPanel backend={backend} />
            <StorePanel />
            <div className="card">
              <h3>how BLE advertising actually works</h3>
              <p className="prose tiny">
                Every Bluetooth Low Energy device that wants to be findable shouts a
                short packet into the air a few times a second, on three fixed
                channels, to nobody in particular. That is what you are watching. It
                is entirely public — your phone receives thousands of these an hour
                and throws them away.
              </p>
              <p className="prose tiny">
                What a device puts in that packet is up to it. Some announce a name,
                a battery level and what their owner is doing. Others rotate a random
                identifier every fifteen minutes and say nothing else. The gap between
                those two is what the exposure view measures.
              </p>
              <p className="prose tiny">
                Once two devices actually <em>connect</em>, they stop using those three
                channels and start hopping across thirty-seven others in a pattern only
                they know. A normal Bluetooth adapter cannot follow that. Seeing what
                devices say to each other — rather than what they broadcast to everyone —
                is the one thing that needs dedicated sniffer hardware.
              </p>
            </div>
            <div className="card">
              <h3>alerts</h3>
              {unacked.length === 0 ? (
                <p className="prose tiny" style={{ margin: 0 }}>
                  Nothing to flag. Alerts appear here when a known tracker stays near you
                  for a sustained period, or an unidentified device with a rotating
                  address keeps turning up.
                </p>
              ) : (
                <Alerts alerts={alerts} onSelect={setSelected} />
              )}
            </div>
          </div>
        )}

        {unacked.length > 0 && tab !== "about" && (
          <div style={{ position: "absolute", top: 12, right: 12, width: "min(380px, 42vw)", zIndex: 15 }}>
            <Alerts alerts={alerts.slice(0, 2)} onSelect={setSelected} />
          </div>
        )}

        {selected && (
          <DeviceDetail
            deviceKey={selected}
            onClose={() => setSelected(null)}
            onFollow={follow}
            backend={backend}
          />
        )}

        {toast && (
          <div
            style={{
              position: "absolute", bottom: 16, left: "50%", transform: "translateX(-50%)",
              background: "var(--panel-2)", border: "1px solid var(--line-hi)",
              padding: "8px 14px", maxWidth: "min(70ch, 90vw)", zIndex: 40,
              fontFamily: "var(--sans)", fontSize: 12.5, color: "var(--ink-dim)",
            }}
          >
            {toast}
          </div>
        )}

        {link === "offline" && (
          <div
            style={{
              position: "absolute", inset: 0, display: "grid", placeItems: "center",
              background: "rgba(8,11,16,.86)", zIndex: 50, textAlign: "center", padding: 24,
            }}
          >
            <div>
              <div style={{ fontSize: 16, marginBottom: 8 }}>Lost the capture service</div>
              <p className="prose" style={{ margin: "0 auto" }}>
                The dashboard is a client of a capture service that is no longer
                answering. It reconnects automatically. If it does not come back, check
                the terminal running <span className="mono">blemon serve</span>.
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
