import { useEffect, useRef, useState } from "react";
import type { Device } from "../types";
import { BAND_LABEL, BAND_RADIUS, CATEGORY_COLOR, radialPosition, withAlpha } from "../palette";

/**
 * The radar / proximity field.
 *
 * Two honesty constraints are structural here, not cosmetic:
 *
 *  1. Bluetooth carries no bearing information at all. Each device's angle
 *     comes from a hash of its identity, so it holds still frame to frame and
 *     is stable across sessions — but it means nothing. The view says so
 *     permanently, not in a dismissible tooltip.
 *  2. Signal strength does not convert reliably to metres, so the rings are
 *     labelled with coarse bands and no distance figure is ever drawn.
 *
 * Rendered on canvas with animated per-device state so several hundred
 * devices stay at 60fps.
 */

interface Sprite {
  key: string;
  angle: number;
  radius: number;     // target, 0..1
  drawnRadius: number; // eased
  color: string;
  label: string;
  category: string;
  rate: number;
  isTracker: boolean;
  rotating: boolean;
  isGuess: boolean;
  exposure: number;
  lastSeen: number;
  bornAt: number;
  pulse: number;
  alpha: number;
}

export function Radar({
  devices,
  onSelect,
  selected,
}: {
  devices: Device[];
  onSelect: (key: string) => void;
  selected: string | null;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const spritesRef = useRef<Map<string, Sprite>>(new Map());
  const devicesRef = useRef<Device[]>(devices);
  const selectedRef = useRef<string | null>(selected);
  const hoverRef = useRef<{ key: string; x: number; y: number } | null>(null);
  const [hover, setHover] = useState<{ device: Device; x: number; y: number } | null>(null);

  devicesRef.current = devices;
  selectedRef.current = selected;

  // Reconcile sprites with the live device list. New devices arrive with a
  // pulse; departed ones fade rather than vanishing, because a device blinking
  // out of existence reads as a glitch rather than as "it went quiet".
  useEffect(() => {
    const sprites = spritesRef.current;
    const now = performance.now();
    const live = new Set<string>();
    for (const d of devices) {
      live.add(d.key);
      const existing = sprites.get(d.key);
      const radius = radialPosition(d.proximity, d.rssi_smoothed);
      if (existing) {
        existing.radius = radius;
        existing.color = CATEGORY_COLOR[d.category] ?? CATEGORY_COLOR.unknown;
        existing.label = d.display_name;
        existing.category = d.category;
        existing.rate = d.advertising_rate;
        existing.isTracker = d.is_tracker;
        existing.rotating = d.address_is_rotating;
        existing.isGuess = d.identification?.is_guess ?? true;
        existing.exposure = d.exposure.score;
        existing.lastSeen = d.last_seen;
      } else {
        sprites.set(d.key, {
          key: d.key,
          angle: d.radar_angle,
          radius,
          drawnRadius: 1.05,
          color: CATEGORY_COLOR[d.category] ?? CATEGORY_COLOR.unknown,
          label: d.display_name,
          category: d.category,
          rate: d.advertising_rate,
          isTracker: d.is_tracker,
          rotating: d.address_is_rotating,
          isGuess: d.identification?.is_guess ?? true,
          exposure: d.exposure.score,
          lastSeen: d.last_seen,
          bornAt: now,
          pulse: 1,
          alpha: 0,
        });
      }
    }
    for (const [key, sprite] of sprites) if (!live.has(key)) sprite.alpha = -1; // fade out
  }, [devices]);

  useEffect(() => {
    const canvas = canvasRef.current!;
    const ctx = canvas.getContext("2d")!;
    let raf = 0;
    let running = true;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

    const draw = (t: number) => {
      if (!running) return;
      const dpr = Math.min(devicePixelRatio || 1, 2);
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const cx = w / 2;
      const cy = h / 2;
      const R = Math.min(w, h) / 2 - 46;
      const nowSec = Date.now() / 1000;

      // --- rings ---------------------------------------------------------
      ctx.lineWidth = 1;
      for (const band of ["immediate", "near", "far", "distant"] as const) {
        const [, outer] = BAND_RADIUS[band];
        ctx.strokeStyle = "#1B2430";
        ctx.beginPath();
        ctx.arc(cx, cy, R * outer, 0, Math.PI * 2);
        ctx.stroke();
        ctx.fillStyle = "#3B4756";
        ctx.font = "10px ui-monospace, monospace";
        ctx.textAlign = "center";
        ctx.fillText(BAND_LABEL[band], cx, cy - R * outer - 5);
      }

      // Radial guides, drawn faintly so they read as a grid and not as bearings.
      ctx.strokeStyle = "#141B24";
      for (let i = 0; i < 12; i++) {
        const a = (i / 12) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R);
        ctx.stroke();
      }

      // --- me at the centre ----------------------------------------------
      const breathe = reduce ? 0 : Math.sin(t / 700) * 1.6;
      ctx.strokeStyle = "#4CE0B3";
      ctx.globalAlpha = 0.75;
      ctx.beginPath();
      ctx.arc(cx, cy, 5 + breathe, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 0.22;
      ctx.beginPath();
      ctx.arc(cx, cy, 11 + breathe * 2, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.fillStyle = "#3B4756";
      ctx.font = "10px ui-monospace, monospace";
      ctx.fillText("you", cx, cy + 26);

      // --- devices ---------------------------------------------------------
      const sprites = spritesRef.current;
      const hoverKey = hoverRef.current?.key ?? null;
      const sel = selectedRef.current;

      for (const [key, s] of sprites) {
        // Ease radius so movement reads as drift rather than teleporting.
        s.drawnRadius += (s.radius - s.drawnRadius) * (reduce ? 1 : 0.06);
        if (s.alpha < 0) {
          s.alpha += 0.02;
          if (s.alpha >= -0.001) { sprites.delete(key); continue; }
        } else if (s.alpha < 1) {
          s.alpha = Math.min(1, s.alpha + 0.05);
        }
        const fade = s.alpha < 0 ? 1 + s.alpha : s.alpha;

        // Quiet devices dim. This is the single most useful ambient signal on
        // the whole view: you can see a room go still.
        const silence = nowSec - s.lastSeen;
        const liveness = Math.max(0.22, 1 - silence / 60);

        const x = cx + Math.cos(s.angle) * R * s.drawnRadius;
        const y = cy + Math.sin(s.angle) * R * s.drawnRadius;
        s.pulse = reduce ? 0 : Math.max(0, s.pulse - 0.012);

        const base = 3 + Math.min(5, Math.sqrt(Math.max(0, s.rate)) * 1.7);
        const size = base * (1 + s.pulse * 1.4);
        const isHover = key === hoverKey;
        const isSel = key === sel;

        // Advertising pulse: a ring that expands on the device's own rhythm.
        if (!reduce && s.rate > 0.05) {
          const period = 1000 / Math.min(6, Math.max(0.25, s.rate));
          const phase = ((t + s.bornAt) % period) / period;
          ctx.strokeStyle = withAlpha(s.color, (1 - phase) * 0.3 * fade * liveness);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(x, y, size + phase * 14, 0, Math.PI * 2);
          ctx.stroke();
        }

        if (s.isTracker) {
          // Trackers get a distinct silhouette so they are unmistakable.
          ctx.strokeStyle = withAlpha(s.color, fade);
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(x, y - size - 3);
          ctx.lineTo(x + size + 2, y);
          ctx.lineTo(x, y + size + 3);
          ctx.lineTo(x - size - 2, y);
          ctx.closePath();
          ctx.stroke();
          ctx.fillStyle = withAlpha(s.color, 0.3 * fade * liveness);
          ctx.fill();
        } else {
          ctx.fillStyle = withAlpha(s.color, fade * liveness);
          ctx.beginPath();
          ctx.arc(x, y, size, 0, Math.PI * 2);
          ctx.fill();
          if (s.rotating) {
            // A dashed outline for devices that rotate their address — you can
            // see at a glance how much of the room is trying not to be tracked.
            ctx.strokeStyle = withAlpha(s.color, 0.85 * fade);
            ctx.lineWidth = 1;
            ctx.setLineDash([2, 2]);
            ctx.beginPath();
            ctx.arc(x, y, size + 2.5, 0, Math.PI * 2);
            ctx.stroke();
            ctx.setLineDash([]);
          }
        }

        if (isSel || isHover) {
          ctx.strokeStyle = "#DCE4EE";
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(x, y, size + 6, 0, Math.PI * 2);
          ctx.stroke();
        }
        if (isSel || isHover || size > 6) {
          ctx.fillStyle = isSel || isHover ? "#DCE4EE" : withAlpha("#8C9BAD", fade * 0.85);
          ctx.font = "10.5px ui-monospace, monospace";
          ctx.textAlign = "left";
          const text = s.label.length > 26 ? s.label.slice(0, 25) + "…" : s.label;
          ctx.fillText(text + (s.isGuess ? " ?" : ""), x + size + 6, y + 3.5);
        }
      }

      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => { running = false; cancelAnimationFrame(raf); };
  }, []);

  const hitTest = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current!;
    const rect = canvas.getBoundingClientRect();
    const mx = event.clientX - rect.left;
    const my = event.clientY - rect.top;
    const cx = rect.width / 2;
    const cy = rect.height / 2;
    const R = Math.min(rect.width, rect.height) / 2 - 46;
    let best: { key: string; d: number } | null = null;
    for (const [key, s] of spritesRef.current) {
      if (s.alpha < 0) continue;
      const x = cx + Math.cos(s.angle) * R * s.drawnRadius;
      const y = cy + Math.sin(s.angle) * R * s.drawnRadius;
      const d = Math.hypot(mx - x, my - y);
      if (d < 16 && (!best || d < best.d)) best = { key, d };
    }
    return { key: best?.key ?? null, mx, my };
  };

  return (
    <div className="stage">
      <canvas
        ref={canvasRef}
        onMouseMove={(e) => {
          const { key, mx, my } = hitTest(e);
          hoverRef.current = key ? { key, x: mx, y: my } : null;
          const device = key ? devicesRef.current.find((d) => d.key === key) ?? null : null;
          setHover(device ? { device, x: mx, y: my } : null);
        }}
        onMouseLeave={() => { hoverRef.current = null; setHover(null); }}
        onClick={(e) => { const { key } = hitTest(e); if (key) onSelect(key); }}
      />

      <div className="overlay tl">
        <div className="honesty">
          <b>Angle here means nothing.</b> Bluetooth carries no direction
          information, so each device sits at an angle derived from a hash of its
          identity — stable frame to frame and across sessions, but arbitrary.
          Only distance from the centre is real, and it is a coarse band, never
          metres.
        </div>
      </div>

      <div className="overlay bl">
        <div className="legend">
          {(["phone", "computer", "audio", "wearable", "tracker", "beacon", "sensor",
             "appliance", "peripheral", "unknown"] as const).map((c) => (
            <span key={c}>
              <i style={{ background: CATEGORY_COLOR[c] }} />
              {c}
            </span>
          ))}
        </div>
        <div style={{ marginTop: 6, background: "rgba(8,11,16,.8)", padding: "4px 10px" }}>
          dashed ring = rotates its address · diamond = item tracker · dot size =
          how chatty · dimming = going quiet
        </div>
      </div>

      {hover && (
        <div
          className="tooltip"
          style={{
            left: Math.min(hover.x + 14, (canvasRef.current?.clientWidth ?? 800) - 340),
            top: hover.y + 14,
          }}
        >
          <b>{hover.device.display_name}</b>
          <div className="dim tiny">
            {hover.device.category} · {hover.device.proximity} ·{" "}
            {hover.device.rssi_smoothed ?? "?"} dBm ·{" "}
            {hover.device.advertising_rate.toFixed(1)}/s
          </div>
          <div className={`tiny band-${hover.device.exposure.band.replace(" ", "-")}`}>
            exposure: {hover.device.exposure.band}
          </div>
          {hover.device.identification?.is_guess && hover.device.identification.best && (
            <div className="tiny dim">
              best guess ({hover.device.identification.best.confidence} confidence) — click for
              the evidence
            </div>
          )}
        </div>
      )}
    </div>
  );
}
