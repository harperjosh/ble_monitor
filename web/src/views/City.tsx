import { useEffect, useMemo, useRef, useState } from "react";
import type { Category, Device } from "../types";
import { CATEGORY_COLOR, CATEGORY_ORDER, hashUnit, shade, withAlpha } from "../palette";

/**
 * The city block view.
 *
 * The idea it is built around: a place should have a *skyline you can learn*.
 * Every device's plot is derived from a hash of its identity, so the same
 * device lands on the same lot every time — walk back into the same café and
 * the shape of the city is recognisable before you have read a single label.
 *
 *   height     advertising rate — chatty devices are skyscrapers
 *   footprint  how long it has been observed — persistent devices become landmarks
 *   district   category, as an angular sector
 *   distance   proximity band, as a radius from you at the centre
 *   lit        advertised in the last few seconds
 *   material   glass = broadcasting readable identity or content in the clear;
 *              opaque and shuttered = rotating address, minimal payload
 *
 * Canvas-rendered, back-to-front, so several hundred buildings hold 60fps.
 */

const GRID = 46;
const CENTER = GRID / 2;
const TILE_W = 38;
const TILE_H = 19;
const MAX_BUILDING_PX = 78;

const BAND_RING: Record<string, [number, number]> = {
  immediate: [1.6, 4.4],
  near: [4.4, 8.2],
  far: [8.2, 12.4],
  distant: [12.4, 17.0],
};

interface Lot { gx: number; gy: number }

function preferredLot(hash: number, category: Category, proximity: string): Lot {
  const sectorIndex = Math.max(0, CATEGORY_ORDER.indexOf(category));
  const sectorWidth = (Math.PI * 2) / CATEGORY_ORDER.length;
  // Keep a small margin inside each sector so districts stay visually distinct.
  const angle = sectorIndex * sectorWidth + sectorWidth * (0.12 + 0.76 * hashUnit(hash, 1));
  const [inner, outer] = BAND_RING[proximity] ?? BAND_RING.distant;
  const radius = inner + (outer - inner) * hashUnit(hash, 2);
  return {
    gx: Math.round(CENTER + Math.cos(angle) * radius),
    gy: Math.round(CENTER + Math.sin(angle) * radius),
  };
}

/** Deterministic outward spiral, so a contested lot resolves the same way. */
function* spiral(): Generator<[number, number]> {
  yield [0, 0];
  for (let ring = 1; ring < 8; ring++) {
    for (let dx = -ring; dx <= ring; dx++) {
      for (let dy = -ring; dy <= ring; dy++) {
        if (Math.max(Math.abs(dx), Math.abs(dy)) === ring) yield [dx, dy];
      }
    }
  }
}

interface Building {
  key: string; lot: Lot; device: Device;
  height: number; footprint: number;
  color: string; glass: boolean; lit: boolean;
  screenX: number; screenY: number;
}

export function City({
  devices,
  onSelect,
  onFollow,
  selected,
  canFollow,
}: {
  devices: Device[];
  onSelect: (key: string) => void;
  onFollow: (key: string) => void;
  selected: string | null;
  canFollow: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const lotsRef = useRef<Map<string, Lot>>(new Map());
  const occupiedRef = useRef<Map<string, string>>(new Map());
  const viewRef = useRef({ x: 0, y: 0, zoom: 1 });
  // The camera frames the occupied lots by itself until you touch it. An
  // empty-looking city because the default zoom happened to be wrong is a
  // worse failure than any amount of clever rendering.
  const userMovedRef = useRef(false);
  const dragRef = useRef<{ x: number; y: number } | null>(null);
  const [hover, setHover] = useState<{ device: Device; x: number; y: number } | null>(null);
  const hoverKeyRef = useRef<string | null>(null);
  const buildingsRef = useRef<Building[]>([]);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  // --- lot assignment ----------------------------------------------------
  // A lot, once granted, is kept for as long as the device is present, so the
  // skyline does not reshuffle underneath you.
  // Returns the building count; the buildings themselves live in a ref so the
  // animation loop can read them without resubscribing on every frame.
  const buildingCount = useMemo(() => {
    const lots = lotsRef.current;
    const occupied = occupiedRef.current;
    const live = new Set(devices.map((d) => d.key));
    for (const [key, lot] of lots) {
      if (!live.has(key)) { occupied.delete(`${lot.gx},${lot.gy}`); lots.delete(key); }
    }

    const maxRate = Math.max(1e-6, ...devices.map((d) => d.advertising_rate));
    const maxDuration = Math.max(1, ...devices.map((d) => d.duration));

    // Assign in hash order so the outcome does not depend on arrival order.
    const ordered = [...devices].sort((a, b) => a.stable_hash - b.stable_hash);
    for (const d of ordered) {
      if (lots.has(d.key)) continue;
      const want = preferredLot(d.stable_hash, d.category, d.proximity);
      for (const [dx, dy] of spiral()) {
        const gx = Math.max(0, Math.min(GRID - 1, want.gx + dx));
        const gy = Math.max(0, Math.min(GRID - 1, want.gy + dy));
        const cell = `${gx},${gy}`;
        if (!occupied.has(cell)) {
          occupied.set(cell, d.key);
          lots.set(d.key, { gx, gy });
          break;
        }
      }
    }

    const now = Date.now() / 1000;
    const out: Building[] = [];
    for (const d of devices) {
      const lot = lots.get(d.key);
      if (!lot) continue;
      out.push({
        key: d.key,
        lot,
        device: d,
        height: Math.min(1, Math.sqrt(d.advertising_rate / maxRate)),
        footprint: 0.42 + 0.5 * Math.min(1, d.duration / maxDuration),
        color: CATEGORY_COLOR[d.category] ?? CATEGORY_COLOR.unknown,
        glass: d.exposure.score >= 45,
        lit: now - d.last_seen < 5,
        screenX: 0,
        screenY: 0,
      });
    }
    // Painter's algorithm: back rows first.
    out.sort((a, b) => a.lot.gx + a.lot.gy - (b.lot.gx + b.lot.gy));
    buildingsRef.current = out;
    return out.length;
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
        canvas.width = w * dpr; canvas.height = h * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = "#080B10";
      ctx.fillRect(0, 0, w, h);

      const view = viewRef.current;
      if (!userMovedRef.current && buildingsRef.current.length > 0) {
        let uMin = Infinity, uMax = -Infinity, vMin = Infinity, vMax = -Infinity;
        for (const b of buildingsRef.current) {
          const u = b.lot.gx - b.lot.gy;
          const v = b.lot.gx - CENTER + (b.lot.gy - CENTER);
          uMin = Math.min(uMin, u); uMax = Math.max(uMax, u);
          vMin = Math.min(vMin, v); vMax = Math.max(vMax, v);
        }
        const spanX = Math.max(4, uMax - uMin + 3) * (TILE_W / 2);
        const spanY = Math.max(4, vMax - vMin + 3) * (TILE_H / 2) + MAX_BUILDING_PX;
        const fit = Math.min((w * 0.82) / spanX, (h * 0.74) / spanY);
        view.zoom = Math.max(0.4, Math.min(2.6, fit));
        view.x = -((uMin + uMax) / 2) * (TILE_W / 2) * view.zoom;
        view.y = -((vMin + vMax) / 2) * (TILE_H / 2) * view.zoom + MAX_BUILDING_PX * view.zoom * 0.34;
      }
      const ox = w / 2 + view.x;
      const oy = h / 2 + view.y;
      const tw = TILE_W * view.zoom;
      const th = TILE_H * view.zoom;

      const iso = (gx: number, gy: number) => ({
        x: ox + (gx - CENTER - (gy - CENTER)) * (tw / 2),
        y: oy + (gx - CENTER + (gy - CENTER)) * (th / 2),
      });

      // --- ground: proximity rings as concentric diamonds ------------------
      ctx.lineWidth = 1;
      for (const [band, [, outer]] of Object.entries(BAND_RING)) {
        ctx.strokeStyle = band === "immediate" ? "#22303D" : "#151D26";
        ctx.beginPath();
        for (let i = 0; i <= 64; i++) {
          const a = (i / 64) * Math.PI * 2;
          const p = iso(CENTER + Math.cos(a) * outer, CENTER + Math.sin(a) * outer);
          i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y);
        }
        ctx.closePath();
        ctx.stroke();
      }

      // --- you, at the centre ---------------------------------------------
      const me = iso(CENTER, CENTER);
      const breathe = reduce ? 0 : 1 + Math.sin(t / 800) * 0.35;
      ctx.strokeStyle = "#4CE0B3";
      ctx.globalAlpha = 0.8;
      ctx.beginPath();
      ctx.ellipse(me.x, me.y, 9 * view.zoom * breathe, 4.5 * view.zoom * breathe, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.fillStyle = "#3B4756";
      ctx.font = `${10 * Math.min(1.4, view.zoom)}px ui-monospace, monospace`;
      ctx.textAlign = "center";
      ctx.fillText("you", me.x, me.y + 18);

      // --- buildings -------------------------------------------------------
      const maxHeight = MAX_BUILDING_PX * view.zoom;
      const hoverKey = hoverKeyRef.current;
      const sel = selectedRef.current;

      for (const b of buildingsRef.current) {
        const base = iso(b.lot.gx, b.lot.gy);
        b.screenX = base.x;
        b.screenY = base.y;

        const halfW = (tw / 2) * b.footprint;
        const halfH = (th / 2) * b.footprint;
        const bh = 6 * view.zoom + b.height * maxHeight;
        const top = base.y - bh;
        const focused = b.key === hoverKey || b.key === sel;

        const face = b.glass ? 0.55 : 0.3;
        const leftCol = shade(b.color, face * 0.6);
        const rightCol = shade(b.color, face * 0.9);
        const topCol = shade(b.color, b.glass ? 1.0 : 0.62);

        // left face
        ctx.fillStyle = leftCol;
        ctx.beginPath();
        ctx.moveTo(base.x - halfW, base.y - halfH);
        ctx.lineTo(base.x, base.y);
        ctx.lineTo(base.x, top);
        ctx.lineTo(base.x - halfW, top - halfH);
        ctx.closePath();
        ctx.fill();

        // right face
        ctx.fillStyle = rightCol;
        ctx.beginPath();
        ctx.moveTo(base.x + halfW, base.y - halfH);
        ctx.lineTo(base.x, base.y);
        ctx.lineTo(base.x, top);
        ctx.lineTo(base.x + halfW, top - halfH);
        ctx.closePath();
        ctx.fill();

        // roof
        ctx.fillStyle = topCol;
        ctx.beginPath();
        ctx.moveTo(base.x, top - halfH * 2);
        ctx.lineTo(base.x + halfW, top - halfH);
        ctx.lineTo(base.x, top);
        ctx.lineTo(base.x - halfW, top - halfH);
        ctx.closePath();
        ctx.fill();

        // Glass buildings get bright edges; opaque ones stay matte. You can
        // read "how much of this city has its blinds open" from across the room.
        if (b.glass) {
          ctx.strokeStyle = withAlpha(b.color, 0.75);
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        // Lit windows: recent activity. Rows scale with height so a tall
        // chatty device genuinely looks busy.
        if (b.lit && bh > 14 * view.zoom && view.zoom > 0.55) {
          const rows = Math.max(1, Math.floor(bh / (9 * view.zoom)));
          ctx.fillStyle = withAlpha(b.glass ? "#DCE4EE" : b.color, b.glass ? 0.5 : 0.65);
          for (let r = 0; r < rows; r++) {
            const wy = top + 5 * view.zoom + r * 9 * view.zoom;
            if (wy > base.y - 4) break;
            for (let c = 0; c < 2; c++) {
              if (hashUnit(b.device.stable_hash, r * 7 + c * 31) < 0.42) continue;
              const wx = base.x - halfW * (0.62 - c * 0.34);
              ctx.fillRect(wx, wy + halfH * 0.5 * (0.62 - c * 0.34), 2.4 * view.zoom, 2.4 * view.zoom);
            }
          }
        }

        // Trackers get an unmistakable silhouette: a spire with a beacon.
        if (b.device.is_tracker) {
          ctx.strokeStyle = CATEGORY_COLOR.tracker;
          ctx.lineWidth = 1.4;
          ctx.beginPath();
          ctx.moveTo(base.x, top - halfH * 2);
          ctx.lineTo(base.x, top - halfH * 2 - 16 * view.zoom);
          ctx.stroke();
          const blink = reduce ? 1 : 0.45 + 0.55 * Math.abs(Math.sin(t / 420));
          ctx.fillStyle = withAlpha(CATEGORY_COLOR.tracker, blink);
          ctx.beginPath();
          ctx.arc(base.x, top - halfH * 2 - 18 * view.zoom, 2.6 * view.zoom, 0, Math.PI * 2);
          ctx.fill();
        }

        if (focused) {
          ctx.strokeStyle = "#DCE4EE";
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.moveTo(base.x, base.y);
          ctx.lineTo(base.x + halfW, base.y - halfH);
          ctx.lineTo(base.x, base.y - halfH * 2);
          ctx.lineTo(base.x - halfW, base.y - halfH);
          ctx.closePath();
          ctx.stroke();

          ctx.fillStyle = "#DCE4EE";
          ctx.font = `${11 * Math.min(1.3, view.zoom)}px ui-monospace, monospace`;
          ctx.textAlign = "center";
          ctx.fillText(b.device.display_name.slice(0, 30), base.x, top - halfH * 2 - 26 * view.zoom);
        }
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => { running = false; cancelAnimationFrame(raf); };
  }, []);

  const hitTest = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const mx = event.clientX - rect.left;
    const my = event.clientY - rect.top;
    // Front to back, so a building in front wins over one it occludes.
    for (let i = buildingsRef.current.length - 1; i >= 0; i--) {
      const b = buildingsRef.current[i];
      const zoom = viewRef.current.zoom;
      const halfW = (TILE_W * zoom / 2) * b.footprint;
      const bh = 6 * zoom + b.height * MAX_BUILDING_PX * zoom;
      if (mx >= b.screenX - halfW && mx <= b.screenX + halfW &&
          my >= b.screenY - bh - 12 && my <= b.screenY + 6) {
        return { key: b.key, device: b.device, mx, my };
      }
    }
    return { key: null, device: null, mx, my };
  };

  return (
    <div className="stage">
      <canvas
        ref={canvasRef}
        style={{ cursor: dragRef.current ? "grabbing" : "crosshair" }}
        onMouseDown={(e) => { if (e.button === 0) dragRef.current = { x: e.clientX, y: e.clientY }; }}
        onMouseUp={() => { dragRef.current = null; }}
        onMouseMove={(e) => {
          if (dragRef.current) {
            userMovedRef.current = true;
            viewRef.current.x += e.clientX - dragRef.current.x;
            viewRef.current.y += e.clientY - dragRef.current.y;
            dragRef.current = { x: e.clientX, y: e.clientY };
            return;
          }
          const { key, device, mx, my } = hitTest(e);
          hoverKeyRef.current = key;
          setHover(device ? { device, x: mx, y: my } : null);
        }}
        onMouseLeave={() => { dragRef.current = null; hoverKeyRef.current = null; setHover(null); }}
        onClick={(e) => { const { key } = hitTest(e); if (key) onSelect(key); }}
        onContextMenu={(e) => {
          e.preventDefault();
          const { key } = hitTest(e);
          if (key && canFollow) onFollow(key);
        }}
        onWheel={(e) => {
          userMovedRef.current = true;
          const v = viewRef.current;
          v.zoom = Math.max(0.35, Math.min(3, v.zoom * (e.deltaY < 0 ? 1.12 : 0.89)));
        }}
      />

      {buildingCount === 0 && (
        <div className="overlay tr" style={{ top: "50%", right: "50%", transform: "translate(50%, -50%)" }}>
          <span className="dim">No devices yet — the city is empty.</span>
        </div>
      )}

      <div className="overlay tl">
        <div className="honesty">
          <b>The plots are stable, the map is not a map.</b> Each device's lot
          comes from a hash of its identity, so the same device sits in the same
          place every session and a room you have visited before is
          recognisable. Direction is still meaningless — only distance from the
          centre, which is a coarse proximity band, carries information.
        </div>
      </div>

      <div className="overlay bl">
        <div className="legend" style={{ display: "block", lineHeight: 1.7 }}>
          <div><b style={{ color: "#8C9BAD" }}>height</b> advertising rate ·
            <b style={{ color: "#8C9BAD" }}> footprint</b> how long it has been here ·
            <b style={{ color: "#8C9BAD" }}> district</b> category ·
            <b style={{ color: "#8C9BAD" }}> distance</b> proximity</div>
          <div><b style={{ color: "#8C9BAD" }}>glass and lit edges</b> broadcasting readable
            identity or content in the clear · <b style={{ color: "#8C9BAD" }}>matte</b> rotating
            address, saying little · <b style={{ color: "#E0604C" }}>spire</b> item tracker</div>
          <div className="dim">drag to pan · scroll to zoom · click a building for
            detail{canFollow ? " · right-click to aim the sniffer at it" : ""}</div>
          <div style={{ pointerEvents: "auto", marginTop: 4 }}>
            <button onClick={() => { userMovedRef.current = false; }}>reset view</button>
          </div>
        </div>
      </div>

      {hover && (
        <div
          className="tooltip"
          style={{
            left: Math.min(hover.x + 14, (canvasRef.current?.clientWidth ?? 800) - 340),
            top: Math.max(8, hover.y - 60),
          }}
        >
          <b>{hover.device.display_name}</b>
          <div className="dim tiny">
            {hover.device.category} district · {hover.device.proximity} ·{" "}
            {hover.device.advertising_rate.toFixed(1)} adverts/s ·{" "}
            {Math.round(hover.device.duration)}s here
          </div>
          <div className={`tiny band-${hover.device.exposure.band.replace(" ", "-")}`}>
            {hover.device.exposure.score >= 45
              ? "glass — broadcasting in the clear"
              : "shuttered — rotating and saying little"}
          </div>
        </div>
      )}
    </div>
  );
}
