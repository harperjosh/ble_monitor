# ble-monitor — Project Brief

Build a BLE (Bluetooth Low Energy) environment monitor: a tool that makes the
invisible radio chatter saturating every public space visible, legible, and
understandable.

## The vision

Right now BLE traffic is completely invisible to me. I know it's there. I want to
see it. Success is going from "no idea what's happening around me" to "I can look
at a screen and genuinely understand what devices are near me, what they're
broadcasting, what they're saying to each other, and how much of it is exposed
versus protected." I want the veil lifted.

This is passive reception of public broadcasts — the same advertisements my phone
receives and discards thousands of times a day. Build it as an instrument for
understanding my own radio environment.

Build the complete scope in one pass, but architect deliberately for expansion:
capture backends, protocol decoders, identification rules, and dashboard views
should all be registry-driven plugin points, so adding a new decoder or a new
visualization later is a small additive change and never a refactor.

## Target platforms

macOS and Linux (Raspberry Pi). Windows is not a target — but don't hard-code
POSIX-only assumptions where avoiding them is free.

Expect this deployment shape: the Pi runs headless 24/7 capture, the Mac runs
interactive sessions, and the dashboard on the Mac can point at either its own
local capture service or the Pi's over the LAN.

## Three components

**1. Capture service** (Python) — owns radio access, decoding, identification,
and storage. Exposes a documented HTTP + WebSocket API. Runs standalone and
headless; the UI is strictly a client.

**2. CLI** — a first-class interface, not an afterthought. I want to be able to
work entirely from a terminal over SSH to the Pi.

- `blemon scan` — live updating terminal table of nearby devices (rich/textual)
- `blemon watch <addr>` — live decoded packet stream for one device
- `blemon devices` / `blemon sessions` — query recorded history
- `blemon probe <addr>` — opt-in active GATT enumeration (see below)
- `blemon follow <addr>` — sniffer-based connection following
- `blemon export` — JSON / CSV / PCAP output
- `blemon doctor` — diagnose adapter access, permissions, sniffer firmware, and
  print exactly what this setup can and cannot see
- `blemon serve` — start the capture service + dashboard
- `--json` on every query command so it composes with other tools

**3. Web app** (TypeScript + React) — the visual layer. Served as prebuilt static
assets by the capture service so **there is no Node.js requirement at runtime**.

## Deployment must be genuinely easy

This matters as much as the features. Target:

- macOS: one command to install, one command to run, browser opens.
- Pi: one command to install, plus a provided systemd unit for headless
  always-on capture.
- Ship the built web assets inside the Python package. Installing must never
  require a Node toolchain.
- Use uv/pyproject for packaging; `uvx ble-monitor serve` should just work.
- Document Linux Bluetooth permissions properly — prefer granting capabilities
  (cap_net_raw/cap_net_admin) over demanding blanket root, and have
  `blemon doctor` detect and explain the fix.
- Bind localhost by default; `--host 0.0.0.0` opt-in for LAN/phone viewing.
- Docker is optional and Pi-only; if provided, document the host-network and
  device-access caveats honestly rather than shipping something that silently
  can't see the radio.

## Capture backends

Put a capture-source abstraction at the boundary. Every backend implements the
same interface and **declares its own capabilities**, so the UI and CLI can show
exactly what the current setup can and cannot observe.

**Backend A — host Bluetooth adapter (advertising only, channels 37/38/39).**

- **Linux/Pi (best):** read the raw HCI socket and decode LE Advertising Report
  and LE Extended Advertising Report events directly. Real MAC addresses, address
  types, complete raw payloads, extended advertising. Prefer this over the BlueZ
  D-Bus API, which discards raw advertising data.
- **macOS:** CoreBluetooth via bleak. Be explicit and unmissable in the UI that
  **macOS hides MAC addresses** (per-app UUID instead) and filters some raw data,
  so device identity and cross-session continuity are degraded. Point the user at
  the Pi for the full picture. Do not silently pretend the two are equivalent.

**Backend B — external sniffer (in scope now, not deferred).**

- **Primary: Sniffle** on TI CC1352/CC2652 hardware — specifically the SONOFF
  CC2652P USB Dongle Plus, and TI CC1352P7 / CC26x2R LaunchPads. Use Sniffle's
  Python interface. Support its three-channel advertising capture for a target
  MAC, and its connection following with channel-map and PHY tracking.
- **Secondary: Nordic nRF Sniffer** on nRF52840 dongles.
- Auto-detect attached sniffer hardware over serial, identify the variant, and
  report firmware status in `blemon doctor` with flashing instructions.

Be honest in the UI about the core limitation: **a sniffer follows one connection
at a time.** Advertising capture is broad and continuous; connection following is
a spotlight you aim. Design the UX around aiming that spotlight — let me pick a
device from any view and say "follow this one."

If multiple sniffers are attached, allow following multiple connections in
parallel, one per device.

## Decoding — go deep

Parse advertising payloads structurally, never as opaque hex:

- All AD types: Flags, 16/32/128-bit service UUIDs, complete and shortened local
  name, TX power, appearance, service data, manufacturer-specific data.
- Resolve company IDs and service UUIDs against the Bluetooth SIG assigned
  numbers. Vendor the data locally; no runtime network access.
- Classify address type — public, random static, resolvable private (RPA),
  non-resolvable private — and surface what each implies about that device's
  privacy hygiene.
- Decode the ecosystem protocols, because this is where the actual content lives:
  - **Apple Continuity** (company 0x004C) — Nearby Info, Handoff, AirDrop,
    AirPlay, Nearby Action, proximity pairing. Decode subtypes and status bytes.
    This is Apple devices continuously narrating their own state, in the clear,
    to everyone in the room. Make it readable.
  - **Find My / offline finding** advertisements
  - **iBeacon** (0x004C type 0x02) — UUID, major, minor, measured power
  - **Eddystone** (0xFEAA) — UID, URL, TLM, EID frames
  - **Google Fast Pair** (0xFE2C)
  - **Microsoft Swift Pair / CDP** (0x0006)
  - **Tile, Chipolo, Samsung SmartTag** and other consumer trackers
  - Standard GATT service data: heart rate, battery, environmental sensing, and
    other common fitness/medical/industrial formats
- For unrecognized payloads, still show structured hex with byte offsets, flag
  which bytes change between advertisements versus which are stable (that alone
  reveals a lot), and let me copy the raw bytes out.

With the sniffer attached, additionally decode connection events: GATT
reads/writes/notifications/indications, service and characteristic UUIDs, MTU
negotiation, and pairing/encryption establishment.

## Identification — guesses must look like guesses

Build a rule-based identification engine where each matcher emits
`(label, confidence, evidence[])`, aggregating into a ranked list.

Non-negotiable: **never present an inference as a fact.** Every device shows its
best guess, a confidence level, the runner-up candidates, and an expandable
"why we think this" listing the concrete observations behind it — "advertises
service 0xFD6F", "manufacturer ID 0x004C", "name matches ^\[AirPods\]", "TX power
and advertising interval consistent with a wearable". I must always be able to
inspect the reasoning and disagree with it. Let me override a guess with my own
label, and have that override persist.

## The two hero views

Build BOTH of these as co-equal primary views. They answer different questions —
the radar is "what is around me right now," the city is "what does this place
look like."

### Radar / proximity field

Me at center. Devices positioned by signal strength, drifting closer and further
as they actually move, fading as they go quiet, arriving with a pulse when
they're new. Color-coded by category: phone, wearable, audio, tracker, beacon,
appliance, vehicle, unknown.

Two honesty constraints, both mandatory:

- **BLE gives no bearing.** A radar implies direction and we do not have it.
  Assign each device a stable pseudo-random angle derived from its identity so it
  stays put frame to frame, and label the view clearly: only distance is
  meaningful, angle is arbitrary.
- **RSSI-to-distance is deeply unreliable.** Use coarse proximity bands —
  immediate / near / far / distant — and never display fabricated meters.

### City block view

An isometric 2.5D city where every device is a building and the skyline IS the
radio environment.

- **Deterministic layout.** A device's position derives from a hash of its
  identity, so it occupies the same lot every time. The city must be a *place* I
  can learn, not a reshuffling mess. Returning to the same café should produce a
  recognizably similar skyline — that recognition is the point.
- **Height** = advertising rate / observed traffic volume. Chatty devices are
  skyscrapers.
- **Footprint** = how long it has been observed. Persistent devices grow into
  landmarks; transients stay small.
- **Districts** = category and manufacturer, with similar devices adjacent. Let
  the Apple district, tracker alley, and sensor row emerge visibly.
- **Distance from center** = proximity band.
- **Lit windows** = recent activity. A device going quiet goes dark, then
  weathers, then is demolished once past the absence threshold.
- **Building material encodes exposure** — devices broadcasting readable identity
  in the clear render as transparent glass; devices using rotating addresses and
  minimal payloads render as opaque and shuttered. I should be able to see, at a
  glance, how much of this city has its blinds open.
- Trackers get a distinct, immediately recognizable silhouette.
- Click any building for full device detail. Right-click to aim the sniffer at it.

Both views must hold 60fps with several hundred concurrent devices and thousands
of advertisements per minute.

## Supporting views

- **Packet waterfall** — every advertisement as it lands, color-coded, scrolling.
  Wireshark-but-beautiful. Expand any row for the full decode.
- **Timeline** — device presence over time. Who's permanent, who's passing
  through, who arrived when.
- **Device inventory** — sortable, filterable, searchable table. Nicknames.
- **Exposure dashboard** — the "how much of this is in the clear" answer. What
  fraction of nearby devices broadcast a readable name, expose plaintext service
  data, use static or public addresses instead of rotating ones, or leak state
  through unencrypted payloads. With the sniffer attached, extend this to real
  encrypted-versus-plaintext link statistics and pairing-method observations.
- **Device detail** — full history, every payload, signal over time, complete
  decode, and the plain-English translation.

## Plain-English translation layer

Alongside every technical decode, generate one or two sentences of ordinary
English explaining what this device is doing and why it's interesting. For
example: "This is an Apple device broadcasting its Nearby Info state — it's
announcing that its screen is on and the device is unlocked. Its address rotates
about every 15 minutes, so it's actively trying not to be tracked."

This translation layer is the entire point of the project. It is what turns a
packet dump into understanding. Treat it as a core feature, not decoration.

## Live and recorded

Stream live over WebSocket, and persist everything to SQLite so I can ask: how
many devices were here at 8am versus 8pm? Which devices have I seen more than
once, across days? How does the airport compare to my apartment?

Support named capture sessions, session comparison, and replaying a recorded
session through the live views at adjustable speed. Include a configurable
retention window, a visible "what is stored" view, and one-click purge.

## Continuity across MAC rotation

Modern phones rotate their addresses roughly every 15 minutes specifically to
resist tracking. Implement best-effort continuity — correlating on stable payload
structure, service UUID sets, TX power, and advertising interval — so a single
device doesn't appear as fifty and my device counts mean something.

Treat this as an explicitly labeled, confidence-scored inference, never as
certainty. Keep it strictly local. The purpose is an accurate picture of the
room, not a dossier on anyone.

## Tracker awareness

Identify known tracker hardware (AirTag, Tile, SmartTag, Chipolo) on sight, and
raise an alert when an unknown rotating-address device persists near me across a
long window and multiple sessions. This is the defensive use case and it's
genuinely valuable — build it properly, with a clear explanation of the evidence
behind any alert.

## Active probing — opt-in only

Default posture is strictly receive-only. Never transmit unless I explicitly ask.

Provide an override: `blemon probe <addr>`, and a per-device action in the UI,
that connects and enumerates GATT services and characteristics. This dramatically
improves identification — exact model, firmware revision, battery level. Require
an explicit action every time, warn clearly that connecting is visible to the
target device, and support an allowlist mode restricted to hardware I've marked
as my own. Never probe automatically, never probe in bulk.

## Responsible-use posture

Build these in rather than bolting them on:

- All data stays local. No network egress, no telemetry, ever.
- Passive by default; active probing gated as described above.
- Retention limits enabled by default with obvious purge controls.
- Exports offer MAC redaction.
- The README frames this as environment awareness and security research, notes
  that passive reception is what every phone does continuously, and states
  plainly that indefinitely logging identifiable strangers is not the intent.

## Engineering expectations

- Decoders tested against recorded and synthetic payload fixtures, so the whole
  decode layer is verifiable in CI with no radio hardware present.
- Capability matrix surfaced in both UI and `blemon doctor` — I should always
  know what my current setup can and cannot see, and why.
- Graceful degradation everywhere: no adapter, no sniffer, no permissions, or a
  dense hostile RF environment should each produce a clear explanation rather
  than a crash or an empty screen.
- PCAP export using LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR so captures open in
  Wireshark.
- README with screenshots of both hero views, the macOS-versus-Pi capability
  table, sniffer hardware setup and flashing instructions, and a short primer on
  how BLE advertising actually works — the tool should teach, not just display.
