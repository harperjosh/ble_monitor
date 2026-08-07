"""``blemon`` — the command line interface.

Designed to be used over SSH to a headless Raspberry Pi, so every query
command takes ``--json`` and composes with other tools, and the live views
degrade gracefully on a dumb terminal.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from blemon import __version__
from blemon.capture import CaptureError, autoselect, create
from blemon.cli import render
from blemon.cli.doctor import FAIL, INFO, OK, WARN, run_doctor
from blemon.service import Hub
from blemon.store import Store, write_pcap

DEFAULT_PORT = 8420

LEVEL_STYLE = {OK: "green", WARN: "yellow", FAIL: "bold red", INFO: "grey62"}
LEVEL_MARK = {OK: "ok  ", WARN: "warn", FAIL: "FAIL", INFO: "    "}


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blemon",
        description=(
            "See the BLE radio traffic around you. Passive by default — nothing is "
            "transmitted unless you explicitly ask for it."
        ),
        epilog="Start with `blemon doctor` to find out what your setup can see.",
    )
    parser.add_argument("--version", action="version", version=f"ble-monitor {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def radio_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--backend", help="sniffle, nrf, hci, bleak, synthetic, replay")
        p.add_argument("--device", type=int, default=0, help="HCI adapter index (Linux)")
        p.add_argument("--port", dest="serial_port", help="serial port for a sniffer")
        p.add_argument(
            "--hci-mode",
            choices=("user", "monitor"),
            default="user",
            help="user takes exclusive control; monitor is read-only",
        )
        p.add_argument("--channel", type=int, default=37, help="advertising channel for sniffers")
        p.add_argument("--session-id", type=int, help="session to replay (with --backend replay)")
        p.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
        p.add_argument("--db", help="path to the capture database")
        p.add_argument("--no-store", action="store_true", help="do not persist anything")

    p_scan = sub.add_parser("scan", help="live table of nearby devices")
    radio_args(p_scan)
    p_scan.add_argument("--name", default="scan", help="name for this capture session")
    p_scan.add_argument("--limit", type=int, default=30, help="rows to show")
    p_scan.add_argument("--seconds", type=float, help="stop after this long")
    p_scan.add_argument("--json", action="store_true", help="emit JSON lines instead of a table")
    p_scan.add_argument("--feed", action="store_true", help="scrolling packet feed instead of a table")

    p_watch = sub.add_parser("watch", help="live decoded packet stream for one device")
    radio_args(p_watch)
    p_watch.add_argument("address", help="device address, or a substring of its name")
    p_watch.add_argument("--json", action="store_true")
    p_watch.add_argument("--seconds", type=float)

    p_devices = sub.add_parser("devices", help="query recorded devices")
    p_devices.add_argument("--db")
    p_devices.add_argument("--session-id", type=int)
    p_devices.add_argument("--category")
    p_devices.add_argument("--trackers", action="store_true", help="only item trackers")
    p_devices.add_argument("--search")
    p_devices.add_argument("--since", type=float, help="unix timestamp")
    p_devices.add_argument("--limit", type=int, default=100)
    p_devices.add_argument("--json", action="store_true")

    p_sessions = sub.add_parser("sessions", help="list recorded capture sessions")
    p_sessions.add_argument("--db")
    p_sessions.add_argument("--json", action="store_true")

    p_probe = sub.add_parser(
        "probe",
        help="connect to a device and enumerate GATT (ACTIVE — transmits)",
        description=(
            "This is the one command that transmits. It connects to the device, reads "
            "its service list and identifying characteristics, and disconnects. The "
            "target can see it."
        ),
    )
    p_probe.add_argument("address")
    p_probe.add_argument("--json", action="store_true")
    p_probe.add_argument("--timeout", type=float, default=20.0)
    p_probe.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    p_follow = sub.add_parser("follow", help="aim a sniffer at one device's connection")
    radio_args(p_follow)
    p_follow.add_argument("address")
    p_follow.add_argument("--seconds", type=float)
    p_follow.add_argument("--json", action="store_true")

    p_export = sub.add_parser("export", help="export a session as JSON, CSV or PCAP")
    p_export.add_argument("--db")
    p_export.add_argument("--session-id", type=int, help="defaults to the most recent")
    p_export.add_argument(
        "--format", choices=("json", "csv", "pcap"), default="json", dest="fmt"
    )
    p_export.add_argument("--what", choices=("devices", "observations"), default="devices")
    p_export.add_argument("-o", "--output", help="output file; defaults to stdout")
    p_export.add_argument("--redact", action="store_true", help="pseudonymise addresses")
    p_export.add_argument("--limit", type=int, default=200_000)

    p_doctor = sub.add_parser("doctor", help="what can this setup see, and why not more")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.add_argument("--backend", help="check a specific backend")

    p_serve = sub.add_parser("serve", help="run the capture service and dashboard")
    radio_args(p_serve)
    p_serve.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to allow LAN access")
    p_serve.add_argument("--http-port", type=int, default=DEFAULT_PORT)
    p_serve.add_argument("--name", default="serve", help="name for this capture session")
    p_serve.add_argument("--open", action="store_true", help="open a browser")
    p_serve.add_argument(
        "--allow-probe", action="store_true", help="enable active probing from the UI"
    )
    p_serve.add_argument(
        "--probe-any",
        action="store_true",
        help="allow probing devices not marked as yours (implies --allow-probe)",
    )

    p_purge = sub.add_parser("purge", help="delete stored capture data")
    p_purge.add_argument("--db")
    p_purge.add_argument("--yes", action="store_true")
    p_purge.add_argument("--labels", action="store_true", help="also delete your own labels")

    sub.add_parser("stored", help="show exactly what is stored on this machine").add_argument(
        "--db"
    )
    return parser


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_backend(args: argparse.Namespace):
    kwargs: dict[str, Any] = {
        "device": getattr(args, "device", 0),
        "mode": getattr(args, "hci_mode", "user"),
        "port": getattr(args, "serial_port", None),
        "channel": getattr(args, "channel", 37),
        "speed": getattr(args, "speed", 1.0),
        "db_path": getattr(args, "db", None),
    }
    if getattr(args, "session_id", None) is not None:
        kwargs["session_id"] = args.session_id
    name = getattr(args, "backend", None)
    if name:
        return create(name, **kwargs)
    return autoselect(**kwargs)


def make_store(args: argparse.Namespace) -> Store | None:
    if getattr(args, "no_store", False):
        return None
    return Store(getattr(args, "db", None))


def emit_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def fail(console: Console, exc: CaptureError) -> int:
    console.print(Panel(
        Text(str(exc), style="bold red"),
        title="[bold red]cannot capture[/]",
        border_style="red",
        title_align="left",
    ))
    if exc.remedy:
        console.print(Text(exc.remedy, style="yellow"))
    console.print("\n[grey62]Run [bold]blemon doctor[/bold] for a full diagnosis.[/]")
    return 2


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    backend = make_backend(args)
    hub = Hub(backend, store=make_store(args), session_name=args.name,
              persist=not args.no_store)
    try:
        await hub.start()
    except CaptureError as exc:
        return fail(console, exc)

    deadline = time.time() + args.seconds if args.seconds else None

    if args.json:
        # One JSON object per line, so it pipes into jq.
        queue = hub.subscribe()
        try:
            while deadline is None or time.time() < deadline:
                message = await queue.get()
                if message["type"] in ("packet", "devices", "alerts"):
                    sys.stdout.write(json.dumps(message, default=str) + "\n")
                    sys.stdout.flush()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await hub.stop()
        return 0

    caps = backend.capabilities
    try:
        with Live(console=console, screen=False, refresh_per_second=4, transient=False) as live:
            while deadline is None or time.time() < deadline:
                await asyncio.sleep(0.25)
                devices = hub.device_list()
                snapshot = hub.snapshot()
                parts = [
                    render.header_panel(
                        backend.name, caps.name, snapshot["stats"], snapshot["summary"],
                        caps.missing(),
                    )
                ]
                alerts = render.alerts_panel(hub.alerts)
                if alerts:
                    parts.append(alerts)
                if args.feed:
                    lines = [render.packet_line(r) for r in list(hub.feed)[-args.limit:]]
                    parts.append(Panel(
                        Text("\n").join(lines) if lines else Text("waiting for packets…",
                                                                  style="grey42"),
                        border_style="grey30", title="[bold]packets[/]", title_align="left",
                    ))
                else:
                    parts.append(render.device_table(devices, limit=args.limit))
                from rich.console import Group

                live.update(Group(*parts))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await hub.stop()

    console.print(f"\n[grey62]{hub.stats.packets} packets from "
                  f"{hub.stats.devices_seen} devices.[/]")
    if hub.session_id:
        console.print(f"[grey62]Saved as session {hub.session_id}. "
                      f"Replay it with [bold]blemon scan --backend replay "
                      f"--session-id {hub.session_id}[/bold].[/]")
    return 0


async def cmd_watch(args: argparse.Namespace, console: Console) -> int:
    backend = make_backend(args)
    hub = Hub(backend, store=None, persist=False)
    try:
        await hub.start()
    except CaptureError as exc:
        return fail(console, exc)

    needle = args.address.upper()
    deadline = time.time() + args.seconds if args.seconds else None
    console.print(f"[grey62]Watching for [bold]{args.address}[/bold] — "
                  f"matching on address or name. Ctrl-C to stop.[/]\n")
    seen = 0
    try:
        while deadline is None or time.time() < deadline:
            await asyncio.sleep(0.2)
            for device in hub.device_list():
                if needle not in device.address.upper() and needle not in device.display_name.upper():
                    continue
                if device.last_parsed is None:
                    continue
                parsed = device.last_parsed.to_dict()
                if args.json:
                    sys.stdout.write(json.dumps(parsed, default=str) + "\n")
                    sys.stdout.flush()
                else:
                    console.print(render.decode_tree(parsed))
                    console.rule(style="grey23")
                seen += 1
                device.last_parsed = None  # only print each new packet once
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await hub.stop()
    if seen == 0:
        console.print(f"[yellow]Nothing matched {args.address!r}.[/] "
                      "Run [bold]blemon scan[/bold] to see what is actually in range.")
    return 0


def cmd_devices(args: argparse.Namespace, console: Console) -> int:
    store = Store(args.db)
    rows = store.devices(
        session_id=args.session_id,
        since=args.since,
        category=args.category,
        tracker_only=args.trackers,
        search=args.search,
        limit=args.limit,
    )
    if args.json:
        emit_json({"count": len(rows), "devices": [r["snapshot"] for r in rows]})
        return 0
    if not rows:
        console.print("[grey62]No stored devices match. Run [bold]blemon scan[/bold] first.[/]")
        return 0

    from rich.table import Table

    table = Table(header_style="bold grey62", border_style="grey30", expand=True)
    for col, width in (("device", None), ("category", 11), ("address", 17),
                       ("pkts", 6), ("exposure", 8), ("last seen", 17)):
        table.add_column(col, width=width, no_wrap=(col != "device"),
                         justify="right" if col in ("pkts", "exposure") else "left")
    for row in rows:
        snap = row["snapshot"]
        table.add_row(
            (row["label"] or "?") + ("  TRACKER" if row["is_tracker"] else ""),
            render.category_text(row["category"] or "unknown"),
            row["address"],
            str(row["packet_count"]),
            str(row["exposure"] or 0),
            time.strftime("%Y-%m-%d %H:%M", time.localtime(row["last_seen"])),
        )
        del snap
    console.print(table)
    console.print(f"[grey62]{len(rows)} devices.[/]")
    return 0


def cmd_sessions(args: argparse.Namespace, console: Console) -> int:
    store = Store(args.db)
    sessions = store.sessions()
    if args.json:
        emit_json({"sessions": sessions})
        return 0
    if not sessions:
        console.print("[grey62]No recorded sessions yet.[/]")
        return 0
    from rich.table import Table

    table = Table(header_style="bold grey62", border_style="grey30")
    for col in ("id", "name", "started", "duration", "devices", "packets", "backend"):
        table.add_column(col, justify="right" if col in ("id", "devices", "packets") else "left")
    for s in sessions:
        table.add_row(
            str(s["id"]),
            s["name"],
            time.strftime("%Y-%m-%d %H:%M", time.localtime(s["started_at"])),
            render._ago(s["duration"]),
            str(s["device_count"]),
            str(s["observation_count"]),
            s.get("backend") or "?",
        )
    console.print(table)
    return 0


async def cmd_probe(args: argparse.Namespace, console: Console) -> int:
    from blemon.capture.probe import PROBE_WARNING, probe

    if not args.yes and not args.json:
        console.print(Panel(
            Text(PROBE_WARNING, style="yellow"),
            title="[bold yellow]this transmits[/]",
            border_style="yellow",
            title_align="left",
        ))
        try:
            answer = input(f"Connect to {args.address}? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            console.print("[grey62]Cancelled. Nothing was transmitted.[/]")
            return 1

    result = await probe(args.address, timeout=args.timeout)
    if args.json:
        emit_json(result.to_dict())
        return 0 if result.success else 1

    if not result.success:
        console.print(f"[red]{result.error}[/]")
        if result.remedy:
            console.print(f"[yellow]{result.remedy}[/]")
        return 1

    console.print(f"\n[bold]{result.summary()}[/]\n")
    if result.device_info:
        from rich.table import Table

        info = Table(show_header=False, border_style="grey30", box=None)
        for key, value in result.device_info.items():
            info.add_row(Text(key, style="grey62"), Text(str(value)))
        console.print(info)
        console.print()
    for service in result.services:
        console.print(Text(f"  {service['uuid']}  ", style="grey42").append(
            service.get("name") or "", style="bold"))
        for char in service.get("characteristics", []):
            line = Text("      ")
            line.append(f"{char['uuid'][:8]} ", style="grey42")
            line.append(f"{(char.get('name') or ''):<38}", style="grey70")
            line.append(",".join(char.get("properties", [])), style="grey50")
            if char.get("value"):
                line.append(f"  = {char['value']}", style="bright_cyan")
            console.print(line)
    return 0


async def cmd_follow(args: argparse.Namespace, console: Console) -> int:
    backend = make_backend(args)
    if not backend.capabilities.connection_following:
        console.print(Panel(
            Text(
                f"The `{backend.name}` backend cannot follow connections. Following a "
                "connection means hopping across 37 data channels in step with the two "
                "devices, and a host Bluetooth adapter simply cannot do it — you need "
                "sniffer hardware.",
                style="yellow",
            ),
            title="[bold yellow]not possible with this hardware[/]",
            border_style="yellow",
            title_align="left",
        ))
        console.print("[grey62]Run [bold]blemon doctor[/bold] for hardware recommendations.[/]")
        return 2

    hub = Hub(backend, store=make_store(args), session_name=f"follow {args.address}",
              persist=not args.no_store)
    try:
        await hub.start()
    except CaptureError as exc:
        return fail(console, exc)

    ok = await backend.follow(args.address)
    if not ok:
        console.print(f"[red]Could not aim the sniffer at {args.address}.[/]")
        await hub.stop()
        return 1

    console.print(
        f"[grey62]Aimed at [bold]{args.address}[/bold]. The sniffer follows one "
        "connection at a time, so broad advertising capture is reduced while it is "
        "pointed here. Waiting for it to connect… Ctrl-C to stop.[/]\n"
    )
    deadline = time.time() + args.seconds if args.seconds else None
    printed = 0
    try:
        while deadline is None or time.time() < deadline:
            await asyncio.sleep(0.2)
            rows = list(hub.link_feed)[printed:]
            printed += len(rows)
            for row in rows:
                if args.json:
                    sys.stdout.write(json.dumps(row, default=str) + "\n")
                    sys.stdout.flush()
                    continue
                line = Text()
                line.append(time.strftime("%H:%M:%S ", time.localtime(row["timestamp"])),
                            style="grey42")
                line.append(f"{row['kind']:<11}", style="grey58")
                style = "grey50" if row.get("encrypted") else "bright_cyan"
                line.append(row.get("summary", ""), style=style)
                console.print(line)
                if row.get("english"):
                    console.print(Text("           " + row["english"], style="grey50"))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        with contextlib.suppress(Exception):
            await backend.unfollow()
        await hub.stop()
    if printed == 0:
        console.print(
            "\n[yellow]No connection events captured.[/] The device may not have "
            "connected to anything while we were watching — connection following only "
            "sees a connection that is established while the sniffer is aimed at it."
        )
    return 0


def cmd_export(args: argparse.Namespace, console: Console) -> int:
    from blemon.store import (
        devices_to_csv,
        devices_to_json,
        observations_to_csv,
        observations_to_json,
    )

    store = Store(args.db)
    session_id = args.session_id
    if session_id is None:
        sessions = store.sessions(limit=1)
        if not sessions:
            console.print("[yellow]Nothing recorded yet.[/]")
            return 1
        session_id = sessions[0]["id"]

    if args.fmt == "pcap":
        if not args.output:
            console.print("[red]PCAP is binary — pass -o/--output.[/]")
            return 1
        advertisements = (adv for _key, adv in store.replay(session_id))
        count = write_pcap(args.output, advertisements, redact=args.redact)
        console.print(
            f"[green]Wrote {count} packets to {args.output}.[/]\n"
            "[grey62]Open it in Wireshark — it uses LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR, "
            "so the full BLE dissector applies.[/]"
        )
        return 0

    if args.what == "devices":
        rows = store.devices(session_id=session_id, limit=args.limit)
        text = (devices_to_json(rows, redact=args.redact)
                if args.fmt == "json" else devices_to_csv(rows, redact=args.redact))
    else:
        rows = store.observations(session_id=session_id, limit=args.limit)
        text = (observations_to_json(rows, redact=args.redact)
                if args.fmt == "json" else observations_to_csv(rows, redact=args.redact))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        console.print(f"[green]Wrote {len(rows)} rows to {args.output}.[/]")
        if args.redact:
            console.print("[grey62]Addresses are keyed hashes, consistent within this "
                          "file only.[/]")
    else:
        sys.stdout.write(text)
    return 0


def cmd_doctor(args: argparse.Namespace, console: Console) -> int:
    report = run_doctor(check_backend=args.backend)
    if args.json:
        emit_json(report.to_dict())
        return 0 if report.worst != FAIL else 1

    console.print()
    for finding in report.findings:
        mark = LEVEL_MARK[finding.level]
        console.print(Text(f"[{mark}] ", style=LEVEL_STYLE[finding.level]).append(
            finding.title, style="bold" if finding.level != INFO else "grey70"))
        if finding.detail:
            for line in finding.detail.split("\n"):
                console.print(Text("       " + line, style="grey58"))
        if finding.remedy:
            for line in finding.remedy.split("\n"):
                console.print(Text("       " + line, style="yellow"))
        console.print()

    if report.capabilities:
        console.print(Panel(
            render.capability_table(report.capabilities),
            title=f"[bold]what `{report.chosen_backend}` can see[/]",
            border_style="grey30",
            title_align="left",
            expand=False,
        ))
        caveats = report.capabilities.get("caveats") or []
        for caveat in caveats:
            console.print(Text("  · " + caveat, style="grey62"))
        console.print()

    verdict = {
        OK: "[green]This setup is ready.[/]",
        WARN: "[yellow]This setup works, with the limits noted above.[/]",
        FAIL: "[bold red]This setup cannot capture. See the FAIL lines above.[/]",
        INFO: "[grey62]No problems found.[/]",
    }[report.worst]
    console.print(verdict)
    return 1 if report.worst == FAIL else 0


async def cmd_serve(args: argparse.Namespace, console: Console) -> int:
    import uvicorn

    from blemon.service import create_app, web_asset_dir

    backend = make_backend(args)
    hub = Hub(backend, store=make_store(args), session_name=args.name,
              persist=not args.no_store)
    try:
        await hub.start()
    except CaptureError as exc:
        return fail(console, exc)

    app = create_app(
        hub,
        allow_probe=args.allow_probe or args.probe_any,
        allowlist_only=not args.probe_any,
    )
    url = f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.http_port}"

    console.print()
    console.print(Panel(
        Text(f"{backend.capabilities.name}\n", style="bold").append(
            f"Dashboard: {url}\n", style="bright_cyan").append(
            "All data stays on this machine. Nothing is uploaded anywhere.",
            style="grey58"),
        border_style="grey30", title="[bold]blemon serve[/]", title_align="left",
    ))
    if args.host == "0.0.0.0":  # noqa: S104 — deliberate, and announced
        console.print(
            "[yellow]Listening on all interfaces — anyone on your network can reach "
            "this dashboard and everything it has captured.[/]"
        )
    if web_asset_dir() is None:
        console.print("[yellow]The web bundle is not built, so / shows a placeholder. "
                      "The API works fully.[/]")
    if args.open:
        import webbrowser

        webbrowser.open(url)

    config = uvicorn.Config(app, host=args.host, port=args.http_port, log_level="warning")
    server = uvicorn.Server(config)
    try:
        await server.serve()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await hub.stop()
    return 0


def cmd_purge(args: argparse.Namespace, console: Console) -> int:
    store = Store(args.db)
    stored = store.what_is_stored()
    console.print(f"[bold]{stored['size_human']}[/] at {stored['database_path']}")
    console.print(f"  {stored['counts']['observations']} observations, "
                  f"{stored['counts']['devices']} device records, "
                  f"{stored['counts']['sessions']} sessions, "
                  f"{stored['distinct_addresses']} distinct addresses")
    if not args.yes:
        try:
            answer = input("Delete all of it? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            console.print("[grey62]Cancelled.[/]")
            return 1
    store.purge(keep_labels=not args.labels)
    console.print("[green]Purged.[/]" + ("" if args.labels else " Your own labels were kept."))
    return 0


def cmd_stored(args: argparse.Namespace, console: Console) -> int:
    store = Store(args.db)
    emit_json(store.what_is_stored())
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ASYNC_COMMANDS = {"scan": cmd_scan, "watch": cmd_watch, "probe": cmd_probe,
                  "follow": cmd_follow, "serve": cmd_serve}
SYNC_COMMANDS = {"devices": cmd_devices, "sessions": cmd_sessions, "export": cmd_export,
                 "doctor": cmd_doctor, "purge": cmd_purge, "stored": cmd_stored}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(stderr=False)

    if not args.command:
        parser.print_help()
        console.print("\n[grey62]New here? Run [bold]blemon doctor[/bold] to see what "
                      "your setup can observe, then [bold]blemon scan[/bold].[/]")
        return 0

    try:
        if args.command in ASYNC_COMMANDS:
            return asyncio.run(ASYNC_COMMANDS[args.command](args, console))
        return SYNC_COMMANDS[args.command](args, console)
    except CaptureError as exc:
        return fail(console, exc)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
