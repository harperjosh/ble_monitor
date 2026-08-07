"""Terminal rendering helpers, shared by the CLI commands."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:  # pragma: no cover
    from blemon.device import Device

CATEGORY_STYLE = {
    "phone": "bright_cyan",
    "computer": "cyan",
    "wearable": "bright_magenta",
    "audio": "magenta",
    "tracker": "bright_red",
    "beacon": "yellow",
    "appliance": "green",
    "sensor": "bright_green",
    "vehicle": "blue",
    "medical": "bright_yellow",
    "peripheral": "bright_blue",
    "network": "blue",
    "unknown": "grey58",
}

PROXIMITY_BAR = {
    "immediate": "████",
    "near": "███░",
    "far": "██░░",
    "distant": "█░░░",
}

EXPOSURE_STYLE = {
    "wide open": "bright_red",
    "chatty": "yellow",
    "guarded": "cyan",
    "closed": "green",
}

CONFIDENCE_MARK = {"certain": "", "high": "", "medium": "?", "low": "??"}


def category_text(category: str) -> Text:
    return Text(category, style=CATEGORY_STYLE.get(category, "grey58"))


def signal_text(rssi: int | None, proximity: str) -> Text:
    bar = PROXIMITY_BAR.get(proximity, "░░░░")
    style = {
        "immediate": "bright_green",
        "near": "green",
        "far": "yellow",
        "distant": "grey58",
    }.get(proximity, "grey58")
    value = f"{rssi:>4}" if rssi is not None else "   ?"
    return Text(f"{bar} {value}", style=style)


def label_text(device: Device) -> Text:
    ident = device.identification
    mark = ""
    if device.user_label:
        mark = "*"
    elif ident and ident.best:
        mark = CONFIDENCE_MARK.get(ident.best.confidence.value, "")
    text = Text(device.display_name)
    if mark:
        text.append(mark, style="grey58")
    if device.is_tracker:
        text.append("  TRACKER", style="bold bright_red")
    return text


def device_table(devices: list[Device], limit: int = 40, title: str | None = None) -> Table:
    table = Table(
        title=title,
        title_style="bold",
        header_style="bold grey62",
        border_style="grey30",
        expand=True,
        pad_edge=False,
    )
    table.add_column("signal", width=10, no_wrap=True)
    table.add_column("device", ratio=3, no_wrap=True, overflow="ellipsis")
    table.add_column("category", width=11, no_wrap=True)
    table.add_column("address", width=17, no_wrap=True)
    table.add_column("adv/s", width=6, justify="right", no_wrap=True)
    table.add_column("pkts", width=6, justify="right", no_wrap=True)
    table.add_column("seen", width=6, justify="right", no_wrap=True)
    table.add_column("exposure", width=10, no_wrap=True)

    now = time.time()
    for device in devices[:limit]:
        exposure = device.exposure()
        addr = device.address
        if device.rotates_address:
            addr = f"{addr} ~"
        table.add_row(
            signal_text(device.smoothed_rssi, device.proximity.value),
            label_text(device),
            category_text(device.category.value),
            Text(addr, style="grey58" if device.rotates_address else "white"),
            f"{device.advertising_rate:.1f}",
            str(device.packet_count),
            _ago(now - device.last_seen),
            Text(exposure.band, style=EXPOSURE_STYLE.get(exposure.band, "white")),
        )
    return table


def _ago(seconds: float) -> str:
    if seconds < 1:
        return "now"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def header_panel(
    backend_name: str,
    caps_name: str,
    stats: dict[str, Any],
    summary: str,
    missing: list[str],
) -> Panel:
    left = Text()
    left.append(f"{caps_name}\n", style="bold")
    left.append(summary + "\n", style="grey70")
    if missing:
        left.append("Cannot see: " + ", ".join(missing), style="yellow")
    right = (
        f"{stats['packets']} packets · {stats['packets_per_second']}/s · "
        f"{stats['devices_seen']} devices · up {_ago(stats['uptime'])}"
    )
    return Panel(
        Group(left, Text(right, style="grey50")),
        border_style="grey30",
        title=f"[bold]blemon[/] [grey50]{backend_name}[/]",
        title_align="left",
    )


def alerts_panel(alerts: list[Any]) -> Panel | None:
    if not alerts:
        return None
    body = Text()
    for alert in alerts[:5]:
        style = {"attention": "bold bright_red", "notable": "yellow"}.get(
            alert.level.value, "grey62"
        )
        body.append(f"[{alert.level.value}] ", style=style)
        body.append(alert.title + "\n")
        body.append(f"        {alert.explanation}\n", style="grey58")
    return Panel(body, title="[bold]alerts[/]", border_style="red", title_align="left")


def packet_line(row: dict[str, Any]) -> Text:
    text = Text()
    text.append(time.strftime("%H:%M:%S", time.localtime(row["t"])), style="grey42")
    rssi = row.get("rssi")
    text.append(f" {rssi if rssi is not None else '   ?':>4} ", style="grey62")
    channel = row.get("channel")
    text.append(f"ch{channel:>2} " if channel else "     ", style="grey42")
    text.append(f"{row['address']:<17} ", style="grey70")
    text.append(f"{row.get('label', '')[:26]:<26} ", style=CATEGORY_STYLE.get(row.get("category", "unknown"), "white"))
    text.append(row.get("summary", "")[:70])
    return text


def decode_tree(parsed: dict[str, Any]) -> Group:
    """Full structural decode of one advertisement, for `blemon watch`."""
    items: list[Any] = []
    adv = parsed.get("advertisement", {})
    head = Text()
    head.append(f"{adv.get('address', '')}  ", style="bold")
    head.append(f"{adv.get('address_type', '')}  ", style="grey58")
    head.append(f"{adv.get('rssi')} dBm  ", style="grey70")
    head.append(f"{adv.get('pdu_type', '')} {adv.get('phy', '')}", style="grey58")
    items.append(head)

    for structure in parsed.get("structures", []):
        line = Text("  ")
        line.append(f"0x{structure['type_code']:02X} ", style="grey42")
        line.append(structure["type_name"], style="bold grey70")
        line.append(f"  [{len(structure['data']) // 2} bytes]", style="grey42")
        items.append(line)
        for field in structure.get("fields", []):
            fl = Text("      ")
            fl.append(f"{field['name']}: ", style="grey58")
            fl.append(str(field["value"])[:80])
            if field.get("note"):
                fl.append(f"   {field['note']}"[:90], style="grey42")
            items.append(fl)
        for decoding in structure.get("decodings", []):
            dl = Text("      → ", style="bright_cyan")
            dl.append(decoding["summary"], style="bright_cyan")
            items.append(dl)
            if decoding.get("english"):
                items.append(Text("        " + decoding["english"], style="grey62"))
            if decoding.get("tags"):
                items.append(
                    Text("        tags: " + ", ".join(decoding["tags"]), style="grey42")
                )
    if parsed.get("parse_errors"):
        for err in parsed["parse_errors"]:
            items.append(Text("  ! " + err, style="yellow"))
    return Group(*items)


def capability_table(caps: dict[str, Any]) -> Table:
    table = Table(
        header_style="bold grey62", border_style="grey30", expand=False, pad_edge=False
    )
    table.add_column("capability", width=34)
    table.add_column("", width=5)
    rows = [
        ("Advertising (channels 37/38/39)", "advertising"),
        ("BT5 extended advertising", "extended_advertising"),
        ("Real MAC addresses", "real_mac_addresses"),
        ("Unmodified raw payloads", "raw_payloads"),
        ("Scan responses", "scan_responses"),
        ("Connection following", "connection_following"),
        ("All three ad channels at once", "three_channel_advertising"),
        ("2M PHY", "two_m_phy"),
        ("Long-range Coded PHY", "coded_phy"),
        ("Per-packet channel numbers", "channel_reporting"),
        ("Can transmit (probing)", "can_transmit"),
    ]
    for label, key in rows:
        value = caps.get(key)
        table.add_row(
            label,
            Text("yes", style="green") if value else Text("no", style="red"),
        )
    return table
