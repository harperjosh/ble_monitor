"""ble-monitor: make the invisible BLE radio chatter around you visible.

The package is deliberately layered so each stage is independently testable and
independently extensible:

    capture/   radio access. Backends declare capabilities; nothing above this
               layer is allowed to assume a capability that was not declared.
    decode/    bytes -> structured, named fields. Pure functions, no I/O.
    identity/  structured fields -> ranked guesses with evidence. Never facts.
    translate/ everything above -> one or two sentences of ordinary English.
    store/     SQLite persistence, sessions, retention, export.
    service/   HTTP + WebSocket API. The UI is strictly a client of this.
    cli/       a first-class terminal interface, not an afterthought.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
