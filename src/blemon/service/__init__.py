"""The capture service: a headless HTTP + WebSocket API. The UI is a client."""

from __future__ import annotations

from blemon.service.app import create_app, web_asset_dir
from blemon.service.hub import Hub

__all__ = ["Hub", "create_app", "web_asset_dir"]
