"""
WebSocket Connection Manager & Real-Time SOC Event Broadcaster.

Maintains active client connections, channel multiplexing (telemetry, alerts, mitigation),
heartbeat keep-alives, and sub-second push delivery to SOC dashboard operators.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

logger = logging.getLogger("edr.websocket")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [WEBSOCKET] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class ChannelType:
    """Supported broadcast channels."""

    TELEMETRY = "telemetry"
    ALERTS = "alerts"
    MITIGATION = "mitigation"
    SYSTEM = "system"
    SCANS = "scans"


class BroadcastEvent(BaseModel):
    """Structured envelope for real-time WebSocket payloads."""

    channel: str
    event_type: str
    timestamp: float = Field(default_factory=time.time)
    payload: Dict[str, Any]


class WebSocketConnectionManager:
    """
    Thread-safe asynchronous WebSocket connection manager.

    Supports dynamic channel subscriptions, dead socket cleanup,
    and cross-thread event dispatching from sync collectors.
    """

    def __init__(self, heartbeat_interval_sec: float = 30.0):
        """Initialize the connection pool and synchronization locks."""
        self._active_connections: Set[WebSocket] = set()
        self._subscriptions: Dict[WebSocket, Set[str]] = {}
        self._lock = asyncio.Lock()
        self.heartbeat_interval_sec = heartbeat_interval_sec
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the running asyncio event loop for thread-safe cross-dispatches."""
        self._loop = loop

    async def connect(self, websocket: WebSocket, default_channels: Optional[List[str]] = None) -> None:
        """Accept incoming client handshake and register to channel pool."""
        await websocket.accept()
        channels = set(default_channels or [
            ChannelType.TELEMETRY,
            ChannelType.ALERTS,
            ChannelType.MITIGATION,
            ChannelType.SYSTEM,
            ChannelType.SCANS,
        ])
        async with self._lock:
            self._active_connections.add(websocket)
            self._subscriptions[websocket] = channels

        client_host = websocket.client.host if websocket.client else "unknown"
        logger.info(
            "SOC Dashboard client connected: %s. Active connections: %d",
            client_host,
            len(self._active_connections),
        )

        # Welcome handshake
        await self.send_personal_message(
            websocket,
            BroadcastEvent(
                channel=ChannelType.SYSTEM,
                event_type="connection_established",
                payload={
                    "status": "connected",
                    "subscribed_channels": list(channels),
                    "server_time": time.time(),
                },
            ),
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Unregister closed or broken connection."""
        async with self._lock:
            if websocket in self._active_connections:
                self._active_connections.remove(websocket)
            if websocket in self._subscriptions:
                del self._subscriptions[websocket]

        client_host = websocket.client.host if websocket.client else "unknown"
        logger.info(
            "SOC Dashboard client disconnected: %s. Remaining: %d",
            client_host,
            len(self._active_connections),
        )

    async def send_personal_message(self, websocket: WebSocket, event: BroadcastEvent) -> None:
        """Send a direct message to a single specific client."""
        try:
            await websocket.send_text(event.model_dump_json())
        except Exception as exc:
            logger.warning("Failed sending personal message to socket: %s", exc)
            await self.disconnect(websocket)

    async def broadcast(self, channel: str, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Broadcast an event to all connected clients subscribed to the specified channel.
        """
        event = BroadcastEvent(
            channel=channel,
            event_type=event_type,
            payload=payload,
        )
        message_json = event.model_dump_json()

        # Capture snapshot of subscribers under lock
        async with self._lock:
            subscribers = [
                ws
                for ws, channels in self._subscriptions.items()
                if channel in channels and ws in self._active_connections
            ]

        if not subscribers:
            return

        dead_sockets: List[WebSocket] = []
        for ws in subscribers:
            try:
                await ws.send_text(message_json)
            except Exception as exc:
                logger.debug("Broadcast write failed for client (%s): %s", ws, exc)
                dead_sockets.append(ws)

        if dead_sockets:
            for dead_ws in dead_sockets:
                await self.disconnect(dead_ws)

    def broadcast_sync(self, channel: str, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Thread-safe helper to trigger broadcasts from synchronous background threads
        (such as simulation loops or detection collectors).
        """
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.broadcast(channel, event_type, payload),
                self._loop,
            )
        else:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.broadcast(channel, event_type, payload))
            except RuntimeError:
                pass


# Global singleton instance
ws_manager = WebSocketConnectionManager()

# Router definition for easy integration into FastAPI app
router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/soc")
async def soc_websocket_endpoint(websocket: WebSocket):
    """
    Primary real-time bi-directional telemetry stream for SOC dashboards.
    Receives control messages (e.g. subscribe/unsubscribe/ping) and streams alerts.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Handle incoming client commands / heartbeats
            data_text = await websocket.receive_text()
            try:
                client_msg = json.loads(data_text)
                action = client_msg.get("action")
                if action == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "timestamp": time.time()}))
                elif action == "subscribe":
                    channel = client_msg.get("channel")
                    if channel:
                        async with ws_manager._lock:
                            if websocket in ws_manager._subscriptions:
                                ws_manager._subscriptions[websocket].add(channel)
                        await websocket.send_text(json.dumps({"type": "subscribed", "channel": channel}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.error("Unhandled exception in WebSocket session: %s", exc)
        await ws_manager.disconnect(websocket)
