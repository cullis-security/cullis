"""
WebSocket Connection Manager — manages active WS connections of agents.

Dual-mode delivery:
  - Local-first: if the agent is connected to this worker, deliver directly.
  - Redis Pub/Sub: if Redis is available, publish to a channel so other workers
    can deliver the message to agents connected on their end.

When Redis is not available (dev, single-worker), the manager works exactly
as before — purely in-memory.

Events pushed:
  - session_pending  → to the target when the initiator opens a session
  - new_message      → to the recipient when a message arrives
"""
import asyncio
import json
import logging
from typing import Dict

from fastapi import WebSocket

logger = logging.getLogger("agent_trust")

_REDIS_CHANNEL_PREFIX = "ws:agent:"


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: Dict[str, WebSocket] = {}
        self._redis = None
        self._pubsub = None
        self._listener_task: asyncio.Task | None = None

    async def init_redis(self) -> None:
        """
        Initialize Redis Pub/Sub for cross-worker message delivery.
        Must be called after the Redis pool is initialized (from lifespan).
        """
        from app.redis.pool import get_redis
        redis = get_redis()
        if redis is None:
            logger.info("WebSocket manager: no Redis — single-worker mode")
            return

        self._redis = redis
        self._pubsub = redis.pubsub()
        logger.info("WebSocket manager: Redis Pub/Sub enabled")

    async def connect(self, agent_id: str, websocket: WebSocket) -> None:
        """
        Register the WebSocket connection for agent_id.
        If the agent already has an open connection, close it first.
        Also subscribes to the agent's Redis channel for cross-worker delivery.
        """
        if agent_id in self._connections:
            logger.warning("Closing existing WebSocket for agent %s before reconnecting", agent_id)
            await self.disconnect(agent_id)

        self._connections[agent_id] = websocket
        logger.info("Agent %s connected via WebSocket", agent_id)

        # Subscribe to Redis channel for this agent (cross-worker delivery)
        if self._pubsub is not None:
            channel = f"{_REDIS_CHANNEL_PREFIX}{agent_id}"
            await self._pubsub.subscribe(channel)
            logger.debug("Subscribed to Redis channel %s", channel)

            # Start the listener if not already running
            if self._listener_task is None or self._listener_task.done():
                self._listener_task = asyncio.create_task(self._redis_listener())

    async def disconnect(self, agent_id: str) -> None:
        """
        Remove the connection and unsubscribe from Redis channel.
        """
        ws = self._connections.pop(agent_id, None)
        if ws is not None:
            try:
                await ws.close()
            except Exception as exc:
                logger.debug("Error closing WebSocket for agent %s: %s", agent_id, exc)
            logger.info("Agent %s disconnected from WebSocket", agent_id)

        # Unsubscribe from Redis channel
        if self._pubsub is not None:
            channel = f"{_REDIS_CHANNEL_PREFIX}{agent_id}"
            await self._pubsub.unsubscribe(channel)

    async def send_to_agent(self, agent_id: str, data: dict) -> None:
        """
        Send a JSON message to the agent.

        Strategy:
        1. If the agent is connected locally → deliver directly.
        2. If Redis is available → publish to the agent's channel
           (another worker may have the connection).
        3. If neither → log and return (client will use REST polling fallback).
        """
        # Try local delivery first
        ws = self._connections.get(agent_id)
        if ws is not None:
            try:
                await ws.send_json(data)
                return
            except Exception as exc:
                logger.error("Failed to send WS to agent %s: %s — forcing disconnect",
                             agent_id, exc)
                await self.disconnect(agent_id)

        # Fall back to Redis Pub/Sub (cross-worker delivery)
        if self._redis is not None:
            channel = f"{_REDIS_CHANNEL_PREFIX}{agent_id}"
            try:
                await self._redis.publish(channel, json.dumps(data))
                logger.debug("Published WS message to Redis channel %s", channel)
            except Exception as exc:
                logger.error("Redis publish failed for agent %s: %s", agent_id, exc)

    def is_connected(self, agent_id: str) -> bool:
        return agent_id in self._connections

    async def _redis_listener(self) -> None:
        """
        Background task: listen on all subscribed Redis channels and
        deliver messages to locally connected agents.
        """
        if self._pubsub is None:
            return

        logger.info("Redis Pub/Sub listener started")
        try:
            while True:
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0,
                )
                if message is None:
                    await asyncio.sleep(0.05)
                    continue

                if message["type"] != "message":
                    continue

                # Channel format: "ws:agent:{agent_id}"
                channel: str = message["channel"]
                if isinstance(channel, bytes):
                    channel = channel.decode()
                agent_id = channel.removeprefix(_REDIS_CHANNEL_PREFIX)

                ws = self._connections.get(agent_id)
                if ws is None:
                    continue  # agent not connected to this worker

                try:
                    data = json.loads(message["data"])
                    await ws.send_json(data)
                except Exception as exc:
                    logger.error("Redis listener: failed to deliver to agent %s: %s",
                                 agent_id, exc)
                    await self.disconnect(agent_id)

        except asyncio.CancelledError:
            logger.info("Redis Pub/Sub listener stopped")
        except Exception as exc:
            logger.error("Redis Pub/Sub listener crashed: %s", exc)

    async def shutdown(self) -> None:
        """Graceful shutdown: cancel the listener and close pubsub."""
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass

        if self._pubsub is not None:
            await self._pubsub.aclose()

        # Close all WebSocket connections
        for agent_id in list(self._connections):
            await self.disconnect(agent_id)


# Singleton
ws_manager = ConnectionManager()
