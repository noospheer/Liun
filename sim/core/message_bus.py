"""Central message bus with adversary hooks.

Single interception point for the adversary. Complete observability.
Messages are delivered at the next tick (or with configurable delay).
"""

from dataclasses import dataclass, field
from typing import Callable, Optional
from sim.core.clock import SimClock


@dataclass
class Message:
    src: int
    dst: int
    msg_type: str
    payload: dict
    tick_sent: int = 0
    tick_delivered: int = 0
    id: int = 0


class AdversaryHook:
    """Base class for adversary interception hooks."""

    def on_send(self, msg: Message) -> Optional[Message]:
        """Called when a message is sent. Return None to drop, or modified msg."""
        return msg

    def on_deliver(self, msg: Message) -> Optional[Message]:
        """Called just before delivery. Return None to drop."""
        return msg


class SimMessageBus:
    """Central router for inter-node messages with adversary hooks."""

    def __init__(self, clock: SimClock, default_delay: int = 1):
        self.clock = clock
        self.default_delay = default_delay
        self._msg_seq = 0
        self._pending: list = []  # (delivery_tick, Message)
        self._delivered: list = []  # audit log
        self._hooks: list[AdversaryHook] = []
        self._handlers: dict = {}  # node_id -> callback(Message)

    def register_handler(self, node_id: int, handler: Callable):
        """Register a message delivery handler for a node."""
        self._handlers[node_id] = handler

    def add_hook(self, hook: AdversaryHook):
        self._hooks.append(hook)

    def remove_hook(self, hook: AdversaryHook):
        self._hooks.remove(hook)

    def send(self, src: int, dst: int, msg_type: str, payload: dict,
             delay: int = None):
        """Send a message from src to dst."""
        if delay is None:
            delay = self.default_delay

        msg = Message(
            src=src, dst=dst, msg_type=msg_type, payload=payload,
            tick_sent=self.clock.tick, id=self._msg_seq,
        )
        self._msg_seq += 1

        # Run through adversary hooks
        for hook in self._hooks:
            msg = hook.on_send(msg)
            if msg is None:
                return  # dropped

        msg.tick_delivered = self.clock.tick + delay
        self._pending.append((msg.tick_delivered, msg))

        # Schedule delivery
        self.clock.schedule(delay, self._deliver, msg)

    def _deliver(self, msg: Message):
        """Deliver a message to its destination handler."""
        # Run delivery hooks
        for hook in self._hooks:
            msg = hook.on_deliver(msg)
            if msg is None:
                return  # dropped at delivery

        self._delivered.append(msg)
        handler = self._handlers.get(msg.dst)
        if handler:
            handler(msg)

    def broadcast(self, src: int, msg_type: str, payload: dict,
                  recipients: list = None, delay: int = None):
        """Broadcast a message to all registered nodes (or a subset)."""
        targets = recipients if recipients is not None else [
            nid for nid in self._handlers if nid != src
        ]
        for dst in targets:
            self.send(src, dst, msg_type, dict(payload), delay)

    @property
    def delivered_count(self) -> int:
        return len(self._delivered)

    @property
    def audit_log(self) -> list:
        return list(self._delivered)

    def messages_between(self, a: int, b: int) -> list:
        """Return all delivered messages between a and b (either direction)."""
        return [m for m in self._delivered
                if (m.src == a and m.dst == b) or (m.src == b and m.dst == a)]
