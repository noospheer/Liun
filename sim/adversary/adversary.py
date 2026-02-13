"""Base adversary and corrupt node management."""

from sim.core.message_bus import AdversaryHook, Message


class Adversary:
    """Base adversary that controls a set of corrupt nodes."""

    def __init__(self, corrupt_ids: list = None):
        self.corrupt_ids: set = set(corrupt_ids or [])
        self.observed_messages: list = []
        self.intercepted_shares: dict = {}  # {(src, dst): payload}

    def add_corrupt(self, node_id: int):
        self.corrupt_ids.add(node_id)

    def is_corrupt(self, node_id: int) -> bool:
        return node_id in self.corrupt_ids

    def get_hook(self) -> 'AdversaryMessageHook':
        """Get a message bus hook for this adversary."""
        return AdversaryMessageHook(self)


class AdversaryMessageHook(AdversaryHook):
    """Message bus hook that lets the adversary observe/modify messages."""

    def __init__(self, adversary: Adversary):
        self.adversary = adversary

    def on_send(self, msg: Message):
        # Record all messages from/to corrupt nodes
        if (msg.src in self.adversary.corrupt_ids or
                msg.dst in self.adversary.corrupt_ids):
            self.adversary.observed_messages.append(msg)
            key = (msg.src, msg.dst)
            self.adversary.intercepted_shares[key] = msg.payload.copy()
        return msg
