"""Liu protocol channel wrapper.

Manages Liu (liuproto) channels as ITS key engines for the overlay network.
Handles channel lifecycle, PSK management, and key material consumption.

In simulation, this wraps MockLiuChannel. In production, this wraps
liuproto's NetworkServerLink/NetworkClientLink.
"""

from enum import Enum


class ChannelStatus(Enum):
    ACTIVE = 'active'
    IDLE = 'idle'
    EXPIRED = 'expired'


class LiuChannel:
    """Wraps a Liu protocol channel (mock or real).

    Interface for ITS key material generation and MAC authentication.
    """

    def __init__(self, peer_id: int, psk: bytes, mock_channel=None):
        self.peer_id = peer_id
        self.psk = psk
        self.status = ChannelStatus.ACTIVE
        self._mock = mock_channel
        self.total_bits = 0

    def key_material(self, n_bits: int) -> bytes:
        """Extract n_bits of ITS key material from channel."""
        if self.status != ChannelStatus.ACTIVE:
            raise RuntimeError(f"Channel to {self.peer_id} is {self.status.value}")
        if self._mock is None:
            raise RuntimeError("No channel backend configured")
        bits = self._mock.generate_key_bits(n_bits)
        self.total_bits += n_bits
        return bits

    def authenticate(self, data: list, run_idx: int = 0) -> int:
        """Compute MAC on data using channel keys."""
        if self._mock is None:
            raise RuntimeError("No channel backend configured")
        return self._mock.authenticate(data, run_idx)

    def verify_mac(self, data: list, tag: int, run_idx: int = 0) -> bool:
        if self._mock is None:
            raise RuntimeError("No channel backend configured")
        return self._mock.verify_mac(data, tag, run_idx)

    def recycle_psk(self) -> bytes:
        """Generate new PSK from channel output for continuous operation."""
        return self.key_material(256 * 8)  # 256 bytes = new PSK

    def close(self):
        self.status = ChannelStatus.EXPIRED
        if self._mock:
            self._mock.close()


class ChannelTable:
    """Manages active/idle/expired channels per node."""

    def __init__(self):
        self.channels: dict[int, LiuChannel] = {}  # peer_id -> channel

    def add(self, channel: LiuChannel):
        self.channels[channel.peer_id] = channel

    def get(self, peer_id: int) -> LiuChannel:
        return self.channels.get(peer_id)

    def remove(self, peer_id: int):
        ch = self.channels.pop(peer_id, None)
        if ch:
            ch.close()

    @property
    def active(self) -> list:
        return [c for c in self.channels.values()
                if c.status == ChannelStatus.ACTIVE]

    @property
    def idle(self) -> list:
        return [c for c in self.channels.values()
                if c.status == ChannelStatus.IDLE]

    @property
    def count(self) -> int:
        return len(self.channels)
