"""Simulated Liun network orchestrator.

Creates N nodes, establishes channels, orchestrates protocols.
"""

import random as _random
import math
from sim.core.clock import SimClock
from sim.core.message_bus import SimMessageBus
from sim.network.sim_node import SimNode
from sim.network.graph_gen import (
    random_graph, barabasi_albert, small_world, geographic,
    channels_per_node_default,
)


def _make_psk(a: int, b: int, rng: _random.Random) -> bytes:
    """Generate a deterministic PSK for a channel between a and b."""
    return bytes(rng.getrandbits(8) for _ in range(256))


class SimNetwork:
    """Orchestrates N nodes with channels and protocols."""

    TOPOLOGY_GENERATORS = {
        'random': random_graph,
        'barabasi_albert': barabasi_albert,
        'small_world': small_world,
        'geographic': geographic,
    }

    def __init__(self, n_nodes: int, topology_type: str = 'random',
                 seed: int = 42, use_real_liu: bool = False):
        self.n_nodes = n_nodes
        self.seed = seed
        self.use_real_liu = use_real_liu
        self.rng = _random.Random(seed)
        self.clock = SimClock()
        self.bus = SimMessageBus(self.clock)

        # Create nodes
        self.nodes: dict[int, SimNode] = {}
        for i in range(n_nodes):
            node = SimNode(i, _random.Random(seed + i))
            self.nodes[i] = node
            self.bus.register_handler(i, node.receive_message)

        # Generate topology and establish channels
        gen = self.TOPOLOGY_GENERATORS.get(topology_type)
        if gen is None:
            raise ValueError(f"Unknown topology: {topology_type}")

        self.adj = gen(n_nodes, rng=_random.Random(seed))
        self._establish_channels()

    def _establish_channels(self):
        """Create Liu channels for all edges in the topology."""
        established = set()
        for node_id, neighbors in self.adj.items():
            for peer_id in neighbors:
                edge = (min(node_id, peer_id), max(node_id, peer_id))
                if edge not in established:
                    psk = _make_psk(edge[0], edge[1], self.rng)
                    self.nodes[edge[0]].establish_channel(
                        edge[1], psk, use_real_liu=self.use_real_liu)
                    self.nodes[edge[1]].establish_channel(
                        edge[0], psk, use_real_liu=self.use_real_liu)
                    established.add(edge)
        self.n_channels = len(established)

    def send(self, src: int, dst: int, msg_type: str, payload: dict,
             delay: int = None):
        """Send a message between nodes."""
        self.bus.send(src, dst, msg_type, payload, delay)

    def broadcast(self, src: int, msg_type: str, payload: dict):
        """Broadcast from src to all neighbors."""
        neighbors = list(self.nodes[src].neighbors)
        self.bus.broadcast(src, msg_type, payload, recipients=neighbors)

    def tick(self, n: int = 1):
        """Advance simulation by n ticks."""
        self.clock.advance(n)

    def run_until_idle(self, max_ticks: int = 10000) -> int:
        return self.clock.run_until_idle(max_ticks)

    @property
    def honest_nodes(self) -> list:
        return [n for n in self.nodes.values() if not n.corrupt]

    @property
    def corrupt_nodes(self) -> list:
        return [n for n in self.nodes.values() if n.corrupt]

    def mark_corrupt(self, node_ids: list):
        """Mark nodes as adversary-controlled."""
        for nid in node_ids:
            self.nodes[nid].corrupt = True

    def is_connected(self) -> bool:
        """Check if the overlay graph is connected."""
        if not self.nodes:
            return True
        visited = set()
        stack = [0]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            stack.extend(self.adj.get(node, set()) - visited)
        return len(visited) == self.n_nodes

    def average_degree(self) -> float:
        if not self.nodes:
            return 0.0
        return sum(len(neighbors) for neighbors in self.adj.values()) / self.n_nodes
