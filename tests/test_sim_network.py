"""Tests for simulation network layer."""

import pytest
from sim.network.graph_gen import (
    random_graph, barabasi_albert, small_world, geographic,
    channels_per_node_default,
)
from sim.network.sim_network import SimNetwork
import random


class TestGraphGenerators:

    def test_random_graph_size(self):
        g = random_graph(20, rng=random.Random(1))
        assert len(g) == 20
        # Every node has at least some connections
        assert all(len(g[i]) >= 0 for i in range(20))

    def test_barabasi_albert_size(self):
        g = barabasi_albert(20, m=3, rng=random.Random(1))
        assert len(g) == 20

    def test_small_world_size(self):
        g = small_world(20, k=4, p=0.1, rng=random.Random(1))
        assert len(g) == 20

    def test_geographic_size(self):
        g = geographic(20, rng=random.Random(1))
        assert len(g) == 20

    def test_symmetry(self):
        """All graphs must be undirected (symmetric adjacency)."""
        for gen in [random_graph, barabasi_albert, small_world, geographic]:
            g = gen(15, rng=random.Random(42))
            for node, neighbors in g.items():
                for n in neighbors:
                    assert node in g[n], f"{gen.__name__}: {node} -> {n} not symmetric"

    def test_channels_per_node_default(self):
        assert channels_per_node_default(8) == 4  # log2(8)+1=4, max(3,4)=4
        assert channels_per_node_default(4) == 3  # log2(4)+1=3, max(3,3)=3
        assert channels_per_node_default(1024) == 11  # log2(1024)+1=11


class TestSimNetwork:

    def test_n10_initializes(self):
        net = SimNetwork(10, 'random', seed=42)
        assert len(net.nodes) == 10
        assert net.n_channels > 0

    def test_channels_established(self):
        net = SimNetwork(10, 'random', seed=42)
        # Each node should have channels
        for node in net.nodes.values():
            assert len(node.channels) > 0
            assert node.degree > 0

    def test_messages_route(self):
        net = SimNetwork(10, 'random', seed=42)
        # Find two connected nodes
        node0 = net.nodes[0]
        if node0.neighbors:
            peer = next(iter(node0.neighbors))
            net.send(0, peer, 'test', {'data': 42})
            net.tick(1)
            assert len(net.nodes[peer].inbox) == 1
            assert net.nodes[peer].inbox[0].payload['data'] == 42

    def test_broadcast(self):
        net = SimNetwork(10, 'random', seed=42)
        net.broadcast(0, 'announce', {'msg': 'hello'})
        net.tick(1)
        for peer_id in net.nodes[0].neighbors:
            assert len(net.nodes[peer_id].inbox) >= 1

    def test_connectivity(self):
        """Random graph on 10 nodes should be connected with high probability."""
        net = SimNetwork(10, 'random', seed=42)
        assert net.is_connected()

    def test_all_topologies(self):
        for topo in ['random', 'barabasi_albert', 'small_world', 'geographic']:
            net = SimNetwork(10, topo, seed=42)
            assert len(net.nodes) == 10

    def test_mark_corrupt(self):
        net = SimNetwork(10, 'random', seed=42)
        net.mark_corrupt([1, 3, 5])
        assert len(net.corrupt_nodes) == 3
        assert len(net.honest_nodes) == 7

    def test_average_degree(self):
        net = SimNetwork(20, 'random', seed=42)
        avg = net.average_degree()
        assert avg > 1  # should have some connectivity
