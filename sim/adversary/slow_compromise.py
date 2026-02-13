"""Slow compromise: gradual node takeover.

Tests how the system responds when Eve compromises 1 node per epoch.
Measures epochs until trust shift becomes detectable.
"""

from liun.overlay import OverlayGraph, personalized_pagerank


class SlowCompromise:
    """Simulates gradual compromise of nodes over time.

    Eve compromises one honest node per epoch.
    Tracks trust evolution and detects when corruption shifts trust.
    """

    def __init__(self, graph: OverlayGraph, honest_ids: set,
                 compromise_order: list = None, rng=None):
        self.graph = graph
        self.honest_ids = set(honest_ids)
        self.compromised: set = set()
        self.epoch = 0
        self.trust_history: list = []

        if compromise_order is None:
            import random
            r = rng or random.Random(42)
            self.compromise_order = list(honest_ids)
            r.shuffle(self.compromise_order)
        else:
            self.compromise_order = list(compromise_order)

    def compromise_next(self) -> int:
        """Compromise the next node. Returns the compromised node ID."""
        if not self.compromise_order:
            return None
        node = self.compromise_order.pop(0)
        self.compromised.add(node)
        self.honest_ids.discard(node)
        self.epoch += 1
        return node

    def measure_trust(self, seed: int) -> dict:
        """Measure current trust state from seed's perspective."""
        trust = personalized_pagerank(seed, self.graph)

        honest_trust = sum(trust.get(n, 0) for n in self.honest_ids)
        compromised_trust = sum(trust.get(n, 0) for n in self.compromised)
        total = honest_trust + compromised_trust

        result = {
            'epoch': self.epoch,
            'n_compromised': len(self.compromised),
            'honest_trust': honest_trust,
            'compromised_trust': compromised_trust,
            'compromised_fraction': compromised_trust / total if total > 0 else 0,
            'can_disrupt_consensus': compromised_trust > total / 3,
        }

        self.trust_history.append(result)
        return result

    def run_epochs(self, n_epochs: int, seed: int) -> list:
        """Run n epochs of slow compromise, measuring trust each epoch."""
        results = []
        # Initial measurement
        results.append(self.measure_trust(seed))

        for _ in range(n_epochs):
            node = self.compromise_next()
            if node is None:
                break
            results.append(self.measure_trust(seed))

        return results

    def epochs_to_disruption(self) -> int:
        """How many epochs until compromised nodes can disrupt consensus?"""
        for entry in self.trust_history:
            if entry['can_disrupt_consensus']:
                return entry['epoch']
        return -1  # never reached
