"""Physical internet topology model for bootstrap attack testing.

Simulates routers, ASes, submarine cables, and IXPs to model
realistic bootstrap path diversity.
"""

import random as _random
import math


class AS:
    """Autonomous System."""

    def __init__(self, as_id: int, country: str, tier: int = 2):
        self.as_id = as_id
        self.country = country
        self.tier = tier  # 1=backbone, 2=regional, 3=access
        self.routers: set[int] = set()
        self.peers: set[int] = set()  # peer AS IDs
        self.upstreams: set[int] = set()  # upstream provider AS IDs


class PhysicalTopology:
    """Model of internet physical infrastructure.

    Represents routers, ASes, submarine cables, and IXPs.
    Used to evaluate bootstrap path diversity.
    """

    def __init__(self, rng=None):
        self.rng = rng or _random.Random(42)
        self.ases: dict[int, AS] = {}
        self.routers: dict[int, int] = {}  # router_id -> as_id
        self.links: dict[tuple, dict] = {}  # (router_a, router_b) -> metadata
        self.chokepoints: set[int] = set()  # router IDs that are chokepoints
        self.ixps: list[set] = []  # list of sets of AS IDs at each IXP

    def add_as(self, as_id: int, country: str, tier: int = 2) -> AS:
        a = AS(as_id, country, tier)
        self.ases[as_id] = a
        return a

    def add_router(self, router_id: int, as_id: int):
        self.routers[router_id] = as_id
        self.ases[as_id].routers.add(router_id)

    def add_link(self, r_a: int, r_b: int, link_type: str = 'fiber',
                 capacity_gbps: float = 10.0):
        key = (min(r_a, r_b), max(r_a, r_b))
        self.links[key] = {
            'type': link_type, 'capacity': capacity_gbps,
        }

    def add_ixp(self, as_ids: set):
        self.ixps.append(as_ids)
        for a in as_ids:
            for b in as_ids:
                if a != b and a in self.ases and b in self.ases:
                    self.ases[a].peers.add(b)
                    self.ases[b].peers.add(a)

    def mark_chokepoint(self, router_id: int):
        self.chokepoints.add(router_id)

    def find_path(self, src_router: int, dst_router: int,
                  avoid: set = None) -> list:
        """BFS path from src to dst router, avoiding specific routers."""
        if avoid is None:
            avoid = set()
        from collections import deque
        visited = {src_router}
        queue = deque([(src_router, [src_router])])
        while queue:
            node, path = queue.popleft()
            for (a, b) in self.links:
                neighbor = b if a == node else (a if b == node else None)
                if neighbor is None:
                    continue
                if neighbor == dst_router:
                    return path + [dst_router]
                if neighbor not in visited and neighbor not in avoid:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return []

    def path_as_diversity(self, path: list) -> set:
        """Return set of ASes traversed by a router path."""
        return {self.routers[r] for r in path if r in self.routers}

    def path_country_diversity(self, path: list) -> set:
        """Return set of countries traversed."""
        countries = set()
        for r in path:
            if r in self.routers:
                as_id = self.routers[r]
                if as_id in self.ases:
                    countries.add(self.ases[as_id].country)
        return countries

    def generate_realistic(self, n_ases: int = 20, routers_per_as: int = 3):
        """Generate a realistic-ish topology for testing."""
        countries = ['US', 'DE', 'JP', 'BR', 'AU', 'GB', 'FR', 'KR', 'IN', 'ZA']
        router_id = 0

        # Create ASes
        for i in range(n_ases):
            tier = 1 if i < 3 else (2 if i < 8 else 3)
            country = countries[i % len(countries)]
            self.add_as(i, country, tier)
            for _ in range(routers_per_as):
                self.add_router(router_id, i)
                router_id += 1

        # Connect routers within ASes
        for as_obj in self.ases.values():
            routers = sorted(as_obj.routers)
            for i in range(len(routers) - 1):
                self.add_link(routers[i], routers[i + 1], 'internal')

        # Connect ASes: tier-1 to tier-1, tier-2 to tier-1, tier-3 to tier-2
        tier1 = [a for a in self.ases.values() if a.tier == 1]
        tier2 = [a for a in self.ases.values() if a.tier == 2]
        tier3 = [a for a in self.ases.values() if a.tier == 3]

        # Tier-1 mesh
        for i, a in enumerate(tier1):
            for b in tier1[i + 1:]:
                r_a = max(a.routers)
                r_b = min(b.routers)
                self.add_link(r_a, r_b, 'submarine')
                a.peers.add(b.as_id)
                b.peers.add(a.as_id)

        # Tier-2 connect to tier-1
        for a in tier2:
            upstream = self.rng.choice(tier1)
            r_a = max(a.routers)
            r_b = min(upstream.routers)
            self.add_link(r_a, r_b, 'transit')
            a.upstreams.add(upstream.as_id)

        # Tier-3 connect to tier-2
        for a in tier3:
            if tier2:
                upstream = self.rng.choice(tier2)
                r_a = max(a.routers)
                r_b = min(upstream.routers)
                self.add_link(r_a, r_b, 'transit')
                a.upstreams.add(upstream.as_id)

        return self


class MultiPathBootstrap:
    """Multi-path bootstrap: Shamir-encode shares, route via diverse paths.

    Protocol 01: new node establishes ITS shared secrets with existing
    nodes via geographically diverse paths.
    """

    def __init__(self, topology: PhysicalTopology, k: int = 20,
                 threshold: int = 14):
        self.topology = topology
        self.k = k
        self.threshold = threshold

    def select_targets(self, new_node_as: int,
                       candidate_ases: list) -> list:
        """Select k target ASes maximizing geographic diversity."""
        # Group by country
        by_country: dict[str, list] = {}
        for as_id in candidate_ases:
            if as_id in self.topology.ases:
                country = self.topology.ases[as_id].country
                by_country.setdefault(country, []).append(as_id)

        # Round-robin from each country
        targets = []
        country_lists = list(by_country.values())
        idx = 0
        while len(targets) < self.k and country_lists:
            for cl in list(country_lists):
                if idx < len(cl) and len(targets) < self.k:
                    targets.append(cl[idx])
                elif idx >= len(cl):
                    country_lists.remove(cl)
            idx += 1

        return targets[:self.k]

    def find_diverse_paths(self, src_router: int,
                           dst_routers: list) -> list:
        """Find paths from src to each dst, maximizing diversity."""
        paths = []
        for dst in dst_routers:
            path = self.topology.find_path(src_router, dst)
            if path:
                paths.append({
                    'path': path,
                    'dst': dst,
                    'ases': self.topology.path_as_diversity(path),
                    'countries': self.topology.path_country_diversity(path),
                })
        return paths

    def evaluate_eclipse_resistance(self, src_router: int,
                                    dst_routers: list,
                                    eve_routers: set) -> dict:
        """Evaluate how many paths Eve can observe.

        Returns metrics on eclipse coverage.
        """
        paths = self.find_diverse_paths(src_router, dst_routers)
        observed = 0
        for p in paths:
            if eve_routers & set(p['path'][1:-1]):  # Eve on the path
                observed += 1

        return {
            'total_paths': len(paths),
            'observed_paths': observed,
            'clean_paths': len(paths) - observed,
            'coverage': observed / len(paths) if paths else 0,
            'bootstrap_success': (len(paths) - observed) >= 1,
        }


class PathSelector:
    """Selects bootstrap paths maximizing geographic/AS diversity."""

    def __init__(self, topology: PhysicalTopology):
        self.topology = topology

    def diversity_score(self, paths: list) -> float:
        """Score path set by AS and country diversity."""
        all_ases = set()
        all_countries = set()
        for p in paths:
            all_ases.update(p.get('ases', set()))
            all_countries.update(p.get('countries', set()))
        return len(all_ases) + 2 * len(all_countries)
