"""Eclipse attack: all bootstrap paths through Eve.

Tests whether Eve controlling all paths to a new node can
intercept all Shamir shares during bootstrap.
"""

from liun.overlay import OverlayGraph


class EclipseAttack:
    """Simulates an eclipse attack on bootstrap.

    Eve controls relay nodes on all k bootstrap paths. If she controls
    all paths, she intercepts all shares and reconstructs the secret.
    """

    def __init__(self, n_paths: int, eclipse_fraction: float):
        """
        n_paths: total number of bootstrap paths (k).
        eclipse_fraction: fraction of paths controlled by Eve (0.0 to 1.0).
        """
        self.n_paths = n_paths
        self.eclipse_fraction = eclipse_fraction
        self.eclipsed_paths = int(n_paths * eclipse_fraction)
        self.observed_shares: list = []

    def run(self, shares: list) -> dict:
        """Simulate eclipse attack on a set of bootstrap shares.

        shares: list of n_paths (share_index, share_value) tuples.

        Returns:
            dict with:
                'observed': list of shares Eve saw
                'unobserved': list of shares Eve missed
                'can_reconstruct': bool (True if Eve got all shares)
                'coverage': fraction of shares observed
        """
        observed = shares[:self.eclipsed_paths]
        unobserved = shares[self.eclipsed_paths:]
        self.observed_shares = observed

        return {
            'observed': observed,
            'unobserved': unobserved,
            'can_reconstruct': len(unobserved) == 0,
            'coverage': len(observed) / len(shares) if shares else 0,
        }


class EclipseTopologyAttack:
    """Eclipse via topology manipulation.

    Configure the overlay graph so all paths from target converge
    through Eve's nodes.
    """

    def __init__(self, graph: OverlayGraph, eve_nodes: set, target: int):
        self.graph = graph
        self.eve_nodes = eve_nodes
        self.target = target

    def find_independent_paths(self, source: int) -> list:
        """Find all node-independent paths from source to target.

        Returns list of paths, each path is a list of node IDs.
        """
        paths = []
        used_nodes = set()
        # Simple BFS-based path finding
        for _ in range(100):  # max attempts
            path = self._find_path_avoiding(source, self.target, used_nodes)
            if path is None:
                break
            paths.append(path)
            used_nodes.update(path[1:-1])  # exclude source and target
        return paths

    def _find_path_avoiding(self, src, dst, avoid):
        """BFS path from src to dst avoiding certain nodes."""
        from collections import deque
        visited = {src}
        queue = deque([(src, [src])])
        while queue:
            node, path = queue.popleft()
            for neighbor in self.graph.neighbors(node):
                if neighbor == dst:
                    return path + [dst]
                if neighbor not in visited and neighbor not in avoid:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return None

    def all_paths_through_eve(self, source: int) -> bool:
        """Check if all paths from source to target pass through Eve's nodes."""
        paths = self.find_independent_paths(source)
        if not paths:
            return True  # no paths at all
        for path in paths:
            intermediaries = set(path[1:-1])
            if not intermediaries & self.eve_nodes:
                return False  # found a clean path
        return True
