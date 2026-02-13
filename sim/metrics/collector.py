"""Timing, throughput, memory, and security metrics collection."""

import time
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class Measurement:
    name: str
    n: int  # network size
    time_s: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    memory_bytes: int = 0
    extra: dict = field(default_factory=dict)


class MetricsCollector:
    """Instruments protocol operations with timing and resource metrics."""

    def __init__(self):
        self.measurements: list[Measurement] = []
        self._active: dict[str, dict] = {}

    @contextmanager
    def measure(self, name: str, n: int = 0):
        """Context manager to measure an operation.

        Usage:
            with collector.measure('dkg', n=100) as m:
                run_dkg(100)
            # m.time_s now contains elapsed time
        """
        m = Measurement(name=name, n=n)
        start_time = time.perf_counter()
        try:
            yield m
        finally:
            m.time_s = time.perf_counter() - start_time
            self.measurements.append(m)

    def record(self, name: str, n: int, time_s: float = 0,
               bytes_sent: int = 0, memory_bytes: int = 0, **extra):
        """Manually record a measurement."""
        m = Measurement(
            name=name, n=n, time_s=time_s,
            bytes_sent=bytes_sent, memory_bytes=memory_bytes,
            extra=extra,
        )
        self.measurements.append(m)
        return m

    def get(self, name: str) -> list[Measurement]:
        """Get all measurements with given name."""
        return [m for m in self.measurements if m.name == name]

    def get_series(self, name: str) -> dict:
        """Get (n, time) series for a named measurement.

        Returns: {'n': [...], 'time_s': [...], 'bytes': [...], 'memory': [...]}
        """
        ms = sorted(self.get(name), key=lambda m: m.n)
        return {
            'n': [m.n for m in ms],
            'time_s': [m.time_s for m in ms],
            'bytes': [m.bytes_sent for m in ms],
            'memory': [m.memory_bytes for m in ms],
        }

    def measure_memory(self, obj) -> int:
        """Estimate memory usage of an object."""
        return sys.getsizeof(obj)

    def clear(self):
        self.measurements.clear()
