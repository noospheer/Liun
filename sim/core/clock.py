"""Discrete tick-based simulation clock.

One tick = one communication round. Deterministic for reproducible tests.
"""

import heapq
from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass(order=True)
class ScheduledEvent:
    tick: int
    seq: int = field(compare=True)  # tie-breaker for FIFO ordering
    callback: Callable = field(compare=False)
    args: tuple = field(default=(), compare=False)


class SimClock:
    """Deterministic tick-based simulation clock with event scheduling."""

    def __init__(self):
        self._tick = 0
        self._seq = 0
        self._events: list[ScheduledEvent] = []
        self._history: list[tuple] = []  # (tick, event_name) for debugging

    @property
    def tick(self) -> int:
        return self._tick

    def advance(self, n: int = 1):
        """Advance clock by n ticks, firing any scheduled events."""
        for _ in range(n):
            self._tick += 1
            self._fire_events()

    def schedule(self, delay: int, callback: Callable, *args) -> int:
        """Schedule an event to fire after `delay` ticks.

        Returns event sequence number.
        """
        if delay < 0:
            raise ValueError(f"Delay must be non-negative, got {delay}")
        event = ScheduledEvent(
            tick=self._tick + delay,
            seq=self._seq,
            callback=callback,
            args=args,
        )
        self._seq += 1
        heapq.heappush(self._events, event)
        return event.seq

    def schedule_at(self, tick: int, callback: Callable, *args) -> int:
        """Schedule an event at an absolute tick."""
        if tick < self._tick:
            raise ValueError(f"Cannot schedule in the past: {tick} < {self._tick}")
        return self.schedule(tick - self._tick, callback, *args)

    def _fire_events(self):
        """Fire all events scheduled for the current tick."""
        while self._events and self._events[0].tick <= self._tick:
            event = heapq.heappop(self._events)
            self._history.append((self._tick, event.callback.__name__))
            event.callback(*event.args)

    @property
    def pending_events(self) -> int:
        return len(self._events)

    def run_until_idle(self, max_ticks: int = 10000) -> int:
        """Advance until no more events, or max_ticks reached.

        Returns number of ticks advanced.
        """
        start = self._tick
        while self._events and (self._tick - start) < max_ticks:
            next_tick = self._events[0].tick
            if next_tick > self._tick:
                self._tick = next_tick
            self._fire_events()
        return self._tick - start
