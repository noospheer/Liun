"""CSV/JSON output for all measurements."""

import json
import csv
import io
from sim.metrics.collector import MetricsCollector


class Reporter:
    """Generates CSV and JSON reports from collected metrics."""

    def __init__(self, collector: MetricsCollector):
        self.collector = collector

    def to_csv(self, name: str = None) -> str:
        """Export measurements to CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['name', 'n', 'time_s', 'bytes_sent', 'memory_bytes'])

        measurements = (self.collector.get(name) if name
                        else self.collector.measurements)
        for m in measurements:
            writer.writerow([m.name, m.n, m.time_s, m.bytes_sent, m.memory_bytes])

        return output.getvalue()

    def to_json(self, name: str = None) -> str:
        """Export measurements to JSON string."""
        measurements = (self.collector.get(name) if name
                        else self.collector.measurements)
        data = []
        for m in measurements:
            entry = {
                'name': m.name,
                'n': m.n,
                'time_s': m.time_s,
                'bytes_sent': m.bytes_sent,
                'memory_bytes': m.memory_bytes,
            }
            entry.update(m.extra)
            data.append(entry)

        return json.dumps(data, indent=2)

    def to_dict(self, name: str = None) -> list:
        """Export as list of dicts."""
        measurements = (self.collector.get(name) if name
                        else self.collector.measurements)
        return [
            {
                'name': m.name, 'n': m.n, 'time_s': m.time_s,
                'bytes_sent': m.bytes_sent, 'memory_bytes': m.memory_bytes,
                **m.extra,
            }
            for m in measurements
        ]

    def summary(self, name: str) -> dict:
        """Summary statistics for a named measurement."""
        ms = self.collector.get(name)
        if not ms:
            return {}

        times = [m.time_s for m in ms]
        return {
            'name': name,
            'count': len(ms),
            'min_time': min(times),
            'max_time': max(times),
            'avg_time': sum(times) / len(times),
            'total_time': sum(times),
            'n_values': sorted(set(m.n for m in ms)),
        }

    def write_csv(self, filepath: str, name: str = None):
        """Write CSV to file."""
        with open(filepath, 'w') as f:
            f.write(self.to_csv(name))

    def write_json(self, filepath: str, name: str = None):
        """Write JSON to file."""
        with open(filepath, 'w') as f:
            f.write(self.to_json(name))
