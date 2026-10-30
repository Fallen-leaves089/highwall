"""In-process counters exposed through the loopback admin plane."""

from __future__ import annotations

from typing import Mapping


class Metrics:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}

    def inc(self, name: str, amount: float = 1.0) -> None:
        if not self.enabled:
            return
        self._counters[name] = self._counters.get(name, 0.0) + amount

    def set_gauge(self, name: str, value: float) -> None:
        if not self.enabled:
            return
        self._gauges[name] = float(value)

    def get(self, name: str) -> float:
        return self._gauges.get(name, self._counters.get(name, 0.0))

    def snapshot(self) -> dict[str, float]:
        data = dict(self._counters)
        data.update(self._gauges)
        return data

    def to_prometheus(self) -> str:
        lines: list[str] = []
        for name, value in sorted(self._counters.items()):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {_format_number(value)}")
        for name, value in sorted(self._gauges.items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {_format_number(value)}")
        return "\n".join(lines) + ("\n" if lines else "")


def _format_number(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")


def merge_metrics(items: Mapping[str, float]) -> dict[str, float]:
    return dict(items)

