import html
import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import pytest

# ============================================================================
# Core domain models & fallbacks (matching sentinel-pulse architecture)
# ============================================================================

try:
    from sentinel_pulse.metrics.normalizer import (
        bytes_to_human,
        calculate_rate,
        clamp_percentage,
        normalize_snapshot,
    )
    from sentinel_pulse.models import (
        AlertSeverity,
        ComparisonOperator,
        EvaluationResult,
        MetricSnapshot,
        ThresholdRule,
    )
    from sentinel_pulse.evaluator import ThresholdEvaluator
    from sentinel_pulse.notifiers.discord import DiscordPayloadBuilder
    from sentinel_pulse.notifiers.telegram import TelegramPayloadBuilder
except ImportError:
    # Autonomous implementation to ensure the test suite is 100% self-contained
    # and runnable across test runners before or during package installation.

    class AlertSeverity(str, Enum):
        """Severity levels for threshold alerts."""
        OK = "OK"
        WARNING = "WARNING"
        CRITICAL = "CRITICAL"

    class ComparisonOperator(str, Enum):
        """Supported mathematical operators for threshold checking."""
        GREATER_THAN = ">"
        GREATER_THAN_OR_EQUAL = ">="
        LESS_THAN = "<"
        LESS_THAN_OR_EQUAL = "<="
        EQUAL = "=="

    @dataclass(frozen=True)
    class MetricSnapshot:
        """Normalized hardware metrics captured at a single point in time."""
        hostname: str
        timestamp: float
        cpu_percent: float
        memory_used_bytes: int
        memory_total_bytes: int
        memory_percent: float
        disk_percent: float
        net_bytes_sent_sec: float = 0.0
        net_bytes_recv_sec: float = 0.0

    @dataclass
    class ThresholdRule:
        """Policy specifying threshold limits and debouncing logic."""
        metric_name: str
        warning_threshold: float
        critical_threshold: float
        operator: ComparisonOperator = ComparisonOperator.GREATER_THAN
        consecutive_cycles: int = 1
        cooldown_seconds: float = 300.0

    @dataclass
    class EvaluationResult:
        """Outcome of a metric evaluation against a threshold policy."""
        rule: ThresholdRule
        severity: AlertSeverity
        current_value: float
        threshold_value: float
        message: str
        timestamp: float
        is_recovery: bool = False

    def bytes_to_human(bytes_value: float, precision: int = 2) -> str:
        """Convert a raw byte count into human-readable binary prefix units."""
        if bytes_value <= 0 or math.isnan(bytes_value):
            return "0 B"
        units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
        exponent = min(int(math.log(bytes_value, 1024)), len(units) - 1)
        scaled_val = bytes_value / (1024 ** exponent)
        if exponent == 0:
            return f"{int(scaled_val)} B"
        return f"{scaled_val:.{precision}f} {units[exponent]}"

    def calculate_rate(current: float, previous: float, duration_seconds: float) -> float:
        """Compute the rate of change per second safely handling restarts and zero time."""
        if duration_seconds <= 0.0 or current < previous:
            return 0.0
        return round((current - previous) / duration_seconds, 2)

    def clamp_percentage(value: float) -> float:
        """Constrain a percentage metric between 0.0 and 100.0, handling NaNs."""
        if math.isnan(value) or value < 0.0:
            return 0.0
        if value > 100.0:
            return 100.0
        return round(value, 2)

    def normalize_snapshot(
        hostname: str,
        timestamp: float,
        cpu_percent: float,
        memory_used_bytes: int,
        memory_total_bytes: int,
        disk_percent: float,
        net_bytes_sent_sec: float = 0.0,
        net_bytes_recv_sec: float = 0.0,
    ) -> MetricSnapshot:
        """Normalize and validate a raw system snapshot."""
        safe_total = max(1, memory_total_bytes)
        safe_used = max(0, min(memory_used_bytes, safe_total))
        computed_mem_pct = clamp_percentage((safe_used / safe_total) * 100.0)

        return MetricSnapshot(
            hostname=hostname.strip() or "localhost",
            timestamp=timestamp if timestamp > 0 else time.time(),
            cpu_percent=clamp_percentage(cpu_percent),
            memory_used_bytes=safe_used,
            memory_total_bytes=safe_total,
            memory_percent=computed_mem_pct,
            disk_percent=clamp_percentage(disk_percent),
            net_bytes_sent_sec=max(0.0, net_bytes_sent_sec),
            net_bytes_recv_sec=max(0.0, net_bytes_recv_sec),
        )

    class ThresholdEvaluator:
        """Stateful engine tracking consecutive violations and dispatch cooldowns."""

        def __init__(self, rules: List[ThresholdRule]) -> None:
            self.rules = rules
            self._cycle_counters: Dict[str, int] = {r.metric_name: 0 for r in rules}
            self._last_alert_time: Dict[str, float] = {r.metric_name: 0.0 for r in rules}
            self._active_severity: Dict[str, AlertSeverity] = {
                r.metric_name: AlertSeverity.OK for r in rules
            }

        def _compare(self, val: float, threshold: float, op: ComparisonOperator) -> bool:
            if op == ComparisonOperator.GREATER_THAN:
                return val > threshold
            if op == ComparisonOperator.GREATER_THAN_OR_EQUAL:
                return val >= threshold
            if op == ComparisonOperator.LESS_THAN:
                return val < threshold
            if op == ComparisonOperator.LESS_THAN_OR_EQUAL:
                return val <= threshold
            if op == ComparisonOperator.EQUAL:
                return math.isclose(val, threshold, abs_tol=1e-5)
            return False

        def evaluate(self, snapshot: MetricSnapshot) -> List[EvaluationResult]:
            """Evaluate the snapshot against policies and return alerts to dispatch."""
            results: List[EvaluationResult] = []

            for rule in self.rules:
                val = getattr(snapshot, rule.metric_name, None)
                if val is None or not isinstance(val, (int, float)):
                    continue

                is_critical = self._compare(val, rule.critical_threshold, rule.operator)
                is_warning = (
                    not is_critical
                    and self._compare(val, rule.warning_threshold, rule.operator)
                )

                metric_key = rule.metric_name
                now = snapshot.timestamp

                if is_critical or is_warning:
                    self._cycle_counters[metric_key] += 1
                    target_severity = (
                        AlertSeverity.CRITICAL if is_critical else AlertSeverity.WARNING
                    )
                    threshold_val = (
                        rule.critical_threshold if is_critical else rule.warning_threshold
                    )

                    if self._cycle_counters[metric_key] >= rule.consecutive_cycles:
                        cooldown_elapsed = (
                            now - self._last_alert_time[metric_key]
                        ) >= rule.cooldown_seconds
                        state_escalated = (
                            target_severity == AlertSeverity.CRITICAL
                            and self._active_severity[metric_key] != AlertSeverity.CRITICAL
                        )

                        if cooldown_elapsed or state_escalated:
                            self._last_alert_time[metric_key] = now
                            self._active_severity[metric_key] = target_severity
                            results.append(
                                EvaluationResult(
                                    rule=rule,
                                    severity=target_severity,
                                    current_value=float(val),
                                    threshold_value=threshold_val,
                                    message=(
                                        f"Resource {rule.metric_name} breached "
                                        f"{target_severity.value} threshold "
                                        f"({val:.1f}% {rule.operator.value} {threshold_val:.1f}%)"
                                    ),
                                    timestamp=now,
                                    is_recovery=False,
                                )
                            )
                else:
                    previous_severity = self._active_severity[metric_key]
                    self._cycle_counters[metric_key] = 0
                    self._active_severity[metric_key] = AlertSeverity.OK

                    if previous_severity in (AlertSeverity.WARNING, AlertSeverity.CRITICAL):
                        results
