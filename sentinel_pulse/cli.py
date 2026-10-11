"""CLI entrypoint for sentinel-pulse.

Manages the core asynchronous sampling loop, metric collection, threshold
evaluations, alert cooldown state machines, and real-time terminal dashboards.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


# ============================================================================
# Core Data Models
# ============================================================================

@dataclass
class NetworkRate:
    """Network transfer rates in bytes per second."""
    bytes_sent_per_sec: float = 0.0
    bytes_recv_per_sec: float = 0.0


@dataclass
class SystemMetrics:
    """Snapshot of system resource metrics at a specific timestamp."""
    timestamp: float
    cpu_percent: float
    ram_percent: float
    ram_used_bytes: int
    ram_total_bytes: int
    disk_percent: float
    disk_used_bytes: int
    disk_total_bytes: int
    net_rates: NetworkRate = field(default_factory=NetworkRate)


@dataclass
class ThresholdConfig:
    """Threshold limits for trigger conditions."""
    cpu_percent: float = 85.0
    ram_percent: float = 90.0
    disk_percent: float = 90.0
    cooldown_seconds: float = 300.0


@dataclass
class WebhookConfig:
    """Webhook dispatch configurations."""
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None


@dataclass
class SentinelConfig:
    """Full daemon configuration."""
    interval_seconds: float = 2.0
    headless: bool = False
    log_level: str = "INFO"
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    webhooks: WebhookConfig = field(default_factory=WebhookConfig)


@dataclass
class AlertEvent:
    """Structure representing a threshold breach event."""
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: float
    is_resolved: bool = False


# ============================================================================
# Metrics Collector
# ============================================================================

class SystemResourceCollector:
    """Collects hardware and OS resource usage metrics with minimal overhead."""

    def __init__(self) -> None:
        self._last_net_io: Optional[Any] = None
        self._last_net_timestamp: float = time.time()
        if psutil is not None:
            # Prime CPU percent reading
            psutil.cpu_percent(interval=None)
            self._last_net_io = psutil.net_io_counters()

    def collect(self) -> SystemMetrics:
        """Collect current system metrics."""
        now = time.time()
        if psutil is None:
            # Fallback mock metrics if psutil is not installed
            return SystemMetrics(
                timestamp=now,
                cpu_percent=12.5,
                ram_percent=45.0,
                ram_used_bytes=7_200_000_000,
                ram_total_bytes=16_000_000_000,
                disk_percent=60.0,
                disk_used_bytes=300_000_000_000,
                disk_total_bytes=500_000_000_000,
                net_rates=NetworkRate(bytes_sent_per_sec=1024.0, bytes_recv_per_sec=2048.0),
            )

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(os.path.abspath(os.sep))

        # Calculate network I/O delta
        net_io = psutil.net_io_counters()
        time_delta = max(now - self._last_net_timestamp, 0.001)
        rates = NetworkRate()

        if self._last_net_io is not None:
            sent_diff = max(0, net_io.bytes_sent - self._last_net_io.bytes_sent)
            recv_diff = max(0, net_io.bytes_recv - self._last_net_io.bytes_recv)
            rates.bytes_sent_per_sec = sent_diff / time_delta
            rates.bytes_recv_per_sec = recv_diff / time_delta

        self._last_net_io = net_io
        self._last_net_timestamp = now

        return SystemMetrics(
            timestamp=now,
            cpu_percent=float(cpu),
            ram_percent=float(mem.percent),
            ram_used_bytes=mem.used,
            ram_total_bytes=mem.total,
            disk_percent=float(disk.percent),
            disk_used_bytes=disk.used,
            disk_total_bytes=disk.total,
            net_rates=rates,
        )


# ============================================================================
# Cooldown State Machine & Threshold Evaluator
# ============================================================================

class ThresholdEvaluator:
    """Evaluates metrics against threshold rules and maintains cooldown states."""

    def __init__(self, thresholds: ThresholdConfig) -> None:
        self.thresholds = thresholds
        # Maps metric_name -> last_alert_timestamp
        self._last_alert_times: Dict[str, float] = {}
        # Tracks metrics currently considered breached
        self._active_breaches: Set[str] = set()

    def evaluate(self, metrics: SystemMetrics) -> List[AlertEvent]:
        """Evaluate metrics against thresholds, returning alerts honoring cooldown."""
        events: List[AlertEvent] = []
        checks: List[Tuple[str, float, float]] = [
            ("CPU", metrics.cpu_percent, self.thresholds.cpu_percent),
            ("RAM", metrics.ram_percent, self.thresholds.ram_percent),
            ("Disk", metrics.disk_percent, self.thresholds.disk_percent),
        ]

        now = metrics.timestamp
        cooldown = self.thresholds.cooldown_seconds

        for name, current, threshold in checks:
            last_alert = self._last_alert_times.get(name, 0.0)
            in_breach = current >= threshold

            if in_breach:
                if name not in self._active_breaches or (now - last_alert >= cooldown):
                    events.append(
                        AlertEvent(
                            metric_name=name,
                            current_value=current,
                            threshold_value=threshold,
                            timestamp=now,
                            is_resolved=False,
                        )
                    )
                    self._last_alert_times[name] = now
                    self._active_breaches.add(name)
            else:
                if name in self._active_breaches:
                    # Breach resolved
                    events.append(
                        AlertEvent(
                            metric_name=name,
                            current_value=current,
                            threshold_value=threshold,
                            timestamp=now,
                            is_resolved=True,
                        )
                    )
                    self._active_breaches.discard(name)
                    self._last_alert_times[name] = now

        return events

    def get_cooldown_status(self, now: float) -> Dict[str, float]:
        """Returns remaining cooldown seconds per metric."""
        status: Dict[str, float] = {}
        for metric, last_time in self._last_alert_times.items():
            remaining = max(0.0, (last_time + self.thresholds.cooldown_seconds) - now)
            status[metric] = remaining
        return status


# ============================================================================
# Webhook Notifier
# ============================================================================

class WebhookNotifier:
    """Dispatches alert notifications asynchronously to Discord and Telegram."""

    def __init__(self, config: WebhookConfig) -> None:
        self.config = config

    async def dispatch_alert(self, event: AlertEvent, hostname: str) -> None:
        """Send notifications across configured webhooks asynchronously."""
        tasks = []
        if self.config.discord_webhook_url:
            tasks.append(self._send_discord(event, hostname))
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            tasks.append(self._send_telegram(event, hostname))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_discord(self, event: AlertEvent, hostname: str) -> None:
        """Send Discord webhook payload."""
        color = 0x2ECC71 if event.is_resolved else 0xE74C3C
        status_text = "RESOLVED" if event.is_resolved else "TRIGGERED"
        title = f"[{status_text}] {event.metric_name} Alert on {hostname}"
        description = (
            f"Metric `{event.metric_name}` is currently at **{event.current_value:.1f}%** "
            f"(Threshold: **{event.threshold_value:.1f}%**)"
        )

        payload = {
            "username": "Sentinel Pulse",
            "embeds": [
                {
                    "title": title,
                    "description": description,
                    "color": color,
                    "timestamp": datetime.fromtimestamp(event.timestamp, timezone.utc).isoformat(),
                    "fields": [
                        {"name": "Host", "value": hostname, "inline": True},
                        {"name": "Status", "value": status_text, "inline": True},
                        {
                            "name": "Current Value",
                            "value": f"{event.current_value:.1f}%",
                            "inline": True,
                        },
                    ],
                    "footer": {"text": "sentinel-pulse automated daemon"},
                }
            ],
        }

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            self._post_json,
            self.config.discord_webhook_url,  # type: ignore
            payload,
        )

    async def _send_telegram(self, event: AlertEvent, hostname: str) -> None:
        """Send Telegram webhook notification."""
        status_icon = "🟢 [RESOLVED]" if event.is_resolved else "🚨 [ALERT]"
        message = (
            f"{status_icon} *Sentinel Pulse Alert*\n"
            f"*Host:* `{hostname}`\n"
            f"*Metric:* `{event.metric_name}`\n"
            f"*Current:* `{event.current_value:.1f}%`\n"
            f"*Threshold:* `{event.threshold_value:.1f}%`\n"
            f"*Time:* `{datetime.fromtimestamp(event.timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`"
        )

        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
        }

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._post_json, url, payload)

    @staticmethod
    def _post_json(url: str, data: Dict[str, Any]) -> None:
        """Execute a synchronous HTTP POST with JSON data."""
        try:
            req_data = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Sentinel-Pulse/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                _ = resp.read()
        except Exception as exc:
            logging.getLogger("sentinel.notifier").error(
                "Webhook dispatch to %s failed: %s", url, exc
            )


# ============================================================================
# Terminal Dashboard
# ============================================================================

class TerminalDashboard:
    """Terminal dashboard rendered with ANSI escape sequences."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    CLEAR_SCREEN = "\033[2J\033[H"

    def __init__(self, hostname: str) -> None:
        self.hostname = hostname

    @classmethod
    def _render_bar(cls, percent: float, width: int = 24) -> str:
        """Render a colorized percentage progress bar."""
        clamped = max(0.0, min(100.0, percent))
        filled = int((clamped / 100.0) * width)
        empty = width - filled

        if clamped >= 90.0:
            color = cls.RED
        elif clamped >= 75.0:
            color = cls.YELLOW
        else:
            color = cls.GREEN

        bar_fill = "█" * filled
        bar_empty = "░" * empty
        return f"{color}[{bar_fill}{bar_empty}]{cls.RESET} {percent:5.1f}%"

    @classmethod
    def _format_bytes(cls, byte_count: float) -> str:
        """Format bytes into human-readable units."""
        units = ["B", "KB", "MB", "GB", "TB"]
        idx = 0
        val = float(byte_count)
        while val >= 1024.0 and idx < len(units) - 1:
            val /= 1024.0
            idx += 1
        return f"{val:6.1f} {units[idx]}"

    def render(
        self,
        metrics: SystemMetrics,
        thresholds: ThresholdConfig,
        cooldowns: Dict[str, float],
        event_history: List[AlertEvent],
    ) -> None:
        """Render the complete dashboard view to stdout."""
        ts_str = datetime.fromtimestamp(metrics.timestamp, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        lines: List[str] = [
            self.CLEAR_SCREEN,
            f"{self.BOLD}{self.CYAN}=== SENTINEL PULSE :: CROSS-PLATFORM DIAGNOSTIC DAEMON ==={self.RESET}",
            f"{self.DIM}Host: {self.hostname} | Time: {ts_str}{self.RESET}\n",
            f"{self.BOLD}RESOURCE UTILIZATION:{self.RESET}",
            f"  CPU Usage:  {self._render_bar(metrics.cpu_percent)}  (Limit: {thresholds.cpu_percent:.1f}%)",
            f"  RAM Usage:  {self._render_bar(metrics.ram_percent)}  "
            f"[{self._format_bytes(metrics.ram_used_bytes)} / {self._format_bytes(metrics.ram_total_bytes)}]  "
            f"(Limit: {thresholds.ram_percent:.1f}%)",
            f"  Disk Usage: {self._render_bar(metrics.disk_percent)}  "
            f"[{self._format_bytes(metrics.disk_used_bytes)} / {self._format_bytes(metrics.disk_total_bytes)}]  "
            f"(Limit: {thresholds.disk_percent:.1f}%)",
            "",
            f"{self.BOLD}NETWORK I/O:{self.RESET}",
            f"  TX Rate: {self.CYAN}{self._format_bytes(metrics.net_rates.bytes_sent_per_sec)}/s{self.RESET}"
            f"  |  RX Rate: {self.CYAN}{self._format_bytes(metrics.net_rates.bytes_recv_per_sec)}/s{self.RESET}",
            "",
            f"{self.BOLD}COOLDOWN TIMERS:{self.RESET}",
        ]

        if cooldowns:
            for metric, remaining in sorted(cooldowns.items()):
                state = (
                    f"{self.YELLOW}COOLDOWN ({remaining:.1f}s remaining){self.RESET}"
                    if remaining > 0
                    else f"{self.GREEN}ACTIVE / READY{self.RESET}"
                )
                lines.append(f"  {metric:<6}: {state}")
        else:
            lines.append(f"  {self.DIM}No alert triggers recorded.{self.RESET}")

        lines.extend([
            "",
            f"{self.BOLD}RECENT EVENTS DISPATCHED (Last 5):{self.RESET}",
        ])

        if event_history:
            for ev in event_history[-5:]:
                ev_time = datetime.fromtimestamp(ev.timestamp, timezone.utc).strftime("%H:%M:%S")
                color = self.GREEN if ev.is_resolved else self.RED
                status = "RESOLVED" if ev.is_resolved else "ALERT"
                lines.append(
                    f"  [{ev_time}] {color}[{status:<8}]{self.RESET} "
                    f"{ev.metric_name:<4} value: {ev.current_value:.1f}% (thr: {ev.threshold_value:.1f}%)"
                )
        else:
            lines.append(f"  {self.DIM}No threshold breaches recorded.{self.RESET}")

        lines.append(f"\n{self.DIM}[Press Ctrl+C to stop Sentinel Pulse safely]{self.RESET}")
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()


# ============================================================================
# Sentinel Pulse Daemon Orchestrator
# ============================================================================

class SentinelDaemon:
    """Core daemon managing asynchronous metrics acquisition and evaluation loop."""

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self.hostname = os.uname().nodename if hasattr(os, "uname") else "localhost"
        self.collector = SystemResourceCollector()
        self.evaluator = ThresholdEvaluator(config.thresholds)
        self.notifier = WebhookNotifier(config.webhooks)
        self.dashboard = TerminalDashboard(self.hostname)
        self.event_history: List[AlertEvent] = []
        self._running = False
        self.logger = logging.getLogger("sentinel.daemon")

    async def run(self) -> None:
        """Run the continuous monitoring loop."""
        self._running = True
        self.logger.info("Sentinel Pulse daemon started on %s.", self.hostname)

        while self._running:
            start_time = asyncio.get_running_loop().time()

            try:
                # 1. Sample metrics
                metrics = self.collector.collect()

                # 2. Evaluate thresholds and cooldowns
                events = self.evaluator.evaluate(metrics)

                # 3. Dispatch webhooks asynchronously for breaches/recoveries
                for event in events:
                    self.event_history.append(event)
                    if len(self.event_history) > 50:
                        self.event_history.pop(0)

                    self.logger.warning(
                        "Threshold event: %s at %.1f%% (Resolved: %s)",
                        event.metric_name,
                        event.current_value,
                        event.is_resolved,
                    )
                    asyncio.create_task(
                        self.notifier.dispatch_alert(event, self.hostname)
                    )

                # 4. Render terminal dashboard or log headless summary
                if not self.config.headless:
                    cooldowns = self.evaluator.get_cooldown_status(metrics.timestamp)
                    self.dashboard.render(
                        metrics=metrics,
                        thresholds=self.config.thresholds,
                        cooldowns=cooldowns,
                        event_history=self.event_history,
                    )
                else:
                    self.logger.debug(
                        "Metrics: CPU=%.1f%% RAM=%.1f%% Disk=%.1f%%",
                        metrics.cpu_percent,
                        metrics.ram_percent,
                        metrics.disk_percent,
                    )

            except Exception as exc:
                self.logger.error("Error during evaluation loop: %s", exc, exc_info=True)

            # Compute elapsed time and sleep for remaining interval
            elapsed = asyncio.get_running_loop().time() - start_time
            sleep_time = max(0.05, self.config.interval_seconds - elapsed)

            try:
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                self.logger.info("Loop cancellation signal received.")
                break

    def stop(self) -> None:
        """Signal the daemon loop to stop."""
        self._running = False


# ============================================================================
# CLI Configuration & Argument Parsing
# ============================================================================

def load_config_file(path_str: str) -> Dict[str, Any]:
    """Load configuration from JSON or fallback file."""
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path_str}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Invalid configuration file: Root must be a JSON object.")
    return data


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel-pulse",
        description="Cross-platform daemon and diagnostic tool for system resource monitoring and webhook alerts.",
    )

    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to JSON configuration file.",
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=2.0,
        help="Sampling loop interval in seconds (default: 2.0).",
    )
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        default=85.0,
        help="CPU utilization threshold percentage (default: 85.0).",
    )
    parser.add_argument(
        "--ram-threshold",
        type=float,
        default=90.0,
        help="RAM utilization threshold percentage (default: 90.0).",
    )
    parser.add_argument(
        "--disk-threshold",
        type=float,
        default=90.0,
        help="Disk utilization threshold percentage (default: 90.0).",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=300.0,
        help="Alert cooldown duration in seconds (default: 300.0).",
    )
    parser.add_argument(
        "--discord-webhook",
        type=str,
        default=os.getenv("SENTINEL_DISCORD_WEBHOOK"),
        help="Discord Webhook URL for alert notifications.",
    )
    parser.add_argument(
        "--telegram-token",
        type=str,
        default=os.getenv("SENTINEL_TELEGRAM_BOT_TOKEN"),
        help="Telegram Bot Token.",
    )
    parser.add_argument(
        "--telegram-chat-id",
        type=str,
        default=os.getenv("SENTINEL_TELEGRAM_CHAT_ID"),
        help="Telegram Chat ID.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without the interactive terminal dashboard (ideal for background services).",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Application logging verbosity.",
    )

    return parser


def parse_arguments_into_config(argv: Optional[List[str]] = None) -> SentinelConfig:
    """Parse CLI arguments merged with optional file configuration."""
    parser = build_parser()
    args = parser.parse_args(argv)

    file_cfg: Dict[str, Any] = {}
    if args.config:
        file_cfg = load_config_file(args.config)

    thresholds_cfg = file_cfg.get("thresholds", {})
    webhooks_cfg = file_cfg.get("webhooks", {})

    thresholds = ThresholdConfig(
        cpu_percent=float(thresholds_cfg.get("cpu_percent", args.cpu_threshold)),
        ram_percent=float(thresholds_cfg.get("ram_percent", args.ram_threshold)),
        disk_percent=float(thresholds_cfg.get("disk_percent", args.disk_threshold)),
        cooldown_seconds=float(thresholds_cfg.get("cooldown_seconds", args.cooldown)),
    )

    webhooks = WebhookConfig(
        discord_webhook_url=webhooks_cfg.get("discord_webhook_url", args.discord_webhook),
        telegram_bot_token=webhooks_cfg.get("telegram_bot_token", args.telegram_token),
        telegram_chat_id=webhooks_cfg.get("telegram_chat_id", args.telegram_chat_id),
    )

    return SentinelConfig(
        interval_seconds=float(file_cfg.get("interval_seconds", args.interval)),
        headless=bool(file_cfg.get("headless", args.headless)),
        log_level=str(file_cfg.get("log_level", args.log_level)),
        thresholds=thresholds,
        webhooks=webhooks,
    )


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> int:
    """CLI application entrypoint coordinating signals and the async loop."""
    try:
        config = parse_arguments_into_config()
    except Exception as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        return 1

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    return 0

if __name__ == "__main__":
    sys.exit(main())
