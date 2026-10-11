"""Webhook dispatch engine implementing Discord Embeds and Telegram Bot API formatting.

This module provides asynchronous notification dispatching across Discord and
Telegram platforms using httpx with resilience features such as retries, rate-limit
handling, and structured payload formatting.
"""

from __future__ import annotations

import abc
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import html
import logging
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

import httpx

logger = logging.getLogger("sentinel_pulse.notifiers")


class AlertSeverity(str, Enum):
    """Severity levels for sentinel-pulse alert notifications."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    RESOLVED = "RESOLVED"

    @property
    def color_discord(self) -> int:
        """Hexadecimal color code corresponding to the severity for Discord embeds."""
        colors = {
            AlertSeverity.INFO: 0x3498DB,      # Blue
            AlertSeverity.WARNING: 0xF1C40F,   # Yellow
            AlertSeverity.CRITICAL: 0xE74C3C,  # Red
            AlertSeverity.RESOLVED: 0x2ECC71,  # Green
        }
        return colors[self]

    @property
    def emoji(self) -> str:
        """Visual emoji icon for text representation."""
        emojis = {
            AlertSeverity.INFO: "ℹ️",
            AlertSeverity.WARNING: "⚠️",
            AlertSeverity.CRITICAL: "🚨",
            AlertSeverity.RESOLVED: "✅",
        }
        return emojis[self]


@dataclass(frozen=True)
class MetricSnapshot:
    """Individual metric observation at alert trigger time."""

    name: str
    current_value: Union[float, int, str]
    threshold_value: Optional[Union[float, int, str]] = None
    unit: str = "%"

    def format_value(self) -> str:
        """Format the current metric value with its unit."""
        if isinstance(self.current_value, float):
            return f"{self.current_value:.2f}{self.unit}"
        return f"{self.current_value}{self.unit}"

    def format_threshold(self) -> str:
        """Format the threshold value with unit, if available."""
        if self.threshold_value is None:
            return "N/A"
        if isinstance(self.threshold_value, float):
            return f"{self.threshold_value:.2f}{self.unit}"
        return f"{self.threshold_value}{self.unit}"


@dataclass
class AlertNotification:
    """Standardized alert payload consumed by all notification backends."""

    title: str
    message: str
    severity: AlertSeverity
    hostname: str
    metrics: List[MetricSnapshot] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseNotifier(abc.ABC):
    """Abstract base class for all notification adapters."""

    def __init__(
        self,
        name: str,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
    ) -> None:
        """Initialize base notifier settings.

        Args:
            name: Human-readable name for logging purposes.
            timeout: HTTP request timeout in seconds.
            max_retries: Maximum number of delivery attempts upon retryable errors.
            backoff_factor: Exponential backoff factor between attempts.
        """
        self.name = name
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    @abc.abstractmethod
    def build_payload(self, alert: AlertNotification) -> Dict[str, Any]:
        """Convert a standard alert notification into destination-specific JSON payload.

        Args:
            alert: The standardized AlertNotification object.

        Returns:
            Dictionary payload ready for JSON serialization.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def dispatch(
        self,
        alert: AlertNotification,
        client: Optional[httpx.AsyncClient] = None,
    ) -> bool:
        """Send the alert notification asynchronously.

        Args:
            alert: The alert event to notify.
            client: Optional shared httpx.AsyncClient instance.

        Returns:
            True if delivered successfully, False otherwise.
        """
        raise NotImplementedError

    async def _post_with_retry(
        self,
        url: str,
        payload: Dict[str, Any],
        client: Optional[httpx.AsyncClient] = None,
    ) -> bool:
        """Execute HTTP POST with automated backoff and rate-limit handling.

        Args:
            url: Endpoint target URL.
            payload: JSON payload to transmit.
            client: Optional shared httpx client.

        Returns:
            True if status code is 2xx, False otherwise.
        """
        owns_client = client is None
        async_client = client or httpx.AsyncClient(timeout=self.timeout)

        try:
            for attempt in range(1, self.max_retries + 1):
                try:
                    response = await async_client.post(url, json=payload)

                    if response.is_success:
                        logger.debug(
                            "[%s] Successfully delivered notification on attempt %d",
                            self.name,
                            attempt,
                        )
                        return True

                    if response.status_code == 429:
                        retry_after = 1.0
                        retry_header = response.headers.get("Retry-After")
                        if retry_header:
                            try:
                                retry_after = float(retry_header)
                            except ValueError:
                                pass
                        else:
                            try:
                                data = response.json()
                                retry_after = float(data.get("retry_after", 1.0))
                            except Exception:
                                pass

                        logger.warning(
                            "[%s] Rate-limited (429). Retrying in %.2fs (attempt %d/%d)",
                            self.name,
                            retry_after,
                            attempt,
                            self.max_retries,
                        )
                        await asyncio.sleep(retry_after)
                        continue

                    if response.status_code in (500, 502, 503, 504):
                        sleep_time = self.backoff_factor ** attempt
                        logger.warning(
                            "[%s] Server error %d. Retrying in %.2fs (attempt %d/%d)",
                            self.name,
                            response.status_code,
                            sleep_time,
                            attempt,
                            self.max_retries,
                        )
                        await asyncio.sleep(sleep_time)
                        continue

                    logger.error(
                        "[%s] Permanent failure with HTTP %d: %s",
                        self.name,
                        response.status_code,
                        response.text,
                    )
                    return False

                except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                    sleep_time = self.backoff_factor ** attempt
                    logger.warning(
                        "[%s] Network error '%s' on attempt %d/%d. Retrying in %.2fs",
                        self.name,
                        exc,
                        attempt,
                        self.max_retries,
                        sleep_time,
                    )
                    if attempt < self.max_retries:
                        await asyncio.sleep(sleep_time)
                    else:
                        logger.error("[%s] Max retries exceeded due to network error", self.name)
                        return False

            return False
        finally:
            if owns_client:
                await async_client.aclose()


class DiscordNotifier(BaseNotifier):
    """Discord Webhook adapter formatting alerts into rich Discord Embed structures."""

    def __init__(
        self,
        webhook_url: str,
        username: str = "Sentinel Pulse",
        avatar_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
    ) -> None:
        """Initialize Discord notifier.

        Args:
            webhook_url: Discord Webhook endpoint URL.
            username: Override username displayed by Discord.
            avatar_url: Override webhook avatar image URL.
            timeout: Network request timeout.
            max_retries: Max attempts for transient errors.
        """
        super().__init__(
            name="DiscordNotifier",
            timeout=timeout,
            max_retries=max_retries,
        )
        self.webhook_url = webhook_url
        self.username = username
        self.avatar_url = avatar_url

    def build_payload(self, alert: AlertNotification) -> Dict[str, Any]:
        """Generate Discord Embed payload.

        Args:
            alert: Source alert notification.

        Returns:
            Discord-compatible Webhook JSON payload dictionary.
        """
        embed_fields: List[Dict[str, Any]] = [
            {"name": "Host", "value": f"`{alert.hostname}`", "inline": True},
            {"name": "Severity", "value": f"{alert.severity.emoji} {alert.severity.value}", "inline": True},
        ]

        for metric in alert.metrics:
            val_text = f"Current: **{metric.format_value()}**"
            if metric.threshold_value is not None:
                val_text += f"\nThreshold: `{metric.format_threshold()}`"
            embed_fields.append(
                {
                    "name": metric.name,
                    "value": val_text,
                    "inline": True,
                }
            )

        if alert.metadata:
            meta_str = "\n".join(f"• **{k}**: {v}" for k, v in alert.metadata.items())
            embed_fields.append(
                {
                    "name": "Diagnostic Context",
                    "value": meta_str[:1024],
                    "inline": False,
                }
            )

        embed: Dict[str, Any] = {
            "title": f"{alert.severity.emoji} {alert.title}",
            "description": alert.message,
            "color": alert.severity.color_discord,
            "fields": embed_fields,
            "timestamp": alert.timestamp.isoformat(),
            "footer": {
                "text": "Sentinel Pulse Resource Monitor",
            },
        }

        payload: Dict[str, Any] = {
            "username": self.username,
            "embeds": [embed],
        }

        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url

        return payload

    async def dispatch(
        self,
        alert: AlertNotification,
        client: Optional[httpx.AsyncClient] = None,
    ) -> bool:
        """Transmit Discord Embed notification via HTTP POST.

        Args:
            alert: The alert payload.
            client: Optional shared httpx client instance.

        Returns:
            True on successful reception by Discord API, False otherwise.
        """
        if not self.webhook_url:
            logger.error("[%s] Webhook URL is not configured", self.name)
            return False

        payload = self.build_payload(alert)
        return await self._post_with_retry(self.webhook_url, payload, client=client)


class TelegramNotifier(BaseNotifier):
    """Telegram Bot API adapter converting alerts to HTML formatted messages."""

    def __init__(
        self,
        bot_token: str,
        chat_id: Union[int, str],
        api_base_url: str = "https://api.telegram.org",
        disable_web_page_preview: bool = True,
        timeout: float = 10.0,
        max_retries: int = 3,
    ) -> None:
        """Initialize Telegram notifier.

        Args:
            bot_token: Telegram bot API token (from @BotFather).
            chat_id: Target Telegram chat, channel, or user ID.
            api_base_url: Custom API URL endpoint (useful for self-hosted Bot API).
            disable_web_page_preview: Whether to disable URL previews in messages.
            timeout: Network request timeout.
            max_retries: Max retry attempts.
        """
        super().__init__(
            name="TelegramNotifier",
            timeout=timeout,
            max_retries=max_retries,
        )
        self.bot_token = bot_token
        self.chat_id = str(chat_id)
        self.api_base_url = api_base_url.rstrip("/")
        self.disable_web_page_preview = disable_web_page_preview

    @property
    def endpoint_url(self) -> str:
        """Construct the sendMessage endpoint for this bot instance."""
        return f"{self.api_base_url}/bot{self.bot_token}/sendMessage"

    def build_payload(self, alert: AlertNotification) -> Dict[str, Any]:
        """Build HTML formatted payload for Telegram Bot API.

        Args:
            alert: The alert notification.

        Returns:
            Telegram sendMessage JSON request payload.
        """
        safe_title = html.escape(alert.title)
        safe_msg = html.escape(alert.message)
        safe_host = html.escape(alert.hostname)
        iso_time = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            f"{alert.severity.emoji} <b>[{alert.severity.value}] {safe_title}</b>",
            f"<b>Host:</b> <code>{safe_host}</code>",
            f"<b>Time:</b> <code>{iso_time}</code>",
            "",
            f"<b>Details:</b> {safe_msg}",
        ]

        if alert.metrics:
            lines.append("")
            lines.append("📊 <b>Resource Metrics:</b>")
            for m in alert.metrics:
                safe_name = html.escape(m.name)
                val = html.escape(m.format_value())
                if m.threshold_value is not None:
                    thresh = html.escape(m.format_threshold())
                    lines.append(f"• <b>{safe_name}</b>: <code>{val}</code> (Limit: <code>{thresh}</code>)")
                else:
                    lines.append(f"• <b>{safe_name}</b>: <code>{val}</code>")

        if alert.metadata:
            lines.append("")
            lines.append("⚙️ <b>Diagnostics:</b>")
            for k, v in alert.metadata.items():
                safe_k = html.escape(str(k))
                safe_v = html.escape(str(v))
                lines.append(f"• <b>{safe_k}</b>: <code>{safe_v}</code>")

        lines.append("")
        lines.append("<i>Sentinel Pulse Monitor</i>")

        text = "\n".join(lines)

        return {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": self.disable_web_page_preview,
        }

    async def dispatch(
        self,
        alert: AlertNotification,
        client: Optional[httpx.AsyncClient] = None,
    ) -> bool:
        """Transmit message to Telegram Bot API.

        Args:
            alert: The alert payload.
            client: Optional shared httpx client instance.

        Returns:
            True on successful message dispatch, False otherwise.
        """
        if not self.bot_token or not self.chat_id:
            logger.error("[%s] Bot token or chat_id is missing", self.name)
            return False

        payload = self.build_payload(alert)
        return await self._post_with_retry(self.endpoint_url, payload, client=client)


class WebhookDispatcher:
    """Asynchronous notification hub routing alerts across multiple active channels."""

    def __init__(
        self,
        notifiers: Optional[Sequence[BaseNotifier]] = None,
        timeout: float = 10.0,
    ) -> None:
        """Initialize the dispatcher.

        Args:
            notifiers: Sequence of initialized BaseNotifier instances.
            timeout: Shared client timeout in seconds.
        """
        self._notifiers: List[BaseNotifier] = list(notifiers or [])
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()

    def register(self, notifier: BaseNotifier) -> None:
        """Register a new notification channel adapter.

        Args:
            notifier: The notifier instance to register.
        """
        self._notifiers.append(notifier)
        logger.debug("Registered notifier: %s", notifier.name)

    async def get_client(self) -> httpx.AsyncClient:
        """Get or initialize the persistent async HTTP client.

        Returns:
            An active httpx.AsyncClient instance.
        """
        async with self._lock:
            if self._client is None or self._client.is_closed:
                limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
                self._client = httpx.AsyncClient(timeout=self._timeout, limits=limits)
            return self._client

    async def broadcast(self, alert: AlertNotification) -> Mapping[str, bool]:
        """Broadcast an alert concurrently to all registered notification channels.

        Args:
            alert: The alert notification to broadcast.

        Returns:
            Dictionary mapping notifier names to their boolean success status.
        """
        if not self._notifiers:
            logger.warning("No notifiers registered. Alert '%s' was dropped.", alert.title)
            return {}

        client = await self.get_client()

        async def _dispatch_single(notifier: BaseNotifier) -> tuple[str, bool]:
            try:
                success = await notifier.dispatch(alert, client=client)
                return notifier.name, success
            except Exception as exc:
                logger.exception("[%s] Unexpected exception during dispatch: %s", notifier.name, exc)
                return notifier.name, False

        results = await asyncio.gather(*[_dispatch_single(n) for n in self._notifiers])
        status_map = dict(results)

        success_count = sum(1 for s in status_map.values() if s)
        logger.info(
            "Dispatched alert '%s' (%s) to %d/%d channels",
            alert.title,
            alert.severity.value,
            success_count,
            len(self._notifiers),
        )

        return status_map

    async def close(self) -> None:
        """Close internal network resources."""
        async with self._lock:
            if self._client is not None and not self._client.is_closed:
                await self._client.aclose()
                self._client = None
                logger.debug("WebhookDispatcher HTTP client closed.")

    async def __aenter__(self) -> "WebhookDispatcher":
        """Enter async context."""
        await self.get_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context and cleanup connections."""
        await self.close()
