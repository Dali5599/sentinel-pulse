"""Configuration management module for the sentinel-pulse daemon.

Provides Pydantic models for configuration validation, handling threshold policies,
notification webhooks, and daemon operational settings. Supports configuration
ingestion from YAML files with granular environment variable overrides.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
)


class CpuThresholdConfig(BaseModel):
    """Threshold settings for CPU utilization."""

    warning_percent: float = Field(
        default=75.0,
        ge=0.0,
        le=100.0,
        description="CPU utilization warning threshold percentage.",
    )
    critical_percent: float = Field(
        default=90.0,
        ge=0.0,
        le=100.0,
        description="CPU utilization critical threshold percentage.",
    )

    @model_validator(mode="after")
    def validate_threshold_order(self) -> CpuThresholdConfig:
        """Validate that warning threshold does not exceed critical threshold."""
        if self.warning_percent > self.critical_percent:
            raise ValueError(
                f"CPU warning threshold ({self.warning_percent}%) cannot exceed "
                f"critical threshold ({self.critical_percent}%)."
            )
        return self


class MemoryThresholdConfig(BaseModel):
    """Threshold settings for RAM utilization."""

    warning_percent: float = Field(
        default=80.0,
        ge=0.0,
        le=100.0,
        description="RAM utilization warning threshold percentage.",
    )
    critical_percent: float = Field(
        default=95.0,
        ge=0.0,
        le=100.0,
        description="RAM utilization critical threshold percentage.",
    )

    @model_validator(mode="after")
    def validate_threshold_order(self) -> MemoryThresholdConfig:
        """Validate that warning threshold does not exceed critical threshold."""
        if self.warning_percent > self.critical_percent:
            raise ValueError(
                f"Memory warning threshold ({self.warning_percent}%) cannot exceed "
                f"critical threshold ({self.critical_percent}%)."
            )
        return self


class DiskThresholdConfig(BaseModel):
    """Threshold settings for storage filesystems."""

    warning_percent: float = Field(
        default=85.0,
        ge=0.0,
        le=100.0,
        description="Disk utilization warning threshold percentage.",
    )
    critical_percent: float = Field(
        default=95.0,
        ge=0.0,
        le=100.0,
        description="Disk utilization critical threshold percentage.",
    )
    mount_points: List[str] = Field(
        default_factory=lambda: ["/"],
        description="List of mount points or drive roots to monitor.",
    )

    @model_validator(mode="after")
    def validate_threshold_order(self) -> DiskThresholdConfig:
        """Validate that warning threshold does not exceed critical threshold."""
        if self.warning_percent > self.critical_percent:
            raise ValueError(
                f"Disk warning threshold ({self.warning_percent}%) cannot exceed "
                f"critical threshold ({self.critical_percent}%)."
            )
        return self


class NetworkThresholdConfig(BaseModel):
    """Threshold settings for network interface throughput."""

    warning_rx_mbps: float = Field(
        default=100.0,
        ge=0.0,
        description="Network receive warning threshold in Megabits per second.",
    )
    critical_rx_mbps: float = Field(
        default=250.0,
        ge=0.0,
        description="Network receive critical threshold in Megabits per second.",
    )
    warning_tx_mbps: float = Field(
        default=100.0,
        ge=0.0,
        description="Network transmit warning threshold in Megabits per second.",
    )
    critical_tx_mbps: float = Field(
        default=250.0,
        ge=0.0,
        description="Network transmit critical threshold in Megabits per second.",
    )
    interfaces: Optional[List[str]] = Field(
        default=None,
        description="List of specific network interfaces to monitor. None monitors all active.",
    )

    @model_validator(mode="after")
    def validate_threshold_orders(self) -> NetworkThresholdConfig:
        """Validate that rx/tx warning thresholds do not exceed critical thresholds."""
        if self.warning_rx_mbps > self.critical_rx_mbps:
            raise ValueError(
                f"Network RX warning threshold ({self.warning_rx_mbps} Mbps) cannot exceed "
                f"critical threshold ({self.critical_rx_mbps} Mbps)."
            )
        if self.warning_tx_mbps > self.critical_tx_mbps:
            raise ValueError(
                f"Network TX warning threshold ({self.warning_tx_mbps} Mbps) cannot exceed "
                f"critical threshold ({self.critical_tx_mbps} Mbps)."
            )
        return self


class ThresholdsConfig(BaseModel):
    """Combined system resource threshold configurations."""

    cpu: CpuThresholdConfig = Field(default_factory=CpuThresholdConfig)
    memory: MemoryThresholdConfig = Field(default_factory=MemoryThresholdConfig)
    disk: DiskThresholdConfig = Field(default_factory=DiskThresholdConfig)
    network: NetworkThresholdConfig = Field(default_factory=NetworkThresholdConfig)


class DiscordWebhookConfig(BaseModel):
    """Discord notification dispatch settings."""

    enabled: bool = Field(default=False, description="Enable Discord webhook alerts.")
    webhook_url: Optional[str] = Field(
        default=None,
        description="Discord incoming webhook URL.",
    )
    username: str = Field(
        default="Sentinel Pulse",
        description="Bot name override displayed on Discord embeds.",
    )
    avatar_url: Optional[str] = Field(
        default=None,
        description="Bot avatar URL displayed on Discord embeds.",
    )

    @model_validator(mode="after")
    def validate_webhook_presence(self) -> DiscordWebhookConfig:
        """Ensure webhook URL is supplied when the dispatch channel is enabled."""
        if self.enabled and not self.webhook_url:
            raise ValueError("Discord webhook is enabled but no webhook_url is configured.")
        return self


class TelegramWebhookConfig(BaseModel):
    """Telegram notification dispatch settings."""

    enabled: bool = Field(default=False, description="Enable Telegram bot alerts.")
    bot_token: Optional[str] = Field(
        default=None,
        description="Telegram Bot API token.",
    )
    chat_id: Optional[str] = Field(
        default=None,
        description="Target Telegram chat ID or channel username.",
    )

    @model_validator(mode="after")
    def validate_telegram_presence(self) -> TelegramWebhookConfig:
        """Ensure bot token and chat ID are present when channel is enabled."""
        if self.enabled:
            if not self.bot_token:
                raise ValueError("Telegram is enabled but no bot_token is configured.")
            if not self.chat_id:
                raise ValueError("Telegram is enabled but no chat_id is configured.")
        return self


class NotificationConfig(BaseModel):
    """Notification channels and throttling settings."""

    cooldown_seconds: int = Field(
        default=300,
        ge=10,
        description="Minimum duration in seconds between duplicate alerts for the same resource.",
    )
    discord: DiscordWebhookConfig = Field(default_factory=DiscordWebhookConfig)
    telegram: TelegramWebhookConfig = Field(default_factory=TelegramWebhookConfig)


class DaemonConfig(BaseModel):
    """Operational settings for the sentinel-pulse background daemon."""

    interval_seconds: float = Field(
        default=3.0,
        ge=0.5,
        le=3600.0,
        description="Metric polling frequency in seconds.",
    )
    hostname: str = Field(
        default_factory=platform.node,
        description="Identifier for the monitored node used in notification payloads.",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Normalize and validate log level strings."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalized = value.strip().upper()
        if normalized not in allowed:
            raise ValueError(f"Invalid log_level '{value}'. Allowed: {', '.join(allowed)}")
        return normalized


class SentinelConfig(BaseModel):
    """Root configuration model aggregating all daemon parameters."""

    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)


def _deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge source dictionary into target dictionary."""
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value
    return target


def _apply_env_overrides(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Extract environment variables with SENTINEL_ prefix and merge into config dictionary."""
    env_mappings = {
        "SENTINEL_DAEMON_INTERVAL": ("daemon", "interval_seconds", float),
        "SENTINEL_DAEMON_HOSTNAME": ("daemon", "hostname", str),
        "SENTINEL_DAEMON_LOG_LEVEL": ("daemon", "log_level", str),
        "SENTINEL_CPU_WARNING": ("thresholds", "cpu", "warning_percent", float),
        "SENTINEL_CPU_CRITICAL": ("thresholds", "cpu", "critical_percent", float),
        "SENTINEL_MEMORY_WARNING": ("thresholds", "memory", "warning_percent", float),
        "SENTINEL_MEMORY_CRITICAL": ("thresholds", "memory", "critical_percent", float),
        "SENTINEL_DISK_WARNING": ("thresholds", "disk", "warning_percent", float),
        "SENTINEL_DISK_CRITICAL": ("thresholds", "disk", "critical_percent", float),
        "SENTINEL_NOTIFICATION_COOLDOWN": ("notifications", "cooldown_seconds", int),
        "SENTINEL_DISCORD_ENABLED": ("notifications", "discord", "enabled", lambda v: v.lower() in ("1", "true", "yes")),
        "SENTINEL_DISCORD_WEBHOOK_URL": ("notifications", "discord", "webhook_url", str),
        "SENTINEL_DISCORD_USERNAME": ("notifications", "discord", "username", str),
        "SENTINEL_TELEGRAM_ENABLED": ("notifications", "telegram", "enabled", lambda v: v.lower() in ("1", "true", "yes")),
        "SENTINEL_TELEGRAM_BOT_TOKEN": ("notifications", "telegram", "bot_token", str),
        "SENTINEL_TELEGRAM_CHAT_ID": ("notifications", "telegram", "chat_id", str),
    }

    for env_var, spec in env_mappings.items():
        raw_val = os.getenv(env_var)
        if raw_val is None:
            continue

        converter = spec[-1]
        keys = spec[:-1]
        try:
            converted_val = converter(raw_val)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value for environment variable {env_var}: '{raw_val}'") from exc

        current = config_dict
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[keys[-1]] = converted_val

    return config_dict


def load_config(config_path: Optional[Path | str] = None) -> SentinelConfig:
    """Load configuration from a YAML file overlaid with environment variables.

    Searches for the YAML file in the specified path or standard locations:
    1. Explicit path parameter
    2. SENTINEL_CONFIG environment variable
    3. ./sentinel.yaml
    4. ~/.config/sentinel-pulse/sentinel.yaml
    5. /etc/sentinel-pulse/sentinel.yaml

    Args:
        config_path: Optional explicit filesystem path to the YAML file.

    Returns:
        SentinelConfig: Fully validated configuration instance.

    Raises:
        FileNotFoundError: If an explicitly provided config path is not found.
        ValueError: If YAML syntax is invalid or configuration schema fails validation.
    """
    candidate_paths: List[Path] = []

    if config_path:
        candidate_paths.append(Path(config_path))
    elif "SENTINEL_CONFIG" in os.environ:
        candidate_paths.append(Path(os.environ["SENTINEL_CONFIG"]))
    else:
        candidate_paths.extend([
            Path("sentinel.yaml"),
            Path("sentinel.yml"),
            Path.home() / ".config" / "sentinel-pulse" / "sentinel.yaml",
            Path("/etc/sentinel-pulse/sentinel.yaml"),
        ])

    raw_data: Dict[str, Any] = {}
    resolved_path: Optional[Path] = None

    for path in candidate_paths:
        if path.is_file():
            resolved_path = path
            break

    if config_path and not resolved_path:
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")

    if resolved_path:
        try:
            with open(resolved_path, "r", encoding="utf-8") as file_stream:
                parsed = yaml.safe_load(file_stream)
                if isinstance(parsed, dict):
                    raw_data = parsed
                elif parsed is not None:
                    raise ValueError(f"YAML configuration at {resolved_path} must define a mapping/dictionary.")
        except yaml.YAMLError as exc:
            raise ValueError(f"Failed to parse YAML file {resolved_path}: {exc}") from exc

    merged_data = _apply_env_overrides(raw_data)
    return SentinelConfig.model_validate(merged_data)
