# Architecture Technique : sentinel-pulse

> Lightweight, zero-bloat system health monitor with instant Discord and Telegram webhook alerting.

Modular, event-driven CLI architecture built around three decoupled layers: 1) Collector Layer using psutil for non-blocking resource sampling; 2) Rule Engine evaluating metrics against sliding-window thresholds to prevent alert flapping; 3) Dispatcher Layer utilizing an abstract notifier interface with concrete Discord and Telegram HTTP client implementations.

## Structure des Fichiers

- `pyproject.toml` : Project metadata, dependencies (psutil, httpx, pydantic, rich), and console script entrypoints.
- `sentinel_pulse/config.py` : Pydantic-based configuration model parsing YAML/ENV settings for thresholds and webhook credentials.
- `sentinel_pulse/collector.py` : Resource sampling engine querying CPU, memory, disk partitions, and network throughput via psutil.
- `sentinel_pulse/notifiers.py` : Webhook dispatch engine implementing Discord Embeds and Telegram Bot API formatting over async httpx.
- `sentinel_pulse/cli.py` : CLI entrypoint managing the sampling loop, threshold evaluations, cooldown states, and terminal dashboards.
- `tests/test_monitor.py` : Unit tests verifying threshold evaluation logic, metric normalization, and webhook payload generation.
