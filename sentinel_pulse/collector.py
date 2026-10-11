"""Resource sampling engine for sentinel-pulse.

Queries system metrics including CPU, memory, disk partitions, and network throughput
via psutil with minimal overhead and non-blocking delta evaluations.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CpuSnapshot:
    """Aggregated and per-core CPU utilization metrics."""

    total_percent: float
    per_cpu_percent: List[float]
    load_avg: Optional[Tuple[float, float, float]]
    frequency_mhz: Optional[float]


@dataclass(frozen=True)
class MemorySnapshot:
    """Volatile and virtual swap memory metrics."""

    total_bytes: int
    available_bytes: int
    used_bytes: int
    percent: float
    swap_total_bytes: int
    swap_used_bytes: int
    swap_percent: float


@dataclass(frozen=True)
class DiskUsageSnapshot:
    """Storage metrics for a single mounted filesystem partition."""

    device: str
    mountpoint: str
    fstype: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent: float


@dataclass(frozen=True)
class DiskIoSnapshot:
    """System-wide disk input/output transfer rates."""

    read_bytes_per_sec: float
    write_bytes_per_sec: float
    read_count_per_sec: float
    write_count_per_sec: float


@dataclass(frozen=True)
class NetworkInterfaceSnapshot:
    """Network transfer rates and hardware counters for a single interface."""

    interface: str
    rx_bytes_per_sec: float
    tx_bytes_per_sec: float
    rx_packets_per_sec: float
    tx_packets_per_sec: float
    rx_errors_total: int
    tx_errors_total: int
    rx_drop_total: int
    tx_drop_total: int


@dataclass(frozen=True)
class SystemSnapshot:
    """Complete immutable point-in-time snapshot of host system metrics."""

    timestamp: float
    uptime_seconds: float
    cpu: CpuSnapshot
    memory: MemorySnapshot
    disks: List[DiskUsageSnapshot]
    disk_io: DiskIoSnapshot
    network_interfaces: Dict[str, NetworkInterfaceSnapshot]
    total_rx_bytes_per_sec: float
    total_tx_bytes_per_sec: float

    def to_dict(self) -> dict:
        """Serialize the snapshot into a nested dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "uptime_seconds": self.uptime_seconds,
            "cpu": {
                "total_percent": self.cpu.total_percent,
                "per_cpu_percent": self.cpu.per_cpu_percent,
                "load_avg": self.cpu.load_avg,
                "frequency_mhz": self.cpu.frequency_mhz,
            },
            "memory": {
                "total_bytes": self.memory.total_bytes,
                "available_bytes": self.memory.available_bytes,
                "used_bytes": self.memory.used_bytes,
                "percent": self.memory.percent,
                "swap_total_bytes": self.memory.swap_total_bytes,
                "swap_used_bytes": self.memory.swap_used_bytes,
                "swap_percent": self.memory.swap_percent,
            },
            "disks": [
                {
                    "device": d.device,
                    "mountpoint": d.mountpoint,
                    "fstype": d.fstype,
                    "total_bytes": d.total_bytes,
                    "used_bytes": d.used_bytes,
                    "free_bytes": d.free_bytes,
                    "percent": d.percent,
                }
                for d in self.disks
            ],
            "disk_io": {
                "read_bytes_per_sec": self.disk_io.read_bytes_per_sec,
                "write_bytes_per_sec": self.disk_io.write_bytes_per_sec,
                "read_count_per_sec": self.disk_io.read_count_per_sec,
                "write_count_per_sec": self.disk_io.write_count_per_sec,
            },
            "network_interfaces": {
                name: {
                    "interface": iface.interface,
                    "rx_bytes_per_sec": iface.rx_bytes_per_sec,
                    "tx_bytes_per_sec": iface.tx_bytes_per_sec,
                    "rx_packets_per_sec": iface.rx_packets_per_sec,
                    "tx_packets_per_sec": iface.tx_packets_per_sec,
                    "rx_errors_total": iface.rx_errors_total,
                    "tx_errors_total": iface.tx_errors_total,
                    "rx_drop_total": iface.rx_drop_total,
                    "tx_drop_total": iface.tx_drop_total,
                }
                for name, iface in self.network_interfaces.items()
            },
            "total_rx_bytes_per_sec": self.total_rx_bytes_per_sec,
            "total_tx_bytes_per_sec": self.total_tx_bytes_per_sec,
        }


class ResourceCollector:
    """Stateful system metric collector that computes resource throughput and rates."""

    def __init__(self, include_virtual_mounts: bool = False) -> None:
        """Initialize collector state and prime initial counters.

        Args:
            include_virtual_mounts: If True, query all disk partitions including virtual ones.
        """
        self._include_virtual_mounts = include_virtual_mounts

        # Prime non-blocking CPU baseline
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(percpu=True, interval=None)

        # Baseline timestamp and monotonic clock
        self._last_sample_mono = time.monotonic()
        self._last_disk_io = psutil.disk_io_counters(perdisk=False)
        self._last_net_io = psutil.net_io_counters(pernic=True)

    def sample(self) -> SystemSnapshot:
        """Collect and return a full point-in-time system resource snapshot.

        Returns:
            A populated SystemSnapshot containing CPU, memory, disk, and network stats.
        """
        now_epoch = time.time()
        now_mono = time.monotonic()
        delta_seconds = max(now_mono - self._last_sample_mono, 1e-6)

        cpu_data = self._collect_cpu()
        memory_data = self._collect_memory()
        disks_data = self._collect_disks()
        disk_io_data = self._collect_disk_io(delta_seconds)
        network_data, total_rx_rate, total_tx_rate = self._collect_network(delta_seconds)

        self._last_sample_mono = now_mono

        try:
            boot_time = psutil.boot_time()
            uptime_seconds = max(0.0, now_epoch - boot_time)
        except Exception as exc:
            logger.debug("Failed to retrieve system boot time: %s", exc)
            uptime_seconds = 0.0

        return SystemSnapshot(
            timestamp=now_epoch,
            uptime_seconds=uptime_seconds,
            cpu=cpu_data,
            memory=memory_data,
            disks=disks_data,
            disk_io=disk_io_data,
            network_interfaces=network_data,
            total_rx_bytes_per_sec=total_rx_rate,
            total_tx_bytes_per_sec=total_tx_rate,
        )

    def _collect_cpu(self) -> CpuSnapshot:
        """Retrieve CPU metrics including percentage, frequencies, and load averages."""
        total_percent = psutil.cpu_percent(interval=None)
        per_cpu_percent = psutil.cpu_percent(percpu=True, interval=None)

        frequency_mhz: Optional[float] = None
        try:
            freq_info = psutil.cpu_freq()
            if freq_info is not None and freq_info.current > 0:
                frequency_mhz = float(freq_info.current)
        except (PermissionError, FileNotFoundError, OSError) as exc:
            logger.debug("CPU frequency collection unavailable: %s", exc)

        load_avg: Optional[Tuple[float, float, float]] = None
        try:
            if hasattr(os, "getloadavg"):
                load_avg = os.getloadavg()
            elif hasattr(psutil, "getloadavg"):
                load_avg = psutil.getloadavg()
        except (OSError, AttributeError) as exc:
            logger.debug("System load averages unavailable on current platform: %s", exc)

        return CpuSnapshot(
            total_percent=float(total_percent),
            per_cpu_percent=[float(p) for p in per_cpu_percent],
            load_avg=load_avg,
            frequency_mhz=frequency_mhz,
        )

    def _collect_memory(self) -> MemorySnapshot:
        """Retrieve volatile virtual memory and swap statistics."""
        vmem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return MemorySnapshot(
            total_bytes=vmem.total,
            available_bytes=vmem.available,
            used_bytes=vmem.used,
            percent=float(vmem.percent),
            swap_total_bytes=swap.total,
            swap_used_bytes=swap.used,
            swap_percent=float(swap.percent),
        )

    def _collect_disks(self) -> List[DiskUsageSnapshot]:
        """Enumerate mounted partitions and compute usage statistics."""
        disks: List[DiskUsageSnapshot] = []
        try:
            partitions = psutil.disk_partitions(all=self._include_virtual_mounts)
        except (PermissionError, OSError) as exc:
            logger.warning("Failed to enumerate disk partitions: %s", exc)
            return disks

        seen_mounts = set()

        for partition in partitions:
            # Prevent duplicate checks for bind mounts or overlay partitions
            if partition.mountpoint in seen_mounts:
                continue
            seen_mounts.add(partition.mountpoint)

            # Skip CD-ROM drives or raw unmounted optical devices on Windows
            if sys.platform == "win32" and "cdrom" in partition.opts:
                continue

            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append(
                    DiskUsageSnapshot(
                        device=partition.device,
                        mountpoint=partition.mountpoint,
                        fstype=partition.fstype,
                        total_bytes=usage.total,
                        used_bytes=usage.used,
                        free_bytes=usage.free,
                        percent=float(usage.percent),
                    )
                )
            except (PermissionError, FileNotFoundError, OSError) as exc:
                # Partitions like inaccessible network shares, disconnected removable disks,
                # or sandbox mounts may raise errors
                logger.debug("Skipping inaccessible mount point '%s': %s", partition.mountpoint, exc)
                continue

        return disks

    def _collect_disk_io(self, delta_seconds: float) -> DiskIoSnapshot:
        """Calculate read/write rate across all physical block devices."""
        current_io = psutil.disk_io_counters(perdisk=False)
        last_io = self._last_disk_io
        self._last_disk_io = current_io

        if current_io is None or last_io is None:
            return DiskIoSnapshot(
                read_bytes_per_sec=0.0,
                write_bytes_per_sec=0.0,
                read_count_per_sec=0.0,
                write_count_per_sec=0.0,
            )

        read_bytes_delta = max(0, current_io.read_bytes - last_io.read_bytes)
        write_bytes_delta = max(0, current_io.write_bytes - last_io.write_bytes)
        read_count_delta = max(0, current_io.read_count - last_io.read_count)
        write_count_delta = max(0, current_io.write_count - last_io.write_count)

        return DiskIoSnapshot(
            read_bytes_per_sec=read_bytes_delta / delta_seconds,
            write_bytes_per_sec=write_bytes_delta / delta_seconds,
            read_count_per_sec=read_count_delta / delta_seconds,
            write_count_per_sec=write_count_delta / delta_seconds,
        )

    def _collect_network(
        self, delta_seconds: float
    ) -> Tuple[Dict[str, NetworkInterfaceSnapshot], float, float]:
        """Compute network throughput per interface and aggregated totals."""
        current_net = psutil.net_io_counters(pernic=True)
        last_net = self._last_net_io
        self._last_net_io = current_net

        snapshots: Dict[str, NetworkInterfaceSnapshot] = {}
        total_rx_rate = 0.0
        total_tx_rate = 0.0

        for iface_name, current_counters in current_net.items():
            last_counters = last_net.get(iface_name)

            if last_counters is None:
                rx_bytes_rate = 0.0
                tx_bytes_rate = 0.0
                rx_packets_rate = 0.0
                tx_packets_rate = 0.0
            else:
                rx_bytes_delta = max(0, current_counters.bytes_recv - last_counters.bytes_recv)
                tx_bytes_delta = max(0, current_counters.bytes_sent - last_counters.bytes_sent)
                rx_packets_delta = max(0, current_counters.packets_recv - last_counters.packets_recv)
                tx_packets_delta = max(0, current_counters.packets_sent - last_counters.packets_sent)

                rx_bytes_rate = rx_bytes_delta / delta_seconds
                tx_bytes_rate = tx_bytes_delta / delta_seconds
                rx_packets_rate = rx_packets_delta / delta_seconds
                tx_packets_rate = tx_packets_delta / delta_seconds

            snapshots[iface_name] = NetworkInterfaceSnapshot(
                interface=iface_name,
                rx_bytes_per_sec=rx_bytes_rate,
                tx_bytes_per_sec=tx_bytes_rate,
                rx_packets_per_sec=rx_packets_rate,
                tx_packets_per_sec=tx_packets_rate,
                rx_errors_total=current_counters.errin,
                tx_errors_total=current_counters.errout,
                rx_drop_total=current_counters.dropin,
                tx_drop_total=current_counters.dropout,
            )

            total_rx_rate += rx_bytes_rate
            total_tx_rate += tx_bytes_rate

        return snapshots, total_rx_rate, total_tx_rate
