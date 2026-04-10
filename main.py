#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import math
import os
import signal
import socket
import struct
import sys
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


APP_NAME = "cgnet-anomaly"
APP_VERSION = "0.1.0"


@dataclass(slots=True)
class InterfaceCounters:
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errs: int = 0
    tx_errs: int = 0
    rx_drop: int = 0
    tx_drop: int = 0


@dataclass(slots=True)
class InterfaceIdentity:
    name: str
    operstate: str = "unknown"
    carrier: Optional[int] = None
    mtu: Optional[int] = None
    speed: Optional[int] = None
    duplex: Optional[str] = None
    mac: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: List[str] = field(default_factory=list)


@dataclass(slots=True)
class InterfaceSample:
    timestamp_wall: float
    timestamp_mono: float
    identity: InterfaceIdentity
    counters: InterfaceCounters


@dataclass(slots=True)
class InterfaceRates:
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    rx_pps: float = 0.0
    tx_pps: float = 0.0
    rx_errs_ps: float = 0.0
    tx_errs_ps: float = 0.0
    rx_drop_ps: float = 0.0
    tx_drop_ps: float = 0.0
    elapsed: float = 0.0


@dataclass(slots=True)
class RollingStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0

    def push(self, value: float) -> None:
        if self.count == 0:
            self.count = 1
            self.mean = value
            self.m2 = 0.0
            self.minimum = value
            self.maximum = value
            return
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        if value < self.minimum:
            self.minimum = value
        if value > self.maximum:
            self.maximum = value

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stdev(self) -> float:
        return math.sqrt(self.variance)


@dataclass(slots=True)
class BaselineSnapshot:
    samples: int
    mean: float
    stdev: float
    minimum: float
    maximum: float


@dataclass(slots=True)
class InterfaceBaseline:
    rx_bps: RollingStats = field(default_factory=RollingStats)
    tx_bps: RollingStats = field(default_factory=RollingStats)
    rx_pps: RollingStats = field(default_factory=RollingStats)
    tx_pps: RollingStats = field(default_factory=RollingStats)
    rx_errs_ps: RollingStats = field(default_factory=RollingStats)
    tx_errs_ps: RollingStats = field(default_factory=RollingStats)
    rx_drop_ps: RollingStats = field(default_factory=RollingStats)
    tx_drop_ps: RollingStats = field(default_factory=RollingStats)

    def push(self, rates: InterfaceRates) -> None:
        self.rx_bps.push(rates.rx_bps)
        self.tx_bps.push(rates.tx_bps)
        self.rx_pps.push(rates.rx_pps)
        self.tx_pps.push(rates.tx_pps)
        self.rx_errs_ps.push(rates.rx_errs_ps)
        self.tx_errs_ps.push(rates.tx_errs_ps)
        self.rx_drop_ps.push(rates.rx_drop_ps)
        self.tx_drop_ps.push(rates.tx_drop_ps)

    def as_dict(self) -> Dict[str, BaselineSnapshot]:
        return {
            "rx_bps": BaselineSnapshot(
                self.rx_bps.count,
                self.rx_bps.mean,
                self.rx_bps.stdev,
                self.rx_bps.minimum,
                self.rx_bps.maximum,
            ),
            "tx_bps": BaselineSnapshot(
                self.tx_bps.count,
                self.tx_bps.mean,
                self.tx_bps.stdev,
                self.tx_bps.minimum,
                self.tx_bps.maximum,
            ),
            "rx_pps": BaselineSnapshot(
                self.rx_pps.count,
                self.rx_pps.mean,
                self.rx_pps.stdev,
                self.rx_pps.minimum,
                self.rx_pps.maximum,
            ),
            "tx_pps": BaselineSnapshot(
                self.tx_pps.count,
                self.tx_pps.mean,
                self.tx_pps.stdev,
                self.tx_pps.minimum,
                self.tx_pps.maximum,
            ),
            "rx_errs_ps": BaselineSnapshot(
                self.rx_errs_ps.count,
                self.rx_errs_ps.mean,
                self.rx_errs_ps.stdev,
                self.rx_errs_ps.minimum,
                self.rx_errs_ps.maximum,
            ),
            "tx_errs_ps": BaselineSnapshot(
                self.tx_errs_ps.count,
                self.tx_errs_ps.mean,
                self.tx_errs_ps.stdev,
                self.tx_errs_ps.minimum,
                self.tx_errs_ps.maximum,
            ),
            "rx_drop_ps": BaselineSnapshot(
                self.rx_drop_ps.count,
                self.rx_drop_ps.mean,
                self.rx_drop_ps.stdev,
                self.rx_drop_ps.minimum,
                self.rx_drop_ps.maximum,
            ),
            "tx_drop_ps": BaselineSnapshot(
                self.tx_drop_ps.count,
                self.tx_drop_ps.mean,
                self.tx_drop_ps.stdev,
                self.tx_drop_ps.minimum,
                self.tx_drop_ps.maximum,
            ),
        }


@dataclass(slots=True)
class AnomalyEvent:
    event_id: int
    ts_wall: float
    ts_mono: float
    iface: str
    severity: str
    category: str
    metric: str
    message: str
    value: float
    baseline_mean: float
    baseline_stdev: float
    zscore: float
    ratio: float
    tags: List[str] = field(default_factory=list)


@dataclass(slots=True)
class InterfaceState:
    latest: Optional[InterfaceSample] = None
    previous: Optional[InterfaceSample] = None
    latest_rates: Optional[InterfaceRates] = None
    baseline: InterfaceBaseline = field(default_factory=InterfaceBaseline)
    events: Deque[AnomalyEvent] = field(default_factory=lambda: deque(maxlen=256))
    recent_rates: Deque[Dict[str, float]] = field(default_factory=lambda: deque(maxlen=256))
    last_state_change: Optional[float] = None
    flap_count: int = 0


@dataclass(slots=True)
class ThresholdPolicy:
    min_baseline_samples: int = 6
    spike_ratio_warn: float = 2.5
    spike_ratio_crit: float = 5.0
    drop_ratio_warn: float = 0.20
    drop_ratio_crit: float = 0.05
    zscore_warn: float = 2.5
    zscore_crit: float = 4.0
    error_rate_warn: float = 0.10
    error_rate_crit: float = 1.00
    drop_rate_warn: float = 0.10
    drop_rate_crit: float = 1.00
    flap_window_seconds: float = 30.0
    flap_warn_count: int = 2
    flap_crit_count: int = 4
    cooldown_seconds: float = 10.0


@dataclass(slots=True)
class MonitorConfig:
    interval: float = 2.0
    include: List[str] = field(default_factory=list)
    exclude_loopback: bool = False
    event_history: int = 1024
    rate_history: int = 256
    policy: ThresholdPolicy = field(default_factory=ThresholdPolicy)


class TextReader:
    @staticmethod
    def read_text(path: str | Path) -> Optional[str]:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError, UnicodeDecodeError):
            return None

    @staticmethod
    def read_int(path: str | Path) -> Optional[int]:
        value = TextReader.read_text(path)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None


class LinuxNetReader:
    def __init__(self) -> None:
        self.sys_net = Path("/sys/class/net")
        self.proc_net_dev = Path("/proc/net/dev")
        self.proc_if_inet6 = Path("/proc/net/if_inet6")
        self._cached_interfaces: Optional[List[str]] = None
        self._cache_time: Optional[float] = None
        self._cache_ttl: float = 5.0

    def list_interfaces(self, force_refresh: bool = False) -> List[str]:
        now = time.monotonic()
        if not force_refresh and self._cached_interfaces is not None and self._cache_time is not None:
            if (now - self._cache_time) < self._cache_ttl:
                return self._cached_interfaces
        try:
            self._cached_interfaces = sorted(p.name for p in self.sys_net.iterdir() if p.exists())
            self._cache_time = now
        except OSError:
            self._cached_interfaces = []
        return self._cached_interfaces

    def parse_proc_net_dev(self) -> Dict[str, InterfaceCounters]:
        result: Dict[str, InterfaceCounters] = {}
        text = TextReader.read_text(self.proc_net_dev)
        if not text:
            return result
        for line in text.splitlines()[2:]:
            if ":" not in line:
                continue
            left, right = line.split(":", 1)
            iface = left.strip()
            parts = right.split()
            if len(parts) < 16:
                continue
            try:
                result[iface] = InterfaceCounters(
                    rx_bytes=int(parts[0]),
                    rx_packets=int(parts[1]),
                    rx_errs=int(parts[2]),
                    rx_drop=int(parts[3]),
                    tx_bytes=int(parts[8]),
                    tx_packets=int(parts[9]),
                    tx_errs=int(parts[10]),
                    tx_drop=int(parts[11]),
                )
            except ValueError:
                continue
        return result

    def get_ipv6_map(self) -> Dict[str, List[str]]:
        mapping: Dict[str, List[str]] = {}
        try:
            with self.proc_if_inet6.open("r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) != 6:
                        continue
                    hex_addr = parts[0]
                    iface = parts[5]
                    try:
                        raw = bytes.fromhex(hex_addr)
                        addr = socket.inet_ntop(socket.AF_INET6, raw)
                    except (ValueError, OSError):
                        continue
                    mapping.setdefault(iface, []).append(addr)
        except OSError:
            return mapping
        return mapping

    def get_ipv4(self, iface: str) -> Optional[str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                encoded = iface.encode("utf-8")
                if len(encoded) > 15:
                    return None
                request = struct.pack("256s", encoded)
                response = fcntl.ioctl(s.fileno(), 0x8915, request)
                return socket.inet_ntoa(response[20:24])
        except OSError:
            return None

    def get_identity(self, iface: str, ipv6_map: Dict[str, List[str]]) -> InterfaceIdentity:
        base = self.sys_net / iface
        return InterfaceIdentity(
            name=iface,
            operstate=TextReader.read_text(base / "operstate") or "unknown",
            carrier=TextReader.read_int(base / "carrier"),
            mtu=TextReader.read_int(base / "mtu"),
            speed=TextReader.read_int(base / "speed"),
            duplex=TextReader.read_text(base / "duplex"),
            mac=TextReader.read_text(base / "address"),
            ipv4=self.get_ipv4(iface),
            ipv6=ipv6_map.get(iface, []),
        )

    def collect(self, selected: Optional[Iterable[str]] = None) -> Dict[str, InterfaceSample]:
        now_wall = time.time()
        now_mono = time.monotonic()
        counters = self.parse_proc_net_dev()
        ipv6_map = self.get_ipv6_map()
        names = list(selected) if selected is not None else self.list_interfaces()
        result: Dict[str, InterfaceSample] = {}
        for iface in names:
            identity = self.get_identity(iface, ipv6_map)
            result[iface] = InterfaceSample(
                timestamp_wall=now_wall,
                timestamp_mono=now_mono,
                identity=identity,
                counters=counters.get(iface, InterfaceCounters()),
            )
        return result


class RateCalculator:
    @staticmethod
    def calculate(previous: Optional[InterfaceSample], current: InterfaceSample) -> InterfaceRates:
        if previous is None:
            return InterfaceRates(elapsed=0.0)
        elapsed = current.timestamp_mono - previous.timestamp_mono
        if elapsed <= 0:
            return InterfaceRates(elapsed=0.0)

        def delta(a: int, b: int) -> int:
            if b >= a:
                return b - a
            return 0

        prev = previous.counters
        curr = current.counters

        return InterfaceRates(
            rx_bps=delta(prev.rx_bytes, curr.rx_bytes) / elapsed,
            tx_bps=delta(prev.tx_bytes, curr.tx_bytes) / elapsed,
            rx_pps=delta(prev.rx_packets, curr.rx_packets) / elapsed,
            tx_pps=delta(prev.tx_packets, curr.tx_packets) / elapsed,
            rx_errs_ps=delta(prev.rx_errs, curr.rx_errs) / elapsed,
            tx_errs_ps=delta(prev.tx_errs, curr.tx_errs) / elapsed,
            rx_drop_ps=delta(prev.rx_drop, curr.rx_drop) / elapsed,
            tx_drop_ps=delta(prev.tx_drop, curr.tx_drop) / elapsed,
            elapsed=elapsed,
        )


class AnomalyEngine:
    def __init__(self, policy: ThresholdPolicy) -> None:
        self.policy = policy
        self._event_id = 0
        self._last_event_times: Dict[Tuple[str, str, str], float] = {}
        self._lock = threading.RLock()

    def next_event_id(self) -> int:
        with self._lock:
            self._event_id += 1
            return self._event_id

    def baseline_snapshot(self, baseline: InterfaceBaseline, metric: str) -> BaselineSnapshot:
        return baseline.as_dict()[metric]

    def maybe_emit(
        self,
        iface: str,
        ts_wall: float,
        ts_mono: float,
        category: str,
        metric: str,
        severity: str,
        message: str,
        value: float,
        baseline_mean: float,
        baseline_stdev: float,
        zscore: float,
        ratio: float,
        tags: Optional[List[str]] = None,
    ) -> Optional[AnomalyEvent]:
        key = (iface, category, metric)
        with self._lock:
            last_ts = self._last_event_times.get(key)
            if last_ts is not None and (ts_mono - last_ts) < self.policy.cooldown_seconds:
                return None
            self._last_event_times[key] = ts_mono
        return AnomalyEvent(
            event_id=self.next_event_id(),
            ts_wall=ts_wall,
            ts_mono=ts_mono,
            iface=iface,
            severity=severity,
            category=category,
            metric=metric,
            message=message,
            value=value,
            baseline_mean=baseline_mean,
            baseline_stdev=baseline_stdev,
            zscore=zscore,
            ratio=ratio,
            tags=list(tags or []),
        )

    def classify_deviation(
        self,
        iface: str,
        ts_wall: float,
        ts_mono: float,
        metric: str,
        value: float,
        baseline: BaselineSnapshot,
        kind: str,
    ) -> Optional[AnomalyEvent]:
        if baseline.samples < self.policy.min_baseline_samples:
            return None
        mean = baseline.mean
        stdev = baseline.stdev
        if mean > 0:
            ratio = value / mean
        elif value > 0:
            ratio = float("inf")
        else:
            ratio = 1.0
        zscore = ((value - mean) / stdev) if stdev > 0 else 0.0

        if kind == "spike":
            if (ratio >= self.policy.spike_ratio_crit and not math.isinf(ratio)) or zscore >= self.policy.zscore_crit:
                return self.maybe_emit(
                    iface,
                    ts_wall,
                    ts_mono,
                    "spike",
                    metric,
                    "critical",
                    f"{metric} spike detected on {iface}",
                    value,
                    mean,
                    stdev,
                    zscore,
                    ratio,
                    [kind],
                )
            if (ratio >= self.policy.spike_ratio_warn and not math.isinf(ratio)) or zscore >= self.policy.zscore_warn:
                return self.maybe_emit(
                    iface,
                    ts_wall,
                    ts_mono,
                    "spike",
                    metric,
                    "warning",
                    f"{metric} elevated above baseline on {iface}",
                    value,
                    mean,
                    stdev,
                    zscore,
                    ratio,
                    [kind],
                )
            return None

        if kind == "drop":
            if mean <= 0 or math.isinf(ratio):
                return None
            if ratio <= self.policy.drop_ratio_crit:
                return self.maybe_emit(
                    iface,
                    ts_wall,
                    ts_mono,
                    "drop",
                    metric,
                    "critical",
                    f"{metric} dropped sharply on {iface}",
                    value,
                    mean,
                    stdev,
                    zscore,
                    ratio,
                    [kind],
                )
            if ratio <= self.policy.drop_ratio_warn:
                return self.maybe_emit(
                    iface,
                    ts_wall,
                    ts_mono,
                    "drop",
                    metric,
                    "warning",
                    f"{metric} below baseline on {iface}",
                    value,
                    mean,
                    stdev,
                    zscore,
                    ratio,
                    [kind],
                )
            return None

        return None

    def classify_rate_guard(
        self,
        iface: str,
        ts_wall: float,
        ts_mono: float,
        metric: str,
        value: float,
        warn: float,
        crit: float,
        category: str,
    ) -> Optional[AnomalyEvent]:
        if value >= crit:
            return self.maybe_emit(
                iface,
                ts_wall,
                ts_mono,
                category,
                metric,
                "critical",
                f"{metric} high on {iface}",
                value,
                0.0,
                0.0,
                0.0,
                0.0,
                [category],
            )
        if value >= warn:
            return self.maybe_emit(
                iface,
                ts_wall,
                ts_mono,
                category,
                metric,
                "warning",
                f"{metric} increased on {iface}",
                value,
                0.0,
                0.0,
                0.0,
                0.0,
                [category],
            )
        return None

    def classify_flap(
        self,
        iface: str,
        ts_wall: float,
        ts_mono: float,
        flap_count: int,
    ) -> Optional[AnomalyEvent]:
        if flap_count >= self.policy.flap_crit_count:
            return self.maybe_emit(
                iface,
                ts_wall,
                ts_mono,
                "flap",
                "operstate",
                "critical",
                f"interface state flapping on {iface}",
                float(flap_count),
                0.0,
                0.0,
                0.0,
                0.0,
                ["flap"],
            )
        if flap_count >= self.policy.flap_warn_count:
            return self.maybe_emit(
                iface,
                ts_wall,
                ts_mono,
                "flap",
                "operstate",
                "warning",
                f"interface state instability on {iface}",
                float(flap_count),
                0.0,
                0.0,
                0.0,
                0.0,
                ["flap"],
            )
        return None

    def evaluate(
        self,
        iface: str,
        current: InterfaceSample,
        rates: InterfaceRates,
        state: InterfaceState,
    ) -> List[AnomalyEvent]:
        events: List[AnomalyEvent] = []
        baseline = state.baseline

        for metric, value in (
            ("rx_bps", rates.rx_bps),
            ("tx_bps", rates.tx_bps),
            ("rx_pps", rates.rx_pps),
            ("tx_pps", rates.tx_pps),
        ):
            snap = self.baseline_snapshot(baseline, metric)
            spike = self.classify_deviation(
                iface,
                current.timestamp_wall,
                current.timestamp_mono,
                metric,
                value,
                snap,
                "spike",
            )
            if spike is not None:
                events.append(spike)
            drop = self.classify_deviation(
                iface,
                current.timestamp_wall,
                current.timestamp_mono,
                metric,
                value,
                snap,
                "drop",
            )
            if drop is not None:
                events.append(drop)

        for metric, value, warn, crit, category in (
            ("rx_errs_ps", rates.rx_errs_ps, self.policy.error_rate_warn, self.policy.error_rate_crit, "errors"),
            ("tx_errs_ps", rates.tx_errs_ps, self.policy.error_rate_warn, self.policy.error_rate_crit, "errors"),
            ("rx_drop_ps", rates.rx_drop_ps, self.policy.drop_rate_warn, self.policy.drop_rate_crit, "drops"),
            ("tx_drop_ps", rates.tx_drop_ps, self.policy.drop_rate_warn, self.policy.drop_rate_crit, "drops"),
        ):
            event = self.classify_rate_guard(
                iface,
                current.timestamp_wall,
                current.timestamp_mono,
                metric,
                value,
                warn,
                crit,
                category,
            )
            if event is not None:
                events.append(event)

        flap = self.classify_flap(
            iface,
            current.timestamp_wall,
            current.timestamp_mono,
            state.flap_count,
        )
        if flap is not None:
            events.append(flap)

        return events


class MonitorState:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.started_wall = time.time()
        self.started_mono = time.monotonic()
        self.reader = LinuxNetReader()
        self.engine = AnomalyEngine(config.policy)
        self.interfaces: Dict[str, InterfaceState] = {}
        self.global_events: Deque[AnomalyEvent] = deque(maxlen=config.event_history)
        self.lock = threading.RLock()
        self.cycles = 0
        self.last_tick_wall: Optional[float] = None
        self.last_tick_mono: Optional[float] = None
        self._interface_list_cache: Optional[List[str]] = None
        self._interface_cache_time: Optional[float] = None

    def selected_interfaces(self) -> List[str]:
        now = time.monotonic()
        if self._interface_list_cache is not None and self._interface_cache_time is not None:
            if (now - self._interface_cache_time) < 5.0:
                names = self._interface_list_cache
            else:
                names = self.reader.list_interfaces(force_refresh=True)
                self._interface_list_cache = names
                self._interface_cache_time = now
        else:
            names = self.reader.list_interfaces()
            self._interface_list_cache = names
            self._interface_cache_time = now

        if self.config.include:
            allowed = set(self.config.include)
            names = [name for name in names if name in allowed]
        if self.config.exclude_loopback:
            names = [name for name in names if name != "lo"]
        return names

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "started_wall": self.started_wall,
                "uptime": time.monotonic() - self.started_mono,
                "cycles": self.cycles,
                "interfaces": {
                    iface: self.interface_snapshot(iface, state)
                    for iface, state in self.interfaces.items()
                },
                "events_total": len(self.global_events),
                "last_tick_wall": self.last_tick_wall,
            }

    def interface_snapshot(self, iface: str, state: InterfaceState) -> Dict[str, Any]:
        latest = state.latest
        previous = state.previous
        rates = state.latest_rates
        baseline_dict = {}
        for key, value in state.baseline.as_dict().items():
            baseline_dict[key] = {
                "samples": value.samples,
                "mean": value.mean,
                "stdev": value.stdev,
                "minimum": value.minimum,
                "maximum": value.maximum,
            }
        return {
            "iface": iface,
            "latest": asdict(latest) if latest is not None else None,
            "previous": asdict(previous) if previous is not None else None,
            "rates": asdict(rates) if rates is not None else None,
            "baseline": baseline_dict,
            "events": [asdict(event) for event in list(state.events)],
            "recent_rates": list(state.recent_rates),
            "last_state_change": state.last_state_change,
            "flap_count": state.flap_count,
        }

    def list_interface_names(self) -> List[str]:
        with self.lock:
            return sorted(self.interfaces.keys())

    def get_interface(self, iface: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            state = self.interfaces.get(iface)
            if state is None:
                return None
            return self.interface_snapshot(iface, state)

    def list_events(self, iface: Optional[str] = None, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            items = list(self.global_events)
        if iface is not None:
            items = [item for item in items if item.iface == iface]
        if severity is not None:
            items = [item for item in items if item.severity == severity]
        items = items[-limit:]
        return [asdict(item) for item in items]

    def update(self) -> None:
        selected = self.selected_interfaces()
        samples = self.reader.collect(selected)
        with self.lock:
            for iface, sample in samples.items():
                state = self.interfaces.setdefault(
                    iface,
                    InterfaceState(
                        events=deque(maxlen=self.config.event_history),
                        recent_rates=deque(maxlen=self.config.rate_history),
                    ),
                )
                prev = state.latest
                state.previous = prev
                state.latest = sample
                rates = RateCalculator.calculate(prev, sample)
                state.latest_rates = rates

                if prev is not None and prev.identity.operstate != sample.identity.operstate:
                    now = sample.timestamp_mono
                    if state.last_state_change is not None:
                        if (now - state.last_state_change) <= self.config.policy.flap_window_seconds:
                            state.flap_count += 1
                        else:
                            state.flap_count = 1
                    else:
                        state.flap_count = 1
                    state.last_state_change = now

                if rates.elapsed > 0:
                    state.recent_rates.append({
                        "ts_wall": sample.timestamp_wall,
                        "rx_bps": rates.rx_bps,
                        "tx_bps": rates.tx_bps,
                        "rx_pps": rates.rx_pps,
                        "tx_pps": rates.tx_pps,
                        "rx_errs_ps": rates.rx_errs_ps,
                        "tx_errs_ps": rates.tx_errs_ps,
                        "rx_drop_ps": rates.rx_drop_ps,
                        "tx_drop_ps": rates.tx_drop_ps,
                    })

                    events = self.engine.evaluate(iface, sample, rates, state)
                    for event in events:
                        state.events.append(event)
                        self.global_events.append(event)

                    state.baseline.push(rates)

            to_remove = [iface for iface in self.interfaces if iface not in samples]
            for iface in to_remove:
                del self.interfaces[iface]

            self.cycles += 1
            self.last_tick_wall = time.time()
            self.last_tick_mono = time.monotonic()


class MonitorWorker:
    def __init__(self, state: MonitorState) -> None:
        self.state = state
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self.run, name="monitor-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def run(self) -> None:
        interval = self.state.config.interval
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.state.update()
            except Exception:
                logging.exception("monitor update failed")
            elapsed = time.monotonic() - started
            remaining = interval - elapsed
            if remaining > 0:
                self._stop.wait(remaining)


class JsonResponse:
    @staticmethod
    def send(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
        try:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        except (TypeError, ValueError, OverflowError) as e:
            error_body = json.dumps({"error": "serialization failed", "detail": str(e)}).encode("utf-8")
            handler.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            handler.send_header("Content-Type", "application/json; charset=utf-8")
            handler.send_header("Content-Length", str(len(error_body)))
            handler.end_headers()
            handler.wfile.write(error_body)
            return

        handler.send_response(code)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


class ApiHandler(BaseHTTPRequestHandler):
    state_ref: Optional[MonitorState] = None

    def log_message(self, format: str, *args: Any) -> None:
        logging.info("%s - %s", self.address_string(), format % args)

    def do_GET(self) -> None:
        state = self.state_ref
        if state is None:
            JsonResponse.send(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "state unavailable"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            JsonResponse.send(
                self,
                HTTPStatus.OK,
                {
                    "app": APP_NAME,
                    "version": APP_VERSION,
                    "endpoints": [
                        "/health",
                        "/v1/status",
                        "/v1/interfaces",
                        "/v1/interfaces/{iface}",
                        "/v1/events",
                        "/v1/config",
                    ],
                },
            )
            return

        if path == "/health":
            JsonResponse.send(self, HTTPStatus.OK, {"status": "ok", "time": time.time()})
            return

        if path == "/v1/status":
            JsonResponse.send(self, HTTPStatus.OK, state.snapshot())
            return

        if path == "/v1/interfaces":
            names = state.list_interface_names()
            JsonResponse.send(self, HTTPStatus.OK, {"interfaces": names, "count": len(names)})
            return

        if path.startswith("/v1/interfaces/"):
            iface = path.split("/", 3)[3] if len(path.split("/", 3)) == 4 else ""
            data = state.get_interface(iface)
            if data is None:
                JsonResponse.send(self, HTTPStatus.NOT_FOUND, {"error": "interface not found", "iface": iface})
                return
            JsonResponse.send(self, HTTPStatus.OK, data)
            return

        if path == "/v1/events":
            iface = first(query.get("iface"))
            severity = first(query.get("severity"))
            limit_raw = first(query.get("limit")) or "100"
            try:
                limit_val = int(limit_raw)
                if limit_val <= 0:
                    limit_val = 100
                limit = max(1, min(limit_val, 5000))
            except ValueError:
                JsonResponse.send(self, HTTPStatus.BAD_REQUEST, {"error": "invalid limit"})
                return
            JsonResponse.send(self, HTTPStatus.OK, {"events": state.list_events(iface=iface, severity=severity, limit=limit)})
            return

        if path == "/v1/config":
            JsonResponse.send(self, HTTPStatus.OK, asdict(state.config))
            return

        JsonResponse.send(self, HTTPStatus.NOT_FOUND, {"error": "not found", "path": path})


def first(values: Optional[List[str]]) -> Optional[str]:
    if not values:
        return None
    return values[0]


class ConsoleRenderer:
    @staticmethod
    def human_bytes_per_second(value: float) -> str:
        units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
        idx = 0
        val = value
        while val >= 1024 and idx < len(units) - 1:
            val /= 1024.0
            idx += 1
        return f"{val:.2f} {units[idx]}"

    @staticmethod
    def human_pps(value: float) -> str:
        if value >= 1_000_000:
            return f"{value / 1_000_000:.2f} Mpps"
        if value >= 1_000:
            return f"{value / 1_000:.2f} Kpps"
        return f"{value:.2f} pps"

    @staticmethod
    def render(state: MonitorState) -> str:
        with state.lock:
            lines: List[str] = []
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            lines.append(f"{APP_NAME} {APP_VERSION}  time={ts}  cycles={state.cycles}")
            lines.append(
                f"{'IFACE':<12} {'STATE':<12} {'RX':>14} {'TX':>14} {'RX PPS':>12} {'TX PPS':>12} {'EVENTS':>8}"
            )
            lines.append("-" * 92)
            for iface in sorted(state.interfaces):
                item = state.interfaces[iface]
                latest = item.latest
                rates = item.latest_rates
                if latest is None or rates is None:
                    continue
                lines.append(
                    f"{iface:<12} "
                    f"{latest.identity.operstate:<12} "
                    f"{ConsoleRenderer.human_bytes_per_second(rates.rx_bps):>14} "
                    f"{ConsoleRenderer.human_bytes_per_second(rates.tx_bps):>14} "
                    f"{ConsoleRenderer.human_pps(rates.rx_pps):>12} "
                    f"{ConsoleRenderer.human_pps(rates.tx_pps):>12} "
                    f"{len(item.events):>8}"
                )
            lines.append("")
            recent = list(state.global_events)[-10:]
            if recent:
                lines.append("recent anomalies:")
                for event in recent:
                    wall = time.strftime("%H:%M:%S", time.localtime(event.ts_wall))
                    lines.append(
                        f"{wall} {event.severity.upper():<8} {event.iface:<12} "
                        f"{event.metric:<12} {event.message} value={event.value:.4f} ratio={event.ratio:.3f} z={event.zscore:.3f}"
                    )
            return "\n".join(lines)


def parse_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config_from_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config not found: {path}")
    text = p.read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def merge_config(args: argparse.Namespace, data: Dict[str, Any]) -> MonitorConfig:
    policy_data = data.get("policy", {}) if isinstance(data.get("policy"), dict) else {}
    policy = ThresholdPolicy(
        min_baseline_samples=int(policy_data.get("min_baseline_samples", args.min_baseline_samples)),
        spike_ratio_warn=float(policy_data.get("spike_ratio_warn", args.spike_ratio_warn)),
        spike_ratio_crit=float(policy_data.get("spike_ratio_crit", args.spike_ratio_crit)),
        drop_ratio_warn=float(policy_data.get("drop_ratio_warn", args.drop_ratio_warn)),
        drop_ratio_crit=float(policy_data.get("drop_ratio_crit", args.drop_ratio_crit)),
        zscore_warn=float(policy_data.get("zscore_warn", args.zscore_warn)),
        zscore_crit=float(policy_data.get("zscore_crit", args.zscore_crit)),
        error_rate_warn=float(policy_data.get("error_rate_warn", args.error_rate_warn)),
        error_rate_crit=float(policy_data.get("error_rate_crit", args.error_rate_crit)),
        drop_rate_warn=float(policy_data.get("drop_rate_warn", args.drop_rate_warn)),
        drop_rate_crit=float(policy_data.get("drop_rate_crit", args.drop_rate_crit)),
        flap_window_seconds=float(policy_data.get("flap_window_seconds", args.flap_window_seconds)),
        flap_warn_count=int(policy_data.get("flap_warn_count", args.flap_warn_count)),
        flap_crit_count=int(policy_data.get("flap_crit_count", args.flap_crit_count)),
        cooldown_seconds=float(policy_data.get("cooldown_seconds", args.cooldown_seconds)),
    )
    include = data.get("include")
    if include is None:
        include = parse_list(args.include)
    elif not isinstance(include, list):
        raise ValueError("include must be a list")
    include = [str(item) for item in include]

    return MonitorConfig(
        interval=float(data.get("interval", args.interval)),
        include=include,
        exclude_loopback=bool(data.get("exclude_loopback", args.exclude_loopback)),
        event_history=int(data.get("event_history", args.event_history)),
        rate_history=int(data.get("rate_history", args.rate_history)),
        policy=policy,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_NAME, description="Network anomaly monitor with JSON APIs")
    parser.add_argument("--host", default="127.0.0.1", help="API bind host")
    parser.add_argument("--port", type=int, default=8080, help="API bind port")
    parser.add_argument("--interval", type=float, default=2.0, help="sampling interval")
    parser.add_argument("--include", default="", help="comma-separated interface allow-list")
    parser.add_argument("--exclude-loopback", action="store_true", help="exclude lo")
    parser.add_argument("--event-history", type=int, default=1024, help="global and per-interface event history")
    parser.add_argument("--rate-history", type=int, default=256, help="per-interface rate history")
    parser.add_argument("--config", help="JSON config file")
    parser.add_argument("--quiet", action="store_true", help="disable console rendering")
    parser.add_argument("--console-interval", type=float, default=2.0, help="console refresh interval")
    parser.add_argument("--min-baseline-samples", type=int, default=6)
    parser.add_argument("--spike-ratio-warn", type=float, default=2.5)
    parser.add_argument("--spike-ratio-crit", type=float, default=5.0)
    parser.add_argument("--drop-ratio-warn", type=float, default=0.20)
    parser.add_argument("--drop-ratio-crit", type=float, default=0.05)
    parser.add_argument("--zscore-warn", type=float, default=2.5)
    parser.add_argument("--zscore-crit", type=float, default=4.0)
    parser.add_argument("--error-rate-warn", type=float, default=0.10)
    parser.add_argument("--error-rate-crit", type=float, default=1.00)
    parser.add_argument("--drop-rate-warn", type=float, default=0.10)
    parser.add_argument("--drop-rate-crit", type=float, default=1.00)
    parser.add_argument("--flap-window-seconds", type=float, default=30.0)
    parser.add_argument("--flap-warn-count", type=int, default=2)
    parser.add_argument("--flap-crit-count", type=int, default=4)
    parser.add_argument("--cooldown-seconds", type=float, default=10.0)
    parser.add_argument("--debug", action="store_true")
    return parser


def clear_screen() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def run_console_loop(state: MonitorState, stop: threading.Event, interval: float) -> None:
    while not stop.is_set():
        clear_screen()
        print(ConsoleRenderer.render(state))
        stop.wait(interval)


def install_signal_handlers(stop: threading.Event) -> None:
    def handler(_sig: int, _frame: Any) -> None:
        stop.set()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        config_data = load_config_from_file(args.config)
        config = merge_config(args, config_data)
    except Exception as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1

    state = MonitorState(config)
    worker = MonitorWorker(state)
    stop = threading.Event()
    install_signal_handlers(stop)

    ApiHandler.state_ref = state
    server = ThreadingHTTPServer((args.host, args.port), ApiHandler)
    server_thread = threading.Thread(target=server.serve_forever, name="api-server", daemon=True)

    worker.start()
    server_thread.start()

    console_thread: Optional[threading.Thread] = None
    if not args.quiet:
        console_thread = threading.Thread(
            target=run_console_loop,
            args=(state, stop, args.console_interval),
            name="console-renderer",
            daemon=True,
        )
        console_thread.start()

    logging.info("api listening on http://%s:%d", args.host, args.port)

    try:
        while not stop.is_set():
            stop.wait(1.0)
    finally:
        server.shutdown()
        server.server_close()
        worker.stop()
        if console_thread is not None:
            stop.set()
            console_thread.join(timeout=2.0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
