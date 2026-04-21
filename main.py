#!/usr/bin/env python3

from __future__ import annotations

import argparse
import array
import fcntl
import json
import logging
import math
import os
import random
import signal
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import asdict, dataclass, field
from functools import wraps
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


APP_NAME = "cgnet-anomaly"
APP_VERSION = "0.3.1"

RATE_METRICS = (
    "rx_bps",
    "tx_bps",
    "rx_pps",
    "tx_pps",
    "rx_errs_ps",
    "tx_errs_ps",
    "rx_drop_ps",
    "tx_drop_ps",
)


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
    elapsed_us: int = 0

    @property
    def elapsed(self) -> float:
        return self.elapsed_us / 1_000_000.0


@dataclass(slots=True)
class RollingStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0

    def push(self, value: float) -> None:
        if math.isnan(value) or math.isinf(value):
            return
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

    def snapshot(self, metric: str) -> BaselineSnapshot:
        stats = getattr(self, metric)
        return BaselineSnapshot(
            samples=stats.count,
            mean=stats.mean,
            stdev=stats.stdev,
            minimum=stats.minimum,
            maximum=stats.maximum,
        )

    def as_dict(self) -> Dict[str, BaselineSnapshot]:
        return {metric: self.snapshot(metric) for metric in RATE_METRICS}


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
class InterfaceHealth:
    status: str = "unknown"
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    last_evaluated_wall: float = 0.0


@dataclass(slots=True)
class InterfaceState:
    latest: Optional[InterfaceSample] = None
    previous: Optional[InterfaceSample] = None
    latest_rates: Optional[InterfaceRates] = None
    baseline: InterfaceBaseline = field(default_factory=InterfaceBaseline)
    events: Deque[AnomalyEvent] = field(default_factory=lambda: deque(maxlen=256))
    recent_rates: Deque[Tuple[float, float, float, float, float, float, float, float]] = field(default_factory=lambda: deque(maxlen=256))
    last_state_change: Optional[float] = None
    flap_count: int = 0
    health: InterfaceHealth = field(default_factory=InterfaceHealth)


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
    anomaly_freeze_baseline: bool = True


@dataclass(slots=True)
class MonitorConfig:
    interval: float = 2.0
    include: List[str] = field(default_factory=list)
    exclude_loopback: bool = False
    global_event_history: int = 1024
    interface_event_history: int = 256
    rate_history: int = 256
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    event_log_path: Optional[str] = None
    sqlite_path: Optional[str] = None
    console_sort: str = "iface"
    console_filter_status: str = "all"
    replay_path: Optional[str] = None
    replay_speed: float = 1.0
    selftest_mode: bool = False
    selftest_interfaces: int = 3
    selftest_seed: int = 1337
    policy: ThresholdPolicy = field(default_factory=ThresholdPolicy)
    api_rate_limit: int = 60
    enable_cors: bool = False


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_ip: str) -> bool:
        if self.requests_per_minute <= 0:
            return True
        now = time.time()
        window = 60.0
        with self._lock:
            if client_ip in self.requests:
                self.requests[client_ip] = [t for t in self.requests[client_ip] if now - t < window]
                if len(self.requests[client_ip]) >= self.requests_per_minute:
                    return False
                self.requests[client_ip].append(now)
            else:
                self.requests[client_ip] = [now]
        return True


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


class SampleProvider:
    def collect(self, selected: Optional[Iterable[str]] = None) -> Dict[str, InterfaceSample]:
        raise NotImplementedError


class LinuxNetReader(SampleProvider):
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
        base = Path("/sys/class/net") / iface
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


class ReplayReader(SampleProvider):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.frames = self._load_frames()
        self.index = 0
        self.started_wall = time.time()
        self.started_mono = time.monotonic()
        self.frame_count = len(self.frames)

    def _load_frames(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            raise FileNotFoundError(f"replay file not found: {self.path}")
        text = self.path.read_text(encoding="utf-8")
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("replay file must contain a JSON array")
        return data

    def collect(self, selected: Optional[Iterable[str]] = None) -> Dict[str, InterfaceSample]:
        if not self.frames:
            return {}
        frame = self.frames[self.index % len(self.frames)]
        self.index += 1
        now_wall = time.time()
        now_mono = time.monotonic()
        names_filter = set(selected) if selected is not None else None
        result: Dict[str, InterfaceSample] = {}
        interfaces = frame.get("interfaces", {})
        if not isinstance(interfaces, dict):
            return result
        for iface, payload in interfaces.items():
            if names_filter is not None and iface not in names_filter:
                continue
            identity_data = payload.get("identity", {}) if isinstance(payload, dict) else {}
            counters_data = payload.get("counters", {}) if isinstance(payload, dict) else {}
            identity = InterfaceIdentity(
                name=iface,
                operstate=str(identity_data.get("operstate", "up")),
                carrier=coerce_int(identity_data.get("carrier")),
                mtu=coerce_int(identity_data.get("mtu")),
                speed=coerce_int(identity_data.get("speed")),
                duplex=coerce_str(identity_data.get("duplex")),
                mac=coerce_str(identity_data.get("mac")),
                ipv4=coerce_str(identity_data.get("ipv4")),
                ipv6=[str(x) for x in identity_data.get("ipv6", [])] if isinstance(identity_data.get("ipv6", []), list) else [],
            )
            counters = InterfaceCounters(
                rx_bytes=coerce_int(counters_data.get("rx_bytes")) or 0,
                tx_bytes=coerce_int(counters_data.get("tx_bytes")) or 0,
                rx_packets=coerce_int(counters_data.get("rx_packets")) or 0,
                tx_packets=coerce_int(counters_data.get("tx_packets")) or 0,
                rx_errs=coerce_int(counters_data.get("rx_errs")) or 0,
                tx_errs=coerce_int(counters_data.get("tx_errs")) or 0,
                rx_drop=coerce_int(counters_data.get("rx_drop")) or 0,
                tx_drop=coerce_int(counters_data.get("tx_drop")) or 0,
            )
            result[iface] = InterfaceSample(
                timestamp_wall=now_wall,
                timestamp_mono=now_mono,
                identity=identity,
                counters=counters,
            )
        return result


class SelfTestReader(SampleProvider):
    def __init__(self, count: int, seed: int) -> None:
        self.rng = random.Random(seed)
        self.names = [f"sim{i}" for i in range(1, max(1, count) + 1)]
        self.counters: Dict[str, InterfaceCounters] = {name: InterfaceCounters() for name in self.names}
        self.states: Dict[str, str] = {name: "up" for name in self.names}

    def collect(self, selected: Optional[Iterable[str]] = None) -> Dict[str, InterfaceSample]:
        now_wall = time.time()
        now_mono = time.monotonic()
        names = list(selected) if selected is not None else list(self.names)
        result: Dict[str, InterfaceSample] = {}
        for iface in names:
            if iface not in self.counters:
                continue
            c = self.counters[iface]
            burst = self.rng.random()
            rx_step = self.rng.randint(20_000, 200_000)
            tx_step = self.rng.randint(10_000, 140_000)
            if burst > 0.96:
                rx_step *= self.rng.randint(10, 60)
                tx_step *= self.rng.randint(10, 50)
            rx_packets = max(1, rx_step // self.rng.randint(500, 1500))
            tx_packets = max(1, tx_step // self.rng.randint(500, 1500))
            c.rx_bytes += rx_step
            c.tx_bytes += tx_step
            c.rx_packets += rx_packets
            c.tx_packets += tx_packets
            if self.rng.random() > 0.985:
                c.rx_errs += self.rng.randint(1, 3)
            if self.rng.random() > 0.987:
                c.tx_errs += self.rng.randint(1, 3)
            if self.rng.random() > 0.988:
                c.rx_drop += self.rng.randint(1, 4)
            if self.rng.random() > 0.989:
                c.tx_drop += self.rng.randint(1, 4)
            if self.rng.random() > 0.994:
                self.states[iface] = "down" if self.states[iface] == "up" else "up"
            identity = InterfaceIdentity(
                name=iface,
                operstate=self.states[iface],
                carrier=1 if self.states[iface] == "up" else 0,
                mtu=1500,
                speed=1000,
                duplex="full",
                mac=f"02:00:00:{self.rng.randint(0,255):02x}:{self.rng.randint(0,255):02x}:{self.rng.randint(0,255):02x}",
                ipv4=f"10.0.0.{self.rng.randint(2, 250)}",
                ipv6=[],
            )
            result[iface] = InterfaceSample(
                timestamp_wall=now_wall,
                timestamp_mono=now_mono,
                identity=identity,
                counters=InterfaceCounters(
                    rx_bytes=c.rx_bytes,
                    tx_bytes=c.tx_bytes,
                    rx_packets=c.rx_packets,
                    tx_packets=c.tx_packets,
                    rx_errs=c.rx_errs,
                    tx_errs=c.tx_errs,
                    rx_drop=c.rx_drop,
                    tx_drop=c.tx_drop,
                ),
            )
        return result


class RateCalculator:
    @staticmethod
    def calculate(previous: Optional[InterfaceSample], current: InterfaceSample) -> InterfaceRates:
        if previous is None:
            return InterfaceRates(elapsed_us=0)
        elapsed_us = int((current.timestamp_mono - previous.timestamp_mono) * 1_000_000)
        if elapsed_us <= 0:
            return InterfaceRates(elapsed_us=0)

        def delta(a: int, b: int) -> int:
            if b >= a:
                return b - a
            return 0

        prev = previous.counters
        curr = current.counters
        elapsed_sec = elapsed_us / 1_000_000.0

        return InterfaceRates(
            rx_bps=delta(prev.rx_bytes, curr.rx_bytes) / elapsed_sec,
            tx_bps=delta(prev.tx_bytes, curr.tx_bytes) / elapsed_sec,
            rx_pps=delta(prev.rx_packets, curr.rx_packets) / elapsed_sec,
            tx_pps=delta(prev.tx_packets, curr.tx_packets) / elapsed_sec,
            rx_errs_ps=delta(prev.rx_errs, curr.rx_errs) / elapsed_sec,
            tx_errs_ps=delta(prev.tx_errs, curr.tx_errs) / elapsed_sec,
            rx_drop_ps=delta(prev.rx_drop, curr.rx_drop) / elapsed_sec,
            tx_drop_ps=delta(prev.tx_drop, curr.tx_drop) / elapsed_sec,
            elapsed_us=elapsed_us,
        )


class EventStore:
    def __init__(self, jsonl_path: Optional[str], sqlite_path: Optional[str]) -> None:
        self.jsonl_path = jsonl_path
        self.sqlite_path = sqlite_path
        self._lock = threading.RLock()
        self._sqlite_conn: Optional[sqlite3.Connection] = None
        if self.sqlite_path:
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        try:
            parent = Path(self.sqlite_path).expanduser().resolve().parent
            parent.mkdir(parents=True, exist_ok=True)
            self._sqlite_conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
            self._sqlite_conn.execute("PRAGMA journal_mode=WAL")
            self._sqlite_conn.execute("PRAGMA synchronous=NORMAL")
            with self._sqlite_conn:
                self._sqlite_conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id INTEGER PRIMARY KEY,
                        ts_wall REAL NOT NULL,
                        ts_mono REAL NOT NULL,
                        iface TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        category TEXT NOT NULL,
                        metric TEXT NOT NULL,
                        message TEXT NOT NULL,
                        value REAL NOT NULL,
                        baseline_mean REAL NOT NULL,
                        baseline_stdev REAL NOT NULL,
                        zscore REAL NOT NULL,
                        ratio REAL NOT NULL,
                        tags_json TEXT NOT NULL
                    )
                    """
                )
                self._sqlite_conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts_wall ON events(ts_wall)")
                self._sqlite_conn.execute("CREATE INDEX IF NOT EXISTS idx_events_iface ON events(iface)")
                self._sqlite_conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
        except sqlite3.Error:
            logging.exception("failed to initialize sqlite store")
            self._sqlite_conn = None

    def append(self, event: AnomalyEvent) -> None:
        with self._lock:
            self._append_jsonl(event)
            self._append_sqlite(event)

    def _append_jsonl(self, event: AnomalyEvent) -> None:
        if not self.jsonl_path:
            return
        record = asdict(event)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        try:
            parent = Path(self.jsonl_path).expanduser().resolve().parent
            parent.mkdir(parents=True, exist_ok=True)
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            logging.exception("failed to append jsonl event log")

    def _append_sqlite(self, event: AnomalyEvent) -> None:
        if not self.sqlite_path or self._sqlite_conn is None:
            return
        try:
            with self._sqlite_conn:
                self._sqlite_conn.execute(
                    """
                    INSERT OR REPLACE INTO events (
                        event_id, ts_wall, ts_mono, iface, severity, category, metric,
                        message, value, baseline_mean, baseline_stdev, zscore, ratio, tags_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.ts_wall,
                        event.ts_mono,
                        event.iface,
                        event.severity,
                        event.category,
                        event.metric,
                        event.message,
                        event.value,
                        event.baseline_mean,
                        event.baseline_stdev,
                        event.zscore,
                        event.ratio,
                        json.dumps(event.tags, ensure_ascii=False),
                    ),
                )
        except sqlite3.Error:
            logging.exception("failed to append sqlite event log")

    def close(self) -> None:
        if self._sqlite_conn:
            self._sqlite_conn.close()


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
        return baseline.snapshot(metric)

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
        if math.isnan(value) or math.isinf(value):
            return None
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
            if (math.isinf(ratio) and value > 0) or zscore >= self.policy.zscore_crit or ratio >= self.policy.spike_ratio_crit:
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
            if zscore >= self.policy.zscore_warn or ratio >= self.policy.spike_ratio_warn:
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
        if math.isnan(value) or math.isinf(value):
            return None
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


class HealthEvaluator:
    @staticmethod
    def from_state(state: InterfaceState, now_wall: float) -> InterfaceHealth:
        if state.latest is None or state.latest_rates is None:
            return InterfaceHealth(status="unknown", score=0, reasons=["no sample"], last_evaluated_wall=now_wall)

        score = 0
        reasons: List[str] = []
        latest = state.latest
        rates = state.latest_rates

        if latest.identity.operstate not in {"up", "unknown"}:
            score += 50
            reasons.append(f"operstate={latest.identity.operstate}")

        if rates.rx_errs_ps > 0 or rates.tx_errs_ps > 0:
            score += 25
            reasons.append("errors")

        if rates.rx_drop_ps > 0 or rates.tx_drop_ps > 0:
            score += 25
            reasons.append("drops")

        recent = list(state.events)[-10:]
        for event in recent:
            if event.severity == "critical":
                score += 40
            elif event.severity == "warning":
                score += 15

        if state.flap_count >= 4:
            score += 40
            reasons.append("flapping")
        elif state.flap_count >= 2:
            score += 20
            reasons.append("instability")

        if score >= 80:
            status = "critical"
        elif score >= 30:
            status = "warning"
        else:
            status = "healthy"

        return InterfaceHealth(status=status, score=score, reasons=sorted(set(reasons)), last_evaluated_wall=now_wall)


class MonitorState:
    def __init__(self, config: MonitorConfig, reader: SampleProvider) -> None:
        self.config = config
        self.started_wall = time.time()
        self.started_mono = time.monotonic()
        self.reader = reader
        self.engine = AnomalyEngine(config.policy)
        self.store = EventStore(config.event_log_path, config.sqlite_path)
        self.interfaces: Dict[str, InterfaceState] = {}
        self.global_events: Deque[AnomalyEvent] = deque(maxlen=config.global_event_history)
        self.lock = threading.RLock()
        self.cycles = 0
        self.last_tick_wall: Optional[float] = None
        self.last_tick_mono: Optional[float] = None
        self._interface_list_cache: Optional[List[str]] = None
        self._interface_cache_time: Optional[float] = None
        self.cycle_times: Deque[float] = deque(maxlen=100)

    def selected_interfaces(self) -> List[str]:
        if self.config.selftest_mode:
            names = list(getattr(self.reader, "names", []))
        elif self.config.replay_path:
            names = []
            if hasattr(self.reader, "frames") and getattr(self.reader, "frames"):
                first_frame = getattr(self.reader, "frames")[0]
                interfaces = first_frame.get("interfaces", {}) if isinstance(first_frame, dict) else {}
                if isinstance(interfaces, dict):
                    names = sorted(interfaces.keys())
        else:
            now = time.monotonic()
            linux_reader = self.reader
            if isinstance(linux_reader, LinuxNetReader):
                if self._interface_list_cache is not None and self._interface_cache_time is not None:
                    if (now - self._interface_cache_time) < 5.0:
                        names = self._interface_list_cache
                    else:
                        names = linux_reader.list_interfaces(force_refresh=True)
                        self._interface_list_cache = names
                        self._interface_cache_time = now
                else:
                    names = linux_reader.list_interfaces()
                    self._interface_list_cache = names
                    self._interface_cache_time = now
            else:
                names = []

        if self.config.include:
            allowed = set(self.config.include)
            names = [name for name in names if name in allowed]
        if self.config.exclude_loopback:
            names = [name for name in names if name != "lo"]
        return names

    def summary(self) -> Dict[str, Any]:
        with self.lock:
            interface_count = len(self.interfaces)
            status_counts = {"healthy": 0, "warning": 0, "critical": 0, "unknown": 0}
            for state in self.interfaces.values():
                status_counts[state.health.status] = status_counts.get(state.health.status, 0) + 1
            avg_cycle = sum(self.cycle_times) / len(self.cycle_times) if self.cycle_times else 0.0
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "uptime": time.monotonic() - self.started_mono,
                "cycles": self.cycles,
                "interface_count": interface_count,
                "events_total": len(self.global_events),
                "health": status_counts,
                "last_tick_wall": self.last_tick_wall,
                "mode": self.mode_name(),
                "avg_cycle_ms": avg_cycle * 1000,
            }

    def mode_name(self) -> str:
        if self.config.selftest_mode:
            return "selftest"
        if self.config.replay_path:
            return "replay"
        return "live"

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
                "mode": self.mode_name(),
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
        recent_rates_list = []
        for rate_tuple in state.recent_rates:
            recent_rates_list.append({
                "ts_wall": rate_tuple[0],
                "rx_bps": rate_tuple[1],
                "tx_bps": rate_tuple[2],
                "rx_pps": rate_tuple[3],
                "tx_pps": rate_tuple[4],
                "rx_errs_ps": rate_tuple[5],
                "tx_errs_ps": rate_tuple[6],
                "rx_drop_ps": rate_tuple[7],
                "tx_drop_ps": rate_tuple[8],
            })
        return {
            "iface": iface,
            "latest": asdict(latest) if latest is not None else None,
            "previous": asdict(previous) if previous is not None else None,
            "rates": asdict(rates) if rates is not None else None,
            "baseline": baseline_dict,
            "events": [asdict(event) for event in list(state.events)],
            "recent_rates": recent_rates_list,
            "last_state_change": state.last_state_change,
            "flap_count": state.flap_count,
            "health": asdict(state.health),
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

    def apply_events(self, state: InterfaceState, events: List[AnomalyEvent]) -> None:
        for event in events:
            state.events.append(event)
            self.global_events.append(event)
            self.store.append(event)

    def maybe_update_baseline(self, state: InterfaceState, rates: InterfaceRates, events: List[AnomalyEvent]) -> None:
        if rates.elapsed_us <= 0:
            return
        if self.config.policy.anomaly_freeze_baseline and events:
            return
        state.baseline.push(rates)

    def update(self) -> None:
        cycle_start = time.monotonic()
        selected = self.selected_interfaces()
        samples = self.reader.collect(selected if selected else None)
        with self.lock:
            for iface, sample in samples.items():
                state = self.interfaces.setdefault(
                    iface,
                    InterfaceState(
                        events=deque(maxlen=self.config.interface_event_history),
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

                if rates.elapsed_us > 0:
                    state.recent_rates.append((
                        sample.timestamp_wall,
                        rates.rx_bps,
                        rates.tx_bps,
                        rates.rx_pps,
                        rates.tx_pps,
                        rates.rx_errs_ps,
                        rates.tx_errs_ps,
                        rates.rx_drop_ps,
                        rates.tx_drop_ps,
                    ))

                    events = self.engine.evaluate(iface, sample, rates, state)
                    self.apply_events(state, events)
                    self.maybe_update_baseline(state, rates, events)

                state.health = HealthEvaluator.from_state(state, sample.timestamp_wall)

            to_remove = [iface for iface in self.interfaces if iface not in samples]
            for iface in to_remove:
                del self.interfaces[iface]

            self.cycles += 1
            self.last_tick_wall = time.time()
            self.last_tick_mono = time.monotonic()
            cycle_time = time.monotonic() - cycle_start
            self.cycle_times.append(cycle_time)


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
        if handler.enable_cors:
            handler.send_header("Access-Control-Allow-Origin", "*")
            handler.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            handler.send_header("Access-Control-Allow-Headers", "Content-Type")
        handler.end_headers()
        handler.wfile.write(body)


class ApiHandler(BaseHTTPRequestHandler):
    state_ref: Optional[MonitorState] = None
    rate_limiter: Optional[RateLimiter] = None
    enable_cors: bool = False

    def log_message(self, format: str, *args: Any) -> None:
        logging.info("%s - %s", self.address_string(), format % args)

    def do_OPTIONS(self) -> None:
        if self.enable_cors:
            self.send_response(HTTPStatus.OK)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
        else:
            self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
            self.end_headers()

    def do_GET(self) -> None:
        state = self.state_ref
        if state is None:
            JsonResponse.send(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "state unavailable"})
            return

        if self.rate_limiter and not self.rate_limiter.allow(self.client_address[0]):
            JsonResponse.send(self, HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        segments = [segment for segment in path.split("/") if segment]

        if path == "/":
            JsonResponse.send(
                self,
                HTTPStatus.OK,
                {
                    "app": APP_NAME,
                    "version": APP_VERSION,
                    "endpoints": [
                        "/health",
                        "/metrics",
                        "/v1/status",
                        "/v1/summary",
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

        if path == "/metrics":
            metrics = {
                "uptime_seconds": time.monotonic() - state.started_mono,
                "cycles_total": state.cycles,
                "interfaces_total": len(state.interfaces),
                "events_total": len(state.global_events),
                "avg_cycle_ms": (sum(state.cycle_times) / len(state.cycle_times) * 1000) if state.cycle_times else 0,
            }
            JsonResponse.send(self, HTTPStatus.OK, metrics)
            return

        if path == "/v1/status":
            JsonResponse.send(self, HTTPStatus.OK, state.snapshot())
            return

        if path == "/v1/summary":
            JsonResponse.send(self, HTTPStatus.OK, state.summary())
            return

        if path == "/v1/interfaces":
            names = state.list_interface_names()
            JsonResponse.send(self, HTTPStatus.OK, {"interfaces": names, "count": len(names)})
            return

        if len(segments) == 3 and segments[0] == "v1" and segments[1] == "interfaces":
            iface = urllib.parse.unquote(segments[2])
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
    def sort_items(items: List[Tuple[str, InterfaceState]], sort_key: str) -> List[Tuple[str, InterfaceState]]:
        def key_func(item: Tuple[str, InterfaceState]) -> Tuple[Any, ...]:
            iface, state = item
            rates = state.latest_rates or InterfaceRates()
            health_score = state.health.score
            if sort_key == "rx":
                return (-rates.rx_bps, iface)
            if sort_key == "tx":
                return (-rates.tx_bps, iface)
            if sort_key == "events":
                return (-len(state.events), iface)
            if sort_key == "health":
                return (-health_score, iface)
            return (iface,)

        return sorted(items, key=key_func)

    @staticmethod
    def render(state: MonitorState, sort_key: str, status_filter: str) -> str:
        with state.lock:
            lines: List[str] = []
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            avg_cycle = (sum(state.cycle_times) / len(state.cycle_times) * 1000) if state.cycle_times else 0
            lines.append(f"{APP_NAME} {APP_VERSION}  time={ts}  cycles={state.cycles}  mode={state.mode_name()}  sort={sort_key}  filter={status_filter}  cycle_ms={avg_cycle:.1f}")
            lines.append(
                f"{'IFACE':<12} {'STATE':<12} {'HEALTH':<10} {'SCORE':>6} {'RX':>14} {'TX':>14} {'RX PPS':>12} {'TX PPS':>12} {'EVENTS':>8}"
            )
            lines.append("-" * 114)
            items = ConsoleRenderer.sort_items(list(state.interfaces.items()), sort_key)
            for iface, item in items:
                latest = item.latest
                rates = item.latest_rates
                if latest is None or rates is None:
                    continue
                if status_filter != "all" and item.health.status != status_filter:
                    continue
                lines.append(
                    f"{iface:<12} "
                    f"{latest.identity.operstate:<12} "
                    f"{item.health.status:<10} "
                    f"{item.health.score:>6} "
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
    if isinstance(value, list):
        return [str(item) for item in value]
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


def coerce_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def coerce_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def coerce_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def validate_host(value: str) -> str:
    if not value:
        raise ValueError("host must not be empty")
    return value


def validate_port(value: int) -> int:
    if not (1 <= value <= 65535):
        raise ValueError("port must be between 1 and 65535")
    return value


def validate_interval(value: float, name: str) -> float:
    if value <= 0:
        raise ValueError(f"{name} must be greater than 0")
    return value


def validate_history(value: int, name: str) -> int:
    if value <= 0:
        raise ValueError(f"{name} must be greater than 0")
    return value


def validate_choice(value: str, allowed: List[str], name: str) -> str:
    if value not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(allowed)}")
    return value


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
        anomaly_freeze_baseline=bool(policy_data.get("anomaly_freeze_baseline", args.anomaly_freeze_baseline)),
    )

    include = data.get("include")
    if include is None:
        include = parse_list(args.include)
    elif not isinstance(include, list):
        raise ValueError("include must be a list")
    include = [str(item) for item in include]

    bind_host = validate_host(str(data.get("bind_host", args.host)))
    bind_port = validate_port(int(data.get("bind_port", args.port)))
    interval = validate_interval(float(data.get("interval", args.interval)), "interval")
    global_event_history = validate_history(int(data.get("global_event_history", args.global_event_history)), "global_event_history")
    interface_event_history = validate_history(int(data.get("interface_event_history", args.interface_event_history)), "interface_event_history")
    rate_history = validate_history(int(data.get("rate_history", args.rate_history)), "rate_history")
    replay_speed = validate_interval(float(data.get("replay_speed", args.replay_speed)), "replay_speed")

    console_sort = validate_choice(str(data.get("console_sort", args.console_sort)), ["iface", "rx", "tx", "events", "health"], "console_sort")
    console_filter_status = validate_choice(str(data.get("console_filter_status", args.console_filter_status)), ["all", "healthy", "warning", "critical", "unknown"], "console_filter_status")

    selftest_interfaces = int(data.get("selftest_interfaces", args.selftest_interfaces))
    if selftest_interfaces <= 0:
        raise ValueError("selftest_interfaces must be greater than 0")

    api_rate_limit = int(data.get("api_rate_limit", getattr(args, "api_rate_limit", 60)))
    enable_cors = bool(data.get("enable_cors", getattr(args, "enable_cors", False)))

    return MonitorConfig(
        interval=interval,
        include=include,
        exclude_loopback=bool(data.get("exclude_loopback", args.exclude_loopback)),
        global_event_history=global_event_history,
        interface_event_history=interface_event_history,
        rate_history=rate_history,
        bind_host=bind_host,
        bind_port=bind_port,
        event_log_path=data.get("event_log_path", args.event_log_path),
        sqlite_path=data.get("sqlite_path", args.sqlite_path),
        console_sort=console_sort,
        console_filter_status=console_filter_status,
        replay_path=data.get("replay_path", args.replay_path),
        replay_speed=replay_speed,
        selftest_mode=bool(data.get("selftest_mode", args.selftest_mode)),
        selftest_interfaces=selftest_interfaces,
        selftest_seed=int(data.get("selftest_seed", args.selftest_seed)),
        policy=policy,
        api_rate_limit=api_rate_limit,
        enable_cors=enable_cors,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_NAME, description="Network anomaly monitor with JSON APIs")
    parser.add_argument("--host", default="127.0.0.1", help="API bind host")
    parser.add_argument("--port", type=int, default=8080, help="API bind port")
    parser.add_argument("--interval", type=float, default=2.0, help="sampling interval")
    parser.add_argument("--include", default="", help="comma-separated interface allow-list")
    parser.add_argument("--exclude-loopback", action="store_true", help="exclude lo")
    parser.add_argument("--global-event-history", type=int, default=1024, help="global event history")
    parser.add_argument("--interface-event-history", type=int, default=256, help="per-interface event history")
    parser.add_argument("--rate-history", type=int, default=256, help="per-interface rate history")
    parser.add_argument("--event-log-path", help="append anomaly events to JSONL file")
    parser.add_argument("--sqlite-path", help="persist anomaly events to SQLite")
    parser.add_argument("--console-sort", default="iface", choices=["iface", "rx", "tx", "events", "health"])
    parser.add_argument("--console-filter-status", default="all", choices=["all", "healthy", "warning", "critical", "unknown"])
    parser.add_argument("--replay-path", help="replay samples from JSON file")
    parser.add_argument("--replay-speed", type=float, default=1.0, help="multiply replay speed")
    parser.add_argument("--selftest-mode", action="store_true")
    parser.add_argument("--selftest-interfaces", type=int, default=3)
    parser.add_argument("--selftest-seed", type=int, default=1337)
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
    parser.add_argument("--anomaly-freeze-baseline", action="store_true")
    parser.add_argument("--api-rate-limit", type=int, default=60, help="requests per minute per IP")
    parser.add_argument("--enable-cors", action="store_true", help="enable CORS headers")
    parser.add_argument("--debug", action="store_true")
    return parser


def clear_screen() -> None:
    if sys.stdout.isatty():
        if sys.platform == "win32":
            os.system("cls")
        else:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()


def run_console_loop(state: MonitorState, stop: threading.Event, interval: float, sort_key: str, status_filter: str) -> None:
    interval = validate_interval(interval, "console_interval")
    while not stop.is_set():
        clear_screen()
        print(ConsoleRenderer.render(state, sort_key, status_filter))
        stop.wait(interval)


def install_signal_handlers(stop: threading.Event) -> None:
    def handler(_sig: int, _frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def create_reader(config: MonitorConfig) -> SampleProvider:
    if config.selftest_mode:
        return SelfTestReader(config.selftest_interfaces, config.selftest_seed)
    if config.replay_path:
        return ReplayReader(config.replay_path)
    return LinuxNetReader()


def adjust_runtime_interval(config: MonitorConfig) -> float:
    if config.replay_path:
        return config.interval / config.replay_speed
    return config.interval


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
        validate_interval(args.console_interval, "console_interval")
        reader = create_reader(config)
        config.interval = adjust_runtime_interval(config)
    except Exception as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1

    state = MonitorState(config, reader)
    worker = MonitorWorker(state)
    stop = threading.Event()
    install_signal_handlers(stop)

    ApiHandler.state_ref = state
    ApiHandler.rate_limiter = RateLimiter(config.api_rate_limit)
    ApiHandler.enable_cors = config.enable_cors
    server = ThreadingHTTPServer((config.bind_host, config.bind_port), ApiHandler)
    server_thread = threading.Thread(target=server.serve_forever, name="api-server", daemon=True)

    worker.start()
    server_thread.start()

    console_thread: Optional[threading.Thread] = None
    if not args.quiet:
        console_thread = threading.Thread(
            target=run_console_loop,
            args=(state, stop, args.console_interval, config.console_sort, config.console_filter_status),
            name="console-renderer",
            daemon=True,
        )
        console_thread.start()

    logging.info("api listening on http://%s:%d", config.bind_host, config.bind_port)

    try:
        while not stop.is_set():
            stop.wait(1.0)
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        worker.stop()
        state.store.close()
        server_thread.join(timeout=2.0)
        if console_thread is not None:
            console_thread.join(timeout=2.0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
