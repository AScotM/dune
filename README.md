# Dune v0.5.0

Linux network interface anomaly monitor, derived from cgnet-anomaly v0.4.0.

## Changes

- Detect counter decreases and classify them as counter resets rather than zero-traffic intervals
- Emit counter-reset events, restart affected statistical baselines, and expose reset counts through the API
- Bound statistical baselines using a configurable rolling sample window (default 256)
- Reject nonfinite sampling intervals and threshold values
- Keep self-test interface MAC and IPv4 addresses stable across samples
- Warn when the unauthenticated HTTP API binds beyond loopback
- Retain existing HTTP API, console, SQLite, JSONL, replay, and self-test features

## Usage

```bash
python3 main.py --selftest-mode --exclude-loopback --interval 1
python3 main.py --interval 2 --sqlite-path ./events.db --event-log-path ./events.jsonl
python3 main.py --baseline-window 128 --min-baseline-samples 8
python3 -m unittest discover -v
```

The HTTP API listens on 127.0.0.1:8080 by default. Do not expose it publicly without authentication at a trusted proxy.

`rx_bps` and `tx_bps` are bytes per second in the inherited application naming scheme.

## Verification

Five regression tests cover rate calculation, counter resets, rolling baseline eviction, synthetic identity stability, and state event emission.
