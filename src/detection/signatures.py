"""
Signature-based first-pass detector.

Catches well-known attack patterns deterministically using flow metadata,
BEFORE the ML model runs.  This gives Vulnsight reliable detection for the
obvious 80% of attacks without depending on the model's distribution
matching the live traffic source.

Covered attack types
--------------------
- port_scan          : one src probing many (dst, port) targets
- ddos               : burst of flows arriving at one dst
- brute_force        : repeated connections to an auth service
- data_exfiltration  : large asymmetric outbound transfer (single flow
                       OR cumulative bytes per src/dst over a window)
- c2_beacon          : regular periodic connections (low-jitter
                       inter-arrival pattern) with small payloads

Design contract
---------------
- One observation per flow.  All rules share rolling 60–180s windows of
  recent flow metadata.
- check() returns a SignatureMatch dict OR None.  When it returns a match,
  the caller skips the ML model and emits the alert directly.
- Thresholds are conservative on purpose — false positives here matter
  more than missed signatures, since the ML model still runs as a second
  pass for anything signatures miss.
"""

import statistics
import time
from collections import defaultdict, deque
from typing import Dict, Optional


# Auth services commonly targeted by credential-stuffing tools (hydra, medusa,
# patator).  A burst of connections from one src to one dst on these ports is
# almost certainly a brute-force attempt.
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900}

# Per-rule feature evidence — mirrors SHAP's output shape so the UI's
# explanation drawer renders the same way for signature hits.  The "impact"
# values are illustrative weights, not learned attributions; they tell the
# analyst WHICH features the rule fired on, in priority order.
_RULE_EVIDENCE: Dict[str, list] = {
    "port_scan": [
        {"feature": "Destination Port",            "impact": 0.40, "direction": "increases_risk"},
        {"feature": "Total Fwd Packets",           "impact": 0.25, "direction": "increases_risk"},
        {"feature": "Flow Duration",               "impact": 0.20, "direction": "decreases_risk"},
        {"feature": "Packet Length Std",           "impact": 0.15, "direction": "decreases_risk"},
    ],
    "ddos": [
        {"feature": "Flow Packets/s",              "impact": 0.45, "direction": "increases_risk"},
        {"feature": "Flow Bytes/s",                "impact": 0.30, "direction": "increases_risk"},
        {"feature": "Total Fwd Packets",           "impact": 0.15, "direction": "increases_risk"},
        {"feature": "Flow IAT Mean",               "impact": 0.10, "direction": "decreases_risk"},
    ],
    "brute_force": [
        {"feature": "Destination Port",            "impact": 0.45, "direction": "increases_risk"},
        {"feature": "Total Fwd Packets",           "impact": 0.25, "direction": "increases_risk"},
        {"feature": "Fwd Packets/s",               "impact": 0.20, "direction": "increases_risk"},
        {"feature": "Packet Length Std",           "impact": 0.10, "direction": "decreases_risk"},
    ],
    "data_exfiltration": [
        {"feature": "Total Length of Fwd Packets", "impact": 0.50, "direction": "increases_risk"},
        {"feature": "Total Length of Bwd Packets", "impact": 0.25, "direction": "decreases_risk"},
        {"feature": "Flow Duration",               "impact": 0.15, "direction": "increases_risk"},
        {"feature": "Flow Bytes/s",                "impact": 0.10, "direction": "increases_risk"},
    ],
    "c2_beacon": [
        {"feature": "Flow IAT Mean",               "impact": 0.40, "direction": "increases_risk"},
        {"feature": "Total Length of Fwd Packets", "impact": 0.25, "direction": "decreases_risk"},
        {"feature": "Flow Duration",               "impact": 0.20, "direction": "decreases_risk"},
        {"feature": "Destination Port",            "impact": 0.15, "direction": "increases_risk"},
    ],
}

# Ports where regular small periodic traffic is normal (DNS, NTP, mDNS, ICMP
# echo).  We don't fire the c2_beacon rule on these — too many false positives.
BEACON_IGNORE_PORTS = {53, 67, 68, 123, 137, 138, 5353, 5355, 1900}

# Feature indices (must match FEATURE_NAMES order in feature_config.py).
_F_DST_PORT  = 0
_F_DURATION  = 1   # microseconds
_F_FWD_PKTS  = 2
_F_BWD_PKTS  = 3
_F_FWD_BYTES = 4
_F_BWD_BYTES = 5


class SignatureEngine:
    # Short window — used by port_scan, ddos, brute_force, exfil-cumulative.
    WINDOW_SECONDS = 60
    # Long window — used by c2_beacon (needs enough occurrences to assess
    # period regularity for 10–60s beacons).
    BEACON_WINDOW_SECONDS = 180

    # --- Rule thresholds (tuned for nfstream 10s idle / 60s active flows) ---
    PORTSCAN_UNIQUE_TARGETS = 15    # distinct (dst_ip, dst_port) pairs
    PORTSCAN_MIN_FLOWS      = 20

    DDOS_FLOWS_TO_DST       = 150   # flows arriving at one dst in 60s

    BRUTEFORCE_FLOWS_TO_SVC = 8     # repeated hits on (dst, auth_port)

    EXFIL_SINGLE_FWD_BYTES  = 1_000_000   # 1 MB in one flow
    EXFIL_SINGLE_DURATION_S = 3.0
    EXFIL_SINGLE_RATIO      = 3.0          # fwd_bytes / bwd_bytes
    EXFIL_CUMUL_FWD_BYTES   = 10_000_000   # 10 MB total over 60s
    EXFIL_CUMUL_RATIO       = 3.0          # outbound much greater than inbound

    BEACON_MIN_OCCURRENCES  = 5
    BEACON_MAX_JITTER_RATIO = 0.30   # stddev(intervals) / mean(intervals)
    BEACON_MAX_FLOW_BYTES   = 5_000  # ignore "beacons" that are real downloads
    BEACON_MIN_INTERVAL_S   = 3.0    # below this looks like keep-alive noise
    BEACON_MAX_INTERVAL_S   = 90.0   # above this we can't reliably classify

    MAX_TRACKED_KEYS = 5000

    def __init__(self) -> None:
        # by_src[src] = deque of (ts, dst_ip, dst_port)
        self._by_src: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        # by_dst[dst] = deque of (ts, src_ip)
        self._by_dst: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        # exfil_bytes[(src, dst)] = deque of (ts, fwd_bytes, bwd_bytes)
        self._exfil: Dict[tuple, deque] = defaultdict(lambda: deque(maxlen=500))
        # beacons[(src, dst, dst_port)] = deque of (ts, total_bytes)
        self._beacons: Dict[tuple, deque] = defaultdict(lambda: deque(maxlen=50))

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    def check(self, features: list, meta: dict) -> Optional[dict]:
        now      = time.time()
        src      = str(meta.get("src_ip", ""))
        dst      = str(meta.get("dst_ip", ""))
        if not src or not dst or not features:
            return None

        dst_port    = int(features[_F_DST_PORT])
        duration_us = float(features[_F_DURATION])
        fwd_bytes   = float(features[_F_FWD_BYTES])
        bwd_bytes   = float(features[_F_BWD_BYTES])
        total_bytes = fwd_bytes + bwd_bytes

        # Update short-window state.
        self._by_src[src].append((now, dst, dst_port))
        self._by_dst[dst].append((now, src))
        cutoff = now - self.WINDOW_SECONDS
        self._prune(self._by_src[src], cutoff)
        self._prune(self._by_dst[dst], cutoff)

        # Update exfil + beacon state.
        exfil_key  = (src, dst)
        beacon_key = (src, dst, dst_port)
        self._exfil[exfil_key].append((now, fwd_bytes, bwd_bytes))
        self._beacons[beacon_key].append((now, total_bytes))
        self._prune(self._exfil[exfil_key], cutoff)
        self._prune(self._beacons[beacon_key], now - self.BEACON_WINDOW_SECONDS)

        # Opportunistic GC.
        if len(self._by_src) > self.MAX_TRACKED_KEYS:
            self._evict_empty()

        # ── Rule 1: Port scan ─────────────────────────────────────────
        src_recent = self._by_src[src]
        if len(src_recent) >= self.PORTSCAN_MIN_FLOWS:
            unique_targets = {(t[1], t[2]) for t in src_recent}
            if len(unique_targets) >= self.PORTSCAN_UNIQUE_TARGETS:
                return self._match(
                    "port_scan",
                    f"{src} probed {len(unique_targets)} unique dst:port pairs "
                    f"({len(src_recent)} flows) in {self.WINDOW_SECONDS}s",
                )

        # ── Rule 2: DDoS / flood ──────────────────────────────────────
        dst_recent = self._by_dst[dst]
        if len(dst_recent) >= self.DDOS_FLOWS_TO_DST:
            unique_sources = len({t[1] for t in dst_recent})
            return self._match(
                "ddos",
                f"{dst} received {len(dst_recent)} flows from {unique_sources} "
                f"source(s) in {self.WINDOW_SECONDS}s",
            )

        # ── Rule 3: Brute force ───────────────────────────────────────
        if dst_port in AUTH_PORTS:
            same_service = sum(
                1 for t in src_recent if t[1] == dst and t[2] == dst_port
            )
            if same_service >= self.BRUTEFORCE_FLOWS_TO_SVC:
                return self._match(
                    "brute_force",
                    f"{same_service} connections from {src} to {dst}:{dst_port} "
                    f"(auth service) in {self.WINDOW_SECONDS}s",
                )

        # ── Rule 4: Data exfiltration ─────────────────────────────────
        # (a) Single big asymmetric flow.
        if (
            fwd_bytes >= self.EXFIL_SINGLE_FWD_BYTES
            and duration_us / 1_000_000 >= self.EXFIL_SINGLE_DURATION_S
            and fwd_bytes >= self.EXFIL_SINGLE_RATIO * max(bwd_bytes, 1.0)
        ):
            mb = fwd_bytes / 1_000_000
            return self._match(
                "data_exfiltration",
                f"{src} -> {dst}: {mb:.1f} MB outbound in single flow "
                f"({duration_us/1_000_000:.1f}s, fwd/bwd ratio "
                f"{fwd_bytes / max(bwd_bytes, 1.0):.0f}x)",
            )
        # (b) Cumulative outbound burst across many flows.
        exfil_buf = self._exfil[exfil_key]
        total_fwd = sum(t[1] for t in exfil_buf)
        total_bwd = sum(t[2] for t in exfil_buf)
        if (
            total_fwd >= self.EXFIL_CUMUL_FWD_BYTES
            and total_fwd >= self.EXFIL_CUMUL_RATIO * max(total_bwd, 1.0)
        ):
            mb = total_fwd / 1_000_000
            return self._match(
                "data_exfiltration",
                f"{src} -> {dst}: {mb:.1f} MB outbound across "
                f"{len(exfil_buf)} flows in {self.WINDOW_SECONDS}s "
                f"(fwd/bwd ratio {total_fwd / max(total_bwd, 1.0):.0f}x)",
            )

        # ── Rule 5: C2 beacon ─────────────────────────────────────────
        # Regular periodic connections to the same dst:port with small
        # payloads — classic implant heartbeat (Cobalt Strike, Empire,
        # Meterpreter reverse_https, custom RATs).
        if dst_port not in BEACON_IGNORE_PORTS:
            beacon_buf = self._beacons[beacon_key]
            # Only consider entries that are themselves small payloads.
            small_entries = [t for t in beacon_buf if t[1] <= self.BEACON_MAX_FLOW_BYTES]
            if len(small_entries) >= self.BEACON_MIN_OCCURRENCES:
                timestamps = [t[0] for t in small_entries]
                intervals  = [
                    b - a for a, b in zip(timestamps, timestamps[1:])
                ]
                if intervals:
                    mean_iv = statistics.mean(intervals)
                    if self.BEACON_MIN_INTERVAL_S <= mean_iv <= self.BEACON_MAX_INTERVAL_S:
                        stdev_iv = statistics.pstdev(intervals)
                        jitter_ratio = stdev_iv / mean_iv if mean_iv > 0 else 1.0
                        if jitter_ratio <= self.BEACON_MAX_JITTER_RATIO:
                            return self._match(
                                "c2_beacon",
                                f"{src} -> {dst}:{dst_port} beacons every "
                                f"{mean_iv:.1f}s ± {stdev_iv:.1f}s "
                                f"(jitter {jitter_ratio:.0%}, "
                                f"{len(small_entries)} occurrences)",
                            )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match(attack_type: str, reason: str) -> dict:
        return {
            "attack_type": attack_type,
            "confidence":  1.0,
            "reason":      reason,
            "source":      "signature",
            "evidence":    _RULE_EVIDENCE.get(attack_type, []),
        }

    @staticmethod
    def _prune(buffer: deque, cutoff: float) -> None:
        while buffer and buffer[0][0] < cutoff:
            buffer.popleft()

    def _evict_empty(self) -> None:
        for store in (self._by_src, self._by_dst, self._exfil, self._beacons):
            empty = [k for k, v in store.items() if not v]
            for k in empty:
                del store[k]
