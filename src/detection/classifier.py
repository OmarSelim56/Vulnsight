"""
Rule-based attack-type classifier.

Uses the 20 engineered flow features produced by TrafficCollector /
nfstream to assign a human-readable attack category to each malicious
flow.  Benign flows always return "normal".
"""
from typing import List

# ── Feature indices (must match FEATURE_NAMES order) ───────────────────────
_DST_PORT      = 0
_DURATION      = 1   # milliseconds
_FWD_PKTS      = 2
_BWD_PKTS      = 3
_FWD_BYTES     = 4
_BWD_BYTES     = 5
_FWD_LEN_MAX   = 6
_FWD_LEN_MIN   = 7
_BWD_LEN_MAX   = 8
_BWD_LEN_MIN   = 9
_FLOW_BYTES_S  = 10
_FLOW_PKTS_S   = 11
_IAT_MEAN      = 12
_IAT_MAX       = 13
_IAT_MIN       = 14
_FWD_PSH       = 15
_BWD_PSH       = 16
_FWD_PKTS_S    = 17
_BWD_PKTS_S    = 18
_PKT_LEN_STD   = 19

# Ports commonly targeted in brute-force campaigns
_BRUTE_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 8080}


_LABEL_TO_ATTACK_TYPE: dict = {
    "PORT SCAN":          "port_scan",
    "PORTSCAN":           "port_scan",
    "DDOS ATTEMPT":       "ddos",
    "DDOS":               "ddos",
    "DOS":                "ddos",
    "BRUTE FORCE":        "brute_force",
    "BRUTEFORCE":         "brute_force",
    "DATA EXFILTRATION":  "data_exfiltration",
    "EXFILTRATION":       "data_exfiltration",
    "C2 BEACON":          "c2_beacon",
    "C2":                 "c2_beacon",
    "COMMAND AND CONTROL":"c2_beacon",
    "ATTACK DETECTED":    "intrusion",
    "INTRUSION":          "intrusion",
    "NORMAL":             "normal",
    "BENIGN":             "normal",
}


def infer_attack_type_from_label(label: str, is_malicious: bool) -> str:
    """
    Derive an attack_type string from a human-readable alert label.
    Used for manually injected / imported alerts that bypass the flow classifier.
    """
    if not is_malicious:
        return "normal"
    return _LABEL_TO_ATTACK_TYPE.get(label.upper().strip(), "intrusion")


def classify_attack_type(features: List[float], is_malicious: bool) -> str:
    """
    Classify a single flow.

    Args:
        features:     20-element float list from TrafficCollector.get_flows()
        is_malicious: model prediction (True = attack)

    Returns:
        A lowercase string label, e.g. "ddos", "port_scan", "brute_force",
        "data_exfiltration", "c2_beacon", "intrusion", or "normal".
    """
    if not is_malicious:
        return "normal"
    if len(features) < 20:
        return "intrusion"

    dst_port     = int(features[_DST_PORT])
    duration_ms  = float(features[_DURATION])
    fwd_pkts     = float(features[_FWD_PKTS])
    bwd_pkts     = float(features[_BWD_PKTS])
    fwd_bytes    = float(features[_FWD_BYTES])
    bwd_bytes    = float(features[_BWD_BYTES])
    flow_bytes_s = float(features[_FLOW_BYTES_S])
    flow_pkts_s  = float(features[_FLOW_PKTS_S])
    iat_mean     = float(features[_IAT_MEAN])
    pkt_len_std  = float(features[_PKT_LEN_STD])

    # ── DDoS ───────────────────────────────────────────────────────────────
    # Extremely high packet/byte rate characteristic of volumetric attacks.
    if flow_pkts_s > 1_000 or flow_bytes_s > 1_000_000:
        return "ddos"
    if flow_pkts_s > 400 and flow_bytes_s > 400_000:
        return "ddos"

    # ── Port scan ──────────────────────────────────────────────────────────
    # Very short flows, minimal payload, mostly SYN-only probes.
    if (duration_ms < 600
            and fwd_pkts <= 3
            and bwd_pkts <= 1
            and fwd_bytes < 300
            and pkt_len_std < 20):
        return "port_scan"

    # ── Brute force ────────────────────────────────────────────────────────
    # Repeated auth attempts: known auth port + many forward packets.
    if dst_port in _BRUTE_PORTS:
        if fwd_pkts > 8 or flow_pkts_s > 40:
            return "brute_force"

    # ── Data exfiltration ──────────────────────────────────────────────────
    # Bulk data sent outbound: large forward payload, long duration, low rate.
    if fwd_bytes > bwd_bytes * 4 and duration_ms > 8_000 and flow_pkts_s < 60:
        return "data_exfiltration"

    # ── C2 beaconing ───────────────────────────────────────────────────────
    # Regular low-volume heartbeats to a command-and-control server.
    if iat_mean > 500 and duration_ms > 20_000 and flow_pkts_s < 15:
        return "c2_beacon"

    # ── Generic intrusion ─────────────────────────────────────────────────
    return "intrusion"
