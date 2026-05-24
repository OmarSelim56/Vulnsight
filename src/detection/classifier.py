"""
Rule-based attack-type classifier.

Uses the 20 engineered flow features produced by TrafficCollector /
nfstream to assign a human-readable attack category to each malicious
flow.  Benign flows always return "normal".

Decision order (evaluated top-to-bottom, first match wins):
    1. DDoS / DoS  — high-rate OR slow-exhaustion flows
    2. Port scan   — very short, near-empty flows (SYN probes)
    3. Brute force — auth / web port + repeated packet pattern
    4. Data exfil  — large outbound payload, long duration, low rate
    5. C2 beacon   — bidirectional balanced or low-intensity traffic
    6. Intrusion   — catch-all for unclassified malicious traffic

Design notes (NFStream vs CICFlowMeter):
  - HTTP DoS attacks (Hulk, GoldenEye) are BIDIRECTIONAL — the server
    responds before being overwhelmed. Requiring _mostly_one_way misses
    them entirely. We detect DoS/DDoS on rate alone.
  - NFStream bidirectional_mean_piat_ms can be 0 for burst flows (all
    packets within a single timer tick). Guard against this.
  - Flow rates are naturally lower than CICFlowMeter because NFStream
    aggregates across a 10 s idle-timeout window.
"""
from typing import List

# ── Feature indices (must match FEATURE_NAMES order in feature_config.py) ───
# Updated to the 34-feature tool-agnostic layout — no rate/IAT/duration
# columns anymore (those were dropped to make live deployment work).
# Rate-driven attacks are handled by the SignatureEngine; this classifier
# only labels ML-model hits that signatures missed, using counts and flags.
_DST_PORT        = 0
_FWD_PKTS        = 1
_BWD_PKTS        = 2
_FWD_BYTES       = 3
_BWD_BYTES       = 4
_FWD_LEN_MAX     = 5
_FWD_LEN_MIN     = 6
_FWD_LEN_MEAN    = 7
_FWD_LEN_STD     = 8
_BWD_LEN_MAX     = 9
_BWD_LEN_MIN     = 10
_BWD_LEN_MEAN    = 11
_BWD_LEN_STD     = 12
_MIN_PKT_LEN     = 13
_MAX_PKT_LEN     = 14
_PKT_LEN_MEAN    = 15
_PKT_LEN_STD     = 16
_PKT_LEN_VAR     = 17
_FIN_FLAG        = 18
_SYN_FLAG        = 19
_RST_FLAG        = 20
_PSH_FLAG        = 21
_ACK_FLAG        = 22
_URG_FLAG        = 23
_CWE_FLAG        = 24
_ECE_FLAG        = 25
_FWD_PSH         = 26
_BWD_PSH         = 27
_FWD_URG         = 28
_BWD_URG         = 29
_DOWN_UP_RATIO   = 30
_AVG_PKT_SIZE    = 31
_AVG_FWD_SEG     = 32
_AVG_BWD_SEG     = 33

# Auth ports commonly targeted in brute-force campaigns
_BRUTE_PORTS = {
    21, 22, 23, 25, 110, 143, 389, 445,
    1433, 3306, 3389, 5432, 5900, 8080,
}

# Web / application ports (HTTP brute force, SQL injection, XSS …)
_WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}


_LABEL_TO_ATTACK_TYPE: dict = {
    # ── DDoS / DoS ──────────────────────────────────────────────────────────
    "DDOS":                        "ddos",
    "DDOS ATTEMPT":                "ddos",
    "DDOS DETECTED":               "ddos",
    "DOS":                         "ddos",
    "DOS DETECTED":                "ddos",
    "DOS HULK":                    "ddos",
    "DOS GOLDENEYE":               "ddos",
    "DOS SLOWLORIS":               "ddos",
    "DOS SLOWHTTPTEST":            "ddos",
    "HEARTBLEED":                  "ddos",
    # ── Port scan ────────────────────────────────────────────────────────────
    "PORT SCAN":                   "port_scan",
    "PORT SCAN DETECTED":          "port_scan",
    "PORTSCAN":                    "port_scan",
    "PORTSCAN DETECTED":           "port_scan",
    # ── Brute force ──────────────────────────────────────────────────────────
    "BRUTE FORCE":                 "brute_force",
    "BRUTE FORCE DETECTED":        "brute_force",
    "BRUTEFORCE":                  "brute_force",
    "BRUTEFORCE DETECTED":         "brute_force",
    "FTP-PATATOR":                 "brute_force",
    "SSH-PATATOR":                 "brute_force",
    "WEB ATTACK BRUTE FORCE":      "brute_force",
    "WEB ATTACK – BRUTE FORCE":    "brute_force",
    "WEB ATTACK - BRUTE FORCE":    "brute_force",
    "WEB ATTACK XSS":              "brute_force",
    "WEB ATTACK – XSS":            "brute_force",
    "WEB ATTACK - XSS":            "brute_force",
    "WEB ATTACK SQL INJECTION":    "brute_force",
    "WEB ATTACK – SQL INJECTION":  "brute_force",
    "WEB ATTACK - SQL INJECTION":  "brute_force",
    # ── Data exfiltration ────────────────────────────────────────────────────
    "DATA EXFILTRATION":           "data_exfiltration",
    "DATA EXFILTRATION DETECTED":  "data_exfiltration",
    "EXFILTRATION":                "data_exfiltration",
    "INFILTRATION":                "data_exfiltration",
    # ── C2 / Bot ─────────────────────────────────────────────────────────────
    "C2":                          "c2_beacon",
    "C2 BEACON":                   "c2_beacon",
    "C2 BEACON DETECTED":          "c2_beacon",
    "BOT":                         "c2_beacon",
    "COMMAND AND CONTROL":         "c2_beacon",
    # ── Generic ──────────────────────────────────────────────────────────────
    "ATTACK DETECTED":             "intrusion",
    "INTRUSION":                   "intrusion",
    "INTRUSION DETECTED":          "intrusion",
    "NORMAL":                      "normal",
    "BENIGN":                      "normal",
}


def infer_attack_type_from_label(label: str, is_malicious: bool) -> str:
    """Derive attack_type from a human-readable label (used for imported alerts)."""
    if not is_malicious:
        return "normal"
    return _LABEL_TO_ATTACK_TYPE.get(label.upper().strip(), "intrusion")


def classify_attack_type(features: List[float], is_malicious: bool) -> str:
    """
    Classify a single flow into an attack category using only count- and
    flag-based features (the new 34-feature tool-agnostic layout).

    This is a FALLBACK for ML-model hits that the SignatureEngine missed.
    Rate-driven attacks (DDoS, fast brute force, periodic C2) are caught
    upstream by signatures with much higher precision than feature heuristics
    alone can achieve without timing information.

    Args:
        features:     34-element float list from TrafficCollector.get_flows()
        is_malicious: model prediction (True = attack)

    Returns:
        "ddos", "port_scan", "brute_force", "data_exfiltration",
        "c2_beacon", "intrusion", or "normal".
    """
    if not is_malicious:
        return "normal"
    if len(features) < 34:
        return "intrusion"

    dst_port    = int(features[_DST_PORT])
    fwd_pkts    = float(features[_FWD_PKTS])
    bwd_pkts    = float(features[_BWD_PKTS])
    fwd_bytes   = float(features[_FWD_BYTES])
    bwd_bytes   = float(features[_BWD_BYTES])
    syn_flag    = float(features[_SYN_FLAG])
    rst_flag    = float(features[_RST_FLAG])
    ack_flag    = float(features[_ACK_FLAG])
    psh_flag    = float(features[_PSH_FLAG])
    pkt_len_std = float(features[_PKT_LEN_STD])
    total_pkts  = fwd_pkts + bwd_pkts

    # ── 1. Port scan ───────────────────────────────────────────────────────
    # SYN probes: 1-3 SYN packets, almost no payload, possibly RST back.
    if (syn_flag >= 1
            and total_pkts <= 5
            and fwd_bytes < 500
            and bwd_bytes < 500):
        return "port_scan"

    # ── 2. DDoS / DoS ──────────────────────────────────────────────────────
    # SYN flood: many SYN packets in one flow.
    if syn_flag > 50:
        return "ddos"

    # Volumetric flood: very high total packet count in single aggregated flow.
    if total_pkts > 500 and pkt_len_std < 100:
        return "ddos"

    # ── 3. Brute force ─────────────────────────────────────────────────────
    # Repeated auth attempts on known service ports.
    if dst_port in _BRUTE_PORTS and fwd_pkts > 5:
        return "brute_force"

    # HTTP-layer attacks (brute force login / SQL injection / XSS via POST).
    if dst_port in _WEB_PORTS and fwd_pkts > 8 and fwd_bytes > bwd_bytes:
        return "brute_force"

    # Port-agnostic: many symmetric exchanges, repeated request pattern.
    if fwd_pkts > 20 and bwd_pkts > 8 and pkt_len_std < 50:
        return "brute_force"

    # ── 4. Data exfiltration ───────────────────────────────────────────────
    # Bulk outbound: attacker sends far more bytes than they receive.
    if fwd_bytes > 100_000 and fwd_bytes > bwd_bytes * 3:
        return "data_exfiltration"

    # ── 5. C2 beacon ───────────────────────────────────────────────────────
    # Small bidirectional flow, small payload — implant heartbeat.  Without
    # IAT we can't measure regularity here, but the SignatureEngine handles
    # the periodicity check; this catches small balanced traffic the model
    # flagged as anomalous.
    if (total_pkts <= 10
            and fwd_bytes < 2_000
            and bwd_bytes < 2_000
            and bwd_pkts >= 1):
        return "c2_beacon"

    # ── 6. Generic intrusion ───────────────────────────────────────────────
    return "intrusion"
