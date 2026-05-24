import json
import subprocess
from typing import Dict, List, Optional

from nfstream import NFStreamer

from src.core.feature_config import FEATURE_NAMES

class TrafficCollector:
    def __init__(self, interface=None, use_pcap=None):
        self.interface = interface if interface else self._auto_detect_interface()
        self.use_pcap = use_pcap

    @staticmethod
    def _get_windows_adapters() -> List[Dict]:
        command = (
            "Get-NetAdapter | "
            "Select-Object Name, InterfaceDescription, InterfaceGuid, Status, LinkSpeed | "
            "ConvertTo-Json -Compress"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                check=True,
            )
            output = result.stdout.strip()
            if not output:
                return []
            parsed = json.loads(output)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return []

    @staticmethod
    def _is_virtual_interface(name: str, description: str) -> bool:
        text = f"{name} {description}".lower()
        virtual_markers = [
            # Pure software loopbacks — carry no real network traffic
            "loopback",
            "npcap loopback",
            # Bluetooth — wrong protocol for IP flow monitoring
            "bluetooth",
            # VPN tunnel adapters — show tunnelled packets only, not raw flows
            "tailscale",
            "wireguard",
            "hamachi",
            # Container / WSL internal bridges
            "docker",
            "wsl",
            # Windows-specific virtual adapters with no real traffic
            # (replaces the old broad "virtual" match which also blocked
            #  VirtualBox and VMware lab adapters by mistake)
            "wi-fi direct",
            "microsoft hosted network",
            "microsoft kernel debug",
            # Hyper-V internal-only virtual switches (not external/bridged)
            "hyper-v",
            "vethernet",
        ]
        # NOTE: "virtual" and "vmware" are intentionally NOT in this list.
        # VirtualBox adapters contain "virtual" in their name/description, and
        # VMware host-only / bridged adapters contain "vmware".  Both are
        # legitimate monitoring targets when Vulnsight defends a VM lab.
        return any(marker in text for marker in virtual_markers)

    @classmethod
    def get_available_interfaces(cls) -> List[Dict]:
        """Return all non-virtual network adapters as a list of dicts with
        keys: name, description, device (the NPF path passed to NFStream)."""
        adapters = cls._get_windows_adapters()
        result = []
        for adapter in adapters:
            name = str(adapter.get("Name", ""))
            desc = str(adapter.get("InterfaceDescription", ""))
            guid = str(adapter.get("InterfaceGuid", "")).strip().strip("{}")
            if not guid:
                continue
            if cls._is_virtual_interface(name, desc):
                continue
            result.append({
                "name": name,
                "description": desc,
                "device": rf"\Device\NPF_{{{guid}}}",
                "status": str(adapter.get("Status", "")),
            })
        return result

    def _auto_detect_interface(self) -> str:
        adapters = self._get_windows_adapters()
        if not adapters:
            raise RuntimeError(
                "No network adapters found. Run as Administrator or pass interface explicitly."
            )

        up_adapters = [a for a in adapters if str(a.get("Status", "")).lower() == "up"]
        candidates = up_adapters if up_adapters else adapters

        filtered = []
        for adapter in candidates:
            name = str(adapter.get("Name", ""))
            desc = str(adapter.get("InterfaceDescription", ""))
            guid = str(adapter.get("InterfaceGuid", "")).strip()
            if not guid:
                continue
            if self._is_virtual_interface(name, desc):
                continue
            filtered.append(adapter)

        selected = filtered[0] if filtered else candidates[0]
        guid = str(selected.get("InterfaceGuid", "")).strip().strip("{}")
        if not guid:
            raise RuntimeError("Could not resolve adapter GUID for traffic collection.")

        return rf"\Device\NPF_{{{guid}}}"

    def get_flows(self):
        source = self.use_pcap if self.use_pcap else self.interface

        # Reduced timeouts for faster testing
        # idle_timeout=10: If a flow is silent for 10s, it's sent to the model
        # active_timeout=60: Long flows are split every 60s so you get alerts faster
        streamer = NFStreamer(
            source=source,
            statistical_analysis=True,
            idle_timeout=10,  
            active_timeout=60,
            promiscuous_mode=True
        )

        for flow in streamer:
            # ── 34 tool-agnostic features ───────────────────────────────
            # All derived from counts, byte sums, packet-length statistics,
            # and TCP flag counts — quantities that CICFlowMeter and nfstream
            # compute identically.  No timing-based features (Flow Duration,
            # IAT, rates) because those differ between the two tools and
            # break live inference.  Rate-driven attacks are caught by the
            # SignatureEngine instead.
            #
            # Order must match src/core/feature_config.FEATURE_NAMES exactly.
            fwd_pkts = flow.src2dst_packets
            bwd_pkts = flow.dst2src_packets
            fwd_byt  = flow.src2dst_bytes
            bwd_byt  = flow.dst2src_bytes
            tot_pkt  = flow.bidirectional_packets
            tot_byt  = flow.bidirectional_bytes

            features = [
                flow.dst_port,                                     # 1.  Destination Port
                fwd_pkts,                                          # 2.  Total Fwd Packets
                bwd_pkts,                                          # 3.  Total Backward Packets
                fwd_byt,                                           # 4.  Total Length of Fwd Packets
                bwd_byt,                                           # 5.  Total Length of Bwd Packets
                flow.src2dst_max_ps,                               # 6.  Fwd Packet Length Max
                flow.src2dst_min_ps,                               # 7.  Fwd Packet Length Min
                flow.src2dst_mean_ps,                              # 8.  Fwd Packet Length Mean
                flow.src2dst_stddev_ps,                            # 9.  Fwd Packet Length Std
                flow.dst2src_max_ps,                               # 10. Bwd Packet Length Max
                flow.dst2src_min_ps,                               # 11. Bwd Packet Length Min
                flow.dst2src_mean_ps,                              # 12. Bwd Packet Length Mean
                flow.dst2src_stddev_ps,                            # 13. Bwd Packet Length Std
                flow.bidirectional_min_ps,                         # 14. Min Packet Length
                flow.bidirectional_max_ps,                         # 15. Max Packet Length
                flow.bidirectional_mean_ps,                        # 16. Packet Length Mean
                flow.bidirectional_stddev_ps,                      # 17. Packet Length Std
                flow.bidirectional_stddev_ps ** 2,                 # 18. Packet Length Variance
                flow.bidirectional_fin_packets,                    # 19. FIN Flag Count
                flow.bidirectional_syn_packets,                    # 20. SYN Flag Count
                flow.bidirectional_rst_packets,                    # 21. RST Flag Count
                flow.bidirectional_psh_packets,                    # 22. PSH Flag Count
                flow.bidirectional_ack_packets,                    # 23. ACK Flag Count
                flow.bidirectional_urg_packets,                    # 24. URG Flag Count
                flow.bidirectional_cwr_packets,                    # 25. CWE Flag Count
                flow.bidirectional_ece_packets,                    # 26. ECE Flag Count
                flow.src2dst_psh_packets,                          # 27. Fwd PSH Flags
                flow.dst2src_psh_packets,                          # 28. Bwd PSH Flags
                flow.src2dst_urg_packets,                          # 29. Fwd URG Flags
                flow.dst2src_urg_packets,                          # 30. Bwd URG Flags
                (bwd_byt / fwd_byt) if fwd_byt > 0 else 0.0,       # 31. Down/Up Ratio
                (tot_byt / tot_pkt) if tot_pkt > 0 else 0.0,       # 32. Average Packet Size
                (fwd_byt / fwd_pkts) if fwd_pkts > 0 else 0.0,     # 33. Avg Fwd Segment Size
                (bwd_byt / bwd_pkts) if bwd_pkts > 0 else 0.0,     # 34. Avg Bwd Segment Size
            ]

            if len(features) != len(FEATURE_NAMES):
                continue

            metadata = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "protocol": flow.protocol,
                "interface": source,
            }

            yield features, metadata