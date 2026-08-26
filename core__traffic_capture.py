"""
NetGuard AI - Traffic capture.

Two modes:
1. replay_from_csv(): reads pre-recorded/synthetic flow records and feeds them
   through the pipeline - this is the default demo mode and needs no
   special privileges or network access.
2. live_capture(): uses scapy to sniff real packets on a NIC and aggregate
   them into flow-like records. Requires root and Config.LIVE_CAPTURE_ENABLED=True.
   Guarded so it never runs unless explicitly enabled by the operator.
"""
import time
import pandas as pd

from config import Config
from ml.generate_synthetic_data import FEATURE_COLUMNS


def replay_from_csv(csv_path: str, on_record, delay_seconds: float = 0.0, limit: int = None):
    """
    Streams rows from a traffic CSV to a callback, simulating real-time arrival.
    on_record(record: dict) is called for every row.
    """
    df = pd.read_csv(csv_path)
    if limit:
        df = df.head(limit)

    for _, row in df.iterrows():
        record = {col: row[col] for col in FEATURE_COLUMNS}
        record["src_ip"] = row.get("src_ip", "0.0.0.0")
        on_record(record)
        if delay_seconds:
            time.sleep(delay_seconds)


def live_capture(on_record, interface: str = Config.CAPTURE_INTERFACE):
    """
    Sniffs live traffic and builds simple per-packet feature records.
    NOTE: this is a lightweight illustrative aggregator (per-packet, not true
    flow-based like the training data), intended as a starting point for
    real deployments - not the accuracy of a full flow exporter (e.g. NetFlow).
    """
    if not Config.LIVE_CAPTURE_ENABLED:
        raise RuntimeError(
            "Live capture is disabled. Set LIVE_CAPTURE_ENABLED=True in your "
            "environment and run with sufficient privileges (root/CAP_NET_RAW)."
        )

    from scapy.all import sniff, IP, TCP  # imported lazily; optional dependency at runtime

    def _handle(pkt):
        if IP in pkt:
            record = {
                "duration": 0.0,
                "src_bytes": len(pkt),
                "dst_bytes": 0,
                "packet_count": 1,
                "packets_per_second": 1.0,
                "avg_packet_size": len(pkt),
                "syn_flag_count": 1 if (TCP in pkt and pkt[TCP].flags & 0x02) else 0,
                "unique_dst_ports": 1,
                "same_src_conn_count": 1,
                "tcp_error_rate": 0.0,
                "src_ip": pkt[IP].src,
            }
            on_record(record)

    sniff(iface=interface, prn=_handle, store=False)
