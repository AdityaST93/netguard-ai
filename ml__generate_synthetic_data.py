"""
NetGuard AI - Synthetic network traffic generator.

Generates a labeled dataset of network flow records (normal vs. attack)
with feature distributions modeled after well-known IDS datasets
(NSL-KDD / CICIDS style flow features), so the pipeline can be trained,
tested, and demoed end-to-end without needing to download a large
external dataset.

Attack types simulated: port_scan, dos, brute_force, ddos.

Usage:
    python ml/generate_synthetic_data.py --rows 20000 --out data/sample_traffic.csv
"""
import argparse
import os
import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)

FEATURE_COLUMNS = [
    "duration", "src_bytes", "dst_bytes", "packet_count",
    "packets_per_second", "avg_packet_size", "syn_flag_count",
    "unique_dst_ports", "same_src_conn_count", "tcp_error_rate",
]


def _normal_traffic(n):
    return pd.DataFrame({
        "duration": RNG.exponential(2.0, n),
        "src_bytes": RNG.normal(500, 150, n).clip(20),
        "dst_bytes": RNG.normal(600, 200, n).clip(20),
        "packet_count": RNG.poisson(12, n),
        "packets_per_second": RNG.normal(5, 2, n).clip(0.1),
        "avg_packet_size": RNG.normal(400, 80, n).clip(40),
        "syn_flag_count": RNG.poisson(1, n),
        "unique_dst_ports": RNG.poisson(1, n).clip(1),
        "same_src_conn_count": RNG.poisson(2, n).clip(1),
        "tcp_error_rate": RNG.beta(1, 20, n),
        "label": "normal",
    })


def _port_scan(n):
    return pd.DataFrame({
        "duration": RNG.exponential(0.3, n),
        "src_bytes": RNG.normal(60, 20, n).clip(10),
        "dst_bytes": RNG.normal(0, 5, n).clip(0),
        "packet_count": RNG.poisson(2, n).clip(1),
        "packets_per_second": RNG.normal(40, 15, n).clip(5),
        "avg_packet_size": RNG.normal(60, 15, n).clip(20),
        "syn_flag_count": RNG.poisson(3, n).clip(1),
        "unique_dst_ports": RNG.integers(20, 500, n),
        "same_src_conn_count": RNG.poisson(30, n).clip(5),
        "tcp_error_rate": RNG.beta(8, 3, n),
        "label": "port_scan",
    })


def _dos(n):
    return pd.DataFrame({
        "duration": RNG.exponential(0.05, n),
        "src_bytes": RNG.normal(1500, 400, n).clip(100),
        "dst_bytes": RNG.normal(10, 5, n).clip(0),
        "packet_count": RNG.poisson(200, n),
        "packets_per_second": RNG.normal(800, 200, n).clip(100),
        "avg_packet_size": RNG.normal(1400, 100, n).clip(200),
        "syn_flag_count": RNG.poisson(50, n),
        "unique_dst_ports": RNG.poisson(1, n).clip(1),
        "same_src_conn_count": RNG.poisson(400, n).clip(50),
        "tcp_error_rate": RNG.beta(2, 10, n),
        "label": "dos",
    })


def _brute_force(n):
    return pd.DataFrame({
        "duration": RNG.exponential(1.0, n),
        "src_bytes": RNG.normal(200, 50, n).clip(20),
        "dst_bytes": RNG.normal(150, 40, n).clip(10),
        "packet_count": RNG.poisson(6, n).clip(1),
        "packets_per_second": RNG.normal(15, 5, n).clip(1),
        "avg_packet_size": RNG.normal(180, 40, n).clip(40),
        "syn_flag_count": RNG.poisson(2, n),
        "unique_dst_ports": RNG.poisson(1, n).clip(1),
        "same_src_conn_count": RNG.poisson(80, n).clip(10),
        "tcp_error_rate": RNG.beta(5, 8, n),
        "label": "brute_force",
    })


def _ddos(n):
    return pd.DataFrame({
        "duration": RNG.exponential(0.02, n),
        "src_bytes": RNG.normal(2500, 600, n).clip(100),
        "dst_bytes": RNG.normal(5, 5, n).clip(0),
        "packet_count": RNG.poisson(500, n),
        "packets_per_second": RNG.normal(2500, 500, n).clip(300),
        "avg_packet_size": RNG.normal(1450, 80, n).clip(200),
        "syn_flag_count": RNG.poisson(150, n),
        "unique_dst_ports": RNG.poisson(2, n).clip(1),
        "same_src_conn_count": RNG.poisson(1200, n).clip(100),
        "tcp_error_rate": RNG.beta(3, 10, n),
        "label": "ddos",
    })


def generate(n_rows: int) -> pd.DataFrame:
    """Generate a shuffled synthetic dataset. ~70% normal, 30% split across attacks."""
    n_normal = int(n_rows * 0.70)
    n_each_attack = int(n_rows * 0.075)

    frames = [
        _normal_traffic(n_normal),
        _port_scan(n_each_attack),
        _dos(n_each_attack),
        _brute_force(n_each_attack),
        _ddos(n_rows - n_normal - 3 * n_each_attack),
    ]
    df = pd.concat(frames, ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    # Add a fake but plausible source IP per row for demo/dashboard purposes
    def _fake_ip():
        return f"{RNG.integers(1, 255)}.{RNG.integers(0, 255)}.{RNG.integers(0, 255)}.{RNG.integers(1, 255)}"

    df.insert(0, "src_ip", [_fake_ip() for _ in range(len(df))])
    return df


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic NetGuard AI traffic data")
    parser.add_argument("--rows", type=int, default=20000, help="Number of rows to generate")
    parser.add_argument("--out", type=str, default="data/sample_traffic.csv", help="Output CSV path")
    args = parser.parse_args()

    df = generate(args.rows)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Generated {len(df)} rows -> {args.out}")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
