"""
Basic tests for NetGuard AI. Run with: pytest

These tests train a tiny throwaway model on a small synthetic dataset so
they don't depend on any pre-existing trained model artifact.
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.generate_synthetic_data import generate, FEATURE_COLUMNS  # noqa: E402


@pytest.fixture(scope="module")
def trained_detector():
    from ml.train_model import train
    from ml.detector import ThreatDetector

    with tempfile.TemporaryDirectory() as tmp:
        data_path = os.path.join(tmp, "data.csv")
        model_path = os.path.join(tmp, "model.pkl")
        scaler_path = os.path.join(tmp, "scaler.pkl")

        df = generate(4000)
        df.to_csv(data_path, index=False)
        train(data_path, model_path, scaler_path)

        yield ThreatDetector(model_path=model_path, scaler_path=scaler_path)


def test_synthetic_data_has_expected_columns():
    df = generate(500)
    for col in FEATURE_COLUMNS:
        assert col in df.columns
    assert "label" in df.columns
    assert "src_ip" in df.columns
    assert set(df["label"].unique()).issubset(
        {"normal", "port_scan", "dos", "brute_force", "ddos"}
    )


def test_detector_is_ready(trained_detector):
    assert trained_detector.is_ready


def test_detector_predicts_normal_traffic(trained_detector):
    record = {
        "duration": 2.0, "src_bytes": 500, "dst_bytes": 600, "packet_count": 12,
        "packets_per_second": 5, "avg_packet_size": 400, "syn_flag_count": 1,
        "unique_dst_ports": 1, "same_src_conn_count": 2, "tcp_error_rate": 0.02,
    }
    result = trained_detector.predict(record)
    assert result["label"] == "normal"
    assert result["is_threat"] is False
    assert 0.0 <= result["confidence"] <= 1.0


def test_detector_predicts_ddos_traffic(trained_detector):
    record = {
        "duration": 0.01, "src_bytes": 2600, "dst_bytes": 2, "packet_count": 550,
        "packets_per_second": 2600, "avg_packet_size": 1450, "syn_flag_count": 160,
        "unique_dst_ports": 1, "same_src_conn_count": 1300, "tcp_error_rate": 0.2,
    }
    result = trained_detector.predict(record)
    assert result["label"] == "ddos"
    assert result["is_threat"] is True


def test_detector_scores_sum_close_to_one(trained_detector):
    record = {col: 1 for col in FEATURE_COLUMNS}
    result = trained_detector.predict(record)
    total = sum(result["scores"].values())
    assert abs(total - 1.0) < 1e-3


def test_alert_manager_creates_and_lists_alerts(tmp_path):
    from core.alert_manager import AlertManager

    mgr = AlertManager(log_path=str(tmp_path / "alerts.log"))
    mgr.create_alert("10.0.0.5", "port_scan", 0.91, {"port_scan": 0.91, "normal": 0.09})
    recent = mgr.recent()
    assert len(recent) == 1
    assert recent[0]["src_ip"] == "10.0.0.5"
    assert recent[0]["severity"] in ("low", "medium", "high", "critical")


def test_ip_blocker_block_and_unblock(tmp_path):
    from core.ip_blocker import IPBlocker

    blocker = IPBlocker(store_path=str(tmp_path / "blocked.json"))
    assert not blocker.is_blocked("203.0.113.9")
    blocker.block("203.0.113.9", reason="test")
    assert blocker.is_blocked("203.0.113.9")
    assert blocker.unblock("203.0.113.9")
    assert not blocker.is_blocked("203.0.113.9")
