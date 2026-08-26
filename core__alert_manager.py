"""
NetGuard AI - Alert manager.

Keeps an in-memory + on-disk log of generated alerts (detected threats)
so the dashboard/API can display real-time and historical activity.
"""
import json
import os
import threading
from collections import deque
from datetime import datetime, timezone

from config import Config


class AlertManager:
    def __init__(self, log_path: str = Config.ALERTS_LOG, max_in_memory: int = 500):
        self.log_path = log_path
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=max_in_memory)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._load_existing()

    def _load_existing(self):
        if not os.path.exists(self.log_path):
            return
        try:
            with open(self.log_path, "r") as f:
                for line in f.readlines()[-500:]:
                    line = line.strip()
                    if line:
                        self._alerts.append(json.loads(line))
        except (json.JSONDecodeError, OSError):
            pass

    def create_alert(self, src_ip: str, label: str, confidence: float, detail: dict = None) -> dict:
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "threat_type": label,
            "confidence": confidence,
            "severity": self._severity_for(label, confidence),
            "detail": detail or {},
        }
        with self._lock:
            self._alerts.append(alert)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(alert) + "\n")
        return alert

    @staticmethod
    def _severity_for(label: str, confidence: float) -> str:
        if label == "normal":
            return "info"
        if label in ("ddos", "dos") and confidence > 0.8:
            return "critical"
        if confidence > 0.75:
            return "high"
        if confidence > 0.5:
            return "medium"
        return "low"

    def recent(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._alerts)[-limit:][::-1]

    def count_for_ip(self, src_ip: str) -> int:
        with self._lock:
            return sum(1 for a in self._alerts if a["src_ip"] == src_ip and a["threat_type"] != "normal")

    def stats(self) -> dict:
        with self._lock:
            alerts = list(self._alerts)
        total = len(alerts)
        threats = [a for a in alerts if a["threat_type"] != "normal"]
        by_type = {}
        for a in threats:
            by_type[a["threat_type"]] = by_type.get(a["threat_type"], 0) + 1
        return {
            "total_events": total,
            "total_threats": len(threats),
            "by_type": by_type,
        }


alert_manager = AlertManager()
