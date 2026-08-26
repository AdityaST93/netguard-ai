"""
NetGuard AI - IP blocker.

Maintains a persisted blocklist of suspicious source IPs. Optionally
applies an actual OS firewall rule (Linux iptables) when running with
sufficient privileges - this is OFF by default (Config.AUTO_BLOCK_ENABLED)
and is purely defensive (dropping traffic FROM an attacking IP), never
an offensive/exploitation action.
"""
import json
import os
import shutil
import subprocess
import threading
from datetime import datetime, timezone

from config import Config


class IPBlocker:
    def __init__(self, store_path: str = Config.BLOCKED_IPS_FILE):
        self.store_path = store_path
        self._lock = threading.Lock()
        self._blocked = {}
        os.makedirs(os.path.dirname(store_path), exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path, "r") as f:
                    self._blocked = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._blocked = {}

    def _persist(self):
        with open(self.store_path, "w") as f:
            json.dump(self._blocked, f, indent=2)

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def block(self, ip: str, reason: str = "") -> dict:
        with self._lock:
            if ip in self._blocked:
                return self._blocked[ip]
            entry = {
                "ip": ip,
                "reason": reason,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "firewall_applied": False,
            }
            if Config.AUTO_BLOCK_ENABLED:
                entry["firewall_applied"] = self._apply_firewall_rule(ip)
            self._blocked[ip] = entry
            self._persist()
            return entry

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blocked:
                return False
            if self._blocked[ip].get("firewall_applied"):
                self._remove_firewall_rule(ip)
            del self._blocked[ip]
            self._persist()
            return True

    def list_blocked(self) -> list:
        with self._lock:
            return list(self._blocked.values())

    @staticmethod
    def _apply_firewall_rule(ip: str) -> bool:
        """Best-effort: only works on Linux with iptables and root privileges.
        Silently no-ops (returns False) in any environment where this isn't possible,
        e.g. this sandbox, containers without NET_ADMIN, or non-Linux hosts."""
        if shutil.which("iptables") is None:
            return False
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return False

    @staticmethod
    def _remove_firewall_rule(ip: str) -> bool:
        if shutil.which("iptables") is None:
            return False
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return False


ip_blocker = IPBlocker()
