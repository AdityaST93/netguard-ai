"""
NetGuard AI - Central configuration
Reads overrides from environment variables (.env supported via python-dotenv).
"""
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
    DEBUG = os.getenv("DEBUG", "True") == "True"
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 5000))

    # Paths
    MODEL_PATH = os.path.join(BASE_DIR, "models", "netguard_model.pkl")
    SCALER_PATH = os.path.join(BASE_DIR, "models", "netguard_scaler.pkl")
    DATA_PATH = os.path.join(BASE_DIR, "data", "sample_traffic.csv")
    ALERTS_LOG = os.path.join(BASE_DIR, "data", "alerts.log")
    BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "data", "blocked_ips.json")

    # Detection
    ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", 0.65))
    AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "False") == "True"
    BLOCK_AFTER_N_ALERTS = int(os.getenv("BLOCK_AFTER_N_ALERTS", 3))

    # Live capture (requires root + scapy + a real NIC; disabled by default)
    LIVE_CAPTURE_ENABLED = os.getenv("LIVE_CAPTURE_ENABLED", "False") == "True"
    CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
