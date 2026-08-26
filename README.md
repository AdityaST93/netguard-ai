# 🛡️ NetGuard AI

**AI-based Network Security System** — monitors network traffic, uses machine learning to
tell normal traffic apart from attacks, raises real-time alerts, and can automatically block
suspicious IPs. Includes a live dashboard.

```
Network Traffic → Data Analysis → AI/ML Detection → Threat Alert → IP Block/Response
```

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Flask](https://img.shields.io/badge/backend-Flask-black)
![scikit--learn](https://img.shields.io/badge/ML-scikit--learn-orange)

## Features

- 🔍 **ML-based detection** — RandomForest classifier distinguishes normal traffic from
  `port_scan`, `dos`, `ddos`, and `brute_force` attacks using 10 flow-level features.
- 🚨 **Real-time alerting** — every detected threat is logged with severity (`info` → `critical`).
- 🚫 **Automated response** — repeat offenders are auto-blocked after N alerts (configurable),
  with optional real `iptables` enforcement on Linux.
- 📊 **Live dashboard** — dark-themed SOC-style UI showing stats, live alert feed, blocked IPs,
  and a threat-type breakdown, no build step required.
- 🧪 **Synthetic data generator** — train and demo the full pipeline offline, no external
  dataset download needed.
- 🐳 **Docker-ready** — one command to build and run.
- ✅ **Tested** — pytest suite + GitHub Actions CI.

## Quick start

### 1. Clone & install

```bash
git clone https://github.com/<your-username>/netguard-ai.git
cd netguard-ai
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Generate demo traffic data & train the model

```bash
python ml/generate_synthetic_data.py --rows 20000 --out data/sample_traffic.csv
python ml/train_model.py
```

This prints a classification report and saves `models/netguard_model.pkl` +
`models/netguard_scaler.pkl`.

### 3. Run the app

```bash
python app.py
```

Open **http://localhost:5000** and click **"Run traffic simulation"** to watch NetGuard AI
classify traffic, raise alerts, and (if enabled) block IPs live.

### 4. Run tests

```bash
pytest -v
```

## Docker

```bash
docker compose up --build
```

The image generates the demo dataset and trains the model at build time, so it's ready to use
immediately at **http://localhost:5000**.

## Configuration

All settings are environment variables (see `config.py`), optionally via a `.env` file:

| Variable                | Default   | Description                                              |
|--------------------------|-----------|------------------------------------------------------------|
| `SECRET_KEY`             | dev key   | Flask secret key — set a real value in production          |
| `DEBUG`                  | `True`    | Flask debug mode                                            |
| `HOST` / `PORT`          | `0.0.0.0` / `5000` | Bind address                                        |
| `ANOMALY_THRESHOLD`      | `0.65`    | Reserved for custom threshold-based logic                   |
| `AUTO_BLOCK_ENABLED`     | `False`   | Automatically block IPs after repeated alerts                |
| `BLOCK_AFTER_N_ALERTS`   | `3`       | Alert count before an IP is auto-blocked                     |
| `LIVE_CAPTURE_ENABLED`   | `False`   | Enable real packet sniffing via scapy (requires root)        |
| `CAPTURE_INTERFACE`      | `eth0`    | Network interface for live capture                           |

## API reference

| Method | Endpoint          | Description                                   |
|--------|-------------------|------------------------------------------------|
| GET    | `/api/health`     | Service + model status                          |
| POST   | `/api/analyze`    | Classify a single traffic record (JSON body)    |
| POST   | `/api/simulate`   | Replay `data/sample_traffic.csv` through the pipeline |
| GET    | `/api/alerts`     | Recent alerts                                   |
| GET    | `/api/stats`      | Summary stats (events, threats, blocked count)  |
| GET    | `/api/blocked`    | Currently blocked IPs                           |
| POST   | `/api/block`      | Manually block an IP: `{"ip": "..."}`           |
| POST   | `/api/unblock`    | Manually unblock an IP: `{"ip": "..."}`         |

Example — analyze a single flow:

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "203.0.113.9",
    "duration": 0.01, "src_bytes": 2600, "dst_bytes": 2, "packet_count": 550,
    "packets_per_second": 2600, "avg_packet_size": 1450, "syn_flag_count": 160,
    "unique_dst_ports": 1, "same_src_conn_count": 1300, "tcp_error_rate": 0.2
  }'
```

## Project structure

```
netguard-ai/
├── app.py                     # Flask app: dashboard + REST API
├── config.py                  # Central configuration
├── ml/
│   ├── generate_synthetic_data.py   # Synthetic traffic dataset generator
│   ├── train_model.py               # Trains & saves the RandomForest model
│   └── detector.py                  # Loads model, exposes predict()
├── core/
│   ├── traffic_capture.py     # CSV replay + optional live scapy capture
│   ├── alert_manager.py       # Alert creation, storage, stats
│   └── ip_blocker.py          # Blocklist + optional iptables enforcement
├── dashboard/
│   ├── templates/              # Jinja2 HTML (dashboard, alert log)
│   └── static/{css,js}/        # Dashboard styling & client logic
├── data/                       # Generated dataset, alerts.log, blocklist (gitignored)
├── models/                     # Saved model + scaler (gitignored)
├── tests/                      # pytest suite
├── docs/architecture.md        # Deeper architecture notes
├── Dockerfile / docker-compose.yml
└── .github/workflows/ci.yml    # CI: install, generate data, train, test
```

See [`docs/architecture.md`](docs/architecture.md) for pipeline details and notes on going
from this demo to a production deployment with real traffic.

## Live packet capture (optional, advanced)

By default NetGuard AI runs in **replay/demo mode** using the synthetic dataset — no special
privileges needed. To sniff real traffic instead:

1. Install `scapy` (already in `requirements.txt`) and libpcap on your system.
2. Set `LIVE_CAPTURE_ENABLED=True` and `CAPTURE_INTERFACE=<your-nic>` in `.env`.
3. Run the app with root / `CAP_NET_RAW` privileges.
4. Call `core.traffic_capture.live_capture()` from a custom entrypoint that feeds records into
   `app.process_record()`.

This is intentionally not wired up to the default `python app.py` entrypoint, since it needs
elevated privileges and a real network interface.

## Disclaimer

This is a defensive security / educational project. Detection quality depends entirely on the
training data — the bundled synthetic dataset is for demonstration; retrain on real, properly
labeled traffic from your own network before relying on this in production. IP blocking is
disabled by default and, even when enabled, only ever **drops traffic from an already-flagged
source** — it does not perform any offensive action.

## License

[MIT](LICENSE) © 2026 NetGuard AI Contributors — free to use, modify, and distribute.

