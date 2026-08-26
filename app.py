"""
NetGuard AI - Main Flask application.

Serves:
  - / (dashboard UI)
  - /api/analyze     POST  -> classify a single traffic record
  - /api/simulate    POST  -> run the bundled sample dataset through the pipeline
  - /api/alerts      GET   -> recent alerts
  - /api/stats       GET   -> summary stats
  - /api/blocked     GET   -> currently blocked IPs
  - /api/block       POST  -> manually block an IP
  - /api/unblock     POST  -> manually unblock an IP
  - /api/health      GET   -> service health / model status
"""
import os
from flask import Flask, jsonify, request, render_template

from config import Config
from ml.detector import detector
from core.alert_manager import alert_manager
from core.ip_blocker import ip_blocker
from core.traffic_capture import replay_from_csv

app = Flask(__name__, template_folder="dashboard/templates", static_folder="dashboard/static")
app.config.from_object(Config)

try:
    # Optional dependency - only needed if the dashboard is served from a
    # different origin than the API (e.g. separate frontend deployment).
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass


def process_record(record: dict) -> dict:
    """Core pipeline: Data -> AI/ML Detection -> Alert -> (optional) Block."""
    src_ip = record.get("src_ip", "0.0.0.0")

    if ip_blocker.is_blocked(src_ip):
        return {"src_ip": src_ip, "skipped": True, "reason": "already blocked"}

    result = detector.predict(record)
    alert = None
    block_entry = None

    if result["is_threat"]:
        alert = alert_manager.create_alert(
            src_ip=src_ip,
            label=result["label"],
            confidence=result["confidence"],
            detail=result["scores"],
        )
        threat_count = alert_manager.count_for_ip(src_ip)
        if Config.AUTO_BLOCK_ENABLED and threat_count >= Config.BLOCK_AFTER_N_ALERTS:
            block_entry = ip_blocker.block(src_ip, reason=f"{result['label']} x{threat_count}")

    return {
        "src_ip": src_ip,
        "detection": result,
        "alert": alert,
        "blocked": block_entry,
    }


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "model_ready": detector.is_ready,
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(force=True, silent=True) or {}
    if not detector.is_ready:
        return jsonify({"error": "Model not trained. Run ml/train_model.py first."}), 503
    result = process_record(payload)
    return jsonify(result)


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """Feed the bundled/generated sample_traffic.csv through the pipeline."""
    if not detector.is_ready:
        return jsonify({"error": "Model not trained. Run ml/train_model.py first."}), 503
    if not os.path.exists(Config.DATA_PATH):
        return jsonify({"error": f"No dataset at {Config.DATA_PATH}. Run ml/generate_synthetic_data.py first."}), 400

    body = request.get_json(force=True, silent=True) or {}
    limit = int(body.get("limit", 200))

    results = []

    def _on_record(record):
        results.append(process_record(record))

    replay_from_csv(Config.DATA_PATH, _on_record, limit=limit)

    threats = [r for r in results if r.get("detection", {}).get("is_threat")]
    return jsonify({
        "processed": len(results),
        "threats_detected": len(threats),
        "results": results[-50:],  # cap payload size
    })


@app.route("/api/alerts")
def get_alerts():
    limit = int(request.args.get("limit", 100))
    return jsonify(alert_manager.recent(limit=limit))


@app.route("/api/stats")
def get_stats():
    stats = alert_manager.stats()
    stats["blocked_ip_count"] = len(ip_blocker.list_blocked())
    stats["model_ready"] = detector.is_ready
    return jsonify(stats)


@app.route("/api/blocked")
def get_blocked():
    return jsonify(ip_blocker.list_blocked())


@app.route("/api/block", methods=["POST"])
def block_ip():
    body = request.get_json(force=True, silent=True) or {}
    ip = body.get("ip")
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    entry = ip_blocker.block(ip, reason=body.get("reason", "manual block"))
    return jsonify(entry)


@app.route("/api/unblock", methods=["POST"])
def unblock_ip():
    body = request.get_json(force=True, silent=True) or {}
    ip = body.get("ip")
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    ok = ip_blocker.unblock(ip)
    return jsonify({"unblocked": ok, "ip": ip})


if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
