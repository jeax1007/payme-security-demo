import json
import os
import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
METRICS_PATH = "/app/metrics/results.json"
AI_AGENT_URL = os.environ.get("AI_AGENT_URL", "http://ai_agent:5000")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/metrics")
def metrics():
    if not os.path.exists(METRICS_PATH):
        return jsonify({"error": "aun no se ha corrido run_full_demo.sh"}), 404
    with open(METRICS_PATH, "r") as f:
        return jsonify(json.load(f))


@app.route("/api/red-team", methods=["POST"])
def red_team_proxy():
    """Proxy hacia el Red Teamer Virtual embebido (ai_agent) - evita CORS en el navegador."""
    try:
        resp = requests.post(f"{AI_AGENT_URL}/red-team", timeout=30)
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"ai_agent no disponible: {e}"}), 502


@app.route("/api/analyze-logs", methods=["GET"])
def analyze_logs_proxy():
    try:
        resp = requests.get(f"{AI_AGENT_URL}/analyze-logs", timeout=10)
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"ai_agent no disponible: {e}"}), 502


@app.route("/api/recalculate", methods=["POST"])
def recalculate_proxy():
    try:
        resp = requests.post(f"{AI_AGENT_URL}/recalculate", json=request.get_json(silent=True) or {}, timeout=10)
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"ai_agent no disponible: {e}"}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
