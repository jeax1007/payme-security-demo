"""
D2: AUDIT LOGS STORE (VPC Privada)

SECURE_MODE=false (vulnerable):
  - Logs en texto plano, append simple
  - Expone DELETE /log para borrar TODO el historial (simula mala configuracion / credenciales de admin
    comprometidas) -> reproduce BAS6 (Manipulacion de Logs de Auditoria)

SECURE_MODE=true (seguro):
  - Hash-chaining (cada entrada referencia el hash de la anterior, estilo blockchain simplificado)
  - DELETE /log deshabilitado (410 Gone)
  - GET /verify recorre la cadena y detecta cualquier alteracion -> representa
    inmutabilidad / WORM storage (NIST SP 800-204C, V7 ASVS)
"""
import os
import json
import time
import hashlib
import threading
from flask import Flask, request, jsonify

app = Flask(__name__)
SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"
DATA_FILE = "/app/data/audit_log.jsonl"

os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

# NIST SP 800-204C exige garantizar la integridad del log de auditoria incluso bajo
# concurrencia. Sin este lock, dos peticiones simultaneas podrian leer el mismo
# "ultimo hash" antes de que la otra termine de escribir, rompiendo la cadena.
_chain_lock = threading.Lock()


def _read_entries():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r") as f:
        return [json.loads(line) for line in f if line.strip()]


def _write_entry(entry):
    with open(DATA_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _hash_entry(prev_hash, content):
    payload = prev_hash + json.dumps(content, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "secure_mode": SECURE_MODE}), 200


@app.route("/log", methods=["POST"])
def add_log():
    content = request.get_json(silent=True) or {}
    content["received_at"] = time.time()

    with _chain_lock:
        if SECURE_MODE:
            entries = _read_entries()
            prev_hash = entries[-1]["hash"] if entries else "GENESIS"
            entry_hash = _hash_entry(prev_hash, content)
            entry = {"content": content, "prev_hash": prev_hash, "hash": entry_hash}
        else:
            entry = {"content": content}

        _write_entry(entry)

    return jsonify({"status": "logged"}), 201


@app.route("/log", methods=["GET"])
def list_logs():
    return jsonify({"entries": _read_entries(), "count": len(_read_entries())}), 200


@app.route("/log", methods=["DELETE"])
def delete_logs():
    """Endpoint deliberadamente peligroso en modo vulnerable (BAS6)."""
    if SECURE_MODE:
        return jsonify({"error": "operacion no permitida: almacen inmutable (WORM)"}), 410

    if os.path.exists(DATA_FILE):
        os.remove(DATA_FILE)
    return jsonify({"status": "logs borrados"}), 200


@app.route("/verify", methods=["GET"])
def verify_chain():
    """Solo tiene sentido pleno en modo seguro, pero se puede llamar en ambos modos."""
    entries = _read_entries()
    if not SECURE_MODE:
        return jsonify({"secure_mode": False, "chain_valid": None,
                         "detail": "modo vulnerable no mantiene cadena de hashes"}), 200

    prev_hash = "GENESIS"
    for i, e in enumerate(entries):
        expected_hash = _hash_entry(prev_hash, e["content"])
        if e.get("prev_hash") != prev_hash or e.get("hash") != expected_hash:
            return jsonify({"secure_mode": True, "chain_valid": False,
                             "broken_at_index": i}), 200
        prev_hash = e["hash"]

    return jsonify({"secure_mode": True, "chain_valid": True, "entries_checked": len(entries)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
