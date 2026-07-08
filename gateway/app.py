"""
1.1 API GATEWAY MICROSERVICE (Subnet Publica)

SECURE_MODE=false (vulnerable):
  - Sin rate limiting -> vulnerable a BAS5 (DDoS en el borde)
  - Sin validacion de esquema -> vulnerable a BAS3 (Tampering del payload JSON, ej. monto negativo o gigante)
  - Reenvia el payload al core sin firma de integridad

SECURE_MODE=true (seguro):
  - Rate limiting (V13 ASVS / SP 800-204)
  - jsonschema estricto sobre el payload (V13 ASVS)
  - Firma HMAC del payload como integridad este-oeste simplificada (SP 800-204A)
"""
import os
import time
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from jsonschema import validate, ValidationError

app = Flask(__name__)

SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"
CORE_URL = os.environ.get("CORE_URL", "http://core:5000")
HMAC_SECRET = os.environ.get("HMAC_SHARED_SECRET", "changeme").encode()

# Rate limiting: solo aplica limite estricto en modo seguro.
# En modo vulnerable dejamos un limite artificialmente alto para simular "sin control real".
default_limit = "5 per second" if SECURE_MODE else "100000 per second"
limiter = Limiter(get_remote_address, app=app, default_limits=[default_limit])

APPLY_SCHEMA = {
    "type": "object",
    "properties": {
        "dni": {"type": "string", "minLength": 8, "maxLength": 8, "pattern": "^[0-9]+$"},
        "nombre": {"type": "string", "minLength": 1, "maxLength": 150},
        "monto": {"type": "number", "minimum": 1, "maximum": 50000}
    },
    "required": ["dni", "nombre", "monto"],
    "additionalProperties": False
}


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "secure_mode": SECURE_MODE}), 200


@app.route("/apply", methods=["POST"])
def apply_credit():
    raw_body = request.get_data()
    data = request.get_json(silent=True) or {}

    if SECURE_MODE:
        try:
            validate(instance=data, schema=APPLY_SCHEMA)
        except ValidationError as e:
            return jsonify({"error": "payload invalido", "detail": e.message}), 400

        signature = hmac.new(HMAC_SECRET, raw_body, hashlib.sha256).hexdigest()
        headers = {"X-Mesh-Signature": signature, "Content-Type": "application/json"}
    else:
        headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(f"{CORE_URL}/apply", data=raw_body, headers=headers, timeout=5)
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": "core no disponible", "detail": str(e)}), 502


@app.route("/credit/<raw_id>", methods=["GET"])
def get_credit(raw_id):
    """Passthrough directo al core - reproduce el mismo endpoint vulnerable para pruebas SQLi de punta a punta."""
    try:
        resp = requests.get(f"{CORE_URL}/credit/{raw_id}", timeout=5)
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": "core no disponible", "detail": str(e)}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
