"""
1.3 SERVICIO DE VERIFICACION DE IDENTIDAD (VPC Privada) - Mock de RENIEC

No es el foco de esta demo (ese es el Nodo A, con probabilidad baja segun tu modelo, 2.36%),
pero se incluye para que el flujo de punta a punta sea real y completo.
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"

# DNIs "validos" simulados para la demo
VALID_DNIS = {"45678912", "11223344", "99887766", "12345678"}


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "secure_mode": SECURE_MODE}), 200


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    dni = str(data.get("dni", ""))
    valid = dni in VALID_DNIS and len(dni) == 8 and dni.isdigit()
    return jsonify({"dni": dni, "valid": valid}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
