"""
1.2 CORE PAYMENT MICROSERVICE (VPC Privada)

Implementa el toggle SECURE_MODE:
  - false (vulnerable): consulta SQL por concatenacion de strings -> BAS4 (Inyeccion SQL en RDS)
                         no valida el origen del payload que llega del gateway (sin mTLS este-oeste)
  - true  (seguro):     consultas parametrizadas + verificacion HMAC de integridad este-oeste
                         (representa SP 800-204A - autenticacion mutua en el service mesh)
"""
import os
import time
import hmac
import hashlib
import psycopg2
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "creditdb")
DB_USER = os.environ.get("DB_USER", "payme_admin")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "payme_pass_2026")
LOGSTORE_URL = os.environ.get("LOGSTORE_URL", "http://logstore:5000")
IDENTITY_URL = os.environ.get("IDENTITY_URL", "http://identity:5000")
HMAC_SECRET = os.environ.get("HMAC_SHARED_SECRET", "changeme").encode()


def get_conn():
    return psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)


def log_event(event_type, detail, severity="INFO"):
    try:
        requests.post(f"{LOGSTORE_URL}/log", json={
            "ts": time.time(),
            "type": event_type,
            "detail": detail,
            "severity": severity
        }, timeout=2)
    except Exception:
        pass  # no tumbar el flujo transaccional si el log store esta caido


def verify_east_west_integrity(raw_body: bytes, signature: str) -> bool:
    """Representa mTLS/autenticacion mutua este-oeste (SP 800-204A) de forma simplificada
    mediante HMAC compartido entre gateway y core."""
    expected = hmac.new(HMAC_SECRET, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "secure_mode": SECURE_MODE}), 200


@app.route("/credit/<raw_id>", methods=["GET"])
def get_credit(raw_id):
    """
    Endpoint deliberadamente vulnerable a Inyeccion SQL (BAS4) cuando SECURE_MODE=false.
    Ejemplo de explotacion: /credit/1 OR 1=1
    Ejemplo de tampering:   /credit/1; UPDATE credits SET monto=999999 WHERE id=1--
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        if SECURE_MODE:
            # V5 ASVS: Validation, Sanitization and Encoding -> consulta parametrizada
            try:
                credit_id = int(raw_id)
            except ValueError:
                log_event("SQLI_ATTEMPT_BLOCKED", f"input no numerico rechazado: {raw_id}", "WARNING")
                return jsonify({"error": "id invalido"}), 400
            cur.execute("SELECT id, dni, nombre, monto, estado FROM credits WHERE id = %s", (credit_id,))
        else:
            # VULNERABLE: concatenacion directa de strings (igual al ejemplo del Anexo 1)
            query = "SELECT id, dni, nombre, monto, estado FROM credits WHERE id = " + raw_id
            cur.execute(query)

        rows = cur.fetchall()
        conn.commit()
        result = [
            {"id": r[0], "dni": r[1], "nombre": r[2], "monto": float(r[3]), "estado": r[4]}
            for r in rows
        ]
        return jsonify({"results": result, "count": len(result)}), 200
    except Exception as e:
        conn.rollback()
        log_event("SQLI_ERROR", f"input={raw_id} error={str(e)}", "ERROR")
        return jsonify({"error": "error de consulta", "detail": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/apply", methods=["POST"])
def apply_credit():
    """Flujo normal de negocio: solicitud de credito. Valida integridad este-oeste si SECURE_MODE=true."""
    raw_body = request.get_data()
    signature = request.headers.get("X-Mesh-Signature")

    if SECURE_MODE:
        if not verify_east_west_integrity(raw_body, signature):
            log_event("MESH_INTEGRITY_VIOLATION", "firma HMAC invalida entre gateway y core", "CRITICAL")
            return jsonify({"error": "integridad este-oeste invalida"}), 403

    data = request.get_json(silent=True) or {}
    dni = str(data.get("dni", ""))
    monto = data.get("monto", 0)

    # Verificacion de identidad contra el mock de RENIEC (1.3)
    try:
        idv = requests.post(f"{IDENTITY_URL}/verify", json={"dni": dni}, timeout=3).json()
    except Exception:
        idv = {"valid": False}

    if not idv.get("valid"):
        log_event("IDENTITY_REJECTED", f"dni={dni}", "WARNING")
        return jsonify({"error": "identidad no verificada"}), 401

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO credits (dni, nombre, monto, estado) VALUES (%s, %s, %s, %s) RETURNING id",
        (dni, data.get("nombre", "N/A"), monto, "APROBADO")
    )
    new_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    log_event("CREDIT_APPLIED", f"dni={dni} monto={monto} id={new_id}", "INFO")
    return jsonify({"id": new_id, "estado": "APROBADO"}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
