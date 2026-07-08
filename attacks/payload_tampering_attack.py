"""
THE BREAK - BAS3: Tampering en API Gateway (Nodo B, Manipulacion Tecnica)

A diferencia de BAS4 (SQLi en RDS), este vector ataca la CAPA DE ENTRADA: intenta
colar un payload manipulado directamente al endpoint /apply para forzar montos
invalidos, campos extra no esperados, o tipos incorrectos -- sin pasar por SQL en
absoluto. Representa la falla de "Tampering del payload JSON (monto/cuenta destino)"
descrita en tu Tabla 1 (control V13 ASVS: validacion de esquema estricta).

Uso:
    python payload_tampering_attack.py --target http://localhost:8080
"""
import argparse
import json
import time
import requests

PAYLOADS = [
    {"name": "monto_negativo", "body": {"dni": "45678912", "nombre": "Ana Quispe", "monto": -500}},
    {"name": "monto_gigante", "body": {"dni": "45678912", "nombre": "Ana Quispe", "monto": 999999999}},
    {"name": "campo_extra_privilegio", "body": {"dni": "45678912", "nombre": "Ana Quispe", "monto": 500, "estado": "APROBADO_VIP", "is_admin": True}},
    {"name": "tipo_incorrecto_monto_string", "body": {"dni": "45678912", "nombre": "Ana Quispe", "monto": "1000 OR 1=1"}},
]


def run(target):
    results = []
    for p in PAYLOADS:
        try:
            resp = requests.post(f"{target}/apply", json=p["body"], timeout=5)
            accepted = resp.status_code in (200, 201)
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        except Exception as e:
            accepted = False
            body = {"error": str(e)}

        results.append({
            "payload": p["name"],
            "body": p["body"],
            "http_status": getattr(resp, "status_code", None) if 'resp' in dir() else None,
            "accepted": accepted,
            "response": body,
        })
        print(f"[Tampering] {p['name']:32s} -> accepted={accepted}")

    accepted_count = sum(1 for r in results if r["accepted"])
    summary = {
        "attack": "payload_tampering",
        "timestamp": time.time(),
        "target": target,
        "total_payloads": len(PAYLOADS),
        "accepted_count": accepted_count,
        "rejected_count": len(PAYLOADS) - accepted_count,
        "blocked": accepted_count == 0,
        "payload_results": results,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--out", default="metrics/payload_tampering_result.json")
    args = parser.parse_args()

    result = run(args.target)
    try:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"(no se pudo escribir metrics: {e})")
