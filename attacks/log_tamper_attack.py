"""
THE BREAK - BAS6: Manipulacion de Logs de Auditoria D2 (Nodo C, Disrupcion y Ocultamiento)

Intenta:
  1. Borrar todo el historial de logs via DELETE /log (simula credenciales de admin
     comprometidas / mala configuracion de permisos)
  2. Verificar si la cadena de hashes (modo seguro) detecta cualquier alteracion

Uso:
    python log_tamper_attack.py --target http://localhost:5002
"""
import argparse
import json
import time
import requests


def run(target):
    # Paso 1: sembrar un par de entradas de auditoria "legitimas"
    for i in range(3):
        requests.post(f"{target}/log", json={"type": "TEST_EVENT", "detail": f"evento_{i}"}, timeout=3)

    before = requests.get(f"{target}/log", timeout=3).json()
    count_before = before.get("count", 0)

    # Paso 2: intentar borrar todo el historial
    try:
        del_resp = requests.delete(f"{target}/log", timeout=3)
        delete_blocked = del_resp.status_code == 410
        delete_status = del_resp.status_code
    except Exception as e:
        delete_blocked = False
        delete_status = str(e)

    after = requests.get(f"{target}/log", timeout=3).json()
    count_after = after.get("count", 0)

    # Paso 3: verificar integridad de la cadena de hashes (si aplica)
    verify = requests.get(f"{target}/verify", timeout=3).json()

    summary = {
        "attack": "log_tampering",
        "timestamp": time.time(),
        "target": target,
        "count_before_delete": count_before,
        "count_after_delete": count_after,
        "delete_http_status": delete_status,
        "delete_blocked": delete_blocked,
        "chain_verification": verify,
        # el ataque "tuvo exito" si logro reducir/borrar el historial
        "tampering_success": count_after < count_before,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:5002")
    parser.add_argument("--out", default="metrics/log_tamper_result.json")
    args = parser.parse_args()

    result = run(args.target)
    try:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"(no se pudo escribir metrics: {e})")
