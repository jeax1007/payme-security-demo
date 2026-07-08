#!/usr/bin/env bash
# Orquesta el ciclo completo: Pre-Mitigacion (vulnerable) -> ataques -> apagar
#                             Post-Mitigacion (seguro)    -> ataques -> apagar
# y combina todo en metrics/results.json para el dashboard.
set -e

GATEWAY_URL="http://localhost:8080"
LOGSTORE_URL="http://localhost:5002"
mkdir -p metrics

run_phase () {
  PHASE=$1          # "pre" o "post"
  SECURE_MODE=$2     # "false" o "true"

  echo "=================================================="
  echo " Levantando arquitectura Payme (SECURE_MODE=$SECURE_MODE) [$PHASE]"
  echo "=================================================="
  export SECURE_MODE=$SECURE_MODE
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose up --build -d
  echo "Esperando que los servicios levanten..."
  sleep 12

  echo "--- The Break: Payload Tampering en Gateway (Nodo B, BAS3) ---"
  python3 attacks/payload_tampering_attack.py --target "$GATEWAY_URL" --out "metrics/${PHASE}_payload_tampering.json" || true

  echo "--- The Break: SQLi (Nodo B, BAS4) ---"
  python3 attacks/sqli_attack.py --target "$GATEWAY_URL" --out "metrics/${PHASE}_sqli.json" || true

  echo "--- The Break: DDoS (Nodo C, BAS5) ---"
  python3 attacks/ddos_attack.py --target "$GATEWAY_URL" --threads 40 --duration 8 --out "metrics/${PHASE}_ddos.json" || true

  echo "--- The Break: Log Tampering (Nodo C, BAS6) ---"
  python3 attacks/log_tamper_attack.py --target "$LOGSTORE_URL" --out "metrics/${PHASE}_log_tamper.json" || true

  echo "Apagando arquitectura..."
  docker compose down -v --remove-orphans
}

run_phase "pre" "false"
run_phase "post" "true"

echo "=================================================="
echo " Consolidando resultados en metrics/results.json"
echo "=================================================="
python3 ai_agent/consolidate_results.py

echo "Listo. Levanta el dashboard con: docker compose up dashboard -d --build"
echo "y visitalo en http://localhost:8090"
