"""
Microservicio del "Red Teamer Virtual" - Uso Avanzado de IA (TC2, Anexo 4).

Esto NO es un script que se corre aparte y se olvida: es un servicio que vive
DENTRO de la arquitectura Payme (ver docker-compose.yml), disponible en todo
momento para el dashboard, que puede:

  1. Proponer hipotesis de abuso nuevas EN VIVO (POST /red-team)
  2. Analizar el audit log en busca de anomalias (GET /analyze-logs)
  3. FORZAR EL RECALCULO del arbol de ataque incorporando una hipotesis nueva
     como una rama OR adicional en la raiz (POST /recalculate)

El recalculo en (3) es la pieza clave: toma el P(R_T) ya validado empiricamente
(metrics/results.json, generado por consolidate_results.py) y le agrega la nueva
hipotesis propuesta por la IA como una rama mas del semianillo OR de la raiz:

    P(R_T_con_hipotesis) = 1 - (1 - P(R_T_actual)) * (1 - P(hipotesis))

Esto es matematicamente consistente con la Seccion 4 del informe: la raiz es
una compuerta OR de N ramas, y agregar una rama nueva sigue la misma formula
de union de eventos independientes.
"""
import os
import json
from flask import Flask, jsonify, request
import agent_logic

app = Flask(__name__)
METRICS_DIR = "/app/metrics"
RESULTS_PATH = os.path.join(METRICS_DIR, "results.json")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "llm_configured": bool(agent_logic.ANTHROPIC_API_KEY)
    }), 200


@app.route("/red-team", methods=["POST"])
def red_team():
    """Genera hipotesis de abuso EN VIVO (LLM si hay API key, heuristica si no)."""
    result = agent_logic.red_team_new_abuse_cases()
    return jsonify(result), 200


@app.route("/analyze-logs", methods=["GET"])
def analyze_logs():
    """Analiza el audit log store (D2) en busca de patrones sospechosos."""
    result = agent_logic.analyze_logs_for_anomalies()
    return jsonify(result), 200


@app.route("/recalculate", methods=["POST"])
def recalculate():
    """
    Incorpora una hipotesis de abuso (propuesta por el Red Teamer) al arbol de
    ataque como una rama OR adicional en la raiz, y devuelve el P(R_T) recalculado.

    Body esperado: {"name": str, "p_estimate": float, "c_estimate_usd": float}
    """
    body = request.get_json(silent=True) or {}
    p_hipotesis = float(body.get("p_estimate", 0))
    c_hipotesis = float(body.get("c_estimate_usd", 0))
    nombre = body.get("name", "Hipotesis sin nombre")

    if not os.path.exists(RESULTS_PATH):
        return jsonify({
            "error": "no existe metrics/results.json todavia. Corre primero "
                     "ai_agent/consolidate_results.py con los resultados de los ataques."
        }), 404

    with open(RESULTS_PATH, "r") as f:
        baseline = json.load(f)

    p_rt_actual = baseline["raiz_compromiso_total"]["p_rt_post"]
    p_rt_con_hipotesis = 1 - (1 - p_rt_actual) * (1 - p_hipotesis)

    ale_base = baseline["impacto_financiero_ale"]["base_usd_ibm_2025"]
    ale_con_hipotesis = round(p_rt_con_hipotesis * ale_base, 0)

    return jsonify({
        "hipotesis": {
            "nombre": nombre,
            "p_estimate": p_hipotesis,
            "c_estimate_usd": c_hipotesis
        },
        "p_rt_antes_de_hipotesis": round(p_rt_actual, 4),
        "p_rt_con_hipotesis": round(p_rt_con_hipotesis, 4),
        "incremento_absoluto_pp": round((p_rt_con_hipotesis - p_rt_actual) * 100, 2),
        "ale_con_hipotesis_usd": ale_con_hipotesis,
        "formula": "P(R_T_nuevo) = 1 - (1 - P(R_T_actual)) * (1 - P(hipotesis))",
        "recomendacion": (
            "Esta hipotesis aumenta el riesgo de forma significativa; "
            "considerar priorizarla en el siguiente ciclo de mitigacion."
            if (p_rt_con_hipotesis - p_rt_actual) > 0.02 else
            "El impacto marginal de esta hipotesis es bajo dado el estado actual del sistema."
        )
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
