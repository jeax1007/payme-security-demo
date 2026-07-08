"""
Uso Avanzado de IA (requisito TC2) + "Red Teamer Virtual" (Anexo 4, seccion Uso de IA).

A diferencia de un simple script que se corre una vez y se olvida, este modulo esta
pensado para vivir DENTRO de un servicio (ver app.py) que corre embebido en la
arquitectura Payme y que puede ser invocado en vivo desde el dashboard. Cada hipotesis
que propone el Red Teamer trae un P(s) y C(a) ESTIMADOS, para que el dashboard pueda
forzar un recalculo real de P(R_T) incorporando la nueva rama al arbol -- no solo
mostrar un texto sugerido que nadie usa matematicamente.

1. red_team_new_abuse_cases(): entrega la arquitectura (resumen del DFD + arbol de
   ataque) a un LLM y le pide proponer vectores de abuso NO contemplados en el modelo
   actual, acotado con una politica estricta de alcance.

2. analyze_logs_for_anomalies(): revisa las entradas del audit log (D2) buscando
   patrones sospechosos y da una mitigacion secundaria sugerida.

Si no hay ANTHROPIC_API_KEY configurada, ambas funciones caen a un modo heuristico
local para que la demo funcione sin conexion a internet.
"""
import os
import json
import re
import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
LOGSTORE_URL = os.environ.get("LOGSTORE_URL", "http://logstore:5000")

SYSTEM_POLICY = (
    "Eres un Red Teamer Virtual acotado a un unico alcance: la arquitectura Fintech 'Payme' "
    "descrita por el usuario. Reglas estrictas: "
    "1) Solo puedes proponer vectores de abuso a nivel arquitectonico/logico (ej. que componente, "
    "que frontera de confianza, que supuesto de diseno), NUNCA payloads de explotacion operativos, "
    "codigo de exploit, ni instrucciones paso a paso para atacar sistemas reales. "
    "2) No debes salirte del contexto STRIDE/OWASP/NIST de este ejercicio academico. "
    "3) Debes responder UNICAMENTE con un arreglo JSON valido, sin texto adicional, sin markdown, "
    "con este formato exacto para cada hipotesis: "
    '{"name": "...", "componente": "...", "gap": "...", "p_estimate": 0.0-1.0, "c_estimate_usd": numero}. '
    "p_estimate es tu mejor estimacion conservadora de la probabilidad de exito de ese vector "
    "(similar en naturaleza a los P(s) del arbol de ataque existente, basado en la severidad y "
    "plausibilidad del vector). c_estimate_usd es el costo aproximado en USD para el atacante."
)

ARCHITECTURE_SUMMARY = """
Arquitectura Payme (resumen):
- 1.1 API Gateway (subnet publica): terminacion TLS, rate limiting, validacion de esquema.
- 1.2 Core Payment Microservice (VPC privada): logica de negocio, consulta a RDS.
- 1.3 Servicio de Verificacion de Identidad (VPC privada, egreso controlado): integra con RENIEC.
- NAT Gateway: unico punto de salida a internet.
- D1 Amazon RDS: base de datos de creditos.
- D2 Audit Logs Store: logs de auditoria con hash-chaining.
Arbol de ataque actual: Nodo A (Suplantacion, AND, P=2.36%), Nodo B (Manipulacion Tecnica,
OR: tampering API Gateway + SQLi, P post-mitigacion ~2.3%), Nodo C (Disrupcion, OR: DDoS +
tampering de logs, P post-mitigacion ~1.9%), Nodo D (Fuga de informacion, OR: exfiltracion
RDS + sniffing, P=18.4%, fuera de alcance del PoC).
"""


def _extract_json_array(text):
    """El LLM a veces envuelve el JSON en markdown pese a la instruccion; se extrae con regex."""
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        return json.loads(match.group(0))
    return json.loads(text)


def red_team_new_abuse_cases():
    if not ANTHROPIC_API_KEY:
        return _fallback_abuse_cases()

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=800,
            system=SYSTEM_POLICY,
            messages=[{
                "role": "user",
                "content": (
                    ARCHITECTURE_SUMMARY +
                    "\n\nPropone 3 hipotesis de vectores de abuso NO cubiertos aun por el arbol de "
                    "ataque actual, a nivel arquitectonico. Responde solo con el arreglo JSON."
                )
            }]
        )
        text = "".join(b.text for b in msg.content if hasattr(b, "text"))
        cases = _extract_json_array(text)
        return {"source": "anthropic_llm", "abuse_cases": cases}
    except Exception as e:
        fallback = _fallback_abuse_cases()
        fallback["llm_error"] = str(e)
        return fallback


def _fallback_abuse_cases():
    """Heuristica local (sin LLM) - hipotesis genericas basadas en gaps tipicos de arboles STRIDE,
    con P(s) y C(a) estimados conservadoramente para permitir el recalculo matematico."""
    return {
        "source": "heuristic_fallback",
        "abuse_cases": [
            {
                "name": "Session Fixation en reintentos de /apply",
                "componente": "1.1 API Gateway",
                "gap": "El arbol actual no modela reutilizacion de tokens de sesion entre reintentos "
                       "fallidos de aplicacion de credito.",
                "p_estimate": 0.12,
                "c_estimate_usd": 200
            },
            {
                "name": "Race condition en aprobacion concurrente de credito",
                "componente": "1.2 Core Payment Microservice",
                "gap": "El modelo asume operaciones secuenciales; no contempla doble aprobacion "
                       "por solicitudes concurrentes al mismo DNI.",
                "p_estimate": 0.18,
                "c_estimate_usd": 350
            },
            {
                "name": "Abuso del mock/fallback de identidad ante timeout de RENIEC",
                "componente": "1.3 Servicio de Verificacion de Identidad",
                "gap": "No se modela el comportamiento del sistema si el servicio de RENIEC no "
                       "responde a tiempo (fail-open vs fail-closed).",
                "p_estimate": 0.09,
                "c_estimate_usd": 500
            }
        ]
    }


def analyze_logs_for_anomalies():
    try:
        logs = requests.get(f"{LOGSTORE_URL}/log", timeout=5).json().get("entries", [])
    except Exception as e:
        return {"error": f"no se pudo leer logstore: {e}"}

    counts = {}
    flagged = []
    for e in logs:
        content = e.get("content", e)
        etype = content.get("type", "UNKNOWN")
        counts[etype] = counts.get(etype, 0) + 1
        if etype in ("SQLI_ATTEMPT_BLOCKED", "SQLI_ERROR", "MESH_INTEGRITY_VIOLATION", "IDENTITY_REJECTED"):
            flagged.append(content)

    suspicious = counts.get("SQLI_ATTEMPT_BLOCKED", 0) + counts.get("SQLI_ERROR", 0) >= 2 \
        or counts.get("MESH_INTEGRITY_VIOLATION", 0) >= 1

    return {
        "event_counts": counts,
        "flagged_events": flagged[:20],
        "suspicious_pattern_detected": suspicious,
        "suggested_secondary_mitigation": (
            "Bloquear temporalmente la IP de origen y forzar reverificacion de identidad"
            if suspicious else "Sin accion adicional requerida"
        )
    }


if __name__ == "__main__":
    print("=== Red Teamer Virtual: nuevas hipotesis de abuso ===")
    print(json.dumps(red_team_new_abuse_cases(), indent=2, ensure_ascii=False))
    print("\n=== Analisis de logs de auditoria ===")
    print(json.dumps(analyze_logs_for_anomalies(), indent=2, ensure_ascii=False))
