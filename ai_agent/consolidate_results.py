"""
Consolida los resultados de los ataques en una recalculacion FIEL del Arbol de Ataque
Probabilistico (QAT) de la Seccion 4 del informe -- no un "risk score" inventado.

Principio: el 70.1% de P(R_T) del informe es un valor FIJO, calculado a partir de
telemetria CTI real (Verizon, Salt Security, Edgescan, Cloudflare, IBM, Sharma & Selwal).
No se "mide" corriendo un script una vez; es el punto de partida (baseline).

Lo que SI podemos medir empiricamente con este PoC es la EFECTIVIDAD de los controles
que implementamos para el Nodo B (Manipulacion Tecnica) y el Nodo C (Disrupcion y
Ocultamiento) -- porque son los dos nodos que esta demo tecnica realmente ataca y
repara. El Nodo A (Suplantacion / biometria) y el Nodo D (Fuga de informacion /
cifrado en reposo) NO se implementaron en este PoC (quedan como trabajo futuro), asi
que se mantienen en su valor original del informe.

Con la efectividad medida, recalculamos P(s) post-mitigacion de cada BAS, y propagamos
el resultado por el arbol con las MISMAS formulas AND/OR de tu Seccion 4:

    OR:  P(v) = 1 - PRODUCT(1 - P(vi))
    AND: P(v) = PRODUCT(P(vi))

IMPORTANTE: la efectividad empirica se limita (cap) a un maximo de 95%. Ningun control
de seguridad real elimina el riesgo al 100% -- siempre queda un riesgo residual
(zero-days, fallos de configuracion futuros, vectores no probados). Reportar un 0%
post-mitigacion no seria defendible ante un profesor ni ante una auditoria real.
"""
import json
import os

METRICS_DIR = os.path.join(os.path.dirname(__file__), "..", "metrics")

# Cap conservador: ni el mejor control demuestra "riesgo cero" con una muestra pequena
# de pruebas (unos pocos payloads / una corrida de ataque). Ver README seccion 7.
MAX_EFFECTIVENESS = 0.95

# --- Valores FIJOS del informe (Seccion 4 / Tabla 2) ---------------------------------
# Estos NO se recalculan: son la base matematica ya validada con CTI real.
P_S1_PHISHING = 0.027          # BAS1 - Nodo A (fuera de alcance del PoC)
P_S2_SPOOF_BIOMETRICO = 0.70   # BAS2 - Nodo A (fuera de alcance del PoC)
P_S3_TAMPERING_GATEWAY = 0.27  # BAS3 - Nodo B (SI se ataca/repara en este PoC)
P_S4_SQLI_RDS = 0.19           # BAS4 - Nodo B (SI se ataca/repara en este PoC)
P_S5_DDOS_NAT = 0.31           # BAS5 - Nodo C (SI se ataca/repara en este PoC)
P_S6_LOG_TAMPERING = 0.08      # BAS6 - Nodo C (SI se ataca/repara en este PoC)
P_S7_EXFIL_RDS = 0.15          # BAS7 - Nodo D (fuera de alcance del PoC)
P_S8_SNIFFING = 0.04           # BAS8 - Nodo D (fuera de alcance del PoC)

C_A1, C_A2 = 50, 600      # costos Nodo A (USD)
C_A3, C_A4 = 499, 850     # costos Nodo B (USD)
C_A5, C_A6 = 120, 300     # costos Nodo C (USD)
C_A7, C_A8 = 700, 150     # costos Nodo D (USD)

ALE_BASE_USD = 5_560_000  # IBM Cost of a Data Breach Report 2025, promedio sector financiero


def _load(path):
    full = os.path.join(METRICS_DIR, path)
    if not os.path.exists(full):
        return None
    with open(full, "r") as f:
        return json.load(f)


def _or2(p1, p2):
    return p1 + p2 - (p1 * p2)


def _cap(effectiveness):
    return max(0.0, min(MAX_EFFECTIVENESS, effectiveness))


# --- Estimacion de "efectividad del control" a partir de la evidencia empirica -------

def effectiveness_payload_tampering(result):
    """BAS3: fraccion de payloads maliciosos que el gateway rechazo."""
    if not result:
        return 0.0, "sin datos (script no corrido)"
    total = result.get("total_payloads", 0)
    rejected = result.get("rejected_count", 0)
    if total == 0:
        return 0.0, "sin payloads probados"
    raw = rejected / total
    return _cap(raw), f"{rejected}/{total} payloads maliciosos rechazados"


def effectiveness_sqli(result):
    """BAS4: fraccion de payloads SQLi que fallaron Y no lograron tampering persistente."""
    if not result:
        return 0.0, "sin datos (script no corrido)"
    payloads = result.get("payload_results", [])
    total = len(payloads)
    if total == 0:
        return 0.0, "sin payloads probados"
    exitosos = sum(1 for p in payloads if p.get("success"))
    tampering_ok = result.get("tampering_success", False)
    # si el tampering persistio en la BD, el control NO fue efectivo sin importar
    # cuantos payloads hayan fallado por error de sintaxis.
    if tampering_ok:
        return 0.0, "el monto SI fue alterado en la base de datos"
    raw = 1 - (exitosos / total)
    return _cap(raw), f"{total - exitosos}/{total} payloads SQLi bloqueados, sin tampering persistente"


def effectiveness_ddos(result):
    """BAS5: ratio de requests bloqueados por rate limiting."""
    if not result:
        return 0.0, "sin datos (script no corrido)"
    ratio = result.get("blocked_ratio")
    if ratio is None:
        return 0.0, "sin dato de blocked_ratio"
    return _cap(ratio), f"{round(ratio*100,1)}% de requests bloqueados por rate limiting"


def effectiveness_log_tamper(result):
    """BAS6: bloqueo del DELETE + integridad de la cadena de hashes."""
    if not result:
        return 0.0, "sin datos (script no corrido)"
    delete_blocked = result.get("delete_blocked", False)
    chain = result.get("chain_verification", {}) or {}
    chain_valid = chain.get("chain_valid")
    if delete_blocked and chain_valid is True:
        return _cap(MAX_EFFECTIVENESS), "borrado bloqueado (410) + cadena de hashes integra"
    if delete_blocked and chain_valid is None:
        return _cap(0.6), "borrado bloqueado, pero sin verificacion de cadena disponible"
    if delete_blocked and chain_valid is False:
        return _cap(0.3), "borrado bloqueado, pero se detecto una cadena de hashes rota (revisar concurrencia)"
    return 0.0, "el borrado de logs NO fue bloqueado"


def build():
    payload_pre = _load("pre_payload_tampering.json")
    payload_post = _load("post_payload_tampering.json")
    sqli_pre = _load("pre_sqli.json")
    sqli_post = _load("post_sqli.json")
    ddos_pre = _load("pre_ddos.json")
    ddos_post = _load("post_ddos.json")
    log_pre = _load("pre_log_tamper.json")
    log_post = _load("post_log_tamper.json")

    eff_s3, note_s3 = effectiveness_payload_tampering(payload_post)
    eff_s4, note_s4 = effectiveness_sqli(sqli_post)
    eff_s5, note_s5 = effectiveness_ddos(ddos_post)
    eff_s6, note_s6 = effectiveness_log_tamper(log_post)

    # P(s) post-mitigacion de cada BAS = P(s) original * (1 - efectividad medida)
    p_s3_post = P_S3_TAMPERING_GATEWAY * (1 - eff_s3)
    p_s4_post = P_S4_SQLI_RDS * (1 - eff_s4)
    p_s5_post = P_S5_DDOS_NAT * (1 - eff_s5)
    p_s6_post = P_S6_LOG_TAMPERING * (1 - eff_s6)

    # --- Nodo A (AND, fuera de alcance -> se mantiene igual al informe) -------------
    p_s2_given_s1 = P_S2_SPOOF_BIOMETRICO * 1.25
    p_nodo_a = P_S1_PHISHING * p_s2_given_s1
    c_nodo_a = C_A1 + C_A2

    # --- Nodo B (OR) -----------------------------------------------------------------
    p_nodo_b_pre = _or2(P_S3_TAMPERING_GATEWAY, P_S4_SQLI_RDS)
    p_nodo_b_post = _or2(p_s3_post, p_s4_post)
    c_nodo_b = min(C_A3, C_A4)

    # --- Nodo C (OR) -----------------------------------------------------------------
    p_nodo_c_pre = _or2(P_S5_DDOS_NAT, P_S6_LOG_TAMPERING)
    p_nodo_c_post = _or2(p_s5_post, p_s6_post)
    c_nodo_c = min(C_A5, C_A6)

    # --- Nodo D (OR, fuera de alcance -> se mantiene igual al informe) --------------
    p_nodo_d = _or2(P_S7_EXFIL_RDS, P_S8_SNIFFING)
    c_nodo_d = min(C_A7, C_A8)

    # --- Raiz: OR de los 4 nodos -------------------------------------------------------
    def raiz(pa, pb, pc, pd):
        return 1 - (1 - pa) * (1 - pb) * (1 - pc) * (1 - pd)

    p_rt_pre = raiz(p_nodo_a, p_nodo_b_pre, p_nodo_c_pre, p_nodo_d)
    p_rt_post = raiz(p_nodo_a, p_nodo_b_post, p_nodo_c_post, p_nodo_d)

    result = {
        "metodologia": (
            "Recalculo fiel del QAT (Seccion 4 del informe) usando las mismas formulas "
            "AND/OR. Nodo A y Nodo D quedan FIJOS (fuera del alcance tecnico de este PoC: "
            "biometria anti-spoofing y cifrado en reposo no fueron implementados). Nodo B "
            "y Nodo C se recalculan usando la efectividad empirica medida en los ataques, "
            "con un tope maximo de 95% de efectividad (ningun control elimina el riesgo al "
            "100%, y la muestra de pruebas de este PoC es pequena)."
        ),
        "arbol": {
            "nodo_A_suplantacion": {
                "probabilidad": round(p_nodo_a, 4),
                "costo_usd": c_nodo_a,
                "estado": "fuera de alcance del PoC (biometria no implementada)",
                "fuente": "valor fijo del informe, Seccion 4"
            },
            "nodo_B_manipulacion_tecnica": {
                "probabilidad_pre": round(p_nodo_b_pre, 4),
                "probabilidad_post": round(p_nodo_b_post, 4),
                "costo_usd": c_nodo_b,
                "bas3_tampering_gateway": {
                    "p_pre": P_S3_TAMPERING_GATEWAY, "p_post": round(p_s3_post, 5),
                    "efectividad_medida": round(eff_s3, 3), "evidencia": note_s3
                },
                "bas4_sqli_rds": {
                    "p_pre": P_S4_SQLI_RDS, "p_post": round(p_s4_post, 5),
                    "efectividad_medida": round(eff_s4, 3), "evidencia": note_s4
                }
            },
            "nodo_C_disrupcion_ocultamiento": {
                "probabilidad_pre": round(p_nodo_c_pre, 4),
                "probabilidad_post": round(p_nodo_c_post, 4),
                "costo_usd": c_nodo_c,
                "bas5_ddos_nat": {
                    "p_pre": P_S5_DDOS_NAT, "p_post": round(p_s5_post, 5),
                    "efectividad_medida": round(eff_s5, 3), "evidencia": note_s5
                },
                "bas6_log_tampering": {
                    "p_pre": P_S6_LOG_TAMPERING, "p_post": round(p_s6_post, 5),
                    "efectividad_medida": round(eff_s6, 3), "evidencia": note_s6
                }
            },
            "nodo_D_fuga_informacion": {
                "probabilidad": round(p_nodo_d, 4),
                "costo_usd": c_nodo_d,
                "estado": "fuera de alcance del PoC (cifrado en reposo no implementado)",
                "fuente": "valor fijo del informe, Seccion 4"
            }
        },
        "raiz_compromiso_total": {
            "p_rt_pre": round(p_rt_pre, 4),
            "p_rt_post": round(p_rt_post, 4),
            "reduccion_absoluta_pp": round((p_rt_pre - p_rt_post) * 100, 2),
            "reduccion_relativa_pct": round((1 - p_rt_post / p_rt_pre) * 100, 1) if p_rt_pre else 0
        },
        "impacto_financiero_ale": {
            "base_usd_ibm_2025": ALE_BASE_USD,
            "ale_pre_usd": round(p_rt_pre * ALE_BASE_USD, 0),
            "ale_post_usd": round(p_rt_post * ALE_BASE_USD, 0),
            "nota": "ALE = P(R_T) x Impacto base (IBM Cost of a Data Breach 2025, sector "
                    "financiero). No incluye multas de la Ley N.29733, que se suman como "
                    "riesgo regulatorio adicional no cuantificado aqui."
        }
    }

    out_path = os.path.join(METRICS_DIR, "results.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Escrito {out_path}")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return result


if __name__ == "__main__":
    build()
