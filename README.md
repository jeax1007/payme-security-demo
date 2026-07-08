# PAYME — Demo Integral Completa (TC2, Caso 4: Modelado de Amenazas Cuantitativo)

Esta demo implementa, de punta a punta, la arquitectura descrita en el informe
("Modelado de Amenazas Cuantitativo para la Plataforma Fintech Payme"),
transformándola de un sistema vulnerable a uno resiliente, con métricas reales que
validan el Árbol de Ataque Probabilístico (QAT) calculado en el capítulo 4.

## 1. Requisitos previos

- Docker y Docker Compose v2 (`docker compose version`)
- Python 3.10+ en el host (para correr los scripts de ataque y el orquestador)
- (Opcional) una API key de Anthropic para el agente de IA con LLM real:
  `export ANTHROPIC_API_KEY=sk-ant-...`

Instala las dependencias de los scripts de ataque/orquestación en el host:

```bash
pip install -r attacks/requirements.txt
pip install -r ai_agent/requirements.txt
```

## 2. Levantar la arquitectura manualmente

```bash
# Modo VULNERABLE (para "The Break")
SECURE_MODE=false docker compose up --build -d

# Modo SEGURO (para "The Repair")
SECURE_MODE=true docker compose up --build -d
```

Servicios expuestos:

| Servicio   | URL                     | Rol en el DFD                          |
|------------|-------------------------|-----------------------------------------|
| gateway    | http://localhost:8080   | 1.1 API Gateway (subnet pública)        |
| core       | http://localhost:5001   | 1.2 Core Payment Microservice           |
| identity   | http://localhost:5003   | 1.3 Verificación de Identidad (RENIEC)  |
| db         | localhost:5432           | D1 Amazon RDS (Credit DB)               |
| logstore   | http://localhost:5002   | D2 Audit Logs Store                     |
| dashboard  | http://localhost:8090   | Validación Analítica y Telemetría       |

## 3. Correr la demo completa automáticamente (recomendado)

```bash
chmod +x run_full_demo.sh
./run_full_demo.sh
```

Esto:
1. Levanta la arquitectura en modo **vulnerable**.
2. Ejecuta los 4 ataques — **The Break**:
   - `payload_tampering_attack.py` → BAS3 (Tampering en API Gateway)
   - `sqli_attack.py` → BAS4 (Inyección SQL en RDS)
   - `ddos_attack.py` → BAS5 (DDoS en el borde)
   - `log_tamper_attack.py` → BAS6 (Manipulación de Logs D2)
3. Apaga y vuelve a levantar en modo **seguro**.
4. Repite los mismos 4 ataques contra la versión mitigada — **The Repair**.
5. Consolida todo en `metrics/results.json`.

### ⚠️ Metodología de la consolidación (importante para tu sustentación)

`ai_agent/consolidate_results.py` **no inventa un "risk score"** de conteo de aciertos.
Recalcula el Árbol de Ataque Probabilístico completo con las **mismas fórmulas AND/OR
de tu Sección 4**:

- **Nodo A** (Suplantación) y **Nodo D** (Fuga de Información) quedan **fijos**, igual
  al valor de tu informe — porque este PoC técnico no implementa biometría anti-spoofing
  ni cifrado en reposo (son trabajo futuro fuera de alcance).
- **Nodo B** (Manipulación Técnica) y **Nodo C** (Disrupción) sí se recalculan, usando
  la efectividad *empírica* medida en los ataques (ej. `blocked_ratio` del DDoS, si el
  tampering SQL persistió o no, si el borrado de logs fue bloqueado).
- La efectividad medida tiene un **tope máximo de 95%** — ningún control de seguridad
  real elimina el riesgo al 100%, y la muestra de pruebas de este PoC es pequeña. Por
  eso el resultado post-mitigación **nunca debe salir en 0%**; si ves eso, algo está mal.
- El resultado esperado: `P(R_T)` baja de **70.1%** (tu baseline) a algo entre **20-30%**
  aproximadamente, no a cero. Eso es matemáticamente defendible; un 0% no lo es.

Luego levanta el dashboard:

```bash
docker compose up dashboard --build -d
```

Y ábrelo en **http://localhost:8090**.

## 4. Agente de IA embebido — Red Teamer Virtual (en vivo, no un script aparte)

A diferencia de un script que corres una vez y se olvida, el Red Teamer Virtual ahora
es **un microservicio más** dentro de `docker-compose.yml` (`ai_agent`, puerto 5004),
que corre todo el tiempo junto al resto de la arquitectura.

### Cómo usarlo (todo desde el dashboard, sin tocar la terminal)

1. Levanta la arquitectura normalmente (`docker compose up --build -d`).
2. Abre el dashboard en `http://localhost:8090`.
3. Baja hasta la sección **"Uso Avanzado de IA — Red Teamer Virtual"**.
4. Botón **"🔴 Generar hipótesis de ataque (IA)"** → llama en vivo al agente, que
   propone 3 vectores de abuso nuevos (no cubiertos por tu árbol actual), cada uno
   con un P(s) y C(a) estimado.
5. Botón **"⚡ Recalcular P(R_T) con esta hipótesis"** (uno por cada hipótesis) →
   **fuerza el recálculo matemático real** de `P(R_T)`, incorporando la hipótesis
   como una rama OR adicional en la raíz del árbol:

   ```
   P(R_T_nuevo) = 1 - (1 - P(R_T_actual)) × (1 - P(hipótesis))
   ```

   Verás en vivo cómo cambia el porcentaje de riesgo y el ALE si esa hipótesis
   resultara cierta — esto es lo que demuestra que la IA está *integrada al modelo*,
   no solo generando texto decorativo.
6. Botón **"🔍 Analizar logs de auditoría (IA)"** → lee el Audit Log Store (D2) en
   vivo y sugiere una mitigación secundaria si detecta patrones sospechosos.

### Con o sin API key de Anthropic

Si defines `ANTHROPIC_API_KEY` antes de levantar Docker Compose (`$env:ANTHROPIC_API_KEY="sk-ant-..."`
en PowerShell, antes de `docker compose up`), el agente usa un LLM real. Si no la
defines, cae automáticamente a un modo heurístico local con hipótesis predefinidas
razonables — la demo funciona igual, sin depender de internet.

### Uso por línea de comandos (opcional, para pruebas rápidas)

```bash
python3 -m venv .venv && source .venv/bin/activate  # o el equivalente en Windows
pip install -r ai_agent/requirements.txt
python ai_agent/agent_logic.py
```

## 5. Mapeo de entregables exigidos en el TC2 (Anexo N°4)

| Requisito del TC2                                   | Dónde está implementado                                             |
|------------------------------------------------------|-----------------------------------------------------------------------|
| Infraestructura simulada (Docker Compose real)        | `docker-compose.yml` (gateway, core, identity, db, logstore)         |
| The Break — simulación del ataque                    | `attacks/payload_tampering_attack.py`, `attacks/sqli_attack.py`, `attacks/ddos_attack.py`, `attacks/log_tamper_attack.py` |
| The Repair — controles técnicos estructurales         | Toggle `SECURE_MODE` en `gateway/app.py`, `core/app.py`, `logstore/app.py` (consultas parametrizadas, rate limiting, jsonschema, firma HMAC este-oeste, hash-chaining inmutable) |
| Validación Analítica y Telemetría (pre vs post)       | `run_full_demo.sh` + `ai_agent/consolidate_results.py` + `dashboard/` |
| Uso Avanzado de IA (Red Teamer + mitigación secundaria)| `ai_agent/` (servicio Flask embebido en docker-compose) + sección "Red Teamer Virtual" del dashboard, con recálculo en vivo de P(R_T) |
| Refinamiento del Trabajo Parcial 1                    | Ya incorporado en el informe (`TRABAJO_SOFTWARE-nuevo.pdf`)          |

## 6. Qué corregir tú mismo antes de sustentar (aporte humano)

El código automatiza la ejecución, pero **la sustentación debe centrarse en las
decisiones humanas** que el LLM no puede justificar por sí solo, por ejemplo:

- Por qué elegiste HMAC como representación simplificada de mTLS este-oeste en vez
  de certificados reales (trade-off de tiempo/alcance de la demo vs. fidelidad a
  SP 800-204A).
- Por qué el hash-chaining es una aproximación válida (aunque no idéntica) a un
  almacén WORM real.
- Cómo los números que salgan de `metrics/results.json` (blocked_ratio, tampering_success,
  chain_valid) se comparan con las probabilidades P(B)=40.87% y P(C)=36.52% calculadas
  en tu Nodo B y Nodo C del árbol de ataque — este es el argumento central que valida
  tu modelo matemático con evidencia empírica real.
