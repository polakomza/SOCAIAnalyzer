
from datetime import datetime, timezone


def _response_guidance(incident, findings):
    """Genera recomendaciones orientativas según los hallazgos."""

    text = " ".join(
        str(value or "")
        for value in (
            incident.get("rules", []),
            *(f.get("rule_id", "") for f in findings),
            *(f.get("title", "") for f in findings),
            *(f.get("description", "") for f in findings),
        )
    ).lower()

    investigate = [
        "Contrastar las filas de evidencia con los registros "
        "originales, horarios, IP, usuarios y activos afectados.",
        "Correlacionar con otras fuentes y verificar si la "
        "actividad tiene una explicación autorizada.",
    ]

    contain = [
        "Si se confirma actividad maliciosa, aplicar medidas "
        "de contención proporcionales, previa autorización "
        "del responsable.",
    ]

    remediate = [
        "Corregir la causa identificada, reforzar los controles "
        "y verificar la ausencia de recurrencia.",
    ]

    impact = (
        "Podría afectar la confidencialidad, integridad o "
        "disponibilidad de los sistemas involucrados; "
        "el impacto real requiere validación."
    )

    if any(word in text for word in (
        "brute", "fuerza bruta", "password", "login",
        "logon", "auth", "spray", "inicio de sesión",
    )):
        impact = (
            "Posible acceso no autorizado a cuentas, uso indebido "
            "de credenciales y exposición de información, "
            "si se confirma el compromiso."
        )
        investigate.append(
            "Revisar fallos y éxitos de autenticación, origen, "
            "cuentas objetivo y cambios posteriores en la sesión."
        )
        contain.append(
            "Ante evidencia de compromiso, considerar bloqueo "
            "temporal de cuentas o sesiones y restricciones "
            "al origen, según el procedimiento vigente."
        )
        remediate.append(
            "Revisar MFA, contraseñas, políticas de bloqueo "
            "y alertas de autenticación."
        )

    elif any(word in text for word in (
        "powershell", "command", "comando", "process",
        "proceso", "persist", "evasion", "evasión", "windows",
    )):
        impact = (
            "Posible ejecución no autorizada, persistencia "
            "o alteración del equipo, si la actividad "
            "resulta maliciosa."
        )
        investigate.append(
            "Revisar árbol de procesos, línea de comandos, "
            "usuario ejecutor, archivos y conexiones relacionadas."
        )
        contain.append(
            "Si se confirma ejecución maliciosa, considerar "
            "aislar el equipo y preservar evidencia antes "
            "de modificarlo."
        )
        remediate.append(
            "Eliminar mecanismos maliciosos confirmados, "
            "corregir la vía de acceso y reforzar "
            "controles de ejecución."
        )

    elif any(word in text for word in (
        "lateral", "share", "smb", "recurso compartido",
        "network", "red", "scan",
    )):
        impact = (
            "Posible exposición de recursos internos "
            "o propagación hacia otros equipos, "
            "pendiente de confirmar."
        )
        investigate.append(
            "Correlacionar accesos a recursos, autenticaciones, "
            "conexiones internas y equipos de origen y destino."
        )
        contain.append(
            "Si se confirma movimiento no autorizado, restringir "
            "temporalmente conexiones o credenciales comprometidas."
        )
        remediate.append(
            "Revisar segmentación, permisos de recursos "
            "compartidos y accesos administrativos."
        )

    elif any(word in text for word in (
        "web", "http", "url", "path", "ruta",
        "proxy", "exfil", "bytes",
    )):
        impact = (
            "Posible exposición de aplicaciones o transferencia "
            "no autorizada de datos; el volumen observado "
            "no prueba exfiltración."
        )
        investigate.append(
            "Revisar URL, respuestas HTTP, destinos, "
            "volumen de datos y contexto de las solicitudes."
        )
        contain.append(
            "Si se verifica abuso, considerar restricciones "
            "específicas de acceso o tráfico sin afectar "
            "servicios legítimos."
        )
        remediate.append(
            "Revisar configuración de aplicaciones, controles "
            "de acceso, filtrado y monitoreo de tráfico."
        )

    return {
        "potential_impact": impact,
        "action_plan": {
            "investigate": investigate,
            "contain": contain,
            "remediate": remediate,
        },
    }


def build_report(
    analysis_info,
    findings,
    incidents,
    ai_reports=None,
    risk_evaluations=None,
    risk_reviews=None,
    incident_metrics=None,
):
    ai_reports = ai_reports or {}
    risk_evaluations = risk_evaluations or {}
    risk_reviews = risk_reviews or {}
    incident_metrics = incident_metrics or {}

    incident_reports = []

    for incident in incidents:
        incident_id = str(incident["incident_id"])
        finding_details = []

        for finding in incident.get("findings", []):
            finding_details.append({
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "description": finding.get("description"),
                "severity_reason": finding.get(
                    "severity_reason",
                    "Severidad asignada por la regla de detección."
                ),
                "first_seen": finding.get("first_seen"),
                "last_seen": finding.get("last_seen"),
                "evidence_rows": list(
                    finding.get("evidence_rows", [])
                ),
                "destination": finding.get("destination"),
                "bytes_out": finding.get("bytes_out"),
            })

        guidance = _response_guidance(
            incident,
            finding_details,
        )

        incident_reports.append({
            "incident_id": incident_id,
            "severity": incident["severity"],
            "rule_severity": incident.get(
                "rule_severity",
                incident["severity"],
            ),
            "ai_severity": incident.get("ai_severity"),
            "ai_reason": incident.get("ai_reason"),
            "ai_confidence": incident.get("ai_confidence"),
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "rules": list(incident["rules"]),
            "source_ips": list(incident["source_ips"]),
            "users": list(incident["users"]),
            "evidence_rows": list(
                incident["evidence_rows"]
            ),
            "findings_count": incident["findings_count"],
            "findings": finding_details,
            "ai_analysis": ai_reports.get(incident_id),
            "risk_evaluation": risk_evaluations.get(incident_id),
            "risk_review": risk_reviews.get(incident_id),
            "verified_metrics": incident_metrics.get(incident_id),
            **guidance,
        })

    critical_count = sum(
        incident["severity"] == "Crítico"
        for incident in incidents
    )

    high_count = sum(
        incident["severity"] == "Alto"
        for incident in incidents
    )

    if not incidents:
        executive = (
            "No se identificaron incidentes con las reglas "
            "aplicadas a los registros disponibles. Esto no "
            "garantiza la ausencia de amenazas; se recomienda "
            "mantener el monitoreo y revisar la cobertura "
            "de las fuentes."
        )
    else:
        executive = (
            f"Se analizaron {analysis_info['valid_events']} "
            f"eventos válidos y se identificaron "
            f"{len(findings)} hallazgos agrupados en "
            f"{len(incidents)} incidentes. "
            f"De ellos, {critical_count} fueron clasificados "
            f"como críticos y {high_count} como altos. "
            "Se recomienda priorizar la verificación de los "
            "incidentes de mayor severidad, contrastando cada "
            "referencia con los registros originales antes "
            "de adoptar medidas. Las detecciones son indicios, "
            "no confirmaciones de compromiso."
        )

    return {
        "title": "Informe técnico de seguridad",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "analysis": dict(analysis_info),
        "summary": {
            "total_events": analysis_info["total_events"],
            "valid_events": analysis_info["valid_events"],
            "findings_count": len(findings),
            "incidents_count": len(incidents),
            "critical_count": critical_count,
            "high_count": high_count,
        },
        "executive_summary": executive,
        "incidents": incident_reports,
        "general_recommendations": [
            "Revisar los registros originales relacionados "
            "con cada incidente y conservar las evidencias "
            "según los procedimientos internos.",
            "Correlacionar las IP, usuarios y equipos con "
            "otras fuentes de telemetría disponibles.",
            "Reforzar autenticación multifactor, mínimos "
            "privilegios y revisión periódica de accesos.",
            "Mantener sistemas actualizados, segmentar redes "
            "y monitorear actividades administrativas.",
            "Documentar decisiones, responsables, acciones "
            "ejecutadas y resultados de la investigación.",
        ],
        "limitations": [
            "Las detecciones identifican patrones sospechosos, "
            "no compromisos confirmados.",
            "El análisis depende de la calidad y cobertura "
            "de los registros importados.",
            "El impacto y las acciones propuestas son "
            "orientativos y deben adaptarse al contexto "
            "organizacional.",
            "Las interpretaciones de IA requieren "
            "validación por un analista.",
            "Las referencias a filas corresponden al archivo "
            "y hoja utilizados; no sustituyen la cadena "
            "de custodia.",
        ],
    }
