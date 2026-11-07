
from datetime import datetime, timezone


def build_report(
    analysis_info,
    findings,
    incidents,
    ai_reports=None,
    risk_evaluations=None,
    risk_reviews=None,
    incident_metrics=None
):
    ai_reports = ai_reports or {}
    risk_evaluations = risk_evaluations or {}
    risk_reviews = risk_reviews or {}
    incident_metrics = incident_metrics or {}

    incident_reports = []

    for incident in incidents:
        incident_id = str(incident["incident_id"])
        risk_evaluation = risk_evaluations.get(incident_id)
        risk_review = risk_reviews.get(incident_id)
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
                "bytes_out": finding.get("bytes_out")
            })

        incident_reports.append({
            "incident_id": incident_id,
            "severity": incident["severity"],
            "rule_severity": incident.get(
            "rule_severity",
                incident["severity"]
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
            "risk_evaluation": risk_evaluation,
            "risk_review": risk_review,
            "verified_metrics": incident_metrics.get(incident_id),
        })


    critical_count = sum(
        incident["severity"] == "Crítico"
        for incident in incidents
    )

    high_count = sum(
        incident["severity"] == "Alto"
        for incident in incidents
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
            "high_count": high_count
        },
        "incidents": incident_reports,
        "limitations": [
            "Las detecciones identifican patrones "
            "sospechosos, no compromisos confirmados.",
            "El análisis depende de la calidad "
            "y cobertura de los registros importados.",
            "Las interpretaciones de IA requieren "
            "validación por un analista.",
            "Las referencias a filas corresponden "
            "al archivo y hoja utilizados."
        ]
    }
