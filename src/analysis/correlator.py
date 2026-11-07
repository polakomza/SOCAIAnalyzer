
import hashlib
from datetime import datetime, timedelta

import pandas as pd


SEVERITY_ORDER = {
    "Informativo": 0,
    "Bajo": 1,
    "Medio": 2,
    "Alto": 3,
    "Crítico": 4
}


def parse_time(value):
    """Convierte una fecha a datetime."""
    return datetime.fromisoformat(str(value))


def get_evidence(finding):
    """Obtiene las filas de evidencia de un hallazgo."""
    return set(finding.get("evidence_rows", []))


def get_source_ips(finding):
    """Obtiene las IP asociadas a un hallazgo."""
    ips = set()

    if finding.get("source_ip"):
        ips.add(str(finding["source_ip"]))

    ips.update(
        str(ip)
        for ip in finding.get("source_ips", [])
        if ip
    )

    return ips


def get_users(finding):
    """Obtiene los usuarios asociados a un hallazgo."""
    users = set()

    if finding.get("username"):
        users.add(str(finding["username"]))

    users.update(
        str(user)
        for user in finding.get("affected_users", [])
        if user
    )

    return users


def same_single_identity(first, second):
    """
    Exige una IP única compartida y usuarios
    compatibles, cuando ambos están disponibles.
    """
    first_ips = get_source_ips(first)
    second_ips = get_source_ips(second)

    if (
        len(first_ips) != 1
        or len(second_ips) != 1
        or first_ips != second_ips
    ):
        return False

    first_users = get_users(first)
    second_users = get_users(second)

    if first_users and second_users:
        return (
            len(first_users) == 1
            and first_users == second_users
        )

    return True


def same_network_destination(first, second):
    """
    Comprueba que dos hallazgos de transferencia
    tengan el mismo destino explícito.
    """

    first_destination = str(
        first.get("destination") or ""
    ).strip().lower()

    second_destination = str(
        second.get("destination") or ""
    ).strip().lower()

    if not first_destination or not second_destination:
        return False

    return first_destination == second_destination

def time_related(first, second, tolerance_minutes=10):
    """Comprueba proximidad o solapamiento temporal."""

    a_start = parse_time(first["first_seen"])
    a_end = parse_time(first["last_seen"])

    b_start = parse_time(second["first_seen"])
    b_end = parse_time(second["last_seen"])

    tolerance = timedelta(minutes=tolerance_minutes)

    return (
        a_start <= b_end + tolerance
        and b_start <= a_end + tolerance
    )



def are_related(first, second):
    """Relaciona hallazgos con criterios conservadores."""

    # Criterio 1: evidencia compartida y proximidad.
    shared_evidence = (
        get_evidence(first) & get_evidence(second)
    )

    if shared_evidence and time_related(first, second):
        return True

    # Criterio 2: continuidad de transferencias
    # salientes desde la misma identidad.
    if (
    first.get("rule_id") == "SOC-NET-001"
    and second.get("rule_id") == "SOC-NET-001"
    and same_single_identity(first, second)
    and same_network_destination(first, second)
    and time_related(
        first,
        second,
        tolerance_minutes=2
    )
    ):
        return True

    # Criterio 3: persistencia Windows consecutiva
    # desde una misma identidad.
    if (
        first.get("rule_id") == "SOC-WIN-002"
        and second.get("rule_id") == "SOC-WIN-002"
        and same_single_identity(first, second)
        and time_related(
            first,
            second,
            tolerance_minutes=2
        )
    ):
        return True

    return False



def build_incident_id(findings):
    """Genera un ID reproducible para un incidente."""

    identifiers = sorted(
        (
            str(f["rule_id"]),
            str(f["first_seen"]),
            str(f["last_seen"]),
            ",".join(
                map(str, sorted(get_evidence(f)))
            )
        )
        for f in findings
    )

    fingerprint = repr(identifiers).encode("utf-8")
    digest = hashlib.sha256(fingerprint).hexdigest()[:12]

    return f"INC-{digest.upper()}"


def consolidate_group(findings):
    """Construye un incidente a partir de hallazgos."""

    first_seen = min(
        parse_time(f["first_seen"]) for f in findings
    )

    last_seen = max(
        parse_time(f["last_seen"]) for f in findings
    )

    severity = max(
        (f.get("severity", "Informativo") for f in findings),
        key=lambda value: SEVERITY_ORDER.get(value, 0)
    )

    source_ips = set()
    users = set()
    evidence_rows = set()

    for finding in findings:

        if finding.get("source_ip"):
            source_ips.add(str(finding["source_ip"]))

        source_ips.update(
            str(ip) for ip in finding.get("source_ips", [])
        )

        if finding.get("username"):
            users.add(str(finding["username"]))

        users.update(
            str(user)
            for user in finding.get("affected_users", [])
        )

        evidence_rows.update(get_evidence(finding))

    
    return {
        "incident_id": build_incident_id(findings),
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),

        # Severidad utilizada actualmente por el sistema
        "severity": severity,

        # Clasificación original de las reglas
        "rule_severity": severity,

        # Campos reservados para evaluación mediante IA
        "ai_severity": None,
        "ai_reason": None,
        "ai_confidence": None,

        "rules": sorted({
            f["rule_id"] for f in findings
        }),
        "source_ips": sorted(source_ips),
        "users": sorted(users),
        "evidence_rows": sorted(evidence_rows),
        "findings_count": len(findings),
        "findings": findings
    }



def correlate_incidents(findings):
    """
    Agrupa hallazgos relacionados utilizando
    componentes conectados.
    """

    if not findings:
        return []

    visited = set()
    incidents = []

    for index in range(len(findings)):

        if index in visited:
            continue

        group_indices = []
        pending = [index]
        visited.add(index)

        while pending:

            current = pending.pop()
            group_indices.append(current)

            for other in range(len(findings)):

                if other in visited:
                    continue

                if are_related(
                    findings[current],
                    findings[other]
                ):
                    visited.add(other)
                    pending.append(other)

        group = [
            findings[i] for i in group_indices
        ]

        incidents.append(
            consolidate_group(group)
        )

    return sorted(
        incidents,
        key=lambda incident: incident["first_seen"],
        reverse=True
    )
