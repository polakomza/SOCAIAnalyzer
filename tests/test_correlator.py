
from src.analysis.correlator import correlate_incidents


def make_finding(rule, rows, start, end, severity="Medio"):
    return {
        "rule_id": rule,
        "first_seen": start,
        "last_seen": end,
        "severity": severity,
        "evidence_rows": rows,
        "source_ip": "192.168.1.10",
        "username": "admin",
        "description": "Evento simulado"
    }


def test_related_findings_become_one_incident():
    findings = [
        make_finding(
            "SOC-BF-001", [2, 3, 4],
            "2026-11-03T10:00:00",
            "2026-11-03T10:04:00"
        ),
        make_finding(
            "SOC-DBF-001", [3, 4, 5],
            "2026-11-03T10:02:00",
            "2026-11-03T10:06:00",
            "Alto"
        )
    ]

    incidents = correlate_incidents(findings)

    assert len(incidents) == 1
    assert incidents[0]["findings_count"] == 2
    assert incidents[0]["severity"] == "Alto"
    assert incidents[0]["evidence_rows"] == [2, 3, 4, 5]


def test_unrelated_findings_stay_separate():
    findings = [
        make_finding(
            "SOC-BF-001", [2, 3],
            "2026-11-03T10:00:00",
            "2026-11-03T10:03:00"
        ),
        make_finding(
            "SOC-PS-001", [20, 21],
            "2026-11-03T11:00:00",
            "2026-11-03T11:05:00"
        )
    ]

    assert len(correlate_incidents(findings)) == 2


def test_incident_id_is_reproducible():
    findings = [
        make_finding(
            "SOC-BF-001", [2, 3, 4],
            "2026-11-03T10:00:00",
            "2026-11-03T10:04:00"
        )
    ]

    first = correlate_incidents(findings)
    second = correlate_incidents(findings)

    assert first[0]["incident_id"] == second[0]["incident_id"]


def test_empty_findings():
    assert correlate_incidents([]) == []


def make_network_finding(
    start, end, ip, user, row,
    destination="198.51.100.88:443"
):
    return {
        "rule_id": "SOC-NET-001",
        "title": "Transferencia saliente elevada",
        "severity": "Alto",
        "source_ip": ip,
        "username": user,
        "destination": destination,
        "first_seen": start,
        "last_seen": end,
        "evidence_rows": [row],
        "description": "Transferencia sospechosa",
        "failed_attempts": 0,
        "success_after_failures": False
    }



def test_consecutive_network_transfers_are_correlated():
    first = make_network_finding(
        "2026-10-23T10:43:00",
        "2026-10-23T10:47:48",
        "10.10.1.31",
        "CORP\\rrojas",
        431
    )

    second = make_network_finding(
        "2026-10-23T10:48:06",
        "2026-10-23T10:49:18",
        "10.10.1.31",
        "CORP\\rrojas",
        450
    )

    incidents = correlate_incidents([first, second])

    assert len(incidents) == 1
    assert incidents[0]["findings_count"] == 2


def test_different_ips_are_not_correlated():
    first = make_network_finding(
        "2026-10-23T10:43:00",
        "2026-10-23T10:47:48",
        "10.10.1.31",
        "CORP\\rrojas",
        431
    )

    second = make_network_finding(
        "2026-10-23T10:48:06",
        "2026-10-23T10:49:18",
        "10.10.2.24",
        "CORP\\rrojas",
        450
    )

    assert len(correlate_incidents([first, second])) == 2


def test_distant_network_events_are_not_correlated():
    first = make_network_finding(
        "2026-10-23T08:00:00",
        "2026-10-23T08:01:00",
        "10.10.1.31",
        "CORP\\rrojas",
        431
    )

    second = make_network_finding(
        "2026-10-23T10:48:06",
        "2026-10-23T10:49:18",
        "10.10.1.31",
        "CORP\\rrojas",
        450
    )

    assert len(correlate_incidents([first, second])) == 2
def test_different_destinations_are_not_correlated():
    first = make_network_finding(
        "2026-10-23T10:43:00",
        "2026-10-23T10:47:48",
        "10.10.1.31",
        "CORP\\rrojas",
        431,
        destination="198.51.100.88:443"
    )

    second = make_network_finding(
        "2026-10-23T10:48:06",
        "2026-10-23T10:49:18",
        "10.10.1.31",
        "CORP\\rrojas",
        450,
        destination="203.0.113.90:443"
    )

    incidents = correlate_incidents([first, second])

    assert len(incidents) == 2


def test_missing_destination_prevents_continuity():
    first = make_network_finding(
        "2026-10-23T10:43:00",
        "2026-10-23T10:47:48",
        "10.10.1.31",
        "CORP\\rrojas",
        431
    )

    second = make_network_finding(
        "2026-10-23T10:48:06",
        "2026-10-23T10:49:18",
        "10.10.1.31",
        "CORP\\rrojas",
        450
    )

    second.pop("destination")

    assert len(correlate_incidents([first, second])) == 2


def test_same_destination_preserves_correlation():
    first = make_network_finding(
        "2026-10-23T10:43:00",
        "2026-10-23T10:47:48",
        "10.10.1.31",
        "CORP\\rrojas",
        431
    )

    second = make_network_finding(
        "2026-10-23T10:48:06",
        "2026-10-23T10:49:18",
        "10.10.1.31",
        "CORP\\rrojas",
        450
    )

    incidents = correlate_incidents([first, second])

    assert len(incidents) == 1
    assert incidents[0]["findings_count"] == 2


def test_incident_preserves_rule_severity():
    from src.analysis.correlator import correlate_incidents

    finding = {
        "rule_id": "SOC-NET-001",
        "title": "Transferencia saliente elevada",
        "severity": "Alto",
        "source_ip": "10.10.1.31",
        "source_ips": ["10.10.1.31"],
        "username": "CORP\\rrojas",
        "affected_users": ["CORP\\rrojas"],
        "first_seen": "2026-10-23T10:43:00",
        "last_seen": "2026-10-23T10:45:00",
        "evidence_rows": [431, 432],
        "description": "Transferencia sospechosa"
    }

    incidents = correlate_incidents([finding])

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["severity"] == "Alto"
    assert incident["rule_severity"] == "Alto"
    assert incident["ai_severity"] is None
    assert incident["ai_reason"] is None
    assert incident["ai_confidence"] is None
