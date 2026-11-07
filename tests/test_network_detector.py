
import pandas as pd

from src.analysis.network_detector import classify_transfer_severity, detect_network_threats


def make_event(row, event_type, minute, destination, command=""):
    return {
        "source_row": row,
        "normalized_event_type": event_type,
        "normalized_timestamp": (
            pd.Timestamp("2026-10-23 10:43:00")
            + pd.Timedelta(minutes=minute)
        ).isoformat(),
        "normalized_source_ip": "10.10.1.31",
        "destination": destination,
        "normalized_command": command,
        "event_description": "Network event",
        "username": "CORP\\test"
    }


def test_large_outbound_transfer():
    df = pd.DataFrame([
        make_event(
            i + 2,
            "proxy_access",
            i,
            "198.51.100.88:443",
            "bytes_out=20000000 uri=/upload/session"
        )
        for i in range(4)
    ])

    findings = detect_network_threats(df)

    assert any(
        finding["rule_id"] == "SOC-NET-001"
        for finding in findings
    )


def test_multiple_network_shares():
    destinations = ["FS-SRV01", "DC-01", "DB-SRV01"]

    df = pd.DataFrame([
        make_event(
            i + 2,
            "network_share_access",
            i,
            destination
        )
        for i, destination in enumerate(destinations)
    ])

    findings = detect_network_threats(df)

    assert any(
        finding["rule_id"] == "SOC-NET-002"
        for finding in findings
    )


def test_normal_network_activity():
    df = pd.DataFrame([
        make_event(
            2,
            "proxy_access",
            0,
            "198.51.100.88:443",
            "bytes_out=1024"
        )
    ])

    assert detect_network_threats(df) == []
def test_transfer_severity_high():
    severity, reason = classify_transfer_severity(
        100 * 1024 * 1024,
        5
    )

    assert severity == "Alto"
    assert reason


def test_transfer_severity_large():
    severity, reason = classify_transfer_severity(
        250 * 1024 * 1024,
        5
    )

    assert severity == "Alto"
    assert "200 MiB" in reason


def test_transfer_severity_critical():
    severity, reason = classify_transfer_severity(
        600 * 1024 * 1024,
        12
    )

    assert severity == "Crítico"
    assert "500 MiB" in reason


def test_transfer_severity_not_critical_without_events():
    severity, reason = classify_transfer_severity(
        600 * 1024 * 1024,
        3
    )

    assert severity == "Alto"
