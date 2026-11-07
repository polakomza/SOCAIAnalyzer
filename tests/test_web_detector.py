
import pandas as pd

from src.analysis.web_detector import detect_web_threats, is_suspicious_web_request
from src.analysis.correlator import correlate_incidents

def make_event(row, command, status="200", minute=0):
    return {
        "source_row": row,
        "normalized_event_type": "http_access",
        "normalized_timestamp": (
            pd.Timestamp("2026-10-23 12:00:00")
            + pd.Timedelta(minutes=minute)
        ).isoformat(),
        "normalized_source_ip": "192.0.2.91",
        "username": "webuser",
        "event_description": "HTTP request",
        "normalized_command": command,
        "result": status
    }


def test_command_injection():
    df = pd.DataFrame([
        make_event(
            2,
            "/uploads/test.aspx?cmd=whoami"
        )
    ])

    findings = detect_web_threats(df)

    assert any(
        f["rule_id"] == "SOC-WEB-001"
        for f in findings
    )


def test_sensitive_path_scanning():
    df = pd.DataFrame([
        make_event(
            i + 2,
            "/admin/",
            minute=i
        )
        for i in range(5)
    ])

    findings = detect_web_threats(df)

    assert any(
        f["rule_id"] == "SOC-WEB-002"
        for f in findings
    )


def test_http_errors():
    df = pd.DataFrame([
        make_event(
            i + 2,
            "/missing",
            status="404",
            minute=i
        )
        for i in range(5)
    ])

    findings = detect_web_threats(df)

    assert any(
        f["rule_id"] == "SOC-WEB-003"
        for f in findings
    )


def test_normal_request():
    df = pd.DataFrame([
        make_event(2, "/index.html")
    ])

    assert detect_web_threats(df) == []
def test_web_and_windows_timestamps():
    df = pd.DataFrame([
        make_event(
            2,
            "/uploads/test.aspx?cmd=whoami"
        )
    ])

    web_findings = detect_web_threats(df)

    windows_finding = {
        "rule_id": "SOC-WIN-001",
        "title": "Actividad sospechosa",
        "severity": "Alto",
        "source_ip": "192.0.2.91",
        "username": "webuser",
        "first_seen": "2026-10-23T12:00:00",
        "last_seen": "2026-10-23T12:00:00",
        "failed_attempts": 0,
        "success_after_failures": False,
        "evidence_rows": [2],
        "description": "Actividad sospechosa"
    }

    incidents = correlate_incidents(
        web_findings + [windows_finding]
    )

    assert len(incidents) == 1
    
def test_legitimate_command_parameter():
    assert not is_suspicious_web_request(
        "GET /api?cmd=status HTTP/1.1"
    )


def test_legitimate_web_request():
    assert not is_suspicious_web_request(
        "GET /api/products?page=2 HTTP/1.1"
    )


def test_web_command_injection_indicator():
    assert is_suspicious_web_request(
        "GET /uploads/test.aspx?cmd=whoami HTTP/1.1"
    )


def test_encoded_command_injection():
    assert is_suspicious_web_request(
        "GET /run?exec=powershell%20whoami HTTP/1.1"
    )


def test_path_traversal():
    assert is_suspicious_web_request(
        "GET /files/../../../etc/passwd HTTP/1.1"
    )


def test_encoded_path_traversal():
    assert is_suspicious_web_request(
        "GET /files/%2e%2e/%2e%2e/etc/passwd HTTP/1.1"
    )


def test_distant_web_attacks_are_separate():
    df = pd.DataFrame([
        {
            "normalized_event_type": "http_access",
            "normalized_timestamp": "2026-10-23T10:00:00",
            "normalized_source_ip": "192.0.2.91",
            "source_row": 10,
            "event_description": "GET /run?cmd=whoami",
            "result": "404"
        },
        {
            "normalized_event_type": "http_access",
            "normalized_timestamp": "2026-10-23T18:00:00",
            "normalized_source_ip": "192.0.2.91",
            "source_row": 20,
            "event_description": "GET /run?cmd=whoami",
            "result": "404"
        }
    ])

    findings = detect_web_threats(df)

    command_findings = [
        finding for finding in findings
        if finding["rule_id"] == "SOC-WEB-001"
    ]

    assert len(command_findings) == 2
    assert command_findings[0]["evidence_rows"] == [10]
    assert command_findings[1]["evidence_rows"] == [20]


def test_command_word_in_unrelated_parameter():
    assert not is_suspicious_web_request(
        "GET /search?q=powershell&cmd=status HTTP/1.1"
    )


def test_dangerous_command_in_relevant_parameter():
    assert is_suspicious_web_request(
        "GET /run?cmd=whoami HTTP/1.1"
    )


def test_encoded_dangerous_parameter():
    assert is_suspicious_web_request(
        "GET /run?exec=powershell%20whoami HTTP/1.1"
    )


def test_benign_command_parameter():
    assert not is_suspicious_web_request(
        "GET /api?cmd=refresh HTTP/1.1"
    )
