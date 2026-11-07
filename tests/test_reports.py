
from io import BytesIO

from pypdf import PdfReader

from src.reports.report_builder import build_report
from src.reports.pdf_exporter import generate_pdf


def sample_report():
    analysis = {
        "id": 1,
        "source_name": "eventos.xlsx",
        "sheet_name": "Eventos_SOC",
        "total_events": 18,
        "valid_events": 18
    }

    findings = [
        {"rule_id": "SOC-BF-001"}
    ]

    incidents = [{
        "incident_id": "INC-TEST001",
        "severity": "Alto",
        "first_seen": "2026-11-03T10:00:00",
        "last_seen": "2026-11-03T10:05:00",
        "rules": ["SOC-BF-001"],
        "source_ips": ["192.168.1.10"],
        "users": ["admin"],
        "evidence_rows": [2, 3, 4, 5, 6],
        "findings_count": 1
    }]

    return build_report(
        analysis,
        findings,
        incidents,
        ai_reports={
            "INC-TEST001": "Posible ataque de fuerza bruta."
        }
    )


def test_report_structure():
    report = sample_report()

    assert report["summary"]["total_events"] == 18
    assert report["summary"]["incidents_count"] == 1
    assert report["summary"]["high_count"] == 1


def test_ai_analysis_included():
    report = sample_report()

    assert (
        report["incidents"][0]["ai_analysis"]
        == "Posible ataque de fuerza bruta."
    )


def test_pdf_generation():
    pdf = generate_pdf(sample_report())

    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_pdf_content():
    pdf = generate_pdf(sample_report())
    reader = PdfReader(BytesIO(pdf))

    text = "\n".join(
        page.extract_text()
        for page in reader.pages
    )

    assert "SOC AI Analyzer" in text
    assert "SOC-BF-001" in text
    assert "INC-TEST001" in text
    assert "192.168.1.10" in text


def test_empty_incidents():
    report = build_report(
        analysis_info={
            "total_events": 10,
            "valid_events": 10,
            "source_name": "normal.xlsx",
            "sheet_name": "Hoja1"
        },
        findings=[],
        incidents=[]
    )

    pdf = generate_pdf(report)

    assert pdf.startswith(b"%PDF-")
    assert report["summary"]["incidents_count"] == 0


def test_report_includes_finding_evidence():
    finding = {
        "rule_id": "SOC-NET-001",
        "title": "Transferencia saliente elevada",
        "severity": "Alto",
        "description": "Transferencia de datos sospechosa",
        "severity_reason": (
            "Volumen elevado de datos enviados "
            "a un destino externo."
        ),
        "first_seen": "2026-10-23T10:43:00",
        "last_seen": "2026-10-23T10:49:18",
        "evidence_rows": [431, 432],
        "destination": "198.51.100.88:443",
        "bytes_out": 80000000
    }

    incident = {
        "incident_id": "INC-TEST001",
        "severity": "Alto",
        "first_seen": finding["first_seen"],
        "last_seen": finding["last_seen"],
        "rules": ["SOC-NET-001"],
        "source_ips": ["10.10.1.31"],
        "users": ["CORP\\rrojas"],
        "evidence_rows": [431, 432],
        "findings_count": 1,
        "findings": [finding]
    }

    report = build_report(
        {
            "total_events": 100,
            "valid_events": 100
        },
        [finding],
        [incident]
    )

    details = report["incidents"][0]["findings"][0]

    assert details["rule_id"] == "SOC-NET-001"
    assert details["destination"] == "198.51.100.88:443"
    assert details["bytes_out"] == 80000000
    assert details["severity_reason"] == (
        "Volumen elevado de datos enviados "
        "a un destino externo."
    )


def test_pdf_includes_finding_details():
    from io import BytesIO
    from pypdf import PdfReader

    from src.reports.pdf_exporter import generate_pdf

    finding = {
        "rule_id": "SOC-NET-001",
        "title": "Transferencia saliente elevada",
        "severity": "Alto",
        "description": "Actividad saliente sospechosa",
        "severity_reason": "Volumen elevado de transferencia",
        "first_seen": "2026-10-23T10:43:00",
        "last_seen": "2026-10-23T10:49:18",
        "evidence_rows": [431, 432],
        "destination": "198.51.100.88:443",
        "bytes_out": 80000000
    }

    incident = {
        "incident_id": "INC-TEST001",
        "severity": "Alto",
        "first_seen": finding["first_seen"],
        "last_seen": finding["last_seen"],
        "rules": ["SOC-NET-001"],
        "source_ips": ["10.10.1.31"],
        "users": ["CORP\\rrojas"],
        "evidence_rows": [431, 432],
        "findings_count": 1,
        "findings": [finding]
    }

    report = build_report(
        {
            "total_events": 100,
            "valid_events": 100
        },
        [finding],
        [incident]
    )

    pdf_bytes = generate_pdf(report)
    reader = PdfReader(BytesIO(pdf_bytes))

    content = "\n".join(
        page.extract_text() or ""
        for page in reader.pages
    )

    assert "SOC-NET-001" in content
    assert "198.51.100.88:443" in content
    assert "Volumen elevado de transferencia" in content
    assert "80,000,000 bytes" in content
    

def test_report_includes_risk_and_verified_metrics():
    incident = {
        "incident_id": "INC-TEST",
        "severity": "Alto",
        "rule_severity": "Alto",
        "first_seen": "2026-10-23T10:43:00",
        "last_seen": "2026-10-23T10:49:18",
        "rules": ["SOC-NET-001"],
        "source_ips": ["10.10.1.31"],
        "users": ["CORP\\rrojas"],
        "evidence_rows": [431, 432],
        "findings_count": 0,
        "findings": [],
    }

    evaluation = {
        "ai_severity": "Alto",
        "ai_confidence": "Media",
        "ai_reason": "Transferencia saliente elevada.",
        "ai_evidence_rows": [431, 432],
    }

    metrics = {
        "event_count": 22,
        "bytes_out_total": 253305558,
        "bytes_out_mib": 241.57,
        "duration_seconds": 378,
        "destinations": ["198.51.100.88:443"],
        "events_with_bytes": 22,
        "missing_rows": [],
    }

    review = {
        "status": "Aprobada",
        "analyst_comment": "Evidencia revisada.",
        "reviewed_at": "2026-11-06T10:00:00+00:00",
        "evaluation_id": "test-hash",
    }

    report = build_report(
        analysis_info={
            "total_events": 715,
            "valid_events": 715,
        },
        findings=[],
        incidents=[incident],
        risk_evaluations={"INC-TEST": evaluation},
        risk_reviews={"INC-TEST": review},
        incident_metrics={"INC-TEST": metrics},
    )

    result = report["incidents"][0]

    assert result["risk_evaluation"] == evaluation
    assert result["risk_review"] == review
    assert result["verified_metrics"] == metrics
    assert result["severity"] == "Alto"
