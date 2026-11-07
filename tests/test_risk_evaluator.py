
import json
import pytest

from src.ai import risk_evaluator


@pytest.fixture
def incident():
    return {
        "incident_id": "INC-TEST001",
        "severity": "Alto",
        "rule_severity": "Alto",
        "first_seen": "2026-10-23T10:43:00",
        "last_seen": "2026-10-23T10:45:00",
        "rules": ["SOC-NET-001"],
        "source_ips": ["10.10.1.31"],
        "users": ["CORP\\rrojas"],
        "evidence_rows": [431, 432],
        "findings": [{
            "rule_id": "SOC-NET-001",
            "title": "Transferencia saliente elevada",
            "severity": "Alto",
            "description": "Transferencia sospechosa",
            "bytes_out": 80000000,
            "destination": "198.51.100.88:443",
            "evidence_rows": [431, 432]
        }]
    }


def test_valid_risk_evaluation(incident):
    response = json.dumps({
        "ai_severity": "Crítico",
        "ai_reason": "Transferencia elevada y actividad correlacionada.",
        "ai_confidence": "Media",
        "evidence_rows": [431]
    })

    result = risk_evaluator.validate_risk_response(
        response, incident
    )

    assert result["ai_severity"] == "Crítico"
    assert result["ai_evidence_rows"] == [431]
    assert incident["severity"] == "Alto"


def test_invalid_severity(incident):
    response = json.dumps({
        "ai_severity": "Extremo",
        "ai_reason": "Riesgo elevado",
        "ai_confidence": "Media",
        "evidence_rows": [431]
    })

    with pytest.raises(risk_evaluator.RiskEvaluationError):
        risk_evaluator.validate_risk_response(
            response, incident
        )


def test_invented_evidence_rejected(incident):
    response = json.dumps({
        "ai_severity": "Alto",
        "ai_reason": "Actividad sospechosa",
        "ai_confidence": "Alta",
        "evidence_rows": [9999]
    })

    with pytest.raises(risk_evaluator.RiskEvaluationError):
        risk_evaluator.validate_risk_response(
            response, incident
        )


def test_evaluate_risk_uses_ollama(
    monkeypatch, incident
):
    def fake_generate_response(prompt, model):
        return json.dumps({
            "ai_severity": "Alto",
            "ai_reason": "Volumen elevado de datos",
            "ai_confidence": "Media",
            "evidence_rows": [431, 432]
        })

    monkeypatch.setattr(
        risk_evaluator,
        "generate_response",
        fake_generate_response
    )

    result = risk_evaluator.evaluate_incident_risk(
        incident
    )

    assert result["ai_severity"] == "Alto"
    assert result["ai_confidence"] == "Media"


def test_risk_prompt_includes_verified_metrics(incident):
    metrics = {
        "event_count": 22,
        "bytes_out_total": 253305558,
        "bytes_out_mib": 241.57,
        "duration_seconds": 378,
        "destinations": ["198.51.100.88:443"],
        "verified_rows": [431, 432],
        "missing_rows": [],
        "events_with_bytes": 22,
    }

    prompt = risk_evaluator.build_risk_prompt(
        incident,
        metrics=metrics
    )

    assert '"verified_metrics"' in prompt
    assert '"bytes_out_total": 253305558' in prompt
    assert '"event_count": 22' in prompt
    assert '"duration_seconds": 378' in prompt


def test_evaluate_risk_passes_metrics_to_ollama(
    monkeypatch,
    incident
):
    captured = {}

    def fake_generate_response(prompt, model):
        captured["prompt"] = prompt

        return json.dumps({
            "ai_severity": "Alto",
            "ai_reason": (
                "El incidente presenta un volumen "
                "elevado de datos salientes."
            ),
            "ai_confidence": "Media",
            "evidence_rows": [431, 432],
        })

    monkeypatch.setattr(
        risk_evaluator,
        "generate_response",
        fake_generate_response
    )

    metrics = {
        "event_count": 22,
        "bytes_out_total": 253305558,
        "bytes_out_mib": 241.57,
        "duration_seconds": 378,
        "destinations": ["198.51.100.88:443"],
        "verified_rows": [431, 432],
        "missing_rows": [],
        "events_with_bytes": 22,
    }

    result = risk_evaluator.evaluate_incident_risk(
        incident,
        metrics=metrics
    )

    assert result["ai_severity"] == "Alto"
    assert '"verified_metrics"' in captured["prompt"]
    assert '"bytes_out_total": 253305558' in captured["prompt"]
