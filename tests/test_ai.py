
from unittest.mock import patch

import pytest
import requests

from src.ai.incident_analyzer import (
    prepare_incident,
    build_prompt,
    analyze_incident
)
from src.ai.ollama_client import (
    check_ollama,
    generate_response,
    OllamaError
)


SAMPLE_INCIDENT = {
    "incident_id": "INC-TEST001",
    "severity": "Alto",
    "first_seen": "2026-11-03T10:00:00",
    "last_seen": "2026-11-03T10:05:00",
    "rules": ["SOC-BF-001"],
    "source_ips": ["192.168.1.10"],
    "users": ["admin"],
    "evidence_rows": [2, 3, 4, 5, 6],
    "findings": [{
        "rule_id": "SOC-BF-001",
        "failed_attempts": 5,
        "success_after_failures": True
    }]
}


def test_prepare_incident():
    result = prepare_incident(SAMPLE_INCIDENT)

    assert result["severity"] == "Alto"
    assert result["source_ips"] == ["192.168.1.10"]
    assert len(result["findings"]) == 1


def test_prompt_contains_evidence():
    prompt = build_prompt(SAMPLE_INCIDENT)

    assert "SOC-BF-001" in prompt
    assert "192.168.1.10" in prompt
    assert "No inventes" in prompt


@patch("src.ai.incident_analyzer.generate_response")
def test_analyze_incident(mock_generate):
    mock_generate.return_value = "Posible fuerza bruta."

    response = analyze_incident(SAMPLE_INCIDENT)

    assert response == "Posible fuerza bruta."
    mock_generate.assert_called_once()


@patch("src.ai.ollama_client.requests.get")
def test_check_ollama(mock_get):
    mock_get.return_value.status_code = 200

    assert check_ollama() is True


@patch("src.ai.ollama_client.requests.post")
def test_generate_response(mock_post):
    mock_post.return_value.json.return_value = {
        "response": "Análisis generado."
    }

    result = generate_response("Analizá este evento")

    assert result == "Análisis generado."


@patch("src.ai.ollama_client.requests.post")
def test_ollama_connection_error(mock_post):
    mock_post.side_effect = requests.ConnectionError()

    with pytest.raises(OllamaError):
        generate_response("Prueba")
