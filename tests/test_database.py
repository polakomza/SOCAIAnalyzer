
from src.storage.database import (
    init_database,
    save_analysis,
    list_analyses,
    load_analysis
)


def sample_finding():
    return {
        "rule_id": "SOC-BF-001",
        "severity": "Alto",
        "source_ip": "192.168.1.10",
        "username": "admin",
        "evidence_rows": [2, 3, 4, 5, 6]
    }


def sample_incident():
    return {
        "incident_id": "INC-TEST001",
        "severity": "Alto",
        "rules": ["SOC-BF-001"],
        "source_ips": ["192.168.1.10"],
        "users": ["admin"],
        "evidence_rows": [2, 3, 4, 5, 6],
        "findings_count": 1
    }


def test_save_and_load(tmp_path):
    db_path = tmp_path / "test.db"

    init_database(db_path)

    analysis_id, created = save_analysis(
        analysis_key="test-key-001",
        source_name="eventos.xlsx",
        sheet_name="Hoja1",
        total_events=10,
        valid_events=10,
        findings=[sample_finding()],
        incidents=[sample_incident()],
        db_path=db_path
    )

    assert created is True

    saved = load_analysis(analysis_id, db_path)

    assert saved is not None
    assert saved["analysis"]["total_events"] == 10
    assert len(saved["findings"]) == 1
    assert len(saved["incidents"]) == 1
    assert saved["incidents"][0]["severity"] == "Alto"


def test_duplicate_analysis(tmp_path):
    db_path = tmp_path / "test.db"

    arguments = {
        "analysis_key": "same-analysis",
        "source_name": "eventos.xlsx",
        "sheet_name": "Hoja1",
        "total_events": 5,
        "valid_events": 5,
        "findings": [],
        "incidents": [],
        "db_path": db_path
    }

    first_id, first_created = save_analysis(**arguments)
    second_id, second_created = save_analysis(**arguments)

    assert first_created is True
    assert second_created is False
    assert first_id == second_id
    assert len(list_analyses(db_path)) == 1


def test_history(tmp_path):
    db_path = tmp_path / "test.db"

    save_analysis(
        analysis_key="history-001",
        source_name="prueba.xlsx",
        sheet_name="Eventos",
        total_events=20,
        valid_events=18,
        findings=[],
        incidents=[],
        db_path=db_path
    )

    history = list_analyses(db_path)

    assert len(history) == 1
    assert history[0]["valid_events"] == 18
    assert history[0]["source_name"] == "prueba.xlsx"


def test_missing_analysis(tmp_path):
    db_path = tmp_path / "test.db"

    assert load_analysis(999, db_path) is None
