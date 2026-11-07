
import pytest

from src.ai.risk_review import (
    calculate_evaluation_id,
    create_review,
    is_review_current
)


@pytest.fixture
def evaluation():
    return {
        "ai_severity": "Alto",
        "ai_confidence": "Media",
        "ai_reason": "Transferencias salientes elevadas.",
        "ai_evidence_rows": [431, 432],
    }


def test_evaluation_id_is_deterministic(evaluation):
    first = calculate_evaluation_id(evaluation)
    second = calculate_evaluation_id(evaluation)

    assert first == second


def test_create_approved_review(evaluation):
    review = create_review(
        evaluation,
        "Aprobada",
        "La evidencia respalda la clasificación."
    )

    assert review["status"] == "Aprobada"
    assert is_review_current(review, evaluation)


def test_modified_evaluation_invalidates_review(evaluation):
    review = create_review(
        evaluation,
        "Aprobada",
        "Clasificación justificada."
    )

    modified = {
        **evaluation,
        "ai_severity": "Crítico"
    }

    assert not is_review_current(
        review,
        modified
    )


def test_review_requires_comment(evaluation):
    with pytest.raises(ValueError):
        create_review(
            evaluation,
            "Aprobada",
            ""
        )


def test_invalid_review_status(evaluation):
    with pytest.raises(ValueError):
        create_review(
            evaluation,
            "Pendiente",
            "Observación de prueba."
        )
