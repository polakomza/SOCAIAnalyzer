
import hashlib
import json
from datetime import datetime, timezone


def calculate_evaluation_id(evaluation):
    """
    Identifica el contenido exacto de una evaluación.
    """
    relevant_data = {
        "ai_severity": evaluation["ai_severity"],
        "ai_confidence": evaluation["ai_confidence"],
        "ai_reason": evaluation["ai_reason"],
        "ai_evidence_rows": evaluation["ai_evidence_rows"],
    }

    serialized = json.dumps(
        relevant_data,
        sort_keys=True,
        ensure_ascii=False
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def create_review(evaluation, status, comment=""):
    if status not in {"Aprobada", "Rechazada"}:
        raise ValueError("Estado de revisión inválido.")

    if not comment.strip():
        raise ValueError(
            "La revisión requiere una observación del analista."
        )

    return {
        "evaluation_id": calculate_evaluation_id(evaluation),
        "status": status,
        "ai_severity": evaluation["ai_severity"],
        "ai_confidence": evaluation["ai_confidence"],
        "ai_reason": evaluation["ai_reason"],
        "ai_evidence_rows": list(
            evaluation["ai_evidence_rows"]
        ),
        "analyst_comment": comment.strip(),
        "reviewed_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }


def is_review_current(review, evaluation):
    if not review:
        return False

    return (
        review.get("evaluation_id")
        == calculate_evaluation_id(evaluation)
    )
