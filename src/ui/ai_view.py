
import streamlit as st

from src.ai.incident_analyzer import analyze_incident
from src.ai.ollama_client import OllamaError, check_ollama
from src.ai.risk_evaluator import (
    RiskEvaluationError,
    evaluate_incident_risk,
)
from src.ai.risk_review import create_review, is_review_current
from src.analysis.incident_metrics import calculate_incident_metrics


def navegar_a(destino):
    st.session_state["pagina_actual"] = destino


def render():
    st.header("🤖 Análisis con IA")

    if not st.session_state.get("analysis_completed", False):
        st.info("Primero ejecutá un análisis de seguridad.")
        return

    incidents = st.session_state.get("incidents", [])
    normalized_df = st.session_state.get("normalized_df")

    if not incidents:
        st.info("No hay incidentes para evaluar.")
        return

    if normalized_df is None:
        st.warning("No se encontraron registros normalizados.")
        return

    # ==========================================
    # SELECCIÓN ÚNICA DEL INCIDENTE
    # ==========================================

    incident_options = {
        str(incident["incident_id"]): incident
        for incident in incidents
    }

    incident_ids = list(incident_options.keys())

    selected_id = str(
        st.session_state.get("selected_incident_id", "")
    )

    if selected_id not in incident_options:
        selected_id = incident_ids[0]

    # Sincronizar el selector cuando se navega
    # desde otra sección.
    if (
        st.session_state.get("ai_incident_selector")
        != selected_id
    ):
        st.session_state["ai_incident_selector"] = selected_id

    selected_id = st.selectbox(
        "Seleccioná el incidente a investigar",
        options=incident_ids,
        format_func=lambda incident_id: (
            f"{incident_id} | "
            f"{incident_options[incident_id].get('severity', 'N/D')}"
        ),
        key="ai_incident_selector",
    )

    st.session_state["selected_incident_id"] = selected_id

    selected_incident = incident_options[selected_id]

    st.caption(
        f"Incidente activo: {selected_id} | "
        f"Severidad del detector: "
        f"{selected_incident.get('rule_severity', selected_incident.get('severity', 'N/D'))}"
    )

    # ==========================================
    # MÉTRICAS VERIFICABLES
    # ==========================================

    st.divider()
    st.subheader("Métricas verificadas")

    metrics = calculate_incident_metrics(
        normalized_df,
        selected_incident,
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Filas de evidencia únicas",
        metrics["event_count"],
    )

    col2.metric(
        "Datos salientes",
        f"{metrics['bytes_out_mib']:.2f} MiB",
    )

    duration = metrics["duration_seconds"]

    col3.metric(
        "Duración",
        f"{duration // 60} min {duration % 60} s"
        if duration is not None
        else "N/D",
    )

    st.write(
        "**Destinos identificados:**",
        ", ".join(metrics["destinations"]) or "No disponibles",
    )

    if metrics["missing_rows"]:
        st.warning(
            "No se pudieron recuperar las filas: "
            + ", ".join(map(str, metrics["missing_rows"]))
        )

    # ==========================================
    # EVALUACIÓN CONTEXTUAL DE RIESGOS
    # ==========================================

    st.divider()
    st.subheader("Evaluación de riesgos con IA")

    st.write(
        "**Severidad del detector:**",
        selected_incident.get(
            "rule_severity",
            selected_incident.get("severity", "N/D"),
        ),
    )

    if st.button(
        "Evaluar riesgo con IA",
        key="evaluate_risk_button",
    ):
        with st.spinner("Ollama está evaluando las evidencias..."):
            try:
                evaluation = evaluate_incident_risk(
                    selected_incident,
                    metrics=metrics,
                )

                st.session_state.setdefault(
                    "risk_evaluations", {}
                )[selected_id] = evaluation

                # Invalidar revisión anterior
                review_key = (
                    st.session_state.get("analysis_key", ""),
                    selected_id,
                )

                st.session_state.setdefault(
                    "risk_reviews", {}
                ).pop(review_key, None)

                st.session_state.pop(
                    f"analyst_comment_{selected_id}",
                    None,
                )

                st.session_state.pop("prepared_pdf", None)

                st.success("Evaluación generada correctamente.")

            except (OllamaError, RiskEvaluationError) as exc:
                st.error(
                    f"No se pudo evaluar el incidente: {exc}"
                )

    evaluation = st.session_state.get(
        "risk_evaluations", {}
    ).get(selected_id)

    if evaluation:
        st.write(
            "**Severidad propuesta por IA:**",
            evaluation.get("ai_severity", "N/D"),
        )

        st.write(
            "**Confianza de la IA:**",
            evaluation.get("ai_confidence", "N/D"),
        )

        st.write(
            "**Justificación:**",
            evaluation.get("ai_reason", "No disponible"),
        )

        evidence_rows = evaluation.get(
            "ai_evidence_rows", []
        )

        st.write("**Filas citadas por la IA:**")

        st.code(
            ", ".join(map(str, evidence_rows))
            if evidence_rows
            else "No se citaron filas específicas.",
            language=None,
        )

        st.caption(
            "La clasificación propuesta por IA "
            "no reemplaza automáticamente "
            "la severidad del detector."
        )

        # ======================================
        # REVISIÓN HUMANA
        # ======================================

        st.divider()
        st.subheader("Revisión del analista SOC")

        review_key = (
            st.session_state.get("analysis_key", ""),
            selected_id,
        )

        st.session_state.setdefault(
            "risk_reviews", {}
        )

        current_review = st.session_state[
            "risk_reviews"
        ].get(review_key)

        if current_review:
            if is_review_current(
                current_review,
                evaluation,
            ):
                st.success(
                    "Estado de revisión: "
                    + current_review["status"]
                )

                st.write(
                    "**Observación del analista:**",
                    current_review["analyst_comment"],
                )
            else:
                st.warning(
                    "La revisión anterior no corresponde "
                    "a la evaluación actual."
                )

        analyst_comment = st.text_area(
            "Observaciones del analista",
            key=f"analyst_comment_{selected_id}",
            placeholder=(
                "Justificá la aceptación o el rechazo "
                "de la clasificación propuesta."
            ),
        )

        col_accept, col_reject = st.columns(2)

        with col_accept:
            accept = st.button(
                "Aceptar clasificación",
                key=f"accept_risk_{selected_id}",
                use_container_width=True,
            )

        with col_reject:
            reject = st.button(
                "Rechazar clasificación",
                key=f"reject_risk_{selected_id}",
                use_container_width=True,
            )

        if accept or reject:
            status = (
                "Aprobada" if accept else "Rechazada"
            )

            try:
                review = create_review(
                    evaluation,
                    status,
                    analyst_comment,
                )

                st.session_state[
                    "risk_reviews"
                ][review_key] = review

                st.session_state.pop(
                    "prepared_pdf", None
                )

                st.success(
                    f"Clasificación {status.lower()} correctamente."
                )

            except ValueError as exc:
                st.error(str(exc))

    # ==========================================
    # INTERPRETACIÓN DEL INCIDENTE
    # ==========================================

    st.divider()
    st.subheader("Interpretación asistida por IA")

    if not check_ollama():
        st.warning(
            "Ollama no está disponible. "
            "Verificá que el servicio esté iniciado."
        )
    else:
        st.success("Ollama está disponible.")

        model_name = st.text_input(
            "Modelo local",
            value="qwen2.5:3b",
        )

        analysis_key = st.session_state.get(
            "analysis_key", ""
        )

        incident_key = (
            analysis_key,
            selected_id,
            model_name,
        )

        if st.button(
            "Analizar incidente con IA",
            key="analyze_incident_button",
        ):
            with st.spinner(
                "Ollama está interpretando el incidente..."
            ):
                try:
                    response = analyze_incident(
                        selected_incident,
                        model=model_name,
                    )

                    st.session_state.setdefault(
                        "ai_reports", {}
                    )[incident_key] = response

                    st.session_state.pop(
                        "prepared_pdf", None
                    )

                except OllamaError as exc:
                    st.error(str(exc))

        report = st.session_state.get(
            "ai_reports", {}
        ).get(incident_key)

        if report:
            st.subheader("Interpretación del incidente")
            st.markdown(report)

            st.caption(
                "Informe generado por IA local. "
                "Requiere revisión de un analista."
            )

    # ==========================================
    # NAVEGACIÓN
    # ==========================================

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.button(
            "🔎 Volver a evidencias",
            on_click=navegar_a,
            args=("Incidentes y evidencias",),
            use_container_width=True,
        )

    with col2:
        st.button(
            "📄 Ir a informes",
            on_click=navegar_a,
            args=("Informes",),
            use_container_width=True,
        )
