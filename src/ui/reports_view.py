
import streamlit as st
import pandas as pd

from src.reports.pdf_exporter import generate_pdf
from src.reports.report_builder import build_report
from src.ai.risk_review import is_review_current
from src.analysis.incident_metrics import calculate_incident_metrics
from src.storage.database import (
    save_analysis,
    list_analyses,
    load_analysis,
    save_risk_results,
    load_risk_results,
)


def invalidar_pdf():
    """Invalida el PDF anterior cuando cambian sus opciones."""
    st.session_state.pop("prepared_pdf", None)


def render():
    st.header("📄 Informes")

    required_keys = (
        "findings",
        "incidents",
        "normalized_df",
        "valid_events_count",
        "analysis_key",
    )

    has_active_analysis = (
        st.session_state.get("analysis_completed", False)
        and all(key in st.session_state for key in required_keys)
    )

    if has_active_analysis:
        current_findings = st.session_state["findings"]
        current_incidents = st.session_state["incidents"]
        analysis_key = st.session_state["analysis_key"]
        normalized_df = st.session_state["normalized_df"]

        analysis_info = {
            "id": analysis_key[:12],
            "source_name": st.session_state.get(
                "source_name", "Desconocido"
            ),
            "sheet_name": st.session_state.get(
                "sheet_name", "Desconocida"
            ),
            "total_events": len(normalized_df),
            "valid_events": st.session_state["valid_events_count"],
        }

        # ==========================================
        # RESUMEN DEL ANÁLISIS
        # ==========================================

        st.subheader("Resumen del análisis")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Eventos procesados",
            analysis_info["total_events"],
        )

        col2.metric(
            "Hallazgos",
            len(current_findings),
        )

        col3.metric(
            "Incidentes",
            len(current_incidents),
        )

        col4.metric(
            "Incidentes críticos",
            sum(
                incident.get("severity") == "Crítico"
                for incident in current_incidents
            ),
        )

        st.caption(
            f"Archivo: {analysis_info['source_name']} | "
            f"Hoja: {analysis_info['sheet_name']} | "
            f"Identificador: {analysis_info['id']}"
        )

        # ==========================================
        # CONFIGURACIÓN DEL INFORME
        # ==========================================

        st.subheader("Contenido del informe")

        include_ai = st.checkbox(
            "Incluir interpretaciones de incidentes generadas por IA",
            value=False,
            key="report_include_ai",
            on_change=invalidar_pdf,
        )

        include_risk = st.checkbox(
            "Incluir evaluaciones de riesgo y revisiones del analista",
            value=True,
            key="report_include_risk",
            on_change=invalidar_pdf,
        )

        st.caption(
            "Las evaluaciones de IA son recomendaciones. "
            "La aprobación o el rechazo del analista "
            "se registra por separado."
        )

        # Interpretaciones de IA del análisis actual.
        ai_by_incident = {}

        for key, response in st.session_state.get(
            "ai_reports", {}
        ).items():
            if (
                isinstance(key, tuple)
                and len(key) == 3
                and key[0] == analysis_key
            ):
                ai_by_incident[str(key[1])] = response

        # Evaluaciones y revisiones vigentes.
        all_evaluations = st.session_state.get(
            "risk_evaluations", {}
        )

        all_reviews = st.session_state.get(
            "risk_reviews", {}
        )

        risk_evaluations_for_pdf = {}
        risk_reviews_for_pdf = {}

        for incident in current_incidents:
            incident_id = str(incident["incident_id"])

            evaluation = all_evaluations.get(incident_id)

            if evaluation is not None:
                risk_evaluations_for_pdf[incident_id] = evaluation

                review = all_reviews.get(
                    (analysis_key, incident_id)
                )

                if review and is_review_current(
                    review, evaluation
                ):
                    risk_reviews_for_pdf[incident_id] = review

        # ==========================================
        # GENERACIÓN DEL PDF
        # ==========================================

        if st.button(
            "Preparar informe PDF",
            key="prepare_report_pdf",
        ):
            invalidar_pdf()

            try:
                with st.spinner("Generando informe técnico..."):
                    metrics_for_pdf = {
                        str(incident["incident_id"]):
                        calculate_incident_metrics(
                            normalized_df,
                            incident,
                        )
                        for incident in current_incidents
                    }

                    report = build_report(
                        analysis_info=analysis_info,
                        findings=current_findings,
                        incidents=current_incidents,
                        ai_reports=(
                            ai_by_incident if include_ai else {}
                        ),
                        risk_evaluations=(
                            risk_evaluations_for_pdf
                            if include_risk else {}
                        ),
                        risk_reviews=(
                            risk_reviews_for_pdf
                            if include_risk else {}
                        ),
                        incident_metrics=metrics_for_pdf,
                    )

                    pdf_bytes = generate_pdf(report)

                    if not pdf_bytes:
                        raise ValueError(
                            "El generador devolvió un PDF vacío."
                        )

                    st.session_state["prepared_pdf"] = {
                        "analysis_key": analysis_key,
                        "include_ai": include_ai,
                        "include_risk": include_risk,
                        "content": pdf_bytes,
                    }

                st.success(
                    "Informe PDF preparado correctamente."
                )

            except Exception as exc:
                st.error(
                    f"No se pudo generar el informe: {exc}"
                )

        prepared = st.session_state.get("prepared_pdf")

        if prepared is not None:
            is_current = (
                prepared.get("analysis_key") == analysis_key
                and prepared.get("include_ai") == include_ai
                and prepared.get("include_risk") == include_risk
            )

            if is_current and prepared.get("content"):
                st.download_button(
                    "📥 Descargar informe técnico PDF",
                    data=prepared["content"],
                    file_name=(
                        f"informe_SOC_{analysis_key[:12]}.pdf"
                    ),
                    mime="application/pdf",
                    use_container_width=True,
                )

            elif not is_current:
                invalidar_pdf()

    else:
        st.info(
            "Primero ejecutá un análisis de seguridad "
            "para generar un PDF."
        )

    # ==========================================
    # ALMACENAMIENTO E HISTORIAL
    # ==========================================

    with st.expander(
        "Almacenamiento e historial (opcional)",
        expanded=False,
    ):
        if has_active_analysis:
            st.subheader("Guardar análisis")

            st.write(
                "Guardá los resultados para consultarlos "
                "en futuras sesiones."
            )

            if st.button(
                "Guardar análisis en SQLite",
                key="save_analysis_sqlite",
            ):
                try:
                    analysis_id, created = save_analysis(
                        analysis_key=analysis_key,
                        source_name=analysis_info["source_name"],
                        sheet_name=analysis_info["sheet_name"],
                        total_events=len(normalized_df),
                        valid_events=st.session_state[
                            "valid_events_count"
                        ],
                        findings=current_findings,
                        incidents=current_incidents,
                    )

                    # Guardar evaluaciones y revisiones
                    # asociadas a esta versión del análisis.
                    save_risk_results(
                        analysis_key=analysis_key,
                        risk_evaluations=risk_evaluations_for_pdf,
                        risk_reviews=risk_reviews_for_pdf,
                        analysis_id=analysis_id,
                    )

                    if created:
                        st.success(
                            f"Análisis #{analysis_id} "
                            "guardado correctamente."
                        )
                    else:
                        st.success(
                            f"Análisis #{analysis_id}: "
                            "resultados idénticos. "
                            "No se creó un duplicado; "
                            "se actualizaron los datos de riesgo."
                        )

                    st.caption(
                        "Evaluaciones guardadas: "
                        f"{len(risk_evaluations_for_pdf)} | "
                        "Revisiones vigentes guardadas: "
                        f"{len(risk_reviews_for_pdf)}"
                    )

                except Exception as exc:
                    st.error(
                        f"No se pudo guardar el análisis: {exc}"
                    )

        # ==========================================
        # HISTORIAL DE ANÁLISIS
        # ==========================================

        st.divider()
        st.subheader("Historial de análisis")

        try:
            history = list_analyses()

        except Exception as exc:
            st.error(
                f"No se pudo consultar el historial: {exc}"
            )
            return

        if not history:
            st.info("Todavía no hay análisis guardados.")
            return

        history_df = pd.DataFrame(history)

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

        history_by_id = {
            row["id"]: row for row in history
        }

        selected_id = st.selectbox(
            "Seleccionar análisis",
            options=list(history_by_id),
            format_func=lambda value: (
                f"Análisis #{value} — "
                f"{history_by_id[value]['source_name']}"
            ),
            key="history_analysis_selector",
        )

        if st.button(
            "Consultar análisis guardado",
            key="load_saved_analysis",
        ):
            try:
                saved = load_analysis(selected_id)

                if saved is None:
                    st.error(
                        "No se encontró el análisis."
                    )
                    st.session_state.pop(
                        "saved_analysis", None
                    )

                else:
                    saved["risk_results"] = (
                        load_risk_results(selected_id)
                    )

                    st.session_state["saved_analysis"] = saved

            except Exception as exc:
                st.error(
                    f"No se pudo cargar el análisis: {exc}"
                )

        saved = st.session_state.get(
            "saved_analysis"
        )

        if (
            saved
            and saved["analysis"]["id"] not in history_by_id
        ):
            st.session_state.pop(
                "saved_analysis", None
            )
            saved = None

        if saved:
            info = saved["analysis"]

            st.subheader(
                f"Análisis histórico #{info['id']}"
            )

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Eventos procesados",
                info["total_events"],
            )

            col2.metric(
                "Hallazgos",
                len(saved["findings"]),
            )

            col3.metric(
                "Incidentes",
                len(saved["incidents"]),
            )

            st.write(
                "**Archivo:**",
                info["source_name"],
            )

            st.write(
                "**Fecha del análisis:**",
                info["created_at"],
            )

            risk_results = saved.get(
                "risk_results", {}
            )

            stored_evaluations = risk_results.get(
                "risk_evaluations", {}
            )

            stored_reviews = risk_results.get(
                "risk_reviews", {}
            )

            st.caption(
                "Evaluaciones de riesgo guardadas: "
                f"{len(stored_evaluations)} | "
                "Revisiones guardadas: "
                f"{len(stored_reviews)}"
            )

            # ======================================
            # DETALLE DE INCIDENTES HISTÓRICOS
            # ======================================

            for incident in saved["incidents"]:
                incident_id = str(
                    incident["incident_id"]
                )

                with st.expander(
                    f"{incident_id} | "
                    f"{incident['severity']}"
                ):
                    st.write(
                        "**Reglas:**",
                        ", ".join(
                            map(
                                str,
                                incident.get("rules", []),
                            )
                        ),
                    )

                    st.write(
                        "**IP involucradas:**",
                        ", ".join(
                            map(
                                str,
                                incident.get("source_ips", []),
                            )
                        ),
                    )

                    st.write(
                        "**Usuarios:**",
                        ", ".join(
                            map(
                                str,
                                incident.get("users", []),
                            )
                        ),
                    )

                    st.write(
                        "**Evidencia:**",
                        incident.get(
                            "evidence_rows", []
                        ),
                    )

                    evaluation = stored_evaluations.get(
                        incident_id
                    )

                    review = stored_reviews.get(
                        incident_id
                    )

                    if evaluation:
                        st.markdown(
                            "**Evaluación de riesgo por IA**"
                        )

                        st.write(
                            "**Severidad propuesta:**",
                            evaluation.get(
                                "ai_severity", "N/D"
                            ),
                        )

                        st.write(
                            "**Confianza declarada:**",
                            evaluation.get(
                                "ai_confidence", "N/D"
                            ),
                        )

                        st.write(
                            "**Justificación:**",
                            evaluation.get(
                                "ai_reason", "N/D"
                            ),
                        )

                        st.write(
                            "**Filas citadas:**",
                            evaluation.get(
                                "ai_evidence_rows", []
                            ),
                        )

                        if review and is_review_current(
                            review, evaluation
                        ):
                            st.markdown(
                                "**Revisión del analista**"
                            )

                            st.write(
                                "**Estado:**",
                                review.get(
                                    "status", "N/D"
                                ),
                            )

                            st.write(
                                "**Observación:**",
                                review.get(
                                    "analyst_comment", ""
                                ),
                            )

                            st.write(
                                "**Fecha:**",
                                review.get(
                                    "reviewed_at", "N/D"
                                ),
                            )

                        elif review:
                            st.warning(
                                "Existe una revisión histórica "
                                "que no corresponde a esta evaluación."
                            )

                        else:
                            st.caption(
                                "Evaluación pendiente "
                                "de revisión humana."
                            )
