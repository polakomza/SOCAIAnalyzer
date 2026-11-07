
import streamlit as st
import pandas as pd

from src.analysis.evidence_viewer import (
    get_incident_evidence,
    get_finding_evidence,
)


def navegar_a(destino):
    st.session_state["pagina_actual"] = destino


def seleccionar_incidente(incident_id):
    st.session_state["selected_incident_id"] = str(incident_id)


def texto_lista(valor):
    if valor is None:
        return "N/D"

    if isinstance(valor, (list, tuple, set)):
        return ", ".join(str(item) for item in valor) or "N/D"

    return str(valor)


def render():
    st.header("🔎 Incidentes y evidencias")

    if not st.session_state.get("analysis_completed", False):
        st.info("Primero importá y analizá registros.")
        st.button(
            "📁 Importar registros",
            on_click=navegar_a,
            args=("Importar y analizar",),
        )
        return

    result = st.session_state.get("normalized_df")
    incidents = st.session_state.get("incidents", [])
    findings = st.session_state.get("findings", [])

    if result is None:
        st.warning("No hay registros normalizados disponibles.")
        return

    # ==========================================
    # INDICADORES
    # ==========================================

    col1, col2, col3 = st.columns(3)

    col1.metric("Incidentes consolidados", len(incidents))
    col2.metric("Hallazgos detectados", len(findings))

    col3.metric(
        "Incidentes críticos",
        sum(
            incident.get("severity") == "Crítico"
            for incident in incidents
        ),
    )

    if not incidents:
        st.info("No se identificaron incidentes.")

        if findings:
            with st.expander("Consultar hallazgos detectados"):
                for finding in findings:
                    st.write(
                        f"**{finding.get('rule_id', 'N/D')}**: "
                        f"{finding.get('description', 'Sin descripción')}"
                    )
        return

    st.divider()

    # ==========================================
    # SELECCIÓN DE INCIDENTES
    # ==========================================

    st.subheader("Seleccionar incidente")

    incident_by_id = {
        str(incident["incident_id"]): incident
        for incident in incidents
    }

    incident_ids = list(incident_by_id.keys())

    selected_id = st.session_state.get("selected_incident_id")

    if selected_id not in incident_by_id:
        selected_id = incident_ids[0]
        st.session_state["selected_incident_id"] = selected_id

    selected_id = st.selectbox(
        "Incidente a investigar",
        options=incident_ids,
        index=incident_ids.index(selected_id),
        format_func=lambda incident_id: (
            f"{incident_id} | "
            f"{incident_by_id[incident_id].get('severity', 'N/D')} | "
            f"{incident_by_id[incident_id].get('findings_count', 0)} hallazgos"
        ),
        key="incident_selector",
    )

    st.session_state["selected_incident_id"] = selected_id

    incident = incident_by_id[selected_id]

    # ==========================================
    # DETALLE DEL INCIDENTE
    # ==========================================

    st.divider()
    st.subheader(f"Investigación: {selected_id}")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Severidad",
        incident.get("severity", "N/D"),
    )

    col2.metric(
        "Hallazgos asociados",
        incident.get("findings_count", 0),
    )

    col3.metric(
        "Filas de evidencia",
        len(incident.get("evidence_rows") or []),
    )

    with st.container(border=True):
        st.write("**Primer evento:**", incident.get("first_seen", "N/D"))
        st.write("**Último evento:**", incident.get("last_seen", "N/D"))
        st.write("**Reglas activadas:**", texto_lista(incident.get("rules")))
        st.write("**IP involucradas:**", texto_lista(incident.get("source_ips")))
        st.write("**Usuarios involucrados:**", texto_lista(incident.get("users")))
        st.write("**Filas de evidencia:**", incident.get("evidence_rows", []))

    # ==========================================
    # EVIDENCIAS VERIFICABLES
    # ==========================================

    st.subheader("Evidencias verificables")

    evidence_df = get_incident_evidence(result, incident)

    if evidence_df.empty:
        st.warning("No se encontraron registros asociados.")
    else:
        st.caption(f"Registros relacionados: {len(evidence_df)}")

        preferred_columns = [
            "source_row",
            "normalized_timestamp",
            "normalized_event_type",
            "normalized_source_ip",
            "username",
            "destination",
            "event_description",
            "normalized_command",
            "result",
        ]

        available_columns = [
            column
            for column in preferred_columns
            if column in evidence_df.columns
        ]

        st.dataframe(
            evidence_df[available_columns]
            if available_columns
            else evidence_df,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "⬇️ Exportar evidencias CSV",
            data=evidence_df.to_csv(index=False).encode("utf-8-sig"),
            file_name=f"evidencias_{selected_id}.csv",
            mime="text/csv",
            key=f"evidence_csv_{selected_id}",
        )

    # ==========================================
    # HALLAZGOS ASOCIADOS
    # ==========================================

    st.divider()
    st.subheader("Hallazgos asociados")

    associated_findings = incident.get("findings") or []

    for index, finding in enumerate(associated_findings, start=1):
        with st.expander(
            f"{index}. {finding.get('rule_id', 'N/D')} "
            f"| {finding.get('severity', 'N/D')}"
        ):
            st.write(
                "**Descripción:**",
                finding.get("description", "Sin descripción"),
            )

            st.write(
                "**Justificación de severidad:**",
                finding.get("severity_reason", "No disponible"),
            )

            st.write(
                "**Primer evento:**",
                finding.get("first_seen", "N/D"),
            )

            st.write(
                "**Último evento:**",
                finding.get("last_seen", "N/D"),
            )

            st.write(
                "**Intentos fallidos:**",
                finding.get("failed_attempts", "N/D"),
            )

            st.write(
                "**Acceso exitoso posterior:**",
                "Sí" if finding.get("success_after_failures") else "No",
            )

            finding_df = get_finding_evidence(result, finding)

            if finding_df.empty:
                st.info("No hay registros disponibles.")
            else:
                st.dataframe(
                    finding_df,
                    use_container_width=True,
                    hide_index=True,
                )

    # ==========================================
    # NAVEGACIÓN A IA
    # ==========================================

    st.divider()

    st.info(
        "Podés continuar la investigación utilizando "
        "el módulo de análisis con inteligencia artificial."
    )

    st.button(
        "🤖 Continuar análisis con IA",
        use_container_width=True,
        on_click=navegar_a,
        args=("Análisis con IA",),
        key="incident_ir_ia",
    )
