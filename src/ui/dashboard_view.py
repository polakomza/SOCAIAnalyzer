
import streamlit as st
import pandas as pd

from src.dashboard.charts import (
    events_timeline,
    rule_distribution,
    severity_distribution,
    top_source_ips,
)


SEVERIDADES = ["Crítico", "Alto", "Medio", "Bajo", "Informativo"]


def navegar_a(destino):
    st.session_state["pagina_actual"] = destino


def texto_lista(valor):
    """Convierte listas u otros valores en texto legible."""
    if valor is None:
        return "N/D"

    if isinstance(valor, (list, tuple, set)):
        return ", ".join(str(item) for item in valor) or "N/D"

    return str(valor)

def abrir_incidente(incident_id):
    st.session_state["selected_incident_id"] = str(incident_id)
    st.session_state["pagina_actual"] = "Incidentes y evidencias"

def render():
    st.header("📊 Dashboard SOC")

    if not st.session_state.get("analysis_completed", False):
        st.info(
            "Todavía no hay un análisis completado. "
            "Importá un archivo Excel para comenzar."
        )

        st.button(
            "📁 Importar registros",
            on_click=navegar_a,
            args=("Importar y analizar",),
            use_container_width=True,
        )
        return

    dashboard_df = st.session_state.get("normalized_df")

    if dashboard_df is None:
        st.warning(
            "No se encontraron registros normalizados "
            "para el análisis activo."
        )
        return

    findings = st.session_state.get("findings", [])
    incidents = st.session_state.get("incidents", [])

    st.caption(
        f"Archivo: {st.session_state.get('source_name', 'N/D')} "
        f"| Hoja: {st.session_state.get('sheet_name', 'N/D')}"
    )

    # ==========================================
    # INDICADORES GENERALES
    # ==========================================

    st.subheader("Indicadores generales")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Eventos analizados", len(dashboard_df))
    col2.metric("Hallazgos detectados", len(findings))
    col3.metric("Incidentes detectados", len(incidents))

    critical_count = sum(
        incident.get("severity") == "Crítico"
        for incident in incidents
    )

    col4.metric("Incidentes críticos", critical_count)

    st.divider()

    # ==========================================
    # FILTROS DE INCIDENTES
    # ==========================================

    st.subheader("Filtros de incidentes")

    col_filtro1, col_filtro2 = st.columns(2)

    severidades_disponibles = [
        severity
        for severity in SEVERIDADES
        if any(
            incident.get("severity") == severity
            for incident in incidents
        )
    ]

    with col_filtro1:
        selected_severities = st.multiselect(
            "Severidad",
            options=severidades_disponibles,
            default=severidades_disponibles,
            key="dashboard_severidades",
        )

    reglas_disponibles = sorted({
        str(rule)
        for incident in incidents
        for rule in (incident.get("rules") or [])
    })

    with col_filtro2:
        selected_rules = st.multiselect(
            "Reglas de detección",
            options=reglas_disponibles,
            key="dashboard_reglas",
            placeholder="Todas las reglas",
        )

    filtered_incidents = [
        incident
        for incident in incidents
        if (
            incident.get("severity") in selected_severities
            and (
                not selected_rules
                or any(
                    rule in selected_rules
                    for rule in (incident.get("rules") or [])
                )
            )
        )
    ]

    st.caption(
        f"Mostrando {len(filtered_incidents)} "
        f"de {len(incidents)} incidentes."
    )

    # ==========================================
    # GRÁFICOS
    # ==========================================

    st.divider()
    st.subheader("Visualización de seguridad")

    left, right = st.columns(2)

    with left:
        fig = events_timeline(dashboard_df)

        if fig is not None:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay fechas válidas para graficar.")

    with right:
        fig = severity_distribution(filtered_incidents)

        if fig is not None:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay incidentes para graficar.")

    left, right = st.columns(2)

    with left:
        fig = top_source_ips(dashboard_df)

        if fig is not None:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay direcciones IP disponibles.")

    with right:
        fig = rule_distribution(findings)

        if fig is not None:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay reglas activadas.")

    st.caption(
        "Los gráficos de severidad utilizan los incidentes "
        "filtrados. Los demás muestran el conjunto completo "
        "de eventos o hallazgos del análisis."
    )

    # ==========================================
    # TABLA DE INCIDENTES
    # ==========================================

    st.divider()
    st.subheader("Resumen de incidentes")

    if not filtered_incidents:
        st.info(
            "No hay incidentes que coincidan "
            "con los filtros seleccionados."
        )
        return

    incident_rows = []

    for incident in filtered_incidents:
        incident_rows.append({
            "ID": incident.get("incident_id", "N/D"),
            "Severidad": incident.get("severity", "N/D"),
            "Inicio": incident.get("first_seen", "N/D"),
            "Fin": incident.get("last_seen", "N/D"),
            "Hallazgos": incident.get("findings_count", 0),
            "Reglas": texto_lista(incident.get("rules")),
            "IP involucradas": texto_lista(
                incident.get("source_ips")
            ),
            "Usuarios": texto_lista(incident.get("users")),
        })

    incident_table = pd.DataFrame(incident_rows)

    st.dataframe(
        incident_table,
        use_container_width=True,
        hide_index=True,
    )
    st.subheader("Investigar un incidente")

    incident_ids = [
    str(incident["incident_id"])
    for incident in filtered_incidents
    ]

    selected_dashboard_incident = st.selectbox(
        "Seleccioná el incidente",
        options=incident_ids,
        key="dashboard_incident_selector",
    )

    st.button(
        "🔍 Abrir incidente seleccionado",
        on_click=abrir_incidente,
        args=(selected_dashboard_incident,),
        use_container_width=True,
    )
