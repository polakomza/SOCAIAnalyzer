import streamlit as st


RESULT_KEYS = (
    "normalized_df",
    "analysis_key",
    "findings",
    "incidents",
    "valid_events_count",
    "prepared_pdf",
    "ai_reports",
    "risk_evaluations",
    "risk_reviews",
    "selected_incident_id",
)


def inicializar_sesion():
    defaults = {
        "findings": [],
        "incidents": [],
        "risk_evaluations": {},
        "risk_reviews": {},
        "ai_reports": {},
        "analysis_completed": False,
        "uploader_version": 0,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def limpiar_resultados():
    for key in RESULT_KEYS:
        st.session_state.pop(key, None)

    st.session_state["findings"] = []
    st.session_state["incidents"] = []
    st.session_state["risk_evaluations"] = {}
    st.session_state["risk_reviews"] = {}
    st.session_state["ai_reports"] = {}
    st.session_state["analysis_completed"] = False


def limpiar_archivo():
    limpiar_resultados()

    for key in (
        "uploaded_excel_bytes",
        "uploaded_excel_name",
        "uploaded_excel_hash",
        "source_name",
        "sheet_name",
    ):
        st.session_state.pop(key, None)

    st.session_state["uploader_version"] += 1
