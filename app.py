
import streamlit as st

from src.storage.database import init_database
from src.ui import (
    ai_view,
    dashboard_view,
    import_view,
    incidents_view,
    reports_view,
)
from src.ui.session_manager import inicializar_sesion


st.set_page_config(
    page_title="SOC AI Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_database()
inicializar_sesion()

# ==========================================
# ESTILOS GENERALES
# ==========================================

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    [data-testid="stSidebar"] {
        border-right: 1px solid rgba(128, 128, 128, 0.18);
    }

    div[data-testid="stMetric"] {
        border: 1px solid rgba(128, 128, 128, 0.20);
        border-radius: 12px;
        padding: 14px;
    }

    div.stButton > button {
        border-radius: 8px;
    }

    h1, h2, h3 {
        letter-spacing: -0.4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ==========================================
# ENCABEZADO
# ==========================================

st.title("🛡️ SOC AI Analyzer")
st.caption(
    "Plataforma local de análisis de eventos de seguridad, "
    "correlación de incidentes y evaluación asistida por IA."
)

# ==========================================
# NAVEGACIÓN
# ==========================================

pages = {
    "📊 Dashboard SOC": dashboard_view.render,
    "📥 Importar y analizar": import_view.render,
    "🔎 Incidentes y evidencias": incidents_view.render,
    "🤖 Análisis con IA": ai_view.render,
    "📄 Informes": reports_view.render,
}

# Mantener compatibilidad con nombres anteriores.
page_names = list(pages)

old_to_new = {
    "Dashboard SOC": "📊 Dashboard SOC",
    "Importar y analizar": "📥 Importar y analizar",
    "Incidentes y evidencias": "🔎 Incidentes y evidencias",
    "Análisis con IA": "🤖 Análisis con IA",
    "Informes": "📄 Informes",
}

current_page = st.session_state.get(
    "pagina_actual",
    "📥 Importar y analizar",
)

if current_page in old_to_new:
    st.session_state["pagina_actual"] = old_to_new[current_page]

if st.session_state.get("pagina_actual") not in pages:
    st.session_state["pagina_actual"] = "📥 Importar y analizar"

with st.sidebar:
    st.markdown("### 🛡️ SOC AI Analyzer")
    st.caption("Centro de operaciones de seguridad")

    st.divider()

    page = st.radio(
        "Navegación",
        page_names,
        key="pagina_actual",
    )

    st.divider()

    st.markdown("**Estado del sistema**")

    if st.session_state.get("analysis_completed", False):
        incidents = st.session_state.get("incidents", [])

        st.success("Análisis completado")
        st.metric("Incidentes detectados", len(incidents))
    else:
        st.info("Sin análisis activo")

    st.divider()
    st.caption("SOC AI Analyzer | Proyecto académico")

# ==========================================
# VISTA ACTIVA
# ==========================================

pages[page]()

# ==========================================
# DESPLAZAMIENTO AL CAMBIAR DE PÁGINA
# ==========================================

if st.session_state.get("_ultima_pagina") != page:
    st.session_state["_ultima_pagina"] = page

    st.components.v1.html(
        """
        <script>
            const parentWindow = window.parent;
            const main = parentWindow.document.querySelector(
                '[data-testid="stMain"]'
            );

            if (main) {
                main.scrollTo({
                    top: 0,
                    behavior: "instant"
                });
            }
        </script>
        """,
        height=0,
    )
