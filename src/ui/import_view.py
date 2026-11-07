import streamlit as st
import hashlib
import json
from io import BytesIO
from types import SimpleNamespace
import pandas as pd
from src.ingestion.column_mapper import apply_mapping, load_aliases, suggest_mapping
from src.ingestion.normalizer import normalize_dataframe
from src.analysis.validator import validate_for_brute_force
from src.analysis.detector import detect_brute_force
from src.analysis.advanced_detector import detect_advanced_threats
from src.analysis.windows_detector import detect_windows_threats
from src.analysis.web_detector import detect_web_threats
from src.analysis.network_detector import detect_network_threats
from src.analysis.correlator import correlate_incidents
from src.ui.session_manager import limpiar_resultados, limpiar_archivo

def navegar_a(destino):
    st.session_state["pagina_actual"] = destino
    
def render():
    st.header("Importar y analizar")

    if "uploader_version" not in st.session_state:
        st.session_state["uploader_version"] = 0

    archivo_nuevo = st.file_uploader(
        "Seleccioná un archivo Excel",
        type=["xlsx"],
        key=f"excel_uploader_{st.session_state['uploader_version']}",
    )

    if archivo_nuevo is not None:
        nuevos_bytes = archivo_nuevo.getvalue()
        nuevo_hash = hashlib.sha256(nuevos_bytes).hexdigest()

        if st.session_state.get("uploaded_excel_hash") != nuevo_hash:
            limpiar_resultados()

        st.session_state["uploaded_excel_bytes"] = nuevos_bytes
        st.session_state["uploaded_excel_name"] = archivo_nuevo.name
        st.session_state["uploaded_excel_hash"] = nuevo_hash

    archivo = None

    if st.session_state.get("uploaded_excel_bytes") is not None:
        file_bytes = st.session_state["uploaded_excel_bytes"]

        archivo = SimpleNamespace(
            name=st.session_state["uploaded_excel_name"],
            size=len(file_bytes),
            getvalue=lambda: file_bytes,
        )

        st.success(f"Archivo cargado: {archivo.name}")

        if st.button("🗑️ Quitar archivo y comenzar de nuevo"):
            limpiar_archivo()
            st.rerun()
            
    if archivo is not None:
        if archivo.size > 50 * 1024 * 1024:
            st.error("El archivo supera los 50 MB.")
            st.stop()

        try:
            excel_bytes = archivo.getvalue()

            excel = pd.ExcelFile(BytesIO(excel_bytes), engine="openpyxl")

            hoja = st.selectbox("Seleccioná la hoja", excel.sheet_names)

            df = pd.read_excel(BytesIO(excel_bytes), sheet_name=hoja, engine="openpyxl")

        except Exception:
            st.error("No se pudo leer el archivo Excel.")
            st.stop()

        if df.empty:
            st.warning("La hoja seleccionada está vacía.")
            st.stop()

        if not df.columns.is_unique:
            st.error("Existen nombres de columnas duplicados.")
            st.stop()

        st.success("Archivo importado correctamente.")

        col1, col2, col3 = st.columns(3)

        col1.metric("Eventos", len(df))
        col2.metric("Columnas", len(df.columns))
        col3.metric("Valores faltantes", int(df.isna().sum().sum()))

        st.subheader("Vista previa")

        st.dataframe(df.head(20), use_container_width=True, hide_index=True)

        st.divider()

        st.subheader("Mapeo de columnas")

        st.info("Revisá las asociaciones sugeridas. Podés corregirlas manualmente.")

        suggestions = suggest_mapping(df.columns.tolist())
        aliases = load_aliases()

        options = ["No asignar"] + df.columns.tolist()

        mapping = {}

        for field in aliases.keys():
            suggestion = suggestions.get(field, "No asignar")

            selected = st.selectbox(
                f"Campo normalizado: {field}",
                options=options,
                index=options.index(suggestion),
                key=f"map_v2_{field}_{archivo.name}_{hoja}",
            )

            if selected != "No asignar":
                mapping[field] = selected

        selected_columns = list(mapping.values())

        if len(selected_columns) != len(set(selected_columns)):
            st.error(
                "Una columna original no puede asignarse a varios campos normalizados."
            )
            st.stop()

        st.divider()

        st.subheader("Normalización")

        dayfirst = st.checkbox(
            "Interpretar fechas ambiguas como día/mes/año",
            value=True,
            help=(
                "Activá esta opción para fechas como 03/11/2026 "
                "cuando representan el 3 de noviembre."
            ),
        )

        analysis_config = {
            "file_hash": hashlib.sha256(archivo.getvalue()).hexdigest(),
            "sheet": hoja,
            "mapping": mapping,
            "dayfirst": dayfirst,
        }

        analysis_key = hashlib.sha256(
            json.dumps(analysis_config, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()


        st.session_state["source_name"] = archivo.name
        st.session_state["sheet_name"] = hoja

        if st.session_state.get("analysis_key") != analysis_key:
            for key in (
                "normalized_df",
                "findings",
                "incidents",
                "valid_events_count",
                "prepared_pdf",
                "ai_reports",
                "risk_evaluations",
                "risk_reviews",
            ):
                st.session_state.pop(key, None)

            st.session_state["analysis_key"] = analysis_key
            st.session_state["findings"] = []
            st.session_state["incidents"] = []
            st.session_state["valid_events_count"] = 0
            st.session_state["risk_evaluations"] = {}
            st.session_state["risk_reviews"] = {}
            st.session_state["ai_reports"] = {}
            st.session_state["analysis_completed"] = False
            st.session_state.pop("selected_incident_id", None)

        if st.button("Normalizar registros"):
            # Aplicar el mapeo de columnas
            mapped_df = apply_mapping(df, mapping)

            # Ejecutar la normalización
            normalized_df = normalize_dataframe(
                mapped_df, source_name=archivo.name, sheet_name=hoja, dayfirst=dayfirst
            )

            # Guardar resultados en la sesión
            st.session_state["normalized_df"] = normalized_df
            st.session_state["analysis_completed"] = False
            st.session_state["findings"] = []
            st.session_state["incidents"] = []
            st.session_state["risk_evaluations"] = {}
            st.session_state["risk_reviews"] = {}
            st.session_state["ai_reports"] = {}
            st.session_state.pop("prepared_pdf", None)
            st.session_state.pop("selected_incident_id", None)



        # ==========================================
        # DIAGNÓSTICOS Y CONTROL DE CALIDAD
        # ==========================================

        if "normalized_df" in st.session_state:

            result = st.session_state["normalized_df"]

            # ==========================================
            # REGISTROS NORMALIZADOS
            # ==========================================

            st.subheader("Registros normalizados")

            st.dataframe(
                result.head(20),
                use_container_width=True,
                hide_index=True,
            )

            # ==========================================
            # CONTROL DE CALIDAD
            # ==========================================

            st.subheader("Control de calidad")

            col1, col2, col3 = st.columns(3)

            col1.metric("Registros procesados", len(result))

            if "normalized_timestamp" in result.columns:
                invalid_dates = result["normalized_timestamp"].isna().sum()
                col2.metric("Fechas no válidas", int(invalid_dates))
            else:
                col2.metric("Fechas no válidas", "N/D")

            if "source_ip_category" in result.columns:
                invalid_ips = (
                    result["source_ip_category"] == "Inválida"
                ).sum()

                col3.metric("IP inválidas", int(invalid_ips))
            else:
                col3.metric("IP inválidas", "N/D")

            st.info(
                "Los registros originales se conservan. "
                "Los campos normalizados están preparados "
                "para el motor de detección."
            )

            # ==========================================
            # DIAGNÓSTICOS TÉCNICOS AVANZADOS
            # ==========================================

            with st.expander(
                "Diagnósticos técnicos avanzados",
                expanded=False,
            ):

                # --------------------------------------
                # DIAGNÓSTICO DE COMANDOS
                # --------------------------------------

                st.subheader("Diagnóstico de comandos")

                if "normalized_command" not in result.columns:
                    st.warning(
                        "No existe normalized_command. "
                        "Revisar el mapeo de Process_CommandLine."
                    )
                else:
                    commands = result[
                        result["normalized_command"]
                        .fillna("")
                        .ne("")
                    ]

                    st.metric(
                        "Eventos con comandos",
                        len(commands),
                    )

                    command_columns = [
                        "source_row",
                        "normalized_event_type",
                        "normalized_command",
                    ]

                    available_command_columns = [
                        col
                        for col in command_columns
                        if col in commands.columns
                    ]

                    st.dataframe(
                        commands[available_command_columns].head(30),
                        use_container_width=True,
                        hide_index=True,
                    )

                st.divider()

                # --------------------------------------
                # DIAGNÓSTICO DE NORMALIZACIÓN
                # --------------------------------------

                st.subheader("Diagnóstico de normalización")

                if "normalized_event_type" in result.columns:

                    event_counts = (
                        result["normalized_event_type"]
                        .value_counts(dropna=False)
                        .reset_index()
                    )

                    event_counts.columns = [
                        "Tipo de evento",
                        "Cantidad",
                    ]

                    st.dataframe(
                        event_counts,
                        use_container_width=True,
                        hide_index=True,
                    )

                    st.metric(
                        "Eventos normalizados",
                        len(result),
                    )

                else:
                    st.warning(
                        "No se encontró la columna "
                        "normalized_event_type."
                    )

                st.divider()

                # --------------------------------------
                # DIAGNÓSTICO DE EVENTOS DE RED
                # --------------------------------------

                st.subheader("Diagnóstico de eventos de red")

                network_types = [
                    "proxy_access",
                    "network_connection_allowed",
                    "network_share_access",
                    "network_share_access_check",
                ]

                if "normalized_event_type" in result.columns:

                    network_df = result[
                        result["normalized_event_type"].isin(
                            network_types
                        )
                    ]

                    st.metric(
                        "Eventos de red identificados",
                        len(network_df),
                    )

                    st.write("Columnas disponibles:")
                    st.code(", ".join(result.columns.tolist()))

                    preferred_columns = [
                        "source_row",
                        "normalized_timestamp",
                        "normalized_event_type",
                        "normalized_source_ip",
                        "normalized_destination_ip",
                        "destination",
                        "hostname",
                        "event_description",
                        "result",
                        "normalized_command",
                    ]

                    available_columns = [
                        col
                        for col in preferred_columns
                        if col in network_df.columns
                    ]

                    for event_type in network_types:

                        subset = network_df[
                            network_df["normalized_event_type"]
                            == event_type
                        ]

                        if not subset.empty:

                            st.write(
                                f"**{event_type}: "
                                f"{len(subset)} eventos**"
                            )

                            st.dataframe(
                                subset[available_columns].head(10),
                                use_container_width=True,
                                hide_index=True,
                            )

                else:
                    st.warning(
                        "No existe normalized_event_type."
                    )


            st.divider()

            st.subheader("Análisis de seguridad")

            if st.button("Ejecutar análisis de seguridad"):
                # Invalidar resultados derivados del análisis anterior.
                st.session_state["analysis_completed"] = False
                st.session_state["findings"] = []
                st.session_state["incidents"] = []
                st.session_state["risk_reviews"] = {}
                st.session_state["risk_evaluations"] = {}
                st.session_state["ai_reports"] = {}
                st.session_state.pop("prepared_pdf", None)
                st.session_state.pop("selected_incident_id", None)

                # Validación específica para autenticaciones
                valid_df, warnings = validate_for_brute_force(result)

                for warning in warnings:
                    st.warning(warning)

                # Detectores de autenticación
                basic_findings = []
                advanced_findings = []

                if not valid_df.empty:
                    basic_findings = detect_brute_force(valid_df)
                    advanced_findings = detect_advanced_threats(valid_df)
                else:
                    st.info(
                        "No hay Eventos válidos para autenticación"
                        "Se ejecutarán los "
                        "demás detectores disponibles."
                    )

                # Detector Windows: recibe todos los registros
                windows_findings = detect_windows_threats(result)

                # Detectores de amenazas web
                web_findings = detect_web_threats(result)

                # Detectores de amenazas de red
                network_findings = detect_network_threats(result)

                # Consolidar todos los hallazgos
                findings = (
                    basic_findings
                    + advanced_findings
                    + windows_findings
                    + web_findings
                    + network_findings
                )

                incidents = correlate_incidents(findings)

                # Guardar resultados finales
                st.session_state["findings"] = findings
                st.session_state["incidents"] = incidents
                st.session_state["analysis_completed"] = True
                st.session_state["valid_events_count"] = len(valid_df)

            if st.session_state.get("analysis_completed", False):

                st.success(
                    f"Análisis completado: "
                    f"{len(st.session_state['findings'])} hallazgos y "
                    f"{len(st.session_state['incidents'])} incidentes."
                )

                st.info(
                    "Los resultados están disponibles. "
                    "Seleccioná dónde querés consultarlos."
                )

                col1, col2 = st.columns(2)

                with col1:
                    st.button(
                        "📊 Ver Dashboard SOC",
                        use_container_width=True,
                        key="ir_dashboard",
                        on_click=navegar_a,
                        args=("Dashboard SOC",),
                    )

                with col2:
                    st.button(
                        "🔎 Ver incidentes y evidencias",
                        use_container_width=True,
                        key="ir_incidentes",
                        on_click=navegar_a,
                        args=("Incidentes y evidencias",),
                    )
