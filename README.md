SOC AI Analyzer
Aplicación local de apoyo al análisis de registros de seguridad (SOC), desarrollada con Python y Streamlit. Permite importar registros de eventos desde Excel, normalizarlos, detectar patrones sospechosos, correlacionar hallazgos en incidentes, visualizar métricas y generar informes técnicos. Incorpora evaluaciones de riesgo asistidas por un modelo de lenguaje local mediante Ollama, sujetas a revisión humana.
Alcance: herramienta académica/prototipo de apoyo al analista SOC. Sus detecciones y evaluaciones de IA no confirman por sí solas una intrusión y deben verificarse con evidencia adicional.

Funcionalidades
- Importación de archivos .xlsx y selección de hoja.
- Mapeo y normalización de columnas de distintas fuentes de registros.
- Reglas de detección y correlación de eventos en incidentes.
- Dashboard con métricas y gráficos de seguridad.
- Exploración de incidentes y referencias a las filas originales de evidencia.
- Interpretación de incidentes y propuesta de riesgo con IA local (Ollama).
- Aprobación o rechazo de evaluaciones por parte del analista.
- Generación y descarga de informes técnicos PDF.
- Historial local en SQLite, con versiones cuando cambian los resultados.

Tecnologías
Python, Streamlit, pandas, openpyxl, Plotly, SQLite, requests, ReportLab, pypdf y Ollama (modelo qwen2.5:3b por defecto en la versión revisada).
Requisitos
- Python 3.13 (version probada) No esta verificada la compatibilidad con otras versiones.
- Ollama instalado y en ejecución solo para utilizar las funciones de IA.
- Se utiliza qwen2.5:3b como modelo configurado por defecto de Ollama.
- Espacio y memoria suficientes para ejecutar el modelo local elegido.

Instalación
git clone <URL-DE-TU-REPOSITORIO>
cd <CARPETA-DEL-REPOSITORIO>
python -m venv .venv
Activar el entorno virtual:

Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
Linux/macOS:
source .venv/bin/activate
Instalar dependencias:
python -m pip install -r requirements.txt
Ejecutar la aplicación desde la raíz del proyecto:
streamlit run app.py
IA local (opcional)
Instalar Ollama desde su sitio oficial: https://ollama.com/

Descargar el modelo configurado por defecto:
ollama pull qwen2.5:3b
Asegurarse de que Ollama esté ejecutándose y accesible en http://127.0.0.1:11434. El análisis basado en reglas y el historial pueden utilizarse sin el modelo; las funciones de IA requieren que esté disponible.

Flujo de uso
1. Importar un archivo Excel de registros y elegir la hoja.
2. Revisar el mapeo de columnas y ejecutar el análisis.
3. Examinar el dashboard, los hallazgos y los incidentes correlacionados.
4. Consultar la evidencia y las filas de origen.
5. Solicitar la evaluación de riesgo mediante IA y revisarla como analista.
6. Generar el informe PDF y guardar una versión del análisis en SQLite.
7. Consultar el historial para recuperar resultados previos.
Estructura principal
app.py                 # Entrada de Streamlit
src/ui/                # Vistas de la interfaz
src/analysis/          # Detectores, correlación y métricas
src/ai/                # Integración con Ollama y evaluación de riesgo
src/dashboard/         # Gráficos
src/reports/           # Construcción y exportación PDF
src/storage/           # Persistencia SQLite
config/                # Reglas y alias de columnas
tests/                 # Pruebas automatizadas

Pruebas
Si el repositorio contiene la carpeta tests/, instalar pytest y ejecutar:
python -m pip install pytest
python -m pytest -q

Privacidad y limitaciones
- La base SQLite y los archivos de registros pueden contener datos sensibles: no publicarlos en GitHub.
- El modelo de IA local puede equivocarse o producir explicaciones no sustentadas. La revisión humana es obligatoria antes de adoptar conclusiones.
- Las referencias a filas del Excel permiten localizar la evidencia original; no reemplazan un procedimiento formal de preservación y cadena de custodia.
- La disponibilidad de IA depende del servicio Ollama y del modelo instalado.
Autoría
Proyecto académico de desarrollo y ciberseguridad para el cursado de SOC N2 de Comunidad DOJO junto a WoSEC PANAMA.Desarrollado por Eduardo Maximiliano Nuñez. Linkedin: https://www.linkedin.com/in/maximiliano-nu%C3%B1ez-23412342a/