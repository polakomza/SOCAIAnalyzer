
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def configure_fonts():
    """Utiliza una fuente Unicode si está disponible."""

    candidates = [
        Path("C:/Windows/Fonts/arial.ttf"),
        Path(
            "/usr/share/fonts/truetype/dejavu/"
            "DejaVuSans.ttf"
        ),
    ]

    for path in candidates:
        if path.exists():
            pdfmetrics.registerFont(
                TTFont("SOCFont", str(path))
            )
            return "SOCFont"

    return "Helvetica"


def safe_text(value):
    """Escapa texto para utilizarlo en ReportLab."""
    return escape(
        str(value if value is not None else "-")
    )


def generate_pdf(report):
    """Genera el informe PDF y devuelve sus bytes."""

    buffer = BytesIO()
    font = configure_fonts()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="SOC AI Analyzer - Informe técnico",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="SOCTitle",
        parent=styles["Title"],
        fontName=font,
        fontSize=18,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=18,
    ))

    styles.add(ParagraphStyle(
        name="SOCHeading",
        parent=styles["Heading2"],
        fontName=font,
        fontSize=12,
        leading=16,
        spaceBefore=14,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="SOCBody",
        parent=styles["BodyText"],
        fontName=font,
        fontSize=9,
        leading=14,
        spaceAfter=7,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="SOCTable",
        parent=styles["BodyText"],
        fontName=font,
        fontSize=8,
        leading=11,
        wordWrap="CJK",
    ))

    story = []

    def paragraph(value):
        return Paragraph(
            safe_text(value),
            styles["SOCBody"],
        )

    def heading(value):
        story.append(
            Paragraph(
                safe_text(value),
                styles["SOCHeading"],
            )
        )

    def field(label, value):
        story.append(
            paragraph(f"{label}: {value}")
        )

    def joined(values):
        return (
            ", ".join(map(str, values))
            if values else "-"
        )

    # ==========================================
    # PORTADA Y DATOS GENERALES
    # ==========================================

    story.append(
        Paragraph(
            "SOC AI Analyzer",
            styles["SOCTitle"],
        )
    )

    story.append(
        paragraph("INFORME TÉCNICO DE SEGURIDAD")
    )

    story.append(Spacer(1, 12))

    analysis = report["analysis"]
    summary = report["summary"]

    heading("1. Información general")

    field(
        "Fecha de generación",
        report["generated_at"],
    )
    field(
        "Archivo analizado",
        analysis.get("source_name", "-"),
    )
    field(
        "Hoja",
        analysis.get("sheet_name", "-"),
    )
    field(
        "ID del análisis",
        analysis.get("id", "-"),
    )

    # ==========================================
    # RESUMEN EJECUTIVO
    # ==========================================

    heading("2. Resumen ejecutivo")

    rows = [
        ["Indicador", "Cantidad"],
        [
            "Eventos importados",
            str(summary["total_events"]),
        ],
        [
            "Eventos válidos",
            str(summary["valid_events"]),
        ],
        [
            "Hallazgos",
            str(summary["findings_count"]),
        ],
        [
            "Incidentes",
            str(summary["incidents_count"]),
        ],
        [
            "Incidentes críticos",
            str(summary["critical_count"]),
        ],
        [
            "Incidentes altos",
            str(summary["high_count"]),
        ],
    ]

    table = Table(
        [
            [
                Paragraph(
                    safe_text(cell),
                    styles["SOCTable"],
                )
                for cell in row
            ]
            for row in rows
        ],
        colWidths=[11 * cm, 5 * cm],
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#17365D"),
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, 0),
            colors.white,
        ),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [
                colors.white,
                colors.HexColor("#F0F4F8"),
            ],
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.3,
            colors.lightgrey,
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP",
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            9,
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            7,
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            7,
        ),
    ]))

    story.append(table)
    story.append(Spacer(1, 10))

    executive = report.get("executive_summary")

    if executive:
        story.append(paragraph(executive))

    # ==========================================
    # INCIDENTES DETECTADOS
    # ==========================================

    heading("3. Incidentes detectados")

    if not report["incidents"]:
        story.append(
            paragraph(
                "No se identificaron incidentes "
                "con las reglas actuales."
            )
        )

    for incident in report["incidents"]:

        details = [
            Paragraph(
                safe_text(
                    f"Incidente {incident['incident_id']}"
                ),
                styles["SOCHeading"],
            ),
            paragraph(
                f"Severidad: {incident['severity']}"
            ),
            paragraph(
                f"Inicio: {incident['first_seen']}"
            ),
            paragraph(
                f"Fin: {incident['last_seen']}"
            ),
            paragraph(
                f"Reglas: {joined(incident['rules'])}"
            ),
            paragraph(
                f"IP: {joined(incident['source_ips'])}"
            ),
            paragraph(
                f"Usuarios: {joined(incident['users'])}"
            ),
            paragraph(
                "Filas de evidencia: "
                f"{joined(incident['evidence_rows'])}"
            ),
            paragraph(
                "Hallazgos relacionados: "
                f"{incident['findings_count']}"
            ),
        ]

        story.append(KeepTogether(details))

        # ======================================
        # MÉTRICAS VERIFICADAS
        # ======================================

        metrics = incident.get("verified_metrics")

        if metrics:
            story.append(
                Paragraph(
                    "Métricas verificadas",
                    styles["SOCHeading"],
                )
            )

            story.append(paragraph(
                "Eventos únicos: "
                f"{metrics['event_count']}"
            ))

            story.append(paragraph(
                "Datos salientes registrados por proxy: "
                f"{metrics['bytes_out_total']:,} bytes "
                f"({metrics['bytes_out_mib']:.2f} MiB)"
            ))

            duration = metrics.get(
                "duration_seconds"
            )

            if duration is not None:
                minutes, seconds = divmod(
                    duration, 60
                )

                story.append(paragraph(
                    "Duración observada: "
                    f"{minutes} min {seconds} s"
                ))

            story.append(paragraph(
                "Destinos identificados: "
                f"{joined(metrics.get('destinations', []))}"
            ))

            story.append(paragraph(
                "Eventos proxy con bytes registrados: "
                f"{metrics.get('events_with_bytes', 0)}"
            ))

            missing = metrics.get(
                "missing_rows", []
            )

            if missing:
                story.append(paragraph(
                    "Advertencia - filas no recuperadas: "
                    f"{joined(missing)}"
                ))

            story.append(paragraph(
                "Estas métricas se calcularon a partir "
                "de los registros normalizados. "
                "No demuestran por sí solas "
                "una exfiltración."
            ))

        # ======================================
        # EVALUACIÓN DE RIESGO
        # ======================================

        evaluation = incident.get(
            "risk_evaluation"
        )
        review = incident.get(
            "risk_review"
        )

        if evaluation:
            story.append(
                Paragraph(
                    "Evaluación contextual de riesgo",
                    styles["SOCHeading"],
                )
            )

            story.append(paragraph(
                "Severidad original del detector: "
                f"{incident.get('rule_severity', incident['severity'])}"
            ))

            story.append(paragraph(
                "Severidad propuesta por IA: "
                f"{evaluation['ai_severity']}"
            ))

            story.append(paragraph(
                "Confianza declarada por IA: "
                f"{evaluation['ai_confidence']}"
            ))

            story.append(paragraph(
                "Justificación de IA: "
                f"{evaluation['ai_reason']}"
            ))

            story.append(paragraph(
                "Filas citadas por IA: "
                f"{joined(evaluation.get('ai_evidence_rows', []))}"
            ))

            # Revisión humana
            story.append(
                Paragraph(
                    "Revisión del analista SOC",
                    styles["SOCHeading"],
                )
            )

            if review:
                story.append(paragraph(
                    f"Estado: {review['status']}"
                ))

                story.append(paragraph(
                    "Observaciones: "
                    f"{review['analyst_comment']}"
                ))

                story.append(paragraph(
                    "Fecha de revisión (UTC): "
                    f"{review['reviewed_at']}"
                ))

                story.append(paragraph(
                    "Identificador de evaluación: "
                    f"{review['evaluation_id']}"
                ))

            else:
                story.append(paragraph(
                    "Estado: Pendiente de revisión humana."
                ))

            story.append(paragraph(
                "La propuesta de IA no modifica "
                "la severidad original del detector."
            ))

        # ======================================
        # IMPACTO POTENCIAL
        # ======================================

        story.append(
            Paragraph(
                "Impacto potencial",
                styles["SOCHeading"],
            )
        )

        story.append(paragraph(
            incident.get(
                "potential_impact",
                "Pendiente de evaluación.",
            )
        ))

        # ======================================
        # PLAN DE ACCIÓN
        # ======================================

        story.append(
            Paragraph(
                "Plan de acción recomendado",
                styles["SOCHeading"],
            )
        )

        plan = incident.get(
            "action_plan", {}
        )

        action_sections = [
            ("Investigar", "investigate"),
            ("Contener (si se confirma)", "contain"),
            ("Remediar", "remediate"),
        ]

        for label, key in action_sections:
            story.append(
                paragraph(label + ":")
            )

            for action in plan.get(key, []):
                story.append(
                    paragraph("- " + str(action))
                )

        # ======================================
        # HALLAZGOS Y EVIDENCIAS
        # ======================================

        findings = incident.get(
            "findings", []
        )

        if findings:
            story.append(
                Paragraph(
                    "Hallazgos y evidencias",
                    styles["SOCHeading"],
                )
            )

        for index, finding in enumerate(
            findings, start=1
        ):
            story.append(paragraph(
                f"Hallazgo {index}: "
                f"{finding.get('title') or '-'}"
            ))

            story.append(paragraph(
                "Regla: "
                f"{finding.get('rule_id') or '-'}"
            ))

            story.append(paragraph(
                "Severidad: "
                f"{finding.get('severity') or '-'}"
            ))

            story.append(paragraph(
                "Descripción: "
                f"{finding.get('description') or '-'}"
            ))

            story.append(paragraph(
                "Justificación de severidad: "
                f"{finding.get('severity_reason') or '-'}"
            ))

            story.append(paragraph(
                "Filas de evidencia: "
                f"{joined(finding.get('evidence_rows', []))}"
            ))

            if finding.get("destination"):
                story.append(paragraph(
                    "Destino: "
                    f"{finding['destination']}"
                ))

            if finding.get("bytes_out") is not None:
                byte_count = int(
                    finding["bytes_out"]
                )

                story.append(paragraph(
                    "Datos enviados: "
                    f"{byte_count:,} bytes "
                    f"({byte_count / (1024 * 1024):.2f} MiB)"
                ))

            story.append(Spacer(1, 8))

        # ======================================
        # INTERPRETACIÓN ASISTIDA POR IA
        # ======================================

        if incident.get("ai_analysis"):
            story.append(
                Paragraph(
                    "Interpretación asistida por IA",
                    styles["SOCHeading"],
                )
            )

            story.append(paragraph(
                "Contenido generado por un modelo local. "
                "Pendiente de revisión por un analista."
            ))

            for line in incident["ai_analysis"].splitlines():
                if line.strip():
                    story.append(paragraph(line))

    # ==========================================
    # RECOMENDACIONES GENERALES
    # ==========================================

    heading("4. Recomendaciones generales")

    recommendations = report.get(
        "general_recommendations",
        [
            "Revisar los registros originales "
            "relacionados con cada incidente.",
            "Correlacionar las IP y usuarios "
            "con otras fuentes disponibles.",
            "Documentar las acciones de investigación "
            "y sus resultados.",
        ],
    )

    for recommendation in recommendations:
        story.append(
            paragraph("- " + recommendation)
        )

    # ==========================================
    # LIMITACIONES
    # ==========================================

    heading("5. Limitaciones del análisis")

    for limitation in report["limitations"]:
        story.append(
            paragraph("- " + limitation)
        )

    # ==========================================
    # PIE DE PÁGINA
    # ==========================================

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(font, 8)

        canvas.drawString(
            2 * cm,
            1.2 * cm,
            "SOC AI Analyzer | Informe técnico",
        )

        canvas.drawRightString(
            A4[0] - 2 * cm,
            1.2 * cm,
            f"Página {doc.page}",
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer,
    )

    return buffer.getvalue()
