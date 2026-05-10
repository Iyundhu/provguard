"""
Generate a downloadable PDF audit certificate for each verified file.
This is a tangible artifact users can keep as proof of verification —
exactly what real provenance systems produce in production.
"""
from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)


def generate_certificate(file_record, blocks) -> bytes:
    """
    Generate a PDF certificate for a verified file.

    Args:
        file_record: File ORM object
        blocks: list of ProvenanceBlock objects for this file

    Returns:
        PDF file as bytes
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2*cm, bottomMargin=2*cm,
        leftMargin=2*cm, rightMargin=2*cm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Heading1"],
        textColor=colors.HexColor("#0a2540"),
        fontSize=22, spaceAfter=6, alignment=1
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        textColor=colors.HexColor("#5a6b7a"),
        fontSize=11, spaceAfter=20, alignment=1, fontName="Helvetica-Oblique"
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"],
        textColor=colors.HexColor("#0a2540"),
        fontSize=13, spaceBefore=12, spaceAfter=6
    )

    decision_colors = {
        "TRUSTED": colors.HexColor("#0d7c3d"),
        "SUSPICIOUS": colors.HexColor("#b87100"),
        "MALICIOUS": colors.HexColor("#b81d24"),
    }

    story = []

    story.append(Paragraph("ProvGuard Verification Certificate", title_style))
    story.append(Paragraph("Trust by Verification, Not Detection", subtitle_style))

    # Decision banner
    decision_color = decision_colors.get(file_record.decision, colors.grey)
    decision_style = ParagraphStyle(
        "Decision", parent=styles["Normal"],
        textColor=colors.white, backColor=decision_color,
        fontSize=14, alignment=1, spaceAfter=18,
        leading=20, borderPadding=8, fontName="Helvetica-Bold"
    )
    story.append(Paragraph(
        f"Verdict: {file_record.decision} &nbsp;|&nbsp; Risk Score: {file_record.final_score:.1f}/100",
        decision_style
    ))

    # File details
    story.append(Paragraph("File Details", section_style))
    file_table = Table([
        ["File ID:", file_record.file_id],
        ["Filename:", file_record.original_filename],
        ["SHA-256:", file_record.sha256],
        ["Size:", f"{file_record.size_bytes:,} bytes"],
        ["MIME type:", file_record.mime_type or "unknown"],
        ["Uploaded:", file_record.uploaded_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Uploader:", file_record.uploader],
    ], colWidths=[3.5*cm, 12.5*cm])
    file_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
    ]))
    story.append(file_table)

    # Score breakdown
    story.append(Paragraph("Score Breakdown", section_style))
    score_table = Table([
        ["Component", "Score", "Weight"],
        ["Threat Intelligence", f"{file_record.threat_score:.1f}/100", "50%"],
        ["Provenance Verification", f"{file_record.provenance_score:.1f}/100", "30%"],
        ["Behavioral Analysis", f"{file_record.behavioral_score:.1f}/100", "20%"],
        ["Final Combined Score", f"{file_record.final_score:.1f}/100", "—"],
    ], colWidths=[7*cm, 4*cm, 3*cm])
    score_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a2540")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f0f3f7")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ]))
    story.append(score_table)

    # Provenance chain
    story.append(Paragraph("Provenance Chain", section_style))
    chain_data = [["#", "Event", "Timestamp", "Block Hash (truncated)"]]
    for b in blocks:
        chain_data.append([
            str(b.block_index),
            b.event_type,
            b.timestamp.strftime("%H:%M:%S"),
            b.block_hash[:16] + "..."
        ])
    chain_table = Table(chain_data, colWidths=[1.2*cm, 4*cm, 3*cm, 6.8*cm])
    chain_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a2540")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (3, 1), (3, -1), "Courier"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ]))
    story.append(chain_table)

    # Footer
    story.append(Spacer(1, 1*cm))
    footer_style = ParagraphStyle(
        "Footer", parent=styles["Normal"],
        fontSize=8, textColor=colors.grey, alignment=1
    )
    story.append(Paragraph(
        f"Certificate generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} "
        f"by ProvGuard v1.0. Each block in the provenance chain is digitally signed "
        f"with the system's RSA-2048 key. Tampering with the chain breaks verification.",
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
