"""
OwelSec AI Report Generator — CSV and PDF export for scan results.

Generates professional security assessment reports from completed scans.
"""

import csv
import io
import logging
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

logger = logging.getLogger("strix.reports")


# ── CSV ──────────────────────────────────────────────────────────────────────

def generate_csv(scan: dict) -> str:
    """Generate a CSV string from scan results.

    Returns UTF-8 CSV text with one finding per row.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Type", "URL", "Severity", "Status",
        "Confidence", "Details", "Template", "Tags",
    ])

    for finding in (scan.get("strix_results") or []):
        writer.writerow([
            finding.get("type", ""),
            finding.get("url", ""),
            finding.get("severity", ""),
            finding.get("status", ""),
            finding.get("confidence", ""),
            finding.get("details", ""),
            finding.get("template", ""),
            ", ".join(finding.get("tags", [])) if isinstance(finding.get("tags"), list) else "",
        ])

    logger.info("Generated CSV for scan %s (%d findings)",
                scan.get("scan_id"), len(scan.get("strix_results") or []))
    return output.getvalue()


# ── PDF ──────────────────────────────────────────────────────────────────────

# Color scheme matching OwelSec AI branding
OWELSEC_DARK = colors.HexColor("#0a1428")
OWELSEC_ACCENT = colors.HexColor("#22d3ee")
OWELSEC_TEXT = colors.HexColor("#1a1a2e")
OWELSEC_MUTED = colors.HexColor("#64748b")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#eab308"),
    "low":      colors.HexColor("#22d3ee"),
    "info":     colors.HexColor("#94a3b8"),
}


def generate_pdf(scan: dict) -> bytes:
    """Generate a professional PDF report from scan results.

    Returns PDF content as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Custom styles ────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "OwelSecTitle", parent=styles["Title"],
        fontSize=26, textColor=OWELSEC_DARK, spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "OwelSecSubtitle", parent=styles["Normal"],
        fontSize=11, textColor=OWELSEC_MUTED, spaceAfter=16,
    )
    heading_style = ParagraphStyle(
        "OwelSecHeading", parent=styles["Heading2"],
        fontSize=14, textColor=OWELSEC_DARK, spaceBefore=18, spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "OwelSecBody", parent=styles["Normal"],
        fontSize=10, textColor=OWELSEC_TEXT, leading=14,
    )
    small_style = ParagraphStyle(
        "OwelSecSmall", parent=styles["Normal"],
        fontSize=8, textColor=OWELSEC_MUTED,
    )

    # ── Header ───────────────────────────────────────────────────────────
    elements.append(Paragraph("OwelSec AI Security Report", title_style))
    elements.append(Paragraph("AI-Powered Vulnerability Assessment", subtitle_style))
    elements.append(HRFlowable(
        width="100%", thickness=2, color=OWELSEC_ACCENT, spaceAfter=12,
    ))

    # ── Scan metadata ────────────────────────────────────────────────────
    elements.append(Paragraph("Scan Information", heading_style))

    target = scan.get("target", "N/A")
    scan_id = scan.get("scan_id", "N/A")
    state = scan.get("state", "N/A")
    created = scan.get("created_at", "N/A")
    completed = scan.get("completed_at", "N/A")

    meta_data = [
        ["Target", target],
        ["Scan ID", scan_id],
        ["State", state.upper()],
        ["Started", str(created)],
        ["Completed", str(completed)],
    ]
    meta_table = Table(meta_data, colWidths=[90, 400])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), OWELSEC_MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), OWELSEC_TEXT),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
    ]))
    elements.append(meta_table)

    # ── Summary stats ────────────────────────────────────────────────────
    findings = scan.get("strix_results") or []
    total = len(findings)
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    false_pos = sum(1 for f in findings if f.get("status") == "false_positive")
    unverified = sum(1 for f in findings if f.get("status") == "unverified")

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    elements.append(Paragraph("Summary", heading_style))
    summary_text = (
        f"Total findings: <b>{total}</b> — "
        f"Confirmed: <b>{confirmed}</b>, "
        f"False positives: <b>{false_pos}</b>, "
        f"Unverified: <b>{unverified}</b>"
    )
    elements.append(Paragraph(summary_text, body_style))

    if sev_counts:
        sev_text = " | ".join(
            f"{sev.capitalize()}: {count}"
            for sev, count in sorted(sev_counts.items(),
                                     key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0])
                                     if x[0] in ["critical", "high", "medium", "low", "info"] else 99)
        )
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(f"By severity: {sev_text}", body_style))

    # ── Findings table ───────────────────────────────────────────────────
    if findings:
        elements.append(Paragraph("Detailed Findings", heading_style))

        table_header = ["#", "Type", "Severity", "Status", "Confidence", "URL"]
        table_data = [table_header]

        for i, f in enumerate(findings, 1):
            table_data.append([
                str(i),
                f.get("type", "")[:40],
                f.get("severity", "").upper(),
                f.get("status", ""),
                f"{f.get('confidence', 0) * 100:.0f}%",
                f.get("url", "")[:50],
            ])

        col_widths = [25, 120, 55, 70, 55, 170]
        findings_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        findings_table.setStyle(TableStyle([
            # Header
            ("BACKGROUND", (0, 0), (-1, 0), OWELSEC_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            # Body
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("TEXTCOLOR", (0, 1), (-1, -1), OWELSEC_TEXT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f8fafc")]),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(findings_table)

        # Finding details
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Finding Details", heading_style))
        for i, f in enumerate(findings, 1):
            details = f.get("details", "No details available.")
            elements.append(Paragraph(
                f"<b>#{i} — {f.get('type', 'unknown')}</b>",
                body_style,
            ))
            elements.append(Paragraph(details[:500], small_style))
            elements.append(Spacer(1, 6))

    # ── AI analysis ──────────────────────────────────────────────────────
    analysis = scan.get("analysis")
    if analysis:
        elements.append(Paragraph("AI Analysis", heading_style))
        # Convert markdown-like text to plain paragraphs
        for line in analysis.split("\n"):
            line = line.strip()
            if not line:
                elements.append(Spacer(1, 4))
            elif line.startswith("# "):
                elements.append(Paragraph(f"<b>{line[2:]}</b>", heading_style))
            elif line.startswith("## "):
                elements.append(Paragraph(f"<b>{line[3:]}</b>", body_style))
            elif line.startswith("* ") or line.startswith("- "):
                elements.append(Paragraph(f"• {line[2:]}", body_style))
            else:
                # Strip markdown bold markers
                clean = line.replace("**", "")
                elements.append(Paragraph(clean, body_style))

    # ── Footer ───────────────────────────────────────────────────────────
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=OWELSEC_MUTED))
    elements.append(Spacer(1, 4))
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    elements.append(Paragraph(
        f"Generated by OwelSec AI on {now} — Confidential",
        small_style,
    ))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    logger.info("Generated PDF for scan %s (%d bytes)", scan_id, len(pdf_bytes))
    return pdf_bytes
