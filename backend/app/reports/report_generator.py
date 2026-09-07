"""
Forensic Report Generator.

Builds a professional PDF investigation report from a saved case's
full analysis data. Uses reportlab (Platypus) for structured,
multi-section document layout.
"""

import json
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)


def _section_heading(text, styles):
    return Paragraph(text, styles["Heading2"])


def _kv_table(rows, col_widths=None):
    """Builds a simple two-column key/value table."""
    table = Table(rows, colWidths=col_widths or [1.8 * inch, 4.2 * inch])
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ]))
    return table


def generate_report_pdf(case, analysis: dict) -> BytesIO:
    """
    Builds a PDF forensic report and returns it as an in-memory BytesIO
    buffer, ready to be streamed as a file response.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    story = []

    verdict = analysis.get("final_verdict", {})
    parsed = analysis.get("parsed", {})
    basic = parsed.get("basic_fields", {})

    # --- Title ---
    story.append(Paragraph("Email Threat Investigation Report", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("small", parent=normal, fontSize=8, textColor=colors.grey),
    ))
    story.append(Spacer(1, 16))

    # --- Case Information ---
    story.append(_section_heading("Case Information", styles))
    story.append(_kv_table([
        ["Case ID", case.case_id],
        ["Status", case.status],
        ["Threat Level", case.threat_level or "N/A"],
        ["Created", case.created_at.strftime("%Y-%m-%d %H:%M UTC") if case.created_at else "N/A"],
        ["Subject", basic.get("subject", "N/A")],
    ]))
    story.append(Spacer(1, 14))

    # --- Executive Summary / Final Verdict ---
    story.append(_section_heading("Executive Summary", styles))
    story.append(_kv_table([
        ["Classification", verdict.get("classification", "N/A")],
        ["Final Risk Score", f"{verdict.get('final_risk_score', 'N/A')}/100"],
        ["Risk Level", verdict.get("risk_level", "N/A")],
        ["Methodology", verdict.get("methodology_note", "N/A")],
    ]))
    story.append(Spacer(1, 14))

    # --- Sender Analysis ---
    story.append(_section_heading("Sender Analysis", styles))
    story.append(_kv_table([
        ["From", basic.get("from", "N/A")],
        ["Reply-To", basic.get("reply_to") or "N/A"],
        ["Return-Path", basic.get("return_path") or "N/A"],
        ["Message-ID", basic.get("message_id", "N/A")],
        ["Date", basic.get("date", "N/A")],
    ]))
    story.append(Spacer(1, 14))

    # --- Header & Authentication ---
    header = analysis.get("header_analysis", {})
    story.append(_section_heading("Header & Authentication Analysis", styles))
    story.append(_kv_table([
        ["Header Risk Score", f"{header.get('header_risk_score', 'N/A')}/100"],
        ["Risk Level", header.get("risk_level", "N/A")],
        ["SPF", header.get("authentication", {}).get("spf", "N/A")],
        ["DKIM", header.get("authentication", {}).get("dkim", "N/A")],
        ["DMARC", header.get("authentication", {}).get("dmarc", "N/A")],
    ]))
    story.append(Spacer(1, 8))
    for reason in header.get("reasons", []):
        story.append(Paragraph(f"&#8226; {reason}", normal))
    story.append(Spacer(1, 14))

    # --- URL Analysis ---
    story.append(_section_heading("URL Analysis", styles))
    urls = analysis.get("url_analysis", [])
    if urls:
        for u in urls:
            story.append(Paragraph(
                f"<b>{u.get('url')}</b> — Risk: {u.get('risk_score')}/100 ({u.get('risk_level')})",
                normal,
            ))
            for reason in u.get("reasons", []):
                story.append(Paragraph(f"&nbsp;&nbsp;&#8226; {reason}", normal))
    else:
        story.append(Paragraph("No URLs found in this email.", normal))
    story.append(Spacer(1, 14))

    # --- NLP Analysis ---
    nlp = analysis.get("nlp_analysis", {})
    story.append(_section_heading("NLP Phishing Language Analysis", styles))
    story.append(Paragraph(
        f"NLP Risk Score: {nlp.get('nlp_risk_score', 'N/A')}/100 ({nlp.get('risk_level', 'N/A')})",
        normal,
    ))
    for reason in nlp.get("reasons", []):
        story.append(Paragraph(f"&#8226; {reason}", normal))
    story.append(Spacer(1, 14))

    # --- AI / ML Classification ---
    ml = analysis.get("ml_prediction", {})
    story.append(_section_heading("AI Classification", styles))
    story.append(_kv_table([
        ["Classification", ml.get("classification", "N/A")],
        ["Confidence", f"{ml.get('confidence', 'N/A')}%"],
        ["Top Contributing Words", ", ".join(ml.get("top_contributing_words", []))],
    ]))
    story.append(Spacer(1, 14))

    # --- Threat Intelligence ---
    ti = analysis.get("threat_intelligence", {})
    domain_check = ti.get("domain_check") or {}
    story.append(_section_heading("Threat Intelligence", styles))
    story.append(Paragraph(
        f"Domain checked: {domain_check.get('domain', 'N/A')} — "
        f"Source: {domain_check.get('source', 'N/A')}",
        normal,
    ))
    for reason in domain_check.get("reasons", []):
        story.append(Paragraph(f"&#8226; {reason}", normal))
    story.append(Spacer(1, 14))

    # --- GeoLocation ---
    geo = analysis.get("geo_intelligence", [])
    story.append(_section_heading("GeoLocation Intelligence", styles))
    if geo:
        for g in geo:
            if g.get("note"):
                story.append(Paragraph(f"{g.get('ip')}: {g.get('note')}", normal))
            else:
                story.append(Paragraph(
                    f"{g.get('ip')} — {g.get('city', '')}, {g.get('country', '')} "
                    f"(ISP: {g.get('isp', 'N/A')})",
                    normal,
                ))
        story.append(Paragraph(
            "Note: IP geolocation is approximate and identifies the general "
            "ISP-registered area, not the sender's exact physical address.",
            ParagraphStyle("note", parent=normal, fontSize=8, textColor=colors.grey),
        ))
    else:
        story.append(Paragraph("No public IP addresses found for geolocation.", normal))
    story.append(Spacer(1, 14))

    # --- IOC Table ---
    story.append(_section_heading("Extracted Indicators of Compromise (IOCs)", styles))
    ioc_rows = [["Type", "Indicator"]]
    for ip in parsed.get("ips", []):
        ioc_rows.append(["IP", ip])
    for url in parsed.get("urls", []):
        ioc_rows.append(["URL", url])
    if domain_check.get("domain"):
        ioc_rows.append(["Domain", domain_check["domain"]])
    if len(ioc_rows) > 1:
        ioc_table = Table(ioc_rows, colWidths=[1.2 * inch, 4.8 * inch])
        ioc_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        story.append(ioc_table)
    else:
        story.append(Paragraph("No IOCs extracted.", normal))
    story.append(Spacer(1, 14))

    # --- Recommended Actions ---
    story.append(_section_heading("Recommended Actions", styles))
    classification = verdict.get("classification", "SAFE")
    if classification in ("MALICIOUS", "PHISHING"):
        actions = [
            "Quarantine this email immediately.",
            "Block the sender domain and any malicious URLs after verification.",
            "If any user interacted with the link, reset their credentials.",
            "Search the organization's mail system for similar emails.",
            "Preserve the original .eml file as forensic evidence.",
        ]
    elif classification == "SUSPICIOUS":
        actions = [
            "Flag for manual analyst review before taking action.",
            "Do not click any links or open attachments until reviewed.",
        ]
    else:
        actions = ["No action required. Email appears safe based on current analysis."]
    for action in actions:
        story.append(Paragraph(f"&#8226; {action}", normal))

    doc.build(story)
    buffer.seek(0)
    return buffer