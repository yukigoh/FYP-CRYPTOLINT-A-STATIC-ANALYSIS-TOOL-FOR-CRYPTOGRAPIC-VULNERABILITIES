# © 2025 CryptoLint. All rights reserved.
# This source code is the proprietary and confidential property of CryptoLint.
# Unauthorized reproduction, distribution, or modification of this code,
# in whole or in part, is strictly prohibited without prior written permission.
# For licensing inquiries, contact: legal@cryptolint.io

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import ast
import re
import os
import json
import tempfile
from datetime import datetime
from typing import List, Dict


def mask_sensitive_code(code_line: str) -> str:
    """Mask sensitive literal values in a line of code."""
    return re.sub(
        r'((?:password|secret|api_key|token|key|credential|auth'
        r'|private_key|secret_key|access_token|refresh_token)\s*=\s*)'
        r'(["\'])([^"\']*)\2',
        lambda m: m.group(1) + m.group(2) + '*' * min(len(m.group(3)), 8) + m.group(2),
        code_line,
        flags=re.IGNORECASE
    )


def build_copyright_banner() -> str:
    year = datetime.now().year
    return (
        f"# {'='*70}\n"
        f"# © {year} CryptoLint. All rights reserved.\n"
        f"# This source code is proprietary and confidential.\n"
        f"# Unauthorized reproduction or distribution is strictly prohibited.\n"
        f"# For licensing: legal@cryptolint.io\n"
        f"# {'='*70}\n"
    )


def generate_pdf_report(vulnerabilities: list, meta: dict, filepath: str, password: str) -> None:
    """
    Build a fully-structured, beautiful PDF report from vulnerability objects.
    meta = { 'filename', 'filepath', 'owasp_on', 'nist_on', 'custom_sets' }
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    HRFlowable, Table, TableStyle, KeepTogether,
                                    PageBreak)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from pypdf import PdfReader, PdfWriter

    W, H = A4

    # ── colour palette ──────────────────────────────────────────────────────── #
    C_PAGE     = colors.HexColor('#0f1117')
    C_CARD     = colors.HexColor('#1e2130')
    C_CARD2    = colors.HexColor('#252a3a')
    C_ACCENT   = colors.HexColor('#4a90e2')
    C_ACCENT2  = colors.HexColor('#1a3a5c')
    C_WHITE    = colors.HexColor('#f0f2f5')
    C_MUTED    = colors.HexColor('#8892a4')
    C_CRITICAL = colors.HexColor('#dc3545')
    C_HIGH     = colors.HexColor('#ff9800')
    C_MEDIUM   = colors.HexColor('#ffc107')
    C_LOW      = colors.HexColor('#4caf50')
    C_CODE_BG  = colors.HexColor('#0d1117')
    C_CODE_FG  = colors.HexColor('#ff6b6b')
    C_GREEN    = colors.HexColor('#4caf50')
    C_TEAL     = colors.HexColor('#00bcd4')

    SEV_COLOR = {'critical': C_CRITICAL, 'high': C_HIGH,
                 'medium':   C_MEDIUM,   'low':  C_LOW}
    SEV_ICON  = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
    SEV_DARK  = {'critical': colors.HexColor('#8b0000'),
                 'high':     colors.HexColor('#7a4000'),
                 'medium':   colors.HexColor('#7a6000'),
                 'low':      colors.HexColor('#1a5c1a')}

    def S(name, **kw): return ParagraphStyle(name, **kw)

    st_h1    = S('h1',   fontSize=28, textColor=C_WHITE,  fontName='Helvetica-Bold',
                 leading=34, spaceAfter=4, alignment=TA_LEFT)
    st_h2    = S('h2',   fontSize=14, textColor=C_ACCENT, fontName='Helvetica-Bold',
                 leading=20, spaceBefore=10, spaceAfter=5)
    st_h3    = S('h3',   fontSize=11, textColor=C_WHITE,  fontName='Helvetica-Bold',
                 leading=15, spaceAfter=2)
    st_body  = S('body', fontSize=9,  textColor=C_WHITE,  leading=13, spaceAfter=2)
    st_mute  = S('mute', fontSize=8,  textColor=C_MUTED,  leading=11, spaceAfter=1)
    st_code  = S('code', fontSize=8,  textColor=C_CODE_FG, fontName='Courier',
                 backColor=C_CODE_BG, leading=12, leftIndent=4, rightIndent=4,
                 spaceAfter=2, spaceBefore=2)
    st_ctr   = S('ctr',  fontSize=8,  textColor=C_MUTED,  leading=11, alignment=TA_CENTER)
    st_fix   = S('fix',  fontSize=9,  textColor=C_GREEN,  leading=13)
    st_cover_sub = S('csub', fontSize=13, textColor=C_MUTED, leading=18, spaceAfter=8)
    st_toc_h = S('toch', fontSize=8, textColor=C_MUTED, fontName='Helvetica-Bold',
                 leading=11, alignment=TA_CENTER)
    st_toc   = S('toc',  fontSize=8, textColor=C_WHITE,  leading=11)
    st_toc_s = S('tocs', fontSize=8, textColor=C_MUTED,  leading=11, alignment=TA_CENTER)

    def badge_style(sev):
        return S(f'b_{sev}', fontSize=8, textColor=C_WHITE if sev != 'medium' else C_PAGE,
                 backColor=SEV_COLOR[sev], fontName='Helvetica-Bold',
                 leading=11, leftIndent=4, rightIndent=4, alignment=TA_CENTER)

    now = datetime.now()
    cnt = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for v in vulnerabilities: cnt[v.severity] += 1
    score = cnt['critical']*10 + cnt['high']*5 + cnt['medium']*2 + cnt['low']
    risk  = ('CRITICAL RISK' if score >= 30 else
             'HIGH RISK'     if score >= 15 else
             'MEDIUM RISK'   if score >= 8  else 'LOW RISK')
    risk_col = (C_CRITICAL if score >= 15 else (C_HIGH if score >= 8 else C_GREEN))

    tmp_path = filepath + '.tmp_unenc.pdf'
    doc = SimpleDocTemplate(tmp_path, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=22*mm, bottomMargin=18*mm)

    story = []
    SO = {'critical':0, 'high':1, 'medium':2, 'low':3}
    sorted_vulns = sorted(vulnerabilities, key=lambda x: (SO[x.severity], x.line))

    # ── PAGE BACKGROUND & FOOTER ────────────────────────────────────────────── #
    def on_page(cv, doc):
        cv.saveState()
        cv.setFillColor(C_PAGE)
        cv.rect(0, 0, W, H, fill=1, stroke=0)
        # left accent bar
        cv.setFillColor(C_ACCENT)
        cv.rect(0, 0, 4.5, H, fill=1, stroke=0)
        # footer line
        cv.setStrokeColor(C_ACCENT2)
        cv.setLineWidth(0.5)
        cv.line(18*mm, 14*mm, W - 18*mm, 14*mm)
        # footer text
        cv.setFont('Helvetica', 7)
        cv.setFillColor(C_MUTED)
        cv.drawString(18*mm, 9*mm,
                      f"CryptoLint Security Report  ·  {meta['filename']}  ·  "
                      f"Generated {now.strftime('%d %b %Y, %H:%M')}")
        cv.drawRightString(W - 18*mm, 9*mm, f"Page {doc.page}")
        cv.restoreState()

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  COVER PAGE                                                      ║
    # ╚══════════════════════════════════════════════════════════════════╝
    story.append(Spacer(1, 18*mm))

    # Large logo-style title block
    title_data = [[
        Paragraph("🔐", S('icon', fontSize=36, textColor=C_ACCENT, leading=44)),
        [Paragraph("CryptoLint", st_h1),
         Paragraph("Cryptographic Vulnerability Analysis Report", st_cover_sub)],
    ]]
    title_tbl = Table(title_data, colWidths=[18*mm, 152*mm])
    title_tbl.setStyle(TableStyle([
        ('VALIGN',  (0,0),(-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0),(0,0), 0),
        ('RIGHTPADDING',(0,0),(0,0), 8),
    ]))
    story.append(title_tbl)
    story.append(HRFlowable(width='100%', thickness=1.5, color=C_ACCENT, spaceAfter=6*mm))

    # ── Cover metadata card ─────────────────────────────────────────── #
    meta_data = [
        ['File Analysed', meta['filename']],
        ['Full Path',     meta['filepath']],
        ['Generated',     now.strftime('%d %B %Y  at  %H:%M:%S')],
        ['Active Rulesets', ', '.join(filter(None, [
            'OWASP Top 10'    if meta.get('owasp_on') else '',
            'NIST Guidelines' if meta.get('nist_on')  else '',
        ] + [s for s in meta.get('custom_sets', [])]))],
    ]
    meta_tbl = Table([[Paragraph(k, st_mute), Paragraph(v, st_body)] for k, v in meta_data],
                     colWidths=[38*mm, 132*mm])
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND',     (0,0),(-1,-1), C_CARD),
        ('FONTNAME',       (0,0),(0,-1),  'Helvetica-Bold'),
        ('FONTSIZE',       (0,0),(-1,-1), 8),
        ('TOPPADDING',     (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',  (0,0),(-1,-1), 5),
        ('LEFTPADDING',    (0,0),(-1,-1), 8),
        ('RIGHTPADDING',   (0,0),(-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0),(-1,-1), [C_CARD, C_CARD2]),
        ('LINEBEFORE',     (0,0),(0,-1),  3, C_ACCENT),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 8*mm))

    # ── Cover risk overview ─────────────────────────────────────────── #
    risk_data = [[
        Paragraph(f"{risk}", S('rsk', fontSize=16, textColor=C_WHITE,
                               fontName='Helvetica-Bold', leading=20, alignment=TA_CENTER)),
        Paragraph(f"Risk Score: <b>{score}</b>", S('rsc', fontSize=11, textColor=C_WHITE,
                               leading=16, alignment=TA_CENTER)),
        Paragraph(f"<b>{len(vulnerabilities)}</b><br/>Total Issues",
                  S('tot', fontSize=11, textColor=C_WHITE, leading=15, alignment=TA_CENTER)),
    ]]
    risk_tbl = Table(risk_data, colWidths=[70*mm, 60*mm, 40*mm])
    risk_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), risk_col),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0),(-1,-1), 12),
        ('BOTTOMPADDING', (0,0),(-1,-1), 12),
        ('LINEAFTER',     (0,0),(1,0),   0.5, colors.HexColor('#ffffff44')),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 5*mm))

    # ── Cover severity boxes ────────────────────────────────────────── #
    sev_data = [[
        Paragraph(f"🔴 Critical<br/><b>{cnt['critical']}</b>",
                  S('sc', fontSize=13, textColor=C_WHITE, fontName='Helvetica-Bold',
                    leading=18, alignment=TA_CENTER)),
        Paragraph(f"🟠 High<br/><b>{cnt['high']}</b>",
                  S('sh', fontSize=13, textColor=C_WHITE, fontName='Helvetica-Bold',
                    leading=18, alignment=TA_CENTER)),
        Paragraph(f"🟡 Medium<br/><b>{cnt['medium']}</b>",
                  S('sm', fontSize=13, textColor=C_PAGE, fontName='Helvetica-Bold',
                    leading=18, alignment=TA_CENTER)),
        Paragraph(f"🟢 Low<br/><b>{cnt['low']}</b>",
                  S('sl', fontSize=13, textColor=C_WHITE, fontName='Helvetica-Bold',
                    leading=18, alignment=TA_CENTER)),
    ]]
    sev_tbl = Table(sev_data, colWidths=[43*mm]*4)
    sev_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(0,0), C_CRITICAL),
        ('BACKGROUND',    (1,0),(1,0), C_HIGH),
        ('BACKGROUND',    (2,0),(2,0), C_MEDIUM),
        ('BACKGROUND',    (3,0),(3,0), C_LOW),
        ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0),(-1,-1), 12),
        ('BOTTOMPADDING', (0,0),(-1,-1), 12),
        ('LINEAFTER',     (0,0),(2,0),   0.5, colors.HexColor('#00000033')),
    ]))
    story.append(sev_tbl)

    # ── Cover disclaimer ────────────────────────────────────────────── #
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_MUTED, spaceAfter=4))
    story.append(Paragraph(
        "This report was automatically generated by CryptoLint. All findings should be "
        "reviewed by a qualified security engineer before remediation. Results are based "
        "on static pattern analysis and may include false positives.",
        S('disc', fontSize=8, textColor=C_MUTED, leading=12, alignment=TA_CENTER)))


    story.append(PageBreak())
    story.append(Paragraph("Findings Index", st_h2))
    story.append(Paragraph(
        "All detected vulnerabilities listed by severity. Click a finding number to navigate.",
        S('idx_sub', fontSize=9, textColor=C_MUTED, leading=12, spaceAfter=5)))

    if not sorted_vulns:
        story.append(Paragraph("✅ No vulnerabilities detected in this file.", S('ok',
            fontSize=12, textColor=C_GREEN, fontName='Helvetica-Bold', leading=16)))
    else:
        # Index table header
        idx_header = [
            Paragraph('#',          st_toc_h),
            Paragraph('Severity',   st_toc_h),
            Paragraph('Type',       st_toc_h),
            Paragraph('Line',       st_toc_h),
            Paragraph('Summary',    st_toc_h),
        ]
        idx_rows = [idx_header]
        for i, v in enumerate(sorted_vulns, 1):
            row_bg = C_CARD if i % 2 == 0 else C_CARD2
            idx_rows.append([
                Paragraph(str(i), S('in', fontSize=8, textColor=C_ACCENT,
                                    fontName='Helvetica-Bold', leading=11, alignment=TA_CENTER)),
                Paragraph(v.severity.upper(), badge_style(v.severity)),
                Paragraph(v.vuln_type, S('it', fontSize=8, textColor=C_WHITE, leading=11)),
                Paragraph(str(v.line), S('il', fontSize=8, textColor=C_MUTED, leading=11,
                                         alignment=TA_CENTER)),
                Paragraph(v.description[:80] + ('…' if len(v.description) > 80 else ''),
                          S('is', fontSize=8, textColor=C_MUTED, leading=11)),
            ])

        idx_tbl = Table(idx_rows, colWidths=[10*mm, 20*mm, 42*mm, 12*mm, 86*mm],
                        repeatRows=1)
        idx_tbl.setStyle(TableStyle([
            # header
            ('BACKGROUND',    (0,0),(-1,0), C_ACCENT2),
            ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
            ('ALIGN',         (0,0),(-1,0), 'CENTER'),
            # alternating rows
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_CARD, C_CARD2]),
            # padding
            ('TOPPADDING',    (0,0),(-1,-1), 4),
            ('BOTTOMPADDING', (0,0),(-1,-1), 4),
            ('LEFTPADDING',   (0,0),(-1,-1), 5),
            ('RIGHTPADDING',  (0,0),(-1,-1), 5),
            ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
            # grid
            ('LINEBELOW',     (0,0),(-1,0),  0.5, C_ACCENT),
            ('LINEBEFORE',    (0,1),(0,-1),  2, C_ACCENT2),
        ]))
        story.append(idx_tbl)
        story.append(Spacer(1, 8*mm))

        # ── RECOMMENDATIONS SECTION ─────────────────────────────────────── #
        story.append(Paragraph("Priority Remediation Actions", st_h2))
        pri_rows = [[
            Paragraph('Priority', st_toc_h),
            Paragraph('Action', st_toc_h),
            Paragraph('Applies to', st_toc_h),
        ]]
        # Generate unique remediations grouped by severity
        seen_rem = set()
        for sev_key in ['critical', 'high', 'medium', 'low']:
            for v in sorted_vulns:
                if v.severity == sev_key and v.remediation not in seen_rem:
                    seen_rem.add(v.remediation)
                    pri_rows.append([
                        Paragraph(sev_key.upper(), badge_style(sev_key)),
                        Paragraph(v.remediation,
                                  S('pr', fontSize=8, textColor=C_WHITE, leading=12)),
                        Paragraph(v.vuln_type,
                                  S('pa', fontSize=8, textColor=C_MUTED, leading=12)),
                    ])

        pri_tbl = Table(pri_rows, colWidths=[22*mm, 110*mm, 38*mm], repeatRows=1)
        pri_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0), C_ACCENT2),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_CARD, C_CARD2]),
            ('TOPPADDING',    (0,0),(-1,-1), 4),
            ('BOTTOMPADDING', (0,0),(-1,-1), 4),
            ('LEFTPADDING',   (0,0),(-1,-1), 5),
            ('RIGHTPADDING',  (0,0),(-1,-1), 5),
            ('VALIGN',        (0,0),(-1,-1), 'TOP'),
            ('LINEBELOW',     (0,0),(-1,0),  0.5, C_ACCENT),
        ]))
        story.append(pri_tbl)
        story.append(Spacer(1, 8*mm))

        #   DETAILED FINDINGS                                           
        story.append(HRFlowable(width='100%', thickness=0.5, color=C_ACCENT2, spaceAfter=4))
        story.append(Paragraph("Detailed Findings", st_h2))

        for i, v in enumerate(sorted_vulns, 1):
            sev = v.severity
            col = SEV_COLOR[sev]
            dark = SEV_DARK[sev]

            safe_code = (v.code.replace('&','&amp;')
                               .replace('<','&lt;')
                               .replace('>','&gt;'))

            # ── Finding header (coloured banner) ─────────────────────── #
            hdr_rows = [[
                Paragraph(f"{SEV_ICON[sev]}  {v.vuln_type}", st_h3),
                Paragraph(sev.upper(), badge_style(sev)),
            ]]
            hdr_tbl = Table(hdr_rows, colWidths=[140*mm, 30*mm])
            hdr_tbl.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,-1), col),
                ('ALIGN',         (1,0),(1,0), 'CENTER'),
                ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
                ('TOPPADDING',    (0,0),(-1,-1), 7),
                ('BOTTOMPADDING', (0,0),(-1,-1), 7),
                ('LEFTPADDING',   (0,0),(0,0),  10),
                ('RIGHTPADDING',  (1,0),(1,0),   8),
            ]))

            # ── Finding badge row ─────────────────────────────────────── #
            badge_data = [[
                Paragraph(f"Finding #{i}", S('fn', fontSize=7, textColor=C_MUTED,
                                             fontName='Helvetica-Bold', leading=9)),
                Paragraph(f"Line {v.line}", S('ln', fontSize=7, textColor=C_ACCENT,
                                              fontName='Helvetica-Bold', leading=9)),
            ]]
            badge_tbl = Table(badge_data, colWidths=[85*mm, 85*mm])
            badge_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,-1), dark),
                ('TOPPADDING',    (0,0),(-1,-1), 3),
                ('BOTTOMPADDING', (0,0),(-1,-1), 3),
                ('LEFTPADDING',   (0,0),(0,0),  10),
                ('RIGHTPADDING',  (1,0),(1,0),   8),
                ('ALIGN',         (1,0),(1,0), 'RIGHT'),
            ]))

            # ── Finding body ──────────────────────────────────────────── #
            body_rows = [
                [Paragraph('Description', st_mute),
                 Paragraph(v.description, st_body)],
                [Paragraph('Vulnerable Code', st_mute),
                 Paragraph(safe_code, st_code)],
                [Paragraph('Remediation', st_mute),
                 Paragraph(v.remediation, st_fix)],
            ]
            body_tbl = Table(body_rows, colWidths=[28*mm, 142*mm])
            body_tbl.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,-1), C_CARD),
                ('FONTNAME',      (0,0),(0,-1),  'Helvetica-Bold'),
                ('FONTSIZE',      (0,0),(-1,-1), 9),
                ('TOPPADDING',    (0,0),(-1,-1), 5),
                ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                ('LEFTPADDING',   (0,0),(-1,-1), 8),
                ('RIGHTPADDING',  (0,0),(-1,-1), 8),
                ('ROWBACKGROUNDS',(0,0),(-1,-1), [C_CARD, C_CARD2]),
                ('LINEBEFORE',    (0,0),(0,-1),  3, col),
                ('VALIGN',        (0,0),(-1,-1), 'TOP'),
            ]))

            story.append(KeepTogether([
                badge_tbl,
                hdr_tbl,
                body_tbl,
                Spacer(1, 5*mm),
            ]))

    #   CLOSING PAGE — General Recommendations                         
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_MUTED, spaceAfter=5))
    story.append(Paragraph("General Security Recommendations", st_h2))

    recs = [
        ("Use approved algorithms",
         "Use AES-256-GCM or ChaCha20-Poly1305 for encryption. "
         "Use SHA-256 or SHA-3 for hashing. Avoid MD5, SHA-1, DES, and RC4."),
        ("Protect secrets",
         "Never hardcode passwords, API keys or tokens in source code. "
         "Use environment variables, a secrets manager, or a vault service."),
        ("Use cryptographic randomness",
         "Replace random.random() and random.choice() with the secrets module "
         "for all security-sensitive operations."),
        ("Enforce key size minimums",
         "Use RSA keys of at least 2048 bits (prefer 3072/4096). "
         "For elliptic curve, use P-256 or stronger."),
        ("Keep dependencies updated",
         "Regularly audit and update cryptographic libraries. "
         "Subscribe to CVE feeds for libraries you depend on."),
        ("Re-scan continuously",
         "Integrate CryptoLint into your CI/CD pipeline so that new "
         "vulnerabilities are caught before code is merged."),
    ]
    rec_rows = [[Paragraph('Recommendation', st_toc_h), Paragraph('Guidance', st_toc_h)]]
    for title, body in recs:
        rec_rows.append([
            Paragraph(title, S('rt', fontSize=8, textColor=C_TEAL,
                               fontName='Helvetica-Bold', leading=12)),
            Paragraph(body,  S('rb', fontSize=8, textColor=C_WHITE, leading=12)),
        ])
    rec_tbl = Table(rec_rows, colWidths=[45*mm, 125*mm], repeatRows=1)
    rec_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), C_ACCENT2),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_CARD, C_CARD2]),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LEFTPADDING',   (0,0),(-1,-1), 8),
        ('RIGHTPADDING',  (0,0),(-1,-1), 8),
        ('VALIGN',        (0,0),(-1,-1), 'TOP'),
        ('LINEBELOW',     (0,0),(-1,0),  0.5, C_ACCENT),
        ('LINEBEFORE',    (0,1),(0,-1),  2, C_TEAL),
    ]))
    story.append(rec_tbl)
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_MUTED, spaceAfter=4))
    story.append(Paragraph(
        f"Generated by CryptoLint  ·  © {now.year} CryptoLint. All rights reserved.  ·  "
        "Confidential — For authorised use only  ·  legal@cryptolint.io",
        st_ctr))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    # ── encrypt ──────────────────────────────────────────────────────────────── #
    reader = PdfReader(tmp_path)
    writer = PdfWriter()
    for page in reader.pages: writer.add_page(page)
    writer.encrypt(user_password=password, owner_password=password+'_owner', use_128bit=True)
    with open(filepath, 'wb') as fout: writer.write(fout)
    os.remove(tmp_path)


#  Data model

class Vulnerability:
    """Represents a detected security vulnerability"""
    def __init__(self, line: int, code: str, severity: str, vuln_type: str,
                 description: str, remediation: str):
        self.line = line
        self.code = code
        self.severity = severity
        self.vuln_type = vuln_type
        self.description = description
        self.remediation = remediation


#  Main GUI

class CryptoLintGUI:
    """Main GUI application for CryptoLint"""

    def __init__(self, root):
        self.root = root
        self.root.title("CryptoLint - Cryptographic Vulnerability Scanner")
        self.root.geometry("1400x800")
        self.root.configure(bg="#1a1a1a")

        self.config_file = os.path.join(os.path.expanduser("~"), ".cryptolint_config.json")

        self.files            = []
        self.active_file      = None
        self.vulnerabilities  = []
        self.analysis_counts  = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        self.show_code           = tk.BooleanVar(value=True)
        self.show_ast            = tk.BooleanVar(value=False)
        self.show_dataflow       = tk.BooleanVar(value=False)
        self.show_vulnerabilities = tk.BooleanVar(value=True)
        self.filter_severity     = tk.StringVar(value="all")  # all / critical / high / medium / low

        # owasp_rules / nist_rules: loaded from OWASP.json / NIST.json at startup
        # Each is a list of dicts: {pattern, severity, type, description, remediation}
        self.owasp_rules = []
        self.nist_rules  = []

        # Default rule toggle states — True = enabled
        self.owasp_enabled = tk.BooleanVar(value=True)
        self.nist_enabled  = tk.BooleanVar(value=True)

        # rule_sets: list of imported rule-set dicts, each containing:
        #   { 'id': int, 'name': str (editable), 'source_file': str,
        #     'enabled': BooleanVar (whole set on/off),
        #     'rules': [ { 'id', 'pattern', 'severity', 'type', 'description',
        #                  'remediation', 'nist_ref', 'cwe', 'enabled': BooleanVar } ] }
        self.rule_sets         = []
        self.custom_rules      = []   # flat view, rebuilt from rule_sets for detect_vulnerabilities
        self.custom_rule_count = 0
        self._next_set_id      = 0
        self._next_rule_id     = 0

        # Load OWASP.json and NIST.json — tool cannot run without both
        if not self._load_required_rulesets():
            return   # _load_required_rulesets shows error and destroys root

        self.setup_ui()
        self.load_config()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ------------------------------------------------------------------ #
    #  Required ruleset loader
    # ------------------------------------------------------------------ #

    def _load_required_rulesets(self) -> bool:
        """
        Load OWASP.json and NIST.json from the same directory as this script.
        If either file is missing or invalid, show an error and close the tool.
        Returns True on success, False on failure.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        owasp_path = os.path.join(script_dir, "OWASP.json")
        nist_path  = os.path.join(script_dir, "NIST.json")

        missing = []
        if not os.path.exists(owasp_path): missing.append("OWASP.json")
        if not os.path.exists(nist_path):  missing.append("NIST.json")

        if missing:
            msg = (
                f"CryptoLint cannot start.\n\n"
                f"The following required ruleset file(s) are missing:\n"
                f"  {'  '.join(missing)}\n\n"
                f"Please place the following files in the same folder as cryptolint_app.py:\n"
                f"  • OWASP.json\n"
                f"  • NIST.json\n\n"
                f"Expected location:\n  {script_dir}"
            )
            messagebox.showerror("Missing Required Rulesets", msg)
            self.root.destroy()
            return False

        errors = []
        for path, label, target in [
            (owasp_path, "OWASP.json", "owasp_rules"),
            (nist_path,  "NIST.json",  "nist_rules"),
        ]:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                loaded = []
                for rule in data.get('rules', []):
                    pat = rule.get('pattern') or (rule.get('patterns', [None])[0])
                    if not pat:
                        continue
                    try:
                        re.compile(pat)
                        loaded.append({
                            'pattern':     pat,
                            'severity':    rule.get('severity', 'medium'),
                            'type':        rule.get('type', rule.get('id', 'Rule')),
                            'description': rule.get('description', ''),
                            'remediation': rule.get('remediation', ''),
                            'nist_ref':    rule.get('nist_ref', rule.get('owasp_ref', '')),
                            'cwe':         rule.get('cwe', ''),
                        })
                    except re.error as e:
                        print(f"Invalid pattern in {label}: {pat} — {e}")
                if not loaded:
                    errors.append(f"{label}: no valid rules found inside the file.")
                else:
                    setattr(self, target, loaded)
            except json.JSONDecodeError as e:
                errors.append(f"{label}: invalid JSON — {e}")
            except Exception as e:
                errors.append(f"{label}: could not read — {e}")

        if errors:
            msg = (
                f"CryptoLint cannot start due to ruleset errors:\n\n"
                + "\n".join(f"  • {e}" for e in errors)
                + f"\n\nPlease fix the file(s) and restart."
            )
            messagebox.showerror("Ruleset Error", msg)
            self.root.destroy()
            return False

        return True

    # ------------------------------------------------------------------ #
    #  UI setup
    # ------------------------------------------------------------------ #

    def setup_ui(self):
        header = tk.Frame(self.root, bg="#2d2d2d", height=80)
        header.pack(fill=tk.X)
        tk.Label(header, text="CryptoLint", font=("Arial", 20, "bold"),
                 bg="#2d2d2d", fg="white").pack(anchor=tk.W, padx=20, pady=(15, 0))
        tk.Label(header, text="Cryptographic Vulnerability Scanner",
                 font=("Arial", 10), bg="#2d2d2d", fg="#888888").pack(anchor=tk.W, padx=20, pady=(0, 10))

        toolbar = tk.Frame(self.root, bg="#2d2d2d", height=50)
        toolbar.pack(fill=tk.X)

        btn = {"font": ("Arial", 10), "fg": "white", "relief": tk.FLAT,
               "padx": 15, "pady": 8, "cursor": "hand2"}
        tk.Button(toolbar, text="📁 Open File",    command=self.open_file,    bg="#4a90e2", **btn).pack(side=tk.LEFT, padx=(20, 5), pady=10)
        tk.Button(toolbar, text="📋 Import Rules", command=self.import_rules, bg="#00bcd4", **btn).pack(side=tk.LEFT, padx=5,      pady=10)
        tk.Button(toolbar, text="💾 Export Report",command=self.export_report, bg="#ff9800", **btn).pack(side=tk.LEFT, padx=5,      pady=10)

        tk.Label(toolbar, text=" | View:", bg="#2d2d2d", fg="#888888",
                 font=("Arial", 9)).pack(side=tk.LEFT, padx=(20, 5))
        for text, var in [("Code", self.show_code), ("AST", self.show_ast),
                           ("Data Flow", self.show_dataflow), ("Vulnerabilities", self.show_vulnerabilities)]:
            tk.Checkbutton(toolbar, text=text, variable=var, command=self.update_layout,
                           bg="#2d2d2d", fg="white", selectcolor="#1a1a1a",
                           font=("Arial", 9)).pack(side=tk.LEFT, padx=2)

        self.issue_label = tk.Label(toolbar, text="0 Issues", font=("Arial", 10),
                                    bg="#2d2d2d", fg="#ff9800")
        self.issue_label.pack(side=tk.RIGHT, padx=20)

        main_container = tk.Frame(self.root, bg="#1a1a1a")
        main_container.pack(fill=tk.BOTH, expand=True)

        self.main_paned = tk.PanedWindow(main_container, orient=tk.HORIZONTAL,
                                         bg="#1a1a1a", sashwidth=5, sashrelief=tk.RAISED)
        self.main_paned.pack(fill=tk.BOTH, expand=True)

        self.setup_sidebar()

        self.content_container = tk.Frame(self.main_paned, bg="#1a1a1a")
        self.main_paned.add(self.content_container, minsize=600)

        self.setup_content_panels()
        self.update_layout()

    def setup_sidebar(self):
        sidebar = tk.Frame(self.main_paned, bg="#2d2d2d", width=250)
        self.main_paned.add(sidebar, minsize=200)

        sc = tk.Frame(sidebar, bg="#2d2d2d")
        sc.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(sc, text="PROJECT FILES", font=("Arial", 9, "bold"),
                 bg="#2d2d2d", fg="#888888", anchor=tk.W).pack(fill=tk.X, pady=(5, 5))

        ff = tk.Frame(sc, bg="#2d2d2d")
        ff.pack(fill=tk.BOTH, expand=True)
        fsb = tk.Scrollbar(ff); fsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.files_listbox = tk.Listbox(ff, bg="#1a1a1a", fg="white",
                                        selectbackground="#4a90e2", relief=tk.FLAT,
                                        font=("Arial", 9), yscrollcommand=fsb.set)
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        fsb.config(command=self.files_listbox.yview)
        self.files_listbox.bind('<<ListboxSelect>>', self.on_file_select)

        tk.Button(sc, text="🗑️ Delete Selected", command=self.delete_file,
                  bg="#dc3545", fg="white", font=("Arial", 8), relief=tk.FLAT,
                  padx=10, pady=5, cursor="hand2").pack(fill=tk.X, pady=(5, 0))

        tk.Label(sc, text="ANALYSIS SUMMARY", font=("Arial", 9, "bold"),
                 bg="#2d2d2d", fg="#888888", anchor=tk.W).pack(fill=tk.X, pady=(20, 5))

        sf = tk.Frame(sc, bg="#2d2d2d"); sf.pack(fill=tk.X, pady=5)
        self.severity_labels = {}
        for i, (sev, lbl, col) in enumerate([
            ("critical", "Critical", "#dc3545"), ("high", "High", "#ff9800"),
            ("medium",   "Medium",   "#ffc107"), ("low",  "Low",  "#4caf50"),
        ]):
            f = tk.Frame(sf, bg=col, relief=tk.RAISED, bd=1)
            f.grid(row=i//2, column=i%2, padx=5, pady=5, sticky="nsew")
            cnt = tk.Label(f, text="0", font=("Arial", 18, "bold"), bg=col, fg="white")
            cnt.pack(pady=(5, 0))
            tk.Label(f, text=lbl, font=("Arial", 8), bg=col, fg="white").pack(pady=(0, 5))
            self.severity_labels[sev] = cnt
        sf.columnconfigure(0, weight=1); sf.columnconfigure(1, weight=1)

        rh = tk.Frame(sc, bg="#2d2d2d"); rh.pack(fill=tk.X, pady=(20, 5))
        tk.Label(rh, text="DETECTION RULES", font=("Arial", 9, "bold"),
                 bg="#2d2d2d", fg="#888888", anchor=tk.W).pack(side=tk.LEFT)
        tk.Button(rh, text="⚙️", command=self.view_custom_rules, bg="#2d2d2d",
                  fg="#4a90e2", font=("Arial", 10), relief=tk.FLAT,
                  cursor="hand2", padx=5).pack(side=tk.RIGHT)

        self.rules_frame = tk.Frame(sc, bg="#2d2d2d"); self.rules_frame.pack(fill=tk.X, pady=5)
        self.update_rules_display()

    def _make_rule_toggle_row(self, parent, label, var, tag):
        """Single row: coloured dot + label + ON/OFF toggle button."""
        row = tk.Frame(parent, bg="#2d2d2d"); row.pack(fill=tk.X, pady=2)

        dot = tk.Label(row, text="●", font=("Arial", 9), bg="#2d2d2d",
                       fg="#4caf50" if var.get() else "#555555")
        dot.pack(side=tk.LEFT, padx=(0, 4))

        tk.Label(row, text=label, font=("Arial", 8), bg="#2d2d2d",
                 fg="white" if var.get() else "#666666",
                 anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)

        def toggle(v=var, d=dot, r=row, lbl=label, t=tag):
            v.set(not v.get())
            on = v.get()
            d.configure(fg="#4caf50" if on else "#555555")
            # update text colour of label widget in same row
            for w in r.winfo_children():
                if isinstance(w, tk.Label) and w != d:
                    w.configure(fg="white" if on else "#666666")
            self.save_config()
            if self.active_file: self.analyze_current_file(False)

        btn_txt = "ON" if var.get() else "OFF"
        btn_col = "#4caf50" if var.get() else "#555555"
        btn = tk.Button(row, text=btn_txt, font=("Arial", 7, "bold"),
                        bg=btn_col, fg="white", relief=tk.FLAT,
                        padx=6, pady=1, cursor="hand2")

        def toggle_with_btn(v=var, d=dot, r=row, b=btn):
            v.set(not v.get())
            on = v.get()
            d.configure(fg="#4caf50" if on else "#555555")
            b.configure(text="ON" if on else "OFF",
                        bg="#4caf50" if on else "#555555")
            for w in r.winfo_children():
                if isinstance(w, tk.Label) and w != d:
                    w.configure(fg="white" if on else "#666666")
            self.save_config()
            if self.active_file: self.analyze_current_file(False)

        btn.configure(command=toggle_with_btn)
        btn.pack(side=tk.RIGHT)
        return row

    def update_rules_display(self):
        for w in self.rules_frame.winfo_children(): w.destroy()

        # --- Default rules ---
        tk.Label(self.rules_frame, text="DEFAULT", font=("Arial", 7, "bold"),
                 bg="#2d2d2d", fg="#555555", anchor=tk.W).pack(fill=tk.X)
        owasp_lbl = f"OWASP Top 10  ({len(self.owasp_rules)} rules)"
        nist_lbl  = f"NIST Guidelines  ({len(self.nist_rules)} rules)"
        self._make_rule_toggle_row(self.rules_frame, owasp_lbl, self.owasp_enabled, "owasp")
        self._make_rule_toggle_row(self.rules_frame, nist_lbl,  self.nist_enabled,  "nist")

        # --- Imported rule sets ---
        if self.rule_sets:
            sep = tk.Frame(self.rules_frame, bg="#444444", height=1)
            sep.pack(fill=tk.X, pady=(8, 4))
            enabled_sets = sum(1 for rs in self.rule_sets if rs['enabled'].get())
            tk.Label(self.rules_frame,
                     text=f"IMPORTED  ({enabled_sets}/{len(self.rule_sets)} sets on)",
                     font=("Arial", 7, "bold"), bg="#2d2d2d", fg="#555555",
                     anchor=tk.W).pack(fill=tk.X)
            for rs in self.rule_sets:
                self._make_ruleset_sidebar_row(self.rules_frame, rs)
        else:
            sep = tk.Frame(self.rules_frame, bg="#444444", height=1)
            sep.pack(fill=tk.X, pady=(8, 4))
            tk.Label(self.rules_frame, text="No rule sets imported",
                     font=("Arial", 8), bg="#2d2d2d", fg="#555555",
                     anchor=tk.W).pack(fill=tk.X, pady=2)

    def _make_ruleset_sidebar_row(self, parent, rs):
        """Compact sidebar row for a whole rule set."""
        row = tk.Frame(parent, bg="#2d2d2d"); row.pack(fill=tk.X, pady=1)
        var = rs['enabled']
        n_on = sum(1 for r in rs['rules'] if r['enabled'].get())
        n_total = len(rs['rules'])

        dot = tk.Label(row, text="●", font=("Arial", 8), bg="#2d2d2d",
                       fg="#00bcd4" if var.get() else "#555555")
        dot.pack(side=tk.LEFT, padx=(0, 3))

        short = rs['name'][:16] + ("…" if len(rs['name']) > 16 else "")
        lbl = tk.Label(row, text=f"{short} ({n_on}/{n_total})",
                       font=("Arial", 7), bg="#2d2d2d",
                       fg="#cccccc" if var.get() else "#555555", anchor=tk.W)
        lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def toggle_set(v=var, d=dot, l=lbl, r=rs):
            v.set(not v.get())
            on = v.get()
            d.configure(fg="#00bcd4" if on else "#555555")
            n = sum(1 for x in r['rules'] if x['enabled'].get())
            l.configure(fg="#cccccc" if on else "#555555",
                        text=f"{r['name'][:16]}{'…' if len(r['name'])>16 else ''} ({n}/{len(r['rules'])})")
            self.update_rules_display()
            self.save_config()
            if self.active_file: self.analyze_current_file(False)

        btn = tk.Button(row, text="ON" if var.get() else "OFF",
                        font=("Arial", 7, "bold"),
                        bg="#00bcd4" if var.get() else "#555555",
                        fg="white", relief=tk.FLAT, padx=4, pady=1, cursor="hand2")

        def toggle_with_btn(v=var, d=dot, l=lbl, b=btn, r=rs):
            v.set(not v.get())
            on = v.get()
            d.configure(fg="#00bcd4" if on else "#555555")
            b.configure(text="ON" if on else "OFF", bg="#00bcd4" if on else "#555555")
            n = sum(1 for x in r['rules'] if x['enabled'].get())
            l.configure(fg="#cccccc" if on else "#555555",
                        text=f"{r['name'][:16]}{'…' if len(r['name'])>16 else ''} ({n}/{len(r['rules'])})")
            self.update_rules_display()
            self.save_config()
            if self.active_file: self.analyze_current_file(False)

        btn.configure(command=toggle_with_btn)
        btn.pack(side=tk.RIGHT)

        # --- Custom rules section ---
        enabled_count  = sum(1 for r in self.custom_rules if r['enabled'].get())
        total_count    = len(self.custom_rules)
        if total_count > 0:
            sep = tk.Frame(self.rules_frame, bg="#444444", height=1)
            sep.pack(fill=tk.X, pady=(8, 4))
            tk.Label(self.rules_frame, text=f"IMPORTED  ({enabled_count}/{total_count} on)",
                     font=("Arial", 7, "bold"), bg="#2d2d2d", fg="#555555",
                     anchor=tk.W).pack(fill=tk.X)
            for rule in self.custom_rules:
                self._make_custom_rule_inline_row(self.rules_frame, rule)
        else:
            sep = tk.Frame(self.rules_frame, bg="#444444", height=1)
            sep.pack(fill=tk.X, pady=(8, 4))
            tk.Label(self.rules_frame, text="No custom rules imported",
                     font=("Arial", 8), bg="#2d2d2d", fg="#555555",
                     anchor=tk.W).pack(fill=tk.X, pady=2)

    def _make_custom_rule_inline_row(self, parent, rule):
        pass  # replaced by _make_ruleset_sidebar_row — kept for compatibility

    def view_custom_rules(self):
        win = tk.Toplevel(self.root)
        win.title("Detection Rules Manager"); win.geometry("960x640")
        win.configure(bg="#1a1a1a"); win.transient(self.root)
        win.update_idletasks()
        win.geometry(f"960x640+{win.winfo_screenwidth()//2-480}+{win.winfo_screenheight()//2-320}")

        hdr = tk.Frame(win, bg="#2d2d2d"); hdr.pack(fill=tk.X, pady=(0, 0))
        tk.Label(hdr, text="Detection Rules Manager", font=("Arial", 16, "bold"),
                 bg="#2d2d2d", fg="white").pack(side=tk.LEFT, padx=20, pady=15)
        tk.Button(hdr, text="✕", command=win.destroy, bg="#dc3545", fg="white",
                  font=("Arial", 12, "bold"), relief=tk.FLAT, padx=10, pady=5,
                  cursor="hand2").pack(side=tk.RIGHT, padx=20)

        # ---- tabs strip ----
        tabs_row = tk.Frame(win, bg="#1a1a1a"); tabs_row.pack(fill=tk.X, padx=0)
        tab_default_btn = tk.Button(tabs_row, text="  Default Rules  ",
                                    font=("Arial", 10, "bold"), relief=tk.FLAT,
                                    bg="#4a90e2", fg="white", padx=10, pady=8, cursor="hand2")
        tab_custom_btn  = tk.Button(tabs_row, text="  Imported Rules  ",
                                    font=("Arial", 10), relief=tk.FLAT,
                                    bg="#2d2d2d", fg="#888888", padx=10, pady=8, cursor="hand2")
        tab_default_btn.pack(side=tk.LEFT, padx=(10, 2), pady=5)
        tab_custom_btn.pack(side=tk.LEFT, padx=2, pady=5)

        body = tk.Frame(win, bg="#1a1a1a"); body.pack(fill=tk.BOTH, expand=True)

        # ---- Default rules panel ----
        def make_default_panel():
            p = tk.Frame(body, bg="#1a1a1a"); p.pack(fill=tk.BOTH, expand=True)
            canvas = tk.Canvas(p, bg="#1a1a1a", highlightthickness=0)
            vsb    = tk.Scrollbar(p, orient=tk.VERTICAL, command=canvas.yview)
            cf     = tk.Frame(canvas, bg="#1a1a1a")
            canvas.configure(yscrollcommand=vsb.set)
            vsb.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
            canvas.create_window((0, 0), window=cf, anchor=tk.NW)
            cf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

            SC = {'critical':'#dc3545','high':'#ff9800','medium':'#ffc107','low':'#4caf50'}

            def default_rule_card(parent, title, subtitle, var, rules_list):
                on  = var.get()
                card = tk.Frame(parent, bg="#2d2d2d", relief=tk.RAISED, bd=1)
                card.pack(fill=tk.X, padx=5, pady=8)
                tk.Frame(card, bg="#4a90e2", width=4).pack(side=tk.LEFT, fill=tk.Y)
                cont = tk.Frame(card, bg="#2d2d2d")
                cont.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=12)

                hf = tk.Frame(cont, bg="#2d2d2d"); hf.pack(fill=tk.X)
                title_lbl = tk.Label(hf, text=title, font=("Arial", 12, "bold"),
                                     bg="#2d2d2d", fg="white")
                title_lbl.pack(side=tk.LEFT)

                status_lbl = tk.Label(hf, text="● ENABLED" if on else "● DISABLED",
                                      font=("Arial", 8, "bold"), bg="#2d2d2d",
                                      fg="#4caf50" if on else "#dc3545")
                status_lbl.pack(side=tk.LEFT, padx=10)

                tog = tk.Button(hf, text="Turn OFF" if on else "Turn ON",
                                font=("Arial", 9), relief=tk.FLAT, padx=10, pady=3,
                                bg="#dc3545" if on else "#4caf50", fg="white",
                                cursor="hand2")
                tog.pack(side=tk.RIGHT)

                tk.Label(cont, text=subtitle, font=("Arial", 9), bg="#2d2d2d",
                         fg="#888888").pack(anchor=tk.W, pady=(3, 8))

                # show a few sample rules
                for rule in rules_list[:4]:
                    rf = tk.Frame(cont, bg="#1a1a1a", relief=tk.SOLID, bd=1)
                    rf.pack(fill=tk.X, pady=2)
                    rtype = rule.get('type', 'Rule') if isinstance(rule, dict) else rule[2]
                    rsev  = rule.get('severity', 'medium') if isinstance(rule, dict) else rule[1]
                    tk.Label(rf, text=f"  {rtype}", font=("Arial", 8, "bold"),
                             bg="#1a1a1a", fg="white").pack(side=tk.LEFT, padx=5, pady=3)
                    tk.Label(rf, text=rsev.upper(), font=("Arial", 7, "bold"),
                             bg=SC.get(rsev,'#888'), fg="white",
                             padx=5, pady=2).pack(side=tk.RIGHT, padx=5, pady=3)
                if len(rules_list) > 4:
                    tk.Label(cont, text=f"  + {len(rules_list)-4} more rules…",
                             font=("Arial", 8), bg="#2d2d2d", fg="#555555").pack(anchor=tk.W)

                def do_toggle(v=var, s=status_lbl, t=tog):
                    v.set(not v.get())
                    is_on = v.get()
                    s.configure(text="● ENABLED" if is_on else "● DISABLED",
                                fg="#4caf50" if is_on else "#dc3545")
                    t.configure(text="Turn OFF" if is_on else "Turn ON",
                                bg="#dc3545" if is_on else "#4caf50")
                    self.update_rules_display()
                    self.save_config()
                    if self.active_file: self.analyze_current_file(False)

                tog.configure(command=do_toggle)

            default_rule_card(cf, "OWASP Top 10",
                              f"Covers OWASP A02:2021, A07:2021 — {len(self.owasp_rules)} detection patterns",
                              self.owasp_enabled, self.owasp_rules)
            default_rule_card(cf, "NIST Guidelines",
                              f"Covers SP 800-131A cryptographic algorithm requirements — {len(self.nist_rules)} detection patterns",
                              self.nist_enabled, self.nist_rules)
            return p

        # ---- Custom rules panel ----
        def make_custom_panel():
            p = tk.Frame(body, bg="#1a1a1a"); p.pack(fill=tk.BOTH, expand=True)

            ab = tk.Frame(p, bg="#2d2d2d"); ab.pack(fill=tk.X, padx=10, pady=8)
            n_sets  = len(self.rule_sets)
            n_rules = sum(len(rs['rules']) for rs in self.rule_sets)
            tk.Label(ab, text=f"{n_sets} set(s)  ·  {n_rules} rules total",
                     font=("Arial", 10), bg="#2d2d2d", fg="#4a90e2").pack(side=tk.LEFT, padx=10)
            tk.Button(ab, text="➕ Import Set", bg="#4a90e2", fg="white",
                      font=("Arial", 8), relief=tk.FLAT, padx=8, pady=4, cursor="hand2",
                      command=lambda: [win.destroy(), self.import_rules()]).pack(side=tk.RIGHT, padx=3)

            def refresh(): win.destroy(); self.view_custom_rules()

            if not self.rule_sets:
                ef = tk.Frame(p, bg="#1a1a1a"); ef.pack(expand=True, fill=tk.BOTH, pady=50)
                tk.Label(ef, text="📋", font=("Arial", 48), bg="#1a1a1a", fg="#888888").pack(pady=10)
                tk.Label(ef, text="No Rule Sets Imported", font=("Arial", 14, "bold"),
                         bg="#1a1a1a", fg="#888888").pack(pady=5)
                tk.Label(ef, text="Import a JSON rule file to get started",
                         font=("Arial", 9), bg="#1a1a1a", fg="#555555").pack()
                tk.Button(ef, text="📋 Import Rules",
                          command=lambda: [win.destroy(), self.import_rules()],
                          bg="#4a90e2", fg="white", font=("Arial", 11), relief=tk.FLAT,
                          padx=20, pady=10, cursor="hand2").pack(pady=20)
                return p

            canvas = tk.Canvas(p, bg="#1a1a1a", highlightthickness=0)
            vsb    = tk.Scrollbar(p, orient=tk.VERTICAL, command=canvas.yview)
            cf     = tk.Frame(canvas, bg="#1a1a1a")
            canvas.configure(yscrollcommand=vsb.set)
            vsb.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            canvas.create_window((0, 0), window=cf, anchor=tk.NW, width=900)
            cf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            SC = {'critical':'#dc3545','high':'#ff9800','medium':'#ffc107','low':'#4caf50'}

            for rs in self.rule_sets:
                set_frame = tk.Frame(cf, bg="#252525", relief=tk.RAISED, bd=1)
                set_frame.pack(fill=tk.X, padx=5, pady=6)
                accent_col = "#00bcd4" if rs['enabled'].get() else "#444444"
                accent = tk.Frame(set_frame, bg=accent_col, width=5)
                accent.pack(side=tk.LEFT, fill=tk.Y)
                body_f = tk.Frame(set_frame, bg="#252525")
                body_f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

                hdr_f = tk.Frame(body_f, bg="#2d2d2d"); hdr_f.pack(fill=tk.X)
                expanded = [False]
                rules_area = tk.Frame(body_f, bg="#1e1e1e")

                expand_btn = tk.Button(hdr_f, text="▶", font=("Arial", 9),
                                       bg="#2d2d2d", fg="#888888", relief=tk.FLAT, cursor="hand2", padx=6)
                expand_btn.pack(side=tk.LEFT, padx=(8,4), pady=8)

                name_var = tk.StringVar(value=rs['name'])
                name_lbl = tk.Label(hdr_f, textvariable=name_var, font=("Arial", 12, "bold"),
                                    bg="#2d2d2d", fg="white", cursor="hand2")
                name_lbl.pack(side=tk.LEFT, padx=4, pady=8)

                n_on = sum(1 for r in rs['rules'] if r['enabled'].get())
                count_lbl = tk.Label(hdr_f, text=f"  {n_on}/{len(rs['rules'])} rules active",
                                     font=("Arial", 8), bg="#2d2d2d", fg="#888888")
                count_lbl.pack(side=tk.LEFT, padx=4)
                tk.Label(hdr_f, text=f"from {rs['source_file']}", font=("Arial", 7),
                         bg="#2d2d2d", fg="#555555").pack(side=tk.LEFT, padx=4)

                def make_delete_set(r=rs):
                    def _del():
                        if messagebox.askyesno("Delete Rule Set",
                                f"Delete entire rule set '{r['name']}'?\n"
                                f"This removes all {len(r['rules'])} rules."):
                            self.rule_sets.remove(r)
                            self._rebuild_custom_rules()
                            self.update_rules_display(); self.save_config()
                            if self.active_file: self.analyze_current_file(False)
                            refresh()
                    return _del

                tk.Button(hdr_f, text="🗑 Delete Set", command=make_delete_set(rs),
                          bg="#dc3545", fg="white", font=("Arial", 8),
                          relief=tk.FLAT, padx=8, pady=3, cursor="hand2").pack(side=tk.RIGHT, padx=5)

                def make_rename(r=rs, nv=name_var):
                    def _rename():
                        dlg = tk.Toplevel(win); dlg.title("Rename Rule Set")
                        dlg.geometry("360x130"); dlg.configure(bg="#2d2d2d")
                        dlg.transient(win); dlg.grab_set()
                        dlg.update_idletasks()
                        dlg.geometry(f"360x130+{dlg.winfo_screenwidth()//2-180}+{dlg.winfo_screenheight()//2-65}")
                        tk.Label(dlg, text="New name for rule set:", font=("Arial",10),
                                 bg="#2d2d2d", fg="white").pack(pady=(15,5))
                        ev = tk.StringVar(value=r['name'])
                        ent = tk.Entry(dlg, textvariable=ev, font=("Arial",11),
                                       bg="#1a1a1a", fg="white", insertbackground="white", relief=tk.FLAT)
                        ent.pack(fill=tk.X, padx=20, ipady=6)
                        ent.select_range(0, tk.END); ent.focus_set()
                        def _ok():
                            new = ev.get().strip()
                            if new:
                                r['name'] = new; nv.set(new)
                                self.update_rules_display(); self.save_config()
                            dlg.destroy()
                        ent.bind("<Return>", lambda e: _ok())
                        tk.Button(dlg, text="Rename", command=_ok, bg="#4a90e2",
                                  fg="white", font=("Arial",10), relief=tk.FLAT,
                                  padx=15, pady=5).pack(pady=10)
                        dlg.wait_window()
                    return _rename

                tk.Button(hdr_f, text="✏ Rename", command=make_rename(rs, name_var),
                          bg="#555555", fg="white", font=("Arial", 8),
                          relief=tk.FLAT, padx=8, pady=3, cursor="hand2").pack(side=tk.RIGHT, padx=2)

                set_status = tk.Label(hdr_f, text="● ON" if rs['enabled'].get() else "● OFF",
                                      font=("Arial", 8, "bold"), bg="#2d2d2d",
                                      fg="#00bcd4" if rs['enabled'].get() else "#dc3545")
                set_status.pack(side=tk.RIGHT, padx=5)

                def make_set_toggle_btn(r=rs, sl=set_status, ac=accent):
                    tog_ref = [None]
                    def _tog():
                        r['enabled'].set(not r['enabled'].get())
                        on = r['enabled'].get()
                        sl.configure(text="● ON" if on else "● OFF",
                                     fg="#00bcd4" if on else "#dc3545")
                        ac.configure(bg="#00bcd4" if on else "#444444")
                        if tog_ref[0]: tog_ref[0].configure(text="Disable Set" if on else "Enable Set")
                        self._rebuild_custom_rules(); self.update_rules_display()
                        self.save_config()
                        if self.active_file: self.analyze_current_file(False)
                    return _tog, tog_ref

                _tog_fn, _tog_ref = make_set_toggle_btn(rs, set_status, accent)
                tog_btn = tk.Button(hdr_f, text="Disable Set" if rs['enabled'].get() else "Enable Set",
                                    font=("Arial", 8), relief=tk.FLAT, bg="#444444",
                                    fg="white", padx=8, pady=3, cursor="hand2", command=_tog_fn)
                _tog_ref[0] = tog_btn
                tog_btn.pack(side=tk.RIGHT, padx=2)

                def build_rules_area(r=rs, ra=rules_area, cl=count_lbl):
                    for w in ra.winfo_children(): w.destroy()
                    bar = tk.Frame(ra, bg="#1a1a1a"); bar.pack(fill=tk.X, padx=8, pady=(6,2))
                    def _en_all(rs=r, cl=cl):
                        for x in rs['rules']: x['enabled'].set(True)
                        cl.configure(text=f"  {len(rs['rules'])}/{len(rs['rules'])} rules active")
                        self._rebuild_custom_rules(); self.save_config()
                        if self.active_file: self.analyze_current_file(False)
                        build_rules_area(r, ra, cl)
                    def _dis_all(rs=r, cl=cl):
                        for x in rs['rules']: x['enabled'].set(False)
                        cl.configure(text=f"  0/{len(rs['rules'])} rules active")
                        self._rebuild_custom_rules(); self.save_config()
                        if self.active_file: self.analyze_current_file(False)
                        build_rules_area(r, ra, cl)
                    tk.Button(bar, text="✓ Enable All", bg="#4caf50", fg="white",
                              font=("Arial",7), relief=tk.FLAT, padx=6, pady=2,
                              cursor="hand2", command=_en_all).pack(side=tk.LEFT, padx=2)
                    tk.Button(bar, text="✗ Disable All", bg="#555555", fg="white",
                              font=("Arial",7), relief=tk.FLAT, padx=6, pady=2,
                              cursor="hand2", command=_dis_all).pack(side=tk.LEFT, padx=2)

                    for rule in r['rules']:
                        rf = tk.Frame(ra, bg="#1e1e1e"); rf.pack(fill=tk.X, padx=8, pady=2)
                        sev = rule.get('severity','medium')
                        tk.Frame(rf, bg=SC.get(sev,'#888'), width=3).pack(side=tk.LEFT, fill=tk.Y)
                        rc = tk.Frame(rf, bg="#1e1e1e")
                        rc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=6)
                        rh = tk.Frame(rc, bg="#1e1e1e"); rh.pack(fill=tk.X)

                        rule_name_var = tk.StringVar(value=rule['type'])
                        tk.Label(rh, textvariable=rule_name_var, font=("Arial",9,"bold"),
                                 bg="#1e1e1e", fg="white").pack(side=tk.LEFT)
                        tk.Label(rh, text=sev.upper(), font=("Arial",7,"bold"),
                                 bg=SC.get(sev,'#888'), fg="white", padx=5, pady=1).pack(side=tk.LEFT, padx=5)

                        rstatus = tk.Label(rh, text="ON" if rule['enabled'].get() else "OFF",
                                           font=("Arial",7,"bold"), bg="#1e1e1e",
                                           fg="#4caf50" if rule['enabled'].get() else "#888888")
                        rstatus.pack(side=tk.RIGHT, padx=4)

                        def make_rule_toggle(rl=rule, rs2=r, rsl=rstatus, cl2=cl):
                            def _t():
                                rl['enabled'].set(not rl['enabled'].get())
                                on = rl['enabled'].get()
                                rsl.configure(text="ON" if on else "OFF",
                                              fg="#4caf50" if on else "#888888")
                                n = sum(1 for x in rs2['rules'] if x['enabled'].get())
                                cl2.configure(text=f"  {n}/{len(rs2['rules'])} rules active")
                                self._rebuild_custom_rules(); self.save_config()
                                if self.active_file: self.analyze_current_file(False)
                            return _t
                        tk.Button(rh, text="Toggle", command=make_rule_toggle(rule, r, rstatus, cl),
                                  font=("Arial",7), bg="#333333", fg="white", relief=tk.FLAT,
                                  padx=5, pady=1, cursor="hand2").pack(side=tk.RIGHT)

                        def make_rule_rename(rl=rule, rnv=rule_name_var):
                            def _rn():
                                dlg2 = tk.Toplevel(win); dlg2.title("Rename Rule")
                                dlg2.geometry("360x130"); dlg2.configure(bg="#2d2d2d")
                                dlg2.transient(win); dlg2.grab_set()
                                dlg2.update_idletasks()
                                dlg2.geometry(f"360x130+{dlg2.winfo_screenwidth()//2-180}+{dlg2.winfo_screenheight()//2-65}")
                                tk.Label(dlg2, text="New rule name:", font=("Arial",10),
                                         bg="#2d2d2d", fg="white").pack(pady=(15,5))
                                ev2 = tk.StringVar(value=rl['type'])
                                ent2 = tk.Entry(dlg2, textvariable=ev2, font=("Arial",11),
                                                bg="#1a1a1a", fg="white", insertbackground="white", relief=tk.FLAT)
                                ent2.pack(fill=tk.X, padx=20, ipady=6)
                                ent2.select_range(0, tk.END); ent2.focus_set()
                                def _ok2():
                                    new2 = ev2.get().strip()
                                    if new2:
                                        rl['type'] = new2; rnv.set(new2); self.save_config()
                                    dlg2.destroy()
                                ent2.bind("<Return>", lambda e: _ok2())
                                tk.Button(dlg2, text="Rename", command=_ok2, bg="#4a90e2",
                                          fg="white", font=("Arial",10), relief=tk.FLAT,
                                          padx=15, pady=5).pack(pady=10)
                                dlg2.wait_window()
                            return _rn
                        tk.Button(rh, text="✏", command=make_rule_rename(rule, rule_name_var),
                                  font=("Arial",8), bg="#333333", fg="#aaaaaa",
                                  relief=tk.FLAT, padx=4, pady=1, cursor="hand2").pack(side=tk.RIGHT, padx=2)

                        def make_rule_delete(rl=rule, rs2=r, cl2=cl):
                            def _d():
                                if messagebox.askyesno("Delete Rule", f"Delete rule '{rl['type']}'?"):
                                    rs2['rules'].remove(rl)
                                    if not rs2['rules']: self.rule_sets.remove(rs2)
                                    self._rebuild_custom_rules()
                                    self.update_rules_display(); self.save_config()
                                    if self.active_file: self.analyze_current_file(False)
                                    refresh()
                            return _d
                        tk.Button(rh, text="🗑", command=make_rule_delete(rule, r, cl),
                                  font=("Arial",8), bg="#1e1e1e", fg="#dc3545",
                                  relief=tk.FLAT, padx=4, cursor="hand2").pack(side=tk.RIGHT, padx=2)

                        pf = tk.Frame(rc, bg="#141414", relief=tk.SOLID, bd=1)
                        pf.pack(fill=tk.X, pady=(3,0))
                        tk.Label(pf, text=rule.get('pattern',''), font=("Consolas",8),
                                 bg="#141414", fg="#4a90e2",
                                 wraplength=820, justify=tk.LEFT).pack(anchor=tk.W, padx=6, pady=3)
                        if rule.get('description'):
                            tk.Label(rc, text=rule['description'], font=("Arial",8),
                                     bg="#1e1e1e", fg="#aaaaaa",
                                     wraplength=820, justify=tk.LEFT).pack(anchor=tk.W, pady=(2,0))
                    tk.Frame(ra, bg="#333333", height=1).pack(fill=tk.X, padx=8, pady=6)

                def make_expand(eb=expand_btn, ra=rules_area, exp=expanded, r=rs, cl=count_lbl):
                    def _toggle():
                        exp[0] = not exp[0]
                        if exp[0]:
                            eb.configure(text="▼")
                            build_rules_area(r, ra, cl)
                            ra.pack(fill=tk.X)
                        else:
                            eb.configure(text="▶")
                            ra.pack_forget()
                        canvas.update_idletasks()
                        canvas.configure(scrollregion=canvas.bbox("all"))
                    return _toggle

                _exp_fn = make_expand(expand_btn, rules_area, expanded, rs, count_lbl)
                expand_btn.configure(command=_exp_fn)
                name_lbl.bind("<Button-1>", lambda e, fn=_exp_fn: fn())

            return p

        panels = {}
        active_panel = [None]

        def show_tab(which):
            if active_panel[0]: active_panel[0].pack_forget()
            if which == 'default':
                tab_default_btn.configure(bg="#4a90e2", fg="white", font=("Arial", 10, "bold"))
                tab_custom_btn.configure(bg="#2d2d2d", fg="#888888", font=("Arial", 10))
                if 'default' not in panels:
                    panels['default'] = make_default_panel()
                else:
                    panels['default'].pack(fill=tk.BOTH, expand=True)
                active_panel[0] = panels['default']
            else:
                tab_custom_btn.configure(bg="#4a90e2", fg="white", font=("Arial", 10, "bold"))
                tab_default_btn.configure(bg="#2d2d2d", fg="#888888", font=("Arial", 10))
                if 'custom' not in panels:
                    panels['custom'] = make_custom_panel()
                else:
                    panels['custom'].pack(fill=tk.BOTH, expand=True)
                active_panel[0] = panels['custom']

        tab_default_btn.configure(command=lambda: show_tab('default'))
        tab_custom_btn.configure(command=lambda: show_tab('custom'))
        show_tab('default')

    def update_layout(self):
        if getattr(self, "_layout_updating", False): return
        self._layout_updating = True
        try:
            # If no file loaded, show welcome screen instead of editor
            if not self.active_file:
                self._show_welcome()
                return
            self._show_editor()
            for p in self.content_paned.panes(): self.content_paned.forget(p)
            if self.show_code.get():            self.content_paned.add(self.code_panel)
            if self.show_ast.get():             self.content_paned.add(self.ast_panel)
            if self.show_dataflow.get():        self.content_paned.add(self.dataflow_panel)
            if self.show_vulnerabilities.get(): self.content_paned.add(self.vuln_panel)
            if not self.content_paned.panes():
                self.show_code.set(True); self.content_paned.add(self.code_panel)
        finally:
            self._layout_updating = False

    def setup_content_panels(self):
        self.content_paned = tk.PanedWindow(self.content_container, orient=tk.HORIZONTAL,
                                            bg="#1a1a1a", sashwidth=5, sashrelief=tk.RAISED)
        # NOTE: content_paned is NOT packed here — _show_editor() packs it when needed.
        # This ensures update_layout() at startup correctly shows the welcome screen.

        # -- Welcome panel (shown when no file is loaded) ----------------------
        self.welcome_panel = tk.Frame(self.content_container, bg="#1a1a1a")
        self._build_welcome_panel()

        # -- Code panel --------------------------------------------------------
        self.code_panel = tk.Frame(self.content_container, bg="#1a1a1a")
        ch = tk.Frame(self.code_panel, bg="#1a1a1a"); ch.pack(fill=tk.X, pady=(5,5))
        tk.Label(ch, text="Source Code", font=("Arial",12,"bold"),
                 bg="#1a1a1a", fg="white").pack(side=tk.LEFT)
        self.code_text = scrolledtext.ScrolledText(
            self.code_panel, wrap=tk.NONE, bg="#0d1117", fg="#c9d1d9",
            font=("Consolas", 10), insertbackground="white")
        self.code_text.pack(fill=tk.BOTH, expand=True)
        # tag for copyright banner
        self.code_text.tag_config("copyright", foreground="#4a90e2",
                                  background="#0d2040", font=("Consolas", 10, "italic"))
        # tag for highlighted vulnerable line
        self.code_text.tag_config("vuln_highlight", background="#3a1a1a",
                                  foreground="#ff6b6b", font=("Consolas", 10, "bold"))
        # tag for the jump cursor line
        self.code_text.tag_config("jump_line", background="#ff6b6b",
                                  foreground="#ffffff", font=("Consolas", 10, "bold"))

        # -- AST panel ---------------------------------------------------------
        self.ast_panel = tk.Frame(self.content_container, bg="#1a1a1a")
        ah = tk.Frame(self.ast_panel, bg="#1a1a1a"); ah.pack(fill=tk.X, pady=(5,5))
        tk.Label(ah, text="Abstract Syntax Tree", font=("Arial",12,"bold"),
                 bg="#1a1a1a", fg="white").pack(side=tk.LEFT)
        self.setup_ast_tree(self.ast_panel)

        # -- Data Flow panel ---------------------------------------------------
        self.dataflow_panel = tk.Frame(self.content_container, bg="#1a1a1a")
        dh = tk.Frame(self.dataflow_panel, bg="#1a1a1a"); dh.pack(fill=tk.X, pady=(5,5))
        tk.Label(dh, text="Data Flow Analysis", font=("Arial",12,"bold"),
                 bg="#1a1a1a", fg="white").pack(side=tk.LEFT)
        self.setup_dataflow_tree(self.dataflow_panel)

        # -- Vulnerabilities panel ---------------------------------------------
        self.vuln_panel = tk.Frame(self.content_container, bg="#1a1a1a")

        # header row with title + count
        vh = tk.Frame(self.vuln_panel, bg="#1a1a1a"); vh.pack(fill=tk.X, pady=(5, 0))
        tk.Label(vh, text="Detected Vulnerabilities", font=("Arial",12,"bold"),
                 bg="#1a1a1a", fg="white").pack(side=tk.LEFT)
        self.vuln_count_label = tk.Label(vh, text="(0 issues)", font=("Arial",10),
                                         bg="#1a1a1a", fg="#ff9800")
        self.vuln_count_label.pack(side=tk.LEFT, padx=5)

        # filter bar
        fb = tk.Frame(self.vuln_panel, bg="#1a1a1a"); fb.pack(fill=tk.X, pady=(4, 4))
        tk.Label(fb, text="Filter:", font=("Arial", 8), bg="#1a1a1a",
                 fg="#888888").pack(side=tk.LEFT, padx=(2, 4))

        self._filter_buttons = {}
        filter_opts = [
            ("All",      "all",      "#4a90e2"),
            ("Critical", "critical", "#dc3545"),
            ("High",     "high",     "#ff9800"),
            ("Medium",   "medium",   "#ffc107"),
            ("Low",      "low",      "#4caf50"),
        ]
        for label, val, col in filter_opts:
            b = tk.Button(fb, text=label, font=("Arial", 8, "bold"),
                          bg=col if self.filter_severity.get() == val else "#333333",
                          fg="white", relief=tk.FLAT, padx=10, pady=3, cursor="hand2",
                          command=lambda v=val: self._apply_filter(v))
            b.pack(side=tk.LEFT, padx=2)
            self._filter_buttons[val] = (b, col)

        self.setup_vulnerabilities_panel(self.vuln_panel)

        # NOTE: panels are NOT added to content_paned here.
        # update_layout() adds only the checked panels when a file is loaded.

    def _build_welcome_panel(self):
        """Build the welcome/empty state screen shown before any file is loaded."""
        for w in self.welcome_panel.winfo_children(): w.destroy()
        outer = tk.Frame(self.welcome_panel, bg="#1a1a1a")
        outer.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(outer, text="🔐", font=("Arial", 64), bg="#1a1a1a",
                 fg="#4a90e2").pack(pady=(0, 10))
        tk.Label(outer, text="Welcome to CryptoLint",
                 font=("Arial", 22, "bold"), bg="#1a1a1a", fg="white").pack()
        tk.Label(outer, text="Cryptographic Vulnerability Scanner",
                 font=("Arial", 11), bg="#1a1a1a", fg="#888888").pack(pady=(2, 24))

        # dashed drop zone
        drop = tk.Frame(outer, bg="#1e2a3a", relief=tk.FLAT, bd=2)
        drop.pack(padx=20, pady=4, ipadx=30, ipady=20)
        tk.Label(drop, text="📂", font=("Arial", 32), bg="#1e2a3a",
                 fg="#4a90e2").pack(pady=(10, 4))
        tk.Label(drop, text="Open a Python file to begin scanning",
                 font=("Arial", 11), bg="#1e2a3a", fg="#aaaaaa").pack()
        tk.Label(drop, text="Supports .py files",
                 font=("Arial", 9), bg="#1e2a3a", fg="#555555").pack(pady=(2, 10))

        tk.Button(outer, text="📁  Open File",
                  command=self.open_file,
                  bg="#4a90e2", fg="white", font=("Arial", 12, "bold"),
                  relief=tk.FLAT, padx=30, pady=10, cursor="hand2").pack(pady=20)

        # rule status pills
        pills = tk.Frame(outer, bg="#1a1a1a"); pills.pack(pady=(0, 10))
        for txt, col in [("OWASP Top 10", "#4caf50"), ("NIST Guidelines", "#4caf50")]:
            tk.Label(pills, text=f"● {txt}", font=("Arial", 9),
                     bg="#1a1a1a", fg=col).pack(side=tk.LEFT, padx=8)

    def _show_welcome(self):
        """Switch content area to welcome screen."""
        self.content_paned.pack_forget()
        self.welcome_panel.pack(fill=tk.BOTH, expand=True)

    def _show_editor(self):
        """Switch content area from welcome to editor panels."""
        self.welcome_panel.pack_forget()
        self.content_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _apply_filter(self, severity_val):
        """Set the active severity filter and re-render vulnerability list."""
        self.filter_severity.set(severity_val)
        # update button colours
        for val, (btn, col) in self._filter_buttons.items():
            btn.configure(bg=col if val == severity_val else "#333333")
        self.display_vulnerabilities()

    def setup_ast_tree(self, parent):
        tf = tk.Frame(parent, bg="#0d1117"); tf.pack(fill=tk.BOTH, expand=True)
        sy = tk.Scrollbar(tf); sx = tk.Scrollbar(tf, orient=tk.HORIZONTAL)
        self.ast_tree = ttk.Treeview(tf, yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.config(command=self.ast_tree.yview); sx.config(command=self.ast_tree.xview)
        sy.pack(side=tk.RIGHT, fill=tk.Y); sx.pack(side=tk.BOTTOM, fill=tk.X)
        self.ast_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        s = ttk.Style(); s.theme_use('clam')
        s.configure("Treeview", background="#0d1117", foreground="#c9d1d9",
                    fieldbackground="#0d1117", font=("Consolas",9))
        s.configure("Treeview.Heading", background="#2d2d2d", foreground="white",
                    font=("Arial",10,"bold"))
        s.map('Treeview', background=[('selected','#4a90e2')])

    def setup_dataflow_tree(self, parent):
        tf = tk.Frame(parent, bg="#0d1117"); tf.pack(fill=tk.BOTH, expand=True)
        sy = tk.Scrollbar(tf); sx = tk.Scrollbar(tf, orient=tk.HORIZONTAL)
        self.dataflow_tree = ttk.Treeview(tf, yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.config(command=self.dataflow_tree.yview); sx.config(command=self.dataflow_tree.xview)
        sy.pack(side=tk.RIGHT, fill=tk.Y); sx.pack(side=tk.BOTTOM, fill=tk.X)
        self.dataflow_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def setup_vulnerabilities_panel(self, parent):
        canvas = tk.Canvas(parent, bg="#1a1a1a", highlightthickness=0)
        vsb = tk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        self.vuln_container = tk.Frame(canvas, bg="#1a1a1a")
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=self.vuln_container, anchor=tk.NW)
        self.vuln_container.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    # ------------------------------------------------------------------ #
    #  File management
    # ------------------------------------------------------------------ #

    def open_file(self):
        paths = filedialog.askopenfilenames(
            title="Select Python Files",
            filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        for fp in paths:
            try:
                with open(fp, 'r', encoding='utf-8') as f:
                    content = f.read()
                fd = {'name': os.path.basename(fp), 'path': fp, 'content': content}
                self.files.append(fd)
                self.files_listbox.insert(tk.END, fd['name'])
                if not self.active_file:
                    self.active_file = fd
                    self.files_listbox.selection_set(len(self.files)-1)
                    self._show_editor()
                    self.update_layout()
                    self.display_code()
                    self.analyze_current_file()
                self.save_config()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load {fp}: {e}")

    def delete_file(self):
        sel = self.files_listbox.curselection()
        if not sel:
            messagebox.showwarning("Warning", "Please select a file to delete."); return
        idx  = sel[0]
        name = self.files[idx]['name']
        if not messagebox.askyesno("Confirm Delete",
                f"Remove '{name}' from the project?\n\n"
                "(The actual file on disk will NOT be deleted)"): return
        del self.files[idx]; self.files_listbox.delete(idx)
        if self.active_file and self.active_file['name'] == name:
            self.active_file = None; self.vulnerabilities = []
            self.code_text.delete(1.0, tk.END)
            self.update_severity_counts()
            self.issue_label.configure(text="0 Issues")
            for t in [self.ast_tree, self.dataflow_tree]:
                for i in t.get_children(): t.delete(i)
            for w in self.vuln_container.winfo_children(): w.destroy()
            if self.files:
                self.active_file = self.files[0]
                self.files_listbox.selection_set(0)
                self.display_code(); self.analyze_current_file()
            else:
                self._show_welcome()
        self.save_config()

    def on_file_select(self, event):
        sel = self.files_listbox.curselection()
        if sel:
            self.active_file = self.files[sel[0]]
            self.display_code()
            self.analyze_current_file(show_popup=False)

    def import_rules(self):
        fp = filedialog.askopenfilename(
            title="Select Rule File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
        if not fp: return
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Determine set name: use JSON metadata name, else filename without extension
            set_name = (data.get('metadata', {}).get('name')
                        or data.get('name')
                        or os.path.splitext(os.path.basename(fp))[0])

            rules_in_set = []
            for rule in data.get('rules', []):
                patterns = rule.get('patterns', [])
                if isinstance(patterns, list) and patterns:
                    pat = patterns[0]
                elif rule.get('pattern'):
                    pat = rule.get('pattern')
                else:
                    continue
                try:
                    re.compile(pat)
                    rules_in_set.append({
                        'id':          self._next_rule_id,
                        'pattern':     pat,
                        'severity':    rule.get('severity', 'medium'),
                        'type':        rule.get('type', rule.get('id', 'Custom Rule')),
                        'description': rule.get('description', 'Custom vulnerability detected'),
                        'remediation': rule.get('remediation', 'Review and fix the issue'),
                        'nist_ref':    rule.get('nist_ref', ''),
                        'cwe':         rule.get('cwe', ''),
                        'enabled':     tk.BooleanVar(value=True),
                    })
                    self._next_rule_id += 1
                except re.error:
                    pass

            if not rules_in_set:
                messagebox.showwarning("Warning", "No valid rules found in the selected file.")
                return

            new_set = {
                'id':          self._next_set_id,
                'name':        set_name,
                'source_file': os.path.basename(fp),
                'enabled':     tk.BooleanVar(value=True),
                'rules':       rules_in_set,
            }
            self._next_set_id += 1
            self.rule_sets.append(new_set)
            self._rebuild_custom_rules()
            self.update_rules_display()
            self.save_config()
            messagebox.showinfo("Success",
                f"Imported rule set '{set_name}' with {len(rules_in_set)} rules.")
            if self.active_file: self.analyze_current_file(False)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")

    def _rebuild_custom_rules(self):
        """Rebuild the flat self.custom_rules list from all rule sets (for detection)."""
        self.custom_rules = []
        for rs in self.rule_sets:
            if rs['enabled'].get():
                for r in rs['rules']:
                    self.custom_rules.append(r)
        self.custom_rule_count = sum(len(rs['rules']) for rs in self.rule_sets)

    # ------------------------------------------------------------------ #
    #  Display
    # ------------------------------------------------------------------ #

    def display_code(self):
        """Show source code with copyright banner prepended (display only)."""
        if not self.active_file: return
        self.code_text.delete(1.0, tk.END)

        banner = build_copyright_banner()
        banner_lines = banner.split('\n')

        # Insert banner with blue highlight tag
        for i, bline in enumerate(banner_lines, 1):
            self.code_text.insert(tk.END, f"{'':4s}  {bline}\n", "copyright")

        # Insert actual source lines
        for i, line in enumerate(self.active_file['content'].split('\n'), 1):
            self.code_text.insert(tk.END, f"{i:4d}  {line}\n")

    # ------------------------------------------------------------------ #
    #  Analysis
    # ------------------------------------------------------------------ #

    def analyze_current_file(self, show_popup=False):
        if not self.active_file:
            messagebox.showwarning("Warning", "No file loaded to analyze."); return
        self.vulnerabilities = self.detect_vulnerabilities(self.active_file['content'])
        self.analysis_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in self.vulnerabilities: self.analysis_counts[v.severity] += 1
        self.update_severity_counts()
        self.issue_label.configure(text=f"{len(self.vulnerabilities)} Issues")
        self._highlight_vuln_lines()
        self.generate_ast(); self.generate_data_flow(); self.display_vulnerabilities()
        if show_popup:
            messagebox.showinfo("Analysis Complete",
                                f"Found {len(self.vulnerabilities)} security issues.")

    def _highlight_vuln_lines(self):
        """Paint a soft red background on every vulnerable line in the code viewer."""
        BANNER_OFFSET = 7
        self.code_text.tag_remove("vuln_highlight", "1.0", tk.END)
        self.code_text.tag_remove("jump_line",      "1.0", tk.END)
        seen = set()
        for v in self.vulnerabilities:
            if v.line in seen: continue
            seen.add(v.line)
            actual = v.line + BANNER_OFFSET
            self.code_text.tag_add("vuln_highlight", f"{actual}.0", f"{actual}.end")

    def detect_vulnerabilities(self, code):
        vulns = []
        lines = code.split('\n')

        def run_ruleset(ruleset):
            for ln, line in enumerate(lines, 1):
                for rule in ruleset:
                    try:
                        if re.search(rule['pattern'], line):
                            vulns.append(Vulnerability(
                                line=ln,
                                code=mask_sensitive_code(line.strip()),
                                severity=rule['severity'],
                                vuln_type=rule['type'],
                                description=rule['description'],
                                remediation=rule['remediation']))
                    except re.error:
                        pass

        # Each toggle controls its own independent ruleset
        if self.owasp_enabled.get():
            run_ruleset(self.owasp_rules)

        if self.nist_enabled.get():
            run_ruleset(self.nist_rules)

        # Custom rule sets — set-level and rule-level enabled flags both respected
        for rs in self.rule_sets:
            if not rs['enabled'].get():
                continue
            for ln, line in enumerate(lines, 1):
                for rule in rs['rules']:
                    if not rule['enabled'].get():
                        continue
                    try:
                        if re.search(rule['pattern'], line):
                            vulns.append(Vulnerability(
                                line=ln,
                                code=mask_sensitive_code(line.strip()),
                                severity=rule['severity'],
                                vuln_type=rule['type'],
                                description=rule['description'],
                                remediation=rule['remediation']))
                    except re.error:
                        pass

        return vulns

    def get_description(self, vt):
        """Fallback descriptions for any rules not providing their own description."""
        return {
            'Weak Hashing Algorithm':     'MD5 and SHA1 are cryptographically broken.',
            'Hardcoded Secret':           'Sensitive credentials are hardcoded in source code.',
            'Weak Encryption Algorithm':  'DES is deprecated and vulnerable to brute force.',
            'Insecure Cipher Mode':       'ECB mode reveals patterns in plaintext.',
            'Insecure Random Generation': 'Standard random module is not cryptographically secure.',
            'Insufficient Key Size':      'RSA keys < 2048 bits are vulnerable to factorization.',
        }.get(vt, 'Security vulnerability detected.')

    def get_remediation(self, vt):
        """Fallback remediations for any rules not providing their own remediation."""
        return {
            'Weak Hashing Algorithm':     'Use SHA256 or SHA3: hashlib.sha256()',
            'Hardcoded Secret':           'Store secrets in environment variables or secure vaults',
            'Weak Encryption Algorithm':  'Use AES with GCM or CBC mode',
            'Insecure Cipher Mode':       'Use AES.MODE_GCM or AES.MODE_CBC with random IV',
            'Insecure Random Generation': 'Use secrets module: secrets.token_bytes()',
            'Insufficient Key Size':      'Use at least 2048-bit keys: RSA.generate(2048)',
        }.get(vt, 'Review security best practices.')

    def update_severity_counts(self):
        for sev, lbl in self.severity_labels.items():
            lbl.configure(text=str(self.analysis_counts[sev]))

    def generate_ast(self):
        if not self.active_file: return
        for i in self.ast_tree.get_children(): self.ast_tree.delete(i)
        try:
            self.build_ast_tree(ast.parse(self.active_file['content']), "")
        except SyntaxError as e:
            self.ast_tree.insert("", tk.END, text=f"Syntax Error: {e}")

    def build_ast_tree(self, node, parent):
        txt = type(node).__name__
        if hasattr(node, 'lineno'): txt += f" (line {node.lineno})"
        iid = self.ast_tree.insert(parent, tk.END, text=txt)
        for field, val in ast.iter_fields(node):
            if isinstance(val, ast.AST):
                fid = self.ast_tree.insert(iid, tk.END, text=f"{field}:")
                self.build_ast_tree(val, fid)
            elif isinstance(val, list) and val:
                lid = self.ast_tree.insert(iid, tk.END, text=f"{field} (list, {len(val)} items)")
                for elem in val:
                    if isinstance(elem, ast.AST): self.build_ast_tree(elem, lid)
                    else: self.ast_tree.insert(lid, tk.END, text=str(elem))
            elif val is not None:
                self.ast_tree.insert(iid, tk.END, text=f"{field}: {repr(val)}")

    def generate_data_flow(self):
        if not self.active_file: return
        for i in self.dataflow_tree.get_children(): self.dataflow_tree.delete(i)
        lines = self.active_file['content'].split('\n')
        flows = []
        for ln, line in enumerate(lines, 1):
            m = re.search(r'(password|secret|key|token|api_key)\s*=\s*(.+)', line)
            if m:
                vname = m.group(1)
                val   = re.sub(r'(["\'])([^"\']*)\1',
                               lambda x: x.group(1)+'*'*8+x.group(1),
                               m.group(2).strip())
                usages = [{'line': uln, 'context': ul.strip()}
                          for uln, ul in enumerate(lines, 1)
                          if uln != ln and vname in ul]
                flows.append({'variable': vname, 'defined_at': ln,
                               'value': val, 'usages': usages})
        if not flows:
            self.dataflow_tree.insert("", tk.END, text="✅ No sensitive variables detected")
        else:
            for fl in flows:
                vid = self.dataflow_tree.insert("", tk.END, text=f"⚠️  Variable: {fl['variable']}")
                self.dataflow_tree.insert(vid, tk.END, text=f"Defined at line {fl['defined_at']}: {fl['value']}")
                uid = self.dataflow_tree.insert(vid, tk.END, text=f"Usage count: {len(fl['usages'])}")
                for u in fl['usages']:
                    self.dataflow_tree.insert(uid, tk.END, text=f"Line {u['line']}: {u['context']}")
                if len(fl['usages']) > 2:
                    self.dataflow_tree.insert(vid, tk.END,
                        text=f"🚨 WARNING: Variable reused {len(fl['usages'])} times - security risk!")

    def jump_to_line(self, line_number: int):
        """Scroll code viewer to line_number and flash-highlight it."""
        if not self.active_file: return
        # Make sure Code panel is visible
        if not self.show_code.get():
            self.show_code.set(True)
            self.update_layout()
        # The banner adds 7 lines at the top (6 banner lines + 1 blank after banner)
        BANNER_OFFSET = 7
        actual_line = line_number + BANNER_OFFSET
        pos = f"{actual_line}.0"
        end = f"{actual_line}.end"
        # Clear previous jump highlight
        self.code_text.tag_remove("jump_line", "1.0", tk.END)
        self.code_text.tag_remove("vuln_highlight", "1.0", tk.END)
        # Apply highlight
        self.code_text.tag_add("jump_line", pos, end)
        self.code_text.see(pos)
        # Flash: revert to softer highlight after 800ms
        def _soften():
            self.code_text.tag_remove("jump_line", pos, end)
            self.code_text.tag_add("vuln_highlight", pos, end)
        self.root.after(800, _soften)

    def display_vulnerabilities(self):
        for w in self.vuln_container.winfo_children(): w.destroy()

        active_filter = self.filter_severity.get()

        # Apply filter
        visible = [v for v in self.vulnerabilities
                   if active_filter == "all" or v.severity == active_filter]

        # Update count label to show filtered count
        total = len(self.vulnerabilities)
        shown = len(visible)
        if total == 0:
            self.vuln_count_label.configure(text="(0 issues)")
        elif active_filter == "all":
            self.vuln_count_label.configure(text=f"({total} issues)")
        else:
            self.vuln_count_label.configure(
                text=f"({shown} shown / {total} total)")

        if not visible:
            msg = ("✅ No vulnerabilities detected!" if total == 0
                   else f"✅ No {active_filter} severity issues found.")
            tk.Label(self.vuln_container, text=msg,
                     font=("Arial",12), bg="#1a1a1a", fg="#4caf50").pack(pady=20)
            return

        SC = {'critical':'#dc3545','high':'#ff9800','medium':'#ffc107','low':'#4caf50'}
        SO = {'critical':0,'high':1,'medium':2,'low':3}

        for v in sorted(visible, key=lambda x: (SO[x.severity], x.line)):
            card = tk.Frame(self.vuln_container, bg="#2d2d2d", relief=tk.RAISED, bd=1)
            card.pack(fill=tk.X, padx=5, pady=5)

            # coloured left border
            tk.Frame(card, bg=SC[v.severity], width=4).pack(side=tk.LEFT, fill=tk.Y)
            cont = tk.Frame(card, bg="#2d2d2d")
            cont.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

            # header row: type + severity badge
            hdr = tk.Frame(cont, bg="#2d2d2d"); hdr.pack(fill=tk.X)
            tk.Label(hdr, text=v.vuln_type, font=("Arial",11,"bold"),
                     bg="#2d2d2d", fg="white").pack(side=tk.LEFT)
            tk.Label(hdr, text=v.severity.upper(), font=("Arial",8,"bold"),
                     bg=SC[v.severity], fg="white", padx=8, pady=2).pack(side=tk.RIGHT)

            # description
            tk.Label(cont, text=v.description, font=("Arial",9), bg="#2d2d2d",
                     fg="#cccccc", wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(5,5))

            # code block — clickable to jump to line
            cf2 = tk.Frame(cont, bg="#0d1117", relief=tk.SOLID, bd=1)
            cf2.pack(fill=tk.X, pady=5)

            line_lbl = tk.Label(cf2, text=f"  Line {v.line}  ↗ Click to jump",
                                font=("Consolas", 8), bg="#0d1117", fg="#4a90e2",
                                cursor="hand2")
            line_lbl.pack(anchor=tk.W, padx=5, pady=(5,0))

            code_lbl = tk.Label(cf2, text=v.code, font=("Consolas",9),
                                bg="#0d1117", fg="#ff6b6b",
                                wraplength=700, justify=tk.LEFT, cursor="hand2")
            code_lbl.pack(anchor=tk.W, padx=5, pady=(0,5))

            # bind click on both line label and code label to jump
            for widget in (line_lbl, code_lbl, cf2):
                widget.bind("<Button-1>", lambda e, ln=v.line: self.jump_to_line(ln))

            # hover effect on code block
            def _on_enter(e, f=cf2): f.configure(bg="#1a2a3a")
            def _on_leave(e, f=cf2): f.configure(bg="#0d1117")
            cf2.bind("<Enter>", _on_enter); cf2.bind("<Leave>", _on_leave)

            # fix row: label + text + copy button
            ff = tk.Frame(cont, bg="#2d2d2d"); ff.pack(fill=tk.X, pady=(5,0))
            tk.Label(ff, text="🔧 Fix: ", font=("Arial",9,"bold"),
                     bg="#2d2d2d", fg="#4caf50").pack(side=tk.LEFT)
            tk.Label(ff, text=v.remediation, font=("Arial",9), bg="#2d2d2d",
                     fg="#cccccc", wraplength=620, justify=tk.LEFT).pack(side=tk.LEFT)

            def _copy_fix(text=v.remediation):
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.root.update()

            tk.Button(ff, text="📋 Copy", font=("Arial", 7, "bold"),
                      bg="#333333", fg="#4caf50", relief=tk.FLAT,
                      padx=6, pady=2, cursor="hand2",
                      command=_copy_fix).pack(side=tk.RIGHT, padx=(4, 0))

    # ------------------------------------------------------------------ #
    #  Export
    # ------------------------------------------------------------------ #

    def _ask_password_dialog(self, parent=None):
        """Show a password + confirm dialog. Returns the password or None."""
        dlg = tk.Toplevel(parent or self.root)
        dlg.title("Set PDF Password"); dlg.geometry("420x270")
        dlg.configure(bg="#2d2d2d"); dlg.transient(parent or self.root)
        dlg.grab_set(); dlg.resizable(False, False)
        dlg.update_idletasks()
        dlg.geometry(f"420x270+{dlg.winfo_screenwidth()//2-210}+{dlg.winfo_screenheight()//2-135}")

        tk.Label(dlg, text="🔒 Password-Protect PDF Report",
                 font=("Arial",13,"bold"), bg="#2d2d2d", fg="white").pack(pady=(20,5))
        tk.Label(dlg,
                 text="Set a password to encrypt the exported PDF.\n"
                      "You will need this password to open the file.",
                 font=("Arial",9), bg="#2d2d2d", fg="#aaaaaa",
                 justify=tk.CENTER).pack(pady=(0,15))

        pf = tk.Frame(dlg, bg="#2d2d2d"); pf.pack(fill=tk.X, padx=30)
        tk.Label(pf, text="Password:", font=("Arial",9), bg="#2d2d2d",
                 fg="#cccccc", anchor=tk.W).pack(fill=tk.X)
        pw1 = tk.StringVar()
        e1 = tk.Entry(pf, textvariable=pw1, show="●", font=("Arial",11),
                      bg="#1a1a1a", fg="white", insertbackground="white",
                      relief=tk.FLAT, bd=0)
        e1.pack(fill=tk.X, ipady=7, pady=(3,10))
        tk.Label(pf, text="Confirm Password:", font=("Arial",9), bg="#2d2d2d",
                 fg="#cccccc", anchor=tk.W).pack(fill=tk.X)
        pw2 = tk.StringVar()
        e2 = tk.Entry(pf, textvariable=pw2, show="●", font=("Arial",11),
                      bg="#1a1a1a", fg="white", insertbackground="white",
                      relief=tk.FLAT, bd=0)
        e2.pack(fill=tk.X, ipady=7, pady=(3,0))

        result = {'pw': None}
        def ok():
            p1, p2 = pw1.get(), pw2.get()
            if not p1:
                messagebox.showerror("Error", "Password cannot be empty.", parent=dlg); return
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match.", parent=dlg); return
            result['pw'] = p1; dlg.destroy()

        bf = tk.Frame(dlg, bg="#2d2d2d"); bf.pack(pady=15)
        tk.Button(bf, text="Cancel", command=dlg.destroy, bg="#555555", fg="white",
                  font=("Arial",10), relief=tk.FLAT, padx=20, pady=7,
                  cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Button(bf, text="Set Password & Export", command=ok, bg="#9c27b0", fg="white",
                  font=("Arial",10,"bold"), relief=tk.FLAT, padx=20, pady=7,
                  cursor="hand2").pack(side=tk.LEFT, padx=5)
        e1.focus_set(); dlg.wait_window()
        return result['pw']

    def export_report(self):
        if not self.vulnerabilities:
            messagebox.showwarning("Warning", "No vulnerabilities to export."); return

        dlg = tk.Toplevel(self.root)
        dlg.title("Export Report"); dlg.geometry("700x500")
        dlg.configure(bg="#3a3a3a"); dlg.transient(self.root); dlg.grab_set()
        dlg.resizable(True, True)
        dlg.update_idletasks()
        dlg.geometry(f"700x500+{dlg.winfo_screenwidth()//2-350}+{dlg.winfo_screenheight()//2-250}")

        mc = tk.Frame(dlg, bg="#3a3a3a"); mc.pack(fill=tk.BOTH, expand=True)
        tk.Frame(mc, bg="#2d2d2d", height=60).pack(fill=tk.X, pady=(0,10))
        tk.Label(mc.winfo_children()[-1], text="Export PDF Report",
                 font=("Arial",16,"bold"), bg="#2d2d2d", fg="white").pack(pady=15, padx=20)

        paned = tk.PanedWindow(mc, orient=tk.VERTICAL, bg="#3a3a3a", sashwidth=5)
        paned.pack(fill=tk.BOTH, expand=True)

        cframe = tk.Frame(paned, bg="#3a3a3a")
        canv = tk.Canvas(cframe, bg="#3a3a3a", highlightthickness=0)
        vsb  = tk.Scrollbar(cframe, orient=tk.VERTICAL, command=canv.yview)
        sc   = tk.Frame(canv, bg="#3a3a3a")
        sc.bind("<Configure>", lambda e: canv.configure(scrollregion=canv.bbox("all")))
        canv.create_window((0,0), window=sc, anchor="nw")
        canv.configure(yscrollcommand=vsb.set)
        canv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=5)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        tk.Label(sc, text="Select Sections to Include", font=("Arial",11,"bold"),
                 bg="#3a3a3a", fg="white", anchor=tk.W).pack(fill=tk.X, pady=(0,10))

        export_opts = {k: tk.BooleanVar(value=v) for k, v in [
            ('executive_summary', True), ('detailed_vulnerabilities', True),
            ('fix_recommendations', True), ('ast_diagrams', False),
            ('dataflow_analysis', False),
        ]}
        for key, label in [
            ('executive_summary',        'Executive Summary'),
            ('detailed_vulnerabilities', 'Detailed Vulnerability List'),
            ('fix_recommendations',      'Fix Recommendations'),
            ('ast_diagrams',             'AST Diagrams'),
            ('dataflow_analysis',        'Data Flow Analysis'),
        ]:
            f = tk.Frame(sc, bg="#2d2d2d"); f.pack(fill=tk.X, pady=3)
            tk.Checkbutton(f, text=label, variable=export_opts[key],
                           bg="#2d2d2d", fg="white", selectcolor="#1a1a1a",
                           font=("Arial",10), activebackground="#2d2d2d",
                           activeforeground="white", pady=8, padx=10).pack(anchor=tk.W)

        tk.Label(sc, text="Filter by Severity", font=("Arial",11,"bold"),
                 bg="#3a3a3a", fg="white", anchor=tk.W).pack(fill=tk.X, pady=(15,10))
        sev_filters = {k: tk.BooleanVar(value=True)
                       for k in ['critical','high','medium','low']}
        sf = tk.Frame(sc, bg="#3a3a3a"); sf.pack(fill=tk.X, pady=(0,15))
        for key, lbl, col in [('critical','Critical','#dc3545'),('high','High','#ff9800'),
                                ('medium','Medium','#ffc107'),('low','Low','#4caf50')]:
            tk.Checkbutton(sf, text=lbl, variable=sev_filters[key],
                           bg=col, fg="white", selectcolor=col,
                           font=("Arial",9,"bold"), activebackground=col,
                           activeforeground="white", padx=15, pady=5,
                           indicatoron=False, relief=tk.FLAT,
                           borderwidth=2).pack(side=tk.LEFT, padx=3, expand=True, fill=tk.X)

        tk.Label(sc, text="Output Configuration", font=("Arial",11,"bold"),
                 bg="#3a3a3a", fg="white", anchor=tk.W).pack(fill=tk.X, pady=(0,10))
        tk.Label(sc, text="Report File Name", font=("Arial",9),
                 bg="#3a3a3a", fg="#cccccc", anchor=tk.W).pack(fill=tk.X, pady=(0,5))
        fname_var = tk.StringVar(value="Security_Analysis_Report_1")
        tk.Entry(sc, textvariable=fname_var, font=("Arial",10), bg="#2d2d2d",
                 fg="white", insertbackground="white", relief=tk.FLAT,
                 bd=0).pack(fill=tk.X, ipady=8, pady=(0,10))

        tk.Label(sc, text="Save Location", font=("Arial",9),
                 bg="#3a3a3a", fg="#cccccc", anchor=tk.W).pack(fill=tk.X, pady=(0,5))
        lf = tk.Frame(sc, bg="#2d2d2d"); lf.pack(fill=tk.X, pady=(0,15))
        default_dir = os.path.join(os.path.expanduser("~"), "Documents", "CryptoLint", "Reports")
        loc_var = tk.StringVar(value=default_dir)
        tk.Entry(lf, textvariable=loc_var, font=("Arial",10), bg="#2d2d2d",
                 fg="white", insertbackground="white", relief=tk.FLAT,
                 bd=0).pack(side=tk.LEFT, fill=tk.BOTH, expand=True, ipady=8, padx=(5,5))
        def browse():
            d = filedialog.askdirectory(title="Select Save Location")
            if d: loc_var.set(d)
        tk.Button(lf, text="Browse", command=browse, bg="#4a90e2", fg="white",
                  font=("Arial",9), relief=tk.FLAT, padx=15, pady=8,
                  cursor="hand2").pack(side=tk.RIGHT, padx=5)

        bframe = tk.Frame(paned, bg="#3a3a3a", height=80)
        paned.add(cframe, minsize=300); paned.add(bframe, minsize=80)

        def preview():
            lines = self.generate_report_lines(export_opts, sev_filters)
            pw = tk.Toplevel(dlg); pw.title("Report Preview")
            pw.geometry("900x700"); pw.configure(bg="#1a1a1a")
            tw = scrolledtext.ScrolledText(pw, wrap=tk.WORD, bg="#0d1117", fg="#c9d1d9",
                                           font=("Consolas",10), insertbackground="white")
            tw.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            tw.insert(1.0, "\n".join(lines))
            tw.configure(state='disabled')

        def generate():
            password = self._ask_password_dialog(dlg)
            if password is None: return
            try:
                save_dir = loc_var.get()
                os.makedirs(save_dir, exist_ok=True)
                filepath = os.path.join(save_dir, fname_var.get() + ".pdf")
                filtered_vulns = [v for v in self.vulnerabilities
                                  if sev_filters[v.severity].get()]
                meta = {
                    'filename':    self.active_file['name'] if self.active_file else 'Unknown',
                    'filepath':    self.active_file['path']  if self.active_file else '',
                    'owasp_on':    self.owasp_enabled.get(),
                    'nist_on':     self.nist_enabled.get(),
                    'custom_sets': [rs['name'] for rs in self.rule_sets if rs['enabled'].get()],
                }
                generate_pdf_report(filtered_vulns, meta, filepath, password)
                dlg.destroy()
                messagebox.showinfo("Success",
                    f"Encrypted PDF exported to:\n{filepath}\n\n"
                    "🔒 The PDF is password-protected.\n"
                    "Open it with any PDF reader and enter your password.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export PDF: {e}")

        bc = tk.Frame(bframe, bg="#3a3a3a"); bc.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)
        tk.Button(bc, text="Preview", command=preview, bg="#6c757d", fg="white",
                  font=("Arial",11), relief=tk.FLAT, padx=30, pady=10,
                  cursor="hand2").pack(side=tk.LEFT, padx=(0,10))
        tk.Button(bc, text="🔒 Generate & Download (Password-Protected PDF)",
                  command=generate, bg="#9c27b0", fg="white", font=("Arial",11,"bold"),
                  relief=tk.FLAT, padx=30, pady=10,
                  cursor="hand2").pack(side=tk.RIGHT)

    def generate_report_lines(self, options, severity_filters) -> list:
        """Return report as a list of text lines (used for PDF & preview)."""
        lines = []
        year  = datetime.now().year

        # Copyright header
        lines += [
            "="*80,
            f"© {year} CryptoLint. All rights reserved.",
            "This report is the proprietary output of CryptoLint.",
            "Unauthorized reproduction or redistribution is strictly prohibited.",
            "For licensing inquiries, contact: legal@cryptolint.io",
            "="*80, "",
        ]

        filtered = [v for v in self.vulnerabilities if severity_filters[v.severity].get()]

        if options['executive_summary'].get():
            lines += [
                "="*80,
                "CRYPTOLINT - CRYPTOGRAPHIC VULNERABILITY ANALYSIS REPORT",
                "="*80, "",
                f"File Analyzed: {self.active_file['name']}",
                f"File Path:     {self.active_file['path']}",
                f"Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Tool Version:  CryptoLint v1.0", "",
                "-"*80, "EXECUTIVE SUMMARY", "-"*80,
            ]
            cnt = {'critical':0,'high':0,'medium':0,'low':0}
            for v in filtered: cnt[v.severity] += 1
            lines += [
                "Severity Breakdown:",
                f"  🔴 CRITICAL: {cnt['critical']} issue(s)",
                f"  🟠 HIGH:     {cnt['high']} issue(s)",
                f"  🟡 MEDIUM:   {cnt['medium']} issue(s)",
                f"  🟢 LOW:      {cnt['low']} issue(s)",
                f"  📊 TOTAL:    {len(filtered)} issue(s)", "",
            ]
            score = cnt['critical']*10 + cnt['high']*5 + cnt['medium']*2 + cnt['low']
            risk  = "🔴 HIGH RISK" if score >= 15 else ("🟠 MEDIUM RISK" if score >= 8 else "🟢 LOW RISK")
            lines += [f"Risk Assessment: {risk} (Score: {score})", ""]

        if options['detailed_vulnerabilities'].get() and filtered:
            lines += ["-"*80, "DETAILED VULNERABILITIES", "-"*80, ""]
            SO = {'critical':0,'high':1,'medium':2,'low':3}
            icons = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🟢'}
            for i, v in enumerate(sorted(filtered, key=lambda x:(SO[x.severity],x.line)), 1):
                lines.append(f"{icons[v.severity]} {i}. {v.vuln_type} [{v.severity.upper()}]")
                lines.append(f"   📍 Line {v.line}:")
                lines.append(f"       Code: {v.code}")
                lines.append(f"   📝 {v.description}")
                if options['fix_recommendations'].get():
                    lines.append(f"   🔧 Fix: {v.remediation}")
                lines.append("")

        if options['ast_diagrams'].get():
            lines += ["-"*80, "AST ANALYSIS", "-"*80, ""]
            try:
                tree = ast.parse(self.active_file['content'])
                lines += [
                    f"  Total Nodes: {sum(1 for _ in ast.walk(tree))}",
                    f"  Functions:   {len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)])}",
                    f"  Classes:     {len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])}",
                    f"  Imports:     {len([n for n in ast.walk(tree) if isinstance(n,(ast.Import,ast.ImportFrom))])}",
                    "",
                ]
            except SyntaxError as e:
                lines.append(f"Syntax Error: {e}")
            lines.append("")

        if options['dataflow_analysis'].get():
            lines += ["-"*80, "DATA FLOW ANALYSIS", "-"*80, ""]
            src_lines = self.active_file['content'].split('\n')
            flows = []
            for ln, line in enumerate(src_lines, 1):
                for kw in ['password','secret','key','token','api_key']:
                    m = re.search(rf'\b{kw}\b\s*=\s*(.+)', line, re.IGNORECASE)
                    if m:
                        vname = m.group(0).split('=')[0].strip()
                        raw   = m.group(1).strip()
                        mval  = re.sub(r'(["\'])([^"\']*)\1',
                                       lambda x: x.group(1)+'*'*8+x.group(1), raw)
                        usages = [{'line':uln,'context':ul.strip()}
                                  for uln,ul in enumerate(src_lines,1)
                                  if uln!=ln and re.search(rf'\b{vname}\b', ul)]
                        flows.append({'variable':vname,'defined_at':ln,
                                      'value':mval,'usages':usages})
                        break
            if not flows:
                lines.append("✅ No sensitive variables detected")
            else:
                for fl in flows:
                    lines += [
                        f"📌 {fl['variable']} (line {fl['defined_at']}): {fl['value']}",
                        f"   Used {len(fl['usages'])} time(s)",
                    ]
                    for u in fl['usages'][:5]:
                        lines.append(f"     Line {u['line']}: {u['context']}")
                    lines.append("")
            lines.append("")

        lines += [
            "="*80, "REPORT FOOTER", "="*80, "",
            "Generated by CryptoLint - Cryptographic Vulnerability Scanner",
            "1. Use strong, up-to-date cryptographic algorithms",
            "2. Never hardcode secrets in source code",
            "3. Use environment variables or secure vaults",
            "4. Regularly update dependencies",
            "5. Conduct regular security audits", "",
            f"Total issues addressed: {len(filtered)}",
        ]
        return lines

    # ------------------------------------------------------------------ #
    #  Config persistence
    # ------------------------------------------------------------------ #

    def load_config(self):
        try:
            if not os.path.exists(self.config_file): return
            with open(self.config_file, 'r', encoding='utf-8') as f:
                cfg = json.load(f)

            # Restore default rule toggle states
            rs = cfg.get('rule_states', {})
            self.owasp_enabled.set(rs.get('owasp_enabled', True))
            self.nist_enabled.set(rs.get('nist_enabled', True))

            # Restore rule sets
            self._next_set_id  = cfg.get('next_set_id', 0)
            self._next_rule_id = cfg.get('next_rule_id', 0)
            for saved_set in cfg.get('rule_sets', []):
                rules_loaded = []
                for r in saved_set.get('rules', []):
                    try:
                        re.compile(r.get('pattern', ''))
                        rules_loaded.append({
                            'id':          r.get('id', 0),
                            'pattern':     r.get('pattern', ''),
                            'severity':    r.get('severity', 'medium'),
                            'type':        r.get('type', 'Custom Rule'),
                            'description': r.get('description', ''),
                            'remediation': r.get('remediation', ''),
                            'nist_ref':    r.get('nist_ref', ''),
                            'cwe':         r.get('cwe', ''),
                            'enabled':     tk.BooleanVar(value=r.get('enabled', True)),
                        })
                    except re.error:
                        pass
                if rules_loaded:
                    self.rule_sets.append({
                        'id':          saved_set.get('id', self._next_set_id),
                        'name':        saved_set.get('name', 'Imported Rules'),
                        'source_file': saved_set.get('source_file', ''),
                        'enabled':     tk.BooleanVar(value=saved_set.get('enabled', True)),
                        'rules':       rules_loaded,
                    })
            self._rebuild_custom_rules()
            self.update_rules_display()

            # Restore open files
            for fd in cfg.get('files', []):
                if os.path.exists(fd['path']):
                    try:
                        with open(fd['path'], 'r', encoding='utf-8') as f:
                            content = f.read()
                        fi = {'name': fd['name'], 'path': fd['path'], 'content': content}
                        self.files.append(fi)
                        self.files_listbox.insert(tk.END, fi['name'])
                    except Exception as e:
                        print(f"Could not reload {fd['name']}: {e}")
            idx = cfg.get('active_file_index')
            if self.files and idx is not None and idx < len(self.files):
                self.active_file = self.files[idx]
                self.files_listbox.selection_set(idx)
                self._show_editor()
                self.update_layout()
                self.root.after(100, self.display_code)
                self.root.after(200, lambda: self.analyze_current_file(False))
            else:
                self._show_welcome()
        except Exception as e:
            print(f"Could not load config: {e}")

    def save_config(self):
        try:
            sets_serialized = []
            for rs in self.rule_sets:
                rules_ser = []
                for r in rs['rules']:
                    rules_ser.append({
                        'id':          r['id'],
                        'pattern':     r['pattern'],
                        'severity':    r['severity'],
                        'type':        r['type'],
                        'description': r['description'],
                        'remediation': r['remediation'],
                        'nist_ref':    r.get('nist_ref', ''),
                        'cwe':         r.get('cwe', ''),
                        'enabled':     r['enabled'].get(),
                    })
                sets_serialized.append({
                    'id':          rs['id'],
                    'name':        rs['name'],
                    'source_file': rs['source_file'],
                    'enabled':     rs['enabled'].get(),
                    'rules':       rules_ser,
                })
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'files': [{'name': fd['name'], 'path': fd['path']} for fd in self.files],
                    'active_file_index': (self.files.index(self.active_file)
                                          if self.active_file in self.files else 0),
                    'rule_states': {
                        'owasp_enabled': self.owasp_enabled.get(),
                        'nist_enabled':  self.nist_enabled.get(),
                    },
                    'rule_sets':    sets_serialized,
                    'next_set_id':  self._next_set_id,
                    'next_rule_id': self._next_rule_id,
                }, f, indent=2)
        except Exception as e:
            print(f"Could not save config: {e}")

    def on_closing(self):
        self.save_config(); self.root.destroy()


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #

def main():
    root = tk.Tk()
    CryptoLintGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

