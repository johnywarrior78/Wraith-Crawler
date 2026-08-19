from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from ..domain import redact_text
from ..mitre import technique_label
from .data import ReportData, load_report_data

INK = colors.HexColor("#172033")
NAVY = colors.HexColor("#102A43")
TEAL = colors.HexColor("#168C8C")
LIGHT = colors.HexColor("#EEF4F7")
MUTED = colors.HexColor("#5D6B78")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#8B1E3F"),
    "high": colors.HexColor("#C44536"),
    "medium": colors.HexColor("#D98E04"),
    "low": colors.HexColor("#2D6A9F"),
    "informational": colors.HexColor("#607D8B"),
}

class PDFReportGenerator:
    def generate(self, session: Session, assessment_id: str, output_path: Path) -> Path:
        data = load_report_data(session, assessment_id)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        document = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=f"Wraith Crawler Assessment - {data.application_name}",
            author="Wraith Crawler",
        )
        styles = self._styles()
        story = self._build_story(data, styles)
        document.build(story, onFirstPage=self._page, onLaterPages=self._page)
        return output_path

    def _build_story(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        story: list[object] = [Spacer(1, 30 * mm)]
        story.extend(
            [
                Paragraph("WRAITH CRAWLER", styles["eyebrow"]),
                Paragraph("External Security Assessment", styles["cover_title"]),
                Spacer(1, 8 * mm),
                Paragraph(self._escape(data.application_name), styles["cover_target"]),
                Paragraph(self._escape(data.target), styles["cover_url"]),
                Spacer(1, 18 * mm),
                self._metadata_table(data, styles),
                Spacer(1, 30 * mm),
                Paragraph(
                    "Evidence-first, bounded and non-destructive. Modeled attack progression is explicitly separated from confirmed observations.",
                    styles["callout"],
                ),
                PageBreak(),
            ]
        )
        counts = Counter(f.priority_level for f in data.findings if not f.false_positive)
        story.extend(
            [
                Paragraph("Executive Summary", styles["h1"]),
                Paragraph(
                    f"Wraith Crawler assessed {self._escape(data.target)} using the {data.profile} profile. "
                    f"The completed canonical dataset contains {len(data.findings)} finding(s), "
                    f"{len(data.attack_paths)} modeled attack path(s), and {len(data.manual_reviews)} manual-review item(s).",
                    styles["body"],
                ),
                Spacer(1, 5 * mm),
                self._summary_cards(counts, styles),
                Spacer(1, 8 * mm),
                Paragraph("Priority and validation", styles["h2"]),
                Paragraph(
                    "Priority scores combine scanner severity with validation strength, exploit context, external exposure, "
                    "known exploitation signals, sensitive context, blast radius, and attack-path participation. "
                    "Suspected and manual-review findings are never presented as confirmed.",
                    styles["body"],
                ),
            ]
        )
        story.extend(self._scope_methodology_recon(data, styles))
        story.extend(self._technology(data, styles))
        story.extend(self._owasp(data, styles))
        story.extend(self._findings(data, styles))
        story.extend(self._attack_paths(data, styles))
        story.extend(self._plugins(data, styles))
        story.extend(self._methodology(data, styles))
        return story

    def _scope_methodology_recon(
        self, data: ReportData, styles: dict[str, ParagraphStyle]
    ) -> list[object]:
        story: list[object] = [PageBreak(), Paragraph("Scope", styles["h1"])]
        story.append(
            Paragraph(
                f"The unauthenticated external assessment began from {self._escape(data.target)}. "
                "Only operator-supplied scope and same-origin discoveries were tested; credentials were not guessed and destructive actions were not performed.",
                styles["body"],
            )
        )
        story.append(Paragraph("Pentest Methodology", styles["h1"]))
        story.append(
            Paragraph(
                "Reconnaissance → Scanning → Enumeration → Safe Validation → Analysis → Attack Path → Post-Exploitation Reasoning. Confirmed observations remain separate from inferred capabilities and speculative impact.",
                styles["body"],
            )
        )
        phase_rows: list[list[object]] = [["Phase", "Status", "Tests", "Findings", "Limitations"]]
        for phase in data.pentest_phases:
            phase_rows.append(
                [
                    phase.phase.replace("_", " ").title(),
                    phase.status,
                    f"{phase.tests_completed}/{phase.tests_attempted}",
                    phase.findings_count,
                    Paragraph(self._escape("; ".join(phase.limitations) or "-"), styles["small"]),
                ]
            )
        if len(phase_rows) == 1:
            phase_rows.append(["Legacy assessment", "not recorded", "-", 0, "-"])
        phase_table = Table(
            phase_rows, colWidths=[38 * mm, 25 * mm, 22 * mm, 20 * mm, 67 * mm], repeatRows=1
        )
        phase_table.setStyle(self._table_style())
        story.extend([phase_table, Spacer(1, 5 * mm), Paragraph("Reconnaissance Summary", styles["h1"])])
        if data.assets:
            for asset in data.assets:
                story.append(
                    Paragraph(
                        self._escape(
                            f"{asset.url} — HTTP {asset.http_status or 'unknown'}; "
                            f"IPs {', '.join(asset.resolved_ips) or 'not resolved'}; "
                            f"server {asset.server or 'not advertised'}; CDN/WAF {asset.cdn_waf or 'not identified'}; "
                            f"redirects {' -> '.join(asset.redirect_chain) or 'none'}"
                        ),
                        styles["body"],
                    )
                )
        else:
            story.append(Paragraph("No reconnaissance assets were persisted.", styles["body"]))
        story.extend(
            [
                Paragraph("Attack Surface", styles["h1"]),
                Paragraph(
                    f"The canonical inventory contains {len(data.endpoints)} endpoint(s), "
                    f"{len(data.parameters)} parameter(s), and {len(data.technologies)} technology record(s).",
                    styles["body"],
                ),
            ]
        )
        return story

    def _attack_paths(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        story: list[object] = [
            PageBreak(),
            Paragraph("Critical Attack Paths / Attack Path Analysis", styles["h1"]),
        ]
        if not data.attack_paths:
            story.append(Paragraph("No deterministic chain rule produced an attack path for this assessment.", styles["body"]))
        for index, path in enumerate(data.attack_paths, 1):
            story.extend(
                [
                    Paragraph(f"{index}. {self._escape(path.title)}", styles["h2"]),
                    self._label_value("Score / priority", f"{path.score:.1f} / {path.priority}", styles),
                    self._label_value("Classification", f"{path.classification} ({path.confidence})", styles),
                    self._label_value(
                        "MITRE ATT&CK",
                        "; ".join(technique_label(item) for item in path.mitre_attack)
                        or "No evidence-bounded technique mapping",
                        styles,
                    ),
                    self._label_value("Attack Scenario", path.attack_scenario, styles),
                    self._label_value("Attacker Gain", path.attacker_gain, styles),
                    self._label_value("Next Attacker Step", path.next_step, styles),
                    self._label_value("Potential Technical Impact", path.technical_impact, styles),
                    self._label_value("Potential Business Impact", path.business_impact, styles),
                    self._label_value("Blast Radius", path.blast_radius, styles),
                    self._label_value("Evidence Boundary", path.evidence_boundary, styles),
                    self._label_value("Recommended Break Point", path.recommended_break_point, styles),
                    Spacer(1, 5 * mm),
                ]
            )
        story.append(Paragraph("Post-Exploitation Reasoning", styles["h1"]))
        if data.post_exploitation_steps:
            for step in data.post_exploitation_steps:
                story.extend(
                    [
                        self._label_value(
                            f"Step {step.sequence} ({step.classification})", step.action, styles
                        ),
                        self._label_value("Capability", step.capability, styles),
                        self._label_value(
                            "MITRE ATT&CK",
                            "; ".join(technique_label(item) for item in step.mitre_attack)
                            or "No technique mapping",
                            styles,
                        ),
                        self._label_value("Evidence boundary", step.rationale, styles),
                    ]
                )
        else:
            story.append(
                Paragraph(
                    "No deterministic attack path existed from which to derive bounded next-attacker-action reasoning.",
                    styles["body"],
                )
            )
        story.append(Paragraph("Recommended Attack-Path Break Points", styles["h1"]))
        if data.attack_paths:
            for path in data.attack_paths:
                story.append(
                    self._label_value(path.title, path.recommended_break_point, styles)
                )
        else:
            story.append(Paragraph("No chain-specific break point was generated.", styles["body"]))
        return story

    def _owasp(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        story: list[object] = [PageBreak(), Paragraph("OWASP Top 10 Coverage", styles["h1"])]
        rows: list[list[object]] = [["Category", "Status / tests", "Findings", "Limitations / manual review"]]
        for entry in data.owasp_coverage:
            rows.append(
                [
                    Paragraph(f"{entry['category']}<br/><b>{self._escape(str(entry['name']))}</b>", styles["small"]),
                    Paragraph(
                        self._escape(
                            f"{entry.get('status', 'reference')} — "
                            f"{entry.get('tests_completed', 0)}/{entry.get('tests_attempted', 0)}"
                        ),
                        styles["small"],
                    ),
                    str(entry.get("findings", 0)),
                    Paragraph(
                        self._escape(
                            "; ".join(entry.get("limitations", [entry.get("limitation", "")]))
                            + (
                                " Manual: " + " | ".join(entry.get("manual_review_needs", []))
                                if entry.get("manual_review_needs")
                                else ""
                            )
                        ),
                        styles["small"],
                    ),
                ]
            )
        table = Table(rows, colWidths=[45 * mm, 35 * mm, 18 * mm, 74 * mm], repeatRows=1)
        table.setStyle(self._table_style())
        story.append(table)
        return story

    def _findings(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        story: list[object] = [PageBreak(), Paragraph("Detailed Findings", styles["h1"])]
        if not data.findings:
            story.append(Paragraph("No canonical findings were recorded.", styles["body"]))
            return story
        for index, finding in enumerate(data.findings, 1):
            severity_color = SEVERITY_COLORS.get(finding.priority_level, MUTED)
            header = Table(
                [[Paragraph(f"{index}. {self._escape(finding.title)}", styles["finding_title"]), finding.priority_level.upper()]],
                colWidths=[140 * mm, 32 * mm],
            )
            header.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                        ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                        ("BACKGROUND", (1, 0), (1, 0), severity_color),
                        ("ALIGN", (1, 0), (1, 0), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#C8D4DC")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 7),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                        ("TOPPADDING", (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ]
                )
            )
            details: list[object] = [
                header,
                Spacer(1, 3 * mm),
                Paragraph(self._escape(finding.description), styles["body"]),
                self._label_value("Validation", f"{finding.validation_status} / confidence {finding.confidence}", styles),
                self._label_value("Affected endpoints", ", ".join(finding.affected_endpoints) or finding.asset, styles),
                self._label_value("Priority rationale", self._format_mapping(finding.priority_rationale), styles),
                self._label_value(
                    "Mappings",
                    ", ".join([*finding.owasp, *finding.cwe, *finding.cve, *finding.capec]) or "None",
                    styles,
                ),
                self._label_value(
                    "MITRE ATT&CK",
                    self._mitre_finding_mappings(finding),
                    styles,
                ),
                self._label_value("Remediation", finding.remediation, styles),
            ]
            narrative = finding.attacker_narrative or {}
            details.extend(
                [
                    self._label_value(
                        "How an attacker could exploit it",
                        narrative.get("exploitation", "Not recorded"),
                        styles,
                    ),
                    self._label_value(
                        "Capability gained", narrative.get("capability_gained", "Not recorded"), styles
                    ),
                    self._label_value(
                        "Next realistic attacker step",
                        narrative.get("next_realistic_step", "Not recorded"),
                        styles,
                    ),
                    self._label_value(
                        "Chain opportunities",
                        ", ".join(narrative.get("chain_opportunities", [])) or "None recorded",
                        styles,
                    ),
                    self._label_value(
                        "Confirmed", "; ".join(narrative.get("confirmed", [])) or "None", styles
                    ),
                    self._label_value(
                        "Inferred", "; ".join(narrative.get("inferred", [])) or "None", styles
                    ),
                    self._label_value(
                        "Technical impact", narrative.get("technical_impact", "Not recorded"), styles
                    ),
                    self._label_value(
                        "Business impact", narrative.get("business_impact", "Not recorded"), styles
                    ),
                ]
            )
            evidence = [record for record in data.evidence if record.finding_id == finding.id]
            if evidence:
                details.append(Paragraph("<b>Evidence:</b>", styles["body"]))
                for record in evidence[:10]:
                    suffix = " [sensitive payload redacted]" if record.sensitive else ""
                    details.append(
                        Paragraph(
                            f"- {self._escape(record.summary)}{suffix}",
                            styles["small"],
                        )
                    )
            details.append(Spacer(1, 6 * mm))
            story.append(KeepTogether(details))
        return story

    def _technology(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        story: list[object] = [PageBreak(), Paragraph("Technology Inventory", styles["h1"])]
        rows: list[list[object]] = [["Product", "Version", "Category", "Confidence", "Lifecycle / references"]]
        for technology in data.technologies:
            refs = ", ".join(technology.vulnerability_references)
            rows.append(
                [
                    technology.product,
                    technology.version or "Unknown",
                    technology.category,
                    technology.confidence,
                    "; ".join(filter(None, [technology.eol_state, refs])) or "-",
                ]
            )
        if len(rows) == 1:
            rows.append(["No technologies recorded", "-", "-", "-", "-"])
        table = Table(rows, colWidths=[40 * mm, 25 * mm, 35 * mm, 25 * mm, 47 * mm], repeatRows=1)
        table.setStyle(self._table_style())
        story.append(table)
        story.append(Paragraph("EOL / Outdated Components", styles["h1"]))
        lifecycle = [item for item in data.technologies if item.eol_state or item.vulnerability_references]
        if lifecycle:
            for item in lifecycle:
                story.append(
                    Paragraph(
                        self._escape(
                            f"{item.product} {item.version or 'unknown'} — {item.eol_state or 'potentially vulnerable'}; "
                            f"{'; '.join(item.lifecycle_evidence) or ', '.join(item.vulnerability_references)}"
                        ),
                        styles["body"],
                    )
                )
        else:
            story.append(
                Paragraph(
                    "No observed exact version matched the configured lifecycle or vulnerability knowledge. Unknown versions were not guessed.",
                    styles["body"],
                )
            )
        return story

    def _plugins(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        story: list[object] = [PageBreak(), Paragraph("Plugin Execution / Coverage Limitations", styles["h1"])]
        rows: list[list[object]] = [["Plugin / phase", "State", "Tests", "Findings / limitation"]]
        for plugin in data.plugin_executions:
            rows.append(
                [
                    f"{plugin.plugin_name} / {plugin.phase}",
                    plugin.state,
                    f"{plugin.tests_completed}/{plugin.tests_attempted}",
                    Paragraph(
                        self._escape(
                            f"{plugin.findings_count}; {plugin.failure_reason or plugin.skip_reason or plugin.message or '-'}"
                        ),
                        styles["small"],
                    ),
                ]
            )
        if len(rows) == 1:
            rows.append(["No plugin executions recorded", "-", "-", 0])
        table = Table(rows, colWidths=[50 * mm, 27 * mm, 25 * mm, 70 * mm], repeatRows=1)
        table.setStyle(self._table_style())
        story.append(table)
        return story

    def _methodology(self, data: ReportData, styles: dict[str, ParagraphStyle]) -> list[object]:
        return [
            PageBreak(),
            Paragraph("Methodology and Limitations", styles["h1"]),
            Paragraph(
                "The assessment began from operator-supplied URLs and remained within explicit host and path scope. "
                "Checks were rate-limited, non-destructive, and designed for an unauthenticated external perspective. "
                "Scanner observations were normalized and aggregated before prioritization. Missing optional tools were "
                "recorded as structured plugin-health states rather than treated as evidence that a target was secure.",
                styles["body"],
            ),
            Paragraph(
                "Attack-path outcomes after the validated weakness are models, not post-exploitation results. Authorization, "
                "business logic, internal logging, data-at-rest controls, and authenticated role boundaries may require separate "
                "manual assessment. A finding marked suspected or manual review must not be treated as confirmed until an analyst "
                "completes safe validation. MITRE ATT&CK mappings describe observed preconditions or plausible adversary "
                "behaviors; they do not claim that Wraith executed those behaviors.",
                styles["body"],
            ),
        ]

    @staticmethod
    def _metadata_table(data: ReportData, styles: dict[str, ParagraphStyle]) -> Table:
        rows = [
            ["Assessment ID", data.assessment_id],
            ["Status / profile", f"{data.status} / {data.profile}"],
            ["Started", data.started_at.isoformat() if data.started_at else "Not recorded"],
            ["Completed", data.completed_at.isoformat() if data.completed_at else "Not recorded"],
        ]
        table = Table(rows, colWidths=[42 * mm, 105 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("TEXTCOLOR", (1, 0), (1, -1), INK),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#D7E0E5")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    @staticmethod
    def _summary_cards(counts: Counter[str], styles: dict[str, ParagraphStyle]) -> Table:
        labels = ["Critical", "High", "Medium", "Low", "Informational"]
        values = [[Paragraph(label, styles["card_label"]) for label in labels], [counts[label.lower()] for label in labels]]
        table = Table(values, colWidths=[34 * mm] * 5, rowHeights=[9 * mm, 13 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 1), (-1, 1), 16),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#C8D4DC")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D7E0E5")),
                ]
            )
        )
        return table

    @staticmethod
    def _label_value(label: str, value: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
        return Paragraph(f"<b>{PDFReportGenerator._escape(label)}:</b> {PDFReportGenerator._escape(value)}", styles["body"])

    @staticmethod
    def _format_mapping(value: object) -> str:
        if not isinstance(value, dict):
            return str(value)
        return "; ".join(f"{key}={item}" for key, item in value.items())

    @staticmethod
    def _mitre_finding_mappings(finding: Any) -> str:
        metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
        details = metadata.get("mitre_attack_mappings", [])
        rendered: list[str] = []
        if isinstance(details, list):
            for item in details:
                if not isinstance(item, dict) or not item.get("technique_id"):
                    continue
                rendered.append(
                    f"{technique_label(str(item['technique_id']))} "
                    f"[{item.get('relationship', 'related')}; "
                    f"{item.get('classification', 'inferred')}]"
                )
        if not rendered:
            rendered = [technique_label(item) for item in finding.mitre_attack]
        return "; ".join(rendered) or "No evidence-bounded technique mapping"

    @staticmethod
    def _escape(value: object) -> str:
        text = redact_text(str(value))
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _table_style() -> TableStyle:
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#D7E0E5")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )

    @staticmethod
    def _page(canvas: object, document: object) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D7E0E5"))
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 8 * mm, "Wraith Crawler - Evidence-first external assessment")
        canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    @staticmethod
    def _styles() -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "eyebrow": ParagraphStyle("eyebrow", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=TEAL, spaceAfter=5),
            "cover_title": ParagraphStyle("cover_title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=28, leading=32, textColor=NAVY, alignment=TA_LEFT, spaceAfter=10),
            "cover_target": ParagraphStyle("cover_target", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=INK),
            "cover_url": ParagraphStyle("cover_url", parent=base["Normal"], fontName="Helvetica", fontSize=10, leading=14, textColor=MUTED),
            "callout": ParagraphStyle("callout", parent=base["Normal"], fontName="Helvetica", fontSize=10, leading=15, textColor=INK, backColor=LIGHT, borderColor=TEAL, borderWidth=0, borderPadding=10),
            "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=NAVY, spaceBefore=5, spaceAfter=9),
            "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=TEAL, spaceBefore=9, spaceAfter=5),
            "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=INK, spaceAfter=5),
            "small": ParagraphStyle("small", parent=base["BodyText"], fontName="Helvetica", fontSize=7.5, leading=10, textColor=INK),
            "finding_title": ParagraphStyle("finding_title", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=NAVY),
            "card_label": ParagraphStyle("card_label", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=7, leading=9, alignment=TA_CENTER, textColor=MUTED),
        }
