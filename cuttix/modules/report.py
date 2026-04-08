"""Report generator — CSV, JSON, PDF export.

Pulls data from the Database (hosts, ports, alerts) and exports
in the requested format. PDF uses reportlab if available.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ports considered dangerous when open
DANGEROUS_PORTS = {
    21: ("FTP", "Cleartext authentication, use SFTP instead"),
    23: ("Telnet", "Cleartext protocol, use SSH instead"),
    25: ("SMTP", "May allow open relay if misconfigured"),
    80: ("HTTP", "Unencrypted web traffic, use HTTPS"),
    110: ("POP3", "Cleartext email retrieval, use POP3S"),
    135: ("MSRPC", "Windows RPC, common attack vector"),
    139: ("NetBIOS", "Legacy SMB, often exploited"),
    143: ("IMAP", "Cleartext email, use IMAPS"),
    445: ("SMB", "Frequent target for ransomware and worms"),
    1433: ("MSSQL", "Database exposed to network"),
    1521: ("Oracle", "Database exposed to network"),
    3306: ("MySQL", "Database exposed to network"),
    3389: ("RDP", "Remote desktop, brute-force target"),
    5432: ("PostgreSQL", "Database exposed to network"),
    5900: ("VNC", "Remote desktop, often unencrypted"),
    6379: ("Redis", "In-memory DB, usually no auth by default"),
    8080: ("HTTP-alt", "Alternative HTTP, check if intentional"),
    27017: ("MongoDB", "NoSQL DB, historically no auth"),
}


class AuditReportGenerator:
    """Generate network audit reports in multiple formats.

    Pulls inventory, port scan results, and IDS alerts from the
    Database, then formats and writes the output.
    """

    def __init__(self, db: Any) -> None:
        self._db = db
        self._generated_at = ""

    # -- Protocol: ReportGenerator --

    def generate(self, fmt: str = "json", output_path: str | None = None) -> str:
        if fmt not in self.get_supported_formats():
            raise ValueError(f"Unsupported format: {fmt}")

        self._generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = self._collect_data()

        if fmt == "json":
            content = self._render_json(data)
        elif fmt == "csv":
            content = self._render_csv(data)
        elif fmt == "pdf":
            content = self._render_pdf(data, output_path)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        if output_path and fmt != "pdf":
            Path(output_path).write_text(content, encoding="utf-8")
            logger.info("Report written to %s", output_path)

        return content

    def get_supported_formats(self) -> list[str]:
        fmts = ["json", "csv"]
        try:
            import reportlab  # noqa: F401

            fmts.append("pdf")
        except ImportError:
            pass
        return fmts

    # -- data collection --

    def _collect_data(self) -> dict[str, Any]:
        hosts = self._db.get_all_hosts()
        alerts = self._db.get_alerts(limit=500)

        # gather ports per host
        for h in hosts:
            mac = h.get("mac", "")
            h["ports"] = self._db.get_ports_for_host(mac)

        vulns = self._find_vulnerabilities(hosts)

        return {
            "generated_at": self._generated_at,
            "summary": {
                "total_hosts": len(hosts),
                "total_alerts": len(alerts),
                "total_vulnerabilities": len(vulns),
                "critical_alerts": sum(1 for a in alerts if a.get("severity") == "critical"),
            },
            "hosts": hosts,
            "alerts": alerts,
            "vulnerabilities": vulns,
            "recommendations": self._build_recommendations(vulns),
        }

    def _find_vulnerabilities(self, hosts: list[dict]) -> list[dict[str, Any]]:
        vulns = []
        for h in hosts:
            ip = h.get("ip", "?")
            mac = h.get("mac", "?")
            for port_info in h.get("ports", []):
                port = port_info.get("port")
                state = port_info.get("state", "")
                if state != "open" or port is None:
                    continue
                if port in DANGEROUS_PORTS:
                    svc_name, reason = DANGEROUS_PORTS[port]
                    vulns.append(
                        {
                            "host_ip": ip,
                            "host_mac": mac,
                            "port": port,
                            "service": svc_name,
                            "risk": reason,
                            "severity": _port_severity(port),
                        }
                    )
        return vulns

    def _build_recommendations(self, vulns: list[dict]) -> list[str]:
        recs = []
        seen = set()

        for v in vulns:
            ip = v["host_ip"]
            port = v["port"]
            svc = v["service"]
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)

            if port in (21, 23, 110, 143, 25):
                recs.append(f"Disable {svc} on {ip}:{port} or switch to encrypted alternative")
            elif port in (3306, 5432, 1433, 1521, 27017, 6379):
                recs.append(
                    f"Restrict network access to {svc} on {ip}:{port} "
                    "(firewall or bind to localhost)"
                )
            elif port in (3389, 5900):
                recs.append(f"Restrict {svc} on {ip}:{port} to VPN access only")
            elif port == 445:
                recs.append(f"Ensure SMB on {ip} is patched and restrict access")
            elif port == 80:
                recs.append(f"Redirect HTTP to HTTPS on {ip}")
            else:
                recs.append(f"Review {svc} on {ip}:{port} — {v['risk']}")

        return recs

    # -- JSON output --

    def _render_json(self, data: dict) -> str:
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)

    # -- CSV output --

    def _render_csv(self, data: dict) -> str:
        buf = io.StringIO()

        # hosts section
        w = csv.writer(buf)
        w.writerow(["# Network Inventory"])
        w.writerow(
            [
                "IP",
                "MAC",
                "Vendor",
                "Hostname",
                "OS",
                "First Seen",
                "Last Seen",
                "Gateway",
                "Open Ports",
            ]
        )

        for h in data["hosts"]:
            open_ports = [str(p["port"]) for p in h.get("ports", []) if p.get("state") == "open"]
            w.writerow(
                [
                    h.get("ip", ""),
                    h.get("mac", ""),
                    h.get("vendor", ""),
                    h.get("hostname", ""),
                    h.get("os_guess", ""),
                    h.get("first_seen", ""),
                    h.get("last_seen", ""),
                    "Yes" if h.get("is_gateway") else "No",
                    ",".join(open_ports),
                ]
            )

        # blank line
        w.writerow([])
        w.writerow(["# Vulnerabilities"])
        w.writerow(["Host IP", "Port", "Service", "Severity", "Risk"])
        for v in data["vulnerabilities"]:
            w.writerow([v["host_ip"], v["port"], v["service"], v["severity"], v["risk"]])

        w.writerow([])
        w.writerow(["# Alerts"])
        w.writerow(["Type", "Severity", "Source IP", "Description", "Time"])
        for a in data["alerts"]:
            w.writerow(
                [
                    a.get("alert_type", ""),
                    a.get("severity", ""),
                    a.get("source_ip", ""),
                    a.get("description", ""),
                    a.get("created_at", ""),
                ]
            )

        return buf.getvalue()

    # -- PDF output --

    def _render_pdf(self, data: dict, output_path: str | None) -> str:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise RuntimeError("reportlab not installed — run: pip install reportlab") from exc

        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"cuttix_report_{ts}.pdf"

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )
        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        h2 = styles["Heading2"]
        body = styles["BodyText"]

        # custom styles
        small = ParagraphStyle("Small", parent=body, fontSize=8)

        story = []

        # -- title page --
        story.append(Paragraph("Cuttix — Network Audit Report", title_style))
        story.append(Spacer(1, 10 * mm))
        story.append(Paragraph(f"Generated: {data['generated_at']}", body))
        story.append(
            Paragraph(
                "This report was generated for authorized audit purposes only.",
                small,
            )
        )
        story.append(Spacer(1, 10 * mm))

        # summary
        s = data["summary"]
        story.append(Paragraph("Executive Summary", h2))
        summary_data = [
            ["Metric", "Value"],
            ["Total Hosts", str(s["total_hosts"])],
            ["Total Alerts", str(s["total_alerts"])],
            ["Critical Alerts", str(s["critical_alerts"])],
            ["Vulnerabilities", str(s["total_vulnerabilities"])],
        ]
        t = Table(summary_data, colWidths=[80 * mm, 60 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#ecf0f1")],
                    ),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 8 * mm))

        # -- host inventory --
        story.append(Paragraph("Network Inventory", h2))
        if data["hosts"]:
            host_rows = [["IP", "MAC", "Vendor", "Hostname", "Open Ports"]]
            for h in data["hosts"]:
                open_p = [str(p["port"]) for p in h.get("ports", []) if p.get("state") == "open"]
                host_rows.append(
                    [
                        h.get("ip", ""),
                        h.get("mac", "")[:17],
                        (h.get("vendor", "") or "")[:20],
                        (h.get("hostname", "") or "")[:20],
                        ", ".join(open_p[:8]),
                    ]
                )
            ht = Table(host_rows, repeatRows=1)
            ht.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#ecf0f1")],
                        ),
                    ]
                )
            )
            story.append(ht)
        else:
            story.append(Paragraph("No hosts discovered.", body))

        story.append(Spacer(1, 8 * mm))

        # -- vulnerabilities --
        if data["vulnerabilities"]:
            story.append(Paragraph("Vulnerability Assessment", h2))
            vuln_rows = [["Host", "Port", "Service", "Severity", "Risk"]]
            for v in data["vulnerabilities"]:
                vuln_rows.append(
                    [
                        v["host_ip"],
                        str(v["port"]),
                        v["service"],
                        v["severity"],
                        v["risk"][:50],
                    ]
                )
            vt = Table(vuln_rows, repeatRows=1)
            _sev_colors = {
                "critical": colors.HexColor("#e74c3c"),
                "high": colors.HexColor("#e67e22"),
                "medium": colors.HexColor("#f1c40f"),
                "low": colors.HexColor("#27ae60"),
            }
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
            # color severity column
            for i, v in enumerate(data["vulnerabilities"], start=1):
                sev = v.get("severity", "medium")
                bg = _sev_colors.get(sev, colors.white)
                style_cmds.append(("BACKGROUND", (3, i), (3, i), bg))
            vt.setStyle(TableStyle(style_cmds))
            story.append(vt)
            story.append(Spacer(1, 6 * mm))

        # -- recommendations --
        if data["recommendations"]:
            story.append(Paragraph("Recommendations", h2))
            for i, rec in enumerate(data["recommendations"], 1):
                story.append(Paragraph(f"{i}. {rec}", body))
            story.append(Spacer(1, 6 * mm))

        # -- alerts --
        if data["alerts"]:
            story.append(Paragraph("IDS Alerts", h2))
            alert_rows = [["Type", "Severity", "Source", "Description", "Time"]]
            for a in data["alerts"][:50]:  # cap at 50 for readability
                alert_rows.append(
                    [
                        a.get("alert_type", ""),
                        a.get("severity", ""),
                        a.get("source_ip", "") or "",
                        (a.get("description", "") or "")[:60],
                        (a.get("created_at", "") or "")[:19],
                    ]
                )
            at = Table(alert_rows, repeatRows=1)
            at.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#8e44ad")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ]
                )
            )
            story.append(at)

        # footer
        story.append(Spacer(1, 10 * mm))
        story.append(
            Paragraph(
                "Report generated by Cuttix — LAN administration and audit toolkit. "
                "For authorized use only.",
                small,
            )
        )

        doc.build(story)
        logger.info("PDF report written to %s", output_path)
        return output_path


def _port_severity(port: int) -> str:
    """Map dangerous port to severity level."""
    critical = {445, 3389, 23, 6379, 27017}
    high = {21, 135, 139, 5900, 1433, 1521, 3306, 5432}
    if port in critical:
        return "critical"
    if port in high:
        return "high"
    return "medium"
