"""PDF report built with ReportLab. Charts use ReportLab's own drawing tools,
so no extra browser/image dependency is needed (works on any Windows laptop)."""
from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core import analysis as A
from detectors import rules

BLUE = colors.HexColor("#256abf")
styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=BLUE, fontSize=18)
H2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=BLUE, fontSize=13, spaceBefore=10)
BODY = ParagraphStyle("b", parent=styles["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("s", parent=BODY, fontSize=8, textColor=colors.HexColor("#555555"))


def _table(header: list[str], rows: list[list], widths=None) -> Table:
    t = Table([header] + rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5fa")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _bar(labels: list[str], values: list[int], title: str) -> list:
    d = Drawing(170 * mm, max(40, 14 * len(values) + 30))
    c = HorizontalBarChart()
    c.x, c.y, c.width, c.height = 110, 10, 330, d.height - 25
    c.data = [list(reversed(values))]
    c.categoryAxis.categoryNames = [l[:34] for l in reversed(labels)]
    c.categoryAxis.labels.fontSize = 7
    c.valueAxis.labels.fontSize = 7
    c.valueAxis.valueMin = 0
    c.bars[0].fillColor = BLUE
    d.add(c)
    return [Paragraph(title, H2), d]


def _line(tbl, width: int) -> list:
    d = Drawing(170 * mm, 150)
    p = LinePlot()
    p.x, p.y, p.width, p.height = 45, 25, 390, 105
    p.data = [list(zip(tbl["seconds"], tbl["packets"]))]
    p.lines[0].strokeColor = BLUE
    p.lines[0].strokeWidth = 1.5
    p.xValueAxis.labels.fontSize = 7
    p.yValueAxis.labels.fontSize = 7
    d.add(p)
    return [Paragraph(f"Packets over time ({width}-second buckets; x = seconds since capture start)", H2), d]


def build_pdf(cap, alerts: list, project: str = "Network Traffic Analysis Using Wireshark") -> bytes:
    """Return the report as PDF bytes. `cap` is a core.parser.Capture."""
    df, dns = cap.packets, cap.dns
    ov = A.overview(df)
    layers = A.layer_tables(df)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="NetScope report", author="NetScope")
    s: list = [Paragraph("NetScope — Network Traffic Analysis Report", H1),
               Paragraph(f"Project: {project}", BODY),
               Paragraph("This report is generated from the uploaded capture file only. "
                         "It does not describe the network in general.", SMALL), Spacer(1, 6)]

    fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    s += [Paragraph("1. Capture details", H2), _table(["Item", "Value"], [
        ["File", cap.file_name], ["File size", A.format_bytes(cap.file_size)],
        ["Total packets analysed", f"{ov['packets']:,}"],
        ["Total data (frame bytes)", A.format_bytes(ov["bytes"])],
        ["Capture duration", f"{ov['duration']:.1f} s"],
        ["First / last packet", f"{fmt(ov['start'])} / {fmt(ov['end'])}"],
        ["Unique source IPs / destination IPs", f"{ov['unique_src']} / {ov['unique_dst']}"],
        ["Report generated", fmt(datetime.now(timezone.utc).timestamp())],
    ], [60 * mm, 110 * mm])]
    for n in cap.notes:
        s.append(Paragraph(f"Note: {n}", SMALL))

    s.append(Paragraph("2. Protocol statistics", H2))
    s.append(Paragraph("Each layer is a separate view of the same packets (a TLS packet is also TCP and "
                       "IPv4/IPv6), so percentages are per layer and must not be added across layers.", SMALL))
    for name, t in layers.items():
        s.append(Paragraph(name, BODY))
        s.append(_table(["Protocol", "Packets", "% of all packets"],
                        [[r.protocol, f"{r.packets:,}", f"{r.percent:.2f}"] for r in t.itertuples()],
                        [70 * mm, 40 * mm, 50 * mm]))
        s.append(Spacer(1, 4))
    s.append(Paragraph("Application labels TLS, HTTP and QUIC are identified from packet bytes or well-known "
                       "ports (QUIC = UDP port 443) and are heuristics. Payloads of encrypted traffic are not read.", SMALL))

    tt = A.top_talkers(df, "src", 8)
    s += _bar(list(tt["src"]), [int(x) for x in tt["packets"]], "3. Top source IP addresses (packets)")
    conv = A.conversations(df).head(8)
    s.append(Paragraph("Most active endpoint pairs (by bytes)", BODY))
    s.append(_table(["Endpoint A", "Endpoint B", "Packets", "Bytes"],
                    [[r.a, r.b, f"{r.packets:,}", f"{r.bytes:,}"] for r in conv.itertuples()],
                    [58 * mm, 58 * mm, 22 * mm, 26 * mm]))
    tbl, width = A.traffic_over_time(df)
    s += _line(tbl, width)

    s.append(Paragraph("4. DNS observations (standard DNS, port 53)", H2))
    ds = A.dns_summary(dns)
    if not ds["available"]:
        s.append(Paragraph("No standard DNS packets were found in this capture.", BODY))
    else:
        rtt = f"{ds['rtt_median_ms']:.1f} ms median, {ds['rtt_max_ms']:.1f} ms max" if ds["rtt_median_ms"] is not None else "unavailable"
        s.append(_table(["Item", "Value"], [
            ["Queries / responses", f"{ds['queries']} / {ds['responses']}"],
            ["Responses with an error code", str(ds["failed"])],
            ["Queries without a response in the capture", str(ds["unanswered"])],
            ["DNS servers seen", ", ".join(ds["servers"])],
            ["Query→response time (matched pairs)", rtt]], [70 * mm, 100 * mm]))
        s.append(Spacer(1, 4))
        s.append(_table(["Domain", "Type", "Queries"],
                        [[r.qname, r.qtype, r.queries] for r in A.dns_domains(dns, 12).itertuples()],
                        [100 * mm, 30 * mm, 30 * mm]))

    s.append(Paragraph("5. Security indicators (rule-based, potential only)", H2))
    if alerts:
        for a in alerts:
            ev = "; ".join(f"{k}: {v}" for k, v in a.evidence.items())
            s.append(Paragraph(f"<b>[{a.severity}] {a.title}</b> — {a.explanation}<br/>Evidence: {ev}", BODY))
            s.append(Spacer(1, 3))
    else:
        s.append(Paragraph("No indicators were triggered by the rules below.", BODY))
    s.append(_table(["Rule", "Fires when"], [list(r) for r in rules.rules_table().itertuples(index=False)],
                    [60 * mm, 110 * mm]))
    s.append(Paragraph("These are potential indicators, not confirmed attacks. NetScope is not an intrusion detection system.", SMALL))

    s.append(Paragraph("6. Limitations and interpretation", H2))
    for line in [
        "Results describe only this capture; they do not represent all network behaviour.",
        "HTTPS/TLS and QUIC payloads are encrypted and are not read; only visible metadata is analysed.",
        "Packet loss, latency, throughput and retransmission rates are not established by this tool.",
        "Alerts are simple threshold rules and may be normal behaviour (e.g. retries, caching).",
        "Only traffic you are authorised to capture and inspect should be analysed.",
    ]:
        s.append(Paragraph("• " + line, BODY))
    doc.build(s)
    return buf.getvalue()
