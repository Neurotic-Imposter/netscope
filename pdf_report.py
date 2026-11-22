"""PDF report built with ReportLab.

Charts are drawn using ReportLab's own drawing tools, so no browser or image
library is needed — works on any Windows laptop or Streamlit Cloud.
"""

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

import analysis as A
import rules

# ── Styles ────────────────────────────────────────────────────────────────────
BLUE = colors.HexColor("#256abf")
_base = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_base["Heading1"], textColor=BLUE, fontSize=18)
H2 = ParagraphStyle("h2", parent=_base["Heading2"], textColor=BLUE, fontSize=13, spaceBefore=10)
BODY = ParagraphStyle("b", parent=_base["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("s", parent=BODY, fontSize=8, textColor=colors.HexColor("#555555"))


# ── Helper builders ───────────────────────────────────────────────────────────

def _table(header, rows, widths=None):
    """Create a styled ReportLab table."""
    t = Table([header] + rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5fa")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _bar(labels, values, title):
    """Return a list of ReportLab flowables for a horizontal bar chart."""
    d = Drawing(170 * mm, max(40, 14 * len(values) + 30))
    c = HorizontalBarChart()
    c.x, c.y = 110, 10
    c.width, c.height = 330, d.height - 25
    c.data = [list(reversed(values))]
    c.categoryAxis.categoryNames = [label[:34] for label in reversed(labels)]
    c.categoryAxis.labels.fontSize = 7
    c.valueAxis.labels.fontSize = 7
    c.valueAxis.valueMin = 0
    c.bars[0].fillColor = BLUE
    d.add(c)
    return [Paragraph(title, H2), d]


def _line(tbl, width):
    """Return a list of ReportLab flowables for a time-series line chart."""
    d = Drawing(170 * mm, 150)
    p = LinePlot()
    p.x, p.y = 45, 25
    p.width, p.height = 390, 105
    p.data = [list(zip(tbl["seconds"], tbl["packets"]))]
    p.lines[0].strokeColor = BLUE
    p.lines[0].strokeWidth = 1.5
    p.xValueAxis.labels.fontSize = 7
    p.yValueAxis.labels.fontSize = 7
    d.add(p)
    return [
        Paragraph(
            f"Packets over time ({width}-second buckets; x = seconds since capture start)",
            H2,
        ),
        d,
    ]


# ── Main export function ──────────────────────────────────────────────────────

def build_pdf(cap, alerts, project="Network Traffic Analysis Using Wireshark"):
    """Build the full PDF report and return it as bytes.

    cap    -- a Capture object (from parser.py)
    alerts -- list of Alert objects (from rules.py)
    """
    df = cap.packets
    dns = cap.dns
    overview = A.overview(df)
    layers = A.layer_tables(df)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="NetScope report",
        author="NetScope",
    )

    def fmt_time(timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Build content list ────────────────────────────────────────────────────
    content = [
        Paragraph("NetScope — Network Traffic Analysis Report", H1),
        Paragraph(f"Project: {project}", BODY),
        Paragraph(
            "This report is generated from the uploaded capture file only. "
            "It does not describe the network in general.",
            SMALL,
        ),
        Spacer(1, 6),
    ]

    # Section 1: Capture details
    content += [
        Paragraph("1. Capture details", H2),
        _table(["Item", "Value"], [
            ["File", cap.file_name],
            ["File size", A.format_bytes(cap.file_size)],
            ["Total packets analysed", f"{overview['packets']:,}"],
            ["Total data (frame bytes)", A.format_bytes(overview["bytes"])],
            ["Capture duration", f"{overview['duration']:.1f} s"],
            ["First / last packet",
             f"{fmt_time(overview['start'])} / {fmt_time(overview['end'])}"],
            ["Unique source IPs / destination IPs",
             f"{overview['unique_src']} / {overview['unique_dst']}"],
            ["Report generated", fmt_time(datetime.now(timezone.utc).timestamp())],
        ], [60 * mm, 110 * mm]),
    ]
    for note in cap.notes:
        content.append(Paragraph(f"Note: {note}", SMALL))

    # Section 2: Protocol statistics
    content.append(Paragraph("2. Protocol statistics", H2))
    content.append(Paragraph(
        "Each layer is a separate view of the same packets (a TLS packet is also TCP and "
        "IPv4/IPv6), so percentages are per layer and must not be added across layers.",
        SMALL,
    ))
    for name, table in layers.items():
        content.append(Paragraph(name, BODY))
        content.append(_table(
            ["Protocol", "Packets", "% of all packets"],
            [[r.protocol, f"{r.packets:,}", f"{r.percent:.2f}"] for r in table.itertuples()],
            [70 * mm, 40 * mm, 50 * mm],
        ))
        content.append(Spacer(1, 4))
    content.append(Paragraph(
        "Application labels TLS, HTTP and QUIC are identified from packet bytes or well-known "
        "ports (QUIC = UDP port 443) and are heuristics. Payloads of encrypted traffic are not read.",
        SMALL,
    ))

    # Section 3: Top talkers and conversations
    top_talkers = A.top_talkers(df, "src", 8)
    content += _bar(
        list(top_talkers["src"]),
        [int(x) for x in top_talkers["packets"]],
        "3. Top source IP addresses (packets)",
    )
    conversations = A.conversations(df).head(8)
    content.append(Paragraph("Most active endpoint pairs (by bytes)", BODY))
    content.append(_table(
        ["Endpoint A", "Endpoint B", "Packets", "Bytes"],
        [[r.a, r.b, f"{r.packets:,}", f"{r.bytes:,}"] for r in conversations.itertuples()],
        [58 * mm, 58 * mm, 22 * mm, 26 * mm],
    ))
    tbl, width = A.traffic_over_time(df)
    content += _line(tbl, width)

    # Section 4: DNS
    content.append(Paragraph("4. DNS observations (standard DNS, port 53)", H2))
    ds = A.dns_summary(dns)
    if not ds["available"]:
        content.append(Paragraph("No standard DNS packets were found in this capture.", BODY))
    else:
        if ds["rtt_median_ms"] is not None:
            rtt_text = f"{ds['rtt_median_ms']:.1f} ms median, {ds['rtt_max_ms']:.1f} ms max"
        else:
            rtt_text = "unavailable"
        content.append(_table(["Item", "Value"], [
            ["Queries / responses", f"{ds['queries']} / {ds['responses']}"],
            ["Responses with an error code", str(ds["failed"])],
            ["Queries without a response in the capture", str(ds["unanswered"])],
            ["DNS servers seen", ", ".join(ds["servers"])],
            ["Query→response time (matched pairs)", rtt_text],
        ], [70 * mm, 100 * mm]))
        content.append(Spacer(1, 4))
        content.append(_table(
            ["Domain", "Type", "Queries"],
            [[r.qname, r.qtype, r.queries] for r in A.dns_domains(dns, 12).itertuples()],
            [100 * mm, 30 * mm, 30 * mm],
        ))

    # Section 5: Security indicators
    content.append(Paragraph("5. Security indicators (rule-based, potential only)", H2))
    if alerts:
        for alert in alerts:
            evidence_text = "; ".join(f"{k}: {v}" for k, v in alert.evidence.items())
            content.append(Paragraph(
                f"<b>[{alert.severity}] {alert.title}</b> — {alert.explanation}"
                f"<br/>Evidence: {evidence_text}",
                BODY,
            ))
            content.append(Spacer(1, 3))
    else:
        content.append(Paragraph("No indicators were triggered by the rules below.", BODY))
    content.append(_table(
        ["Rule", "Fires when"],
        [list(r) for r in rules.rules_table().itertuples(index=False)],
        [60 * mm, 110 * mm],
    ))
    content.append(Paragraph(
        "These are potential indicators, not confirmed attacks. "
        "NetScope is not an intrusion detection system.",
        SMALL,
    ))

    # Section 6: Limitations
    content.append(Paragraph("6. Limitations and interpretation", H2))
    for line in [
        "Results describe only this capture; they do not represent all network behaviour.",
        "HTTPS/TLS and QUIC payloads are encrypted and are not read; only visible metadata is analysed.",
        "Packet loss, latency, throughput and retransmission rates are not established by this tool.",
        "Alerts are simple threshold rules and may be normal behaviour (e.g. retries, caching).",
        "Only traffic you are authorised to capture and inspect should be analysed.",
    ]:
        content.append(Paragraph("• " + line, BODY))

    doc.build(content)
    return buf.getvalue()
