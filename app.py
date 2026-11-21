
"""NetScope — Network Traffic Analyzer (Streamlit dashboard).

Run: streamlit run app.py
Data flow: capture file -> core.parser -> core.analysis / detectors
           -> this file shows tables and components.charts draws them.
"""

from __future__ import annotations

import os
import tempfile

import pandas as pd
import streamlit as st

from components import charts
from core import analysis as A
from core.parser import CaptureError, parse_capture
from detectors import rules
from reports.pdf_report import build_pdf


st.set_page_config(
    page_title="NetScope — Network Traffic Analyzer",
    page_icon="📡",
    layout="wide"
)

st.markdown("""
<style>
[data-testid="stMetric"] {
    background: #1a1a19;
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 10px;
    padding: 14px 16px;
}
[data-testid="stMetricLabel"] {
    color: #c3c2b7;
}
h1, h2, h3 {
    letter-spacing: -.01em;
}
.note {
    color: #c3c2b7;
    font-size: .85rem;
}
</style>
""", unsafe_allow_html=True)


# ---------------- capture loading ----------------

@st.cache_data(show_spinner=False, max_entries=2)
def load(file_id: str, _data: bytes, name: str, max_packets: int):
    """Parse an uploaded capture using a temporary file."""
    fd, path = tempfile.mkstemp(
        suffix=os.path.splitext(name)[1] or ".pcapng"
    )

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(_data)

        cap = parse_capture(path, max_packets or None)

    finally:
        if os.path.exists(path):
            os.remove(path)

    cap.file_name = name
    cap.file_size = len(_data)

    return cap


# ---------------- sidebar ----------------

st.sidebar.title("📡 NetScope")
st.sidebar.caption("Network Traffic Analyzer")

page = st.sidebar.radio(
    "Navigate",
    [
        "Overview",
        "Protocol Analysis",
        "Traffic Analysis",
        "DNS Analysis",
        "Packet Explorer",
        "Security Insights",
        "Communication Map",
        "Reports"
    ]
)

st.sidebar.divider()

upload = st.sidebar.file_uploader(
    "Upload a capture (.pcap / .pcapng)",
    type=["pcap", "pcapng"],
    help="Analysed in memory for this session only; never saved."
)

max_packets = st.sidebar.number_input(
    "Max packets to analyse (0 = all)",
    0,
    5_000_000,
    200_000,
    50_000,
    help="Large files are slow. Parsing stops at this limit."
)

st.sidebar.caption(
    "Only analyse traffic you are authorised to capture."
)


# ---------------- empty state ----------------

st.title("NetScope — Network Traffic Analyzer")

if upload is None:
    st.info(
        "**No capture loaded.** Use **Upload a capture** in the sidebar "
        "to choose a `.pcap` or `.pcapng` file and unlock all dashboard "
        "pages. Capture traffic with Wireshark (File → Save As) on a "
        "network you are authorised to monitor."
    )
    st.stop()


# ---------------- process uploaded capture ----------------

try:
    with st.spinner("Reading capture… large files can take a minute."):
        cap = load(
            upload.file_id,
            upload.getvalue(),
            upload.name,
            int(max_packets)
        )

except CaptureError as exc:
    st.error(f"Could not analyse this file. {exc}")
    st.stop()

except Exception as exc:
    st.error(f"Unexpected problem while reading the capture: {exc}")
    st.stop()


df, dns = cap.packets, cap.dns

ov = A.overview(df)
alerts = rules.run_all(df, dns)

st.caption(
    f"Capture: **{cap.file_name}** · "
    f"{ov['packets']:,} packets · "
    "all figures are calculated from this file"
)

for n in cap.notes:
    st.warning(n)


# ---------------- common table function ----------------

def table(frame: pd.DataFrame, **kw):
    st.dataframe(
        frame,
        hide_index=True,
        use_container_width=True,
        **kw
    )


# ---------------- pages ----------------

if page == "Overview":

    c = st.columns(5)

    c[0].metric("Total packets", f"{ov['packets']:,}")
    c[1].metric(
        "Data transferred",
        A.format_bytes(ov["bytes"]),
        help="Sum of frame lengths"
    )
    c[2].metric("Duration", f"{ov['duration']:.1f} s")
    c[3].metric("Unique source IPs", ov["unique_src"])
    c[4].metric("Unique destination IPs", ov["unique_dst"])

    left, right = st.columns(2)

    layers = A.layer_tables(df)

    left.plotly_chart(
        charts.protocol_donut(
            layers["Transport layer"],
            "Transport layer (share of packets)"
        ),
        use_container_width=True
    )

    right.plotly_chart(
        charts.bar_h(
            A.top_ports(df, "dport", 8),
            "port",
            "packets",
            "Most used destination ports"
        ),
        use_container_width=True
    )

    st.caption(
        "ARP packets have no transport layer, so they appear as "
        "'No transport layer'. See Protocol Analysis for network "
        "and application layers."
    )


elif page == "Protocol Analysis":

    st.subheader("Protocols by layer")

    st.info(
        "A single packet belongs to several layers at once "
        "(e.g. IPv6 → TCP → TLS). Each layer below is a separate "
        "view of the same packets; do not add the tables together."
    )

    layers = A.layer_tables(df)

    cols = st.columns(3)

    for col, (name, t) in zip(cols, layers.items()):
        col.plotly_chart(
            charts.protocol_donut(t, name),
            use_container_width=True
        )

        with col:
            table(t)

    st.subheader("Compare with Wireshark display filters")

    wf = pd.DataFrame([
        ("tcp", int((df["transport"] == "TCP").sum())),
        ("udp", int((df["transport"] == "UDP").sum())),
        ("dns (port 53 only)", int((df["app"] == "DNS").sum())),
        ("icmp (ICMPv4 only)", int((df["transport"] == "ICMP").sum())),
        ("arp", int((df["network"] == "ARP").sum())),
        ("icmpv6", int((df["transport"] == "ICMPv6").sum())),
        ("tls (by TLS record header)", int((df["app"] == "TLS").sum())),
        ("http", int((df["app"] == "HTTP").sum())),
    ], columns=["Wireshark filter", "NetScope count"])

    table(wf)

    st.caption(
        "Counts for protocols with 0 packets mean none were found "
        "in this capture (e.g. no cleartext HTTP). mDNS and LLMNR "
        "are counted separately from `dns`. TLS, HTTP and QUIC are "
        "identified from packet bytes/ports and are heuristics."
    )


elif page == "Traffic Analysis":

    a, b = st.columns(2)

    a.plotly_chart(
        charts.bar_h(
            A.top_talkers(df, "src"),
            "src",
            "packets",
            "Top source IPs (packets)"
        ),
        use_container_width=True
    )

    b.plotly_chart(
        charts.bar_h(
            A.top_talkers(df, "dst"),
            "dst",
            "packets",
            "Top destination IPs (packets)",
            charts.SERIES[1]
        ),
        use_container_width=True
    )

    st.subheader("Most active endpoint pairs")

    table(
        A.conversations(df)
        .head(15)
        .rename(columns={"a": "Endpoint A", "b": "Endpoint B"})
    )

    st.subheader("Traffic volume over time")

    metric = st.radio(
        "Show",
        ["packets", "bytes"],
        horizontal=True
    )

    tbl, width = A.traffic_over_time(df)

    st.plotly_chart(
        charts.time_series(tbl, metric, width),
        use_container_width=True
    )

    p1, p2 = st.columns(2)

    p1.plotly_chart(
        charts.bar_h(
            A.top_ports(df, "sport", 10),
            "port",
            "packets",
            "Common source ports",
            charts.SERIES[2]
        ),
        use_container_width=True
    )

    p2.plotly_chart(
        charts.bar_h(
            A.top_ports(df, "dport", 10),
            "port",
            "packets",
            "Common destination ports",
            charts.SERIES[3]
        ),
        use_container_width=True
    )

    st.subheader("Packet length distribution")

    st.plotly_chart(
        charts.histogram(A.length_histogram(df)),
        use_container_width=True
    )


elif page == "DNS Analysis":

    ds = A.dns_summary(dns)

    if not ds["available"]:

        st.info(
            "No standard DNS (port 53) packets were found in this capture."
        )

    else:

        c = st.columns(5)

        c[0].metric("Queries", ds["queries"])
        c[1].metric("Responses", ds["responses"])
        c[2].metric(
            "Error responses",
            ds["failed"],
            help="Response code other than NOERROR"
        )
        c[3].metric("No response seen", ds["unanswered"])

        c[4].metric(
            "Median reply time",
            f"{ds['rtt_median_ms']:.1f} ms"
            if ds["rtt_median_ms"] is not None
            else "unavailable"
        )

        st.write(
            "**DNS servers seen:** " + ", ".join(ds["servers"])
        )

        a, b = st.columns(2)

        a.plotly_chart(
            charts.bar_h(
                A.dns_domains(dns, 12).assign(
                    label=lambda d:
                    d["qname"] + " (" + d["qtype"] + ")"
                ),
                "label",
                "queries",
                "Most queried names"
            ),
            use_container_width=True
        )

        b.plotly_chart(
            charts.protocol_donut(
                A.dns_types(dns).rename(
                    columns={
                        "type": "protocol",
                        "queries": "packets"
                    }
                ),
                "Query types"
            ),
            use_container_width=True
        )

        failed = dns[
            dns["is_response"] & (dns["rcode"] != "NOERROR")
        ]

        if len(failed):

            st.subheader("Unsuccessful responses")

            table(
                failed[
                    ["no", "qname", "qtype", "rcode", "src"]
                ].rename(columns={"src": "server"})
            )

            st.caption(
                "NXDOMAIN means the name does not exist. Reverse "
                "lookups (PTR) for local addresses often fail "
                "normally and are not necessarily a fault."
            )

        st.subheader("Responses and answers")

        table(A.dns_answers(dns, 200))


elif page == "Packet Explorer":

    f1, f2, f3, f4 = st.columns([2, 2, 1, 2])

    protos = f1.multiselect(
        "Protocol",
        sorted(df["protocol"].unique())
    )

    ipq = f2.text_input("IP address contains")
    port = f3.text_input("Port")
    text = f4.text_input("Search info text")

    v = df

    if protos:
        v = v[v["protocol"].isin(protos)]

    if ipq:
        v = v[
            v["src"].str.contains(ipq, regex=False)
            | v["dst"].str.contains(ipq, regex=False)
        ]

    if port.strip().isdigit():
        p = int(port)
        v = v[
            (v["sport"] == p)
            | (v["dport"] == p)
        ]

    elif port.strip():
        st.warning("Port must be a number.")

    if text:
        v = v[
            v["info"].str.contains(
                text,
                case=False,
                regex=False
            )
        ]

    show = v.assign(
        timestamp=pd.to_datetime(
            v["time"],
            unit="s",
            utc=True
        ).dt.strftime("%H:%M:%S.%f").str[:-3]
    )

    show = show[
        [
            "no", "timestamp", "src", "dst",
            "protocol", "sport", "dport", "length", "info"
        ]
    ]

    st.write(
        f"**{len(v):,}** of {len(df):,} packets match"
        + (" (showing first 5,000)" if len(v) > 5000 else "")
    )

    st.dataframe(
        show.head(5000),
        hide_index=True,
        use_container_width=True,
        height=520,
        column_config={
            "info": st.column_config.TextColumn(
                "info",
                width="large"
            )
        }
    )

    export = v.assign(
        timestamp_utc=pd.to_datetime(
            v["time"],
            unit="s",
            utc=True
        ).astype(str)
    )

    export = export[
        [
            "no", "timestamp_utc", "rel_time", "src", "dst",
            "network", "transport", "app", "protocol",
            "sport", "dport", "length", "tcp_flags", "info"
        ]
    ]

    st.download_button(
        "⬇ Download filtered packets as CSV",
        export.to_csv(index=False).encode("utf-8"),
        "netscope_packets.csv",
        "text/csv"
    )


elif page == "Security Insights":

    st.warning(
        "These are **potential indicators** from simple rules. "
        "They are not confirmed attacks, and NetScope is not "
        "an intrusion detection system."
    )

    if not alerts:
        st.success(
            "No indicators were triggered by the rules below for this capture."
        )

    for a in alerts:

        icon = {
            "Medium": "🟠",
            "Low": "🟡",
            "Info": "🔵"
        }[a.severity]

        with st.expander(
            f"{icon} [{a.severity}] {a.title}",
            expanded=True
        ):
            st.write(a.explanation)
            st.json(a.evidence)
            st.caption(a.caveat)

    st.subheader("Rules checked and thresholds")

    table(rules.rules_table())

    st.caption(
        "Assumed capturing computer (excluded from the "
        "'high traffic' rule): "
        f"{', '.join(rules.likely_capture_hosts(df)) or 'not identified'}."
    )


elif page == "Communication Map":

    st.write(
        "Each dot is an IP address; each line is a conversation. "
        "Bigger dots and thicker lines carry more bytes."
    )

    n = st.slider(
        "Number of endpoints",
        5,
        40,
        20
    )

    fig = charts.comm_map(A.conversations(df), n)

    if fig is None:

        st.info("No IP conversations to draw.")

    else:

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        st.caption(
            "Shows the busiest endpoints only, to stay readable. "
            "Hover a dot or line for details."
        )


elif page == "Reports":

    st.subheader("Exports")

    csv = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Download all packets as CSV",
        csv,
        "netscope_all_packets.csv",
        "text/csv"
    )

    st.write("")

    if st.button("Generate PDF report"):

        with st.spinner("Building PDF…"):
            st.session_state["pdf"] = build_pdf(cap, alerts)

    if "pdf" in st.session_state:

        st.download_button(
            "⬇ Download PDF report",
            st.session_state["pdf"],
            "netscope_report.pdf",
            "application/pdf"
        )

    st.caption(
        "The PDF is based only on the capture currently loaded "
        "and states its limitations."
    )
