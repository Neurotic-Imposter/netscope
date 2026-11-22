"""NetScope — Network Traffic Analyzer (Streamlit dashboard).

Run:  streamlit run app.py
Data flow: upload → parser.py → analysis.py / rules.py → charts.py → this file.
"""

import os
import tempfile

import pandas as pd
import streamlit as st

import charts
import analysis as A
from parser import CaptureError, parse_capture, MAX_PACKETS
import rules
from pdf_report import build_pdf

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetScope — Network Traffic Analyzer",
    page_icon="📡",
    layout="wide",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stMetric"]{
  background:#1a1a19;
  border:1px solid rgba(255,255,255,.08);
  border-radius:10px;
  padding:14px 16px
}
[data-testid="stMetricLabel"]{color:#c3c2b7}
[data-testid="stMetricValue"]{font-size:1.6rem !important}
h1,h2,h3{letter-spacing:-.01em}
.note{color:#c3c2b7;font-size:.85rem;margin-top:.2rem}
.device-card{
  background:linear-gradient(135deg,#0d2a1a,#122414);
  border:1px solid #199e70;
  border-radius:10px;
  padding:14px 18px;
}
</style>
""", unsafe_allow_html=True)


def _chart(fig, **kw):
    st.plotly_chart(fig, width='stretch', config=charts.CHART_CONFIG, **kw)


@st.cache_data(show_spinner=False, max_entries=2)
def load(file_id, _data, name):
    """Parse once per uploaded file (file_id keys the cache)."""
    fd, path = tempfile.mkstemp(suffix=os.path.splitext(name)[1] or ".pcapng")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(_data)
        cap = parse_capture(path, MAX_PACKETS)
    finally:
        os.remove(path)
    cap.file_name, cap.file_size = name, len(_data)
    return cap


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("📡 NetScope")
    st.caption("Network Traffic Analyzer")
    st.divider()

    page = st.radio("Navigate", [
        "Overview", "Protocol Analysis", "Traffic Analysis", "DNS Analysis",
        "Packet Explorer", "Security Insights", "Communication Map", "Reports",
    ])

    st.divider()
    upload = st.file_uploader(
        "📂 Upload a capture",
        type=["pcap", "pcapng"],
        help="Drag and drop or click to browse. Analysed in-memory; never saved to disk.",
    )
    st.caption("`.pcap` or `.pcapng` files exported from Wireshark.")
    st.caption("⚠ Only analyse traffic you are authorised to capture.")

    st.divider()
    with st.expander("📖 Learn the basics"):
        st.markdown("**Key networking concepts** — tap any to read more.")
        for title, body in [
            ("📦 Packet",
             "Data sent over a network is split into small chunks called **packets**. "
             "Each packet carries a source address, destination address, and a payload."),
            ("🌐 IP Address",
             "A unique number (like 192.168.1.5) that identifies a device on a network. "
             "IPv4 uses 32-bit numbers; IPv6 uses 128-bit numbers."),
            ("🔗 TCP", A.PROTOCOL_EXPLANATIONS["TCP"]),
            ("💨 UDP", A.PROTOCOL_EXPLANATIONS["UDP"]),
            ("🔍 DNS", A.PROTOCOL_EXPLANATIONS["DNS"]),
            ("🚪 Port",
             "A port is a number (0–65535) that identifies which **application** on a device "
             "should receive data. Port 80 = HTTP, 443 = HTTPS, 53 = DNS."),
            ("🔒 TLS", A.PROTOCOL_EXPLANATIONS["TLS"]),
            ("📡 ARP", A.PROTOCOL_EXPLANATIONS["ARP"]),
            ("📣 ICMP", A.PROTOCOL_EXPLANATIONS["ICMP"]),
        ]:
            with st.expander(title, expanded=False):
                st.write(body)


# ── App title ──────────────────────────────────────────────────────────────────
st.title("NetScope — Network Traffic Analyzer")

# ── Empty state ────────────────────────────────────────────────────────────────
if upload is None:
    st.markdown("""
### Welcome 👋

NetScope turns a Wireshark capture file into an easy-to-read visual dashboard.

**To get started:**
1. Open **Wireshark**, start a capture on your network interface, then stop it after a few seconds.
2. In Wireshark: **File → Save As** → choose `.pcapng` format.
3. Click **📂 Upload a capture** in the left sidebar and select your file.

All eight dashboard pages will unlock automatically.

---
**Don't have a capture yet?**  
Use Wireshark to record some traffic from your own computer — even a few seconds is enough to explore all the features.
""")
    with st.expander("What is Wireshark?"):
        st.write(
            "Wireshark is a free, open-source tool that lets you record all network packets "
            "that pass through your computer's network interface. NetScope reads those recorded "
            "files and turns them into charts and summaries. Wireshark is available at "
            "[wireshark.org](https://www.wireshark.org)."
        )
    st.stop()

# ── Load capture ───────────────────────────────────────────────────────────────
try:
    with st.spinner("Reading capture… large files can take a moment."):
        cap = load(upload.file_id, upload.getvalue(), upload.name)
except CaptureError as exc:
    st.error(f"Could not analyse this file. {exc}")
    st.stop()
except Exception as exc:
    st.error(f"Unexpected problem while reading the capture: {exc}")
    st.stop()

df, dns = cap.packets, cap.dns
ov = A.overview(df)
alerts = rules.run_all(df, dns)
capture_hosts = rules.likely_capture_hosts(df)

st.caption(
    f"Capture: **{cap.file_name}** · "
    f"{ov['packets']:,} packets · "
    f"{A.format_bytes(ov['bytes'])} · "
    f"All figures come from this file only."
)
for n in cap.notes:
    st.warning(n)


# ═══════════════════════════════════════════════════════════════════════════════
# OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════
if page == "Overview":
    st.header("What happened in this network capture?")

    # Likely capture device (green card)
    if capture_hosts:
        host_str = ", ".join(capture_hosts)
        st.markdown(f"""
<div class="device-card">
  <div style="font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#c3c2b7;margin-bottom:4px">
    🖥 Likely Your Device (estimate)
  </div>
  <div style="font-size:1.1rem;font-weight:600;color:#34c77b;margin:4px 0">{host_str}</div>
  <div style="font-size:.85rem;color:#c3c2b7;margin-top:4px">
    This IP address appears in ≥90% of all packets — a strong sign it belongs to
    the computer that recorded the capture. It is excluded from "high traffic" alerts.
    This is an estimate based on packet frequency, not a confirmed identity.
  </div>
</div>
""", unsafe_allow_html=True)
        st.write("")

    # Key numbers
    c0, c1, c2, c3, c4 = st.columns(5)
    c0.metric("📦 Total Packets Captured", f"{ov['packets']:,}",
              help="The number of individual packets found in your capture file.")
    c1.metric("📊 Total Data Transferred", A.format_bytes(ov["bytes"]),
              help="Combined size of all captured packet frames (wire bytes).")
    c2.metric("⏱ Capture Duration", f"{ov['duration']:.1f} s",
              help="Time from the first to the last packet in the capture.")
    c3.metric("🌐 Unique Sender Addresses", ov["unique_src"],
              help="Number of unique IP addresses that sent packets.")
    c4.metric("📍 Unique Receiver Addresses", ov["unique_dst"],
              help="Number of unique IP addresses that received packets.")

    # Auto-generated observations
    st.subheader("Key observations")
    st.caption("These statements are generated from your actual capture — nothing is guessed.")
    for sentence in A.narrative(df, dns, ov):
        st.markdown(f"- {sentence}")

    # Charts
    st.divider()
    left, right = st.columns(2)
    layers = A.layer_tables(df)
    with left:
        st.subheader("Types of Network Traffic")
        st.caption("How packets were carried — TCP for reliable delivery, UDP for speed.")
        _chart(charts.protocol_donut(layers["Transport layer"], "Transport layer (share of packets)"))
    with right:
        st.subheader("Most-Used Services (Destination Ports)")
        st.caption("Ports identify which service on the destination device received the data.")
        top_ports_df = A.top_ports(df, "dport", 8).copy()
        top_ports_df["port"] = top_ports_df["port"].apply(A.label_port)
        _chart(charts.bar_h(top_ports_df, "port", "packets", "Most used destination ports"))

    st.caption(
        "ARP packets have no transport layer, so they appear as 'No transport layer'. "
        "See **Protocol Analysis** for all three layers."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Protocol Analysis":
    st.header("Protocol Analysis — Types of Network Traffic")
    st.markdown(
        "Every packet travels through several **protocol layers** at once — like envelopes inside envelopes. "
        "The **network layer** routes it, the **transport layer** delivers it, and the "
        "**application layer** defines what the data means.\n\n"
        "> Each section below is a separate view of the **same packets**. "
        "Do not add the numbers together."
    )

    layers = A.layer_tables(df)
    layer_descriptions = {
        "Network layer": (
            "The network layer handles addressing and routing between devices. "
            "IPv4 and IPv6 are the two standards in common use today."
        ),
        "Transport layer": (
            "The transport layer controls how data is delivered. "
            "**TCP** guarantees order and delivery. **UDP** is faster but does not guarantee delivery. "
            "**ICMP** carries diagnostic messages (like ping)."
        ),
        "Application layer": (
            "The application layer identifies what the payload is used for — "
            "web browsing (HTTP/TLS), name resolution (DNS), time sync (NTP), etc."
        ),
    }

    for name, t in layers.items():
        st.subheader(name)
        st.caption(layer_descriptions[name])
        col_chart, col_table = st.columns([1, 1])
        with col_chart:
            _chart(charts.protocol_donut(t, name))
        with col_table:
            t_display = t.copy()
            t_display["What it does"] = t_display["protocol"].map(A.PROTOCOL_EXPLANATIONS).fillna("—")
            st.dataframe(
                t_display.rename(columns={"protocol": "Protocol", "packets": "Packets", "percent": "%"}),
                hide_index=True, width='stretch',
            )
        st.write("")

    with st.expander("📋 Compare with Wireshark display filters (advanced)"):
        st.caption(
            "These counts mirror what you would see typing each filter into Wireshark's display filter bar. "
            "Counts of 0 mean that protocol was not found in this capture."
        )
        wf = pd.DataFrame([
            ("tcp",                      int((df["transport"] == "TCP").sum())),
            ("udp",                      int((df["transport"] == "UDP").sum())),
            ("dns  (port 53 only)",      int((df["app"] == "DNS").sum())),
            ("icmp  (ICMPv4 only)",      int((df["transport"] == "ICMP").sum())),
            ("arp",                      int((df["network"] == "ARP").sum())),
            ("icmpv6",                   int((df["transport"] == "ICMPv6").sum())),
            ("tls (by TLS record header)", int((df["app"] == "TLS").sum())),
            ("http",                     int((df["app"] == "HTTP").sum())),
        ], columns=["Wireshark filter", "NetScope count"])
        st.dataframe(wf, hide_index=True, width='stretch')
        st.caption(
            "mDNS and LLMNR are counted separately from `dns`. "
            "TLS, HTTP and QUIC are identified from packet bytes/ports and are heuristics."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Traffic Analysis":
    st.header("Traffic Analysis — Who Sent and Received the Most Data?")
    st.markdown(
        "This page shows the busiest IP addresses (senders and receivers), "
        "their conversations, how traffic changed over time, and which services were most active."
    )

    # Top senders / receivers
    st.subheader("Who sent and received the most packets?")
    st.caption(
        "These are the IP addresses that appeared most often as the sender or receiver. "
        "Your own device usually appears at the top. ★ marks the likely capture device."
    )
    a, b = st.columns(2)
    with a:
        st.caption("**Top Sender IP Addresses**")
        _chart(charts.bar_h(A.top_talkers(df, "src"), "src", "packets", "Top senders (packets)"))
    with b:
        st.caption("**Top Receiver IP Addresses**")
        _chart(charts.bar_h(A.top_talkers(df, "dst"), "dst", "packets",
                            "Top receivers (packets)", charts.SERIES[1]))

    # Conversations
    st.subheader("Most Active Device Pairs")
    st.caption(
        "A conversation is a pair of IP addresses that exchanged packets. "
        "Traffic in both directions is combined into one row."
    )
    conv_df = A.conversations(df).head(15)
    conv_display = conv_df.rename(columns={"a": "Sender / Receiver A", "b": "Sender / Receiver B"}).copy()
    conv_display["Sender / Receiver A"] = conv_display["Sender / Receiver A"].apply(
        lambda ip: f"★ {ip} (your device)" if ip in capture_hosts else ip
    )
    conv_display["Sender / Receiver B"] = conv_display["Sender / Receiver B"].apply(
        lambda ip: f"★ {ip} (your device)" if ip in capture_hosts else ip
    )
    conv_display["bytes"] = conv_display["bytes"].apply(A.format_bytes)
    st.dataframe(
        conv_display.rename(columns={"packets": "Packets", "bytes": "Data Transferred"}),
        hide_index=True, width='stretch',
    )

    # Traffic over time
    st.subheader("Network Activity Over Time")
    st.caption(
        "This chart shows how busy the network was at each moment during the capture. "
        "Spikes may indicate bursts of activity such as file downloads or web page loads."
    )
    metric = st.radio("Show", ["packets", "bytes"], horizontal=True,
                      format_func=lambda x: "Packet count" if x == "packets" else "Bytes transferred")
    tbl, width = A.traffic_over_time(df)
    _chart(charts.time_series(tbl, metric, width))

    # Ports
    st.subheader("Services Being Used (Ports)")
    st.caption(
        "Ports identify which service on a device is communicating. "
        "Port 443 = HTTPS (secure web), 53 = DNS (name lookup), 80 = HTTP (plain web)."
    )
    p1, p2 = st.columns(2)
    with p1:
        st.caption("**Source ports** — where connections came from")
        src_ports = A.top_ports(df, "sport", 10).copy()
        src_ports["port"] = src_ports["port"].apply(A.label_port)
        _chart(charts.bar_h(src_ports, "port", "packets", "Common source ports", charts.SERIES[2]))
    with p2:
        st.caption("**Destination ports** — which services were contacted")
        dst_ports = A.top_ports(df, "dport", 10).copy()
        dst_ports["port"] = dst_ports["port"].apply(A.label_port)
        _chart(charts.bar_h(dst_ports, "port", "packets", "Common destination ports", charts.SERIES[3]))

    # Packet size distribution
    st.subheader("Packet Size Distribution")
    st.caption(
        "Small packets (under 100 bytes) are often control messages. "
        "Large packets near 1500 bytes are typically data transfers — this is the typical "
        "maximum size for Ethernet frames (called the MTU)."
    )
    _chart(charts.histogram(A.length_histogram(df)))


# ═══════════════════════════════════════════════════════════════════════════════
# DNS ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "DNS Analysis":
    st.header("DNS Analysis — Website Address Lookups")
    st.markdown(
        "**DNS (Domain Name System)** is like a phone book for the internet. "
        "When your computer visits `google.com`, it first asks a DNS server: "
        "_\"What is the IP address for google.com?\"_ — that is a DNS query. "
        "This page shows all such lookups found in your capture."
    )

    ds = A.dns_summary(dns)
    if not ds["available"]:
        st.info(
            "No standard DNS (port 53) packets were found in this capture.\n\n"
            "This can happen if DNS traffic was filtered out before saving, "
            "or if the capture was very short. mDNS (multicast DNS) traffic uses "
            "port 5353 and would appear in Protocol Analysis as 'mDNS'."
        )
    else:
        c = st.columns(5)
        c[0].metric("🔍 DNS Queries Sent", ds["queries"],
                    help="DNS lookup requests sent by this device.")
        c[1].metric("✅ Responses Received", ds["responses"],
                    help="Answers received from DNS servers.")
        c[2].metric("❌ Failed Responses", ds["failed"],
                    help="Responses with an error code (e.g. NXDOMAIN = name not found).")
        c[3].metric("❓ Unanswered Queries", ds["unanswered"],
                    help="Queries for which no response was seen in this capture window.")
        c[4].metric("⏱ Median Reply Time",
                    f"{ds['rtt_median_ms']:.1f} ms" if ds["rtt_median_ms"] is not None else "—",
                    help="Median time between a DNS query and its matching response.")

        st.markdown(f"**DNS servers used:** `{'`, `'.join(ds['servers'])}`")
        st.caption(
            "A DNS server is the computer that answers name lookups. "
            "Common DNS servers: 8.8.8.8 (Google), 1.1.1.1 (Cloudflare), 192.168.x.x (your router)."
        )

        a, b = st.columns(2)
        with a:
            st.subheader("Most Looked-Up Domain Names")
            st.caption("Names your device asked the DNS server to resolve.")
            _chart(charts.bar_h(
                A.dns_domains(dns, 12).assign(
                    label=lambda d: d["qname"] + " (" + d["qtype"] + ")"
                ), "label", "queries", "Most queried names"
            ))
        with b:
            st.subheader("Query Types")
            st.caption(
                "**A** = IPv4 address lookup · "
                "**AAAA** = IPv6 address lookup · "
                "**PTR** = reverse lookup (IP → name) · "
                "**HTTPS** = service info"
            )
            _chart(charts.protocol_donut(
                A.dns_types(dns).rename(columns={"type": "protocol", "queries": "packets"}),
                "Query types"
            ))

        # Failed DNS responses
        failed = dns[dns["is_response"] & (dns["rcode"] != "NOERROR")]
        if len(failed):
            st.subheader("Failed DNS Responses")
            rcodes_seen = failed["rcode"].unique()
            st.caption(
                "  |  ".join(
                    f"**{rc}**: {A.DNS_RCODE_EXPLANATIONS.get(rc, '')}" for rc in rcodes_seen
                )
            )
            st.dataframe(
                failed[["no", "qname", "qtype", "rcode", "src"]].rename(columns={"src": "server"}),
                hide_index=True, width='stretch',
            )
            st.caption(
                "NXDOMAIN for reverse lookups (PTR queries on local addresses like 192.168.x.x) "
                "is completely normal — it just means there is no reverse DNS entry set up."
            )

        st.subheader("DNS Answers Received")
        st.caption("Each row is a DNS response. The 'answers' column shows what IP address the DNS server returned.")
        st.dataframe(A.dns_answers(dns, 200), hide_index=True, width='stretch')


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET EXPLORER
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Packet Explorer":
    st.header("Packet Explorer — Browse Every Packet")
    st.markdown(
        "Browse every packet in the capture. Use the filters below to narrow down "
        "what you see, then download the results as a CSV file."
    )

    # Filters
    f1, f2, f3, f4 = st.columns([2, 2, 1, 2])
    protos = f1.multiselect(
        "Protocol",
        sorted(df["protocol"].unique()),
        help="Filter to one or more protocols (e.g. TCP, DNS, TLS).",
    )
    ipq = f2.text_input(
        "IP address contains",
        placeholder="e.g. 192.168.1",
        help="Matches packets where either the sender OR receiver IP contains this text.",
    )
    port = f3.text_input(
        "Port",
        placeholder="e.g. 443",
        help="Filter to packets using this port number (source or destination).",
    )
    text = f4.text_input(
        "Search info",
        placeholder="e.g. SYN or google.com",
        help="Search the packet description field (not the encrypted payload).",
    )

    # Apply filters
    v = df.copy()
    if protos:
        v = v[v["protocol"].isin(protos)]
    if ipq:
        v = v[v["src"].str.contains(ipq, regex=False) | v["dst"].str.contains(ipq, regex=False)]
    if port.strip().isdigit():
        p = int(port)
        v = v[(v["sport"] == p) | (v["dport"] == p)]
    elif port.strip():
        st.warning("Port must be a whole number (e.g. 443).")
    if text:
        v = v[v["info"].str.contains(text, case=False, regex=False)]

    match_msg = f"**{len(v):,}** of {len(df):,} packets match"
    if len(v) > 5000:
        match_msg += " (showing first 5,000 — download CSV for all)"
    st.write(match_msg)

    show = v.copy()
    show["timestamp"] = (
        pd.to_datetime(show["time"], unit="s", utc=True)
        .dt.strftime("%H:%M:%S.%f")
        .str[:-3]
    )
    show["src"] = show["src"].apply(lambda ip: f"★ {ip}" if ip in capture_hosts else ip)
    st.dataframe(
        show[["no", "timestamp", "src", "dst", "protocol", "sport", "dport", "length", "info"]].head(5000),
        hide_index=True,
        width='stretch',
        height=480,
        column_config={
            "no":        st.column_config.NumberColumn("No.", width="small"),
            "timestamp": st.column_config.TextColumn("Time", width="small"),
            "src":       st.column_config.TextColumn("Sender IP", width="medium"),
            "dst":       st.column_config.TextColumn("Receiver IP", width="medium"),
            "protocol":  st.column_config.TextColumn("Protocol", width="small"),
            "sport":     st.column_config.NumberColumn("Sender Port", width="small"),
            "dport":     st.column_config.NumberColumn("Receiver Port", width="small"),
            "length":    st.column_config.NumberColumn("Bytes", width="small"),
            "info":      st.column_config.TextColumn("Info", width="large"),
        },
    )

    # Export
    export_cols = ["no", "src", "dst", "network", "transport", "app",
                   "protocol", "sport", "dport", "length", "tcp_flags", "info"]
    export = v[export_cols].copy()
    export.insert(1, "timestamp_utc", pd.to_datetime(v["time"], unit="s", utc=True).astype(str))
    st.download_button(
        "⬇ Download filtered packets as CSV",
        export.to_csv(index=False).encode("utf-8"),
        "netscope_packets.csv",
        "text/csv",
        help="Downloads all matching packets (not just the first 5,000 shown above).",
    )
    st.caption("★ marks the IP address identified as your device (estimate).")


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY INSIGHTS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Security Insights":
    st.header("Security Insights — Unusual Network Activity")
    st.markdown(
        "NetScope checks your capture against **five simple rules** that look for patterns "
        "associated with unusual network behaviour. These are **not confirmations of attacks** — "
        "they are observations worth investigating further.\n\n"
        "Think of them like a checklist a networking teacher might go through when reviewing a capture."
    )

    with st.expander("ℹ What do these findings mean?"):
        st.markdown("""
**Medium** 🟠 — Pattern is unusual and worth investigating, but has innocent explanations.  
**Low** 🟡 — Mildly unusual; often caused by normal retries or caching.  
**Info** 🔵 — Informational observation; very likely normal behaviour.

Remember: NetScope only sees what was captured. A missing response might simply be outside the capture window.
""")

    if not alerts:
        st.success(
            "✅ No indicators were triggered for this capture. "
            "All five rules checked out clean based on the patterns in this file."
        )
    for a in alerts:
        icon = {"Medium": "🟠", "Low": "🟡", "Info": "🔵"}[a.severity]
        with st.expander(f"{icon} [{a.severity}] {a.title}", expanded=True):
            st.write(a.explanation)
            st.caption("Evidence from the capture:")
            st.dataframe(
                pd.DataFrame(list(a.evidence.items()), columns=["Field", "Value"]),
                hide_index=True, width='stretch',
            )
            st.caption(f"⚠ {a.caveat}")

    st.divider()
    st.subheader("Rules Checked")
    st.caption("These are the exact conditions that trigger each finding. All thresholds are configurable in `rules.py`.")
    st.dataframe(
        rules.rules_table().rename(columns={"Rule": "Rule name", "Fires when": "Triggered when"}),
        hide_index=True, width='stretch',
    )

    if capture_hosts:
        st.caption(
            f"**Likely capture device(s):** {', '.join(capture_hosts)} — "
            "excluded from the 'high traffic from one source' rule, since the recording "
            "device naturally appears in every packet."
        )
    else:
        st.caption("No single device was identified as the likely capture host (no IP appears in ≥90% of packets).")


# ═══════════════════════════════════════════════════════════════════════════════
# COMMUNICATION MAP
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Communication Map":
    st.header("Communication Map — Who Is Communicating With Whom?")
    st.markdown(
        "Each **dot** represents an IP address. Each **line** is a conversation — "
        "packets exchanged between two addresses. Thicker lines carried more data.\n\n"
        "🌟 **Green star** = likely your device (the one that recorded the capture)."
    )

    n = st.slider(
        "Number of devices to show",
        5, 40, 20,
        help="Shows only the busiest endpoints to keep the map readable. Increase to see more.",
    )
    fig = charts.comm_map(A.conversations(df), n, highlight_nodes=set(capture_hosts))
    if fig is None:
        st.info("No IP conversations to draw — the capture may contain only ARP or non-IP packets.")
    else:
        _chart(fig)
        st.caption(
            "Only the busiest endpoints are shown. Hover over any dot or line for details. "
            "Isolated dots that share no edge had conversations only with endpoints not in the top list."
        )

    with st.expander("📖 How to read this map"):
        st.markdown("""
- **Node size** = total bytes sent and received by that IP address
- **Line thickness** = bytes in that specific conversation
- **Green star** = your device (most likely the computer running Wireshark)
- **Blue dots** = other devices (could be local or on the internet)
- **Hover** over any node or line to see exact numbers
""")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Reports":
    st.header("Export & Reports")
    st.markdown(
        "Download the data for use in your project report, spreadsheets, or further analysis."
    )

    st.subheader("📄 CSV Export")
    st.caption("A CSV file can be opened in Excel, Google Sheets, or any spreadsheet tool.")
    st.download_button(
        "⬇ Download all packets as CSV",
        df.to_csv(index=False).encode("utf-8"),
        "netscope_all_packets.csv",
        "text/csv",
        help=f"All {len(df):,} packets with 14 columns including timestamps, IPs, protocols, ports and lengths.",
    )

    st.divider()
    st.subheader("📋 PDF Report")
    st.caption(
        "The PDF includes a summary table, protocol statistics, top talkers, DNS observations, "
        "traffic chart, and security findings — suitable for a project submission."
    )
    if st.button("Generate PDF report", type="primary"):
        with st.spinner("Building PDF… this takes a few seconds."):
            st.session_state["pdf"] = build_pdf(cap, alerts)
        st.success("PDF ready — click the download button below.")

    if "pdf" in st.session_state:
        st.download_button(
            "⬇ Download PDF report",
            st.session_state["pdf"],
            "netscope_report.pdf",
            "application/pdf",
        )

    st.divider()
    st.caption(
        "All exported data describes only the capture currently loaded. "
        "Nothing is saved on the server."
    )
