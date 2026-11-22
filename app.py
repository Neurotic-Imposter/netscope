"""Network Analysis Using Wireshark — PBL project (internal name: NetScope).

Run:  streamlit run app.py
Data flow: upload → parser.py → analysis.py / rules.py → charts.py → this file.
Look and feel: ui.py (theme + shared components). Teaching text: guide.py.
"""

import hashlib
import os
import tempfile
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

import charts
import guide
import rules
import ui
import analysis as A
from parser import CaptureError, parse_capture, MAX_PACKETS
from pdf_report import build_pdf

st.set_page_config(
    page_title="Network Analysis Using Wireshark",
    page_icon="📡",
    layout="wide",
)

# The nine pages, in sidebar order (plain-English names).
PAGES = [
    "Overview",
    "Types of Traffic",
    "Devices & Activity",
    "Website Lookups",
    "Browse Packets",
    "Unusual Activity",
    "Performance",
    "Communication Map",
    "Reports",
]
UPLOAD_TYPES = ["pcap", "pcapng"]
UPLOAD_HELP = ("Drag and drop or click to browse. The file is analysed in memory and never saved.")


# ── Small helpers used by several pages ───────────────────────────────────────
def show_chart(fig):
    st.plotly_chart(fig, width="stretch", config=charts.CHART_CONFIG)


def show_ip(label, ip):
    """A labelled IP address in a code box (the code box has a copy button)."""
    st.caption(label)
    st.code(ip, language=None)


def friendly_table(table):
    """Replace the 'protocol' column of a counts table with friendly name + technical name."""
    out = table.copy()
    out["protocol"] = out["protocol"].map(A.protocol_label)
    return out


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def status_card(column, title, available, what, metrics=(), reason=""):
    """A card that either shows real measurements or says plainly why it cannot."""
    with column:
        with st.container(border=True):
            chip = ui.chip("Available", "ok") if available else ui.chip("Not available")
            st.markdown(f"**{title}** &nbsp; {chip}", unsafe_allow_html=True)
            st.caption(what)
            if available:
                for label, value, help_text in metrics:
                    st.metric(label, value, help=help_text)
            else:
                st.caption(reason)


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
    # A short fingerprint of the file contents: it identifies THIS capture.
    cap.fingerprint = hashlib.sha256(_data).hexdigest()[:16]
    return cap


# ═══════════════════════════════════════════════════════════════════════════════
# LANDING PAGE (shown until a capture is uploaded)
# ═══════════════════════════════════════════════════════════════════════════════
def landing_page():
    """Overview content shown while no capture is loaded."""
    # A. Introduction
    st.markdown(
        '<div class="ns-hero"><span class="ns-eyebrow">PBL Project</span>'
        "<h1>Network Analysis Using Wireshark</h1>"
        '<p class="ns-lead">Everything you do online is sent as small chunks of data called '
        "<b>packets</b>: loading a page, asking where a website lives, replying to a message. "
        "Looking at those packets shows how devices, websites and services really talk to each other.</p></div>",
        unsafe_allow_html=True,
    )
    a, b, c = st.columns(3)
    for col, title, text in [
        (a, "We normally cannot see it", "Ordinary internet use hides all of this communication behind the screen."),
        (b, "Problems are hard to explain", "Why is a site slow? Why did a DNS lookup fail? Why can one device not connect?"),
        (c, "Packets hold the evidence", "Analysing the packets turns those questions into things we can count, chart and check."),
    ]:
        col.markdown(f'<div class="ns-card"><h4>{title}</h4><p>{text}</p></div>', unsafe_allow_html=True)

    # B. Wireshark vs this application
    st.subheader("Wireshark and this application")
    left, right = st.columns(2)
    left.markdown(
        '<div class="ns-card"><h4>Wireshark <span class="ns-chip">Captures and inspects</span></h4><ul>'
        "<li>Captures network packets from your network connection.</li>"
        "<li>Shows every individual packet.</li>"
        "<li>Identifies protocols and shows detailed packet contents.</li>"
        "<li>Filters packets for detailed investigation.</li></ul></div>",
        unsafe_allow_html=True,
    )
    right.markdown(
        '<div class="ns-card accent"><h4>This Python application <span class="ns-chip blue">Analyses and explains</span></h4><ul>'
        "<li>Analyses saved <code>.pcap</code> and <code>.pcapng</code> files.</li>"
        "<li>Summarises what happened on the network.</li>"
        "<li>Shows protocol shares and who communicated with whom.</li>"
        "<li>Creates charts and PDF / CSV reports.</li></ul></div>",
        unsafe_allow_html=True,
    )
    st.caption("Wireshark records the traffic; this application reads the saved file afterwards. "
               "It does not capture live traffic, cannot decrypt HTTPS and does not replace Wireshark.")

    # C. Upload
    st.subheader("Upload a capture")
    with st.container(border=True):
        steps, uploader = st.columns([1, 1.15], gap="large")
        with steps:
            for number, text in enumerate([
                "Capture network traffic using <strong>Wireshark</strong>.",
                "Save it with <strong>File → Save As</strong> as <code>.pcap</code> or <code>.pcapng</code>.",
                "Upload the file here, or with the control in the left sidebar.",
                "Explore the generated analysis on nine pages.",
            ], start=1):
                st.markdown(f'<div class="ns-step"><span class="ns-num">{number}</span><span>{text}</span></div>',
                            unsafe_allow_html=True)
        with uploader:
            st.file_uploader("Upload a capture", type=UPLOAD_TYPES, key="capture_main", help=UPLOAD_HELP,
                             label_visibility="collapsed")
            st.caption(f"Supported: `.pcap`, `.pcapng`. The first {MAX_PACKETS:,} packets are analysed. "
                       "Only analyse traffic you are allowed to capture.")

    # D. Educational simulation (fixed example values, never mixed with a real capture)
    st.subheader("How a packet travels: an example")
    st.markdown('<span class="ns-sim-tag">Educational simulation · example values · not from any capture</span>',
                unsafe_allow_html=True)
    st.caption("Visiting YouTube from a laptop takes four packets in this simplified example. Pick a step.")
    name = st.radio("Step", [s["name"] for s in guide.SIM_STEPS], horizontal=True,
                    key="sim_step", label_visibility="collapsed")
    step = next(s for s in guide.SIM_STEPS if s["name"] == name)
    st.markdown(ui.sim_flow(step["direction"], step["server"]), unsafe_allow_html=True)
    st.caption(step["says"])
    table = "| Field | Example value | What it means |\n|---|---|---|\n" + "\n".join(
        f"| {label} | `{step[key]}` | {meaning} |" for label, key, meaning in guide.SIM_FIELDS)
    st.markdown(table)
    st.caption("The addresses are examples (203.0.113.x is reserved for documentation). "
               "Real HTTPS content is encrypted; only the fields above are visible on the network.")


EMPTY_STATE_TEXT = {
    "Types of Traffic": "which protocols (TCP, UDP, DNS, ARP, ICMP, HTTP, HTTPS) appear and how many packets each has",
    "Devices & Activity": "the busiest IP addresses, ports and packet sizes",
    "Website Lookups": "the DNS questions and answers, and which names were looked up",
    "Browse Packets": "every packet in a filterable table with a detail view",
    "Unusual Activity": "simple observations that may deserve a second look",
    "Performance": "timing that can be measured from packet timestamps",
    "Communication Map": "who sent data to whom, as dots and arrows",
    "Reports": "the PDF report and CSV downloads",
}


def empty_state(page_name):
    """Shown on pages 2-9 until a capture is loaded. It contains no numbers, only instructions."""
    ui.page_header(page_name, f"This page shows {EMPTY_STATE_TEXT[page_name]}.")
    with st.container(border=True):
        st.markdown("**No capture loaded yet**")
        st.write("Upload a `.pcap` or `.pcapng` file saved from Wireshark to see the real analysis here. "
                 "Nothing is shown until then, so no sample numbers can be mistaken for real results.")
        st.markdown("Use **Upload or replace the capture** in the left sidebar, or open **Overview** for the full "
                    "upload instructions and an example of how a packet travels.")


# ═══════════════════════════════════════════════════════════════════════════════
# Page frame: the sidebar is always built first, whether or not a capture exists
# ═══════════════════════════════════════════════════════════════════════════════
ui.inject_theme()

with st.sidebar:
    st.markdown('<div class="ns-brand">Network Analysis Using Wireshark<small>PBL Project</small></div>',
                unsafe_allow_html=True)
    page = st.radio("Pages", PAGES, key="page", label_visibility="collapsed")
    st.divider()
    side_upload = st.file_uploader("Upload or replace the capture", type=UPLOAD_TYPES, key="capture_side",
                                   help=UPLOAD_HELP)
    st.caption("`.pcap` or `.pcapng` files saved from Wireshark.")
    with st.expander("Learn the basics"):
        st.markdown(
            "**Packet**: data sent over a network is split into small chunks called packets. "
            "Each one carries a sender address, a receiver address and some data.\n\n"
            "**IP address**: a number like `192.168.1.5` that identifies a device on a network.\n\n"
            "**Port**: a number that tells a device which program should receive the data "
            "(443 = secure web, 53 = website lookups)."
        )

# ── Which capture is loaded? Two uploaders exist (Overview body and sidebar); the newest upload wins. ──
# shortcut: the uploaded bytes are kept in session state so either uploader can replace the other; fine for
# classroom-sized files, upgrade to a temp file if very large captures are used.
for source, widget in (("main", st.session_state.get("capture_main")), ("side", side_upload)):
    if widget is not None and st.session_state.get("seen_" + source) != widget.file_id:
        st.session_state["seen_" + source] = widget.file_id
        st.session_state["current"] = {"id": widget.file_id, "data": widget.getvalue(),
                                       "name": widget.name, "source": source}
current = st.session_state.get("current")
if current and side_upload is None and current["source"] == "side":
    del st.session_state["current"]          # the user removed the file in the sidebar
    current = None

# ── Load capture (cap stays None when nothing is loaded or the file is rejected) ──
cap, load_error = None, None
if current:
    try:
        with st.spinner("Reading capture… large files can take a moment."):
            cap = load(current["id"], current["data"], current["name"])
    except CaptureError as exc:
        load_error = f"Could not analyse this file. {exc}"
    except Exception as exc:
        load_error = f"Unexpected problem while reading the capture: {exc}"

if cap is not None:
    df, dns = cap.packets, cap.dns
    ov = A.overview(df)
    alerts = rules.run_all(df, dns)
    capture_hosts = rules.likely_capture_hosts(df)

    st.caption(
        f"Capture: **{ui.md_escape(cap.file_name)}** · {ov['packets']:,} packets · "
        f"{A.format_bytes(ov['bytes'])} · All figures come from this file only."
    )
    for n in cap.notes:
        st.warning(n)


# ═══════════════════════════════════════════════════════════════════════════════
# OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════
if cap is None:
    if load_error:
        st.error(load_error)
    if page == "Overview":
        landing_page()
    else:
        empty_state(page)

elif page == "Overview":
    ui.page_header("Overview", "The big picture of what happened in this capture.")

    main, side = st.columns([2.2, 1])
    with main:
        with st.container(border=True):
            cols = st.columns(4)
            for col, label, value, help_text in [
                (cols[0], "Total Packets", f"{ov['packets']:,}",
                 "The total number of individual packets found in the uploaded capture."),
                (cols[1], "Unique IP Addresses", f"{ov['unique_ips']:,}",
                 "The number of distinct IP addresses that sent or received packets. "
                 "An IP address is not always one physical device."),
                (cols[2], "Total Data", A.format_bytes(ov["bytes"]),
                 "Combined size of all captured packets."),
                (cols[3], "Capture Duration", f"{ov['duration']:.1f} s",
                 "Time from the first packet to the last packet."),
            ]:
                with col:
                    st.metric(label, value, help=help_text)
            st.markdown("**Traffic over time**")
            st.caption("How busy the network was during the capture. Spikes are bursts of activity.")
            what = st.radio("Show", ["packets", "bytes"], horizontal=True, key="activity_what",
                            format_func=lambda x: "Number of packets" if x == "packets" else "Amount of data")
            table, width = A.traffic_over_time(df)
            show_chart(charts.time_series(table, what, width))
    with side:
        with st.container(border=True):
            st.markdown("**Capture details**")
            st.caption("File")
            st.code(cap.file_name, language=None)
            st.caption(f"Size on disk: {A.format_bytes(cap.file_size)}")
            st.caption(f"First packet: {utc(ov['start'])}")
            st.caption(f"Last packet: {utc(ov['end'])}")
            st.markdown("**Likely your device**")
            if capture_hosts:
                for host in capture_hosts:
                    st.code(host, language=None)
                st.caption("An estimate: this address appears in at least 90% of all packets, which usually "
                           "means it is the computer that recorded the capture. An IP address does not identify a person.")
            else:
                st.caption("No single address appears in at least 90% of the packets, "
                           "so this cannot be estimated.")

    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown("**Protocol distribution**")
            st.caption("How packets were delivered. Each packet is counted once here. "
                       "Protocols that overlap, such as DNS and HTTPS, are on Types of Traffic.")
            show_chart(charts.bar_h(friendly_table(A.layer_tables(df)["Transport layer"]),
                                    "protocol", "packets", ""))
    with right:
        with st.container(border=True):
            st.markdown("**Top communicating IP addresses**")
            st.caption("Packets sent plus received. Your own device usually appears near the top.")
            show_chart(charts.bar_h(A.ip_activity(df).head(6), "ip", "packets", "",
                                    x_title="Packets (sent + received)"))

    with st.container(border=True):
        st.markdown("**Important observations**")
        st.caption("Written automatically from this capture. Every sentence is based on counts from the file.")
        for sentence in A.narrative(df, dns, ov)[1:6]:
            st.markdown(f"- {sentence}")
        if alerts:
            st.markdown(f"- **{len(alerts)}** item(s) were flagged for a second look on the "
                        "**Unusual Activity** page. These are observations, not proof of anything.")
        else:
            st.markdown("- None of the unusual-activity checks found anything in this capture.")


# ═══════════════════════════════════════════════════════════════════════════════
# TYPES OF TRAFFIC
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Types of Traffic":
    ui.page_header("Types of Traffic",
                   "The protocols found in this capture, what each one is for and what its presence tells you.",
                   "Protocol Analysis")
    st.info("**These counts overlap, so do not add them together.** TCP and UDP are transport-layer protocols. "
            "DNS, HTTP and HTTPS are application-layer protocols that travel inside them, so a DNS packet is "
            "also a UDP packet and an HTTPS packet is also a TCP packet.")

    counts = A.protocol_counts(df)
    st.subheader("Protocols found in this capture")
    for row in (counts[:4], counts[4:]):
        cols = st.columns(4)
        for col, (name, n, pct) in zip(cols, row):
            label = "HTTPS (TLS)" if name == "HTTPS" else name
            ui.metric_card(col, f"{label} · {pct:g}%", f"{n:,}",
                           f"{n:,} packets, {pct:g}% of all packets in the capture. "
                           "A packet can be counted under more than one protocol.")

    st.subheader("What each protocol means")
    icmpv6 = int((df["transport"] == "ICMPv6").sum())
    extras = {
        "DNS": f"Standard DNS on port 53 only. Local name lookups (mDNS) are counted separately: "
               f"{int((df['app'] == 'mDNS').sum()):,} packets.",
        "ICMP": f"ICMP for IPv4 only. ICMPv6 packets are counted separately: {icmpv6:,}.",
        "HTTPS": f"TCP packets on port 443: {int(((df['transport'] == 'TCP') & ((df['sport'] == 443) | (df['dport'] == 443))).sum()):,}. "
                 f"QUIC packets (UDP port 443): {int((df['app'] == 'QUIC').sum()):,}. "
                 "Content is encrypted and is never read.",
    }
    tabs = st.tabs([name for name, _, _ in counts])
    for tab, (name, n, pct) in zip(tabs, counts):
        g = guide.PROTOCOL_GUIDE[name]
        with tab:
            st.markdown(f"**{n:,} packets** ({pct:g}% of this capture) · {g['layer']}")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**What it is**  \n{g['what']}")
                st.markdown(f"**What it does**  \n{g['does']}")
                st.markdown(f"**How it works**  \n{g['how']}")
            with c2:
                st.markdown("**What it means in this capture**")
                st.write(g["present"] if n else f"No {name} packets were found in this capture.")
                if name in extras:
                    st.caption(extras[name])
                st.markdown(f"**What this application analyses**  \n{g['analysed']}")

    st.subheader("Breakdown by layer")
    layers = A.layer_tables(df)
    descriptions = {
        "Network layer": "How packets are addressed and sent between devices (IPv4, IPv6, ARP).",
        "Transport layer": "How data is delivered: reliably (TCP), quickly (UDP) or as connectivity messages (ICMP).",
        "Application layer": "What the data is used for, such as website lookups or encrypted web pages.",
    }
    tab_names = {"Network layer": "Network", "Transport layer": "Transport",
                 "Application layer": "Application"}
    st.caption("Each tab is a different view of the **same packets**. The percentages inside one tab add up to 100%.")
    layer_tabs = st.tabs(list(tab_names.values()))
    for tab, layer in zip(layer_tabs, tab_names):
        with tab:
            st.caption(descriptions[layer])
            t = layers[layer]
            col_chart, col_table = st.columns(2)
            with col_chart:
                show_chart(charts.protocol_donut(friendly_table(t), layer))
            with col_table:
                nice = pd.DataFrame({
                    "Type of traffic": t["protocol"].map(A.friendly_name),
                    "Protocol": t["protocol"],
                    "Packets": t["packets"],
                    "%": t["percent"],
                    "What it does": t["protocol"].map(A.protocol_description),
                })
                st.dataframe(nice, hide_index=True, width="stretch")

    with st.expander("Compare with Wireshark display filters (for students)"):
        st.caption("These counts match what you would see by typing each filter into Wireshark. "
                   "A count of 0 means the protocol was not found in this capture.")
        wf = pd.DataFrame([
            ("tcp", int((df["transport"] == "TCP").sum())),
            ("udp", int((df["transport"] == "UDP").sum())),
            ("dns  (port 53 only)", int((df["app"] == "DNS").sum())),
            ("icmp  (ICMPv4 only)", int((df["transport"] == "ICMP").sum())),
            ("arp", int((df["network"] == "ARP").sum())),
            ("icmpv6", int((df["transport"] == "ICMPv6").sum())),
            ("tls (by TLS record header)", int((df["app"] == "TLS").sum())),
            ("http", int((df["app"] == "HTTP").sum())),
        ], columns=["Wireshark filter", "NetScope count"])
        st.dataframe(wf, hide_index=True, width="stretch")
        st.caption("TLS, HTTP and QUIC are recognised from packet bytes and port numbers, "
                   "so they are good estimates, not certainties.")


# ═══════════════════════════════════════════════════════════════════════════════
# DEVICES & ACTIVITY
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Devices & Activity":
    ui.page_header("Devices & Activity",
                   "Which IP addresses were busiest and which services they used. "
                   "Activity over time is on the Overview page.",
                   "Traffic Analysis")
    st.caption("An IP address is a network address. It may belong to a phone, a laptop, a router or a server, "
               "and NetScope cannot tell which, or who owns it.")

    st.subheader("Busiest IP addresses")
    st.caption("Counted by number of packets. Your own device usually appears near the top.")
    a, b = st.columns(2)
    with a:
        with st.container(border=True):
            show_chart(charts.bar_h(A.top_talkers(df, "src"), "src", "packets", "Top sender IP addresses"))
    with b:
        with st.container(border=True):
            show_chart(charts.bar_h(A.top_talkers(df, "dst"), "dst", "packets",
                                    "Top receiver IP addresses", charts.SERIES[1]))

    activity = A.ip_activity(df).head(15)
    st.caption("Each packet counts once for its sender and once for its receiver, "
               "so the rows below add up to more than the number of packets.")
    st.dataframe(pd.DataFrame({
        "IP address": activity["ip"],
        "Packets sent": activity["packets_sent"],
        "Data sent": activity["bytes_sent"].apply(A.format_bytes),
        "Packets received": activity["packets_received"],
        "Data received": activity["bytes_received"].apply(A.format_bytes),
    }), hide_index=True, width="stretch")

    st.subheader("Most active pairs of addresses")
    st.caption("Each row is two IP addresses that exchanged packets. Traffic in both directions is added "
               "together. The Communication Map page shows the direction.")
    pairs = A.conversations(df).head(15)
    st.dataframe(pd.DataFrame({
        "IP address A": pairs["a"],
        "IP address B": pairs["b"],
        "Packets": pairs["packets"],
        "Data": pairs["bytes"].apply(A.format_bytes),
    }), hide_index=True, width="stretch")

    st.subheader("Services being used")
    st.caption("A port number tells a device which program should receive the data. "
               "443 = secure web (HTTPS), 53 = website lookups (DNS), 80 = plain web (HTTP).")
    ports = A.top_ports(df, "dport", 10).copy()
    ports["port"] = ports["port"].apply(A.label_port)
    with st.container(border=True):
        show_chart(charts.bar_h(ports, "port", "packets", "Most used receiver ports", charts.SERIES[3]))

    st.subheader("Packet sizes")
    st.caption("Small packets (under 100 bytes) are usually control messages. "
               "Packets near 1,500 bytes are usually real data, because that is the normal "
               "maximum size on Ethernet.")
    with st.container(border=True):
        show_chart(charts.histogram(A.length_histogram(df)))


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSITE LOOKUPS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Website Lookups":
    ui.page_header("Website Lookups",
                   "Before a device connects to a name like google.com, it asks a DNS server "
                   "\"what is the IP address for this name?\". Those questions and answers are shown here.",
                   "DNS Analysis")
    st.caption("A lookup only shows that a device asked about a name. "
               "It does not prove that a website was opened or viewed.")
    with st.expander("How a name becomes an IP address"):
        for title, text in guide.DNS_STEPS:
            st.markdown(f"**{title}**  \n{text}")

    ds = A.dns_summary(dns)
    if not ds["available"]:
        st.info("No standard DNS lookups (port 53) were found in this capture. "
                "The lookups may have been filtered out before saving, or the capture was very short. "
                "Local lookups (mDNS) appear on the Types of Traffic page.")
    else:
        repeated = int((A.dns_domains(dns, 10 ** 6)["queries"] >= 2).sum())
        rtt = ds["rtt_median_ms"]
        cols = st.columns(3)
        ui.metric_card(cols[0], "Lookups Sent", f"{ds['queries']:,}",
                       "The number of DNS requests identified in the capture. "
                       "DNS is used to resolve domain names into IP addresses.")
        ui.metric_card(cols[1], "Answers Received", f"{ds['responses']:,}", "Replies received from DNS servers.")
        ui.metric_card(cols[2], "Failed Lookups", f"{ds['failed']:,}",
                       "Replies that reported an error, for example 'name does not exist'.")
        cols = st.columns(3)
        ui.metric_card(cols[0], "Unanswered Lookups", f"{ds['unanswered']:,}",
                       "Questions with no matching answer inside this capture.")
        ui.metric_card(cols[1], "Typical Reply Time", f"{rtt:.1f} ms" if rtt is not None else "Not available",
                       "Median time between a question and its matching answer. "
                       "Not available when no question and answer pair is inside the capture.")
        ui.metric_card(cols[2], "Repeated Names", f"{repeated:,}",
                       "Names that were asked about more than once.")

        st.subheader("DNS servers used")
        st.caption("A DNS server is the computer that answers the lookups.")
        st.code("\n".join(ds["servers"]), language=None)

        a, b = st.columns(2)
        with a:
            st.subheader("Most looked-up names")
            names = A.dns_domains(dns, 12).assign(label=lambda d: d["qname"] + " (" + d["qtype"] + ")")
            with st.container(border=True):
                show_chart(charts.bar_h(names, "label", "queries", "Names asked about", x_title="Lookups"))
        with b:
            st.subheader("Kinds of lookup")
            st.caption("**A** = IPv4 address · **AAAA** = IPv6 address · **CNAME** = alias for another name · "
                       "**PTR** = find the name for an IP address · **HTTPS** = service details")
            with st.container(border=True):
                show_chart(charts.protocol_donut(
                    A.dns_types(dns).rename(columns={"type": "protocol", "queries": "packets"}),
                    "Lookup types"))

        st.subheader("Answer status")
        status = dns[dns["is_response"]]["rcode"].value_counts().rename_axis("Result").reset_index(name="Answers")
        status["What it means"] = status["Result"].map(lambda rc: A.DNS_RCODE_EXPLANATIONS.get(rc, ""))
        st.dataframe(status, hide_index=True, width="stretch")

        failed = dns[dns["is_response"] & (dns["rcode"] != "NOERROR")]
        if len(failed):
            st.subheader("Failed lookups")
            st.dataframe(
                failed[["no", "qname", "qtype", "rcode", "src"]].rename(
                    columns={"no": "Packet No.", "qname": "Name", "qtype": "Type",
                             "rcode": "Result", "src": "DNS Server"}),
                hide_index=True, width="stretch")
            st.caption("A failed lookup for a local address (like 192.168.x.x) is usually normal: "
                       "it just means no name was registered for it.")

        st.subheader("Answers received")
        st.caption("Each row is one answer. The last column shows the IP address the server gave back.")
        st.dataframe(A.dns_answers(dns, 200), hide_index=True, width="stretch")


# ═══════════════════════════════════════════════════════════════════════════════
# BROWSE PACKETS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Browse Packets":
    ui.page_header("Browse Packets",
                   "Look at the packets one by one. Filter the list, then click a row to see its details.",
                   "Packet Explorer")

    f1, f2 = st.columns(2)
    protos = f1.multiselect("Type of traffic", sorted(df["protocol"].unique()),
                            format_func=A.protocol_label,
                            help="Show only these types of traffic.")
    ipq = f2.text_input("IP address contains", placeholder="e.g. 192.168.1",
                        help="Matches packets where the sender OR the receiver address contains this text.")
    f3, f4 = st.columns(2)
    port = f3.text_input("Port", placeholder="e.g. 443",
                         help="Show packets that use this port number (sender or receiver).")
    text = f4.text_input("Search the packet description", placeholder="e.g. SYN or google.com",
                         help="Searches the description column, not the packet contents.")

    v = df
    if protos:
        v = v[v["protocol"].isin(protos)]
    if ipq:
        v = v[v["src"].str.contains(ipq, regex=False) | v["dst"].str.contains(ipq, regex=False)]
    if port.strip().isdigit():
        p = int(port)
        v = v[(v["sport"] == p) | (v["dport"] == p)]
    elif port.strip():
        st.warning("Port must be a whole number, for example 443.")
    if text:
        v = v[v["info"].str.contains(text, case=False, regex=False)]

    message = f"**{len(v):,}** of {len(df):,} packets match."
    if len(v) > 5000:
        message += " Showing the first 5,000. The CSV download has all of them."
    st.write(message)

    if len(v) == 0:
        st.info("No packets match these filters. Try removing one.")
    else:
        shown = v.head(5000).reset_index(drop=True)
        table = pd.DataFrame({
            "No.": shown["no"],
            "Time (UTC)": pd.to_datetime(shown["time"], unit="s", utc=True).dt.strftime("%H:%M:%S.%f").str[:-3],
            "Source": shown["src"],
            "Destination": shown["dst"],
            "Protocol": shown["protocol"],
            "Length": shown["length"],
            "Info": shown["info"],
        })
        # The key changes when the filters or the capture change, so an old row selection is dropped.
        filter_text = repr((protos, ipq, port, text))
        table_key = "packets_" + hashlib.md5((cap.fingerprint + filter_text).encode()).hexdigest()[:10]
        event = st.dataframe(table, hide_index=True, width="stretch", height=420,
                             on_select="rerun", selection_mode="single-row", key=table_key,
                             column_config={"No.": st.column_config.NumberColumn(width="small"),
                                            "Length": st.column_config.NumberColumn("Length (bytes)", width="small")})

        picked = event.selection.rows
        if picked and picked[0] < len(shown):
            packet = shown.iloc[picked[0]]
            details = A.packet_detail(packet)
            with st.container(border=True):
                st.subheader(f"Packet number {int(packet['no'])}")
                left, right = st.columns(2)
                with left:
                    show_ip("Sender IP Address", details["Sender IP Address"])
                with right:
                    show_ip("Receiver IP Address", details["Receiver IP Address"])
                for label, value in details.items():
                    if label not in ("Sender IP Address", "Receiver IP Address"):
                        st.markdown(f"**{label}:** {value}")
                st.caption("Description")
                st.code(packet["info"], language=None)

                if not dns.empty:
                    message = dns[dns["no"] == int(packet["no"])]
                    if not message.empty:
                        m = message.iloc[0]
                        st.markdown("**DNS details**")
                        st.dataframe(pd.DataFrame([
                            ("Message", "Answer" if m["is_response"] else "Question"),
                            ("Name", m["qname"]),
                            ("Record type", m["qtype"]),
                            ("Result", m["rcode"] if m["is_response"] else "(a question has no result)"),
                            ("Answers", m["answers"] or "none"),
                        ], columns=["Field", "Value"]), hide_index=True, width="stretch")

                with st.expander("More technical details"):
                    st.markdown(
                        f"- **Network layer:** {packet['network']} — {A.protocol_description(packet['network'])}\n"
                        f"- **Transport layer:** {packet['transport'] or 'none'} — "
                        f"{A.protocol_description(packet['transport']) or 'not used by this packet'}\n"
                        f"- **Application layer:** {packet['app'] or 'none identified'}\n"
                        f"- **Seconds since capture started:** {packet['rel_time']:.6f}"
                    )
        else:
            st.info("Click a row in the table to see the details of that packet.")

    export_columns = ["no", "src", "dst", "network", "transport", "app",
                      "protocol", "sport", "dport", "length", "tcp_flags", "info"]
    export = v[export_columns].copy()
    export.insert(1, "timestamp_utc", pd.to_datetime(v["time"], unit="s", utc=True).astype(str))
    st.download_button("Download these packets as CSV", export.to_csv(index=False).encode("utf-8"),
                       "netscope_packets.csv", "text/csv",
                       help="Downloads every packet that matches the filters, not just the 5,000 shown.")


# ═══════════════════════════════════════════════════════════════════════════════
# UNUSUAL ACTIVITY
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Unusual Activity":
    n_checks = len(rules.rules_table())
    ui.page_header("Unusual Activity",
                   f"NetScope checks the capture against {n_checks} simple rules. A match is something "
                   "worth a second look, not proof of an attack.",
                   "Security Insights")

    counts = {label: sum(guide.SEVERITY_LABEL[a.severity] == label for a in alerts)
              for label in guide.SEVERITY_MEANING}
    cols = st.columns(3)
    for col, (label, meaning) in zip(cols, guide.SEVERITY_MEANING.items()):
        ui.metric_card(col, label, f"{counts[label]:,}", f"{label}: {meaning}.")

    if not alerts:
        st.success(f"None of the {n_checks} checks found anything unusual in this capture.")
    else:
        st.write("Click an item to see the details.")
    for a in alerts:
        label = guide.SEVERITY_LABEL[a.severity]
        with st.expander(f":{guide.SEVERITY_COLOUR[a.severity]}[**{label}**] {a.title}", expanded=False):
            st.markdown("**What was detected**")
            st.write(a.explanation)
            st.markdown("**Why it may be worth investigating**")
            st.write(guide.RULE_WHY.get(a.rule, "It differs from the usual pattern in this capture."))
            st.markdown("**Evidence from the capture**")
            st.dataframe(pd.DataFrame(list(a.evidence.items()), columns=["Detail", "Value"]),
                         hide_index=True, width="stretch")
            st.markdown("**Why this is not necessarily malicious**")
            st.write(a.caveat)

    st.caption("NetScope only sees what was captured, so a missing reply may simply be outside the capture. "
               "These checks are not an intrusion detection system.")

    with st.expander("How each check works"):
        st.caption("These are the exact conditions. The limits can be changed in `rules.py`.")
        st.dataframe(rules.rules_table().rename(columns={"Rule": "Check", "Fires when": "Flagged when"}),
                     hide_index=True, width="stretch")
        if capture_hosts:
            st.caption(f"The likely capture device ({', '.join(capture_hosts)}) is left out of the "
                       "'busy sender' check, because the recording computer is in nearly every packet.")


# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Performance":
    ui.page_header("Performance",
                   "Timing that can be measured from packet timestamps. When something cannot be measured "
                   "reliably, it says Not available instead of showing a guess.",
                   "Performance Indicators")

    ts = A.timing_summary(df)
    handshakes = A.tcp_handshakes(df)
    tcp = A.tcp_indicators(df)
    ds = A.dns_summary(dns)
    dns_rtt = ds["rtt_median_ms"] if ds["available"] else None

    c1, c2, c3 = st.columns(3)
    status_card(
        c1, "TCP connection set-up", len(handshakes) > 0,
        "Time between a connection request (SYN) and the server's reply (SYN-ACK).",
        [("Typical set-up time", f"{handshakes['ms'].median():.1f} ms" if len(handshakes) else "",
          "Median over the connections measured."),
         ("Slowest set-up", f"{handshakes['ms'].max():.1f} ms" if len(handshakes) else "", ""),
         ("Connections measured", f"{len(handshakes):,}", "Connections whose SYN and SYN-ACK are both in the capture.")],
        "No connection set-up (a SYN followed by its SYN-ACK) is fully inside this capture.")
    status_card(
        c2, "DNS reply time", dns_rtt is not None,
        "Time between a DNS question and its matching answer.",
        [("Typical reply time", f"{dns_rtt:.1f} ms" if dns_rtt is not None else "", "Median over matched pairs."),
         ("Slowest reply", f"{ds['rtt_max_ms']:.1f} ms" if dns_rtt is not None else "", ""),
         ("Pairs measured", f"{ds['queries'] - ds['unanswered']:,}" if ds["available"] else "",
          "DNS questions whose answer is also in the capture.")],
        "No DNS question and answer pair was found in this capture.")
    peak_ratio = ts["peak_packets"] / ts["mean_packets"] if ts["mean_packets"] else 0
    status_card(
        c3, "Traffic bursts", ts["buckets"] > 1,
        f"Busiest {ts['bucket_s']}-second period compared with the average period.",
        [("Busiest period", f"{ts['peak_packets']:,} packets", f"Starts {ts['peak_at_s']} s after the capture began."),
         ("Average period", f"{ts['mean_packets']:.1f} packets", ""),
         ("Busiest vs average", f"{peak_ratio:.1f}x", "A burst is normal for downloads and page loads.")],
        "The capture is too short to compare time periods.")

    c4, c5 = st.columns(2)
    status_card(
        c4, "Packet timing", ts["median_gap_ms"] is not None,
        "Gaps between one packet and the next, from the packet timestamps.",
        [("Typical gap between packets", f"{ts['median_gap_ms']:.2f} ms" if ts["median_gap_ms"] is not None else "", ""),
         ("Longest quiet period", f"{ts['longest_gap_s']:.2f} s" if ts["longest_gap_s"] is not None else "",
          "The longest time with no packets at all.")],
        "At least two packets are needed to measure gaps.")
    status_card(
        c5, "TCP warning signs", tcp["syn"] > 0 or tcp["resets"] > 0,
        "Signals that a connection may not have gone smoothly. They are hints, not proof of a problem.",
        [("Connection requests without a reply", f"{tcp['unanswered']:,} of {tcp['syn']:,}",
          "A SYN with no SYN-ACK in the capture. The reply may simply be outside the capture."),
         ("Reset (RST) packets", f"{tcp['resets']:,}", "A reset ends a TCP connection abruptly. A few are normal.")],
        "This capture has no TCP connection requests or resets.")

    if len(handshakes):
        st.subheader("Slowest TCP connection set-ups")
        st.dataframe(pd.DataFrame({
            "Client": handshakes["client"], "Server": handshakes["server"], "Port": handshakes["port"],
            "Set-up time (ms)": handshakes["ms"].round(2),
        }).sort_values("Set-up time (ms)", ascending=False).head(10), hide_index=True, width="stretch")

    with st.container(border=True):
        st.markdown("**What NetScope does not measure**")
        st.markdown(
            "- **TCP retransmissions and packet loss:** these need TCP sequence numbers, which NetScope does not read. "
            "In Wireshark use the filter `tcp.analysis.retransmission`.\n"
            "- **Website or application delay:** encrypted (HTTPS) content cannot be matched into requests and responses.\n"
            "- **Throughput or bandwidth:** a capture shows what was recorded, not how fast the connection could have been."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# COMMUNICATION MAP
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Communication Map":
    ui.page_header("Communication Map",
                   "Each dot is an IP address. Each arrow points from the sender to the receiver.",
                   "Who Talks to Whom")

    flows = A.directed_flows(df)
    if flows.empty:
        st.info("No IP conversations to draw. The capture may contain only ARP or other non-IP packets.")
    else:
        max_n = min(30, len(flows))
        if max_n > 3:
            top_n = st.slider("Number of busiest connections to show", 3, max_n, min(12, max_n),
                              help="Each connection is one sender → one receiver. "
                                   "Fewer connections make the map easier to read.")
        else:
            top_n = max_n
        shown = flows.head(top_n)

        map_col, panel_col = st.columns([2.2, 1])
        with map_col:
            with st.container(border=True):
                show_chart(charts.comm_map(flows, top_n, highlight_nodes=set(capture_hosts)))
            st.caption(f"Showing the {top_n} busiest of {len(flows):,} sender → receiver connections, ranked by data. "
                       "Only IP packets are drawn. The map does not show locations or device names.")
        with panel_col:
            with st.container(border=True):
                st.markdown("**Inspect an IP address**")
                volume = pd.concat([shown.groupby("src")["bytes"].sum(), shown.groupby("dst")["bytes"].sum()]) \
                           .groupby(level=0).sum().sort_values(ascending=False)
                chosen = st.selectbox("IP address", list(volume.index), label_visibility="collapsed")
                activity = A.ip_activity(df).set_index("ip").loc[chosen]
                st.code(chosen, language=None)
                if chosen in capture_hosts:
                    st.caption("Likely the computer that recorded this capture (estimate).")
                st.metric("Packets sent", f"{int(activity['packets_sent']):,}",
                          help=f"{A.format_bytes(int(activity['bytes_sent']))} sent")
                st.metric("Packets received", f"{int(activity['packets_received']):,}",
                          help=f"{A.format_bytes(int(activity['bytes_received']))} received")
                peers = shown[(shown["src"] == chosen) | (shown["dst"] == chosen)].head(6)
                st.caption("Connections shown for this address")
                st.dataframe(pd.DataFrame({
                    "Direction": ["sends to" if s == chosen else "receives from" for s in peers["src"]],
                    "Other IP": [d if s == chosen else s for s, d in zip(peers["src"], peers["dst"])],
                    "Data": peers["bytes"].apply(A.format_bytes),
                }), hide_index=True, width="stretch")

        with st.expander("How to read this map"):
            st.markdown(
                "- **Dot** = one IP address. A bigger dot sent and received more data.\n"
                "- **Arrow** = packets sent from one IP address to another. The arrow points at the receiver.\n"
                "- **Thicker arrow** = more data in that direction.\n"
                "- **Arrow colour** = the protocol with the most packets in that direction.\n"
                "- **Green dot** = the likely capture device (an estimate). **White dot** = any other address.\n"
                "- **Hover** over a dot or the middle of an arrow for exact numbers and the protocols seen."
            )

        with st.expander("Connections shown (copyable table)"):
            st.dataframe(
                pd.DataFrame({
                    "Sender IP": shown["src"],
                    "Receiver IP": shown["dst"],
                    "Packets": shown["packets"],
                    "Data": shown["bytes"].apply(A.format_bytes),
                    "Protocols seen": shown["protocols"],
                }),
                hide_index=True, width="stretch")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Reports":
    ui.page_header("Reports",
                   "Save the results of this capture to use in a spreadsheet or a project report.")

    with st.container(border=True):
        st.subheader("PDF report")
        st.caption("A short written report for this capture.")
        st.markdown("**Includes:** capture details, protocol statistics by layer, busiest IP addresses and pairs, "
                    "a traffic chart, website lookups, the unusual-activity findings and the limits of the analysis.")
        if st.button("Create PDF report", type="primary"):
            with st.spinner("Building the PDF… this takes a few seconds."):
                # The PDF is stored together with the fingerprint of the capture it was made from.
                st.session_state["pdf_report"] = {"capture": cap.fingerprint,
                                                  "bytes": build_pdf(cap, alerts)}
        report = st.session_state.get("pdf_report")
        if report and report["capture"] == cap.fingerprint:
            st.success("The PDF is ready.")
            st.download_button("Download PDF", report["bytes"], "netscope_report.pdf", "application/pdf")
        elif report:
            st.info("The PDF you made earlier belongs to a different capture. Create a new one for this file.")

    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.subheader("All packets (CSV)")
            st.caption(f"{len(df):,} rows, {len(df.columns)} columns: time, sender and receiver IP, protocol, "
                       "ports and size. Opens in Excel or Google Sheets.")
            st.download_button("Download CSV", df.to_csv(index=False).encode("utf-8"),
                               "netscope_all_packets.csv", "text/csv")
            st.caption("To export only some packets, filter them on Browse Packets and download from there.")
    with right:
        with st.container(border=True):
            st.subheader("Website lookups (CSV)")
            if dns.empty:
                st.caption("Not available: no standard DNS lookups (port 53) were found in this capture.")
            else:
                st.caption(f"{len(dns):,} DNS questions and answers: name, record type, result and the "
                           "addresses returned.")
                st.download_button("Download DNS CSV", dns.to_csv(index=False).encode("utf-8"),
                                   "netscope_dns.csv", "text/csv")

    st.caption("Everything exported comes from the capture that is loaded now. Nothing is stored on the server.")
