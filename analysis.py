"""
analysis.py — Calculates statistics and summaries from the packet table.

All functions here take a pandas DataFrame (from parser.py) and return
either a number, a string, or another DataFrame ready to display.

No Streamlit or chart code lives here, so these functions can be tested
independently without running the app.
"""

import math
import pandas as pd


# ── Protocol explanations (shown as tooltips and captions in the app) ─────────

PROTOCOL_EXPLANATIONS = {
    "TCP":    "Transmission Control Protocol — delivers data reliably, in order. Used for web, email, SSH.",
    "UDP":    "User Datagram Protocol — fast, connectionless. Used for DNS, streaming, games.",
    "DNS":    "Domain Name System — translates names like google.com into IP addresses.",
    "TLS":    "Transport Layer Security — encrypts data inside TCP connections (HTTPS, etc.).",
    "HTTP":   "HyperText Transfer Protocol — plain-text web traffic (not encrypted).",
    "QUIC":   "Quick UDP Internet Connections — Google's encrypted HTTP/3 transport.",
    "ICMP":   "Internet Control Message Protocol — network diagnostics (ping, traceroute).",
    "ICMPv6": "ICMP for IPv6 — also handles Neighbor Discovery between IPv6 devices.",
    "ARP":    "Address Resolution Protocol — finds the hardware (MAC) address for an IPv4 address.",
    "IPv4":   "Internet Protocol version 4 — 32-bit address (e.g. 192.168.1.1).",
    "IPv6":   "Internet Protocol version 6 — 128-bit address, the successor to IPv4.",
    "mDNS":   "Multicast DNS — name lookups on local networks, no central server needed.",
    "LLMNR":  "Link-Local Multicast Name Resolution — Windows name resolution on local networks.",
    "NBNS":   "NetBIOS Name Service — older Windows name resolution.",
    "NTP":    "Network Time Protocol — keeps device clocks synchronised.",
    "DHCP":   "Dynamic Host Configuration Protocol — automatically assigns IP addresses.",
}

# ── Plain-English names (one shared table used by every page) ─────────────────
# protocol -> (friendly name, one-sentence description)
# The technical name is always kept and shown next to the friendly name.

PROTOCOL_INFO = {
    "TCP":    ("Reliable Data Communication", "Delivers data in order and checks that it arrived. Used for web pages, email and file transfers."),
    "UDP":    ("Faster Data Communication", "Sends data quickly without checking that it arrived. Used for lookups, video calls and games."),
    "DNS":    ("Website Address Lookup", "Turns a name like google.com into an IP address."),
    "TLS":    ("Encrypted Connection", "Scrambles data so others cannot read it (this is what HTTPS uses)."),
    "HTTP":   ("Unencrypted Web Traffic", "Web traffic that is not encrypted, so it could be read on the network."),
    "QUIC":   ("Fast Encrypted Web Traffic", "A newer encrypted way of loading web pages, used by browsers such as Chrome."),
    "ICMP":   ("Network Connectivity Messages", "Error and test messages, such as the ones sent by the ping command."),
    "ICMPv6": ("Network Connectivity Messages (IPv6)", "The IPv6 version of connectivity messages. Also used to find nearby devices."),
    "ARP":    ("Finding Devices on a Local Network", "Asks which device owns an IP address on the local network."),
    "IPv4":   ("Internet Addressing (Version 4)", "The older, most common IP address format, like 192.168.1.5."),
    "IPv6":   ("Internet Addressing (Version 6)", "The newer, longer IP address format."),
    "mDNS":   ("Local Name Lookup", "Devices on the same network find each other by name."),
    "LLMNR":  ("Local Windows Name Lookup", "Windows computers find each other by name on a local network."),
    "NBNS":   ("Older Windows Name Lookup", "An older way for Windows computers to find each other by name."),
    "NTP":    ("Clock Synchronisation", "Keeps the clock of a device correct."),
    "DHCP":   ("Automatic Address Assignment", "Gives a device its IP address when it joins a network."),
    "No transport layer": ("No Transport Layer", "Packets that are not carried by TCP or UDP, such as ARP."),
    "None identified":    ("No Specific Application Found", "Packets where NetScope could not tell which application sent them."),
    "Other":  ("Other Traffic", "Packets of a type NetScope does not describe."),
}


def friendly_name(protocol):
    """'TCP' -> 'Reliable Data Communication'. Unknown names are returned unchanged."""
    return PROTOCOL_INFO.get(protocol, (protocol, ""))[0]


def protocol_label(protocol):
    """'TCP' -> 'Reliable Data Communication (TCP)'. The technical name is kept."""
    name = friendly_name(protocol)
    return protocol if name == protocol else f"{name} ({protocol})"


def protocol_description(protocol):
    """One short sentence explaining the protocol ('' if we have none)."""
    return PROTOCOL_INFO.get(protocol, ("", ""))[1]


# DNS response codes → plain English explanation
DNS_RCODE_EXPLANATIONS = {
    "NOERROR":  "Success — the domain was found.",
    "NXDOMAIN": "Non-Existent Domain — this name does not exist in DNS.",
    "SERVFAIL": "Server Failure — the DNS server could not complete the request.",
    "REFUSED":  "Refused — the DNS server declined to answer.",
    "FORMERR":  "Format Error — the query was malformed.",
    "NOTIMP":   "Not Implemented — the server does not support this query type.",
}

# Common port numbers → service names (used to label port charts)
WELL_KNOWN_PORTS = {
    20: "FTP-Data",   21: "FTP",       22: "SSH",        23: "Telnet",
    25: "SMTP",       53: "DNS",       67: "DHCP",       68: "DHCP",
    80: "HTTP",      110: "POP3",     123: "NTP",       143: "IMAP",
   161: "SNMP",     443: "HTTPS",    445: "SMB",       465: "SMTPS",
   587: "SMTP",     993: "IMAPS",    995: "POP3S",    1194: "OpenVPN",
  1433: "MSSQL",   3306: "MySQL",   3389: "RDP",      5353: "mDNS",
  5355: "LLMNR",   8080: "HTTP-Alt",8443: "HTTPS-Alt",
}


# ── Overview statistics ───────────────────────────────────────────────────────

def overview(df):
    """Return the key headline numbers for the capture."""
    ip_df = df[df["network"].isin(["IPv4", "IPv6"])]
    return {
        "packets":    len(df),
        "bytes":      int(df["length"].sum()),
        "duration":   float(df["time"].max() - df["time"].min()),
        "unique_src": ip_df["src"].nunique(),
        "unique_dst": ip_df["dst"].nunique(),
        "unique_ips": len(set(ip_df["src"]) | set(ip_df["dst"])),
        "start":      float(df["time"].min()),
        "end":        float(df["time"].max()),
    }


def format_bytes(n):
    """Convert a byte count to a human-readable string like '1.23 MB'."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.2f} {unit}"
        n /= 1024
    return f"{n:.2f} GB"


def label_port(port_str):
    """
    Add a service name to a port string.
    Example: '443/tcp' → '443/tcp (HTTPS)'
    """
    try:
        num = int(port_str.split("/")[0])
        name = WELL_KNOWN_PORTS.get(num)
        return f"{port_str} ({name})" if name else port_str
    except Exception:
        return port_str


# ── Protocol layer tables ─────────────────────────────────────────────────────

def layer_tables(df):
    """
    Count packets by protocol at each layer (network, transport, application).

    Important: one packet belongs to all three layers at once.
    A TLS packet is also a TCP packet and an IPv4/IPv6 packet.
    So the three tables overlap — never add them together.
    Each table's percentages add up to 100% on their own.

    Returns a dict: {'Network layer': DataFrame, 'Transport layer': ..., 'Application layer': ...}
    """
    total = len(df)

    def make_table(counts, label_col):
        out = counts.rename("packets").reset_index()
        out.columns = [label_col, "packets"]
        out["percent"] = (out["packets"] / total * 100).round(2)
        return out

    net   = df["network"].value_counts()
    trans = df["transport"].replace("", "No transport layer").value_counts()
    app   = df["app"].replace("", "None identified").value_counts()

    return {
        "Network layer":     make_table(net,   "protocol"),
        "Transport layer":   make_table(trans, "protocol"),
        "Application layer": make_table(app,   "protocol"),
    }


# ── Traffic statistics ────────────────────────────────────────────────────────

def top_talkers(df, column, n=10):
    """
    Return the top N IP addresses by packet count.
    column is either 'src' (senders) or 'dst' (receivers).
    """
    ip_df = df[df["network"].isin(["IPv4", "IPv6"])]
    g = ip_df.groupby(column).agg(packets=("no", "count"), bytes=("length", "sum"))
    return g.sort_values("packets", ascending=False).head(n).reset_index()


def top_ports(df, column, n=10):
    """
    Return the top N ports by packet count.
    column is either 'sport' (source ports) or 'dport' (destination ports).
    """
    sub = df[df[column].notna()]
    out = sub.groupby([column, "transport"]).size().rename("packets").reset_index()
    out = out.sort_values("packets", ascending=False).head(n)
    out[column] = out[column].astype(int).astype(str) + "/" + out["transport"].str.lower()
    return out[[column, "packets"]].rename(columns={column: "port"})


def conversations(df):
    """
    Return the top IP address pairs that exchanged the most data.
    Direction is ignored — A→B and B→A are counted together.
    """
    ip_df = df[df["network"].isin(["IPv4", "IPv6"])].copy()
    # Sort each pair alphabetically so A↔B and B↔A become the same pair
    pairs = ip_df[["src", "dst"]].apply(lambda r: tuple(sorted(r)), axis=1)
    ip_df["a"] = pairs.str[0]
    ip_df["b"] = pairs.str[1]
    g = ip_df.groupby(["a", "b"]).agg(packets=("no", "count"), bytes=("length", "sum"))
    return g.sort_values("bytes", ascending=False).reset_index()


def directed_flows(df):
    """
    One row per direction: Sender IP -> Receiver IP.
    A -> B and B -> A are separate rows, so you can see who sent the data.
    Columns: src, dst, packets, bytes, protocols (the protocols actually seen),
    main_protocol (the protocol with the most packets in that direction).
    """
    ip_df = df[df["network"].isin(["IPv4", "IPv6"]) & (df["src"] != df["dst"])]
    if ip_df.empty:
        return pd.DataFrame(columns=["src", "dst", "packets", "bytes", "protocols", "main_protocol"])
    g = ip_df.groupby(["src", "dst"]).agg(
        packets=("no", "count"),
        bytes=("length", "sum"),
        protocols=("protocol", lambda s: ", ".join(sorted(set(s)))),
        main_protocol=("protocol", lambda s: s.value_counts().idxmax()),
    )
    return g.sort_values("bytes", ascending=False).reset_index()


def packet_detail(row):
    """
    Turn one packet row into (label, value) pairs for the detail panel.
    Ports and TCP flags are only included when the packet has them.
    """
    seconds = pd.to_datetime(row["time"], unit="s", utc=True)
    out = {
        "Time (UTC)": seconds.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "Sender IP Address": row["src"],
        "Receiver IP Address": row["dst"],
        "Type of traffic": protocol_label(row["protocol"]),
        "Packet size": f"{int(row['length']):,} bytes",
    }
    if pd.notna(row["sport"]):
        out["Sender port"] = str(int(row["sport"]))
        out["Receiver port"] = str(int(row["dport"]))
    if row["tcp_flags"]:
        out["TCP flags"] = row["tcp_flags"]
    return out


def traffic_over_time(df, buckets=60):
    """
    Group packets into time buckets to show how busy the network was over time.
    Returns (table with 'seconds', 'packets', 'bytes' columns,  bucket_width_in_seconds).
    """
    duration = df["rel_time"].max()
    width = max(1, math.ceil(duration / buckets)) if duration > 0 else 1
    b = (df["rel_time"] // width * width).astype(int)
    out = df.groupby(b).agg(packets=("no", "count"), bytes=("length", "sum"))
    # Fill in quiet seconds with zero (they really had no packets)
    full_index = pd.RangeIndex(0, int(b.max()) + width, width)
    out = out.reindex(full_index, fill_value=0)
    out.index.name = "seconds"
    return out.reset_index(), width


def length_histogram(df, bin_size=100):
    """
    Count packets by size bucket (0–99 bytes, 100–199 bytes, etc.)
    Returns a DataFrame with 'range' and 'packets' columns.
    """
    b = (df["length"] // bin_size * bin_size).astype(int)
    out = b.value_counts().sort_index().rename("packets").reset_index()
    out.columns = ["start", "packets"]
    out["range"] = out["start"].astype(str) + "–" + (out["start"] + bin_size - 1).astype(str)
    return out


def ip_activity(df):
    """
    One row per IP address: packets and bytes it sent, packets and bytes it received,
    and the totals. A packet counts once for its sender and once for its receiver,
    so the totals of different rows must not be added together.
    """
    ip_df = df[df["network"].isin(["IPv4", "IPv6"])]
    sent = ip_df.groupby("src").agg(packets_sent=("no", "count"), bytes_sent=("length", "sum"))
    recv = ip_df.groupby("dst").agg(packets_received=("no", "count"), bytes_received=("length", "sum"))
    out = sent.join(recv, how="outer").fillna(0).astype(int)
    out["packets"] = out["packets_sent"] + out["packets_received"]
    out["bytes"] = out["bytes_sent"] + out["bytes_received"]
    out.index.name = "ip"
    return out.sort_values(["packets", "bytes"], ascending=False).reset_index()


def protocol_counts(df):
    """
    Packet counts for the protocols the Types of Traffic page explains.

    These counts OVERLAP: a DNS packet is also a UDP packet and an HTTPS packet is
    also a TCP packet. HTTPS is counted from TLS record headers (the content is
    encrypted and is never read), so it is an estimate.
    Returns a list of (protocol, packets, percent of all packets).
    """
    total = max(len(df), 1)
    counts = {
        "TCP":   int((df["transport"] == "TCP").sum()),
        "UDP":   int((df["transport"] == "UDP").sum()),
        "DNS":   int((df["app"] == "DNS").sum()),
        "ARP":   int((df["network"] == "ARP").sum()),
        "ICMP":  int((df["transport"] == "ICMP").sum()),
        "HTTP":  int((df["app"] == "HTTP").sum()),
        "HTTPS": int((df["app"] == "TLS").sum()),
    }
    return [(name, n, round(n / total * 100, 2)) for name, n in counts.items()]


# ── Timing (only what the packet timestamps can really show) ─────────────────

def tcp_handshakes(df):
    """
    Time between a TCP connection request (SYN) and the server's reply (SYN-ACK).

    Only connections whose SYN and SYN-ACK are BOTH inside the capture can be
    measured. Returns a table (client, server, port, ms), possibly empty.
    """
    cols = ["client", "server", "port", "ms"]
    tcp = df[df["transport"] == "TCP"]
    flags = tcp["tcp_flags"].fillna("")
    syn = tcp[flags.str.contains("SYN") & ~flags.str.contains("ACK")]
    synack = tcp[flags.str.contains("SYN") & flags.str.contains("ACK")]
    if syn.empty or synack.empty:
        return pd.DataFrame(columns=cols)
    m = syn.merge(synack, left_on=["src", "dst", "sport", "dport"],
                  right_on=["dst", "src", "dport", "sport"], suffixes=("_syn", "_ack"))
    m["ms"] = (m["time_ack"] - m["time_syn"]) * 1000
    m = m[m["ms"] >= 0].sort_values("ms").drop_duplicates("no_syn")
    return pd.DataFrame({"client": m["src_syn"], "server": m["dst_syn"],
                         "port": m["dport_syn"].astype(int), "ms": m["ms"]}).reset_index(drop=True)


def tcp_indicators(df):
    """Counts of TCP connection requests, how many got a reply in the capture, and resets (RST)."""
    tcp = df[df["transport"] == "TCP"]
    flags = tcp["tcp_flags"].fillna("")
    syn_total = int((flags.str.contains("SYN") & ~flags.str.contains("ACK")).sum())
    answered = len(tcp_handshakes(df))
    return {"syn": syn_total, "answered": answered,
            "unanswered": max(syn_total - answered, 0),
            "resets": int(flags.str.contains("RST").sum())}


def timing_summary(df):
    """Gaps between packets and the busiest time bucket, all taken from packet timestamps."""
    gaps = df["time"].sort_values().diff().dropna()
    table, width = traffic_over_time(df)
    peak = table.loc[table["packets"].idxmax()]
    return {
        "median_gap_ms": float(gaps.median() * 1000) if len(gaps) else None,
        "longest_gap_s": float(gaps.max()) if len(gaps) else None,
        "bucket_s": width,
        "peak_packets": int(peak["packets"]),
        "peak_at_s": int(peak["seconds"]),
        "mean_packets": float(table["packets"].mean()),
        "buckets": len(table),
    }


# ── DNS statistics ────────────────────────────────────────────────────────────

def dns_summary(dns):
    """
    Summarise DNS activity: query counts, response counts, errors, and response times.
    Returns a dict. If no DNS packets were found, returns {'available': False}.
    """
    if dns.empty:
        return {"available": False}

    q = dns[~dns["is_response"]]   # query packets
    r = dns[dns["is_response"]]    # response packets

    # Match each query to its response by client IP, server IP, and DNS transaction ID
    qq = q.assign(client=q["src"], server=q["dst"], cport=q["sport"])
    rr = r.assign(client=r["dst"], server=r["src"], cport=r["dport"])
    matched = qq.merge(rr, on=["client", "server", "cport", "dns_id", "qname", "qtype"],
                       suffixes=("_q", "_r"))
    matched["rtt_ms"] = (matched["time_r"] - matched["time_q"]) * 1000
    matched = matched[matched["rtt_ms"] >= 0].drop_duplicates(subset=["no_q"])

    return {
        "available":    True,
        "queries":      len(q),
        "responses":    len(r),
        "unanswered":   len(q) - len(matched),  # no response seen in this capture
        "failed":       int((r["rcode"] != "NOERROR").sum()),
        "servers":      sorted(set(q["dst"])),
        "rtt_median_ms": float(matched["rtt_ms"].median()) if len(matched) else None,
        "rtt_max_ms":    float(matched["rtt_ms"].max())    if len(matched) else None,
    }


def dns_domains(dns, n=15):
    """Return the most-queried domain names."""
    q = dns[~dns["is_response"]]
    g = q.groupby(["qname", "qtype"]).size().rename("queries").reset_index()
    return g.sort_values("queries", ascending=False).head(n)


def dns_types(dns):
    """Return query type counts (A, AAAA, PTR, etc.)."""
    q = dns[~dns["is_response"]]
    return q["qtype"].value_counts().rename("queries").rename_axis("type").reset_index()


def dns_answers(dns, n=50):
    """Return DNS response rows showing which IP addresses were returned."""
    r = dns[dns["is_response"]]
    return r[["no", "qname", "qtype", "rcode", "src", "answers"]].rename(
        columns={"src": "server"}
    ).head(n)


# ── Auto-generated plain English observations ─────────────────────────────────

def narrative(df, dns, ov):
    """
    Generate 3–6 factual plain English sentences describing what happened in the capture.
    Every sentence comes from real data — nothing is made up.
    Returns a list of strings.
    """
    sentences = []

    # Total packets and duration
    sentences.append(
        f"**{ov['packets']:,} packets** were captured over **{ov['duration']:.1f} seconds**."
    )

    # Dominant transport protocol
    layers = layer_tables(df)
    trans = layers["Transport layer"]
    top = trans.iloc[0] if not trans.empty else None
    if top is not None and top["protocol"] != "No transport layer":
        pct = top["percent"]
        explanation = protocol_description(top["protocol"])
        sentences.append(
            f"**{protocol_label(top['protocol'])}** was the most common type of transport "
            f"({pct:.0f}% of packets). {explanation}"
        )

    # DNS lookups
    if not dns.empty:
        q_count  = int((~dns["is_response"]).sum())
        domains  = dns[~dns["is_response"]]["qname"].nunique()
        sentences.append(
            f"**{q_count} website address lookups (DNS queries)** were made, for **{domains} different names**. "
            "A lookup turns a name like google.com into an IP address."
        )

    # IPv4 vs IPv6
    has_v4 = (df["network"] == "IPv4").any()
    has_v6 = (df["network"] == "IPv6").any()
    if has_v4 and has_v6:
        sentences.append("Both **IPv4** and **IPv6** traffic was present — normal for modern devices.")
    elif has_v6:
        sentences.append("All IP traffic used **IPv6** addressing.")

    # TLS encryption
    tls_count = int((df["app"] == "TLS").sum())
    if tls_count > 0:
        tls_pct = tls_count / max(len(df), 1) * 100
        sentences.append(
            f"**{tls_count:,} packets ({tls_pct:.0f}%)** were **TLS-encrypted** "
            "(HTTPS and other secure connections). The content of these packets is not readable."
        )

    # Unencrypted HTTP (worth flagging)
    http_count = int((df["app"] == "HTTP").sum())
    if http_count > 0:
        sentences.append(
            f"**{http_count:,} unencrypted HTTP packet(s)** were detected. "
            "This traffic can be read by anyone on the same network path."
        )

    # ARP activity
    arp_count = int((df["network"] == "ARP").sum())
    if arp_count > 0:
        sentences.append(
            f"**{arp_count} ARP packets** were observed — devices were looking up "
            "each other's hardware addresses on the local network."
        )

    return sentences
