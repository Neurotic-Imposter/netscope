# NetScope — Viva Preparation & Architecture Guide

A concise reference guide for the **"Network Traffic Analysis Using Wireshark"** lab viva (IT Infrastructure and Communication Lab, JIIT Noida).

---

## Part 1: Project Architecture & Calling Hierarchy

NetScope is divided into 6 modular Python files in a single flat folder. Each file has one clear responsibility.

### File Roles

| File | Lines | Role | Primary Responsibility |
|---|---|---|---|
| `app.py` | 693 | Presentation & Controller | Builds the Streamlit web interface, manages sidebar navigation (8 pages), handles file upload caching, and displays charts/tables. |
| `parser.py` | 296 | Packet Decoding Engine | Uses Scapy (`PcapReader`) to decode binary `.pcap`/`.pcapng` packets into Pandas DataFrames. Only file that touches raw packets. |
| `analysis.py` | 317 | Statistics & Aggregation | Computes metrics (totals, protocol shares, top talkers, time buckets, DNS latency) and generates the plain-English narrative. Zero UI code. |
| `charts.py` | 217 | Plotly Visualization | Converts computed tables into Plotly figures with a clean dark theme. Uses NetworkX to compute coordinates for the communication map. |
| `rules.py` | 250 | Heuristic Security Checks | Checks packet tables against 5 fixed threshold rules (SYN flood, port scan, etc.). Generates `Alert` objects with evidence. |
| `pdf_report.py` | 239 | PDF Report Generator | Uses ReportLab to generate a formal 6-section printable PDF report directly from in-memory metrics. |

### Module Communication & Call Hierarchy

```
app.py (main UI controller)
│
├── calls parser.py
│     └── parse_capture(path, MAX_PACKETS)
│           ├── _describe_packet(pkt, row)
│           ├── _parse_dns_packet(pkt, row)
│           ├── _tcp_flags(tcp)
│           ├── _is_tls(payload)
│           └── _is_http(payload)
│
├── calls analysis.py
│     ├── overview(df)
│     ├── narrative(df, dns, ov)
│     ├── layer_tables(df)
│     ├── top_talkers(df, column, n)
│     ├── top_ports(df, column, n)
│     ├── conversations(df)
│     ├── traffic_over_time(df, buckets)
│     ├── length_histogram(df)
│     ├── dns_summary(dns)
│     ├── dns_domains(dns, n)
│     ├── dns_types(dns)
│     └── dns_answers(dns, n)
│
├── calls rules.py
│     ├── likely_capture_hosts(df)
│     ├── run_all(df, dns)
│     │     ├── connection_rules(df) [checks SYN flood, port scan, connection attempts]
│     │     ├── dominant_source_rule(df) [checks for high volume single IP]
│     │     └── dns_rule(dns) [checks repeated domain lookups]
│     └── rules_table()
│
├── calls charts.py
│     ├── bar_h(df, label, value, title, color)
│     ├── protocol_donut(df, title)
│     ├── time_series(tbl, y, width)
│     ├── histogram(tbl)
│     └── comm_map(conv, max_nodes, highlight_nodes)
│
└── calls pdf_report.py
      └── build_pdf(cap, alerts, project)
            ├── calls analysis.py (overview, layer_tables, top_talkers, conversations, traffic_over_time, dns_summary)
            └── calls rules.py (rules_table)
```

---

## Part 2: Top 20 Viva Questions and Answers

### General & Conceptual Questions

#### Q1: What is NetScope, and why did you build it?
**Answer:**  
Wireshark is an industry-standard tool for capturing raw network packets, but its interface is too technical for beginners. NetScope is an educational companion dashboard. It takes an exported Wireshark file (`.pcap` or `.pcapng`) and turns raw packet data into understandable charts, plain-English observations, and relationship graphs that explain who communicated with whom.

#### Q2: Does NetScope capture packets from your network interface?
**Answer:**  
No. Wireshark handles live packet capture. NetScope is purely an analysis and visualization dashboard that reads the captured file on-demand.

#### Q3: Why did you choose Python and Streamlit?
**Answer:**  
Python has powerful networking and data analysis libraries (`scapy`, `pandas`, `networkx`). Streamlit allows building clean, interactive web dashboards in pure Python without writing HTML, CSS, or JavaScript from scratch.

#### Q4: Why is Pandas used instead of regular Python lists and dictionaries?
**Answer:**  
A capture file can have tens of thousands of packets. Pandas stores this data as a two-dimensional table (DataFrame). It can filter, group, and calculate percentages across thousands of rows in milliseconds, which would require many lines of complex, slower nested loops in standard Python.

---

### Packet Parsing & Networking Questions

#### Q5: How does NetScope read `.pcap` files without Wireshark installed?
**Answer:**  
In `parser.py`, we use Scapy's `PcapReader`. `PcapReader` reads the binary packet headers and payload bytes directly from disk using pure Python. Therefore, NetScope runs on any laptop even if Wireshark is not installed.

#### Q6: What does `parse_capture()` in `parser.py` do?
**Answer:**  
It opens the file, iterates through each packet, and calls `_describe_packet()` to determine source IP, destination IP, ports, protocol layers, and flags. It creates two Pandas DataFrames:
1. `packets`: one row per network packet with 14 columns.
2. `dns`: one row per DNS packet with query names, response codes, and resolved IP addresses.  
It packages them into a `Capture` object.

#### Q7: What are TCP flags, and what does "SYN,ACK" mean?
**Answer:**  
TCP flags are 1-bit control signals inside the TCP header:
- `SYN` (Synchronize): starts a connection request.
- `ACK` (Acknowledge): confirms receipt of data or a request.
- `FIN` (Finish): requests a graceful connection close.
- `RST` (Reset): immediately aborts a connection.  
"SYN,ACK" is the server's reply to an initial SYN packet, representing step 2 of the classic TCP three-way handshake (`SYN` → `SYN,ACK` → `ACK`).

#### Q8: How does NetScope detect TLS (HTTPS) if the traffic is encrypted?
**Answer:**  
In `parser.py`, `_is_tls()` inspects the first 5 bytes of the TCP payload using a heuristic: the first byte must be a TLS content type (20–23) and the second byte must be version 3 (`\x03\x01` to `\x03\x04`). This identifies that a TLS session is taking place without decrypting or reading the private user payload.

#### Q9: Why do protocol percentages in Protocol Analysis not add up to 100% across all sections?
**Answer:**  
Because network protocols are layered inside one another. A single web request packet is simultaneously an IPv4 packet (Network layer), a TCP packet (Transport layer), and a TLS packet (Application layer). Adding them together would count the same packet three times. NetScope separates them into 3 distinct tables, and each layer sums to 100% independently.

#### Q10: What is the difference between TCP and UDP in this capture?
**Answer:**  
TCP is connection-oriented and reliable — it ensures packets arrive in order and retransmits lost packets (used for web browsing, email, file transfers). UDP is connectionless and faster — it sends packets without handshakes or delivery guarantees (used for DNS lookups, video streaming, and online gaming). NetScope shows this distribution on the Overview and Protocol Analysis pages.

---

### Analysis & Algorithms Questions

#### Q11: How does `conversations()` in `analysis.py` combine two-way traffic?
**Answer:**  
If Device A sends packets to Device B, and Device B replies to Device A, they are having one conversation. In `conversations()`, we sort each pair of IP addresses alphabetically using `tuple(sorted((src, dst)))`. This ensures both `A → B` and `B → A` become the same pair `(A, B)`. Then Pandas `groupby()` sums all packets and bytes between them.

#### Q12: How does `dns_summary()` calculate DNS response time (latency)?
**Answer:**  
It performs an inner merge between the DNS query packets and DNS response packets by matching their 6 unique identifiers: `client IP`, `server IP`, `client port`, `DNS transaction ID`, `query name`, and `query type`. It then subtracts the query timestamp from the response timestamp to get the exact round-trip time in milliseconds.

#### Q13: How does NetScope estimate which IP address is "Likely Your Device"?
**Answer:**  
In `rules.py`, `likely_capture_hosts()` checks the frequency of every IP address in the capture. Since the capturing laptop is either the sender or receiver in almost all recorded traffic, any IP that appears in ≥90% of all packets is identified as the likely capture device.

#### Q14: How does the Communication Map work?
**Answer:**  
In `charts.py`, `comm_map()` uses the `networkx` library to build a mathematical graph where nodes are IP addresses and edges are active conversations. It uses the `spring_layout` algorithm (a force-directed physics model where connected nodes attract and all nodes repel) to position nodes in 2D space. Plotly then renders the lines (thickness = bytes) and nodes (local device = green star, remote devices = blue circles).

---

### Heuristic Security Rules Questions

#### Q15: What is the difference between an Intrusion Detection System (IDS) and NetScope's Security Insights?
**Answer:**  
NetScope is **not** an IDS or security appliance. It uses 5 simple, transparent threshold rules with evidence to highlight unusual network patterns for educational review. Normal network activity (like retrying a website or opening many tabs) can trigger these thresholds, so they are called **potential indicators**, not confirmed attacks.

#### Q16: How does the sliding window algorithm `_max_in_window()` work in `rules.py`?
**Answer:**  
It uses an efficient two-pointer technique over sorted timestamps. A `right` pointer iterates forward, while a `left` pointer advances whenever the difference `times[right] - times[left]` exceeds the window duration (10 seconds). The maximum difference `right - left + 1` gives the highest number of packets that occurred in any 10-second span in $O(N)$ time.

#### Q17: What are the 5 security rules implemented in `rules.py`?
**Answer:**  
1. **Frequent connection attempts:** ≥20 SYN packets to one destination port within 10 seconds.
2. **SYN flood pattern:** ≥100 SYN packets to one host within 10 seconds with few SYN-ACK replies.
3. **Port scanning pattern:** SYN packets probing ≥15 distinct destination ports on a single host.
4. **High traffic from one source:** One non-local IP accounting for ≥50% of all bytes.
5. **Repeated DNS queries:** The exact same domain name and query type queried ≥10 times.

---

### Implementation, Export & Performance Questions

#### Q18: What is `@st.cache_data` in `app.py`, and why is it important?
**Answer:**  
Streamlit normally re-executes the entire Python script from top to bottom every time a user clicks a button, changes a page, or moves a slider. `@st.cache_data` stores the parsed `Capture` object in memory. When the user navigates between pages, NetScope reuses the cached object instead of re-reading the PCAP file, making the UI instantaneous.

#### Q19: How is the PDF report generated in `pdf_report.py`?
**Answer:**  
It uses ReportLab. Instead of taking browser screenshots, `build_pdf()` queries the same calculation functions from `analysis.py` and `rules.py` and builds standard ReportLab flowables: paragraphs, styled tables with alternating colors, and native vector bar/line drawings. It returns raw PDF bytes to Streamlit's `st.download_button`.

#### Q20: What are the primary technical limitations of NetScope?
**Answer:**  
1. **No payload decryption:** TLS and QUIC payloads remain encrypted; only metadata is read.
2. **Passive capture perspective:** A single PCAP file cannot prove true packet loss or network latency across the entire route.
3. **Pure Python parsing speed:** Decoding packets via Scapy processes ~1,000–5,000 packets per second, which is why a 200,000 packet cap is enforced.
