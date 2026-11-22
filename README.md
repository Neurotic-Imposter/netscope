# NetScope — Network Traffic Analyzer

An educational dashboard for the project **"Network Traffic Analysis Using Wireshark"** (IT Infrastructure and Communication Lab, JIIT Noida).

Wireshark is used to **capture** raw packets from your network interface. NetScope reads the exported `.pcap` or `.pcapng` file and transforms raw network frames into an understandable visual dashboard across 8 interactive pages.

> **Principle:** Every number and chart comes directly from your uploaded capture file. Nothing is fabricated, hard-coded, or simulated.

---

## Project Structure

The project uses a flat, minimal Python architecture:

```
netscope/
├── app.py             # Streamlit web app (8 pages, layout & filters)
├── parser.py          # Scapy packet reader -> Pandas DataFrame
├── analysis.py        # Statistical calculations & plain-English narrative
├── charts.py          # Plotly visualization builders & NetworkX graph
├── rules.py           # 5 rule-based heuristic indicator checks
├── pdf_report.py      # ReportLab PDF report generator
├── requirements.txt   # Python dependencies
├── README.md          # Project documentation
├── VIVA_GUIDE.md      # Architecture breakdown & 20 viva Q&As
└── tests/
    ├── conftest.py            # builds a small synthetic capture with Scapy
    ├── test_core.py           # parser, statistics, rules, CSV/PDF export
    ├── test_new_features.py   # plain-English names, directed flows, map, packet details
    └── test_e2e_pages.py      # Streamlit page tests (AppTest)
```

---

## Installation & Running

### Prerequisites
- Python 3.10 or higher ([python.org](https://www.python.org/downloads/) — check **"Add Python to PATH"** during install).
- Wireshark does **not** need to be installed on the machine running NetScope (NetScope decodes captures using Scapy). Wireshark is only needed to capture traffic.

### Quick Start (Windows PowerShell)

```powershell
# 1. Open PowerShell in this folder and create virtual environment
python -m venv .venv

# 2. Activate virtual environment
.venv\Scripts\Activate.ps1
# If PowerShell restricts scripts, run: Set-ExecutionPolicy -Scope Process Bypass

# 3. Install required packages
pip install -r requirements.txt

# 4. Start the dashboard
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`.

### Running Tests

```powershell
python -m pytest -v
```

The tests build their own small capture, so they pass after a fresh clone and need no private file. One extra test compares NetScope with Wireshark on the real lab capture; it runs only if `captures/netscope_first_capture.pcapng` exists on your computer, and is skipped otherwise.

---

## How to Create and Upload a Capture

1. **Record traffic in Wireshark:**
   - Open Wireshark, select your active interface (Wi-Fi or Ethernet), and click **Start**.
   - Browse a few websites or stream a video for 15–30 seconds.
   - Click **Stop** (red square).
2. **Save the capture:**
   - Go to **File → Save As...**
   - Choose `.pcapng` (default) or `.pcap`.
3. **Upload to NetScope:**
   - In the NetScope sidebar, click **📂 Upload a capture**.
   - Select your saved file.
   - All 8 dashboard pages unlock immediately.

> *Note: NetScope does not automatically load capture files. Analysis is performed on-demand in memory and files are never saved to disk.*

---

## Dashboard Pages

| Page | What it Shows |
|---|---|
| **Overview** | Likely Your Device card (an estimate), four headline numbers, network activity over time, types of traffic donut, and key observations written from the capture. |
| **Types of Traffic** *(Protocol Analysis)* | Three tabs: Network (IPv4/IPv6/ARP), Transport (TCP/UDP/ICMP) and Application (TLS/DNS/HTTP). Each shows a chart and a table with plain-English names. Also a Wireshark display filter comparison. |
| **Devices & Activity** *(Traffic Analysis)* | Top sender and receiver IP addresses, most active pairs of devices, services used (receiver ports) and packet sizes. |
| **Website Lookups** *(DNS Analysis)* | Lookups sent and answered, failed lookups, DNS servers, most looked-up names, lookup types and the answers received. |
| **Browse Packets** *(Packet Explorer)* | Filter by traffic type, IP address, port or description. Click a row to open a detail panel with sender, receiver, protocol, size, time, ports and TCP flags. |
| **Unusual Activity** *(Security Insights)* | 5 rule-based checks. Each finding is collapsed by default and explains what was seen, the evidence, and why it is not proof of an attack. |
| **Who Talks to Whom** *(Communication Map)* | Directed map: arrows go from sender IP to receiver IP. Arrow thickness = bytes; hover shows packets and protocols seen. A slider picks how many of the busiest connections to draw. |
| **Download Reports** | CSV of all packets and a PDF report. The PDF is tied to the capture it was made from, so an old PDF is never offered for a new upload. |

---

## Data Flow Architecture

```
User uploads .pcap / .pcapng in app.py sidebar
                    │
                    ▼
     parser.py :: parse_capture()
     Scapy PcapReader decodes packets into two DataFrames:
     • cap.packets (all packets: IP, ports, flags, layer labels, lengths)
     • cap.dns     (DNS packets: IDs, query names, types, rcodes, answers)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
  analysis.py               rules.py
  Aggregates metrics:       Evaluates 5 indicators:
  • overview()              • connection_rules() (SYN flood, port scan)
  • layer_tables()          • dominant_source_rule() (unusual talker)
  • top_talkers()           • dns_rule() (repeated queries)
  • conversations()         • likely_capture_hosts() (local device)
  • traffic_over_time()                 │
  • dns_summary()                       │
  • narrative()                         │
        │                               │
        └───────────┬───────────────────┘
                    ▼
          app.py (Streamlit UI)
          Coordinates page layouts and passes data tables to:
          • charts.py   -> Draws Plotly charts & NetworkX map
          • Export CSV  -> Direct df.to_csv() download
          • pdf_report.py -> build_pdf() generates printable ReportLab PDF
```

---

## Exports

- **CSV Export:** Available in *Browse Packets* (filtered packets) and *Download Reports* (all packets). Contains 14 standard columns including timestamps, IPs, ports, protocols, flags, and packet info.
- **PDF Report:** Available in *Reports*. Generates a 6-section PDF document containing:
  1. Capture details and file statistics
  2. Protocol layer distribution tables
  3. Top source talkers and active conversation pairs
  4. DNS activity, server addresses, and query performance
  5. Security indicator findings with rule thresholds and evidence
  6. Academic limitations and interpretation guidelines

---

## Important Academic & Technical Limitations

1. **No Decryption:** HTTPS/TLS and QUIC payloads are encrypted on the wire. NetScope inspects only frame headers and packet metadata (IPs, ports, flags, packet lengths). It never reads encrypted application content.
2. **Heuristic Identification:** Application protocols like TLS, HTTP, and QUIC are recognized using port numbers and header byte signatures (e.g. TLS Record version headers or UDP port 443 for QUIC). They are practical heuristics, not full deep-packet reassembly.
3. **Indicators, Not Intrusion Detection:** Security rules detect heuristic patterns using fixed thresholds (such as 100 SYN packets in 10 seconds). Normal network behavior (such as aggressive web page loading or DNS retries) can trigger these rules. They are learning observations, not proof of malicious attacks.
4. **Single-Capture Perspective:** One capture file reflects only what crossed that specific network interface during that recording window. It does not represent overall network health or ISP-level statistics.
5. **No Packet Loss / Latency Proof:** True packet loss, retransmission rates, and end-to-end throughput cannot be definitively determined from a single passive capture file without sender/receiver sequence analysis.
6. **Pure Python Processing Limit:** Pure Python packet decoding runs at approximately 1,000–5,000 packets per second. Files exceeding 200,000 packets are safely truncated to keep the dashboard responsive on standard laptops.
