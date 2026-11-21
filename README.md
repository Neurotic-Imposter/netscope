# NetScope — Network Traffic Analyzer

Companion dashboard for the PBL project **"Network Traffic Analysis Using Wireshark"**
(IT Infrastructure and Communication Lab, JIIT Noida).

Wireshark is still the tool used to **capture and inspect** packets. NetScope reads the
same `.pcap` / `.pcapng` file and summarises it in one dashboard: protocol statistics,
top talkers, DNS, a searchable packet table, simple rule-based indicators, a
communication map, CSV export and a PDF report.

> Only analyse traffic you are authorised to capture. Every number comes from the loaded
> capture file; nothing is hard-coded.

## Run on Windows

1. Install **Python 3.10+** from python.org (tick *Add Python to PATH*).
2. Open **PowerShell** in this folder and run:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks the activate script, run
`Set-ExecutionPolicy -Scope Process Bypass` first, or use `.venv\Scripts\activate.bat` in Command Prompt.

3. The browser opens at `http://localhost:8501` and loads `captures/netscope_first_capture.pcapng`.
   Use **Analyse another capture** in the sidebar to upload a different file.

Wireshark/TShark does **not** need to be installed to run NetScope (it parses files with
Scapy). You only need Wireshark to make new captures.

Run the tests: `python -m pytest -q`

## Pages

| Page | What it shows |
|---|---|
| Overview | Packets, bytes, duration, unique source/destination IPs, transport split, top ports |
| Protocol Analysis | Network / transport / application layers shown **separately**, plus counts to compare with Wireshark display filters |
| Traffic Analysis | Top source/destination IPs, endpoint pairs, traffic over time, ports, packet lengths |
| DNS Analysis | Queried names, query types, DNS servers, error responses, reply times, answers |
| Packet Explorer | Filter by protocol / IP / port / text, CSV export |
| Security Insights | 5 simple rules with evidence. *Potential indicators only* |
| Communication Map | NetworkX graph drawn with Plotly (nodes = IPs, edge width = bytes) |
| Reports | Full CSV and PDF report |

## How data flows

```
.pcapng file
   │  core/parser.py      Scapy reads packets → one pandas row per packet
   ▼                      (+ a separate table of DNS query/response details)
packet table (DataFrame)
   │  core/analysis.py    counts, percentages, top talkers, time buckets, DNS summary
   │  detectors/rules.py  threshold rules → Alert objects with evidence
   ▼
app.py (Streamlit)        pages and tables
   ├─ components/charts.py   Plotly charts and the NetworkX map
   └─ reports/pdf_report.py  ReportLab PDF (same numbers as the dashboard)
```

Parsing is kept separate from presentation, so `tests/` can check the numbers without a browser.

## Accuracy notes (read before presenting)

* **Layers overlap.** A TLS packet is also TCP and IPv6, so protocol tables are per layer and are never added together.
* **`dns` = standard DNS on port 53**, the same packets Wireshark's `dns` filter shows. mDNS (5353), LLMNR (5355) and NBNS are listed separately.
* **`icmp` = ICMPv4 only**, like Wireshark. ICMPv6 (Neighbor Discovery etc.) is shown separately.
* **TLS, HTTP and QUIC are heuristics**: TLS from the record header bytes, HTTP from request/response text, QUIC from UDP port 443. Encrypted content is never read.
* **Not calculated** (cannot be established reliably from one capture): packet loss, latency, throughput, retransmission rate.
* **Security rules are simple thresholds** (shown on the page, editable in `detectors/rules.py`). They are not an IDS and cannot confirm an attack. Normal traffic can trigger them.
* One capture does not represent all network behaviour.

## Limits

* Parsing is pure Python: about 1,000–5,000 packets per second. The sidebar limit (default 200,000) stops very large files from freezing the app, and the page says when it was applied.
* Unreadable packets are skipped and counted, not hidden. Invalid or empty files show an error message.

## Reference

The brief suggested the NetSleuth repository (`github.com/ariwooze/NetSleuth`) as architectural inspiration.
It could not be opened while building this, so its license could not be checked and **no code was copied from it**.
NetScope is an original implementation using Streamlit, Pandas, Plotly, NetworkX, Scapy and ReportLab.
