"""Plain-language teaching text shown around the real results.

Everything here is fixed text written for students. It never contains values taken
from an uploaded capture. The simulation values are examples only.
"""

# ── Protocol guide (Types of Traffic page) ───────────────────────────────────
# layer, what it is, what it does, how it works, what it means when present, what NetScope analyses
PROTOCOL_GUIDE = {
    "TCP": dict(
        layer="Transport layer",
        what="Transmission Control Protocol. A way of sending data that checks it arrived.",
        does="Carries web pages, email and file transfers, where nothing may be lost or reordered.",
        how="Two devices first agree to talk (SYN, SYN-ACK, ACK, the three-way handshake). "
            "Every chunk of data is numbered and acknowledged, and missing chunks are sent again.",
        present="Devices opened reliable connections. Most everyday traffic uses TCP.",
        analysed="Counts, ports, TCP flags (SYN, ACK, RST...), connection set-up time and reset counts.",
    ),
    "UDP": dict(
        layer="Transport layer",
        what="User Datagram Protocol. A fast way of sending data without checking that it arrived.",
        does="Carries DNS lookups, video calls, games and streaming, where speed matters more than perfection.",
        how="Each packet is simply sent. There is no handshake and no acknowledgement, "
            "so the receiving program decides what to do about missing data.",
        present="Some traffic favoured speed over guaranteed delivery.",
        analysed="Counts, ports and sizes. UDP has no flags or sequence numbers to analyse.",
    ),
    "DNS": dict(
        layer="Application layer",
        what="Domain Name System. The internet's phone book for names.",
        does="Turns a name such as example.com into the IP address a device needs to connect.",
        how="A device sends a question to a DNS server (usually UDP port 53). "
            "The server answers with an IP address, or an error if the name does not exist.",
        present="Devices looked up names. A lookup shows that a name was asked about, "
                "not that a website was opened.",
        analysed="Names asked, query types (A, AAAA, PTR...), answers, errors, reply times and repeated queries. "
                 "See the Website Lookups page.",
    ),
    "ARP": dict(
        layer="Network layer (local network only)",
        what="Address Resolution Protocol. Finds which device owns an IP address on the same local network.",
        does="Lets a device learn the hardware (MAC) address it needs to deliver a packet on the local network.",
        how="A device asks everyone \"who has this IP address?\". "
            "The owner replies with its MAC address. ARP never leaves the local network.",
        present="Devices on the same local network (for example Wi-Fi) were finding each other.",
        analysed="Counts, and who asked about which address (shown in the packet description).",
    ),
    "ICMP": dict(
        layer="Transport layer (control messages)",
        what="Internet Control Message Protocol. Test and error messages for the network itself.",
        does="Powers ping and traceroute, and reports problems such as \"destination unreachable\".",
        how="One device sends an echo request (ping) and the other sends an echo reply. "
            "Routers use ICMP to say a packet could not be delivered.",
        present="Someone tested connectivity, or a device reported a delivery problem.",
        analysed="Counts and the message type in the packet description. IPv6 uses ICMPv6, which is counted separately.",
    ),
    "HTTP": dict(
        layer="Application layer",
        what="HyperText Transfer Protocol. The language of web pages, sent as readable text.",
        does="Requests web pages and files (GET) and returns them (responses).",
        how="A browser sends a request such as GET /index.html over TCP (usually port 80). "
            "The server returns the page. None of it is encrypted.",
        present="Some web traffic was not encrypted, so anyone on the network path could read it.",
        analysed="Counted from the first bytes of a TCP payload (GET, POST, HTTP/1.1...). NetScope does not read page contents.",
    ),
    "HTTPS": dict(
        layer="Application layer (HTTP inside TLS)",
        what="HTTP protected by TLS encryption. The padlock in a browser.",
        does="Carries most modern web traffic while keeping the contents private.",
        how="After the TCP handshake the two sides run a TLS handshake and agree on keys. "
            "From then on only scrambled data is visible on the network.",
        present="Encrypted connections were used. Their content cannot be read, only their size, timing and addresses.",
        analysed="Packets whose first bytes look like a TLS record. This is an estimate: TLS is also used by "
                 "protocols other than HTTPS, and NetScope never decrypts anything.",
    ),
}

# ── Why each Unusual Activity check can matter ───────────────────────────────
RULE_WHY = {
    "Frequent connection attempts": "Many connection requests in a short time can mean a program is "
        "retrying a service that is not answering, or something is probing it.",
    "SYN flood pattern": "Very many connection requests with few replies is the shape of a flood that "
        "tries to overwhelm a server. It is also what a broken or overloaded service can look like.",
    "Port scanning pattern": "Trying many different ports on one host is how scanners look for open "
        "services. Network tools and some applications do the same thing.",
    "High traffic from one source": "One address producing most of the data deserves a look: it could be "
        "a large download, a backup, a stream or something misbehaving.",
    "Repeated DNS queries": "The same name asked again and again can mean failed lookups being retried, "
        "no local caching or a program stuck in a loop.",
    "Repeated TCP resets": "Resets end connections abruptly. A few are normal; many can point to a closed "
        "port, a crashing program or a firewall refusing connections.",
    "Traffic spike": "A sudden burst can be a download, an update or a video starting. "
        "It can also be a sign of something unexpected sending a lot at once.",
}

# Display names for the rule severities (rules.py keeps its own values).
SEVERITY_LABEL = {"Info": "Observation", "Low": "Review", "Medium": "Potentially unusual"}
SEVERITY_COLOUR = {"Info": "blue", "Low": "orange", "Medium": "red"}
SEVERITY_MEANING = {
    "Observation": "probably normal behaviour, noted for completeness",
    "Review": "mildly unusual, often normal retries",
    "Potentially unusual": "unusual, with possible innocent explanations",
}

# ── DNS explainer ────────────────────────────────────────────────────────────
DNS_STEPS = [
    ("1. Ask", "The device asks its DNS server: \"what is the IP address of example.com?\""),
    ("2. Look up", "The DNS server checks its memory (cache) or asks other DNS servers on the internet."),
    ("3. Answer", "The server replies with an IP address, or an error such as NXDOMAIN if the name does not exist."),
    ("4. Connect", "Only now can the device send packets to that IP address. NetScope sees the question and the answer, not whether a connection followed."),
]

# ── Educational simulation (landing page) ────────────────────────────────────
# These are EXAMPLE values. 203.0.113.x is a range reserved for documentation, so it is not a real server.
SIM_LAPTOP, SIM_ROUTER, SIM_SERVER = "192.168.1.23", "192.168.1.1", "203.0.113.10"

SIM_STEPS = [
    dict(name="1. DNS question", direction="right", server=False, hop="Laptop → Router / Network",
         src=SIM_LAPTOP, sport="53123", dst=SIM_ROUTER, dport="53", proto="UDP (DNS)", size="74 bytes",
         dns="\"What is the IP address of www.youtube.com?\"",
         says="Before connecting, the laptop asks a DNS server for the address behind the name."),
    dict(name="2. DNS answer", direction="left", server=False, hop="Router / Network → Laptop",
         src=SIM_ROUTER, sport="53", dst=SIM_LAPTOP, dport="53123", proto="UDP (DNS)", size="90 bytes",
         dns=f"\"The address is {SIM_SERVER}\"",
         says="The reply comes back to the same port the question came from, so the laptop knows which question it answers."),
    dict(name="3. Web request", direction="right", server=True, hop="Laptop → Router / Network → Website server",
         src=SIM_LAPTOP, sport="52814", dst=SIM_SERVER, dport="443", proto="TCP (HTTPS)", size="517 bytes",
         dns="Not used. The address is already known.",
         says="The laptop asks the website server for the page. Port 443 means secure web traffic."),
    dict(name="4. Server response", direction="left", server=True, hop="Website server → Router / Network → Laptop",
         src=SIM_SERVER, sport="443", dst=SIM_LAPTOP, dport="52814", proto="TCP (HTTPS)", size="1,460 bytes",
         dns="Not used.",
         says="The server sends the page back in packets. A full-size packet is about 1,500 bytes on Ethernet."),
]

SIM_FIELDS = [
    ("Source IP", "src", "The address that sent this packet."),
    ("Source port", "sport", "Which program on the sender used this connection. Often a random high number."),
    ("Destination IP", "dst", "The address the packet is going to."),
    ("Destination port", "dport", "Which service the packet is for. 443 = secure web, 53 = DNS."),
    ("Protocol", "proto", "The set of rules used to send the data."),
    ("DNS lookup", "dns", "The question or answer about a name, when the packet is a DNS packet."),
    ("Packet size", "size", "How many bytes this packet takes up on the network."),
    ("Direction", "hop", "Where the packet is travelling: toward the website, or back to you."),
]
