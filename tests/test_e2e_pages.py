"""End-to-end tests of the Streamlit app (AppTest) using the synthetic capture."""
import os

from streamlit.testing.v1 import AppTest

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))

PAGES = ["Overview", "Types of Traffic", "Devices & Activity", "Website Lookups",
         "Browse Packets", "Unusual Activity", "Performance", "Communication Map", "Reports"]


def _app():
    return AppTest.from_file(APP_PATH, default_timeout=60).run()


def _upload(at, name, data, key="capture_side"):
    at.file_uploader(key=key).upload(name, data).run()
    return at


def _text(at):
    return " ".join(m.value for m in at.main.markdown) + " " + " ".join(c.value for c in at.main.caption)


def test_landing_page_introduces_the_project_and_offers_upload():
    at = _app()
    assert len(at.exception) == 0
    text = " ".join(m.value for m in at.main.markdown)
    assert "Network Analysis Using Wireshark" in text and "PBL Project" in text
    assert "does not capture live traffic" in _text(at) and "cannot decrypt HTTPS" in _text(at)
    assert [s.value for s in at.main.subheader] == [
        "Wireshark and this application", "Upload a capture", "How a packet travels: an example"]
    assert len(at.file_uploader) == 2   # one in the Overview body, one in the sidebar
    assert len(at.metric) == 0          # no capture numbers before a capture exists


def test_simulation_is_labelled_and_never_shows_capture_numbers():
    at = _app()
    text = " ".join(m.value for m in at.main.markdown)
    assert "Educational simulation" in text and "not from any capture" in text
    at.radio(key="sim_step").set_value("3. Web request").run()
    assert len(at.exception) == 0
    assert "`443`" in " ".join(m.value for m in at.main.markdown)


def test_sidebar_and_all_nine_pages_exist_before_any_upload():
    at = _app()
    assert len(at.exception) == 0
    assert list(at.sidebar.radio[0].options) == PAGES
    assert at.sidebar.radio[0].value == "Overview"
    side = " ".join(m.value for m in at.sidebar.markdown)
    assert "Network Analysis Using Wireshark" in side and "PBL Project" in side
    assert len(at.sidebar.file_uploader) == 1


def test_every_page_opens_with_an_empty_state_and_no_numbers_before_upload():
    at = _app()
    for page in PAGES[1:]:
        at.sidebar.radio[0].set_value(page).run()
        assert len(at.exception) == 0, f"{page}: {[e.value for e in at.exception]}"
        assert [h.value for h in at.main.header] == [page]
        assert "No capture loaded yet" in _text(at), page
        assert len(at.metric) == 0 and len(at.dataframe) == 0, f"{page} shows data without a capture"
        assert len(at.sidebar.radio[0].options) == 9           # navigation stays visible
        assert at.sidebar.radio[0].value == page               # and the active page is the selected one


def test_overview_without_capture_keeps_introduction_and_upload_instructions():
    at = _app()
    at.sidebar.radio[0].set_value("Types of Traffic").run()
    at.sidebar.radio[0].set_value("Overview").run()
    assert "Upload a capture" in [s.value for s in at.main.subheader]
    assert len(at.file_uploader) == 2


def test_navigation_has_the_nine_plain_english_pages(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    assert list(at.sidebar.radio[0].options) == PAGES


def test_all_pages_open_without_errors(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    assert len(at.exception) == 0
    for page in PAGES:
        at.sidebar.radio[0].set_value(page).run()
        assert len(at.exception) == 0, f"{page}: {[e.value for e in at.exception]}"


def test_overview_content(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    labels = [m.label for m in at.metric]
    assert labels == ["Total Packets", "Unique IP Addresses", "Total Data", "Capture Duration"]
    assert at.metric[0].value == "55"
    text = _text(at)
    assert "Likely your device" in text and "estimate" in text
    # the device address is shown clean (no star) in a copyable code box
    assert "10.0.0.5" in [c.value for c in at.main.code]
    assert all("★" not in c.value for c in at.main.code)


def test_overview_activity_switch(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.radio(key="activity_what").set_value("bytes").run()
    assert len(at.exception) == 0


def test_types_of_traffic_explains_each_protocol_with_real_counts(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Types of Traffic").run()
    assert len(at.exception) == 0
    labels = [t.label for t in at.tabs]
    assert labels == ["TCP", "UDP", "DNS", "ARP", "ICMP", "HTTP", "HTTPS",
                      "Network", "Transport", "Application"]
    counts = {m.label.split(" · ")[0]: m.value for m in at.metric}
    assert counts["TCP"] == "36" and counts["DNS"] == "12" and counts["HTTPS (TLS)"] == "29"
    assert "do not add them together" in " ".join(i.value for i in at.info)


def test_unusual_activity_findings_start_collapsed(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Unusual Activity").run()
    assert len(at.exception) == 0
    assert all(not e.proto.expanded for e in at.expander)


def test_browse_packets_filters(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Browse Packets").run()
    assert "55** of 55" in _text(at)
    at.text_input[1].set_value("443").run()          # port filter
    assert len(at.exception) == 0
    assert "30** of 55" in _text(at)                 # 20 + 10 packets use port 443
    at.text_input[1].set_value("").run()
    at.text_input[0].set_value("10.0.0.1").run()     # IP filter
    assert "19** of 55" in _text(at)                 # 12 DNS + 5 ICMP + 2 ARP involve 10.0.0.1


def test_communication_map_slider_and_ip_panel(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Communication Map").run()
    assert len(at.exception) == 0
    at.slider[0].set_value(4).run()
    assert len(at.exception) == 0
    assert "Showing the 4 busiest" in _text(at)
    # the side panel inspects one address and offers only addresses that are on the map
    ips = list(at.selectbox[0].options)
    assert "10.0.0.5" in ips
    at.selectbox[0].set_value("10.0.0.9").run()
    assert len(at.exception) == 0
    assert "10.0.0.9" in [c.value for c in at.main.code]


def test_performance_never_invents_numbers(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Performance").run()
    assert len(at.exception) == 0
    text = _text(at)
    # the synthetic capture has no SYN-ACK, so no connection set-up time can exist
    assert "No connection set-up" in text
    assert "tcp.analysis.retransmission" in text
    # the synthetic DNS replies do match their questions, so DNS timing IS available
    assert "Typical reply time" in [m.label for m in at.metric]


def test_invalid_upload_shows_friendly_error():
    at = _upload(_app(), "bad.pcap", b"this is not a capture file" * 20)
    assert len(at.exception) == 0
    assert len(at.error) == 1 and "Could not analyse" in at.error[0].value


def test_pdf_always_matches_the_current_capture(pcap_bytes, second_pcap_bytes):
    at = _upload(_app(), "first.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Reports").run()
    at.button[0].click().run()
    assert len(at.exception) == 0
    assert any("PDF" in d.label for d in at.main.get("download_button"))

    # Upload a different capture: the old PDF must not be offered for it.
    _upload(at, "second.pcap", second_pcap_bytes)
    assert len(at.exception) == 0
    assert not any("PDF" in d.label for d in at.main.get("download_button"))
    assert any("different capture" in i.value for i in at.info)


def test_selecting_a_packet_shows_its_details(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Browse Packets").run()
    assert any("Click a row" in i.value for i in at.info)       # nothing selected yet

    key = next(k for k in at.session_state.keys() if str(k).startswith("packets_"))
    at.session_state[key] = {"selection": {"rows": [0], "columns": [], "cells": []}}
    at.run()
    assert len(at.exception) == 0
    assert "Packet number 1" in [s.value for s in at.main.subheader]
    codes = [c.value for c in at.main.code]
    assert codes[:2] == ["10.0.0.5", "10.0.0.9"]                          # clean, copyable IPs
    assert codes[2] == "50000 → 443 [SYN] len=0"                          # description, shown as plain text
    assert "**TCP flags:** SYN" in _text(at)
    assert "**Receiver port:** 443" in _text(at)


def test_changing_a_filter_clears_the_selection(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Browse Packets").run()
    key = next(k for k in at.session_state.keys() if str(k).startswith("packets_"))
    at.session_state[key] = {"selection": {"rows": [0], "columns": [], "cells": []}}
    at.run()
    at.text_input[1].set_value("443").run()
    assert any("Click a row" in i.value for i in at.info)


def test_upload_keeps_the_selected_page_and_replacing_keeps_navigation_working(pcap_bytes):
    at = _app()
    at.sidebar.radio[0].set_value("Performance").run()
    assert "No capture loaded yet" in _text(at)
    _upload(at, "synthetic.pcap", pcap_bytes)
    assert at.sidebar.radio[0].value == "Performance"              # stays on the chosen page
    assert len(at.exception) == 0 and "No capture loaded yet" not in _text(at)
    assert "Typical reply time" in [m.label for m in at.metric]    # real analysis now
    for page in PAGES:                                              # replace, then walk every page
        _upload(at, "again.pcap", pcap_bytes)
        at.sidebar.radio[0].set_value(page).run()
        assert len(at.exception) == 0, f"{page}: {[e.value for e in at.exception]}"
        assert "No capture loaded yet" not in _text(at)
        assert len(at.sidebar.radio[0].options) == 9


def test_upload_from_the_overview_body_works_too(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes, key="capture_main")
    assert len(at.exception) == 0
    assert at.metric[0].value == "55"
    at.sidebar.radio[0].set_value("Browse Packets").run()
    assert len(at.exception) == 0 and "No capture loaded yet" not in _text(at)


def test_invalid_upload_shows_an_error_and_keeps_navigation(tmp_path):
    at = _upload(_app(), "bad.pcap", b"this is not a capture" * 10)
    assert len(at.exception) == 0
    assert any("Could not analyse this file" in e.value for e in at.error)
    assert len(at.sidebar.radio[0].options) == 9
    at.sidebar.radio[0].set_value("Reports").run()
    assert len(at.exception) == 0 and len(at.metric) == 0
