"""End-to-end tests of the Streamlit app (AppTest) using the synthetic capture."""
import os

from streamlit.testing.v1 import AppTest

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))

PAGES = ["Overview", "Types of Traffic", "Devices & Activity", "Website Lookups",
         "Browse Packets", "Unusual Activity", "Who Talks to Whom", "Download Reports"]


def _app():
    return AppTest.from_file(APP_PATH, default_timeout=60).run()


def _upload(at, name, data):
    at.sidebar.file_uploader[0].upload(name, data).run()
    return at


def _text(at):
    return " ".join(m.value for m in at.main.markdown) + " " + " ".join(c.value for c in at.main.caption)


def test_empty_state_guides_the_user():
    at = _app()
    assert len(at.exception) == 0
    assert any("Upload a capture" in m.value for m in at.main.markdown)
    assert len(at.metric) == 0


def test_navigation_has_the_eight_plain_english_pages():
    at = _app()
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
    assert labels == ["Number of Packets", "Amount of Data", "Capture Duration", "Different IP Addresses"]
    assert at.metric[0].value == "55"
    text = _text(at)
    assert "Likely Your Device" in text and "estimate" in text
    # the device address is shown clean (no star) in a copyable code box
    assert "10.0.0.5" in [c.value for c in at.main.code]
    assert all("★" not in c.value for c in at.main.code)


def test_overview_activity_switch(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.radio(key="activity_what").set_value("bytes").run()
    assert len(at.exception) == 0


def test_types_of_traffic_has_three_tabs(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Types of Traffic").run()
    assert [t.label for t in at.tabs] == ["Network", "Transport", "Application"]


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


def test_who_talks_to_whom_slider(pcap_bytes):
    at = _upload(_app(), "synthetic.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Who Talks to Whom").run()
    assert len(at.exception) == 0
    at.slider[0].set_value(4).run()
    assert len(at.exception) == 0
    assert "Showing the 4 busiest" in _text(at)


def test_invalid_upload_shows_friendly_error():
    at = _upload(_app(), "bad.pcap", b"this is not a capture file" * 20)
    assert len(at.exception) == 0
    assert len(at.error) == 1 and "Could not analyse" in at.error[0].value


def test_pdf_always_matches_the_current_capture(pcap_bytes, second_pcap_bytes):
    at = _upload(_app(), "first.pcap", pcap_bytes)
    at.sidebar.radio[0].set_value("Download Reports").run()
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
    assert [c.value for c in at.main.code] == ["10.0.0.5", "10.0.0.9"]   # clean, copyable IPs
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
