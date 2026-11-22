"""End-to-end tests for all 8 Streamlit pages and interactions using AppTest."""
import os
import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
REAL_CAPTURE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "captures", "netscope_first_capture.pcapng"))


def test_empty_state():
    """When no file is uploaded, welcome message is shown and no errors occur."""
    at = AppTest.from_file(APP_PATH, default_timeout=30).run()
    assert len(at.exception) == 0
    # Welcome banner should be present in markdown
    md_texts = [m.value for m in at.markdown]
    assert any("Welcome 👋" in t for t in md_texts)


def test_all_pages_with_real_capture():
    """Upload capture and cycle through all 8 pages; verify zero exceptions."""
    with open(REAL_CAPTURE, "rb") as f:
        file_bytes = f.read()

    at = AppTest.from_file(APP_PATH, default_timeout=30).run()
    # Upload capture: upload(filename, content).run()
    at.sidebar.file_uploader[0].upload("netscope_first_capture.pcapng", file_bytes).run()
    assert len(at.exception) == 0

    pages = [
        "Overview",
        "Protocol Analysis",
        "Traffic Analysis",
        "DNS Analysis",
        "Packet Explorer",
        "Security Insights",
        "Communication Map",
        "Reports",
    ]

    for page_name in pages:
        at.sidebar.radio[0].set_value(page_name).run()
        assert len(at.exception) == 0, f"Exception on page: {page_name} -> {[e.value for e in at.exception]}"

        if page_name == "Overview":
            # Verify headline metrics and device card
            metric_labels = [m.label for m in at.metric]
            assert "📦 Total Packets Captured" in metric_labels
            assert "📊 Total Data Transferred" in metric_labels
            # Verify narrative in main markdown
            main_md_texts = " ".join([m.value for m in at.main.markdown])
            assert "were captured over" in main_md_texts

        elif page_name == "Packet Explorer":
            # Test text filter interaction
            at.text_input[1].set_value("443").run()
            assert len(at.exception) == 0
            at.text_input[1].set_value("").run()

        elif page_name == "Reports":
            # Test PDF generation button
            assert len(at.button) > 0
            at.button[0].click().run()
            assert len(at.exception) == 0
            # Download buttons should now include PDF
            btn_labels = [b.label for b in at.download_button]
            assert any("PDF" in lbl for lbl in btn_labels)
