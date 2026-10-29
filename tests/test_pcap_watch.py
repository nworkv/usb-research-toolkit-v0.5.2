import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "pcap-watch.py"
spec = importlib.util.spec_from_file_location("pcap_watch", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_parse_tshark_output_counts_frames_and_finds_usb_events():
    text = "1\t1700000000.0\tUSB\tURB_SUBMIT\n2\t1700000001.0\tUSB\tDevice reset detected\n3\t1700000002.0\tUSB\tTransfer completed\n"
    result = mod.parse_tshark_output(text)
    assert result["frame_count"] == 3
    assert result["first_frame_epoch"] == 1700000000.0
    assert result["last_frame_epoch"] == 1700000002.0
    assert len(result["notable_usb_or_transport_lines"]) == 1
    assert result["notable_usb_or_transport_lines"][0]["frame"] == 2


def test_parse_empty_capture_output():
    result = mod.parse_tshark_output("")
    assert result["frame_count"] == 0
    assert result["notable_usb_or_transport_lines"] == []
