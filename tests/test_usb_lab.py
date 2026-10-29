#!/usr/bin/env python3
import importlib.util
import json
import sys
from pathlib import Path

script = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("usb_lab", script)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def check(condition, message):
    if not condition:
        raise AssertionError(message)

# Type aliases should map user-friendly type names to templates.
check(module.resolve_type("cdc") == "cdc-acm-serial", "CDC alias mapping")
check(module.resolve_type("hid") == "hid-mouse", "HID alias mapping")
check(module.resolve_type("mass-storage") == "msc-bot-disk", "MSC alias mapping")
check(module.resolve_type("hid-keyboard") == "hid-keyboard", "keyboard alias mapping")
check(module.resolve_type("gamepad") == "hid-gamepad", "gamepad alias mapping")
check(module.resolve_type("composite-hid") == "composite-hid-keyboard-mouse-consumer", "HID composite alias mapping")

# Wireshark names bmRequestType as usb.bmRequestType in current releases;
# keep compatibility with legacy builds that used the setup-prefixed name.
check(module.choose_request_type_field({"usb.bmRequestType", "usb.setup.bRequest"}) == "usb.bmRequestType",
      "current TShark bmRequestType field")
check(module.choose_request_type_field({"usb.setup.bmRequestType"}) == "usb.setup.bmRequestType",
      "legacy TShark bmRequestType field")
check(module.choose_request_type_field({"usb.setup.bRequest"}) is None,
      "missing bmRequestType field is detected")

# Raw Gadget DISCONNECT is ambiguous on DWC2 and must not be called a proven
# physical cable pull. Only an explicit physical-disconnect event gets that status.
disconnect = [{"event": "USB_RESET_OR_DISCONNECT", "state": "ENUMERATING", "sequence": 9,
               "note": "DWC2 can report reset as disconnect"}]
report = module.status_report(disconnect, [{"event": "HOST_USB_TRANSFER"}], {}, "d.jsonl", "h.jsonl")
check(report["status"] == "RESET_OR_DISCONNECT_OBSERVED", "ambiguous Raw Gadget disconnect status")
check("нельзя утверждать" in report["summary_ru"], "ambiguous reset/disconnect explanation")
report = module.status_report([{"event": "USB_PHYSICAL_DISCONNECT"}], [], {}, "d.jsonl", "h.jsonl")
check(report["status"] == "DISCONNECT_OBSERVED", "explicit physical disconnect status")

# No host data must not be asserted as a physical disconnect.
report = module.status_report([{"event": "BACKEND_RUNNING", "state": "BACKEND_READY"}], [], {}, "d.jsonl", "h.jsonl")
check(report["status"] == "NO_HOST_EVIDENCE", "empty host status")
check("не доказывает" in report["summary_ru"] or "различить" in report["summary_ru"], "empty capture caution")

# Fully matched comparable events get correlated status.
comparison = {"matched_control_requests": 2, "matched_data_transfers": 3,
              "unmatched_device_events": [], "unmatched_host_signatures": []}
report = module.status_report([{"event": "CONTROL_REQUEST"}], [{"event": "HOST_USB_TRANSFER"}], comparison, "d.jsonl", "h.jsonl")
check(report["status"] == "CORRELATED", "correlated status")

# Host-side status errors are surfaced.
report = module.status_report([], [{"event": "HOST_USB_TRANSFER", "status": "error", "host_status_code": -32}], {}, "d.jsonl", "h.jsonl")
check(report["status"] == "ERROR_OR_STALL_OBSERVED", "host error status")

# A small set of host codes is only a possible disconnect, not a certainty.
report = module.status_report([], [{"event": "HOST_USB_TRANSFER", "status": "error", "host_status_code": -19}], {}, "d.jsonl", "h.jsonl")
check(report["status"] == "POSSIBLE_DISCONNECT", "possible host disconnect")

# Bundled templates should be discoverable and explicitly mark descriptor-only MSC.
items = module.list_profiles(verbose=False)
by_name = {item["name"]: item for item in items}
check("cdc-acm-serial" in by_name, "CDC template exists")
check("hid-mouse" in by_name, "HID template exists")
check(by_name["msc-bot-descriptor-only"]["runtime_ready"] is False, "descriptor-only MSC limitation marked")
check(by_name["msc-bot-disk"]["runtime_ready"] is True, "MSC BOT disk template exists")
check("composite-cdc-hid-keyboard" in by_name, "composite CDC/HID template exists")
check("multi-config-keyboard-mouse" in by_name, "multi-configuration template exists")
check("composite-hid-keyboard-mouse-consumer" in by_name, "three-interface HID composite template exists")
check("composite-cdc-msc-hid-gamepad" in by_name, "CDC/MSC/HID composite template exists")
print("usb-lab tests passed")
