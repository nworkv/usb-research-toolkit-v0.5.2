#!/usr/bin/env python3
"""Static regression checks for the Linux Raw Gadget endpoint lifecycle."""
from pathlib import Path
import sys

source = Path(sys.argv[1] if len(sys.argv) > 1 else "src/raw_gadget_backend_linux.cpp")
text = source.read_text(encoding="utf-8")
compact = "".join(text.split())

# Raw Gadget's EP_DISABLE arg is a scalar endpoint handle, not a pointer.
assert "ioctl(fd,USB_RAW_IOCTL_EP_DISABLE,&n)" not in compact,     "EP_DISABLE must not receive a pointer to the handle"
assert "USB_RAW_IOCTL_EP_DISABLE,static_cast<unsignedlong>(handle)" in compact,     "EP_DISABLE must receive the handle as a scalar value"

# Workers must be interrupted and joined BEFORE attempting to disable endpoints,
# otherwise the kernel may reject the ioctl while urb_queued is still set.
signal_pos = text.index("pthread_kill(ep->worker.native_handle(), SIGUSR1)")
join_pos = text.index("ep->worker.join()", signal_pos)
disable_pos = text.index("USB_RAW_IOCTL_EP_DISABLE", join_pos)
assert signal_pos < join_pos < disable_pos,     "stop and join blocked endpoint workers before USB_RAW_IOCTL_EP_DISABLE"

# dwc2 may report bus reset as DISCONNECT; the event loop must not terminate.
disconnect_pos = text.index("case USB_RAW_EVENT_DISCONNECT")
loop_close_pos = text.index("default:{Json e=Json::Object{};", disconnect_pos)
disconnect_case = text[disconnect_pos:loop_close_pos]
assert "disable_endpoints" in disconnect_case and "break;" in disconnect_case
assert "USB_RAW_EVENT_DISCONNECT" in disconnect_case
assert "disable_endpoints(fd, endpoints, trace, true)" in disconnect_case
assert 'trace.event("USB_RESET_OR_DISCONNECT"' in disconnect_case

# Endpoint workers should be spawned only after the SET_CONFIGURATION status
# transaction completes, not while the EP0 status stage is still pending.
status_stage_pos = text.index("payload=transact_ep0(fd, false, {}, len, trace, reqj)")
start_workers_pos = text.index("start_endpoint_workers(fd, endpoints, out_limit, trace)", status_stage_pos)
assert status_stage_pos < start_workers_pos, "start endpoint workers only after SET_CONFIGURATION status stage"
assert "allow_inactive &&" in text, "reset cleanup must tolerate endpoints already disabled by UDC"
assert 'trace.event("ENDPOINT_ALREADY_INACTIVE"' in text, "already-disabled endpoint is recorded as recoverable"
assert "USB_RAW_IOCTL_CONFIGURE" in text, "Raw Gadget CONFIGURE ioctl remains in use"

print("Raw Gadget endpoint lifecycle tests passed")
