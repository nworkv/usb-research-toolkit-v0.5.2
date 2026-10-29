#pragma once
#include "usb_research/profile.hpp"
#include <string>

namespace usb_research {
struct RawGadgetOptions {
    std::string profile_path;
    std::string trace_path;
    std::string udc_driver;
    std::string udc_device;
    std::string speed = "high";
    std::string run_id = "usb-run";
    bool allow_research = false;
};
int probe_usb_device_mode();
int run_raw_gadget(const RawGadgetOptions& options, const CompiledProfile& profile);
}
