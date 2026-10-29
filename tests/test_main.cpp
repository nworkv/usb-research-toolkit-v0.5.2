#include "usb_research/json.hpp"
#include "usb_research/profile.hpp"
#include "usb_research/trace.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
using namespace usb_research;
int main(){
    auto x=Json::parse(R"({"s":"USB \u03a9","n":42,"b":true,"a":[1,2]})");
    const std::uint64_t exact_timestamp = 1740000123456789012ULL;
    auto exact_roundtrip = Json::parse(Json(exact_timestamp).dump());
    assert(exact_roundtrip.as_u64() == exact_timestamp);
    assert(x.at("n").as_i64()==42);assert(x.at("b").as_bool());assert(x.at("a").size()==2);assert(x.at("s").as_string().find("USB")!=std::string::npos);
    const std::string root=USB_RESEARCH_SOURCE_DIR;
    auto p=Json::parse(read_text_file(root+"/profiles/valid/minimal-device.json"));
    auto r=validate_profile(p,"strict");assert(r.profile_valid);
    auto c=compile_profile(p);assert(c.device_descriptor.size()==18);assert(c.device_descriptor[0]==18);assert(c.device_descriptor[1]==1);assert(c.configuration_descriptors.size()==1);assert(c.configuration_descriptors[0].size()==32);assert(c.configuration_descriptors[0][2]==32);assert(c.configuration_descriptors[0][3]==0);
    auto ds=get_descriptor(c,1,0);assert(ds.size()==18);auto cfg=get_descriptor(c,2,0);assert(cfg.size()==32);auto str=get_descriptor(c,3,1,0x0409);assert(!str.empty());assert(str[1]==3);
    auto malformed=Json::parse(read_text_file(root+"/profiles/research/malformed-device.json"));auto strict_mr=validate_profile(malformed,"strict");assert(!strict_mr.profile_valid);auto mr=validate_profile(malformed,"research");assert(mr.profile_valid); // research mode reports inconsistencies as warnings
    auto mc=compile_profile(malformed);assert(mc.configuration_descriptors[0][2]==0xff&&mc.configuration_descriptors[0][3]==0xff);
    // Exact control-setup and transfer-fingerprint correlation tests.
    const auto tdir=std::filesystem::temp_directory_path()/"usb-research-tests";
    std::filesystem::create_directories(tdir);
    const auto dev=(tdir/"device.jsonl").string(), host=(tdir/"host.jsonl").string();
    const std::string setup=R"("request":{"bmRequestType":128,"bRequest":6,"wValue":256,"wIndex":0,"wLength":18})";
    write_text_file(dev,
        "{\"event\":\"CONTROL_REQUEST\",\"state\":\"ENUMERATING\",\"sequence\":1,"+setup+"}\n"
        "{\"event\":\"CONTROL_RESPONSE_COMPLETE\",\"state\":\"ENUMERATING\",\"sequence\":2,\"endpoint_address\":0,\"direction\":\"device_to_host\",\"actual_length\":4,\"payload_hex\":\"01020304\","+setup+"}\n"
        "{\"event\":\"DEVICE_OUT_TRANSFER_RECEIVED\",\"state\":\"ACTIVE\",\"sequence\":3,\"endpoint_address\":1,\"direction\":\"host_to_device\",\"actual_length\":4,\"payload_hex\":\"01020304\"}\n");
    write_text_file(host,
        "{\"event\":\"HOST_USB_TRANSFER\",\"state\":\"HOST_CAPTURED\",\"sequence\":10,\"endpoint\":0,\"direction\":\"device_to_host\",\"actual_length\":4,\"payload_hex\":\"01020304\","+setup+"}\n"
        "{\"event\":\"HOST_OUT_TRANSFER_COMPLETE\",\"state\":\"ACTIVE\",\"sequence\":11,\"endpoint_address\":1,\"direction\":\"host_to_device\",\"actual_length\":4,\"payload_hex\":\"01020304\"}\n");
    auto compared=compare_traces(dev,host);assert(compared.at("matched_control_requests").as_u64()==1);assert(compared.at("matched_data_transfers").as_u64()==2);
    // Starting a new run at the same trace path must not append stale events.
    const auto reused=(tdir/"reused.jsonl").string();
    { TraceLogger first(reused,"old-run","test"); first.event("STALE_EVENT","OLD"); }
    { TraceLogger second(reused,"new-run","test"); second.event("FRESH_EVENT","NEW"); }
    const auto reused_text=read_text_file(reused);
    assert(reused_text.find("STALE_EVENT")==std::string::npos);
    assert(reused_text.find("FRESH_EVENT")!=std::string::npos);
    // The HID mouse template's report length must match its HID descriptor and a four-byte report.
    auto hid=Json::parse(read_text_file(root+"/profiles/templates/hid-mouse.json"));
    auto hidc=compile_profile(hid);
    auto hid_report=get_descriptor(hidc,34,0);
    assert(hid_report.size()==62);
    const auto& hid_cfg=hidc.configuration_descriptors[0];
    assert(hid_cfg.size()==34 && hid_cfg[25]==62 && hid_cfg[26]==0);
    assert(parse_hex_bytes(hid.at("endpoint_io").at("in_payloads").at("129").as_string()).size()==4);
    std::filesystem::remove_all(tdir);
    std::cout<<"All tests passed\n";
}
