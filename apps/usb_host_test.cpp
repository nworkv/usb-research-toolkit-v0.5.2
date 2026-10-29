#include "usb_research/json.hpp"
#include "usb_research/trace.hpp"
#include <libusb.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace usb_research;
namespace {
std::uint16_t parse_u16(const std::string& s){return static_cast<std::uint16_t>(std::stoul(s,nullptr,0));}
void usage(){std::cout<<"usb-host-test (optional libusb host exerciser)\n\nUsage:\n  usb-host-test --vid 0x1209 --pid 0x0001 --interface 0 --out-endpoint 0x01 --in-endpoint 0x81 --payload-hex 01020304 --trace runs/host/device.jsonl [--control-in-request 0x5a] [--timeout-ms 1000]\n";}
struct Ctx {libusb_context* p{};~Ctx(){if(p)libusb_exit(p);}};
struct Handle {libusb_device_handle* p{};~Handle(){if(p)libusb_close(p);}};
}
int main(int argc,char**argv){try{
    std::uint16_t vid=0x1209,pid=1;int interface_number=0,timeout_ms=1000;std::uint8_t ep_out=0x01,ep_in=0x81,control_request=0x5a;std::uint16_t control_length=64;std::string payload_hex="5553422d5245534541524348",trace_path="runs/host/host.jsonl",run_id="usb-host-test";
    for(int i=1;i<argc;++i){std::string a=argv[i];auto next=[&](){if(i+1>=argc)throw std::runtime_error("missing value for "+a);return std::string(argv[++i]);};if(a=="--vid")vid=parse_u16(next());else if(a=="--pid")pid=parse_u16(next());else if(a=="--interface")interface_number=std::stoi(next());else if(a=="--out-endpoint")ep_out=static_cast<std::uint8_t>(parse_u16(next()));else if(a=="--in-endpoint")ep_in=static_cast<std::uint8_t>(parse_u16(next()));else if(a=="--payload-hex")payload_hex=next();else if(a=="--control-in-request")control_request=static_cast<std::uint8_t>(parse_u16(next()));else if(a=="--control-in-length")control_length=parse_u16(next());else if(a=="--trace")trace_path=next();else if(a=="--run-id")run_id=next();else if(a=="--timeout-ms")timeout_ms=std::stoi(next());else{usage();throw std::runtime_error("unknown argument: "+a);}}
    auto payload=parse_hex_bytes(payload_hex);if(payload.empty())throw std::runtime_error("--payload-hex must contain at least one byte");if(!(ep_out&0x0f)||ep_out&0x80)throw std::runtime_error("--out-endpoint must be a nonzero OUT endpoint address");if(!(ep_in&0x0f)||!(ep_in&0x80))throw std::runtime_error("--in-endpoint must be a nonzero IN endpoint address");
    Ctx ctx;int rc=libusb_init(&ctx.p);if(rc<0)throw std::runtime_error(std::string("libusb_init: ")+libusb_error_name(rc));
    Handle handle;handle.p=libusb_open_device_with_vid_pid(ctx.p,vid,pid);if(!handle.p)throw std::runtime_error("could not open USB device; check VID/PID, permissions, and Windows WinUSB/libusbK driver binding");
    TraceLogger trace(trace_path,run_id,"host_libusb");Json begin=Json::Object{};begin["vid"]=vid;begin["pid"]=pid;begin["interface_number"]=interface_number;begin["out_endpoint"]=ep_out;begin["in_endpoint"]=ep_in;trace.event("HOST_TEST_START","HOST_OPEN",begin);
    if(libusb_kernel_driver_active(handle.p,interface_number)==1){rc=libusb_detach_kernel_driver(handle.p,interface_number);if(rc<0)std::cerr<<"Warning: unable to detach kernel driver: "<<libusb_error_name(rc)<<"\n";}
    rc=libusb_claim_interface(handle.p,interface_number);if(rc<0)throw std::runtime_error(std::string("libusb_claim_interface: ")+libusb_error_name(rc));
    bool had_error=false;
    Json setup=Json::Object{};Json request=Json::Object{};request["bmRequestType"]=192;request["bRequest"]=control_request;request["wValue"]=0;request["wIndex"]=0;request["wLength"]=control_length;request["direction"]="device_to_host";setup["request"]=request;setup["requested_length"]=control_length;trace.event("HOST_CONTROL_REQUEST","ENUMERATING",setup);
    std::vector<unsigned char> control_buf(control_length);rc=libusb_control_transfer(handle.p,static_cast<std::uint8_t>(LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE),control_request,0,0,control_buf.data(),control_length,timeout_ms);
    Json control_done=Json::Object{};control_done["request"]=request;control_done["requested_length"]=control_length;control_done["actual_length"]=rc;control_done["status"]=rc>=0?"completed":libusb_error_name(rc);if(rc>0)control_done["payload_hex"]=hex_bytes(std::vector<std::uint8_t>(control_buf.begin(),control_buf.begin()+rc));trace.event("HOST_CONTROL_RESPONSE_COMPLETE",rc>=0?"ENUMERATING":"ERROR",control_done);if(rc<0){had_error=true;std::cerr<<"Vendor control IN failed: "<<libusb_error_name(rc)<<"\n";}else std::cout<<"Control IN received "<<rc<<" bytes\n";
    Json desc=Json::Object{};desc["endpoint_address"]=ep_out;desc["direction"]="host_to_device";desc["requested_length"]=payload.size();desc["payload_hex"]=hex_bytes(payload);trace.event("HOST_OUT_TRANSFER_SUBMIT","ACTIVE",desc);
    int transferred=0;rc=libusb_bulk_transfer(handle.p,ep_out,payload.data(),static_cast<int>(payload.size()),&transferred,timeout_ms);Json out=Json::Object{};out["endpoint_address"]=ep_out;out["direction"]="host_to_device";out["requested_length"]=payload.size();out["actual_length"]=transferred;out["payload_hex"]=hex_bytes(std::vector<std::uint8_t>(payload.begin(),payload.begin()+std::clamp(transferred,0,static_cast<int>(payload.size()))));out["status"]=rc==0?"completed":libusb_error_name(rc);trace.event("HOST_OUT_TRANSFER_COMPLETE",rc==0?"ACTIVE":"ERROR",out);if(rc<0){had_error=true;std::cerr<<"Bulk OUT failed: "<<libusb_error_name(rc)<<"\n";}
    std::vector<unsigned char> inbuf(4096);transferred=0;Json ins=Json::Object{};ins["endpoint_address"]=ep_in;ins["direction"]="device_to_host";ins["requested_length"]=inbuf.size();trace.event("HOST_IN_TRANSFER_SUBMIT","ACTIVE",ins);rc=libusb_bulk_transfer(handle.p,ep_in,inbuf.data(),static_cast<int>(inbuf.size()),&transferred,timeout_ms);Json ine=Json::Object{};ine["endpoint_address"]=ep_in;ine["direction"]="device_to_host";ine["requested_length"]=inbuf.size();ine["actual_length"]=transferred;ine["status"]=rc==0?"completed":libusb_error_name(rc);if(transferred>0)ine["payload_hex"]=hex_bytes(std::vector<std::uint8_t>(inbuf.begin(),inbuf.begin()+transferred));trace.event("HOST_IN_TRANSFER_COMPLETE",rc==0?"ACTIVE":"ERROR",ine);if(rc<0){had_error=true;std::cerr<<"Bulk IN failed: "<<libusb_error_name(rc)<<"\n";}else std::cout<<"Bulk IN received "<<transferred<<" bytes"<<(ine.contains("payload_hex")?": "+ine.at("payload_hex").as_string():"")<<"\n";
    libusb_release_interface(handle.p,interface_number);Json finish=Json::Object{};finish["status"]=had_error?"completed_with_errors":"completed";trace.event("HOST_TEST_FINISH","HOST_CLOSED",finish);return had_error?1:0;
}catch(const std::exception&e){std::cerr<<"usb-host-test: "<<e.what()<<"\n";return 2;}}
