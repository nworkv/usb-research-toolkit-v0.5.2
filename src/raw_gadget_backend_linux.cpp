#include "usb_research/raw_gadget_backend.hpp"
#include "usb_research/trace.hpp"
#include <algorithm>
#include <array>
#include <condition_variable>
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <limits>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <exception>
#include <fstream>
#include <iostream>
#include <atomic>
#include <thread>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>
#ifdef __linux__
#include <pthread.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace usb_research {
#ifdef __linux__
namespace {
volatile std::sig_atomic_t stop_requested=0;
void on_signal(int){stop_requested=1;}
void on_worker_interrupt(int) {}
std::uint16_t le16(const __le16& x) { const auto* p=reinterpret_cast<const unsigned char*>(&x);return static_cast<std::uint16_t>(p[0]|(p[1]<<8)); }
void check_ioctl(int fd,unsigned long req,void* arg,const std::string& name){if(ioctl(fd,req,arg)<0)throw std::runtime_error(name+" failed: "+std::strerror(errno));}
std::vector<std::uint8_t> transact_ep0(int fd, bool in, const std::vector<std::uint8_t>& data,
                                      std::uint16_t wanted, TraceLogger& trace, const Json& request) {
    const std::size_t n = in ? std::min<std::size_t>(data.size(), wanted) : wanted;
    std::vector<std::uint8_t> mem(sizeof(usb_raw_ep_io) + std::max<std::size_t>(n, 1));
    auto* io = reinterpret_cast<usb_raw_ep_io*>(mem.data());
    io->ep = 0;
    io->flags = 0;
    io->length = static_cast<__u32>(n);
    if (in) std::copy_n(data.begin(), n, io->data);
    int rc = ioctl(fd, in ? USB_RAW_IOCTL_EP0_WRITE : USB_RAW_IOCTL_EP0_READ, io);
    if (rc < 0) throw std::runtime_error(std::string(in ? "EP0_WRITE" : "EP0_READ") + " failed: " + std::strerror(errno));

    std::vector<std::uint8_t> got;
    const auto completed = std::min<std::size_t>(n, static_cast<std::size_t>(std::max(rc, 0)));
    if (!in && completed > 0) got.assign(io->data, io->data + completed);
    const auto& payload = in ? data : got;
    const auto payload_length = in ? completed : got.size();

    Json ev = Json::Object{};
    ev["event"] = in ? "CONTROL_RESPONSE_COMPLETE" : "CONTROL_OUT_COMPLETE";
    ev["state"] = "ENUMERATING";
    ev["endpoint_address"] = 0;
    ev["direction"] = in ? "device_to_host" : "host_to_device";
    ev["request"] = request;
    ev["requested_length"] = n;
    ev["actual_length"] = payload_length;
    ev["status"] = "completed";
    if (payload_length > 0) {
        std::vector<std::uint8_t> actual(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(payload_length));
        ev["payload_hex"] = hex_bytes(actual);
    }
    trace.log(std::move(ev));
    return got;
}
std::vector<std::uint8_t> match_custom_response(const Json& root,const usb_ctrlrequest& ctrl) {
    const auto& responses=root.at("control_responses"); if(!responses.is_array())return {};
    auto rt=ctrl.bRequestType,req=ctrl.bRequest;auto val=le16(ctrl.wValue),idx=le16(ctrl.wIndex);
    for(const auto& r:responses.as_array()){if(field_u(r,"bmRequestType",256)!=rt||field_u(r,"bRequest",256)!=req)continue;if(r.contains("wValue")&&field_u(r,"wValue",val)!=val)continue;if(r.contains("wIndex")&&field_u(r,"wIndex",idx)!=idx)continue;return parse_hex_bytes(r.at("data_hex").as_string());}return {};
}
struct MassStorageState {
    int fd{-1};
    std::string path;
    std::uint32_t block_size{512};
    std::uint64_t block_count{};
    std::uint8_t configuration_value{1};
    std::uint8_t interface_number{0};
    std::uint8_t in_endpoint{0x81};
    std::uint8_t out_endpoint{0x01};
    bool read_only{false};
    std::mutex mutex;
    std::uint8_t sense_key{0};
    std::uint8_t sense_asc{0};
    std::uint8_t sense_ascq{0};
    ~MassStorageState() { if (fd >= 0) ::close(fd); }
};

struct LoopbackChannel {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::vector<std::uint8_t>> queued;
};

struct EndpointHandle {
    std::uint32_t handle{};
    std::uint8_t address{};
    std::uint16_t max_packet{};
    bool in{};
    std::uint8_t transfer_type{};
    std::vector<std::uint8_t> in_payload;
    bool repeat_in{};
    bool msc_in_endpoint{false};
    MassStorageState* mass_storage{nullptr}; // set only on the BOT bulk-OUT endpoint
    EndpointHandle* companion{nullptr};     // BOT bulk-IN endpoint or CDC loopback peer
    std::shared_ptr<LoopbackChannel> loopback;
    std::atomic<bool> stop{false};
    std::thread worker;
};

struct RuntimeControlState {
    std::map<std::string, std::vector<std::uint8_t>> cdc_line_coding;
    std::map<std::string, std::uint8_t> hid_idle;
    std::map<std::string, std::uint8_t> hid_protocol;
};

std::string interface_key(std::uint8_t config, std::uint16_t iface) {
    return std::to_string(config) + ":" + std::to_string(iface);
}

const Json* runtime_interface(const Json& root, std::uint8_t config, std::uint16_t iface) {
    if (!root.contains("runtime") || !root.at("runtime").is_object() ||
        !root.at("runtime").contains("interfaces") || !root.at("runtime").at("interfaces").is_array()) return nullptr;
    for (const auto& item : root.at("runtime").at("interfaces").as_array()) {
        const auto c = field_u(item, "configuration_value", 1);
        const auto i = field_u(item, "interface_number", 0);
        if (c == config && i == iface) return &item;
    }
    return nullptr;
}

std::shared_ptr<MassStorageState> open_mass_storage(const CompiledProfile& profile) {
    const auto& root = profile.source;
    if (!root.contains("runtime") || !root.at("runtime").is_object() ||
        !root.at("runtime").contains("mass_storage")) return {};
    const auto& cfg = root.at("runtime").at("mass_storage");
    if (!cfg.is_object() || !cfg.at("enabled").as_bool(false)) return {};
    auto state = std::make_shared<MassStorageState>();
    state->path = cfg.at("backing_file").as_string("");
    if (state->path.empty()) throw std::runtime_error("runtime.mass_storage.backing_file is required; create a disk image with scripts/create-msd-image.py");
    state->block_size = static_cast<std::uint32_t>(field_u(cfg, "block_size", 512));
    state->configuration_value = static_cast<std::uint8_t>(field_u(cfg, "configuration_value", 1));
    state->interface_number = static_cast<std::uint8_t>(field_u(cfg, "interface_number", 0));
    state->in_endpoint = static_cast<std::uint8_t>(field_u(cfg, "in_endpoint", 0x81));
    state->out_endpoint = static_cast<std::uint8_t>(field_u(cfg, "out_endpoint", 0x01));
    state->read_only = cfg.at("read_only").as_bool(false);
    if (state->block_size < 512 || state->block_size > 4096 || (state->block_size & (state->block_size - 1)) != 0)
        throw std::runtime_error("runtime.mass_storage.block_size must be a power of two in 512..4096");
    state->fd = ::open(state->path.c_str(), (state->read_only ? O_RDONLY : O_RDWR) | O_CLOEXEC);
    if (state->fd < 0) throw std::runtime_error("cannot open mass-storage backing_file '" + state->path + "': " + std::strerror(errno) + "; create it first with scripts/create-msd-image.py");
    struct stat st{};
    if (::fstat(state->fd, &st) < 0) throw std::runtime_error("fstat mass-storage backing file failed: " + std::string(std::strerror(errno)));
    if (!S_ISREG(st.st_mode) || st.st_size <= 0 || (static_cast<std::uint64_t>(st.st_size) % state->block_size) != 0)
        throw std::runtime_error("mass-storage backing file must be a non-empty regular file whose size is a multiple of block_size");
    state->block_count = static_cast<std::uint64_t>(st.st_size) / state->block_size;
    std::cout << "MSC BOT: backing file=" << state->path << ", blocks=" << state->block_count
              << ", block_size=" << state->block_size << ", read_only=" << (state->read_only ? "yes" : "no") << "\n";
    return state;
}

std::vector<std::uint8_t> get_interface_report_descriptor(const CompiledProfile& profile,
                                                          std::uint8_t type, std::uint8_t index,
                                                          std::uint16_t w_index,
                                                          std::uint8_t active_config) {
    if (type == 0x22 && profile.source.contains("interface_descriptors") &&
        profile.source.at("interface_descriptors").is_object()) {
        const auto& m = profile.source.at("interface_descriptors");
        const auto exact = interface_key(active_config, w_index);
        if (m.contains(exact)) return parse_hex_bytes(m.at(exact).as_string());
        const auto fallback = std::to_string(w_index);
        if (m.contains(fallback)) return parse_hex_bytes(m.at(fallback).as_string());
    }
    return get_descriptor(profile, type, index, w_index);
}

std::vector<std::uint8_t> configured_in_payload(const Json& root, std::uint8_t address) {
    if (!root.contains("endpoint_io") || !root.at("endpoint_io").is_object() ||
        !root.at("endpoint_io").contains("in_payloads")) return {};
    const auto& payloads=root.at("endpoint_io").at("in_payloads");
    if(!payloads.is_object()) return {};
    for(const auto& [k,v]:payloads.as_object()) {
        try { if(std::stoul(k,nullptr,0)==address) return parse_hex_bytes(v.as_string()); } catch(...) {}
    }
    return {};
}

std::vector<std::uint8_t> configured_interface_in_payload(const Json& root, std::uint8_t configuration,
                                                            std::uint16_t iface, std::uint8_t address) {
    if(root.contains("runtime") && root.at("runtime").is_object() && root.at("runtime").contains("interfaces") && root.at("runtime").at("interfaces").is_array()) {
        for(const auto& item:root.at("runtime").at("interfaces").as_array()) {
            if(field_u(item,"configuration_value",1)!=configuration || field_u(item,"interface_number",0)!=iface) continue;
            if(field_u(item,"interrupt_in_endpoint",0)==address && item.contains("interrupt_in_payload_hex"))
                return parse_hex_bytes(item.at("interrupt_in_payload_hex").as_string());
        }
    }
    return configured_in_payload(root,address);
}

bool configured_repeat_in(const Json& root, std::uint8_t address, bool default_value) {
    if(root.contains("endpoint_io") && root.at("endpoint_io").is_object() && root.at("endpoint_io").contains("repeat_in_addresses") && root.at("endpoint_io").at("repeat_in_addresses").is_array()) {
        for(const auto& value:root.at("endpoint_io").at("repeat_in_addresses").as_array())
            if(value.as_u64(0)==address) return true;
        return false;
    }
    return default_value;
}

std::uint32_t read_le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
std::uint32_t read_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
std::uint16_t read_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(p[0]) << 8) | p[1]);
}
void append_be32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 24)); b.push_back(static_cast<std::uint8_t>(v >> 16));
    b.push_back(static_cast<std::uint8_t>(v >> 8)); b.push_back(static_cast<std::uint8_t>(v));
}
void append_le32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v)); b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v >> 16)); b.push_back(static_cast<std::uint8_t>(v >> 24));
}

void set_sense(MassStorageState& s, std::uint8_t key, std::uint8_t asc, std::uint8_t ascq=0) {
    std::lock_guard<std::mutex> lock(s.mutex);
    s.sense_key=key; s.sense_asc=asc; s.sense_ascq=ascq;
}

bool send_endpoint_bytes(int fd, EndpointHandle* ep, const std::vector<std::uint8_t>& bytes,
                         TraceLogger& trace, const std::string& event_name) {
    if (bytes.empty()) return true;
    std::vector<std::uint8_t> mem(sizeof(usb_raw_ep_io) + bytes.size());
    auto* io=reinterpret_cast<usb_raw_ep_io*>(mem.data());
    io->ep=static_cast<__u16>(ep->handle); io->flags=0; io->length=static_cast<__u32>(bytes.size());
    std::copy(bytes.begin(),bytes.end(),io->data);
    int rc=ioctl(fd,USB_RAW_IOCTL_EP_WRITE,io);
    if(rc<0) {
        if(ep->stop.load() || errno==ESHUTDOWN || errno==EINTR) return false;
        Json e=Json::Object{};e["endpoint_address"]=ep->address;e["errno"]=errno;e["message"]=std::strerror(errno);e["requested_length"]=bytes.size();
        trace.event(event_name+"_ERROR","ACTIVE",e);return false;
    }
    Json e=Json::Object{};e["endpoint_address"]=ep->address;e["requested_length"]=bytes.size();e["actual_length"]=rc;
    e["status"]=(static_cast<std::size_t>(rc)==bytes.size())?"completed":"short";
    if(bytes.size()<=256) e["payload_hex"]=hex_bytes(bytes);
    else { const auto preview=std::vector<std::uint8_t>(bytes.begin(),bytes.begin()+64);e["payload_preview_hex"]=hex_bytes(preview);e["payload_truncated"]=true; }
    trace.event(event_name,"ACTIVE",e);
    return static_cast<std::size_t>(rc)==bytes.size();
}

bool read_endpoint_exact(int fd, EndpointHandle* ep, std::size_t wanted,
                         std::vector<std::uint8_t>& out, TraceLogger& trace,
                         const std::string& tag) {
    out.clear(); out.reserve(wanted);
    while(out.size()<wanted && !ep->stop.load()) {
        const auto remain=wanted-out.size(); const auto ask=std::min<std::size_t>(remain,65536);
        std::vector<std::uint8_t> mem(sizeof(usb_raw_ep_io)+std::max<std::size_t>(ask,1));
        auto* io=reinterpret_cast<usb_raw_ep_io*>(mem.data());io->ep=static_cast<__u16>(ep->handle);io->flags=0;io->length=static_cast<__u32>(ask);
        int rc=ioctl(fd,USB_RAW_IOCTL_EP_READ,io);
        if(rc<0) {
            if(ep->stop.load()||errno==ESHUTDOWN||errno==EINTR)return false;
            Json e=Json::Object{};e["endpoint_address"]=ep->address;e["errno"]=errno;e["message"]=std::strerror(errno);e["wanted"]=wanted;e["received"]=out.size();
            trace.event(tag+"_ERROR","ACTIVE",e);return false;
        }
        if(rc==0) break;
        const auto got=static_cast<std::size_t>(std::min<int>(rc,static_cast<int>(ask)));
        out.insert(out.end(),io->data,io->data+got);
    }
    return out.size()==wanted;
}

void mass_storage_bot_loop(int fd, EndpointHandle* out_ep, std::size_t out_limit,
                           TraceLogger* trace) {
    auto* storage=out_ep->mass_storage;
    auto* in_ep=out_ep->companion;
    if(!storage || !in_ep) return;
    constexpr std::size_t CBW_LENGTH=31;
        constexpr std::uint32_t CBW_SIGNATURE=0x43425355u; // bytes "USBC"
    constexpr std::uint32_t CSW_SIGNATURE=0x53425355u; // bytes "USBS"
    out_limit=std::clamp<std::size_t>(out_limit, storage->block_size, 65536);
    while(!out_ep->stop.load()) {
        std::vector<std::uint8_t> cbw;
        if(!read_endpoint_exact(fd,out_ep,CBW_LENGTH,cbw,*trace,"MSC_CBW_READ")) {
            if(!out_ep->stop.load()) {
                Json e=Json::Object{};e["endpoint_address"]=out_ep->address;e["received_bytes"]=cbw.size();e["expected_bytes"]=CBW_LENGTH;
                trace->event("MSC_INVALID_CBW","ACTIVE",e);
            }
            continue;
        }
        const auto sig=read_le32(cbw.data());
        if(sig!=CBW_SIGNATURE || (cbw[12]&0x7fu)!=0 || cbw[13]>15 || cbw[14]==0 || cbw[14]>16) {
            Json e=Json::Object{};e["endpoint_address"]=out_ep->address;e["signature"]=sig;e["tag"]=read_le32(cbw.data()+4);e["command_length"]=cbw[14];
            trace->event("MSC_INVALID_CBW","ACTIVE",e);
            std::uint32_t hi=in_ep->handle,ho=out_ep->handle;
            (void)ioctl(fd,USB_RAW_IOCTL_EP_SET_HALT,&hi);(void)ioctl(fd,USB_RAW_IOCTL_EP_SET_HALT,&ho);
            continue;
        }
        const std::uint32_t tag=read_le32(cbw.data()+4);
        const std::uint32_t transfer_length=read_le32(cbw.data()+8);
        const bool host_in=(cbw[12]&0x80u)!=0;
        const std::uint8_t opcode=cbw[15];
        Json seen=Json::Object{};seen["tag"]=tag;seen["transfer_length"]=transfer_length;seen["direction"]=host_in?"IN":"OUT";seen["opcode"]=opcode;seen["cdb_hex"]=hex_bytes(std::vector<std::uint8_t>(cbw.begin()+15,cbw.begin()+15+cbw[14]));
        trace->event("MSC_CBW_RECEIVED","CONFIGURED",seen);

        std::vector<std::uint8_t> data;
        std::uint8_t csw_status=0;
        std::uint32_t data_transferred=0;
        bool do_write=false;
        std::uint64_t lba=0; std::uint64_t block_count=0;
        const auto* cdb=cbw.data()+15;
        const auto expected_for_blocks=[&](std::uint64_t n)->std::uint64_t {
            if(n>std::numeric_limits<std::uint64_t>::max()/storage->block_size)return std::numeric_limits<std::uint64_t>::max();
            return n*storage->block_size;
        };
        switch(opcode) {
            case 0x00: // TEST UNIT READY
                break;
            case 0x12: { // INQUIRY, standard 36-byte response
                data={0x00,0x80,0x05,0x02,0x1f,0x00,0x00,0x00};
                const std::string vendor="USB LAB ";const std::string product="Virtual Disk    ";const std::string rev="0001";
                data.insert(data.end(),vendor.begin(),vendor.end());data.insert(data.end(),product.begin(),product.end());data.insert(data.end(),rev.begin(),rev.end());
                data.resize(std::min<std::size_t>(data.size(),cdb[4])); break;
            }
            case 0x03: { // REQUEST SENSE
                std::uint8_t sk=0,asc=0,ascq=0;{std::lock_guard<std::mutex> lock(storage->mutex);sk=storage->sense_key;asc=storage->sense_asc;ascq=storage->sense_ascq;storage->sense_key=storage->sense_asc=storage->sense_ascq=0;}
                data.assign(18,0);data[0]=0x70;data[2]=sk;data[7]=10;data[12]=asc;data[13]=ascq;data.resize(std::min<std::size_t>(data.size(),cdb[4]));break;
            }
            case 0x1a: { // MODE SENSE(6)
                data={0x03,0x00,static_cast<std::uint8_t>(storage->read_only?0x80:0x00),0x00};data.resize(std::min<std::size_t>(data.size(),cdb[4]));break;
            }
            case 0x5a: { // MODE SENSE(10)
                data={0x00,0x06,0x00,static_cast<std::uint8_t>(storage->read_only?0x80:0x00),0,0,0,0};
                const auto n=read_be16(cdb+7);data.resize(std::min<std::size_t>(data.size(),n));break;
            }
            case 0x23: { // READ FORMAT CAPACITIES
                data.assign(12,0);data[3]=8;const auto capped=static_cast<std::uint32_t>(std::min<std::uint64_t>(storage->block_count,0xffffffffu));data[4]=static_cast<std::uint8_t>(capped>>24);data[5]=static_cast<std::uint8_t>(capped>>16);data[6]=static_cast<std::uint8_t>(capped>>8);data[7]=static_cast<std::uint8_t>(capped);data[8]=0x02;data[9]=static_cast<std::uint8_t>(storage->block_size>>16);data[10]=static_cast<std::uint8_t>(storage->block_size>>8);data[11]=static_cast<std::uint8_t>(storage->block_size);break;
            }
            case 0x25: { // READ CAPACITY(10)
                data.clear();append_be32(data,static_cast<std::uint32_t>(std::min<std::uint64_t>(storage->block_count?storage->block_count-1:0,0xffffffffu)));append_be32(data,storage->block_size);break;
            }
            case 0x9e: { // SERVICE ACTION IN(16), READ CAPACITY(16)
                if((cdb[1]&0x1fu)!=0x10u){csw_status=1;set_sense(*storage,0x05,0x20);break;}
                data.assign(32,0);const auto last=storage->block_count?storage->block_count-1:0;for(int i=0;i<8;++i)data[7-i]=static_cast<std::uint8_t>(last>>(i*8));data[8]=static_cast<std::uint8_t>(storage->block_size>>24);data[9]=static_cast<std::uint8_t>(storage->block_size>>16);data[10]=static_cast<std::uint8_t>(storage->block_size>>8);data[11]=static_cast<std::uint8_t>(storage->block_size);data.resize(std::min<std::size_t>(data.size(),read_be32(cdb+10)));break;
            }
            case 0x1b: // START STOP UNIT
            case 0x1e: // PREVENT/ALLOW MEDIUM REMOVAL
            case 0x35: // SYNCHRONIZE CACHE(10)
                if(opcode==0x35 && ::fsync(storage->fd)<0){csw_status=1;set_sense(*storage,0x04,0x44);}break;
            case 0x28: case 0xa8: case 0x88: { // READ(10/12/16)
                if(opcode==0x28){lba=read_be32(cdb+2);block_count=read_be16(cdb+7);}else if(opcode==0xa8){lba=read_be32(cdb+2);block_count=read_be32(cdb+6);}else{for(int i=0;i<8;++i)lba=(lba<<8)|cdb[2+i];block_count=read_be32(cdb+10);}
                const auto need=expected_for_blocks(block_count);const auto offset=lba*static_cast<std::uint64_t>(storage->block_size);
                if(lba>storage->block_count || block_count>storage->block_count-lba || need>16*1024*1024 || need>transfer_length || !host_in || offset>static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())){csw_status=1;set_sense(*storage,0x05,0x21);break;}
                data.resize(static_cast<std::size_t>(need));std::size_t done=0;while(done<data.size()){ssize_t n=::pread(storage->fd,data.data()+done,data.size()-done,static_cast<off_t>(offset+done));if(n<=0)break;done+=static_cast<std::size_t>(n);}data.resize(done);if(done!=need){csw_status=1;set_sense(*storage,0x03,0x11);}break;
            }
            case 0x2a: case 0xaa: case 0x8a: { // WRITE(10/12/16)
                if(opcode==0x2a){lba=read_be32(cdb+2);block_count=read_be16(cdb+7);}else if(opcode==0xaa){lba=read_be32(cdb+2);block_count=read_be32(cdb+6);}else{for(int i=0;i<8;++i)lba=(lba<<8)|cdb[2+i];block_count=read_be32(cdb+10);}
                const auto need=expected_for_blocks(block_count);const auto offset=lba*static_cast<std::uint64_t>(storage->block_size);
                if(host_in || need!=transfer_length || need>16*1024*1024 || lba>storage->block_count || block_count>storage->block_count-lba || storage->read_only || offset>static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())){csw_status=1;set_sense(*storage,storage->read_only?0x07:0x05,storage->read_only?0x27:0x21);break;}
                do_write=true;break;
            }
            case 0xa0: { // REPORT LUNS: one LUN, 8-byte list header+entry
                data.assign(16,0);data[3]=8;data.resize(std::min<std::size_t>(data.size(),read_be32(cdb+6)));break;
            }
            default:
                csw_status=1;set_sense(*storage,0x05,0x20);break;
        }

        if(do_write) {
            std::vector<std::uint8_t> payload;
            const auto need=static_cast<std::size_t>(expected_for_blocks(block_count));
            if(read_endpoint_exact(fd,out_ep,need,payload,*trace,"MSC_WRITE_DATA")) {
                const auto offset=lba*static_cast<std::uint64_t>(storage->block_size);
                std::size_t done=0;while(done<payload.size()){ssize_t n=::pwrite(storage->fd,payload.data()+done,payload.size()-done,static_cast<off_t>(offset+done));if(n<=0)break;done+=static_cast<std::size_t>(n);}
                data_transferred=static_cast<std::uint32_t>(done);
                if(done!=payload.size()){csw_status=1;set_sense(*storage,0x03,0x0c);}
            } else {csw_status=1;set_sense(*storage,0x0b,0x47);}
        } else if(host_in && transfer_length>0 && !data.empty() && csw_status==0) {
            if(data.size()>transfer_length)data.resize(transfer_length);
            if(!send_endpoint_bytes(fd,in_ep,data,*trace,"MSC_DATA_IN")) { if(out_ep->stop.load())break; csw_status=1; }
            else data_transferred=static_cast<std::uint32_t>(data.size());
        } else if(!host_in && transfer_length>0 && opcode!=0x2a && opcode!=0xaa && opcode!=0x8a) {
            // BOT commands with unexpected OUT payload are unsupported by this simple target.
            csw_status=1;set_sense(*storage,0x05,0x24);
        }
        const auto residue=transfer_length>=data_transferred?transfer_length-data_transferred:0;
        std::vector<std::uint8_t> csw;append_le32(csw,CSW_SIGNATURE);append_le32(csw,tag);append_le32(csw,residue);csw.push_back(csw_status);
        if(!send_endpoint_bytes(fd,in_ep,csw,*trace,"MSC_CSW_SENT") && out_ep->stop.load())break;
        Json done=Json::Object{};done["tag"]=tag;done["opcode"]=opcode;done["status"]=csw_status;done["data_transferred"]=data_transferred;done["residue"]=residue;
        trace->event("MSC_COMMAND_COMPLETE",csw_status==0?"CONFIGURED":"ERROR",done);
        (void)out_limit;
    }
}

void endpoint_worker_loop(int fd, EndpointHandle* ep, std::size_t out_limit, TraceLogger* trace) {
    if (ep->transfer_type == 1) {
        Json e=Json::Object{}; e["endpoint_address"]=ep->address;
        e["reason"]="isochronous data worker is not enabled in this version";
        trace->event("ENDPOINT_IO_UNSUPPORTED","CONFIGURED",e); return;
    }
    if (ep->mass_storage && !ep->in && ep->companion) {
        mass_storage_bot_loop(fd, ep, out_limit, trace); return;
    }
    if (ep->in) {
        if (ep->loopback) {
            while (!ep->stop.load()) {
                std::vector<std::uint8_t> payload;
                {
                    std::unique_lock<std::mutex> lock(ep->loopback->mutex);
                    ep->loopback->ready.wait_for(lock, std::chrono::milliseconds(100), [&]() {
                        return ep->stop.load() || !ep->loopback->queued.empty();
                    });
                    if (ep->stop.load()) break;
                    if (ep->loopback->queued.empty()) continue;
                    payload=std::move(ep->loopback->queued.front()); ep->loopback->queued.pop_front();
                }
                if (!send_endpoint_bytes(fd, ep, payload, *trace, "CDC_LOOPBACK_IN_COMPLETE")) {
                    if (ep->stop.load()) break;
                }
            }
            return;
        }
        bool once=false;
        while(!ep->stop.load() && (!once || ep->repeat_in)) {
            Json queued=Json::Object{};queued["endpoint_address"]=ep->address;queued["direction"]="device_to_host";queued["payload_hex"]=hex_bytes(ep->in_payload);queued["requested_length"]=ep->in_payload.size();trace->event("DEVICE_IN_TRANSFER_QUEUED","ACTIVE",queued);
            std::vector<std::uint8_t> mem(sizeof(usb_raw_ep_io)+ep->in_payload.size());auto* io=reinterpret_cast<usb_raw_ep_io*>(mem.data());io->ep=static_cast<__u16>(ep->handle);io->flags=0;io->length=static_cast<__u32>(ep->in_payload.size());std::copy(ep->in_payload.begin(),ep->in_payload.end(),io->data);
            int rc=ioctl(fd,USB_RAW_IOCTL_EP_WRITE,io);
            if(rc<0){if(ep->stop.load()||errno==ESHUTDOWN||errno==EINTR)break;Json err=Json::Object{};err["endpoint_address"]=ep->address;err["errno"]=errno;err["message"]=std::strerror(errno);trace->event("DEVICE_IN_TRANSFER_ERROR","ACTIVE",err);break;}
            Json done=Json::Object{};done["endpoint_address"]=ep->address;done["direction"]="device_to_host";done["payload_hex"]=hex_bytes(ep->in_payload);done["requested_length"]=ep->in_payload.size();done["actual_length"]=rc;done["status"]="completed";trace->event("DEVICE_IN_TRANSFER_COMPLETE","ACTIVE",done);once=true;
        }
    } else {
        out_limit=std::clamp<std::size_t>(out_limit,ep->max_packet,std::max<std::size_t>(ep->max_packet,65536));
        while(!ep->stop.load()) {
            std::vector<std::uint8_t> mem(sizeof(usb_raw_ep_io)+out_limit);auto* io=reinterpret_cast<usb_raw_ep_io*>(mem.data());io->ep=static_cast<__u16>(ep->handle);io->flags=0;io->length=static_cast<__u32>(out_limit);
            int rc=ioctl(fd,USB_RAW_IOCTL_EP_READ,io);
            if(rc<0){if(ep->stop.load()||errno==ESHUTDOWN||errno==EINTR)break;Json err=Json::Object{};err["endpoint_address"]=ep->address;err["errno"]=errno;err["message"]=std::strerror(errno);trace->event("HOST_OUT_TRANSFER_ERROR","ACTIVE",err);break;}
            std::vector<std::uint8_t> received;
            if (rc>0) received.assign(io->data,io->data+rc);
            Json event=Json::Object{};event["endpoint_address"]=ep->address;event["requested_length"]=out_limit;event["actual_length"]=rc;event["direction"]="host_to_device";event["status"]="completed";if(rc>0)event["payload_hex"]=hex_bytes(received);trace->event("DEVICE_OUT_TRANSFER_RECEIVED","ACTIVE",event);
            if (ep->loopback && !received.empty()) {
                {
                    std::lock_guard<std::mutex> lock(ep->loopback->mutex);
                    // Bound queued echo data so a host that never reads cannot exhaust RAM.
                    if (ep->loopback->queued.size() < 128) ep->loopback->queued.push_back(received);
                }
                ep->loopback->ready.notify_one();
                Json q=Json::Object{};q["out_endpoint"]=ep->address;q["bytes"]=received.size();trace->event("CDC_LOOPBACK_QUEUED","ACTIVE",q);
            }
        }
    }
}

void disable_endpoints(int fd, std::vector<std::unique_ptr<EndpointHandle>>& endpoints,
                       TraceLogger& trace, bool allow_inactive = false) {
    if (endpoints.empty()) return;

    // Raw Gadget EP_READ/EP_WRITE are blocking and keep an URB queued until
    // completion. Stop every worker first; an UDC reset can already have
    // disabled the endpoint before user space receives RESET/DISCONNECT.
    for (auto& ep : endpoints) ep->stop.store(true);
    for (auto& ep : endpoints) if (ep->loopback) ep->loopback->ready.notify_all();
    for (auto& ep : endpoints) {
        if (ep->worker.joinable())
            (void)pthread_kill(ep->worker.native_handle(), SIGUSR1);
    }
    for (auto& ep : endpoints) {
        if (ep->worker.joinable()) ep->worker.join();
    }

    std::vector<std::string> failures;
    for (auto it = endpoints.rbegin(); it != endpoints.rend(); ++it) {
        const auto handle = (*it)->handle;
        if (ioctl(fd, USB_RAW_IOCTL_EP_DISABLE,
                  static_cast<unsigned long>(handle)) < 0) {
            const int saved_errno = errno;
            Json e = Json::Object{};
            e["endpoint_handle"] = handle;
            e["endpoint_address"] = (*it)->address;
            e["errno"] = saved_errno;
            e["message"] = std::strerror(saved_errno);
            e["workers_joined_first"] = true;
            const bool already_inactive = allow_inactive &&
                (saved_errno == EBUSY || saved_errno == ESHUTDOWN || saved_errno == ENODEV);
            if (already_inactive) {
                e["note"] = "UDC may have already disabled this endpoint during reset/disconnect; treating as inactive";
                trace.event("ENDPOINT_ALREADY_INACTIVE", "RESETTING", e);
            } else {
                trace.event("ENDPOINT_DISABLE_ERROR", "CONFIGURED", e);
                failures.push_back("handle=" + std::to_string(handle) +
                                   " address=" + std::to_string((*it)->address) +
                                   ": " + std::strerror(saved_errno));
            }
        } else {
            Json e = Json::Object{};
            e["endpoint_handle"] = handle;
            e["endpoint_address"] = (*it)->address;
            trace.event("ENDPOINT_DISABLED", "ADDRESSED", e);
        }
    }

    // All workers are joined now. Never reuse their handles after a reset,
    // even if the UDC already disabled them and EP_DISABLE returned EBUSY.
    endpoints.clear();

    if (!failures.empty()) {
        std::ostringstream message;
        message << "Raw Gadget could not disable endpoint(s) after stopping all workers: ";
        for (std::size_t i = 0; i < failures.size(); ++i) {
            if (i) message << "; ";
            message << failures[i];
        }
        throw std::runtime_error(message.str());
    }
}

void enable_config_endpoints(int fd,const CompiledProfile& p,std::uint8_t configuration,
                             std::vector<std::unique_ptr<EndpointHandle>>& handles,
                             TraceLogger& trace, MassStorageState* storage) {
    const Json& cs=p.source.at("configurations");
    const Json* selected=nullptr;
    for(const auto& c:cs.as_array()) if(field_u(c,"bConfigurationValue",1)==configuration){selected=&c;break;}
    if(!selected) throw std::runtime_error("host selected unknown configuration value "+std::to_string(configuration));
    const bool repeat_in=p.source.at("endpoint_io").at("repeat_in").as_bool(false);
    for(const auto& iface:selected->at("interfaces").as_array()) {
        if(field_u(iface,"bAlternateSetting",0)!=0)continue;
        const auto interface_number=static_cast<std::uint16_t>(field_u(iface,"bInterfaceNumber",0));
        for(const auto& ep:iface.at("endpoints").as_array()) {
            auto desc=usb_endpoint_descriptor{};desc.bLength=USB_DT_ENDPOINT_SIZE;desc.bDescriptorType=USB_DT_ENDPOINT;desc.bEndpointAddress=static_cast<__u8>(field_u(ep,"bEndpointAddress",0x81));desc.bmAttributes=static_cast<__u8>(field_u(ep,"bmAttributes",2));auto packet=field_u(ep,"wMaxPacketSize",64);desc.wMaxPacketSize=static_cast<__le16>(packet);desc.bInterval=static_cast<__u8>(field_u(ep,"bInterval",0));
            int h=ioctl(fd,USB_RAW_IOCTL_EP_ENABLE,&desc);if(h<0){Json e=Json::Object{};e["endpoint_address"]=desc.bEndpointAddress;e["errno"]=errno;e["message"]=std::strerror(errno);trace.event("ENDPOINT_ENABLE_ERROR","ENUMERATING",e);throw std::runtime_error("UDC cannot enable endpoint address "+std::to_string(desc.bEndpointAddress)+": "+std::strerror(errno));}
            auto worker=std::make_unique<EndpointHandle>();worker->handle=static_cast<std::uint32_t>(h);worker->address=desc.bEndpointAddress;worker->max_packet=static_cast<std::uint16_t>(packet);worker->in=(desc.bEndpointAddress&USB_DIR_IN)!=0;worker->transfer_type=desc.bmAttributes&USB_ENDPOINT_XFERTYPE_MASK;worker->repeat_in=configured_repeat_in(p.source,worker->address,repeat_in);worker->in_payload=configured_interface_in_payload(p.source,configuration,interface_number,worker->address);
            Json e=Json::Object{};e["endpoint_address"]=desc.bEndpointAddress;e["endpoint_handle"]=h;e["max_packet_size"]=packet;trace.event("ENDPOINT_ENABLED","CONFIGURED",e);
            handles.push_back(std::move(worker));
        }
    }
    // Wire explicitly declared CDC-style bulk loopback pairs only within the active configuration.
    if(p.source.contains("endpoint_io") && p.source.at("endpoint_io").contains("loopback_pairs") && p.source.at("endpoint_io").at("loopback_pairs").is_array()) {
        for(const auto& pair:p.source.at("endpoint_io").at("loopback_pairs").as_array()) {
            const auto out_addr=static_cast<std::uint8_t>(field_u(pair,"out_endpoint",0));
            const auto in_addr=static_cast<std::uint8_t>(field_u(pair,"in_endpoint",0));
            EndpointHandle* out=nullptr;EndpointHandle* in=nullptr;
            for(auto& h:handles){if(h->address==out_addr && !h->in)out=h.get();if(h->address==in_addr && h->in)in=h.get();}
            if(out && in) {
                auto ch=std::make_shared<LoopbackChannel>();out->loopback=ch;in->loopback=ch;out->companion=in;in->companion=out;
                Json e=Json::Object{};e["out_endpoint"]=out_addr;e["in_endpoint"]=in_addr;trace.event("ENDPOINT_LOOPBACK_READY","CONFIGURED",e);
            }
        }
    }
    if(storage && storage->configuration_value==configuration) {
        EndpointHandle* out=nullptr;EndpointHandle* in=nullptr;
        for(auto& h:handles){if(h->address==storage->out_endpoint && !h->in)out=h.get();if(h->address==storage->in_endpoint && h->in)in=h.get();}
        if(!out || !in) throw std::runtime_error("MSC BOT runtime endpoint addresses do not exist in selected configuration");
        if(out->transfer_type!=2 || in->transfer_type!=2) throw std::runtime_error("MSC BOT requires bulk OUT and bulk IN endpoints");
        out->mass_storage=storage;out->companion=in;in->msc_in_endpoint=true;in->companion=out;
        Json e=Json::Object{};e["configuration_value"]=configuration;e["interface_number"]=storage->interface_number;e["in_endpoint"]=storage->in_endpoint;e["out_endpoint"]=storage->out_endpoint;e["blocks"]=storage->block_count;e["block_size"]=storage->block_size;
        trace.event("MSC_BOT_READY","CONFIGURED",e);
    }
}

void start_endpoint_workers(int fd,
                            std::vector<std::unique_ptr<EndpointHandle>>& endpoints,
                            std::size_t out_limit, TraceLogger& trace) {
    for (auto& worker : endpoints) {
        if (worker->worker.joinable()) continue;
        if (worker->msc_in_endpoint) {
            continue; // The BOT bulk-OUT worker serializes data-IN and CSW transfers.
        }
        if (!worker->in || worker->loopback || !worker->in_payload.empty()) {
            auto* ptr = worker.get();
            ptr->worker = std::thread([fd, ptr, out_limit, &trace]() {
                endpoint_worker_loop(fd, ptr, out_limit, &trace);
            });
        } else {
            Json no = Json::Object{};
            no["endpoint_address"] = worker->address;
            no["reason"] = "no endpoint_io.in_payloads entry for this IN endpoint; it is enabled but no IN request is queued";
            trace.event("ENDPOINT_IN_NO_PAYLOAD", "CONFIGURED", no);
        }
    }
}

void handle_control(int fd,const CompiledProfile& profile,const usb_ctrlrequest& ctrl,std::uint8_t& active_config,
                    std::vector<std::unique_ptr<EndpointHandle>>& endpoints,TraceLogger& trace,
                    RuntimeControlState& control_state, MassStorageState* storage) {
    const std::uint8_t rt=ctrl.bRequestType, req=ctrl.bRequest; const std::uint16_t val=le16(ctrl.wValue),idx=le16(ctrl.wIndex),len=le16(ctrl.wLength); const bool in=(rt&USB_DIR_IN)!=0;
    Json reqj=Json::Object{};reqj["bmRequestType"]=rt;reqj["bRequest"]=req;reqj["wValue"]=val;reqj["wIndex"]=idx;reqj["wLength"]=len;reqj["direction"]=in?"device_to_host":"host_to_device";
    Json ej=Json::Object{};ej["request"]=reqj;ej["requested_length"]=len;trace.event("CONTROL_REQUEST","ENUMERATING",ej);
    const bool class_interface = ((rt & USB_TYPE_MASK)==USB_TYPE_CLASS) && ((rt & USB_RECIP_MASK)==USB_RECIP_INTERFACE);
    const Json* runtime = class_interface ? runtime_interface(profile.source, active_config, idx) : nullptr;
    if (runtime) {
        const std::string klass=runtime->at("class").as_string("");
        const auto key=interface_key(active_config,idx);
        // CDC ACM class requests used by Windows and common terminal software.
        if (klass=="cdc-acm") {
            if (req==0x21 && in) { // GET_LINE_CODING
                auto it=control_state.cdc_line_coding.find(key);
                if(it==control_state.cdc_line_coding.end()) it=control_state.cdc_line_coding.emplace(key,std::vector<std::uint8_t>{0x00,0xc2,0x01,0x00,0x00,0x00,0x08}).first;
                Json e=Json::Object{};e["interface_number"]=idx;e["baud_rate"]="115200 (default unless changed by host)";trace.event("CDC_GET_LINE_CODING","CONFIGURED",e);
                transact_ep0(fd,true,it->second,len,trace,reqj);return;
            }
            if (req==0x20 && !in) { // SET_LINE_CODING
                auto got=transact_ep0(fd,false,{},len,trace,reqj);
                if(got.size()==7) control_state.cdc_line_coding[key]=got;
                Json e=Json::Object{};e["interface_number"]=idx;e["payload_hex"]=hex_bytes(got);
                if(got.size()==7)e["baud_rate"]=read_le32(got.data());
                trace.event("CDC_SET_LINE_CODING","CONFIGURED",e);return;
            }
            if (req==0x22 && !in) { // SET_CONTROL_LINE_STATE
                transact_ep0(fd,false,{},len,trace,reqj);Json e=Json::Object{};e["interface_number"]=idx;e["dtr"]=(val&1)!=0;e["rts"]=(val&2)!=0;e["wValue"]=val;trace.event("CDC_SET_CONTROL_LINE_STATE","CONFIGURED",e);return;
            }
            if (req==0x23 && !in) { // SEND_BREAK
                transact_ep0(fd,false,{},len,trace,reqj);Json e=Json::Object{};e["interface_number"]=idx;e["duration_ms"]=val;trace.event("CDC_SEND_BREAK","CONFIGURED",e);return;
            }
        }
        // HID class requests. The default reports are neutral (no key press, no mouse motion).
        if (klass=="hid") {
            if (req==0x01 && in) { // GET_REPORT
                std::vector<std::uint8_t> report;
                if(runtime->contains("control_report_hex")) report=parse_hex_bytes(runtime->at("control_report_hex").as_string());
                else if(runtime->contains("interrupt_in_endpoint")) report=configured_in_payload(profile.source,static_cast<std::uint8_t>(field_u(*runtime,"interrupt_in_endpoint",0x81)));
                if(report.empty() && len>0){ioctl(fd,USB_RAW_IOCTL_EP0_STALL);Json e=Json::Object{};e["request"]=reqj;e["reason"]="HID GET_REPORT has no configured neutral/control report";trace.event("CONTROL_STALL","ENUMERATING",e);return;}
                Json e=Json::Object{};e["interface_number"]=idx;e["report_type"]=(val>>8)&0xff;e["report_id"]=val&0xff;trace.event("HID_GET_REPORT","CONFIGURED",e);transact_ep0(fd,true,report,len,trace,reqj);return;
            }
            if (req==0x02 && in) { // GET_IDLE
                const std::uint8_t value=control_state.hid_idle.contains(key)?control_state.hid_idle[key]:static_cast<std::uint8_t>(0);
                Json e=Json::Object{};e["interface_number"]=idx;e["duration"]=value;trace.event("HID_GET_IDLE","CONFIGURED",e);transact_ep0(fd,true,{value},len,trace,reqj);return;
            }
            if (req==0x03 && in) { // GET_PROTOCOL
                auto it=control_state.hid_protocol.find(key);
                if(it==control_state.hid_protocol.end()) it=control_state.hid_protocol.emplace(key,(runtime->contains("boot_protocol") && runtime->at("boot_protocol").as_bool(false))?1:0).first;
                Json e=Json::Object{};e["interface_number"]=idx;e["protocol"]=it->second;trace.event("HID_GET_PROTOCOL","CONFIGURED",e);transact_ep0(fd,true,{it->second},len,trace,reqj);return;
            }
            if (req==0x09 && !in) { // SET_REPORT
                auto got=transact_ep0(fd,false,{},len,trace,reqj);Json e=Json::Object{};e["interface_number"]=idx;e["report_type"]=(val>>8)&0xff;e["report_id"]=val&0xff;e["payload_hex"]=hex_bytes(got);trace.event("HID_SET_REPORT","CONFIGURED",e);return;
            }
            if (req==0x0a && !in) { // SET_IDLE
                const auto duration=static_cast<std::uint8_t>(val>>8);control_state.hid_idle[key]=duration;
                transact_ep0(fd,false,{},len,trace,reqj);Json e=Json::Object{};e["interface_number"]=idx;e["duration"]=duration;e["report_id"]=val&0xff;trace.event("HID_SET_IDLE","CONFIGURED",e);return;
            }
            if (req==0x0b && !in) { // SET_PROTOCOL
                const auto proto=static_cast<std::uint8_t>(val&0xff);control_state.hid_protocol[key]=proto;
                transact_ep0(fd,false,{},len,trace,reqj);Json e=Json::Object{};e["interface_number"]=idx;e["protocol"]=proto;trace.event("HID_SET_PROTOCOL","CONFIGURED",e);return;
            }
        }
        if (klass=="msc-bot" && req==0xfe && in) { // GET_MAX_LUN: only LUN 0 is implemented
            Json e=Json::Object{};e["interface_number"]=idx;e["max_lun"]=0;trace.event("MSC_GET_MAX_LUN","CONFIGURED",e);
            transact_ep0(fd,true,{static_cast<std::uint8_t>(0)},len,trace,reqj);return;
        }
        if (klass=="msc-bot" && req==0xff && !in) { // Bulk-Only Mass Storage Reset
            transact_ep0(fd,false,{},len,trace,reqj);
            if(storage){std::lock_guard<std::mutex> lock(storage->mutex);storage->sense_key=storage->sense_asc=storage->sense_ascq=0;}
            Json e=Json::Object{};e["interface_number"]=idx;e["note"]="BOT reset acknowledged; host should clear endpoint halts as required";trace.event("MSC_BOT_RESET","CONFIGURED",e);return;
        }
    }
    std::vector<std::uint8_t> response;
    if(in) {
        if((rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_GET_DESCRIPTOR) response=get_interface_report_descriptor(profile,static_cast<std::uint8_t>(val>>8),static_cast<std::uint8_t>(val&0xff),idx,active_config);
        else if((rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_GET_CONFIGURATION) response={active_config};
        else if((rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_GET_STATUS) response={0,0};
        else if((rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_GET_INTERFACE) response={0};
        else response=match_custom_response(profile.source,ctrl);
        if(response.empty() && len>0){ioctl(fd,USB_RAW_IOCTL_EP0_STALL);Json e=Json::Object{};e["request"]=reqj;e["reason"]="no response configured";trace.event("CONTROL_STALL","ENUMERATING",e);return;}
        try{transact_ep0(fd, true, response, len, trace, reqj);}catch(const std::exception& e){Json x=Json::Object{};x["error"]=e.what();trace.event("CONTROL_RESPONSE_ERROR","ENUMERATING",x);throw;}
    } else {
        const bool standard_endpoint_halt = ((rt & USB_TYPE_MASK)==USB_TYPE_STANDARD) &&
            ((rt & USB_RECIP_MASK)==USB_RECIP_ENDPOINT) && (val==USB_ENDPOINT_HALT) &&
            (req==USB_REQ_CLEAR_FEATURE || req==USB_REQ_SET_FEATURE);
        if (standard_endpoint_halt) {
            const auto address=static_cast<std::uint8_t>(idx & 0xffu);
            auto it=std::find_if(endpoints.begin(),endpoints.end(),[&](const auto& ep){return ep->address==address;});
            bool ok=false;
            if(it!=endpoints.end()) {
                const auto h=static_cast<unsigned long>((*it)->handle);
                const int rc=ioctl(fd,req==USB_REQ_CLEAR_FEATURE?USB_RAW_IOCTL_EP_CLEAR_HALT:USB_RAW_IOCTL_EP_SET_HALT,h);
                ok=(rc==0);
                if(!ok) {Json e=Json::Object{};e["endpoint_address"]=address;e["errno"]=errno;e["message"]=std::strerror(errno);trace.event("ENDPOINT_HALT_REQUEST_ERROR","CONFIGURED",e);}
            }
            std::vector<std::uint8_t> payload;
            try { (void)transact_ep0(fd,false,{},len,trace,reqj); } catch(const std::exception& e){Json x=Json::Object{};x["error"]=e.what();trace.event("CONTROL_OUT_ERROR","ENUMERATING",x);throw;}
            Json e=Json::Object{};e["endpoint_address"]=address;e["action"]=req==USB_REQ_CLEAR_FEATURE?"clear_halt":"set_halt";e["endpoint_found"]=it!=endpoints.end();e["ioctl_succeeded"]=ok;trace.event("ENDPOINT_HALT_REQUEST","CONFIGURED",e);return;
        }
        const bool set_config=(rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_SET_CONFIGURATION;
        const std::uint8_t requested_config=static_cast<std::uint8_t>(val&0xff);
        if(set_config) {
            // SET_CONFIGURATION can follow a DWC2 reset event. In that case the
            // UDC may have disabled old endpoints before user space fetched the
            // event; stale handles are safe to discard after all workers stop.
            disable_endpoints(fd, endpoints, trace, true);
            if(requested_config!=0) {
                enable_config_endpoints(fd,profile,requested_config,endpoints,trace,storage);
                check_ioctl(fd,USB_RAW_IOCTL_CONFIGURE,nullptr,"USB_RAW_IOCTL_CONFIGURE");
            }
        }
        std::vector<std::uint8_t> payload;
        try { payload=transact_ep0(fd, false, {}, len, trace, reqj); } catch(const std::exception& e){Json x=Json::Object{};x["error"]=e.what();trace.event("CONTROL_OUT_ERROR","ENUMERATING",x);throw;}
        if(set_config) {
            active_config=requested_config;
            Json e=Json::Object{};e["configuration_value"]=requested_config;
            trace.event("SET_CONFIGURATION",requested_config?"CONFIGURED":"ADDRESSED",e);
            // Do not queue interrupt/Bulk worker requests until the host's
            // SET_CONFIGURATION status stage has completed successfully.
            if (requested_config != 0) {
                const auto out_limit = field_u(profile.source.at("endpoint_io"), "out_buffer_bytes", 16384);
                start_endpoint_workers(fd, endpoints, out_limit, trace);
            }
        } else if((rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_SET_INTERFACE) {
            Json e=Json::Object{};e["interface_number"]=idx;e["alternate_setting"]=val;trace.event("SET_INTERFACE_OBSERVED","CONFIGURED",e);
        } else if((rt&USB_TYPE_MASK)==USB_TYPE_STANDARD && req==USB_REQ_SET_ADDRESS) {
            Json e=Json::Object{};e["address"]=val;trace.event("SET_ADDRESS_OBSERVED","ENUMERATING",e);
        }
    }
}
}
int probe_usb_device_mode(){
    std::cout<<"USB Device/Gadget capability probe (Linux)\n";
    const bool raw=std::filesystem::exists("/dev/raw-gadget");std::cout<<"/dev/raw-gadget: "<<(raw?"present":"not found")<<"\n";
    const std::filesystem::path udcdir("/sys/class/udc");bool found=false;
    if(std::filesystem::exists(udcdir)){for(const auto& e:std::filesystem::directory_iterator(udcdir)){found=true;auto name=e.path().filename().string();std::string driver="(unknown)";{std::ifstream uevent(e.path()/"uevent");std::string line;while(std::getline(uevent,line)){const std::string prefix="USB_UDC_NAME=";if(line.rfind(prefix,0)==0){driver=line.substr(prefix.size());break;}}}std::cout<<"UDC device name: "<<name<<"\n  Raw Gadget driver name from uevent: "<<driver<<"\n  candidate command: sudo ./usb-connect run profiles/valid/minimal-device.json --backend raw-gadget --udc-driver '"<<driver<<"' --udc-device '"<<name<<"' --trace runs/test-001/device.jsonl\n";}}
    if(!found)std::cout<<"No controller found under /sys/class/udc. Confirm USB-C device mode, DWC2 configuration, and kernel UDC driver.\n";
    if(!raw)std::cout<<"Raw Gadget missing. Kernel must support CONFIG_USB_RAW_GADGET and expose /dev/raw-gadget.\n";
    return (raw&&found)?0:2;
}
int run_raw_gadget(const RawGadgetOptions& o,const CompiledProfile& profile){
    if(!std::filesystem::exists("/dev/raw-gadget"))throw std::runtime_error("/dev/raw-gadget is absent; kernel/module must enable CONFIG_USB_RAW_GADGET");
    if(o.udc_driver.empty()||o.udc_device.empty())throw std::runtime_error("pass both --udc-driver and --udc-device; run usb-connect probe to inspect UDC");
    int speed=USB_SPEED_HIGH;if(o.speed=="full")speed=USB_SPEED_FULL;else if(o.speed=="low")speed=USB_SPEED_LOW;else if(o.speed!="high")throw std::runtime_error("speed must be high, full or low");
    auto storage = open_mass_storage(profile);
    RuntimeControlState control_state;
    TraceLogger trace(o.trace_path,o.run_id,"raspberry_pi"); Json start=Json::Object{};start["profile_name"]=profile.name;start["backend"]="raw-gadget";start["udc_driver"]=o.udc_driver;start["udc_device"]=o.udc_device;start["speed"]=o.speed;start["research_mode"]=profile.research_mode;trace.event("BACKEND_STARTING","BACKEND_READY",start);
    int fd=open("/dev/raw-gadget",O_RDWR);if(fd<0)throw std::runtime_error(std::string("open /dev/raw-gadget failed: ")+std::strerror(errno));
    std::vector<std::unique_ptr<EndpointHandle>> endpoints;
    try {
        usb_raw_init init{};std::strncpy(reinterpret_cast<char*>(init.driver_name),o.udc_driver.c_str(),sizeof(init.driver_name)-1);std::strncpy(reinterpret_cast<char*>(init.device_name),o.udc_device.c_str(),sizeof(init.device_name)-1);init.speed=static_cast<__u8>(speed);
        check_ioctl(fd,USB_RAW_IOCTL_INIT,&init,"USB_RAW_IOCTL_INIT");check_ioctl(fd,USB_RAW_IOCTL_RUN,nullptr,"USB_RAW_IOCTL_RUN");
        struct sigaction sa{};sa.sa_handler=on_signal;sigemptyset(&sa.sa_mask);sa.sa_flags=0;sigaction(SIGINT,&sa,nullptr);sigaction(SIGTERM,&sa,nullptr);
        struct sigaction worker_interrupt{};worker_interrupt.sa_handler=on_worker_interrupt;sigemptyset(&worker_interrupt.sa_mask);worker_interrupt.sa_flags=0;sigaction(SIGUSR1,&worker_interrupt,nullptr);
        trace.event("BACKEND_RUNNING","BACKEND_READY");std::uint8_t active_config=0;std::cout<<"Raw Gadget running. Press Ctrl+C to stop. Trace: "<<o.trace_path<<"\n";
        while(!stop_requested){alignas(8) std::array<std::uint8_t,256> buf{};auto* ev=reinterpret_cast<usb_raw_event*>(buf.data());ev->length=buf.size()-sizeof(usb_raw_event);int rc=ioctl(fd,USB_RAW_IOCTL_EVENT_FETCH,ev);if(rc<0){if(errno==EINTR&&stop_requested)break;if(errno==EINTR)continue;throw std::runtime_error(std::string("USB_RAW_IOCTL_EVENT_FETCH failed: ")+std::strerror(errno));}
            switch(ev->type){case USB_RAW_EVENT_CONNECT:{trace.event("UDC_BOUND","BACKEND_READY");usb_raw_eps_info eps{};int n=ioctl(fd,USB_RAW_IOCTL_EPS_INFO,&eps);Json e=Json::Object{};e["available_endpoint_count"]=n;if(n>0){Json arr=Json::Array{};for(int i=0;i<std::min(n,USB_RAW_EPS_NUM_MAX);++i){Json x=Json::Object{};x["name"]=reinterpret_cast<const char*>(eps.eps[i].name);x["address"]=eps.eps[i].addr;x["maxpacket_limit"]=eps.eps[i].limits.maxpacket_limit;x["bulk"]=static_cast<bool>(eps.eps[i].caps.type_bulk);x["interrupt"]=static_cast<bool>(eps.eps[i].caps.type_int);x["isochronous"]=static_cast<bool>(eps.eps[i].caps.type_iso);arr.as_array().push_back(std::move(x));}e["endpoints"]=std::move(arr);}trace.event("ENDPOINT_CAPABILITIES","ATTACHED",e);break;}
                case USB_RAW_EVENT_CONTROL:{if(ev->length<sizeof(usb_ctrlrequest)){trace.event("MALFORMED_CONTROL_EVENT","ERROR");break;}usb_ctrlrequest ctrl{};std::memcpy(&ctrl,ev->data,sizeof(ctrl));handle_control(fd,profile,ctrl,active_config,endpoints,trace,control_state,storage.get());break;}
                case USB_RAW_EVENT_SUSPEND:trace.event("USB_SUSPEND","SUSPENDED");break;
                case USB_RAW_EVENT_RESUME:trace.event("USB_RESUME",active_config?"CONFIGURED":"ENUMERATING");break;
                case USB_RAW_EVENT_RESET:{
                    disable_endpoints(fd, endpoints, trace, true);
                    active_config=0;
                    trace.event("USB_RESET","ENUMERATING");
                    break;
                }
                case USB_RAW_EVENT_DISCONNECT:{
                    // The Raw Gadget ABI explicitly documents that DWC2 may
                    // report bus reset as DISCONNECT. Do not declare a physical
                    // cable pull and do not terminate Raw Gadget on this event.
                    Json e=Json::Object{};
                    e["classification"]="reset_or_disconnect";
                    e["note"]="UDC reported USB_RAW_EVENT_DISCONNECT; on DWC2 this may mean bus reset rather than physical cable removal";
                    disable_endpoints(fd, endpoints, trace, true);
                    active_config=0;
                    trace.event("USB_RESET_OR_DISCONNECT","ENUMERATING",e);
                    break;
                }
                default:{Json e=Json::Object{};e["raw_event_type"]=ev->type;trace.event("UNKNOWN_RAW_GADGET_EVENT","UNKNOWN",e);break;}}
        }
        disable_endpoints(fd, endpoints, trace, true);trace.event("BACKEND_STOPPED","DETACHED");close(fd);return 0;
    } catch(...) {
        auto original_error = std::current_exception();
        try {
            disable_endpoints(fd, endpoints, trace, true);
        } catch (const std::exception& cleanup_error) {
            Json e = Json::Object{};
            e["message"] = cleanup_error.what();
            trace.event("BACKEND_CLEANUP_ERROR", "ERROR", e);
        }
        close(fd);
        std::rethrow_exception(original_error);
    }
}
#else
int probe_usb_device_mode(){std::cerr<<"Raw Gadget backend is only available on Linux.\n";return 2;}
int run_raw_gadget(const RawGadgetOptions&,const CompiledProfile&){throw std::runtime_error("Raw Gadget backend is only available on Linux");}
#endif
}
