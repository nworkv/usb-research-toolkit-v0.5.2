#include "usb_research/profile.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>

namespace usb_research {
namespace {
void add(std::vector<ValidationIssue>& v, std::string p, std::string c, std::string m, bool fatal=false) { v.push_back({std::move(p),std::move(c),std::move(m),fatal}); }
std::uint8_t u8(const Json& j,const std::string& f,int d){auto v=field_u(j,f,d); if(v>255) throw std::runtime_error(f+" exceeds uint8 range"); return static_cast<std::uint8_t>(v);}
std::uint16_t u16(const Json& j,const std::string& f,int d){auto v=field_u(j,f,d); if(v>65535) throw std::runtime_error(f+" exceeds uint16 range"); return static_cast<std::uint16_t>(v);}
void le16(std::vector<std::uint8_t>& b, std::uint16_t v){ b.push_back(v&0xff); b.push_back((v>>8)&0xff); }
void utf8_to_utf16le(std::string_view s, std::vector<std::uint8_t>& out) {
    for(std::size_t i=0;i<s.size();) {
        std::uint32_t cp=static_cast<unsigned char>(s[i++]);
        if(cp>=0xF0){ if(i+2>=s.size()) throw std::runtime_error("invalid UTF-8 string"); cp=((cp&7)<<18)|((static_cast<unsigned char>(s[i])&0x3f)<<12)|((static_cast<unsigned char>(s[i+1])&0x3f)<<6)|(static_cast<unsigned char>(s[i+2])&0x3f); i+=3; }
        else if(cp>=0xE0){ if(i+1>=s.size()) throw std::runtime_error("invalid UTF-8 string"); cp=((cp&0xf)<<12)|((static_cast<unsigned char>(s[i])&0x3f)<<6)|(static_cast<unsigned char>(s[i+1])&0x3f); i+=2; }
        else if(cp>=0xC0){ if(i>=s.size()) throw std::runtime_error("invalid UTF-8 string"); cp=((cp&0x1f)<<6)|(static_cast<unsigned char>(s[i])&0x3f); i+=1; }
        if(cp<=0xffff){out.push_back(cp&0xff);out.push_back((cp>>8)&0xff);} else {cp-=0x10000;std::uint16_t hi=0xd800+(cp>>10),lo=0xdc00+(cp&0x3ff);out.push_back(hi&0xff);out.push_back(hi>>8);out.push_back(lo&0xff);out.push_back(lo>>8);}
    }
}
std::vector<std::uint8_t> extras(const Json& obj) { if(!obj.contains("extra_descriptors_hex"))return {}; return parse_hex_bytes(obj.at("extra_descriptors_hex").as_string()); }
std::string pair_key(unsigned a,unsigned b){return std::to_string(a)+":"+std::to_string(b);}
std::uint64_t computed(const Json& obj,const std::string& field,std::uint64_t val,bool auto_calc){bool found=false;auto user=field_u(obj,field,val,found);return (!auto_calc&&found)?user:val;}
std::uint8_t computed8(const Json& obj,const std::string& field,std::uint64_t val,bool auto_calc){auto x=computed(obj,field,val,auto_calc);if(x>255)throw std::runtime_error(field+" exceeds uint8 range");return static_cast<std::uint8_t>(x);}
}
std::uint64_t field_u(const Json& obj,const std::string& n,std::uint64_t d,bool& found) { found=obj.contains(n); if(!found)return d; const auto& j=obj.at(n); if(j.is_string()){auto s=j.as_string(); try { std::size_t idx=0; auto v=std::stoull(s,&idx,0); if(idx==s.size())return v; }catch(...){} } return j.as_u64(d); }
std::uint64_t field_u(const Json& obj,const std::string& n,std::uint64_t d) { bool found=false;return field_u(obj,n,d,found); }
Json ValidationReport::to_json() const { Json o=Json::Object{}; Json a=Json::Array{}; for(const auto& i:issues){Json x=Json::Object{};x["path"]=i.path;x["code"]=i.code;x["message"]=i.message;x["fatal"]=i.fatal;a.as_array().push_back(std::move(x));}o["profile_valid"]=profile_valid;o["backend_compatible"]=backend_compatible;o["issues"]=std::move(a);return o; }

CompiledProfile compile_profile(const Json& p) {
    if(!p.is_object()) throw std::runtime_error("profile root must be a JSON object");
    CompiledProfile out; out.source=p; out.name=p.at("profile_name").as_string("unnamed-device");
    const std::string calc=p.at("validation").at("calculated_fields").as_string("auto"); const bool auto_calc=calc!="manual";
    out.research_mode=p.at("validation").at("mode").as_string("strict")=="research";
    const Json& d=p.at("device"); if(!d.is_object())throw std::runtime_error("profile.device must be an object");
    auto& b=out.device_descriptor;
    b.push_back(computed8(d,"bLength",18,auto_calc));
    b.push_back(computed8(d,"bDescriptorType",1,auto_calc));
    le16(b,u16(d,"bcdUSB",0x0200)); b.push_back(u8(d,"bDeviceClass",0)); b.push_back(u8(d,"bDeviceSubClass",0)); b.push_back(u8(d,"bDeviceProtocol",0)); b.push_back(u8(d,"bMaxPacketSize0",64));
    le16(b,u16(d,"idVendor",0x1209)); le16(b,u16(d,"idProduct",1)); le16(b,u16(d,"bcdDevice",1));
    b.push_back(u8(d,"iManufacturer",1)); b.push_back(u8(d,"iProduct",2)); b.push_back(u8(d,"iSerialNumber",3));
    b.push_back(computed8(d,"bNumConfigurations",p.at("configurations").size(),auto_calc));

    const Json& configs=p.at("configurations");
    if(!configs.is_array()) throw std::runtime_error("profile.configurations must be an array");
    for(const auto& cfg:configs.as_array()) {
        std::vector<std::uint8_t> c; c.push_back(computed8(cfg,"bLength",9,auto_calc)); c.push_back(computed8(cfg,"bDescriptorType",2,auto_calc));
        const std::size_t total_pos=c.size(); le16(c,0);
        std::set<unsigned> interface_nums; for(const auto& iface:cfg.at("interfaces").as_array()) interface_nums.insert(static_cast<unsigned>(field_u(iface,"bInterfaceNumber",0)));
        c.push_back(computed8(cfg,"bNumInterfaces",interface_nums.size(),auto_calc));
        c.push_back(u8(cfg,"bConfigurationValue",1)); c.push_back(u8(cfg,"iConfiguration",0)); c.push_back(u8(cfg,"bmAttributes",0x80)); c.push_back(u8(cfg,"bMaxPower",50));
        auto ce=extras(cfg); c.insert(c.end(),ce.begin(),ce.end());
        const Json& interfaces=cfg.at("interfaces");
        if(interfaces.is_array()) for(const auto& iface:interfaces.as_array()) {
            c.push_back(computed8(iface,"bLength",9,auto_calc)); c.push_back(computed8(iface,"bDescriptorType",4,auto_calc));
            c.push_back(u8(iface,"bInterfaceNumber",0)); c.push_back(u8(iface,"bAlternateSetting",0));
            const auto& eps=iface.at("endpoints").as_array(); c.push_back(computed8(iface,"bNumEndpoints",eps.size(),auto_calc));
            c.push_back(u8(iface,"bInterfaceClass",0xff)); c.push_back(u8(iface,"bInterfaceSubClass",0)); c.push_back(u8(iface,"bInterfaceProtocol",0)); c.push_back(u8(iface,"iInterface",0));
            auto ie=extras(iface); c.insert(c.end(),ie.begin(),ie.end());
            for(const auto& ep:eps) {
                c.push_back(computed8(ep,"bLength",7,auto_calc)); c.push_back(computed8(ep,"bDescriptorType",5,auto_calc));
                c.push_back(u8(ep,"bEndpointAddress",0x81)); c.push_back(u8(ep,"bmAttributes",2)); le16(c,u16(ep,"wMaxPacketSize",64)); c.push_back(u8(ep,"bInterval",0));
                auto ee=extras(ep); c.insert(c.end(),ee.begin(),ee.end());
            }
        }
        if (c.size() > 65535) {
            throw std::runtime_error("constructed configuration descriptor exceeds 65535 bytes");
        }
        const auto total = static_cast<std::uint16_t>(c.size());
        const auto advertised_u = computed(cfg, "wTotalLength", total, auto_calc);
        if (advertised_u > 65535) {
            throw std::runtime_error("wTotalLength exceeds uint16 range");
        }
        const auto advertised = static_cast<std::uint16_t>(advertised_u);
        c[total_pos] = advertised & 0xff;
        c[total_pos + 1] = advertised >> 8;
        out.configuration_descriptors.push_back(std::move(c));
    }
    // USB string descriptor zero contains the supported language IDs.
    std::vector<std::uint8_t> langs{0,3};
    const Json& strings=p.at("strings");
    if(strings.is_object()) for(const auto& [lang,entries]:strings.as_object()) { try { auto id=static_cast<std::uint16_t>(std::stoul(lang,nullptr,0)); le16(langs,id); }catch(...) { throw std::runtime_error("strings language keys must be numeric language IDs, e.g. \"1033\""); } }
    langs[0]=static_cast<std::uint8_t>(langs.size()); out.string_descriptors[{0,0}]=langs;
    if(strings.is_object()) for(const auto& [lang,entries]:strings.as_object()) {
        const auto lang_value=std::stoul(lang,nullptr,0); if(lang_value>65535)throw std::runtime_error("string language ID must fit in 16 bits"); const auto lid=static_cast<std::uint16_t>(lang_value);
        if(!entries.is_object()) continue;
        for(const auto& [idx,txt]:entries.as_object()) {
            std::uint64_t ix=0; try{ix=std::stoull(idx,nullptr,0);}catch(...){throw std::runtime_error("string descriptor indices must be numeric keys");}
            if(ix==0||ix>255)throw std::runtime_error("string descriptor index must be between 1 and 255");
            std::vector<std::uint8_t> bytes{0,3}; utf8_to_utf16le(txt.as_string(),bytes); if(bytes.size()>255)throw std::runtime_error("USB string descriptor exceeds 255 bytes"); bytes[0]=static_cast<std::uint8_t>(bytes.size()); out.string_descriptors[{lid,static_cast<std::uint8_t>(ix)}]=std::move(bytes);
        }
    }
    const Json& raw=p.at("raw_descriptors"); if(raw.is_object()) for(const auto& [key,val]:raw.as_object()) {
        unsigned type=0,index=0; char sep=0; std::istringstream ss(key); if(!(ss>>type>>sep>>index)||sep!=':'||type>255||index>255)throw std::runtime_error("raw_descriptors keys must be 'type:index', e.g. '6:0'"); out.raw_descriptors[{static_cast<std::uint8_t>(type),static_cast<std::uint8_t>(index)}]=parse_hex_bytes(val.as_string());
    }
    return out;
}

ValidationReport validate_profile(const Json& p,const std::string& mode_arg) {
    ValidationReport r; const std::string effective_mode=mode_arg.empty()?p.at("validation").at("mode").as_string("strict"):mode_arg; const bool research=effective_mode=="research"; const std::string calc_mode=p.at("validation").at("calculated_fields").as_string("auto"); const bool manual=calc_mode=="manual";
    auto fatal=[&](std::string path,std::string code,std::string msg){add(r.issues,std::move(path),std::move(code),std::move(msg),true);r.profile_valid=false;};
    auto warn=[&](std::string path,std::string code,std::string msg){add(r.issues,std::move(path),std::move(code),std::move(msg),false);};
    if(!p.is_object()){fatal("$","root_type","Profile root must be an object");return r;}
    if(effective_mode!="strict"&&effective_mode!="research")fatal("validation.mode","invalid_mode","validation mode must be strict or research");
    if(calc_mode!="auto"&&calc_mode!="manual")fatal("validation.calculated_fields","invalid_calculation_policy","calculated_fields must be auto or manual");
    const auto& d=p.at("device"); if(!d.is_object()){fatal("device","required","device must be an object");return r;}
    auto field_check=[&](const Json& obj,const std::string& path,const std::string& name,std::uint64_t expected){if(!obj.contains(name))return;auto val=field_u(obj,name,expected);if(val!=expected){if(research)warn(path+"."+name,"noncanonical_descriptor_field","Research mode preserves a non-canonical descriptor field");else fatal(path+"."+name,"noncanonical_descriptor_field","Field must be "+std::to_string(expected)+" in a standard USB 2.0 descriptor");}};
    field_check(d,"device","bLength",18);field_check(d,"device","bDescriptorType",1);
    const auto vid=field_u(d,"idVendor",0),pid=field_u(d,"idProduct",0),bcd=field_u(d,"bcdUSB",0x0200),mps=field_u(d,"bMaxPacketSize0",64);
    if(manual&&field_u(d,"bNumConfigurations",p.at("configurations").size())!=p.at("configurations").size()){if(research)warn("device.bNumConfigurations","configuration_count_mismatch","Manual bNumConfigurations differs from the number of configurations");else fatal("device.bNumConfigurations","configuration_count_mismatch","Manual bNumConfigurations must match configurations.size()");}
    if(vid==0||vid>65535)fatal("device.idVendor","vid_range","Use a non-zero 16-bit VID assigned/authorized for your project");
    if(pid==0||pid>65535)fatal("device.idProduct","pid_range","PID must be a non-zero 16-bit value");
    if(bcd!=0x0200) { if(research)warn("device.bcdUSB","unusual_usb_version","USB revision differs from the selected USB 2.0 profile"); else fatal("device.bcdUSB","usb_revision","This toolkit profile is for USB 2.0 and expects bcdUSB = 512 (0x0200)"); }
    if(!(mps==8||mps==16||mps==32||mps==64))fatal("device.bMaxPacketSize0","ep0_packet_size","USB 2.0 control endpoint max packet size must be 8, 16, 32 or 64 at full speed; high-speed EP0 uses 64");
    const auto& configs=p.at("configurations"); if(!configs.is_array()){fatal("configurations","configuration_required","configurations must be an array");return r;} if(configs.size()==0)fatal("configurations","configuration_required","At least one configuration is required");
    if(configs.size()>255)fatal("configurations","configuration_count","At most 255 configurations are addressable");
    std::set<unsigned> configuration_values;
    for(std::size_t ci=0;ci<configs.size();++ci){const auto& c=configs[ci];std::string cp="configurations["+std::to_string(ci)+"]";field_check(c,cp,"bLength",9);field_check(c,cp,"bDescriptorType",2);const auto& ifs=c.at("interfaces");if(!ifs.is_array()) {fatal(cp+".interfaces","type","interfaces must be an array");continue;}
        const auto config_value=field_u(c,"bConfigurationValue",ci+1);if(config_value==0||config_value>255)fatal(cp+".bConfigurationValue","configuration_value","bConfigurationValue must be in the range 1..255");if(!configuration_values.insert(static_cast<unsigned>(config_value)).second)fatal(cp+".bConfigurationValue","duplicate_configuration_value","Configuration values must be unique");
        const auto attr=field_u(c,"bmAttributes",0x80); if((attr&0x80)==0)fatal(cp+".bmAttributes","reserved_bit","bmAttributes bit 7 must be set");
        if(field_u(c,"bMaxPower",50)>250)fatal(cp+".bMaxPower","power_range","USB 2.0 bMaxPower is expressed in 2 mA units and must be <= 250");
        std::set<unsigned> nums; std::set<std::pair<unsigned,unsigned>> interface_alternates;
        for(std::size_t ii=0;ii<ifs.size();++ii){const auto& in=ifs[ii];std::string ip=cp+".interfaces["+std::to_string(ii)+"]";field_check(in,ip,"bLength",9);field_check(in,ip,"bDescriptorType",4);unsigned inum=field_u(in,"bInterfaceNumber",ii), alt=field_u(in,"bAlternateSetting",0);if(inum>255||alt>255)fatal(ip,"interface_range","Interface number and alternate setting must fit in 8 bits");nums.insert(inum);if(!interface_alternates.insert({inum,alt}).second)fatal(ip,"duplicate_altsetting","Interface number/alternate-setting pairs must be unique");
            const auto& eps=in.at("endpoints");if(!eps.is_array()){fatal(ip+".endpoints","type","endpoints must be an array");continue;}if(manual&&in.contains("bNumEndpoints")&&field_u(in,"bNumEndpoints",eps.size())!=eps.size()){if(research)warn(ip+".bNumEndpoints","endpoint_count_mismatch","Manual bNumEndpoints differs from the endpoint list for this alternate setting");else fatal(ip+".bNumEndpoints","endpoint_count_mismatch","Manual bNumEndpoints must equal endpoints.size()");}std::set<unsigned> addrs;
            for(std::size_t ei=0;ei<eps.size();++ei){const auto& ep=eps[ei];std::string epth=ip+".endpoints["+std::to_string(ei)+"]";field_check(ep,epth,"bLength",7);field_check(ep,epth,"bDescriptorType",5);unsigned addr=field_u(ep,"bEndpointAddress",0),type=field_u(ep,"bmAttributes",2)&3,packet=field_u(ep,"wMaxPacketSize",64)&0x7ff; if((addr&0x70)!=0)fatal(epth+".bEndpointAddress","endpoint_reserved_bits","Reserved endpoint address bits must be zero");if((addr&0x0f)==0)fatal(epth+".bEndpointAddress","endpoint_zero","Endpoint number 0 is reserved for control transfers");if(addr>255)fatal(epth+".bEndpointAddress","endpoint_range","Address must fit in 8 bits");if(!addrs.insert(addr).second)fatal(epth+".bEndpointAddress","duplicate_endpoint","Duplicate endpoint address in the same alternate setting");if(packet==0)fatal(epth+".wMaxPacketSize","packet_size","Maximum packet size must be non-zero");if(type==0)fatal(epth+".bmAttributes","control_endpoint","Non-default interface endpoints must not use control transfer type");
                if (type == 2 && packet > 512) {
                    fatal(epth + ".wMaxPacketSize", "bulk_packet_size", "USB 2.0 bulk max packet size cannot exceed 512 bytes");
                }
                if (type == 3 && packet > 1024) {
                    fatal(epth + ".wMaxPacketSize", "interrupt_packet_size", "USB 2.0 interrupt max packet size cannot exceed 1024 bytes");
                }
                if (type == 1 && packet > 1024) {
                    fatal(epth + ".wMaxPacketSize", "iso_packet_size", "USB 2.0 isochronous max packet size cannot exceed 1024 bytes");
                }
                if(field_u(ep,"bInterval",0)==0 && (type==1||type==3))warn(epth+".bInterval","interval_zero","Interrupt/isochronous endpoint usually requires a non-zero bInterval");
            }
        }
        if(nums.size()>255)fatal(cp+".interfaces","interface_count","More than 255 distinct interface numbers");
        bool found=false;auto declared=field_u(c,"bNumInterfaces",nums.size(),found);if(found&&declared!=nums.size()){if(manual&&research)warn(cp+".bNumInterfaces","interface_count_mismatch","Research profile has a mismatched manual interface count");else if(manual)fatal(cp+".bNumInterfaces","interface_count_mismatch","Manual bNumInterfaces must match distinct interface numbers");else warn(cp+".bNumInterfaces","auto_field_overridden","bNumInterfaces will be recalculated because calculated_fields is auto");}
        const std::size_t calc_total=9+([&]{std::size_t x=extras(c).size();for(const auto& in:ifs.as_array()){x+=9+extras(in).size();const auto& es=in.at("endpoints");for(const auto& ep:es.as_array())x+=7+extras(ep).size();}return x;})();
        bool found_total=false;auto total=field_u(c,"wTotalLength",calc_total,found_total);if(found_total&&total!=calc_total){if(manual&&research)warn(cp+".wTotalLength","total_length_mismatch","Research profile has a mismatched manual wTotalLength");else if(manual)fatal(cp+".wTotalLength","total_length_mismatch","Manual wTotalLength must equal the combined descriptor length");else warn(cp+".wTotalLength","auto_field_overridden","wTotalLength will be recalculated because calculated_fields is auto");}
    }
    const auto strings=p.at("strings");if(strings.is_object())for(const auto&[lang,entries]:strings.as_object()){(void)lang;if(!entries.is_object())fatal("strings."+lang,"type","String language entry must be an object");else for(const auto&[idx,val]:entries.as_object()){if(idx=="0")fatal("strings."+lang+".0","string_index_zero","String descriptor index 0 is reserved for language IDs");if(!val.is_string())fatal("strings."+lang+"."+idx,"string_type","String descriptor values must be strings");}}
    const auto& endpoint_io=p.at("endpoint_io");
    if(endpoint_io.is_object()) {
        const auto out_size=field_u(endpoint_io,"out_buffer_bytes",16384);if(out_size<64||out_size>65536)fatal("endpoint_io.out_buffer_bytes","out_buffer_range","out_buffer_bytes must be within 64..65536");
        const auto& payloads=endpoint_io.at("in_payloads");if(!payloads.is_null()&&!payloads.is_object())fatal("endpoint_io.in_payloads","type","in_payloads must be an object of endpoint-address to hex-payload values");
        if(payloads.is_object())for(const auto&[key,value]:payloads.as_object()){try{auto addr=std::stoul(key,nullptr,0);if(addr>255||addr==0||(addr&0x80)==0)fatal("endpoint_io.in_payloads."+key,"endpoint_address","IN payload key must be a valid 8-bit IN endpoint address, e.g. 129 or 0x81");auto bytes=parse_hex_bytes(value.as_string());if(bytes.empty())fatal("endpoint_io.in_payloads."+key,"empty_payload","IN payload must contain at least one byte");}catch(const std::exception& e){fatal("endpoint_io.in_payloads."+key,"invalid_payload",e.what());}}
    } else if(!endpoint_io.is_null())fatal("endpoint_io","type","endpoint_io must be an object");
    const auto& control_responses=p.at("control_responses");
    if(!control_responses.is_null()&&!control_responses.is_array())fatal("control_responses","type","control_responses must be an array");
    if(control_responses.is_array())for(std::size_t i=0;i<control_responses.size();++i){const auto& cr=control_responses[i];const auto path="control_responses["+std::to_string(i)+"]";for(const auto& f:std::vector<std::string>{"bmRequestType","bRequest"}){auto v=field_u(cr,f,256);if(v>255)fatal(path+"."+f,"field_range",f+" must fit in 8 bits");}for(const auto& f:std::vector<std::string>{"wValue","wIndex"}){auto v=field_u(cr,f,65536);if(v>65535)fatal(path+"."+f,"field_range",f+" must fit in 16 bits");}if(!cr.at("data_hex").is_string())fatal(path+".data_hex","required","data_hex must be a hexadecimal string");else try{(void)parse_hex_bytes(cr.at("data_hex").as_string());}catch(const std::exception& e){fatal(path+".data_hex","invalid_hex",e.what());}}
    // HID report descriptors are an opaque item stream rather than a bLength/bDescriptorType
    // descriptor chain. Accept type 0x22 in strict mode if it is non-empty and valid hex;
    // all other raw descriptor types remain research-only.
    if(p.contains("raw_descriptors")) {
        const auto& raw = p.at("raw_descriptors");
        if(!raw.is_object()) {
            if(research) warn("raw_descriptors","type","raw_descriptors should be an object mapping type:index to hex bytes");
            else fatal("raw_descriptors","type","raw_descriptors must be an object mapping type:index to hex bytes");
        } else {
            for(const auto& [key, value] : raw.as_object()) {
                unsigned type = 0, index = 0; char sep = 0; std::istringstream ss(key);
                if(!(ss >> type >> sep >> index) || sep != ':' || type > 255 || index > 255) {
                    if(research) warn("raw_descriptors." + key,"key_format","Raw descriptor key must be 'type:index'");
                    else fatal("raw_descriptors." + key,"key_format","Raw descriptor key must be 'type:index'");
                    continue;
                }
                try {
                    const auto bytes = parse_hex_bytes(value.as_string());
                    if(type == 34 && !bytes.empty()) {
                        // HID report descriptor: byte-level item parsing is intentionally separate.
                        warn("raw_descriptors." + key,"hid_report_semantics_unchecked","HID report descriptor bytes are preserved; report-item semantics are not fully validated by this tool");
                    } else if(research) {
                        warn("raw_descriptors." + key,"research_raw_descriptor","Non-HID raw descriptors bypass standard semantic validation");
                    } else {
                        fatal("raw_descriptors." + key,"research_only","Only non-empty HID report descriptors (type 34 / 0x22) are accepted as raw descriptors in strict mode");
                    }
                } catch(const std::exception& e) {
                    if(research) warn("raw_descriptors." + key,"invalid_hex",e.what());
                    else fatal("raw_descriptors." + key,"invalid_hex",e.what());
                }
            }
        }
    }
    if (p.contains("interface_descriptors")) {
        const auto& descriptors = p.at("interface_descriptors");
        if (!descriptors.is_object()) {
            fatal("interface_descriptors", "type", "interface_descriptors must be an object mapping 'configuration:interface' (or interface number) to HID report descriptor hex");
        } else {
            for (const auto& [key, value] : descriptors.as_object()) {
                try {
                    const auto bytes = parse_hex_bytes(value.as_string());
                    if (bytes.empty()) fatal("interface_descriptors." + key, "empty_descriptor", "interface report descriptor must not be empty");
                    if (key.empty()) fatal("interface_descriptors", "key_format", "interface descriptor keys cannot be empty");
                } catch (const std::exception& e) {
                    fatal("interface_descriptors." + key, "invalid_hex", e.what());
                }
            }
        }
    }
    if (p.contains("runtime")) {
        const auto& runtime = p.at("runtime");
        if (!runtime.is_object()) fatal("runtime", "type", "runtime must be an object when supplied");
        else if (runtime.contains("interfaces")) {
            const auto& interfaces = runtime.at("interfaces");
            if (!interfaces.is_array()) fatal("runtime.interfaces", "type", "runtime.interfaces must be an array");
            else for (std::size_t i=0;i<interfaces.size();++i) {
                const auto& item=interfaces[i];
                const auto path="runtime.interfaces["+std::to_string(i)+"]";
                const auto klass=item.at("class").as_string("");
                if (klass!="hid" && klass!="cdc-acm" && klass!="cdc-data" && klass!="msc-bot")
                    fatal(path+".class", "unsupported_runtime_class", "runtime class must be hid, cdc-acm, cdc-data, or msc-bot");
                if (field_u(item,"configuration_value",1)<1 || field_u(item,"configuration_value",1)>255)
                    fatal(path+".configuration_value", "field_range", "configuration_value must be in 1..255");
                if (field_u(item,"interface_number",0)>255)
                    fatal(path+".interface_number", "field_range", "interface_number must fit in 8 bits");
            }
        }
        if (runtime.contains("mass_storage")) {
            const auto& ms=runtime.at("mass_storage");
            if (!ms.is_object()) fatal("runtime.mass_storage", "type", "runtime.mass_storage must be an object");
            else if (ms.at("enabled").as_bool(false)) {
                if (ms.at("backing_file").as_string("").empty()) fatal("runtime.mass_storage.backing_file", "required", "an enabled MSC BOT profile requires a backing_file");
                auto bs=field_u(ms,"block_size",512);
                if (bs<512 || bs>4096 || (bs & (bs-1))!=0) fatal("runtime.mass_storage.block_size", "block_size", "block_size must be a power of two in 512..4096");
                if ((field_u(ms,"in_endpoint",0)&0x80u)==0 || field_u(ms,"in_endpoint",0)>255) fatal("runtime.mass_storage.in_endpoint", "endpoint_address", "MSC IN endpoint must be an 8-bit IN address, e.g. 129");
                if ((field_u(ms,"out_endpoint",0)&0x80u)!=0 || field_u(ms,"out_endpoint",0)==0 || field_u(ms,"out_endpoint",0)>255) fatal("runtime.mass_storage.out_endpoint", "endpoint_address", "MSC OUT endpoint must be a non-zero 8-bit OUT address, e.g. 1");
            }
        }
    }
    bool has_extras=false;
    if(configs.is_array()) for(std::size_t ci=0;ci<configs.size();++ci) {
        const auto& c=configs[ci];
        if(c.contains("extra_descriptors_hex")) has_extras=true;
        const auto& ifs=c.at("interfaces");
        if(ifs.is_array()) for(std::size_t ii=0;ii<ifs.size();++ii) {
            const auto& in=ifs[ii]; if(in.contains("extra_descriptors_hex")) has_extras=true;
            const auto& eps=in.at("endpoints");
            if(eps.is_array()) for(const auto& ep:eps.as_array()) if(ep.contains("extra_descriptors_hex")) has_extras=true;
        }
    }
    if(has_extras) {
        auto check_extra_stream = [&](const Json& obj, const std::string& path) {
            if(!obj.contains("extra_descriptors_hex")) return;
            try {
                const auto bytes = parse_hex_bytes(obj.at("extra_descriptors_hex").as_string());
                std::size_t off = 0;
                while(off < bytes.size()) {
                    if(bytes.size() - off < 2) throw std::runtime_error("descriptor stream has fewer than two bytes remaining");
                    const auto length = static_cast<std::size_t>(bytes[off]);
                    if(length < 2) throw std::runtime_error("descriptor bLength must be at least 2");
                    if(length > bytes.size() - off) throw std::runtime_error("descriptor bLength exceeds remaining byte stream");
                    off += length;
                }
                if(!bytes.empty()) warn(path + ".extra_descriptors_hex","class_descriptor_semantics_unchecked","Extra descriptor byte framing is valid, but class-specific semantic relationships are not fully validated");
            } catch(const std::exception& e) {
                if(research) warn(path + ".extra_descriptors_hex","invalid_descriptor_stream",e.what());
                else fatal(path + ".extra_descriptors_hex","invalid_descriptor_stream",e.what());
            }
        };
        for(std::size_t ci=0;ci<configs.size();++ci) {
            const auto& c=configs[ci]; const std::string cp="configurations["+std::to_string(ci)+"]";
            check_extra_stream(c,cp);
            const auto& ifs=c.at("interfaces");
            if(ifs.is_array()) for(std::size_t ii=0;ii<ifs.size();++ii) {
                const auto& in=ifs[ii]; const std::string ip=cp+".interfaces["+std::to_string(ii)+"]";
                check_extra_stream(in,ip);
                const auto& eps=in.at("endpoints");
                if(eps.is_array()) for(std::size_t ei=0;ei<eps.size();++ei) check_extra_stream(eps[ei],ip+".endpoints["+std::to_string(ei)+"]");
            }
        }
    }
    if(research && !r.issues.empty())warn("validation.mode","research_mode","Research mode can intentionally produce descriptors rejected by the host; use only with your own test hardware");
    // Compilation catches numeric overflow, invalid hex data and malformed numeric map keys
    // that are not necessarily visible to the structural validator above.
    try { (void)compile_profile(p); } catch(const std::exception& e) { fatal("$","compile_error",e.what()); }
    // Hardware compatibility cannot be concluded from a file alone.
    r.backend_compatible=false;warn("backend","not_probed","UDC compatibility is unknown until usb-connect probe/run checks the active controller");
    return r;
}

std::vector<std::uint8_t> get_descriptor(const CompiledProfile& p,std::uint8_t type,std::uint8_t index,std::uint16_t lang) {
    if(type==1 && index==0)return p.device_descriptor;
    if(type==2 && index<p.configuration_descriptors.size())return p.configuration_descriptors[index];
    if(type==3){auto it=p.string_descriptors.find({lang,index}); if(it!=p.string_descriptors.end())return it->second; if(index==0){auto z=p.string_descriptors.find({0,0});if(z!=p.string_descriptors.end())return z->second;} }
    auto it=p.raw_descriptors.find({type,index}); if(it!=p.raw_descriptors.end())return it->second;
    return {};
}
Json compiled_summary(const CompiledProfile& p) {
    Json o=p.source; Json c=Json::Object{}; c["device_descriptor_hex"]=hex_bytes(p.device_descriptor); Json ca=Json::Array{};for(const auto& b:p.configuration_descriptors)ca.as_array().push_back(hex_bytes(b));c["configuration_descriptors_hex"]=std::move(ca);Json sa=Json::Object{};for(const auto&[key,b]:p.string_descriptors)sa[pair_key(key.first,key.second)]=hex_bytes(b);c["string_descriptors_hex"]=std::move(sa);Json ra=Json::Object{};for(const auto&[key,b]:p.raw_descriptors)ra[pair_key(key.first,key.second)]=hex_bytes(b);c["raw_descriptors_hex"]=std::move(ra);o["_compiled"]=std::move(c);return o;
}
}
