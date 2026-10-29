#include "usb_research/profile.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace usb_research;
namespace fs = std::filesystem;

namespace {
struct Options {
    std::string command;
    std::string base_file;
    std::string template_name;
    std::string templates_dir;
    std::string out_dir = "profiles/generated";
    std::string mode = "safe";
    std::string fields = "pid,revision,strings,power,endpoint-addresses,packet-size,interval";
    std::string speed = "high";
    std::uint64_t seed = 0;
    std::uint64_t pid_start = 0;
    std::uint64_t vid = 0;
    std::size_t count = 5;
    bool have_seed = false;
    bool have_pid_start = false;
    bool have_vid = false;
    bool print_profiles = false;
};

std::uint64_t parse_uint(const std::string& s, const std::string& name) {
    std::size_t pos = 0;
    unsigned long long v = 0;
    try { v = std::stoull(s, &pos, 0); }
    catch (...) { throw std::runtime_error("invalid value for " + name + ": " + s); }
    if (pos != s.size()) throw std::runtime_error("invalid value for " + name + ": " + s);
    return static_cast<std::uint64_t>(v);
}

std::set<std::string> split_set(const std::string& csv) {
    std::set<std::string> result;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto first = item.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        auto last = item.find_last_not_of(" \t\r\n");
        result.insert(item.substr(first, last - first + 1));
    }
    return result;
}

void usage() {
    std::cout <<
      "usb-profile-gen - generate USB 2.0 device profiles by mutating template fields\n\n"
      "Commands:\n"
      "  usb-profile-gen list [--templates-dir DIR]\n"
      "  usb-profile-gen show <template-name-or-json-file> [--templates-dir DIR]\n"
      "  usb-profile-gen generate (--template NAME | --base FILE) [options]\n\n"
      "Generate options:\n"
      "  --count N                  Number of variants (1..1000; default 5)\n"
      "  --out-dir DIR              Output directory (default profiles/generated)\n"
      "  --templates-dir DIR        Template directory\n"
      "  --seed N                   Reproducible random seed\n"
      "  --mode safe|research       Valid variants or deliberate descriptor inconsistencies\n"
      "  --fields CSV               pid,revision,strings,manufacturer,product,serial,power,endpoint-addresses,packet-size,interval\n"
      "                             bcd-usb,device-class,device-subclass,device-protocol,interface-class,\n"
      "                             interface-subclass,interface-protocol,ep0-packet-size,endpoint-transfer-type,\n"
      "                             configuration-attributes,configuration-value; use 'all' for every group\n"
      "  --speed high|full          USB speed assumptions for endpoint packet sizes/intervals\n"
      "  --vid N                    Override VID (decimal or 0x-prefixed)\n"
      "  --pid-start N              First PID (decimal or 0x-prefixed)\n"
      "  --print                    Also write each generated JSON profile to stdout\n\n"
      "Examples:\n"
      "  usb-profile-gen list\n"
      "  usb-profile-gen generate --template vendor-bulk --count 10 --seed 42 --out-dir profiles/generated\n"
      "  usb-profile-gen generate --base profiles/valid/minimal-device.json --count 8 --mode research --print\n";
}

Options parse_args(int argc, char** argv) {
    Options o;
    o.templates_dir = (fs::path(USB_RESEARCH_SOURCE_DIR) / "profiles/templates").string();
    if (argc < 2) { usage(); throw std::runtime_error("missing command"); }
    o.command = argv[1];
    int i = 2;
    if (o.command == "show" && i < argc && std::string(argv[i]).rfind("--", 0) != 0) {
        const std::string target = argv[i++];
        if (fs::exists(target)) o.base_file = target;
        else o.template_name = target;
    }
    for (; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](const std::string& opt) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value after " + opt);
            return argv[++i];
        };
        if (a == "--base") o.base_file = value(a);
        else if (a == "--template") o.template_name = value(a);
        else if (a == "--templates-dir") o.templates_dir = value(a);
        else if (a == "--out-dir") o.out_dir = value(a);
        else if (a == "--count") o.count = static_cast<std::size_t>(parse_uint(value(a), a));
        else if (a == "--seed") { o.seed = parse_uint(value(a), a); o.have_seed = true; }
        else if (a == "--pid-start") { o.pid_start = parse_uint(value(a), a); o.have_pid_start = true; }
        else if (a == "--vid") { o.vid = parse_uint(value(a), a); o.have_vid = true; }
        else if (a == "--mode") o.mode = value(a);
        else if (a == "--fields") o.fields = value(a);
        else if (a == "--speed") o.speed = value(a);
        else if (a == "--print") o.print_profiles = true;
        else if (a == "--help" || a == "-h") { usage(); std::exit(0); }
        else throw std::runtime_error("unknown option: " + a);
    }
    return o;
}

std::string filename_slug(std::string s) {
    for (auto& c : s) {
        if (std::isalnum(static_cast<unsigned char>(c))) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        else if (c == '-' || c == '_') c = '-';
        else c = '-';
    }
    while (!s.empty() && s.front() == '-') s.erase(s.begin());
    while (!s.empty() && s.back() == '-') s.pop_back();
    return s.empty() ? "profile" : s;
}

fs::path resolve_template(const std::string& target, const std::string& templates_dir) {
    fs::path p(target);
    if (fs::exists(p)) return p;
    if (p.extension() != ".json") p += ".json";
    fs::path candidate = fs::path(templates_dir) / p.filename();
    if (fs::exists(candidate)) return candidate;
    throw std::runtime_error("template not found: " + target + " (looked in " + templates_dir + ")");
}

std::string padded(std::size_t n, std::size_t width = 4) {
    std::ostringstream ss; ss << std::setw(static_cast<int>(width)) << std::setfill('0') << n; return ss.str();
}

Json load_profile(const Options& o) {
    if (!o.base_file.empty()) return Json::parse(read_text_file(o.base_file));
    if (o.template_name.empty()) throw std::runtime_error("generate/show requires --template NAME or --base FILE");
    const auto path = resolve_template(o.template_name, o.templates_dir);
    return Json::parse(read_text_file(path.string()));
}

std::string get_string_by_index(const Json& profile, std::uint64_t index, const std::string& fallback) {
    const auto& strings = profile.at("strings");
    if (!strings.is_object()) return fallback;
    const auto key = std::to_string(index);
    for (const auto& [lang, entries] : strings.as_object()) {
        (void)lang;
        if (entries.is_object() && entries.contains(key)) return entries.at(key).as_string(fallback);
    }
    return fallback;
}

void set_string_by_index(Json& profile, std::uint64_t index, const std::string& value) {
    if (index == 0 || index > 255) return;
    if (!profile.contains("strings") || !profile["strings"].is_object()) profile["strings"] = Json::Object{};
    auto& strings = profile["strings"];
    if (strings.as_object().empty()) strings["1033"] = Json::Object{};
    const std::string item = std::to_string(index);
    bool updated = false;
    for (auto& [lang, entries] : strings.as_object()) {
        (void)lang;
        if (!entries.is_object()) continue;
        if (entries.contains(item)) { entries[item] = value; updated = true; }
    }
    if (!updated) strings.as_object().begin()->second[item] = value;
}

std::string endpoint_address_key(std::uint64_t addr) { return std::to_string(addr); }

void mutate_endpoint_addresses(Json& profile, std::mt19937_64& rng) {
    std::map<unsigned, unsigned> remap;
    std::array<std::set<unsigned>, 2> used_by_direction;
    if (profile.at("configurations").is_array()) {
        for (auto& config : profile["configurations"].as_array()) {
            if (!config.at("interfaces").is_array()) continue;
            for (auto& iface : config["interfaces"].as_array()) {
                if (!iface.at("endpoints").is_array()) continue;
                for (auto& ep : iface["endpoints"].as_array()) {
                    const unsigned old_addr = static_cast<unsigned>(field_u(ep, "bEndpointAddress", 0));
                    if (remap.contains(old_addr)) continue;
                    const unsigned dir = (old_addr & 0x80u) ? 1u : 0u;
                    unsigned num = 0;
                    std::vector<unsigned> candidates;
                    for (unsigned n = 1; n <= 15; ++n) if (!used_by_direction[dir].contains(n)) candidates.push_back(n);
                    if (candidates.empty()) throw std::runtime_error("too many endpoint addresses to remap");
                    std::uniform_int_distribution<std::size_t> pick(0, candidates.size() - 1);
                    num = candidates[pick(rng)];
                    used_by_direction[dir].insert(num);
                    remap[old_addr] = (dir ? 0x80u : 0u) | num;
                }
            }
        }
    }
    if (profile.at("configurations").is_array()) {
        for (auto& config : profile["configurations"].as_array()) {
            if (!config.at("interfaces").is_array()) continue;
            for (auto& iface : config["interfaces"].as_array()) {
                if (!iface.at("endpoints").is_array()) continue;
                for (auto& ep : iface["endpoints"].as_array()) {
                    const auto old_addr = static_cast<unsigned>(field_u(ep, "bEndpointAddress", 0));
                    if (remap.contains(old_addr)) ep["bEndpointAddress"] = remap[old_addr];
                }
            }
        }
    }
    if (profile.contains("endpoint_io") && profile["endpoint_io"].is_object() &&
        profile["endpoint_io"].contains("in_payloads") && profile["endpoint_io"]["in_payloads"].is_object()) {
        Json::Object updated;
        for (const auto& [key, payload] : profile["endpoint_io"]["in_payloads"].as_object()) {
            try {
                const auto old_addr = static_cast<unsigned>(std::stoul(key, nullptr, 0));
                const auto it = remap.find(old_addr);
                updated[std::to_string(it == remap.end() ? old_addr : it->second)] = payload;
            } catch (...) { updated[key] = payload; }
        }
        profile["endpoint_io"]["in_payloads"] = Json(std::move(updated));
    }
    if (profile.contains("endpoint_io") && profile["endpoint_io"].is_object() &&
        profile["endpoint_io"].contains("loopback_pairs") && profile["endpoint_io"]["loopback_pairs"].is_array()) {
        for (auto& pair : profile["endpoint_io"]["loopback_pairs"].as_array()) {
            for (const auto& key : {std::string("out_endpoint"), std::string("in_endpoint")}) {
                const auto old_addr = static_cast<unsigned>(field_u(pair, key, 0));
                if (remap.contains(old_addr)) pair[key] = remap[old_addr];
            }
        }
    }
    if (profile.contains("runtime") && profile["runtime"].is_object()) {
        for (const auto& key : {std::string("in_endpoint"), std::string("out_endpoint"), std::string("interrupt_in_endpoint")}) {
            if (profile["runtime"].contains(key)) {
                const auto old_addr = static_cast<unsigned>(field_u(profile["runtime"], key, 0));
                if (remap.contains(old_addr)) profile["runtime"][key] = remap[old_addr];
            }
        }
        if (profile["runtime"].contains("mass_storage") && profile["runtime"]["mass_storage"].is_object()) {
            for (const auto& key : {std::string("in_endpoint"), std::string("out_endpoint")}) {
                const auto old_addr = static_cast<unsigned>(field_u(profile["runtime"]["mass_storage"], key, 0));
                if (remap.contains(old_addr)) profile["runtime"]["mass_storage"][key] = remap[old_addr];
            }
        }
        if (profile["runtime"].contains("interfaces") && profile["runtime"]["interfaces"].is_array()) {
            for (auto& iface : profile["runtime"]["interfaces"].as_array()) {
                if (iface.contains("interrupt_in_endpoint")) {
                    const auto old_addr = static_cast<unsigned>(field_u(iface, "interrupt_in_endpoint", 0));
                    if (remap.contains(old_addr)) iface["interrupt_in_endpoint"] = remap[old_addr];
                }
            }
        }
    }
}

void mutate_packet_sizes(Json& profile, std::mt19937_64& rng, const std::string& speed) {
    const std::vector<unsigned> bulk_high{512};
    const std::vector<unsigned> bulk_full{8,16,32,64};
    const std::vector<unsigned> intr_high{8,16,32,64,128,256};
    const std::vector<unsigned> intr_full{4,8,16,32,64};
    const std::vector<unsigned> iso_high{64,128,256,512,1024};
    const std::vector<unsigned> iso_full{64,128,256,512,1023};
    auto choose = [&](const std::vector<unsigned>& values) -> unsigned {
        std::uniform_int_distribution<std::size_t> pick(0, values.size() - 1);
        return values[pick(rng)];
    };
    for (auto& config : profile["configurations"].as_array()) {
        for (auto& iface : config["interfaces"].as_array()) {
            for (auto& ep : iface["endpoints"].as_array()) {
                const unsigned type = static_cast<unsigned>(field_u(ep, "bmAttributes", 2)) & 0x03u;
                if (type == 2) ep["wMaxPacketSize"] = speed == "high" ? choose(bulk_high) : choose(bulk_full);
                else if (type == 3) ep["wMaxPacketSize"] = speed == "high" ? choose(intr_high) : choose(intr_full);
                else if (type == 1) ep["wMaxPacketSize"] = speed == "high" ? choose(iso_high) : choose(iso_full);
            }
        }
    }
}

void mutate_intervals(Json& profile, std::mt19937_64& rng, const std::string& speed) {
    const std::vector<unsigned> high_values{1,4,8,10,16};
    const std::vector<unsigned> full_values{1,4,10,16,32,64,128,255};
    const auto& values = speed == "high" ? high_values : full_values;
    std::uniform_int_distribution<std::size_t> pick(0, values.size() - 1);
    for (auto& config : profile["configurations"].as_array()) {
        for (auto& iface : config["interfaces"].as_array()) {
            for (auto& ep : iface["endpoints"].as_array()) {
                const unsigned type = static_cast<unsigned>(field_u(ep, "bmAttributes", 2)) & 0x03u;
                if (type == 1 || type == 3) ep["bInterval"] = values[pick(rng)];
            }
        }
    }
}

unsigned pick_value(std::mt19937_64& rng, const std::vector<unsigned>& values) {
    std::uniform_int_distribution<std::size_t> pick(0, values.size() - 1);
    return values[pick(rng)];
}

void mutate_descriptor_fields(Json& profile, std::mt19937_64& rng,
                              const std::set<std::string>& fields, const std::string& speed) {
    if (fields.contains("bcd-usb")) {
        profile["device"]["bcdUSB"] = speed == "high"
            ? 0x0200u : pick_value(rng, {0x0110u, 0x0200u});
    }
    if (fields.contains("device-class"))
        profile["device"]["bDeviceClass"] = pick_value(rng, {0x00u, 0x02u, 0x03u, 0x08u, 0xefu, 0xffu});
    if (fields.contains("device-subclass"))
        profile["device"]["bDeviceSubClass"] = pick_value(rng, {0x00u, 0x01u, 0x02u, 0x06u});
    if (fields.contains("device-protocol"))
        profile["device"]["bDeviceProtocol"] = pick_value(rng, {0x00u, 0x01u, 0x02u, 0x50u});
    if (fields.contains("ep0-packet-size"))
        profile["device"]["bMaxPacketSize0"] = speed == "high"
            ? 64u : pick_value(rng, {8u, 16u, 32u, 64u});
    if (fields.contains("configuration-attributes")) {
        static const std::vector<unsigned> attrs{0x80u, 0xa0u, 0xc0u, 0xe0u};
        for (auto& config : profile["configurations"].as_array())
            config["bmAttributes"] = pick_value(rng, attrs);
    }
    if (fields.contains("configuration-value")) {
        for (auto& config : profile["configurations"].as_array())
            config["bConfigurationValue"] = pick_value(rng, {1u, 2u, 3u, 4u, 7u, 8u, 16u, 32u, 64u, 128u, 255u});
    }
    for (auto& config : profile["configurations"].as_array()) {
        for (auto& iface : config["interfaces"].as_array()) {
            if (fields.contains("interface-class"))
                iface["bInterfaceClass"] = pick_value(rng, {0x02u, 0x03u, 0x08u, 0x0au, 0xfeu, 0xffu});
            if (fields.contains("interface-subclass"))
                iface["bInterfaceSubClass"] = pick_value(rng, {0x00u, 0x01u, 0x02u, 0x03u, 0x06u, 0x50u});
            if (fields.contains("interface-protocol"))
                iface["bInterfaceProtocol"] = pick_value(rng, {0x00u, 0x01u, 0x02u, 0x50u, 0x62u});
            for (auto& ep : iface["endpoints"].as_array()) {
                if (fields.contains("endpoint-transfer-type")) {
                    const unsigned attrs = static_cast<unsigned>(field_u(ep, "bmAttributes", 2));
                    // Bulk and interrupt are supported by the current Raw Gadget data plane.
                    // This changes class semantics intentionally; strict validation is structural, not a class conformance test.
                    ep["bmAttributes"] = (attrs & ~0x03u) | pick_value(rng, {2u, 3u});
                }
            }
        }
    }
}

std::size_t extra_descriptor_size(const Json& object) {
    if (!object.contains("extra_descriptors_hex")) return 0;
    return parse_hex_bytes(object.at("extra_descriptors_hex").as_string()).size();
}

void normalize_calculated_fields(Json& profile) {
    auto& device = profile["device"];
    device["bLength"] = 18;
    device["bDescriptorType"] = 1;
    device["bNumConfigurations"] = profile["configurations"].size();
    for (auto& config : profile["configurations"].as_array()) {
        config["bLength"] = 9;
        config["bDescriptorType"] = 2;
        std::set<std::uint64_t> interface_numbers;
        std::size_t total_length = 9 + extra_descriptor_size(config);
        for (auto& iface : config["interfaces"].as_array()) {
            iface["bLength"] = 9;
            iface["bDescriptorType"] = 4;
            iface["bNumEndpoints"] = iface["endpoints"].size();
            interface_numbers.insert(field_u(iface, "bInterfaceNumber", 0));
            total_length += 9 + extra_descriptor_size(iface);
            for (auto& ep : iface["endpoints"].as_array()) {
                ep["bLength"] = 7;
                ep["bDescriptorType"] = 5;
                total_length += 7 + extra_descriptor_size(ep);
            }
        }
        config["bNumInterfaces"] = interface_numbers.size();
        config["wTotalLength"] = total_length;
    }
}

void apply_research_fault(Json& profile, std::size_t index) {
    profile["validation"]["mode"] = "research";
    profile["validation"]["calculated_fields"] = "manual";
    switch (index % 4) {
        case 0:
            profile["device"]["bLength"] = 17;
            break;
        case 1: {
            auto compiled = compile_profile(profile);
            auto& cfg = profile["configurations"].as_array().front();
            const std::size_t length = compiled.configuration_descriptors.front().size();
            cfg["wTotalLength"] = length > 1 ? length - 1 : 0;
            break;
        }
        case 2: {
            auto& iface = profile["configurations"].as_array().front()["interfaces"].as_array().front();
            iface["bNumEndpoints"] = iface["endpoints"].size() + 1;
            break;
        }
        case 3:
            profile["device"]["bNumConfigurations"] = profile["configurations"].size() + 1;
            break;
    }
}

Json generate_variant(const Json& base, const Options& o, std::size_t index,
                      std::uint64_t first_pid, std::uint64_t base_vid,
                      std::uint64_t seed, const std::set<std::string>& fields) {
    Json p = base;
    std::mt19937_64 rng(seed + static_cast<std::uint64_t>(index) * 0x9e3779b97f4a7c15ULL);
    const auto base_name = base.at("profile_name").as_string("usb-lab-device");
    const auto variant_number = index + 1;
    p["profile_name"] = base_name + "-variant-" + padded(variant_number);
    if (!p.contains("template_info") || !p["template_info"].is_object()) p["template_info"] = Json::Object{};
    p["template_info"]["generated_from"] = base_name;
    p["template_info"]["generated_variant"] = variant_number;
    p["template_info"]["generation_mode"] = o.mode;
    p["template_info"]["runtime_ready"] = p["template_info"].contains("runtime_ready") ? p["template_info"]["runtime_ready"] : Json(true);

    if (o.have_vid) p["device"]["idVendor"] = o.vid;
    else if (base_vid != 0) p["device"]["idVendor"] = base_vid;
    if (fields.contains("pid") || o.have_pid_start) p["device"]["idProduct"] = first_pid + index;

    if (fields.contains("revision")) {
        // bcdDevice is a BCD release number: 0x0101, 0x0102, ... 0x0110, 0x0200 ...
        const std::uint64_t release = variant_number % 100;
        const std::uint64_t major = 1 + (variant_number / 100);
        const std::uint64_t minor_tens = (release / 10) & 0x0f;
        const std::uint64_t minor_ones = release % 10;
        if (major <= 99) {
            const std::uint64_t hi = ((major / 10) << 12) | ((major % 10) << 8);
            p["device"]["bcdDevice"] = hi | (minor_tens << 4) | minor_ones;
        }
    }

    if (fields.contains("strings") || fields.contains("product") || fields.contains("serial") || fields.contains("manufacturer")) {
        const auto manufacturer_index = field_u(p.at("device"), "iManufacturer", 1);
        const auto product_index = field_u(p.at("device"), "iProduct", 2);
        const auto serial_index = field_u(p.at("device"), "iSerialNumber", 3);
        const std::string old_manufacturer = get_string_by_index(base, manufacturer_index, "USB Research Lab");
        const std::string old_product = get_string_by_index(base, product_index, base_name);
        const std::string old_serial = get_string_by_index(base, serial_index, "LAB-0001");
        if (fields.contains("strings") || fields.contains("manufacturer"))
            set_string_by_index(p, manufacturer_index, old_manufacturer + " Lab " + padded(variant_number));
        if (fields.contains("strings") || fields.contains("product"))
            set_string_by_index(p, product_index, old_product + " Variant " + padded(variant_number));
        if (fields.contains("strings") || fields.contains("serial"))
            set_string_by_index(p, serial_index, old_serial + "-V" + padded(variant_number));
    }

    mutate_descriptor_fields(p, rng, fields, o.speed);

    if (fields.contains("power")) {
        static const std::vector<unsigned> power_values{25, 50, 75, 100, 125};
        std::uniform_int_distribution<std::size_t> pick(0, power_values.size() - 1);
        for (auto& config : p["configurations"].as_array()) config["bMaxPower"] = power_values[pick(rng)];
    }
    if (fields.contains("endpoint-addresses")) mutate_endpoint_addresses(p, rng);
    if (fields.contains("packet-size")) mutate_packet_sizes(p, rng, o.speed);
    if (fields.contains("interval")) mutate_intervals(p, rng, o.speed);

    normalize_calculated_fields(p);
    p["validation"]["mode"] = o.mode == "research" ? "research" : "strict";
    p["validation"]["calculated_fields"] = o.mode == "research" ? "manual" : "auto";
    if (o.mode == "research") apply_research_fault(p, index);
    return p;
}

void print_templates(const std::string& dir) {
    if (!fs::exists(dir)) throw std::runtime_error("templates directory does not exist: " + dir);
    std::vector<fs::path> files;
    for (const auto& e : fs::directory_iterator(dir))
        if (e.is_regular_file() && e.path().extension() == ".json") files.push_back(e.path());
    std::sort(files.begin(), files.end());
    std::cout << "Available USB profile templates (" << files.size() << "):\n";
    for (const auto& path : files) {
        const auto p = Json::parse(read_text_file(path.string()));
        const auto& info = p.at("template_info");
        std::cout << "  " << path.stem().string() << "\n"
                  << "    profile: " << p.at("profile_name").as_string() << "\n"
                  << "    category: " << info.at("category").as_string("unspecified") << "\n"
                  << "    runtime_ready: " << (info.at("runtime_ready").as_bool(false) ? "yes" : "no") << "\n"
                  << "    notes: " << info.at("notes").as_string() << "\n";
    }
}

void show_profile(const Json& profile) {
    std::cout << "=== Profile JSON ===\n" << profile.dump(2) << "\n";
    const auto compiled = compile_profile(profile);
    std::cout << "=== Compiled descriptors ===\n";
    std::cout << "Device Descriptor (" << compiled.device_descriptor.size() << " bytes): "
              << hex_bytes(compiled.device_descriptor) << "\n";
    for (std::size_t i = 0; i < compiled.configuration_descriptors.size(); ++i)
        std::cout << "Configuration " << i << " (" << compiled.configuration_descriptors[i].size() << " bytes): "
                  << hex_bytes(compiled.configuration_descriptors[i]) << "\n";
    for (const auto& [key, bytes] : compiled.raw_descriptors)
        std::cout << "Raw Descriptor type=" << static_cast<unsigned>(key.first)
                  << " index=" << static_cast<unsigned>(key.second) << ": " << hex_bytes(bytes) << "\n";
}

void generate(const Options& o) {
    if (o.count == 0 || o.count > 1000) throw std::runtime_error("--count must be in the range 1..1000");
    if (o.mode != "safe" && o.mode != "research") throw std::runtime_error("--mode must be safe or research");
    if (o.speed != "high" && o.speed != "full") throw std::runtime_error("--speed must be high or full");
    if (o.have_vid && (o.vid == 0 || o.vid > 65535)) throw std::runtime_error("--vid must be in range 1..65535");
    auto fields = split_set(o.fields);
    const std::set<std::string> allowed{
        "pid","revision","strings","manufacturer","product","serial","power",
        "endpoint-addresses","packet-size","interval","bcd-usb",
        "device-class","device-subclass","device-protocol","interface-class",
        "interface-subclass","interface-protocol","ep0-packet-size",
        "endpoint-transfer-type","configuration-attributes","configuration-value"
    };
    if (fields.size() == 1 && fields.contains("all")) fields = allowed;
    for (const auto& f : fields) if (!allowed.contains(f)) throw std::runtime_error("unknown field mutation: " + f);
    const Json base = load_profile(o);
    const auto base_name = base.at("profile_name").as_string("usb-lab-device");
    const auto base_vid = field_u(base.at("device"), "idVendor", 0x1209);
    const auto base_pid = field_u(base.at("device"), "idProduct", 1);
    const auto first_pid = o.have_pid_start ? o.pid_start : (base_pid + 1);
    if ((fields.contains("pid") || o.have_pid_start) && (first_pid == 0 || first_pid + o.count - 1 > 65535))
        throw std::runtime_error("generated PID range is outside 1..65535; choose --pid-start or a smaller --count");
    const std::uint64_t seed = o.have_seed ? o.seed : static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    fs::create_directories(o.out_dir);

    Json manifest = Json::Object{};
    manifest["schema_version"] = 1;
    manifest["source_profile"] = base_name;
    manifest["generation_mode"] = o.mode;
    manifest["speed_assumption"] = o.speed;
    manifest["seed"] = seed;
    manifest["count"] = o.count;
    manifest["fields"] = o.fields;
    Json entries = Json::Array{};

    std::cout << "Generating " << o.count << " profile(s) from '" << base_name << "'\n"
              << "  mode=" << o.mode << ", speed=" << o.speed << ", seed=" << seed << "\n"
              << "  fields=" << o.fields << "\n";
    for (std::size_t i = 0; i < o.count; ++i) {
        Json profile = generate_variant(base, o, i, first_pid, base_vid, seed, fields);
        auto report = validate_profile(profile, o.mode == "research" ? "research" : "strict");
        if (o.mode == "safe" && !report.profile_valid) {
            std::ostringstream message;
            message << "generated profile failed strict validation at index " << (i + 1);
            for (const auto& issue : report.issues) if (issue.fatal) message << "\n  " << issue.path << ": " << issue.message;
            throw std::runtime_error(message.str());
        }
        const std::string name = filename_slug(profile.at("profile_name").as_string()) + ".json";
        const fs::path output = fs::path(o.out_dir) / name;
        write_text_file(output.string(), profile.dump(2) + "\n");
        Json item = Json::Object{};
        item["file"] = output.string();
        item["profile_name"] = profile.at("profile_name").as_string();
        item["idVendor"] = field_u(profile.at("device"), "idVendor", 0);
        item["idProduct"] = field_u(profile.at("device"), "idProduct", 0);
        item["profile_valid"] = report.profile_valid;
        item["issue_count"] = report.issues.size();
        entries.as_array().push_back(std::move(item));
        std::cout << "  [" << (i + 1) << "/" << o.count << "] " << output.string()
                  << "  VID:PID=" << std::hex << std::setw(4) << std::setfill('0') << field_u(profile.at("device"), "idVendor", 0)
                  << ":" << std::setw(4) << field_u(profile.at("device"), "idProduct", 0) << std::dec
                  << "  profile_valid=" << (report.profile_valid ? "true" : "false")
                  << "  issues=" << report.issues.size() << "\n";
        if (o.print_profiles) std::cout << "----- " << output.string() << " -----\n" << profile.dump(2) << "\n";
    }
    manifest["profiles"] = std::move(entries);
    const auto manifest_path = (fs::path(o.out_dir) / "manifest.json").string();
    write_text_file(manifest_path, manifest.dump(2) + "\n");
    std::cout << "Manifest: " << manifest_path << "\n";
    if (o.mode == "research")
        std::cout << "NOTICE: research variants deliberately contain one descriptor inconsistency each; use only with your isolated test host.\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        const auto o = parse_args(argc, argv);
        if (o.command == "list") { print_templates(o.templates_dir); return 0; }
        if (o.command == "show") { show_profile(load_profile(o)); return 0; }
        if (o.command == "generate") { generate(o); return 0; }
        usage();
        throw std::runtime_error("unknown command: " + o.command);
    } catch (const std::exception& e) {
        std::cerr << "usb-profile-gen: " << e.what() << "\n";
        return 2;
    }
}
