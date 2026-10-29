#pragma once
#include "usb_research/json.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace usb_research {
struct ValidationIssue { std::string path, code, message; bool fatal = false; };
struct ValidationReport { std::vector<ValidationIssue> issues; bool profile_valid = true; bool backend_compatible = true; Json to_json() const; };
struct CompiledProfile {
    Json source;
    std::vector<std::uint8_t> device_descriptor;
    std::vector<std::vector<std::uint8_t>> configuration_descriptors;
    std::map<std::pair<std::uint8_t,std::uint8_t>, std::vector<std::uint8_t>> raw_descriptors;
    std::map<std::pair<std::uint16_t,std::uint8_t>, std::vector<std::uint8_t>> string_descriptors;
    std::string name;
    bool research_mode = false;
};

CompiledProfile compile_profile(const Json& profile);
ValidationReport validate_profile(const Json& profile, const std::string& mode = "");
std::vector<std::uint8_t> get_descriptor(const CompiledProfile& profile, std::uint8_t type, std::uint8_t index, std::uint16_t lang_id = 0);
Json compiled_summary(const CompiledProfile& profile);
std::uint64_t field_u(const Json& obj, const std::string& name, std::uint64_t fallback);
std::uint64_t field_u(const Json& obj, const std::string& name, std::uint64_t fallback, bool& found);
}
