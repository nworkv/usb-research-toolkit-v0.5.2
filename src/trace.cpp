#include "usb_research/trace.hpp"
#include <chrono>
#include <filesystem>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace usb_research {
namespace {
std::uint64_t now_ns(bool steady) {
    if (steady) return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

std::vector<Json> read_jsonl(const std::string& path) {
    std::istringstream in(read_text_file(path));
    std::string line;
    std::vector<Json> out;
    std::size_t line_number = 0;
    while (std::getline(in, line)) {
        ++line_number;
        if (line.empty()) continue;
        try {
            out.push_back(Json::parse(line));
        } catch (const std::exception& ex) {
            throw std::runtime_error(path + ":" + std::to_string(line_number) + ": " + ex.what());
        }
    }
    return out;
}

std::string request_sig(const Json& event) {
    const auto& request = event.at("request");
    if (!request.is_object()) return {};
    const char* keys[] = {"bmRequestType", "bRequest", "wValue", "wIndex", "wLength"};
    std::ostringstream signature;
    for (std::size_t i = 0; i < 5; ++i) {
        const auto& value = request.at(keys[i]);
        if (value.is_null()) return {};
        if (i) signature << ':';
        signature << value.as_u64(999);
    }
    return "control:" + signature.str();
}

std::string transfer_sig(const Json& event) {
    const auto& endpoint_json = event.contains("endpoint_address")
        ? event.at("endpoint_address") : event.at("endpoint");
    const auto direction = event.at("direction").as_string();
    const auto length = event.at("actual_length").as_i64(-1);
    const auto payload = event.at("payload_hex").as_string();
    if (!endpoint_json.is_null() && !direction.empty() && length >= 0 && !payload.empty()) {
        return "transfer:" + std::to_string(endpoint_json.as_i64(-1)) + ":" + direction + ":" +
               std::to_string(length) + ":" + to_lower(payload);
    }
    return {};
}

// A control-data event carries both SETUP metadata and the returned/received bytes.
// Match the SETUP from CONTROL_REQUEST and the data payload from CONTROL_*_COMPLETE
// separately; counting both signatures on a completion would double-count the SETUP.
std::vector<std::string> event_signatures(const Json& event) {
    std::vector<std::string> signatures;
    const auto name = event.at("event").as_string();
    const bool is_control_completion = name == "CONTROL_RESPONSE_COMPLETE" ||
                                       name == "CONTROL_OUT_COMPLETE" ||
                                       name == "CONTROL_OUT_PAYLOAD";
    if (!is_control_completion) {
        auto control = request_sig(event);
        if (!control.empty()) signatures.push_back(std::move(control));
    }
    auto transfer = transfer_sig(event);
    if (!transfer.empty() && (signatures.empty() || signatures.back() != transfer))
        signatures.push_back(std::move(transfer));
    return signatures;
}

Json counts_to_json(const std::map<std::string, std::uint64_t>& counts) {
    Json output = Json::Object{};
    for (const auto& [key, value] : counts) output[key] = value;
    return output;
}
} // namespace

TraceLogger::TraceLogger(const std::string& path, std::string run_id, std::string source)
    : run_id_(std::move(run_id)), source_(std::move(source)) {
    auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent);
    file_.open(path, std::ios::out | std::ios::trunc);
    if (!file_) throw std::runtime_error("cannot open trace file: " + path);
}

void TraceLogger::log(Json event) {
    std::lock_guard<std::mutex> lock(mutex_);
    event["schema_version"] = 1;
    event["run_id"] = run_id_;
    event["sequence"] = ++sequence_;
    event["source"] = source_;
    event["timestamp_monotonic_ns"] = now_ns(true);
    event["timestamp_wall_ns"] = now_ns(false);
    file_ << event.dump() << '\n';
    file_.flush();
}

void TraceLogger::event(const std::string& name, const std::string& state, Json details) {
    Json event = Json::Object{};
    event["event"] = name;
    event["state"] = state;
    if (details.is_object()) {
        for (const auto& [key, value] : details.as_object()) event[key] = value;
    }
    log(std::move(event));
}

Json summarize_trace(const std::string& path) {
    auto events = read_jsonl(path);
    std::map<std::string, std::uint64_t> event_counts, source_counts, state_counts;
    std::uint64_t min_time = 0, max_time = 0;
    for (const auto& event : events) {
        ++event_counts[event.at("event").as_string("UNKNOWN")];
        ++source_counts[event.at("source").as_string("UNKNOWN")];
        ++state_counts[event.at("state").as_string("UNKNOWN")];
        auto timestamp = event.at("timestamp_monotonic_ns").as_u64(0);
        if (timestamp && (min_time == 0 || timestamp < min_time)) min_time = timestamp;
        if (timestamp > max_time) max_time = timestamp;
    }
    Json result = Json::Object{};
    result["file"] = path;
    result["event_count"] = events.size();
    result["events_by_type"] = counts_to_json(event_counts);
    result["events_by_source"] = counts_to_json(source_counts);
    result["events_by_state"] = counts_to_json(state_counts);
    result["duration_monotonic_ns"] = (min_time && max_time >= min_time) ? max_time - min_time : 0;
    return result;
}

Json compare_traces(const std::string& device_path, const std::string& host_path) {
    auto device_events = read_jsonl(device_path);
    auto host_events = read_jsonl(host_path);
    std::map<std::string, std::size_t> host_counts;
    for (const auto& event : host_events) {
        for (const auto& signature : event_signatures(event)) ++host_counts[signature];
    }

    Json matches = Json::Array{};
    Json unmatched_device = Json::Array{};
    Json unmatched_device_signatures = Json::Array{};
    std::size_t matched_control = 0, matched_transfer = 0;
    std::size_t device_controls = 0, device_transfers = 0;

    for (const auto& event : device_events) {
        const auto name = event.at("event").as_string("UNKNOWN");
        if (name == "CONTROL_REQUEST") ++device_controls;
        const auto transfer_signature = transfer_sig(event);
        if (!transfer_signature.empty()) ++device_transfers;

        const auto signatures = event_signatures(event);
        if (signatures.empty()) continue;
        bool any_match = false;
        for (const auto& signature : signatures) {
            const bool control = signature.rfind("control:", 0) == 0;
            auto found = host_counts.find(signature);
            if (found != host_counts.end() && found->second > 0) {
                --found->second;
                any_match = true;
                if (control) ++matched_control;
                else ++matched_transfer;
                Json item = Json::Object{};
                item["signature"] = signature;
                item["device_sequence"] = event.at("sequence");
                item["device_event"] = name;
                item["match_basis"] = control ? "control_setup_signature" : "endpoint_direction_length_payload";
                matches.as_array().push_back(std::move(item));
            } else {
                Json item = Json::Object{};
                item["signature"] = signature;
                item["device_sequence"] = event.at("sequence");
                item["device_event"] = name;
                unmatched_device_signatures.as_array().push_back(std::move(item));
            }
        }
        if (!any_match) unmatched_device.as_array().push_back(event);
    }

    Json unmatched_host = Json::Array{};
    for (const auto& [signature, count] : host_counts) {
        if (count) {
            Json item = Json::Object{};
            item["signature"] = signature;
            item["unmatched_count"] = count;
            unmatched_host.as_array().push_back(std::move(item));
        }
    }

    Json result = Json::Object{};
    result["device_file"] = device_path;
    result["host_file"] = host_path;
    result["device_control_requests"] = device_controls;
    result["matched_control_requests"] = matched_control;
    result["device_data_transfers_with_payload"] = device_transfers;
    result["matched_data_transfers"] = matched_transfer;
    result["unmatched_device_events"] = std::move(unmatched_device);
    result["unmatched_device_signatures"] = std::move(unmatched_device_signatures);
    result["unmatched_host_signatures"] = std::move(unmatched_host);
    result["matches"] = std::move(matches);
    result["note"] = "Control SETUP requests are matched by their exact five fields. Transfer observations are matched when endpoint, direction, actual length, and payload bytes are available and identical. A control transfer's SETUP and data stage are correlated separately. This compares host-stack/software observations, not individual on-wire USB packets; unmatched observations are not automatically proof of physical packet loss.";
    return result;
}
} // namespace usb_research
