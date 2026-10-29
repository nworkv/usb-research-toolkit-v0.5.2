#pragma once
#include "usb_research/json.hpp"
#include <fstream>
#include <mutex>
#include <string>

namespace usb_research {
class TraceLogger {
public:
    TraceLogger(const std::string& path, std::string run_id, std::string source);
    void log(Json event);
    void event(const std::string& name, const std::string& state, Json details = Json::Object{});
private:
    std::ofstream file_;
    std::string run_id_, source_;
    std::uint64_t sequence_ = 0;
    std::mutex mutex_;
};
Json summarize_trace(const std::string& path);
Json compare_traces(const std::string& device_path, const std::string& host_path);
}
