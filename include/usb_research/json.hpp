#pragma once
#include <cstdint>
#include <type_traits>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace usb_research {
class Json {
public:
    using Array = std::vector<Json>;
    using Object = std::map<std::string, Json>;
    using Value = std::variant<std::nullptr_t, bool, std::int64_t, std::uint64_t, double, std::string, Array, Object>;

    Json() : value_(nullptr) {}
    Json(std::nullptr_t) : value_(nullptr) {}
    Json(bool v) : value_(v) {}
    template<class T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<std::remove_cv_t<T>, bool>, int> = 0>
    Json(T v) {
        if constexpr (std::is_signed_v<T>) value_ = static_cast<std::int64_t>(v);
        else value_ = static_cast<std::uint64_t>(v);
    }
    Json(double v) : value_(v) {}
    Json(const char* v) : value_(std::string(v)) {}
    Json(std::string v) : value_(std::move(v)) {}
    Json(Array v) : value_(std::move(v)) {}
    Json(Object v) : value_(std::move(v)) {}

    static Json parse(std::string_view text);
    std::string dump(int indent = -1) const;
    bool is_null() const;
    bool is_bool() const;
    bool is_number() const;
    bool is_string() const;
    bool is_array() const;
    bool is_object() const;
    bool as_bool(bool fallback = false) const;
    double as_number(double fallback = 0) const;
    std::int64_t as_i64(std::int64_t fallback = 0) const;
    std::uint64_t as_u64(std::uint64_t fallback = 0) const;
    std::string number_string() const;
    std::string as_string(std::string fallback = {}) const;
    const Array& as_array() const;
    Array& as_array();
    const Object& as_object() const;
    Object& as_object();
    bool contains(std::string_view key) const;
    const Json& at(std::string_view key) const;
    Json& operator[](const std::string& key);
    const Json& operator[](std::size_t index) const;
    std::size_t size() const;
private:
    Value value_;
};

std::string read_text_file(const std::string& path);
void write_text_file(const std::string& path, const std::string& content);
std::string hex_bytes(const std::vector<std::uint8_t>& bytes);
std::vector<std::uint8_t> parse_hex_bytes(std::string_view hex);
std::string to_lower(std::string s);
}
