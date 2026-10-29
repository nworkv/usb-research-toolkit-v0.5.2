#include "usb_research/json.hpp"
#include <charconv>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace usb_research {
namespace {
class Parser {
public:
    explicit Parser(std::string_view s) : s_(s) {}
    Json parse() { ws(); Json v = value(); ws(); if (p_ != s_.size()) fail("trailing characters"); return v; }
private:
    std::string_view s_; std::size_t p_ = 0;
    [[noreturn]] void fail(const std::string& what) const { throw std::runtime_error("JSON parse error at byte " + std::to_string(p_) + ": " + what); }
    void ws() { while (p_ < s_.size() && (s_[p_] == ' ' || s_[p_] == '\n' || s_[p_] == '\r' || s_[p_] == '\t')) ++p_; }
    bool take(char c) { if (p_ < s_.size() && s_[p_] == c) { ++p_; return true; } return false; }
    void expect(char c) { if (!take(c)) fail(std::string("expected '") + c + "'"); }
    Json value() {
        ws(); if (p_ >= s_.size()) fail("unexpected end"); char c = s_[p_];
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return Json(string());
        if (c == 't' && lit("true")) return Json(true);
        if (c == 'f' && lit("false")) return Json(false);
        if (c == 'n' && lit("null")) return Json(nullptr);
        if (c == '-' || (c >= '0' && c <= '9')) return number();
        fail("unexpected token");
    }
    bool lit(std::string_view w) { if (s_.substr(p_, w.size()) == w) { p_ += w.size(); return true; } return false; }
    Json object() { expect('{'); ws(); Json::Object o; if (take('}')) return Json(std::move(o)); for (;;) { ws(); if (p_ >= s_.size() || s_[p_] != '"') fail("expected object key"); auto k = string(); ws(); expect(':'); auto v = value(); if (!o.emplace(k, std::move(v)).second) fail("duplicate object key: " + k); ws(); if (take('}')) break; expect(','); } return Json(std::move(o)); }
    Json array() { expect('['); ws(); Json::Array a; if (take(']')) return Json(std::move(a)); for (;;) { a.push_back(value()); ws(); if (take(']')) break; expect(','); } return Json(std::move(a)); }
    static void utf8(std::string& out, std::uint32_t cp) { if (cp <= 0x7f) out.push_back(static_cast<char>(cp)); else if (cp <= 0x7ff) { out.push_back(static_cast<char>(0xc0 | (cp >> 6))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); } else if (cp <= 0xffff) { out.push_back(static_cast<char>(0xe0 | (cp >> 12))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); } else { out.push_back(static_cast<char>(0xf0 | (cp >> 18))); out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); } }
    std::uint32_t hex4() { std::uint32_t x=0; for (int i=0;i<4;i++) { if (p_>=s_.size()) fail("short unicode escape"); char c=s_[p_++]; x <<= 4; if(c>='0'&&c<='9') x|=c-'0'; else if(c>='a'&&c<='f') x|=c-'a'+10; else if(c>='A'&&c<='F') x|=c-'A'+10; else fail("invalid unicode escape"); } return x; }
    std::string string() { expect('"'); std::string out; while (p_ < s_.size()) { unsigned char c=s_[p_++]; if(c=='"') return out; if(c<0x20) fail("control character in string"); if(c!='\\') { out.push_back(static_cast<char>(c)); continue; } if(p_>=s_.size()) fail("short escape"); char e=s_[p_++]; switch(e) { case '"':out+='"';break; case '\\':out+='\\';break; case '/':out+='/';break; case 'b':out+='\b';break; case 'f':out+='\f';break; case 'n':out+='\n';break; case 'r':out+='\r';break; case 't':out+='\t';break; case 'u': { auto cp=hex4(); if(cp>=0xd800&&cp<=0xdbff) { if(p_+2>s_.size()||s_[p_]!='\\'||s_[p_+1]!='u') fail("missing low surrogate"); p_+=2; auto lo=hex4(); if(lo<0xdc00||lo>0xdfff) fail("invalid low surrogate"); cp=0x10000+((cp-0xd800)<<10)+(lo-0xdc00); } else if(cp>=0xdc00&&cp<=0xdfff) fail("unexpected low surrogate"); utf8(out,cp); break; } default:fail("invalid escape"); } } fail("unterminated string"); }
    Json number() {
        const std::size_t start = p_;
        if (take('-')) {}
        if (take('0')) {
        } else {
            if (p_ >= s_.size() || s_[p_] < '1' || s_[p_] > '9') fail("invalid number");
            while (p_ < s_.size() && s_[p_] >= '0' && s_[p_] <= '9') ++p_;
        }
        bool has_fraction_or_exponent = false;
        if (take('.')) {
            has_fraction_or_exponent = true;
            if (p_ >= s_.size() || s_[p_] < '0' || s_[p_] > '9') fail("invalid fraction");
            while (p_ < s_.size() && s_[p_] >= '0' && s_[p_] <= '9') ++p_;
        }
        if (p_ < s_.size() && (s_[p_] == 'e' || s_[p_] == 'E')) {
            has_fraction_or_exponent = true;
            ++p_;
            if (p_ < s_.size() && (s_[p_] == '+' || s_[p_] == '-')) ++p_;
            if (p_ >= s_.size() || s_[p_] < '0' || s_[p_] > '9') fail("invalid exponent");
            while (p_ < s_.size() && s_[p_] >= '0' && s_[p_] <= '9') ++p_;
        }
        const auto token = s_.substr(start, p_ - start);
        if (!has_fraction_or_exponent) {
            if (!token.empty() && token.front() == '-') {
                std::int64_t v{};
                auto result = std::from_chars(token.data(), token.data() + token.size(), v);
                if (result.ec == std::errc{} && result.ptr == token.data() + token.size()) return Json(v);
            } else {
                std::uint64_t v{};
                auto result = std::from_chars(token.data(), token.data() + token.size(), v);
                if (result.ec == std::errc{} && result.ptr == token.data() + token.size()) return Json(v);
            }
        }
        double d = 0;
        try { d = std::stod(std::string(token)); }
        catch (...) { fail("number out of range"); }
        if (!std::isfinite(d)) fail("non-finite number");
        return Json(d);
    }
};
void indent(std::string& out, int n) { out.append(static_cast<std::size_t>(n), ' '); }
void stringify(const Json& j, std::string& out, int pretty, int depth) {
    if (j.is_null()) { out += "null"; return; }
    if (j.is_bool()) { out += j.as_bool() ? "true" : "false"; return; }
    if (j.is_number()) { out += j.number_string(); return; }
    if (j.is_string()) { out+='"'; for(unsigned char c:j.as_string()) { switch(c) { case '"':out+="\\\"";break; case '\\':out+="\\\\";break; case '\b':out+="\\b";break; case '\f':out+="\\f";break; case '\n':out+="\\n";break; case '\r':out+="\\r";break; case '\t':out+="\\t";break; default: if(c<0x20) { char b[7]; std::snprintf(b,sizeof(b),"\\u%04x",c); out+=b; } else out+=static_cast<char>(c); } } out+='"'; return; }
    if (j.is_array()) { out+='['; const auto& a=j.as_array(); for(size_t i=0;i<a.size();++i) { if(i) out+=','; if(pretty>=0){out+='\n';indent(out,(depth+1)*pretty);} stringify(a[i],out,pretty,depth+1); } if(!a.empty()&&pretty>=0){out+='\n';indent(out,depth*pretty);} out+=']'; return; }
    out+='{'; const auto& o=j.as_object(); size_t i=0; for(const auto& [k,v]:o) { if(i++) out+=','; if(pretty>=0){out+='\n';indent(out,(depth+1)*pretty);} stringify(Json(k),out,pretty,depth+1); out+= pretty>=0 ? ": " : ":"; stringify(v,out,pretty,depth+1); } if(!o.empty()&&pretty>=0){out+='\n';indent(out,depth*pretty);} out+='}';
}
}
Json Json::parse(std::string_view t) { return Parser(t).parse(); }
std::string Json::dump(int ind) const { std::string o; stringify(*this,o,ind,0); return o; }
bool Json::is_null() const { return std::holds_alternative<std::nullptr_t>(value_); }
bool Json::is_bool() const { return std::holds_alternative<bool>(value_); }
bool Json::is_number() const { return std::holds_alternative<std::int64_t>(value_) || std::holds_alternative<std::uint64_t>(value_) || std::holds_alternative<double>(value_); }
bool Json::is_string() const { return std::holds_alternative<std::string>(value_); }
bool Json::is_array() const { return std::holds_alternative<Array>(value_); }
bool Json::is_object() const { return std::holds_alternative<Object>(value_); }
bool Json::as_bool(bool f) const { if(auto p=std::get_if<bool>(&value_))return *p; return f; }
double Json::as_number(double f) const {
    if (auto p = std::get_if<double>(&value_)) return *p;
    if (auto p = std::get_if<std::int64_t>(&value_)) return static_cast<double>(*p);
    if (auto p = std::get_if<std::uint64_t>(&value_)) return static_cast<double>(*p);
    if (auto s = std::get_if<std::string>(&value_)) {
        try { std::size_t n = 0; double d = std::stod(*s, &n); if (n == s->size()) return d; } catch (...) {}
    }
    return f;
}
std::int64_t Json::as_i64(std::int64_t f) const {
    if (auto p = std::get_if<std::int64_t>(&value_)) return *p;
    if (auto p = std::get_if<std::uint64_t>(&value_)) return *p <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ? static_cast<std::int64_t>(*p) : f;
    double d = as_number(static_cast<double>(f));
    constexpr double lower = -9223372036854775808.0;
    constexpr double upper = 9223372036854775808.0;
    if (!std::isfinite(d) || std::floor(d) != d || d < lower || d >= upper) return f;
    return static_cast<std::int64_t>(d);
}
std::uint64_t Json::as_u64(std::uint64_t f) const {
    if (auto p = std::get_if<std::uint64_t>(&value_)) return *p;
    if (auto p = std::get_if<std::int64_t>(&value_)) return *p >= 0 ? static_cast<std::uint64_t>(*p) : f;
    double d = as_number(static_cast<double>(f));
    constexpr double upper = 18446744073709551616.0;
    if (!std::isfinite(d) || std::floor(d) != d || d < 0 || d >= upper) return f;
    return static_cast<std::uint64_t>(d);
}
std::string Json::number_string() const {
    if (auto p = std::get_if<std::int64_t>(&value_)) return std::to_string(*p);
    if (auto p = std::get_if<std::uint64_t>(&value_)) return std::to_string(*p);
    if (auto p = std::get_if<double>(&value_)) {
        if (std::floor(*p) == *p && std::abs(*p) < 9e15) return std::to_string(static_cast<std::int64_t>(*p));
        std::ostringstream ss; ss << std::setprecision(std::numeric_limits<double>::max_digits10) << *p; return ss.str();
    }
    return "0";
}
std::string Json::as_string(std::string f) const { if(auto p=std::get_if<std::string>(&value_))return *p; return f; }
const Json::Array& Json::as_array() const { static const Array empty; if(auto p=std::get_if<Array>(&value_))return *p; return empty; }
Json::Array& Json::as_array() { if(!is_array())value_=Array{}; return std::get<Array>(value_); }
const Json::Object& Json::as_object() const { static const Object empty; if(auto p=std::get_if<Object>(&value_))return *p; return empty; }
Json::Object& Json::as_object() { if(!is_object())value_=Object{}; return std::get<Object>(value_); }
bool Json::contains(std::string_view k) const { return is_object()&&as_object().find(std::string(k))!=as_object().end(); }
const Json& Json::at(std::string_view k) const { static const Json null; if(!is_object())return null; auto it=as_object().find(std::string(k)); return it==as_object().end()?null:it->second; }
Json& Json::operator[](const std::string& k) { if(!is_object())value_=Object{}; return std::get<Object>(value_)[k]; }
const Json& Json::operator[](std::size_t i) const { static const Json null; const auto& a=as_array(); return i<a.size()?a[i]:null; }
std::size_t Json::size() const { if(is_array())return as_array().size(); if(is_object())return as_object().size(); if(is_string())return as_string().size(); return 0; }
std::string read_text_file(const std::string& p) { std::ifstream f(p,std::ios::binary); if(!f)throw std::runtime_error("cannot open file: "+p); std::ostringstream s;s<<f.rdbuf();return s.str(); }
void write_text_file(const std::string& p,const std::string& c) { std::ofstream f(p,std::ios::binary); if(!f)throw std::runtime_error("cannot write file: "+p); f<<c; if(!f)throw std::runtime_error("failed writing file: "+p); }
std::string hex_bytes(const std::vector<std::uint8_t>& b) { std::ostringstream s;s<<std::hex<<std::setfill('0');for(auto x:b)s<<std::setw(2)<<static_cast<unsigned>(x);return s.str(); }
std::vector<std::uint8_t> parse_hex_bytes(std::string_view s) { std::vector<std::uint8_t> b; int hi=-1; for(char c:s) { if(c==' '||c=='\n'||c=='\r'||c=='\t'||c==':'||c=='-')continue; int v=-1;if(c>='0'&&c<='9')v=c-'0';else if(c>='a'&&c<='f')v=c-'a'+10;else if(c>='A'&&c<='F')v=c-'A'+10;else throw std::runtime_error("invalid hex character"); if(hi<0)hi=v;else{b.push_back(static_cast<std::uint8_t>((hi<<4)|v));hi=-1;} } if(hi>=0)throw std::runtime_error("hex string has odd number of digits");return b; }
std::string to_lower(std::string s) { for(char& c:s) if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return s; }
}
