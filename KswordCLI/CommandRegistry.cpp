#include "CommandRegistry.h"
#include <algorithm>
#include <cwctype>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <set>
#include <sstream>
#include <stdexcept>

namespace ks::cli {
namespace {
std::string narrowOption(const std::wstring& value) { std::string out; for (const auto ch : value) out += ch <= 127 ? static_cast<char>(ch) : '?'; return out; }
std::vector<Command> entries;
std::map<std::wstring, std::wstring> families;
std::vector<std::wstring> tokens(const std::wstring& path) {
    std::wistringstream input(path); std::vector<std::wstring> result;
    for (std::wstring value; input >> value;) result.push_back(value);
    return result;
}
std::set<std::wstring> options(const Command& command) {
    std::set<std::wstring> result{L"--json", L"--backend"};
    const auto& text = command.syntax;
    for (std::size_t at = 0; (at = text.find(L"--", at)) != std::wstring::npos;) {
        auto end = at + 2;
        while (end < text.size() && (std::iswalnum(text[end]) || text[end] == L'-')) ++end;
        result.insert(text.substr(at, end - at)); at = end;
    }
    return result;
}
int emit(const Command& command, const Args& args, const Result& result) {
    const wchar_t* status = result.code == 0 ? L"success" : result.code == 6 ? L"partial" : result.code == 5 ? L"unsupported" : L"failed";
    std::vector<Json> diagnostic;
    for (const auto& value : result.diagnostics) diagnostic.push_back(Json::string(value));
    if (args.has(L"--json")) {
        std::wcout << Json::object({{L"schemaVersion", Json::number(1)}, {L"command", Json::string(command.path)},
            {L"backend", Json::string(L"r3")}, {L"status", Json::string(status)}, {L"data", result.data},
            {L"diagnostics", Json::array(diagnostic)}}).text << L"\n";
    } else {
        std::wcout << L"command=" << command.path << L" backend=r3 status=" << status << L"\n"
                   << result.data.display << L"\n";
        for (const auto& value : result.diagnostics) std::wcout << L"diagnostic: " << value << L"\n";
    }
    return result.code;
}
}
Json Json::string(const std::wstring& value) {
    std::wostringstream out; out << L'"';
    for (const wchar_t c : value) {
        if (c == L'"' || c == L'\\') out << L'\\' << c;
        else if (c == L'\n') out << L"\\n";
        else if (c == L'\r') out << L"\\r";
        else if (c == L'\t') out << L"\\t";
        else if (static_cast<unsigned>(c) < 32 || (c >= 0xD800 && c <= 0xDFFF))
            out << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<unsigned>(c);
        else out << c;
    }
    out << L'"'; return {out.str(), value};
}
Json Json::number(std::uint32_t value) { return {std::to_wstring(value), std::to_wstring(value)}; }
Json Json::real(double value) {
    if (!std::isfinite(value)) return {};
    std::wostringstream out; out.imbue(std::locale::classic()); out << std::setprecision(17) << value;
    return {out.str(), out.str()};
}
Json Json::boolean(bool value) { return {value ? L"true" : L"false", value ? L"true" : L"false"}; }
Json Json::object(const std::vector<std::pair<std::wstring, Json>>& values) {
    std::wstring out = L"{", display;
    for (const auto& [name, value] : values) { if (out.size() > 1) out += L","; out += string(name).text + L":" + value.text;
        if (!display.empty()) display += L"\n"; display += name + L": " + value.display; }
    return {out + L"}", display};
}
Json Json::array(const std::vector<Json>& values) {
    std::wstring out = L"[", display;
    for (std::size_t i = 0; i < values.size(); ++i) { if (out.size() > 1) out += L","; out += values[i].text;
        display += L"\n[" + std::to_wstring(i) + L"] " + values[i].display; }
    return {out + L"]", values.empty() ? L"(empty)" : display};
}
Json Json::strings(const std::vector<std::wstring>& values) { std::vector<Json> rows; for (const auto& value : values) rows.push_back(string(value)); return array(rows); }
Json Json::count(std::uint64_t value) { return string(std::to_wstring(value)); }
Json Json::hex(std::uint64_t value) { std::wostringstream out; out << L"0x" << std::hex << value; return string(out.str()); }
Json Json::bytes(const std::vector<std::uint8_t>& value, std::size_t limit) {
    std::wostringstream out; out << std::hex << std::setfill(L'0');
    for (std::size_t i = 0; i < std::min(value.size(), limit); ++i) out << std::setw(2) << static_cast<unsigned>(value[i]);
    return string(out.str());
}
bool Args::has(const std::wstring& key) const { return values.contains(key); }
std::wstring Args::get(const std::wstring& key, const std::wstring& fallback) const { const auto it = values.find(key); return it == values.end() ? fallback : it->second; }
std::wstring Args::require(const std::wstring& key) const {
    if (!has(key)) throw std::invalid_argument("missing option " + narrowOption(key));
    return get(key);
}
std::uint64_t Args::integer(const std::wstring& key, std::uint64_t fallback) const {
    if (!has(key)) return fallback;
    const auto text = get(key); std::size_t consumed = 0;
    try { if (text.empty() || text[0] == L'-' || text[0] == L'+') throw std::invalid_argument("number");
        const auto value = std::stoull(text, &consumed, text.starts_with(L"0x") || text.starts_with(L"0X") ? 16 : 10);
        if (consumed == text.size()) return value;
    } catch (const std::exception&) {}
    throw std::invalid_argument("invalid integer for " + narrowOption(key));
}
std::uint32_t Args::u32(const std::wstring& key, std::uint32_t fallback) const {
    const auto value = integer(key, fallback);
    if (value > std::numeric_limits<std::uint32_t>::max()) throw std::invalid_argument("integer exceeds uint32");
    return static_cast<std::uint32_t>(value);
}
void addFamily(const std::wstring& name, const std::wstring& summary) { families.emplace(name, summary); }
void addCommand(Command command) {
    for (auto& existing : entries) if (existing.path == command.path) {
        if (!existing.run) { command.legacyDefault = true; command.legacySyntax = existing.syntax; command.legacyOptions = existing.options; }
        existing = std::move(command); return;
    }
    entries.push_back(std::move(command));
}
const std::vector<Command>& commands() { return entries; }
std::wstring commandPath(int argc, wchar_t* argv[], int first) {
    std::wstring path;
    for (int i = first; i < argc; ++i) {
        const std::wstring word = argv[i];
        if (word.starts_with(L"-") || word == L"help" || word == L"/?") break;
        if (!path.empty()) path += L" "; path += word;
    }
    return path;
}
bool printHelp(const std::wstring& path) {
    if (path.empty()) {
        std::wcout << L"KswordCLI CLI\nusage: KswordCLI.exe <family> [subcommands] [--named-options]\n"
                   << L"Help: help [path] | <path> help | <path> --help | -h | /?\nFamilies:\n";
        for (const auto& [name, summary] : families) std::wcout << L"  " << name << L"  " << summary << L"\n";
        return true;
    }
    const Command* leaf = nullptr; std::map<std::wstring, std::wstring> children;
    for (const auto& command : entries) {
        if (command.path == path) leaf = &command;
        if (!command.path.starts_with(path + L" ")) continue;
        auto tail = command.path.substr(path.size() + 1); const auto end = tail.find(L' ');
        children.emplace(tail.substr(0, end), end == std::wstring::npos ? command.summary : L"Subcommands; use help " + path + L" " + tail.substr(0, end));
    }
    if (!leaf && children.empty()) { std::wcerr << L"error: unknown command '" << path << L"'\n"; return false; }
    std::wcout << L"Command: " << path << L"\n";
    if (leaf) std::wcout << L"Syntax:\n  " << leaf->syntax << L"\nSummary:\n  " << leaf->summary << L"\nOptions:\n  " << leaf->options << L"\nNotes:\n  " << leaf->notes << L"\n";
    if (leaf && leaf->legacyDefault) std::wcout << L"Default/R0 syntax:\n  " << leaf->legacySyntax << L" [--backend r0]\n  " << leaf->legacyOptions << L"\n  Omit --backend to retain the existing R0 behavior and output. R3 requires explicit --backend r3.\n";
    if (!children.empty()) {
        std::wcout << L"Commands:\n";
        for (const auto& [name, summary] : children) {
            std::wcout << L"  KswordCLI.exe " << path << L" " << name << L"  " << summary << L"\n";
            for (const auto& entry : entries) if (entry.path == path + L" " + name && (!entry.run || entry.legacyDefault) &&
                (entry.options.find(L"Required:") != std::wstring::npos || entry.options.find(L"必填") != std::wstring::npos))
                std::wcout << L"    " << entry.options << L"\n";
        }
    }
    return true;
}
std::optional<int> dispatchR3(int& argc, wchar_t* argv[]) {
    const Command* found = nullptr; std::size_t count = 0;
    for (const auto& entry : entries) {
        if (!entry.run) continue;
        const auto words = tokens(entry.path);
        if (static_cast<std::size_t>(argc - 1) < words.size()) continue;
        bool match = true;
        for (std::size_t i = 0; i < words.size(); ++i) if (words[i] != argv[i + 1]) match = false;
        if (match && words.size() > count) { found = &entry; count = words.size(); }
    }
    if (!found) return std::nullopt;
    if (found->legacyDefault) {
        int selector = -1; bool duplicate = false;
        for (int i = static_cast<int>(count) + 1; i < argc; ++i) if (std::wstring(argv[i]) == L"--backend") {
            duplicate |= selector != -1; selector = i;
        }
        if (selector == -1) return std::nullopt;
        if (!duplicate && selector + 1 < argc && std::wstring(argv[selector + 1]) == L"r0") {
            for (int i = selector; i + 2 < argc; ++i) argv[i] = argv[i + 2];
            argc -= 2; return std::nullopt;
        }
    }
    Args args;
    for (int i = 1; i < argc; ++i) {
        if (found->acceptsTail && std::wstring(argv[i]) == L"--") break;
        if (std::wstring(argv[i]) == L"--json") args.values[L"--json"] = L"";
    }
    try {
        const auto allowed = options(*found);
        for (int i = static_cast<int>(count) + 1; i < argc; ++i) {
            const std::wstring key = argv[i];
            if (key == L"--" && found->acceptsTail) {
                for (++i; i < argc; ++i) args.tail.emplace_back(argv[i]);
                break;
            }
            if (!allowed.contains(key)) throw std::invalid_argument("unknown option " + narrowOption(key));
            if (args.has(key) && key != L"--json") throw std::invalid_argument("duplicate option");
            if (key == L"--json" || key == L"--confirm") { args.values[key] = L""; continue; }
            if (++i >= argc || std::wstring(argv[i]).starts_with(L"--")) throw std::invalid_argument("missing value for option " + narrowOption(key));
            args.values[key] = argv[i];
        }
        if (args.get(L"--backend", L"r3") != L"r3") throw std::invalid_argument("this command supports --backend r3 only");
        return emit(*found, args, found->run(args));
    } catch (const std::invalid_argument& e) {
        const std::string message = e.what(); const std::wstring wide(message.begin(), message.end());
        std::wcerr << L"error: " << wide << L"\nusage: " << found->syntax << L"\n";
        return emit(*found, args, {1, Json::object({}), {wide}});
    }
}
}
