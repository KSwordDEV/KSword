#pragma once

#include "WinApiMonitorProtocol.h"
#include <algorithm>
#include <array>
#include <cwctype>
#include <cwchar>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ks::winapi_monitor {
// Native CLI view options. Function names remain case-sensitive, module names
// use Windows ordinal case-insensitive comparison; neither is a wildcard.
struct CliModuleLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return ::CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_LESS_THAN;
    }
};
struct CliApiLess {
    bool operator()(const std::pair<std::wstring, std::wstring>& a, const std::pair<std::wstring, std::wstring>& b) const {
        CliModuleLess less;
        if (less(a.first,b.first)) return true;
        if (less(b.first,a.first)) return false;
        return a.second < b.second;
    }
};
// Only bare extensionless module names can receive the conventional .dll
// suffix. Paths and explicit extensions are never reduced to a basename.
inline std::wstring cliModuleIdentity(std::wstring value) {
    if (value.find_first_of(L"\\/:.") == std::wstring::npos) value += L".dll";
    return value;
}
inline std::wstring cliTrim(std::wstring text) {
    const auto space = [](wchar_t c) { return std::iswspace(c) != 0; };
    while (!text.empty() && space(text.front())) text.erase(text.begin());
    while (!text.empty() && space(text.back())) text.pop_back();
    return text;
}
struct CliEventFilter {
    std::set<std::wstring, CliModuleLess> modules;
    std::set<std::pair<std::wstring, std::wstring>, CliApiLess> functions;
    // Exception applies only to its own imported filter; command line rules
    // are stored separately and remain unconditional extra exclusions.
    std::set<std::pair<std::wstring, std::wstring>, CliApiLess> allowedFunctions;
    void addList(const std::wstring& input, bool api) {
        if (input.empty() || input.size() > 16000) throw std::invalid_argument("filter list must contain 1..16000 characters");
        std::size_t start = 0, count = 0;
        while (start <= input.size()) {
            auto end = input.find(L';', start); if (end == std::wstring::npos) end = input.size();
            const auto item = cliTrim(input.substr(start, end-start));
            if (item.empty() || item.find_first_of(L"\r\n\0", 0, 3) != std::wstring::npos || ++count > 1000)
                throw std::invalid_argument("invalid filter list entry");
            const auto split = item.find(L'!');
            if (!api) {
                if (split != std::wstring::npos || item.size() > 260) throw std::invalid_argument("module filters use module names");
                modules.insert(cliModuleIdentity(item));
            } else {
                if (split == std::wstring::npos || !split || split+1 == item.size() || item.find(L'!', split+1) != std::wstring::npos)
                    throw std::invalid_argument("API filters use module!function");
                auto module = cliTrim(item.substr(0,split)); auto function = cliTrim(item.substr(split+1));
                if (module.empty() || function.empty() || module.size() > 260 || function.size() > 1024)
                    throw std::invalid_argument("invalid API filter identity");
                functions.emplace(cliModuleIdentity(std::move(module)), std::move(function));
            }
            if (end == input.size()) break;
            start = end+1;
        }
    }
    template<std::size_t N> static std::wstring field(const wchar_t (&value)[N]) {
        return {value, std::find(value,value+N,L'\0')};
    }
    bool excludes(const ApiMonitorEventPacket& packet) const {
        if (isCoverageEvent(packet.eventKind) || packet.category == static_cast<std::uint32_t>(EventCategory::Internal)) return false;
        if (modules.empty() && functions.empty()) return false;
        const auto module = cliModuleIdentity(field(packet.moduleName));
        const auto identity=std::make_pair(module,field(packet.apiName));
        return functions.contains(identity) || (modules.contains(module) && !allowedFunctions.contains(identity));
    }
};

struct CliRawAbi {
    int bits = 0;
    std::vector<std::pair<std::wstring,std::uint64_t>> registers;
    std::vector<std::uint64_t> stack;
};
inline bool cliHex(const std::wstring& text, std::uint64_t& value, int bits) {
    if(text.size()<3 || text.size()>static_cast<std::size_t>(bits/4+2) || text[0]!=L'0' || text[1]!=L'x') return false;
    value=0;
    for(std::size_t i=2;i<text.size();++i) {
        const auto c=text[i]; unsigned d=0;
        if(c>=L'0' && c<=L'9') d=c-L'0';
        else if(c>=L'a' && c<=L'f') d=c-L'a'+10;
        else if(c>=L'A' && c<=L'F') d=c-L'A'+10;
        else return false;
        value=(value<<4)|d;
    }
    return true;
}
// Parse only complete Agent-produced entry snapshots; no claim is made that
// registers or stack words correspond to a particular argument or type.
inline bool cliParseRawAbi(const ApiMonitorEventPacket& packet, CliRawAbi& out) {
    if(packet.resultKind != static_cast<std::uint32_t>(EventResultKind::EntryOnly)) return false;
    const auto text=CliEventFilter::field(packet.detailText);
    const bool x64=text.find(L" params=raw abi=x64 ")!=std::wstring::npos;
    const bool x86=text.find(L" params=raw abi=x86 ")!=std::wstring::npos;
    if(x64==x86) return false;
    CliRawAbi parsed;parsed.bits=x64?64:32;
    const wchar_t* names64[]={L"RCX",L"RDX",L"R8",L"R9"};
    const wchar_t* names86[]={L"ECX",L"EDX"};
    const auto count=x64?4u:2u;
    for(unsigned i=0;i<count;++i) {
        const std::wstring name=x64?names64[i]:names86[i]; const auto needle=L" "+name+L"=";
        const auto at=text.find(needle);if(at==std::wstring::npos || text.find(needle,at+1)!=std::wstring::npos)return false;
        const auto begin=at+needle.size();const auto end=text.find(L' ',begin);
        if(end==std::wstring::npos)return false;
        std::uint64_t value=0;if(!cliHex(text.substr(begin,end-begin),value,parsed.bits))return false;
        parsed.registers.emplace_back(name,value);
    }
    constexpr auto marker=L" stackSlots=[";
    const auto at=text.find(marker);if(at==std::wstring::npos || text.find(marker,at+1)!=std::wstring::npos)return false;
    const auto begin=at+std::wcslen(marker);const auto end=text.find(L']',begin);
    if(end==std::wstring::npos)return false;
    auto current=begin;
    while(current<end) {
        auto separator=text.find(L',',current);if(separator==std::wstring::npos || separator>end)separator=end;
        std::uint64_t value=0;if(!cliHex(text.substr(current,separator-current),value,parsed.bits))return false;
        parsed.stack.push_back(value);if(parsed.stack.size()>4)return false;
        if(separator==end)break;current=separator+1;if(current==end)return false;
    }
    out=std::move(parsed);return true;
}

// Same bounded, adaptive density idea as GUI: counts every received ApiCall
// after prefilter, including events removed by postfilter or the output limit.
class CliTimeline final {
public:
    static constexpr std::size_t maxBuckets = 2048;
    static constexpr std::uint64_t initialWidth = 100000; // 10 ms, FILETIME ticks
    struct Cell { std::uint64_t count = 0, first = 0, last = 0; };
    using Cells = std::array<Cell,15>;
    void append(const ApiMonitorEventPacket& packet) {
        if (packet.eventKind != static_cast<std::uint32_t>(EventKind::ApiCall)
            || packet.category == static_cast<std::uint32_t>(EventCategory::Internal)) return;
        const auto t=packet.timestamp100ns;
        if (!t) { ++missing; return; }
        if (!count) first=last=t; else { first=(std::min)(first,t); last=(std::max)(last,t); }
        while (last/width-first/width>=maxBuckets) coarsen();
        std::size_t c=14;
        switch (static_cast<EventCategory>(packet.category)) {
        case EventCategory::File:c=0;break; case EventCategory::Registry:c=1;break;
        case EventCategory::Network:c=2;break; case EventCategory::Process:c=3;break;
        case EventCategory::Loader:c=4;break; case EventCategory::Clipboard:c=5;break;
        case EventCategory::Memory:c=6;break;
        case EventCategory::Thread:c=7;break;
        case EventCategory::Service:c=8;break;
        case EventCategory::Security:c=9;break;
        case EventCategory::Crypto:c=10;break;
        case EventCategory::Com:c=11;break;
        case EventCategory::Window:c=12;break;
        case EventCategory::Gui:c=13;break;
        default:break;
        }
        auto& cell=buckets[t/width][c];
        if (!cell.count) cell.first=cell.last=t;
        else {cell.first=(std::min)(cell.first,t);cell.last=(std::max)(cell.last,t);}
        if(cell.count != UINT64_MAX) ++cell.count;
        if(count != UINT64_MAX) ++count;
    }
    std::map<std::uint64_t,Cells> buckets;
    std::uint64_t first=0,last=0,count=0,missing=0,width=initialWidth;
private:
    void coarsen() {
        std::map<std::uint64_t,Cells> merged;
        for(const auto& [bucket,cells]:buckets) for(std::size_t i=0;i<cells.size();++i) {
            const auto& src=cells[i]; if(!src.count) continue; auto& dst=merged[bucket/2][i];
            if(!dst.count) dst=src; else {
                dst.first=(std::min)(dst.first,src.first);dst.last=(std::max)(dst.last,src.last);
                dst.count=src.count>UINT64_MAX-dst.count?UINT64_MAX:dst.count+src.count;
            }
        }
        buckets.swap(merged); width*=2;
    }
};
}
