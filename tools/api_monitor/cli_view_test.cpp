#include "shared/ApiMonitorCliView.h"
#include <iostream>
#include <stdexcept>

using namespace ks::winapi_monitor;
static int checks=0;
static void check(bool value) { ++checks; if (!value) throw std::runtime_error("CLI view assertion"); }
static ApiMonitorEventPacket event(const wchar_t* mod,const wchar_t* name,std::uint64_t time,EventCategory cat) {
    ApiMonitorEventPacket packet{}; wcsncpy_s(packet.moduleName,mod,_TRUNCATE); wcsncpy_s(packet.apiName,name,_TRUNCATE);
    packet.timestamp100ns=time;packet.category=static_cast<std::uint32_t>(cat);return packet;
}
int main() {
    CliEventFilter f; f.addList(L"kernelbase;USER32",false); f.addList(L"ntdll!NtQueryInformationProcess",true);
    auto p=event(L"KernelBase",L"ReadFile",123,EventCategory::File); check(f.excludes(p));
    p=event(L"ntdll",L"NtQueryInformationProcess",124,EventCategory::Process);check(f.excludes(p));
    p=event(L"NTDLL.dll",L"NtQueryInformationProcess",124,EventCategory::Process);check(f.excludes(p));
    p=event(L"C:\\Windows\\ntdll.dll",L"NtQueryInformationProcess",124,EventCategory::Process);check(!f.excludes(p));
    p=event(L"ntdll.exe",L"NtQueryInformationProcess",124,EventCategory::Process);check(!f.excludes(p));
    check(cliModuleIdentity(L"C:foo")==L"C:foo");
    check(cliModuleIdentity(L"foo")==L"foo.dll");
    p=event(L"NTDLL",L"ntqueryinformationprocess",124,EventCategory::Process);check(!f.excludes(p));
    p.category=static_cast<std::uint32_t>(EventCategory::Internal);check(!f.excludes(p));
    p.category=static_cast<std::uint32_t>(EventCategory::Process);p.eventKind=static_cast<std::uint32_t>(EventKind::CoverageItem);check(!f.excludes(p));
    p=event(L"test",L"F",124,EventCategory::Process);
    p.resultKind=static_cast<std::uint32_t>(EventResultKind::EntryOnly);
    wcscpy_s(p.detailText,L"Raw ABI fallback caller=0x3 strongTyped=0 params=raw abi=x64 RCX=0x1 RDX=0x2 R8=0x3 R9=0x4 stackSlots=[0x5,0x6]");
    CliRawAbi raw;check(cliParseRawAbi(p,raw));check(raw.bits==64 && raw.registers.size()==4 && raw.stack.size()==2 && raw.stack[1]==6);
    wcscpy_s(p.detailText,L"strongTyped=0 params=raw abi=x86 ECX=0x1 EDX=0x2 stackSlots=[0xffffffff]");
    check(cliParseRawAbi(p,raw) && raw.bits==32 && raw.stack[0]==UINT32_MAX);
    wcscpy_s(p.detailText,L"strongTyped=0 params=raw abi=x86 ECX=0x1 EDX=0x2 stackSlots=[0x100000000]");check(!cliParseRawAbi(p,raw));
    wcscpy_s(p.detailText,L"strongTyped=0 params=raw abi=x64 RCX=0x1 RDX=0x2 R8=0x3 R9=0x4 stackSlots=[0x5,");check(!cliParseRawAbi(p,raw));
    p.resultKind=static_cast<std::uint32_t>(EventResultKind::StatusCode);check(!cliParseRawAbi(p,raw));
    for(const auto* bad:{L"",L"module;",L";module",L"module!!f",L"!f",L"module!"}) {
        bool rejected=false;try { CliEventFilter t;t.addList(bad,true); } catch(const std::invalid_argument&) { rejected=true; }
        check(rejected);
    }
    CliTimeline timeline;
    constexpr std::uint64_t base=134381074585576380ULL;
    p=event(L"a",L"x",base,EventCategory::File);timeline.append(p);
    p=event(L"b",L"y",base+1000,EventCategory::Network);timeline.append(p);
    check(timeline.count==2 && timeline.buckets.size()==1);
    auto row=timeline.buckets.begin()->second;
    check(row[0].first==base && row[2].first==base+1000 && row[0].count==1 && row[2].count==1);
    p.timestamp100ns=0;timeline.append(p);check(timeline.missing==1 && timeline.count==2);
    p.timestamp100ns=base;p.category=static_cast<std::uint32_t>(EventCategory::Internal);timeline.append(p);check(timeline.count==2);
    for(std::uint64_t i=0;i<1000000;++i) {p.timestamp100ns=base+i*10000000ULL;p.category=static_cast<std::uint32_t>(EventCategory::File);timeline.append(p);}
    check(timeline.count==1000002 && timeline.buckets.size()<=CliTimeline::maxBuckets);
    std::uint64_t sum=0;for(const auto& [id,cells]:timeline.buckets) { (void)id;for(const auto& cell:cells) sum+=cell.count; }
    check(sum==timeline.count && timeline.width>=CliTimeline::initialWidth);
    std::cout << "PASS CLI view: " << checks << " assertions; events=" << timeline.count << " buckets=" << timeline.buckets.size() << '\n';
}
