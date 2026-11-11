#include "KswordCLI/ApiMonitorFilterImport.h"
#include <fstream>
#include <iostream>

using namespace ks::winapi_monitor;
static int checks=0;
static void check(bool value) { ++checks;if(!value)throw std::runtime_error("filter import assertion"); }
static ApiMonitorEventPacket packet(const wchar_t* module,const wchar_t* api) {
    ApiMonitorEventPacket p{};wcscpy_s(p.moduleName,module);wcscpy_s(p.apiName,api);
    p.category=static_cast<std::uint32_t>(EventCategory::File);return p;
}
static void write(const std::filesystem::path& path,const char* data) {
    std::ofstream f(path,std::ios::binary);f<<data;if(!f)throw std::runtime_error("fixture write");
}
int wmain(int argc,wchar_t** argv) {
    if(argc!=2)return 2;const auto file=std::filesystem::path(argv[1])/L"rules.json";
    write(file,R"({"version":2,"rules":[
      {"module":"KernelBase.dll","function":"","pre":true,"post":false,"preAllow":false,"postAllow":false},
      {"module":"KERNELBASE","function":"CreateFileW","pre":false,"post":false,"preAllow":true,"postAllow":false},
      {"module":"KernelBase","function":"WriteFile","pre":true,"post":true,"preAllow":true,"postAllow":false}]})");
    const auto rules=ks::cli::loadApiFilters(file);
    auto create=packet(L"KernelBase",L"CreateFileW");auto writeFile=packet(L"kernelbase",L"WriteFile");
    check(!rules.pre.excludes(create));check(rules.pre.excludes(writeFile));check(rules.post.excludes(writeFile));
    check(rules.pre.excludes(packet(L"KernelBase",L"createfilew")));
    CliEventFilter explicitRule;explicitRule.addList(L"kernelbase.dll",false);
    check(!rules.pre.excludes(create) && explicitRule.excludes(create));
    create.category=static_cast<std::uint32_t>(EventCategory::Internal);check(!explicitRule.excludes(create) && !rules.pre.excludes(create));
    write(file,R"({"version":1,"rules":[{"module":"abc","function":"X","pre":true,"post":false}]})");
    const auto v1=ks::cli::loadApiFilters(file);check(v1.pre.excludes(packet(L"ABC.dll",L"X")));check(!v1.post.excludes(packet(L"abc",L"X")));
    for(const char* invalid:{R"({"version":2,"rules":[{"module":"a","function":"","pre":true,"post":false,"preAllow":true,"postAllow":false}]})",
        R"({"version":2,"rules":[{"module":"a","function":"x","pre":true,"post":false}]})",
        R"({"version":3,"rules":[]})",R"({"version":"1","rules":[]})",
        R"({"version":1,"rules":[{"module":"a","function":"x","pre":1,"post":false}]})"}) {
        write(file,invalid);bool rejected=false;try{(void)ks::cli::loadApiFilters(file);}catch(const std::invalid_argument&){rejected=true;}check(rejected);
    }
    std::cout<<"PASS CLI filter import: "<<checks<<" assertions\n";
}
