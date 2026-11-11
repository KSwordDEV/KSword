#include "KswordCLI/ApiMonitorSignatureCatalog.h"
#include <iostream>
#include <stdexcept>
int wmain(int argc,wchar_t** argv) {
    if(argc!=2 && argc!=3)return 2;
    ks::cli::CliSignatureCatalog catalog;
    if(argc==3 && std::wstring(argv[2])==L"--invalid") {
        try { catalog.load(std::filesystem::path(argv[1])); }
        catch(const std::invalid_argument&) { return 0; }
        return 1;
    }
    catalog.load(std::filesystem::path(argv[1]));
    const auto* owned=catalog.find(L"KernelBase",L"CreateFileW");
    const auto* checked=catalog.find(L"USER32",L"GetMessageW");
    const auto* reference=catalog.find(L"aclui.dll",L"CreateSecurityPage");
    const bool candidate=argc==3 && std::wstring(argv[2])==L"--candidate";
    if((candidate ? catalog.size()<14000 : catalog.size()!=641) || catalog.sha256.size()!=64 || !owned || owned->abiEvidence!=L"project"
        || (candidate && (!checked || checked->abiEvidence!=L"Windows SDK x86/x64" || checked->parameters.empty()
        || !reference || reference->abiEvidence!=L"unverified" || reference->parameters.empty() || reference->parameters[0].direction!=L"unknown"))
        || (!candidate && (checked || reference))
        || catalog.find(L"C:\\Windows\\KernelBase.dll",L"CreateFileW")
        || catalog.find(L"KernelBase.exe",L"CreateFileW")
        || catalog.find(L"kernelbase",L"createfilew"))return 1;
    std::cout << "PASS CLI signatures: " << catalog.size() << " declarations, " << catalog.sha256 << '\n';
}
