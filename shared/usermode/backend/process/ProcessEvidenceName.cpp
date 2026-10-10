#include "ProcessEvidenceName.h"
namespace ks::r3::process {
std::wstring ProcessDisplayName(const std::uint32_t pid,ProcessImageEvidence* output,ULONGLONG expected){ProcessImageEvidence local;auto& e=output?*output:local;e={};if(!pid)return L"Idle/System";
    const auto path=SampleProcessImage(pid,MAX_PATH*4,expected,e);if(!e.available)return L"PID "+std::to_wstring(pid);const auto slash=path.find_last_of(L"\\/");return slash==std::wstring::npos?path:path.substr(slash+1);
}
}
