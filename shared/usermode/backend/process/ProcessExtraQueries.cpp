#include "ProcessExtraQueries.h"
#include "../../../../Ksword5.1/Ksword5.1/ksword/string/string.h"

namespace ks::r3::process {
namespace {
// Documented ABI, no SDK header is provided for these WIP entry points:
// https://learn.microsoft.com/windows/win32/devnotes/edp_context_structure
struct EdpContext {
    ULONG states;
    ULONG allowedCount;
    PWSTR uiIdentity;
    PWSTR allowedIdentities[1];
};

struct EdpBindings {
    using Get = HRESULT(WINAPI*)(DWORD, EdpContext**);
    using Free = void(WINAPI*)(EdpContext*);
    HMODULE module = ::LoadLibraryExW(L"edputil.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    Get get = module ? reinterpret_cast<Get>(::GetProcAddress(module, "EdpGetContextForProcess")) : nullptr;
    Free free = module ? reinterpret_cast<Free>(::GetProcAddress(module, "EdpFreeContext")) : nullptr;
    ~EdpBindings() { if (module) ::FreeLibrary(module); }
};

std::string EnterpriseContext(DWORD pid) {
    static const EdpBindings bindings;
    if (!bindings.get || !bindings.free) return ks::str::Utf16ToUtf8(L"系统不支持 WIP 查询");
    struct ContextOwner {
        EdpContext* value = nullptr;
        EdpBindings::Free free = nullptr;
        ~ContextOwner() { if (value) free(value); }
    } context{ nullptr, bindings.free };
    const HRESULT result = bindings.get(pid, &context.value);
    if (FAILED(result) || !context.value) {
        wchar_t error[64]{};
        ::swprintf_s(error, L"WIP 查询失败：0x%08lX", static_cast<unsigned long>(result));
        return ks::str::Utf16ToUtf8(error);
    }
    std::wstring text;
    const ULONG states = context.value->states;
    const auto add = [&text](const wchar_t* value) { if (!text.empty()) text += L" / "; text += value; };
    if (states == 0) add(L"个人");
    if (states & 0x1U) add(L"豁免");
    if (states & 0x2U) add(L"企业与个人");
    if (states & 0x4U) add(L"仅企业");
    if (states & 0x8U) add(L"允许企业网络访问");
    if (states & 0x10U) add(L"复制豁免");
    if (states & 0x20U) add(L"个人（企业访问被拒绝）");
    if (states & ~0x3fU) {
        wchar_t unknown[64]{};
        ::swprintf_s(unknown, L"其它状态：0x%08lX", static_cast<unsigned long>(states & ~0x3fU));
        add(unknown);
    }
    if (context.value->uiIdentity && context.value->uiIdentity[0]) {
        text += L"：";
        text += context.value->uiIdentity;
    }
    return ks::str::Utf16ToUtf8(text);
}

void QueryEfficiencyFallback(ks::process::ProcessRecord& record) {
    if (record.efficiencyModeSupported || record.pid <= 4) return;
    // ProcessPowerThrottlingState (77), POWER_THROTTLING_PROCESS_STATE:
    // https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
    using Query = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const auto query = ntdll ? reinterpret_cast<Query>(::GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
    if (!query) return;
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, record.pid);
    if (!process) return;
    struct PowerState { ULONG version; ULONG controlMask; ULONG stateMask; } state{ 1, 0, 0 };
    const LONG status = query(process, 77, &state, sizeof(state), nullptr);
    ::CloseHandle(process);
    if (status >= 0) {
        record.efficiencyModeSupported = true;
        record.efficiencyModeEnabled = (state.controlMask & state.stateMask & 1U) != 0;
    }
}
} // namespace

void QueryProcessExtraDetails(ks::process::ProcessRecord& record, std::uint32_t demand, bool needEfficiency) {
    if (demand & ks::process::ProcessDetailDemand::EnterpriseContext)
        record.enterpriseContextText = EnterpriseContext(record.pid);
    if (needEfficiency) QueryEfficiencyFallback(record);
}

} // namespace ks::r3::process
