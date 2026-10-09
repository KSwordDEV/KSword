#include "NtQuery.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
std::pair<LONG, std::vector<std::byte>> QueryGrowable(const std::function<LONG(PVOID, ULONG, PULONG)>& query, ULONG initialSize) {
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    ULONG bufferSize = initialSize;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returned = 0;
        status = query(buffer.data(), bufferSize, &returned);
        if (IsSuccessStatus(status)) {
            return { status, std::move(buffer) };
        }
        if (!IsRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x1000);
    }
    return { status, std::move(buffer) };
}
void AppendNtQueryRow(QueryPacket& packet, const std::wstring& filter, const std::wstring& category, const std::wstring& functionName, ULONG infoClass, LONG status, std::size_t bytes, const std::wstring& detail) {
    KernelResultRow row = Row({
        { L"Category", category },
        { L"Function", functionName },
        { L"Class", std::to_wstring(infoClass) },
        { L"Status", StatusText(status) },
        { L"Success", IsSuccessStatus(status) ? L"true" : L"false" },
        { L"Bytes", std::to_wstring(bytes) },
        { L"Detail", detail },
    }, detail);
    if (MatchesColumnsFilter(row, filter)) {
        packet.rows.push_back(std::move(row));
    }
}
void AppendNtdllExportRows(QueryPacket& packet, const std::wstring& filter) {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        packet.warnings.push_back(L"ntdll.dll 未加载，无法枚举 NtQuery* 导出。");
        return;
    }

    const auto* base = reinterpret_cast<const std::byte*>(ntdll);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        packet.warnings.push_back(L"ntdll DOS 头无效。");
        return;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        packet.warnings.push_back(L"ntdll NT 头无效。");
        return;
    }
    const IMAGE_DATA_DIRECTORY& exportData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportData.VirtualAddress == 0 || exportData.Size == 0) {
        packet.warnings.push_back(L"ntdll 无导出目录。");
        return;
    }

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exportData.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
    const auto* functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);
    std::size_t added = 0;
    for (DWORD index = 0; index < exports->NumberOfNames && added < kMaxExportRows; ++index) {
        const char* exportName = reinterpret_cast<const char*>(base + names[index]);
        if (!exportName || std::strncmp(exportName, "NtQuery", 7) != 0) {
            continue;
        }
        const WORD ordinalIndex = ordinals[index];
        const DWORD rva = ordinalIndex < exports->NumberOfFunctions ? functions[ordinalIndex] : 0;
        const int wideLength = ::MultiByteToWideChar(CP_ACP, 0, exportName, -1, nullptr, 0);
        std::wstring wideName;
        if (wideLength > 0) {
            wideName.assign(static_cast<std::size_t>(wideLength - 1), L'\0');
            ::MultiByteToWideChar(CP_ACP, 0, exportName, -1, wideName.data(), wideLength);
        }
        KernelResultRow row = Row({
            { L"Category", L"Export" },
            { L"Function", wideName.empty() ? L"NtQuery*" : wideName },
            { L"Ordinal", std::to_wstring(exports->Base + ordinalIndex) },
            { L"RVA", HexText(rva) },
            { L"Status", L"Exported" },
        });
        if (MatchesColumnsFilter(row, filter)) {
            packet.rows.push_back(std::move(row));
            ++added;
        }
    }
}
KernelOperationResult QueryNtQueryLegacy(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    AppendNtdllExportRows(packet, request.filterText);

    if (runtime.querySystemInformation) {
        const std::array<ULONG, 6> classes{ 0, 2, 3, 5, 11, 16 };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.querySystemInformation(infoClass, data, size, returned);
            }, infoClass == 11 ? 1024 * 1024 : 128 * 1024);
            AppendNtQueryRow(packet, request.filterText, L"System", L"NtQuerySystemInformation", infoClass, status, buffer.size(), L"安全枚举类探测");
        }
    } else {
        packet.warnings.push_back(L"NtQuerySystemInformation 不可用。");
    }

    if (runtime.queryInformationProcess) {
        const std::array<ULONG, 4> classes{ 0, 7, 20, 27 };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryInformationProcess(::GetCurrentProcess(), infoClass, data, size, returned);
            }, 4096);
            AppendNtQueryRow(packet, request.filterText, L"Process", L"NtQueryInformationProcess", infoClass, status, buffer.size(), L"当前进程句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationProcess 不可用。");
    }

    if (runtime.queryInformationThread) {
        const std::array<ULONG, 2> classes{ 0, 1 };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryInformationThread(::GetCurrentThread(), infoClass, data, size, returned);
            }, 4096);
            AppendNtQueryRow(packet, request.filterText, L"Thread", L"NtQueryInformationThread", infoClass, status, buffer.size(), L"当前线程句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationThread 不可用。");
    }

    if (runtime.queryInformationToken) {
        HANDLE token = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
            const std::array<ULONG, 3> classes{ 1, 25, 10 };
            for (const ULONG infoClass : classes) {
                auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                    return runtime.queryInformationToken(token, infoClass, data, size, returned);
                }, 4096);
                AppendNtQueryRow(packet, request.filterText, L"Token", L"NtQueryInformationToken", infoClass, status, buffer.size(), L"当前进程令牌");
            }
            ::CloseHandle(token);
        } else {
            packet.warnings.push_back(std::wstring(L"OpenProcessToken 失败，Win32=") + std::to_wstring(::GetLastError()));
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationToken 不可用。");
    }

    if (runtime.queryObject) {
        const std::array<ULONG, 3> classes{ kObjectBasicInformation, kObjectNameInformation, kObjectTypeInformation };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryObject(::GetCurrentProcess(), infoClass, data, size, returned);
            }, 4096);
            AppendNtQueryRow(packet, request.filterText, L"Object", L"NtQueryObject", infoClass, status, buffer.size(), L"当前进程伪句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryObject 不可用。");
    }

    return MakeResult(request.featureId, !packet.rows.empty(), L"历史 NtQuery 探测", std::move(packet));
}
}
