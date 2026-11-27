#pragma once
#include "ApiMonitorInjectionProtocol.h"

namespace ks::winapi_monitor {
// 独立于原观察包ABI。调度请求在原API前交接；新执行区域在成功分配/改保护后、返回调用者前交接。
inline constexpr DWORD kTransferHandoffVersion = 2; // operationId区分同入口的不同内存API调用及Pending重连。
enum class TransferHandoffKind : DWORD {
    ThreadCreate = 1, Apc = 2, Context = 3, ExecutableRegion = 4,
    ExecutableWritePrepare = 5, // 写前请求范围设防，不代表原写入成功或实际完成长度。
    ThreadResume = 6 // 恢复调用前读取到的真实线程IP；不证明恢复成功或线程已执行。
};
struct TransferHandoffRequest {
    DWORD size = sizeof(TransferHandoffRequest), version = kTransferHandoffVersion;
    DWORD kind = 0, targetPid = 0;
    std::uint64_t sourceCreation = 0, targetCreation = 0, address = 0, operationId = 0; // 同源同入口的独立API调用编号，Pending重连沿用。
    wchar_t token[128]{};
};
struct TransferHandoffResponse {
    DWORD size = sizeof(TransferHandoffResponse), version = kTransferHandoffVersion;
    DWORD error = ERROR_INVALID_DATA, reserved = 0;
    std::uint64_t rangeBase = 0, rangeBytes = 0;
};
static_assert(sizeof(TransferHandoffRequest) == 304 && sizeof(TransferHandoffResponse) == 32);

inline std::uint64_t transferProcessCreation(HANDLE process)
{
    // 输入持有的真实进程句柄，输出创建FILETIME；读取失败返回0，不用PID补身份。
    FILETIME created{}, exited{}, kernel{}, user{};
    return GetProcessTimes(process, &created, &exited, &kernel, &user)
        ? (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime : 0;
}

inline bool requestTransferHandoff(const InjectionEndpoint& endpoint, TransferHandoffRequest request,
    TransferHandoffResponse& response)
{
    // 输入本轮配置端点与冻结目标请求；同步等待目标外布防回执，输出成功/原生错误。
    if (endpoint.pipeName.empty() || endpoint.token.empty() || endpoint.token.size() >= 128 ||
        !endpoint.hostPid || !endpoint.hostCreation) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    HANDLE host = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, endpoint.hostPid);
    const bool sameHost = host && transferProcessCreation(host) == endpoint.hostCreation;
    if (host) CloseHandle(host);
    if (!sameHost) { SetLastError(ERROR_INVALID_HANDLE); return false; }
    wcscpy_s(request.token, endpoint.token.c_str());
    request.sourceCreation = transferProcessCreation(GetCurrentProcess());
    const auto deadline = GetTickCount64() + 15000;
    // Pending仅释放单客户端连接，Hook继续等待最终ACK；让后台安装期间的其它交接也能被主worker服务。
    while (GetTickCount64() < deadline) {
        HANDLE pipe = CreateFileW(endpoint.pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            if (error != ERROR_PIPE_BUSY) { SetLastError(error); return false; }
            WaitNamedPipeW(endpoint.pipeName.c_str(), 20);
            continue;
        }
        ULONG server = 0;
        DWORD mode = PIPE_READMODE_MESSAGE;
        const auto beforeWrite = GetTickCount64();
        const auto remaining = static_cast<DWORD>(deadline > beforeWrite ? deadline - beforeWrite : 0);
        SetLastError(ERROR_SUCCESS); // 同宿主PID不匹配时给出本次认证错误，不继承上次PipeBusy。
        bool ok = remaining && GetNamedPipeServerProcessId(pipe, &server) && server == endpoint.hostPid &&
            SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
        if (ok) ok = injectionPipeTransfer(pipe, &request, sizeof(request), true, nullptr, remaining);
        const auto now = GetTickCount64();
        if (ok) ok = now < deadline && injectionPipeTransfer(pipe, &response, sizeof(response), false, nullptr,
            static_cast<DWORD>(deadline - now));
        const auto nativeError = GetLastError();
        DWORD error = ok ? ERROR_SUCCESS : GetTickCount64() >= deadline ? ERROR_TIMEOUT :
            nativeError ? nativeError : ERROR_ACCESS_DENIED;
        CloseHandle(pipe);
        if (ok && (response.size != sizeof(response) || response.version != kTransferHandoffVersion || response.reserved)) {
            ok = false; error = ERROR_INVALID_DATA;
        }
        if (ok && response.error == ERROR_IO_PENDING) { Sleep(5); continue; }
        if (ok && response.error) { ok = false; error = response.error; }
        SetLastError(error);
        return ok;
    }
    SetLastError(ERROR_TIMEOUT);
    return false;
}
}
