// 合成会话回归：真实自有线程只用于身份/存活查询，采集、模块与符号边界全部替换；不打开驱动。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkThreadStackSymbols.h"
#include "../../shared/usermode/backend/driver/DriverQueries.h"
#include <cstdio>
#include <stdexcept>

namespace
{
    enum class Failure { None, Before, After, BeforeFalse, AfterFalse, Symbols, Transport, Exit }; // 当前注入点只影响本测试边界。
    Failure failure = Failure::None; // 各用例串行执行，不与生产或其它进程共享。
    unsigned captures = 0; // 证明注释失败不会重发捕获请求。
    unsigned observations = 0; // 区分采集前后模块快照。
    unsigned savedCaptures = 0; // 证明首选新来源时没有悄悄重复执行旧 APC。
    enum class SavedMode { Unsupported, Success, Failure }; // 新来源的三个独立传输替身。
    SavedMode savedMode = SavedMode::Unsupported; // 旧回归默认保留端点不支持的兼容路径。
    HANDLE exitEvent = nullptr; // 自有工作线程正常退出信号，不使用终止/挂起 API。
    HANDLE targetThread = nullptr; // 与冻结身份对应的原线程句柄。
    constexpr std::uint64_t address = 0xfffff80010001000ULL; // 明确为合成返回地址，不能作为现场帧证据。

    // 输入自有退出事件；线程只等待，供生产会话的公开身份与存活查询使用。
    DWORD WINAPI WaitOwnedThread(void* event)
    {
        return WaitForSingleObject(static_cast<HANDLE>(event), INFINITE) == WAIT_OBJECT_0 ? 0 : 1;
    }

    // 输入公开 FILETIME，输出无浮点损失的请求身份。
    std::uint64_t CreationTime(const FILETIME& time)
    {
        return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime;
    }
}

namespace ks::r3::driver
{
    // 仅替换模块枚举边界，故意先写入部分记录再抛异常，验证生产会话不误信半快照。
    bool QueryModuleInformation(std::vector<DriverOverviewRow>& rows, std::wstring& diagnostic,
        DriverEnumerationEvidence* evidence, bool signature)
    {
        (void)diagnostic;
        (void)evidence;
        (void)signature;
        rows.emplace_back();
        ++observations;
        if ((failure == Failure::Before && observations == 1) ||
            (failure == Failure::After && observations == 2))
        {
            throw std::runtime_error("synthetic module enumeration failure");
        }
        return !((failure == Failure::BeforeFalse && observations == 1) ||
            (failure == Failure::AfterFalse && observations == 2)); // 普通失败返回也可能附带半快照。
    }
}

namespace ksword::ark
{
    // 新端点缺失的合成替身：自动模式必须保留旧驱动的显式 APC 诊断兼容路径。
    ThreadStackSnapshotResult DriverClient::snapshotThreadStack(const KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST& request) const
    {
        ThreadStackSnapshotResult result; // 不创建真实设备，后续 APC 捕获次数仍必须恰好一次。
        ++savedCaptures;
        if (savedMode != SavedMode::Unsupported)
        {
            result.io.ok = savedMode == SavedMode::Success;
            result.io.win32Error = result.io.ok ? 0 : ERROR_INVALID_DATA;
            result.response.capture.frameCount = result.io.ok ? 1UL : 0UL;
            result.response.capture.frames[0] = result.io.ok ? address : 0;
            result.response.capture.processId = request.processId;
            result.response.capture.threadId = request.threadId;
            return result; // 即使新来源失败，也不设置 unsupported 来诱发第二次 APC 捕获。
        }
        result.io.win32Error = ERROR_INVALID_FUNCTION;
        result.unsupported = true;
        return result;
    }

    // 仅替换 R0 传输边界；绝不创建控制设备句柄或宣称取得了真实内核帧。
    ThreadStackCaptureResult DriverClient::captureThreadStack(const KSWORD_ARK_THREAD_STACK_REQUEST& request) const
    {
        ++captures;
        ThreadStackCaptureResult result; // 已校验响应的合成替身，字节校验另由 wire 测试覆盖。
        result.io.ok = failure != Failure::Transport;
        result.response.frameCount = result.io.ok ? 1UL : 0UL;
        result.response.frames[0] = result.io.ok ? address : 0;
        result.response.processId = request.processId;
        result.response.threadId = request.threadId;
        return result;
    }

    // 仅替换符号边界；只在两侧观察都存在时附加合成符号，并覆盖解析过程中目标退出。
    std::vector<ThreadStackFrameSymbol> ResolveThreadStackFrames(const KSWORD_ARK_THREAD_STACK_RESPONSE& response,
        const std::vector<ks::r3::driver::DriverOverviewRow>& before,
        const std::vector<ks::r3::driver::DriverOverviewRow>& after, const std::wstring& path)
    {
        (void)path;
        if (failure == Failure::Symbols)
        {
            throw std::runtime_error("synthetic symbol failure");
        }
        ThreadStackFrameSymbol frame; // 与唯一合成返回地址一一对应。
        frame.address = response.frames[0];
        if (!before.empty() && !after.empty())
        {
            frame.symbolName = L"synthetic_symbol";
            frame.localPdbMatched = true;
        }
        if (failure == Failure::Exit)
        {
            SetEvent(exitEvent);
            if (WaitForSingleObject(targetThread, 5000) != WAIT_OBJECT_0)
            {
                throw std::runtime_error("owned target did not exit");
            }
        }
        return {frame};
    }
}

// 输入无；输出合成会话用例结果。测试退出总是正常唤醒并等待原线程，不操作外部目标。
int main()
{
    exitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD tid = 0; // 保存新建线程的真实数值身份。
    targetThread = exitEvent ? CreateThread(nullptr, 0, WaitOwnedThread, exitEvent, 0, &tid) : nullptr;
    if (!targetThread)
    {
        if (exitEvent) CloseHandle(exitEvent);
        return 2;
    }
    FILETIME processCreated{}, threadCreated{}, exited{}, kernel{}, user{}; // 真实 API 的独立身份输出。
    KSWORD_ARK_THREAD_STACK_REQUEST request{}; // 唯一共享协议的合法输入，不增加测试专用字段。
    request.size = sizeof(request);
    request.version = KSWORD_ARK_THREAD_STACK_VERSION;
    request.processId = GetCurrentProcessId();
    request.threadId = tid;
    request.frameLimit = 64;
    request.timeoutMs = 1000;
    bool passed = GetProcessTimes(GetCurrentProcess(), &processCreated, &exited, &kernel, &user) &&
        GetThreadTimes(targetThread, &threadCreated, &exited, &kernel, &user);
    request.expectedProcessCreationTime100ns = CreationTime(processCreated);
    request.expectedThreadCreationTime100ns = CreationTime(threadCreated);

    // 同一个真实实例覆盖全部注释失败点；每次最多调用一次合成捕获。
    const ksword::ark::DriverClient client; // 链接生产会话实现，而非另写一份身份控制流。
    for (const auto kind : {Failure::None, Failure::Before, Failure::After, Failure::BeforeFalse,
        Failure::AfterFalse, Failure::Symbols, Failure::Transport})
    {
        failure = kind;
        captures = observations = 0;
        const auto result = client.captureVerifiedThreadStack(request); // 只运行身份会话，不运行驱动。
        const bool transport = kind != Failure::Transport; // 运输失败不能保留符号替身产生的帧。
        const bool symbols = kind == Failure::None;
        passed = passed && result.identityVerified && result.targetAliveAtReadback &&
            result.deviceAccessAttempted && captures == 1 && result.capture.io.ok == transport &&
            result.frames.size() == (transport ? 1U : 0U);
        if (transport && result.frames.size() == 1)
        {
            passed = passed && result.frames[0].address == address && result.frames[0].localPdbMatched == symbols;
        }
    }

    // 独立新来源、自动首选及真正失败不回退分别验证；仍然没有任何真实驱动访问。
    savedMode = SavedMode::Success;
    failure = Failure::None;
    for (const auto method : {ksword::ark::ThreadStackCaptureMethod::SavedContext, ksword::ark::ThreadStackCaptureMethod::Auto})
    {
        captures = observations = savedCaptures = 0;
        const auto result = client.captureVerifiedThreadStack(request, std::wstring(), method);
        passed = passed && result.usedSavedContext && result.capture.io.ok && savedCaptures == 1 && captures == 0 && result.frames.size() == 1;
    }
    savedMode = SavedMode::Failure;
    captures = observations = savedCaptures = 0;
    const auto failedSaved = client.captureVerifiedThreadStack(request);
    passed = passed && failedSaved.usedSavedContext && !failedSaved.capture.io.ok && savedCaptures == 1 && captures == 0 && failedSaved.frames.empty();
    savedMode = SavedMode::Unsupported;

    // 错误创建身份必须在设备边界前拒绝；最终退出后不得发布迟到的合成帧。
    captures = observations = 0;
    auto wrong = request; // 只修改线程创建时间，不换成另一个活动实例。
    ++wrong.expectedThreadCreationTime100ns;
    const auto refused = client.captureVerifiedThreadStack(wrong);
    passed = passed && !refused.identityVerified && !refused.deviceAccessAttempted && captures == 0;
    failure = Failure::Exit;
    const auto late = client.captureVerifiedThreadStack(request);
    passed = passed && late.identityVerified && !late.targetAliveAtReadback && late.frames.empty();
    SetEvent(exitEvent);
    passed = WaitForSingleObject(targetThread, 5000) == WAIT_OBJECT_0 && passed;
    CloseHandle(targetThread);
    CloseHandle(exitEvent);
    std::printf("LIVE_STACK_SYNTHETIC_SESSION_ONLY=%s cases=12; no driver access\n", passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
