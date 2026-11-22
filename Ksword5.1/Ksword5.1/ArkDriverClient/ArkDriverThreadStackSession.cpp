#include "ArkDriverClient.h"
#include "ArkThreadStackSymbols.h"
#include "../../../shared/usermode/backend/driver/DriverQueries.h"

#include <exception>

namespace ksword::ark
{
    namespace
    {
        // 输入 FILETIME，返回不经过浮点数转换的创建身份。
        std::uint64_t CreationTime(const FILETIME& value)
        {
            return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) | value.dwLowDateTime;
        }

        // 输入仍持有的原进程/线程句柄；只判断存活，不唤醒、挂起或修改目标。
        bool Alive(const DriverHandle& process, const DriverHandle& thread)
        {
            return ::WaitForSingleObject(process.native(), 0) == WAIT_TIMEOUT &&
                ::WaitForSingleObject(thread.native(), 0) == WAIT_TIMEOUT;
        }
    }

    VerifiedThreadStackCaptureResult DriverClient::captureVerifiedThreadStack(
        const KSWORD_ARK_THREAD_STACK_REQUEST& request, const std::wstring& localSymbolPath,
        const ThreadStackCaptureMethod method) const
    {
        VerifiedThreadStackCaptureResult result; // 身份失败不会触发设备打开或模块枚举。
        if (request.size != sizeof(request) || request.version != KSWORD_ARK_THREAD_STACK_VERSION ||
            !request.processId || !request.threadId || !request.expectedProcessCreationTime100ns ||
            !request.expectedThreadCreationTime100ns || !request.frameLimit ||
            request.frameLimit > KSWORD_ARK_THREAD_STACK_MAX_FRAMES || !request.timeoutMs ||
            request.timeoutMs > KSWORD_ARK_THREAD_STACK_MAX_TIMEOUT_MS || request.flags || request.reserved)
        {
            result.capture.io.win32Error = ERROR_INVALID_PARAMETER;
            result.capture.io.message = "Positive frozen identities and valid capture budgets are required";
            return result;
        }

        // 只申请公开身份和存活查询权限；原对象句柄覆盖请求与后续符号注释全过程。
        const DriverHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            FALSE, request.processId)); // 冻结的进程实例。
        const DriverHandle thread(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            FALSE, request.threadId)); // 冻结的线程实例。
        FILETIME processCreated{}, threadCreated{}, exited{}, kernel{}, user{}; // 公开 API 身份与计时输出。
        result.identityVerified = process.isValid() && thread.isValid() &&
            ::GetProcessIdOfThread(thread.native()) == request.processId &&
            ::GetProcessTimes(process.native(), &processCreated, &exited, &kernel, &user) &&
            ::GetThreadTimes(thread.native(), &threadCreated, &exited, &kernel, &user) &&
            CreationTime(processCreated) == request.expectedProcessCreationTime100ns &&
            CreationTime(threadCreated) == request.expectedThreadCreationTime100ns && Alive(process, thread);
        if (!result.identityVerified)
        {
            result.capture.io.win32Error = ERROR_INVALID_OWNER;
            result.capture.io.message = "Frozen process/thread identity mismatched, exited or inaccessible";
            return result;
        }

        // 模块表只是采集前后的映像范围观察，不伪装成加载中 PE/PDB 身份的独立证明。
        std::vector<ks::r3::driver::DriverOverviewRow> before; // 捕获前的只读模块快照。
        std::wstring moduleDiagnostic; // 模块枚举诊断不改变真正捕获的传输结果。
        try
        {
            if (!ks::r3::driver::QueryModuleInformation(before, moduleDiagnostic, nullptr, false))
            {
                before.clear(); // 返回失败也可能留下部分记录，不能把它当成完整的前侧模块观察。
            }
        }
        catch (const std::exception&)
        {
            before.clear(); // 模块观察失败不能阻止真实 R0 请求；缺少前侧观察时只允许裸地址。
        }
        result.deviceAccessAttempted = true;
        if (method != ThreadStackCaptureMethod::Apc)
        {
            auto savedRequest = request; // 同一冻结身份，独立 wire 版本，不能把两个来源的帧拼接。
            savedRequest.version = KSWORD_ARK_STACK_SNAPSHOT_VERSION;
            result.saved = snapshotThreadStack(savedRequest);
            result.usedSavedContext = true;
            result.capture.io = result.saved.io;
            result.capture.response = result.saved.response.capture;
            result.capture.unsupported = result.saved.unsupported;
        }
        // Auto 只对明确不支持的新端点使用旧 APC 诊断；快照失败或部分帧不重发采集。
        if (method == ThreadStackCaptureMethod::Apc ||
            (method == ThreadStackCaptureMethod::Auto && result.saved.unsupported))
        {
            result.usedSavedContext = false;
            result.capture = captureThreadStack(request);
        }
        result.targetAliveAtReadback = Alive(process, thread);
        if (!result.capture.io.ok || !result.targetAliveAtReadback)
        {
            return result; // 无效协议或目标已退出时，不把回执里的地址公开为帧。
        }

        if (result.capture.response.frameCount)
        {
            // 先保留每个已经核验的返回地址；符号处理失败时不得丢帧或重新执行另一次捕获。
            result.frames.reserve(result.capture.response.frameCount);
            for (unsigned long index = 0; index < result.capture.response.frameCount; ++index)
            {
                ThreadStackFrameSymbol frame; // 单个真实返回地址的裸投影，不附加未经确认的模块或符号。
                frame.address = result.capture.response.frames[index];
                result.frames.push_back(std::move(frame));
            }
            try
            {
                std::vector<ks::r3::driver::DriverOverviewRow> after; // 捕获后的独立模块范围观察。
                if (!ks::r3::driver::QueryModuleInformation(after, moduleDiagnostic, nullptr, false))
                {
                    after.clear(); // 不完整后侧观察禁用归属注释，但仍保留同次捕获的原始地址。
                }
                result.frames = ResolveThreadStackFrames(result.capture.response, before, after, localSymbolPath);
            }
            catch (const std::exception&)
            {
                // 保留上面的同批裸地址，不放宽精确 PDB 校验，也不把注释失败误报为内核采集失败。
            }
        }
        // 符号可能耗时；返回前再次检查同一对象，不能把退出后的迟到结果发布到 UI。
        result.targetAliveAtReadback = Alive(process, thread);
        if (!result.targetAliveAtReadback)
        {
            result.frames.clear();
        }
        return result;
    }
}
