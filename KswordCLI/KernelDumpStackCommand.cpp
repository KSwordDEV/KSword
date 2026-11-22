#include "CommandRegistry.h"
#include "../shared/usermode/KernelDumpThreadStack.h"

#include <stdexcept>

namespace ks::cli
{
    namespace
    {
        using kernel_dump::ThreadStackStatus;

        // 把共享状态映射为脚本可比较的名称，不依赖本地化诊断文本。
        const wchar_t* StatusName(const ThreadStackStatus status)
        {
            switch (status)
            {
            case ThreadStackStatus::Ok: return L"ok";
            case ThreadStackStatus::Partial: return L"partial";
            case ThreadStackStatus::InvalidRequest: return L"invalid_request";
            case ThreadStackStatus::EngineUnavailable: return L"engine_unavailable";
            case ThreadStackStatus::DumpOpenFailed: return L"dump_open_failed";
            case ThreadStackStatus::UnsupportedDump: return L"unsupported_dump";
            case ThreadStackStatus::ThreadNotFound: return L"thread_not_found";
            case ThreadStackStatus::IdentityMismatch: return L"identity_mismatch";
            case ThreadStackStatus::IdentityUnavailable: return L"identity_unavailable";
            case ThreadStackStatus::ContextUnavailable: return L"context_unavailable";
            case ThreadStackStatus::UnwindUnavailable: return L"unwind_unavailable";
            }
            return L"unknown";
        }

        // 仅查询显式指定的转储；不将转储 TID 与宿主机线程混用。
        Result RunDumpStack(const Args& args)
        {
            kernel_dump::ThreadStackRequest request; // 转储与目标身份在调用前冻结。
            request.dumpPath = args.require(L"--dump");
            (void)args.require(L"--pid");
            (void)args.require(L"--tid");
            request.processId = args.u32(L"--pid");
            request.threadId = args.u32(L"--tid");
            request.processCreationTime100ns = args.integer(L"--creation-time");
            request.threadCreationTime100ns = args.integer(L"--thread-creation-time");
            request.frameLimit = args.u32(L"--limit", kernel_dump::MaxThreadStackFrames);
            request.symbolPath = args.get(L"--symbols"); // 空值不自动连接符号服务器。
            if (!request.processId || !request.threadId || request.dumpPath.empty() || !request.frameLimit ||
                request.frameLimit > kernel_dump::MaxThreadStackFrames)
            {
                throw std::invalid_argument("--dump, positive --pid and --tid, and --limit 1..128 required");
            }

            const auto result = kernel_dump::UnwindThreadStack(request); // 和 GUI 使用同一读取/展开实现。
            std::vector<Json> frames; // 仅包含由 DbgEng 恢复的已匹配目标帧。
            frames.reserve(result.frames.size());
            for (const auto& frame : result.frames)
            {
                frames.push_back(Json::object({{L"index", Json::number(frame.index)},
                    {L"instruction", Json::hex(frame.instruction)}, {L"stack", Json::hex(frame.stack)},
                    {L"returnAddress", Json::hex(frame.returnAddress)},
                    {L"module", frame.module.empty() ? Json{} : Json::string(frame.module)},
                    {L"symbol", frame.symbol.empty() ? Json{} : Json::string(frame.symbol)},
                    {L"displacement", frame.symbol.empty() ? Json{} : Json::hex(frame.displacement)}}));
            }
            const auto code = result.status == ThreadStackStatus::Ok ? 0 : result.status == ThreadStackStatus::Partial ? 6 :
                result.status == ThreadStackStatus::InvalidRequest ? 1 : result.status == ThreadStackStatus::EngineUnavailable ? 2 : 5;
            return {code, Json::object({{L"source", Json::string(L"kernel_dump")}, {L"live", Json::boolean(false)},
                {L"status", Json::string(StatusName(result.status))}, {L"dump", Json::string(result.dumpPath)},
                {L"pid", Json::number(request.processId)}, {L"tid", Json::number(request.threadId)},
                {L"threadCreationTime", result.threadCreationTime100ns ? Json::count(result.threadCreationTime100ns) : Json{}},
                {L"processCreationTime", result.processCreationTime100ns ? Json::count(result.processCreationTime100ns) : Json{}},
                {L"dumpTimeUnixSeconds", result.dumpTimeUnixSeconds ? Json::number(result.dumpTimeUnixSeconds) : Json{}},
                {L"dumpQualifier", Json::number(result.dumpQualifier)}, {L"hresult", Json::hex(result.hresult)},
                {L"identityMatched", Json::boolean(result.identityMatched)}, {L"limited", Json::boolean(result.limited)},
                {L"frames", Json::array(frames)}}), result.diagnostic.empty() ? std::vector<std::wstring>{}
                    : std::vector<std::wstring>{result.diagnostic}};
        }
    }

    // 登记独立的离线命令，不重定义 stack query 的 R3 或 R0 行为。
    void registerKernelDumpStack()
    {
        addCommand({L"process thread stack dump",
            L"KswordCLI.exe process thread stack dump --dump PATH --pid PID --tid TID [--creation-time FILETIME] [--thread-creation-time FILETIME] [--symbols PATH] [--limit N] [--json]",
            L"Unwind an AMD64 thread's kernel stack from a local Windows kernel dump.",
            L"Required: --dump absolute path, --pid and --tid in the dump. Optional: creation FILETIMEs, --symbols DbgEng path, --limit 1..128.",
            L"Requires local x64 Debugging Tools. No live access or kernel driver is used. Selects and verifies the thread in the dump before unwinding.", RunDumpStack});
    }
}
