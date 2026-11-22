#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

namespace ks::cli
{
    // 从已验证的进程与线程读取现有 R0 边界数据；不挂起、不读取栈内容、不生成栈帧。
    Result queryR0ThreadStackClues(const Args& args)
    {
        const auto tid = args.u32(L"--tid"); // 目标内核线程标识。
        const auto expected = args.integer(L"--thread-creation-time"); // 调用者冻结的 FILETIME。
        (void)args.require(L"--tid");
        (void)args.require(L"--thread-creation-time");
        if (!tid || !expected || args.has(L"--limit"))
        {
            throw std::invalid_argument("positive --tid and --thread-creation-time required; --limit is R3 only");
        }

        const process::Lease process(args); // 持有已核对的进程对象，避免 PID 复用。
        const ks::r3::common::UniqueHandle thread(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
        FILETIME created{}, exited{}, kernel{}, user{}; // 查询原线程对象的身份时间。
        if (!process.matches || !process.alive() || !thread.valid() ||
            ::GetProcessIdOfThread(thread.get()) != process.pid ||
            !::GetThreadTimes(thread.get(), &created, &exited, &kernel, &user) ||
            ((static_cast<std::uint64_t>(created.dwHighDateTime) << 32U) | created.dwLowDateTime) != expected ||
            ::WaitForSingleObject(thread.get(), 0) != WAIT_TIMEOUT)
        {
            return {3, Json::object({{L"target", process.json()}, {L"tid", Json::number(tid)}, {L"requestAttempted", Json::boolean(false)}}),
                {L"Thread identity is unavailable, mismatched or exited; no R0 request was sent."}};
        }

        // 用现有只读协议采样。组状态可能是部分可用，例如只返回非零 KernelStack。
        const auto detail = ksword::ark::DriverClient().queryThreadRuntimeDetail(tid, process.pid,
            KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY | KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK);
        const auto& data = detail.response; // 固定协议回执。
        const bool matched = detail.io.ok && data.version == KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION &&
            data.threadId == tid && data.processId == process.pid &&
            (data.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY) != 0;
        const bool alive = process.alive() && ::WaitForSingleObject(thread.get(), 0) == WAIT_TIMEOUT;
        const bool accepted = matched && alive; // 查询期间退出时不把旧值当成当前现场。
        const bool hasClues = accepted && (data.kernelStack || data.initialStack || data.stackBase || data.stackLimit);
        const auto clue = [hasClues](const std::uint64_t value)
        {
            return hasClues && value ? Json::hex(value) : Json{};
        };
        const int code = !detail.io.ok ? (detail.io.deviceOpenFailed ? 2 : detail.unsupported ? 5 : 3)
            : !matched ? 4 : !alive ? 3 : hasClues ? 6 : 5;
        std::vector<std::wstring> diagnostics; // 原始输运消息和明确的证据不足说明。
        if (!detail.io.message.empty())
        {
            diagnostics.emplace_back(detail.io.message.begin(), detail.io.message.end());
        }
        diagnostics.push_back(hasClues
            ? L"KTHREAD pointers are unverified diagnostic clues, not kernel call frames."
            : L"No kernel call frames or usable stack clues were captured.");
        return {code, Json::object({{L"target", process.json()}, {L"tid", Json::number(tid)},
            {L"threadCreationTime", Json::count(expected)}, {L"requestAttempted", Json::boolean(true)},
            {L"identityMatched", Json::boolean(matched)}, {L"targetAlive", Json::boolean(alive)},
            {L"win32Error", Json::number(detail.io.win32Error)}, {L"ntStatus", Json::hex(static_cast<std::uint32_t>(data.lastStatus))},
            {L"trust", Json::string(hasClues ? L"unverified_clue" : L"unavailable")},
            {L"kernelStack", clue(data.kernelStack)}, {L"initialStack", clue(data.initialStack)},
            {L"stackBase", clue(data.stackBase)}, {L"stackLimit", clue(data.stackLimit)}, {L"frames", Json::array({})}}),
            std::move(diagnostics)};
    }
}
