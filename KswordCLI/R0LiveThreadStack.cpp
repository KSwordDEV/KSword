#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

namespace ks::cli
{
    namespace
    {
        // 输入 Windows FILETIME，输出无精度损失的对象创建身份。
        std::uint64_t PackTime(const FILETIME& time)
        {
            return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime;
        }

        // 输入协议业务结果，输出稳定诊断名；未知值只能由共享验证器拒绝。
        const wchar_t* CaptureResultName(const unsigned long value)
        {
            switch (value)
            {
            case KSWORD_ARK_STACK_SNAPSHOT_COMPLETE: return L"complete";
            case KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL: return L"partial";
            case KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH: return L"identity_mismatch";
            case KSWORD_ARK_THREAD_STACK_RESULT_TIMEOUT: return L"timeout";
            case KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE: return L"lifetime_unavailable";
            default: return L"unavailable";
            }
        }

        // 输入 CLI 参数，输出显式部分帧或拒绝；始终持有真实对象句柄，不暂停、恢复或修改目标。
        Result Capture(const Args& args)
        {
            (void)args.require(L"--pid");
            (void)args.require(L"--tid");
            (void)args.require(L"--creation-time");
            (void)args.require(L"--thread-creation-time");
            KSWORD_ARK_THREAD_STACK_REQUEST request{}; // 没有内核地址、任意偏移或用户回调输入。
            request.size = sizeof(request);
            request.version = KSWORD_ARK_THREAD_STACK_VERSION;
            request.processId = args.u32(L"--pid");
            request.threadId = args.u32(L"--tid");
            request.expectedProcessCreationTime100ns = args.integer(L"--creation-time");
            request.expectedThreadCreationTime100ns = args.integer(L"--thread-creation-time");
            request.frameLimit = args.u32(L"--limit", KSWORD_ARK_THREAD_STACK_MAX_FRAMES);
            request.timeoutMs = args.u32(L"--timeout-ms", 1000);
            const auto requestedMethod = args.get(L"--method", L"auto"); // 显式选择独立来源；自动模式也不拼接两次采集。
            const auto method = requestedMethod == L"auto" ? ksword::ark::ThreadStackCaptureMethod::Auto :
                requestedMethod == L"saved" ? ksword::ark::ThreadStackCaptureMethod::SavedContext :
                ksword::ark::ThreadStackCaptureMethod::Apc; // 下方先拒绝其他拼写，不能悄悄改成 APC。
            if (!request.processId || !request.threadId || !request.expectedProcessCreationTime100ns ||
                !request.expectedThreadCreationTime100ns || !request.frameLimit ||
                request.frameLimit > KSWORD_ARK_THREAD_STACK_MAX_FRAMES || !request.timeoutMs ||
                request.timeoutMs > KSWORD_ARK_THREAD_STACK_MAX_TIMEOUT_MS || args.get(L"--backend", L"r0") != L"r0" ||
                (requestedMethod != L"auto" && requestedMethod != L"saved" && requestedMethod != L"apc"))
            {
                throw std::invalid_argument("positive frozen identities, --limit 1..64, --timeout-ms 1..5000, --method auto|saved|apc and --backend r0 required");
            }

            const process::Lease process(args); // 原始进程句柄贯穿所有检查和驱动调用。
            ks::r3::common::UniqueHandle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                FALSE, request.threadId)); // 只申请身份/存活查询权限，不请求挂起或上下文修改。
            FILETIME created{}, exited{}, kernel{}, user{}; // GetThreadTimes 的独立公开身份结果。
            const bool identity = process.matches && process.alive() && thread.valid() &&
                GetProcessIdOfThread(thread.get()) == request.processId &&
                GetThreadTimes(thread.get(), &created, &exited, &kernel, &user) &&
                PackTime(created) == request.expectedThreadCreationTime100ns &&
                WaitForSingleObject(thread.get(), 0) == WAIT_TIMEOUT;
            if (!identity)
            {
                return {3, Json::object({{L"availability", Json::string(L"target_identity_unavailable")},
                    {L"target", process.json()}, {L"deviceAccessAttempted", Json::boolean(false)},
                    {L"frames", Json::array({})}}), {L"Held target identity mismatched, exited or inaccessible; no device access."}};
            }

            const auto session = ksword::ark::DriverClient().captureVerifiedThreadStack(request, std::wstring(), method); // GUI 与 CLI 使用同一持句柄采集和符号投影。
            const auto& captured = session.capture; // 固定协议回执仍完整保留，不以符号结果代替。
            const auto& response = captured.response; // 仅在完整协议被共享验证器接受后才能读取为证据。
            const bool alive = session.targetAliveAtReadback && process.alive() && WaitForSingleObject(thread.get(), 0) == WAIT_TIMEOUT;
            const bool accepted = captured.io.ok && alive; // 目标退出时不公开迟到帧。
            const bool complete = accepted && session.usedSavedContext && response.result == KSWORD_ARK_STACK_SNAPSHOT_COMPLETE; // 只有独立 wire 已验证真实用户机器帧边界才能完成。
            std::vector<Json> frames; // 保持系统展开顺序，不从栈字节搜索候选地址。
            if (accepted)
            {
                for (const auto& frame : session.frames)
                {
                    frames.push_back(Json::object({{L"address", Json::hex(frame.address)},
                        {L"module", Json::string(frame.moduleName)}, {L"moduleBase", Json::hex(frame.moduleBase)},
                        {L"symbol", Json::string(frame.symbolName)}, {L"displacement", Json::hex(frame.displacement)},
                        {L"localPdbMatched", Json::boolean(frame.localPdbMatched)}})); // 注释不改变原始帧地址或次序。
                }
            }
            const auto flag = [&response, accepted](const unsigned long bit) // 输入协议位，输出已验证事实。
            {
                return Json::boolean(accepted && (response.flags & bit) != 0);
            };
            std::vector<std::uint8_t> wire; // 完整固定原始回执供独立复核；拒绝包不作为可信证据公开。
            if (accepted)
            {
                const auto* begin = session.usedSavedContext ? reinterpret_cast<const std::uint8_t*>(&session.saved.response) :
                    reinterpret_cast<const std::uint8_t*>(&response); // 完整保留独立来源原始回执，不截成旧协议。
                wire.assign(begin, begin + (session.usedSavedContext ? sizeof(session.saved.response) : sizeof(response)));
            }
            int code = 3; // 身份、等待或执行失败不是成功。
            if (!captured.io.ok)
            {
                code = captured.io.deviceOpenFailed ? 2 : captured.io.win32Error == ERROR_INVALID_DATA ? 4 :
                    captured.unsupported ? 5 : 3;
            }
            else if (accepted)
            {
                code = complete ? 0 : response.frameCount ? 6 : captured.unsupported ? 5 : 3; // 真实部分帧仍返回 6，完整必须有机器帧边界证明。
            }
            return {code, Json::object({
                {L"availability", Json::string(accepted ? CaptureResultName(response.result) : L"transport_or_identity_failed")},
                {L"source", Json::string(accepted && response.source == KSWORD_ARK_STACK_SNAPSHOT_SOURCE ? L"target_saved_context" :
                    accepted && response.source == KSWORD_ARK_THREAD_STACK_SOURCE_TARGET_NORMAL_APC ? L"target_normal_apc" : L"none")},
                {L"live", Json::boolean(accepted && response.source != KSWORD_ARK_THREAD_STACK_SOURCE_NONE)},
                {L"complete", Json::boolean(complete)},
                {L"originalStackCompleteness", Json::string(complete ? L"kernel_chain_to_user_machine_frame" : L"unknown")},
                {L"requestedMethod", Json::string(requestedMethod)},
                {L"ioctlFunction", Json::hex(session.usedSavedContext ? KSWORD_ARK_IOCTL_FUNCTION_SNAPSHOT_THREAD_STACK : KSWORD_ARK_IOCTL_FUNCTION_CAPTURE_THREAD_STACK)},
                {L"savedContext", session.usedSavedContext && accepted ? Json::object({
                    {L"savedKernelStack", Json::hex(session.saved.response.savedKernelStack)},
                    {L"initialInstructionPointer", Json::hex(session.saved.response.initialInstructionPointer)},
                    {L"initialStackPointer", Json::hex(session.saved.response.initialStackPointer)},
                    {L"stackLow", Json::hex(session.saved.response.stackLow)}, {L"stackHigh", Json::hex(session.saved.response.stackHigh)},
                    {L"terminalInstructionPointer", Json::hex(session.saved.response.terminalInstructionPointer)},
                    {L"terminalStackPointer", Json::hex(session.saved.response.terminalStackPointer)},
                    {L"terminalCodeSegment", Json::hex(session.saved.response.terminalCodeSegment)},
                    {L"snapshotByteCount", Json::number(session.saved.response.snapshotByteCount)},
                    {L"processorCount", Json::number(session.saved.response.processorCount)},
                    {L"threadState", Json::number(session.saved.response.threadState)},
                    {L"unwindStop", Json::number(session.saved.response.unwindStop)} }) : Json{}},
                {L"frameProjection", Json::string(L"shared_gui_cli_verified_capture")},
                {L"symbolEvidence", Json::string(L"local_pe_pdb_match_only_not_live_image_attestation")},
                {L"target", process.json()}, {L"tid", Json::number(request.threadId)},
                {L"targetAliveAtReadback", Json::boolean(alive)},
                {L"identityVerified", flag(KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED)},
                {L"executedInTarget", flag(KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET)},
                {L"queued", flag(KSWORD_ARK_THREAD_STACK_FLAG_QUEUED)},
                {L"retirementVerified", flag(KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED)},
                {L"ownApcCancelled", flag(KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED)},
                {L"ntStatus", captured.io.ok ? Json::hex(static_cast<std::uint32_t>(response.status)) : Json{}},
                {L"requestTime100ns", accepted ? Json::count(response.requestTime100ns) : Json{}},
                {L"captureStartTime100ns", accepted && response.captureStartTime100ns ? Json::count(response.captureStartTime100ns) : Json{}},
                {L"captureEndTime100ns", accepted && response.captureEndTime100ns ? Json::count(response.captureEndTime100ns) : Json{}},
                {L"captureIrql", accepted && response.captureStartTime100ns ? Json::number(response.captureIrql) : Json{}},
                {L"frameCount", Json::number(static_cast<std::uint32_t>(frames.size()))},
                {L"frames", Json::array(frames)}, {L"wireResponse", accepted ? Json::bytes(wire, wire.size()) : Json{}},
                {L"deviceAccessAttempted", Json::boolean(session.deviceAccessAttempted)},
                {L"deviceOpenFailed", Json::boolean(captured.io.deviceOpenFailed)},
                {L"win32Error", Json::number(captured.io.win32Error)}
            }), {session.usedSavedContext ? L"Saved target context copied during a topology-guarded all-processor rendezvous; completeness requires a verified user machine-frame boundary. No target APC is queued." :
                L"Diagnostic only: real APC-time frames retain capture/dispatcher frames; they do not establish a complete pre-delivery target stack."}};
        }
    }

    // 在现有 query（R3/栈线索）与 dump（离线）旁注册独立在线诊断，避免改变旧命令语义。
    void registerR0LiveThreadStack()
    {
        Command command{L"process thread stack capture",
            L"KswordCLI.exe process thread stack capture --pid PID --tid TID --creation-time FILETIME --thread-creation-time FILETIME [--limit N] [--timeout-ms N] [--method auto|saved|apc] [--backend r0] [--json]",
            L"Capture an original saved-context kernel chain or explicit partial APC diagnostics.",
            L"Requires frozen creation times; --limit 1..64 (64), --timeout-ms 1..5000 (1000), --method auto (default), saved or apc; --backend r0 only.",
            L"Auto prefers saved context and uses APC only for an unsupported endpoint. No suspension, forced delivery, private cancellation or deferred pin. Verified user-boundary completion exits 0; partial exits 6; unsupported exits 5.",
            Capture}; // 帮助元数据与真实执行函数在同一登记点。
        command.supportsR0 = true;
        command.supportsR3 = false; // 顶层封套必须如实标记 R0，不能让默认 R3 与真实设备访问矛盾。
        command.defaultBackend = L"r0";
        addCommand(std::move(command));
    }
}
