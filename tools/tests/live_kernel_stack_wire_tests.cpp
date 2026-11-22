#include "../../shared/usermode/LiveKernelThreadStack.h"

#include <cstdio>
#include <functional>
#include <vector>

namespace
{
    // 返回明确的合成请求；只用于验证器测试，不打开设备或向任何线程投递。
    KSWORD_ARK_THREAD_STACK_REQUEST Request()
    {
        KSWORD_ARK_THREAD_STACK_REQUEST value{}; // 固定大小与零保留字段。
        value.size = sizeof(value);
        value.version = KSWORD_ARK_THREAD_STACK_VERSION;
        value.processId = 123;
        value.threadId = 456;
        value.expectedProcessCreationTime100ns = 100;
        value.expectedThreadCreationTime100ns = 101;
        value.frameLimit = 64;
        value.timeoutMs = 100;
        return value;
    }

    // 为给定请求构造自洽的合成部分帧；地址都是测试数字，不是实采证据。
    KSWORD_ARK_THREAD_STACK_RESPONSE Partial(const KSWORD_ARK_THREAD_STACK_REQUEST& request)
    {
        KSWORD_ARK_THREAD_STACK_RESPONSE value{}; // 未用帧必须为零。
        value.size = sizeof(value);
        value.version = request.version;
        value.result = KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL;
        value.source = KSWORD_ARK_THREAD_STACK_SOURCE_TARGET_NORMAL_APC;
        value.flags = KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED | KSWORD_ARK_THREAD_STACK_FLAG_QUEUED |
            KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET | KSWORD_ARK_THREAD_STACK_FLAG_APC_ENTRY_FRAMES |
            KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN | KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED;
        value.processId = value.currentProcessId = request.processId;
        value.threadId = value.currentThreadId = request.threadId;
        value.processCreationTime100ns = value.currentProcessCreationTime100ns = request.expectedProcessCreationTime100ns;
        value.threadCreationTime100ns = value.currentThreadCreationTime100ns = request.expectedThreadCreationTime100ns;
        value.processObject = value.currentProcessObject = 0xFFFF800000001000ULL;
        value.threadObject = value.currentThreadObject = 0xFFFF800000002000ULL;
        value.requestTime100ns = 1000;
        value.queuedTime100ns = 1001;
        value.captureStartTime100ns = 1002;
        value.captureEndTime100ns = 1003;
        value.captureQpc = 12345;
        value.qpcFrequency = 10000000;
        value.frameCount = 2;
        value.frameLimit = request.frameLimit;
        value.timeoutMs = request.timeoutMs;
        value.captureIrql = 1;
        value.frames[0] = 0xFFFFF80000001000ULL;
        value.frames[1] = 0xFFFFF80000002000ULL;
        return value;
    }
}

// 合成线上协议拒绝回归；链接生产验证器，不把此进程的栈或固定地址称为内核采集。
int main()
{
    const auto request = Request(); // 各变异使用相同冻结请求，不能随伪造回执改变期望身份。
    const auto partial = Partial(request); // 自洽的唯一正例基准。
    unsigned int passed = 0; // 只有判定符合预期才增加计数。
    const auto check = [&passed](const bool condition, const char* name) // 输入真实断言，输出失败定位或成功计数。
    {
        if (!condition)
        {
            std::printf("FAIL %s\n", name);
            return false;
        }
        ++passed;
        return true;
    };
    if (!check(ks::live_kernel_stack::ValidateResponse(request, partial, sizeof(partial)), "self-consistent synthetic partial"))
    {
        return 1;
    }
    using Mutation = std::pair<const char*, std::function<void(KSWORD_ARK_THREAD_STACK_RESPONSE&)>>; // 名称与独立变异函数配对。
    const std::vector<Mutation> mutations = {
        {"version", [](auto& p) { p.version = 1; }},
        {"size", [](auto& p) { --p.size; }},
        {"pid", [](auto& p) { ++p.processId; }},
        {"tid", [](auto& p) { ++p.threadId; }},
        {"process creation", [](auto& p) { ++p.processCreationTime100ns; }},
        {"thread creation", [](auto& p) { ++p.threadCreationTime100ns; }},
        {"wrong execution thread", [](auto& p) { ++p.currentThreadObject; }},
        {"wrong execution process", [](auto& p) { ++p.currentProcessObject; }},
        {"wrong execution identity", [](auto& p) { ++p.currentThreadCreationTime100ns; }},
        {"user frame", [](auto& p) { p.frames[0] = 0x1000; }},
        {"tail exposure", [](auto& p) { p.frames[63] = p.frames[0]; }},
        {"invalid sentinel", [](auto& p) { p.frames[0] = ~0ULL; }},
        {"over capacity", [](auto& p) { p.frameCount = 65; }},
        {"changed frame limit", [](auto& p) { p.frameLimit = 63; }},
        {"changed timeout", [](auto& p) { ++p.timeoutMs; }},
        {"failure with frames", [](auto& p) { p.status = -1; }},
        {"unavailable with frames", [](auto& p) { p.result = 0; }},
        {"no request time", [](auto& p) { p.requestTime100ns = 0; }},
        {"no queue time", [](auto& p) { p.queuedTime100ns = 0; }},
        {"no capture time", [](auto& p) { p.captureStartTime100ns = 0; }},
        {"no QPC", [](auto& p) { p.captureQpc = 0; }},
        {"unknown source", [](auto& p) { p.source = 2; }},
        {"unknown flags", [](auto& p) { p.flags |= 0x80000000UL; }},
        {"old permanent retention", [](auto& p) { p.flags |= KSWORD_ARK_THREAD_STACK_FLAG_RETAINED_AFTER_TIMEOUT; }},
        {"no retirement proof", [](auto& p) { p.flags &= ~KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED; }},
        {"false cancellation", [](auto& p) { p.flags |= KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED; }},
        {"wrong IRQL", [](auto& p) { p.captureIrql = 0; }}
    }; // 每个案例都必须被生产验证器拒绝。
    for (const auto& mutation : mutations)
    {
        auto value = partial; // 每次独立还原，避免前一次错误掩盖后一次。
        mutation.second(value);
        if (!check(!ks::live_kernel_stack::ValidateResponse(request, value, sizeof(value)), mutation.first))
        {
            return 1;
        }
    }
    if (!check(!ks::live_kernel_stack::ValidateResponse(request, partial, sizeof(partial) - 1), "short receipt"))
    {
        return 1;
    }
    std::printf("LIVE_STACK_SYNTHETIC_WIRE_ONLY=PASS cases=%u; no kernel execution\n", passed);
    return 0;
}
