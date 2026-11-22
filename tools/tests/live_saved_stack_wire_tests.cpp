// 合成 wire 回归：直接链接生产验证器；不会打开设备、取样线程或产生现场帧。
#include "../../shared/usermode/LiveKernelThreadStack.h"
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

int main()
{
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST request{}; // 固定合成身份与预算。
    request.size = sizeof(request);
    request.version = KSWORD_ARK_STACK_SNAPSHOT_VERSION;
    request.processId = 123;
    request.threadId = 456;
    request.expectedProcessCreationTime100ns = 100;
    request.expectedThreadCreationTime100ns = 101;
    request.frameLimit = 64;
    request.timeoutMs = 1000;
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE original{}; // 自洽正例仅为字节契约基准，不是实采证据。
    auto& capture = original.capture; // 同一回执的公共字段视图。
    capture.size = sizeof(original);
    capture.version = request.version;
    capture.result = KSWORD_ARK_STACK_SNAPSHOT_COMPLETE;
    capture.source = KSWORD_ARK_STACK_SNAPSHOT_SOURCE;
    capture.flags = KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED | KSWORD_ARK_STACK_SNAPSHOT_FROZEN | KSWORD_ARK_STACK_SNAPSHOT_USER_BOUNDARY;
    capture.processId = request.processId;
    capture.threadId = request.threadId;
    capture.processCreationTime100ns = request.expectedProcessCreationTime100ns;
    capture.threadCreationTime100ns = request.expectedThreadCreationTime100ns;
    capture.processObject = 0xffff800000001000;
    capture.threadObject = 0xffff800000002000;
    capture.requestTime100ns = 1000;
    capture.captureStartTime100ns = 1001;
    capture.captureEndTime100ns = 1002;
    capture.captureQpc = 12345;
    capture.qpcFrequency = 10000000;
    capture.frameCount = 1;
    capture.frameLimit = request.frameLimit;
    capture.timeoutMs = request.timeoutMs;
    capture.captureIrql = 2;
    original.kernelImageBase = 0xfffff80010000000;
    original.kernelImageSize = 17063936;
    original.kernelTimeDateStamp = 3986539294UL;
    original.kernelPdbAge = 1;
    constexpr unsigned char guid[16] = {0x2d,0xda,0x23,0xf9,0x8e,0x23,0x7c,0x7c,0xe1,0x80,0xb9,0x62,0xb1,0x9a,0x37,0x81};
    std::memcpy(original.kernelPdbGuid, guid, sizeof(guid));
    original.savedKernelStack = 0xffffa00000001000;
    original.stackLow = original.savedKernelStack;
    original.stackHigh = original.stackLow + 0x2000;
    original.initialInstructionPointer = original.kernelImageBase + 0x3fbf96;
    original.initialStackPointer = original.savedKernelStack + 0x40;
    original.terminalInstructionPointer = 0x7ff612341000;
    original.terminalStackPointer = 0x123450000;
    original.terminalCodeSegment = 0x33;
    original.snapshotByteCount = 0x2000;
    original.processorCount = 4;
    original.threadState = 5;
    original.unwindStop = KSWORD_ARK_STACK_SNAPSHOT_STOP_USER;
    capture.frames[0] = original.initialInstructionPointer;
    const auto validate = [&request](const auto& response) // 使用生产验证器，不在测试里另写接受条件。
    {
        return ks::live_kernel_stack::ValidateSavedResponse(request, response, sizeof(response));
    };
    if (!validate(original)) return 1;
    using Mutation = std::pair<const char*, std::function<void(KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE&)>>;
    const std::vector<Mutation> mutations = {
        {"old-size", [](auto& p){p.capture.size = 680;}},
        {"old-version", [](auto& p){p.capture.version = 2;}},
        {"wrong-instance", [](auto& p){++p.capture.threadCreationTime100ns;}},
        {"forged-apc", [](auto& p){p.capture.source = 1;}},
        {"forged-execution", [](auto& p){p.capture.currentThreadId = p.capture.threadId;}},
        {"forged-queue", [](auto& p){p.capture.flags |= KSWORD_ARK_THREAD_STACK_FLAG_QUEUED;}},
        {"no-freeze", [](auto& p){p.capture.flags &= ~KSWORD_ARK_STACK_SNAPSHOT_FROZEN;}},
        {"no-identity", [](auto& p){p.capture.flags &= ~KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED;}},
        {"no-machine-cs", [](auto& p){p.terminalCodeSegment = 0x10;}},
        {"kernel-terminal-ip", [](auto& p){p.terminalInstructionPointer = p.kernelImageBase;}},
        {"kernel-terminal-sp", [](auto& p){p.terminalStackPointer = p.savedKernelStack;}},
        {"wrong-guid", [](auto& p){p.kernelPdbGuid[15] ^= 1;}},
        {"wrong-age", [](auto& p){++p.kernelPdbAge;}},
        {"wrong-timestamp", [](auto& p){++p.kernelTimeDateStamp;}},
        {"running-state", [](auto& p){p.threadState = 2;}},
        {"incomplete-copy", [](auto& p){--p.snapshotByteCount;}},
        {"wrong-save-offset", [](auto& p){p.initialStackPointer += 8;}},
        {"forged-first-frame", [](auto& p){p.capture.frames[0] += 8;}},
        {"forged-initial-pc", [](auto& p){p.initialInstructionPointer += 8;p.capture.frames[0] += 8;}},
        {"unknown-completeness", [](auto& p){p.capture.flags |= KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN;}},
        {"budget-claims-complete", [](auto& p){p.capture.flags |= KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT;}},
        {"no-processors", [](auto& p){p.processorCount = 0;}},
        {"tail-exposure", [](auto& p){p.capture.frames[63] = p.capture.frames[0];}}
    }; // 各变异独立执行，不能让前一个错误掩盖后一个。
    for (const auto& [name, mutate] : mutations)
    {
        auto changed = original; // 每轮恢复同一自洽基准。
        mutate(changed);
        if (validate(changed))
        {
            std::printf("FAIL=%s\n", name);
            return 1;
        }
    }
    std::printf("SAVED_STACK_SYNTHETIC_WIRE_ONLY=PASS cases=%zu; no driver access\n", mutations.size() + 1);
    return 0;
}
