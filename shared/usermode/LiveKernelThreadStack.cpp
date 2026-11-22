#include "LiveKernelThreadStack.h"

namespace ks::live_kernel_stack
{
    namespace
    {
        constexpr long StatusTimeout = 258L;
        constexpr long StatusNotSupported = -1073741637L;
        constexpr unsigned long ValidFlags =
            KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED |
            KSWORD_ARK_THREAD_STACK_FLAG_QUEUED |
            KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET |
            KSWORD_ARK_THREAD_STACK_FLAG_APC_ENTRY_FRAMES |
            KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN |
            KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT |
            KSWORD_ARK_THREAD_STACK_FLAG_INVALID_FRAME |
            KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED |
            KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED;

        constexpr unsigned long RealFrameFlags =
            KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED |
            KSWORD_ARK_THREAD_STACK_FLAG_QUEUED |
            KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET |
            KSWORD_ARK_THREAD_STACK_FLAG_APC_ENTRY_FRAMES |
            KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN |
            KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED;

        constexpr bool IsKernelAddress(unsigned long long address) noexcept
        {
            // 同时容纳四级和五级分页的高半区；实际驱动仍必须依据系统边界验证。
            return address >= 0xFF00000000000000ULL && address != ~0ULL;
        }

        constexpr bool ValidRequest(const KSWORD_ARK_THREAD_STACK_REQUEST& request) noexcept
        {
            return request.size == sizeof(request) &&
                request.version == KSWORD_ARK_THREAD_STACK_VERSION &&
                request.processId != 0 && request.threadId != 0 &&
                request.expectedProcessCreationTime100ns != 0 &&
                request.expectedThreadCreationTime100ns != 0 &&
                request.frameLimit >= 1 && request.frameLimit <= KSWORD_ARK_THREAD_STACK_MAX_FRAMES &&
                request.timeoutMs >= 1 && request.timeoutMs <= KSWORD_ARK_THREAD_STACK_MAX_TIMEOUT_MS &&
                request.flags == 0 && request.reserved == 0;
        }

        constexpr bool HasCaptureEvidence(const KSWORD_ARK_THREAD_STACK_RESPONSE& response) noexcept
        {
            return response.source != KSWORD_ARK_THREAD_STACK_SOURCE_NONE ||
                response.currentProcessId != 0 || response.currentThreadId != 0 ||
                response.currentThreadObject != 0 || response.currentProcessObject != 0 ||
                response.currentProcessCreationTime100ns != 0 || response.currentThreadCreationTime100ns != 0 ||
                response.captureStartTime100ns != 0 || response.captureEndTime100ns != 0 ||
                response.captureQpc != 0 || response.qpcFrequency != 0 || response.captureIrql != 0;
        }

        constexpr bool ValidateResponseWire(const KSWORD_ARK_THREAD_STACK_REQUEST& request,
            const KSWORD_ARK_THREAD_STACK_RESPONSE& response, DWORD bytesReturned) noexcept
        {
            if (!ValidRequest(request) || bytesReturned != sizeof(response) ||
                response.size != sizeof(response) || response.version != KSWORD_ARK_THREAD_STACK_VERSION ||
                response.processId != request.processId || response.threadId != request.threadId ||
                response.frameLimit != request.frameLimit || response.timeoutMs != request.timeoutMs ||
                response.frameCount > request.frameLimit ||
                response.result > KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE ||
                response.source > KSWORD_ARK_THREAD_STACK_SOURCE_TARGET_NORMAL_APC ||
                (response.flags & ~ValidFlags) != 0 || response.requestTime100ns == 0)
                return false;

            for (unsigned long index = 0; index < KSWORD_ARK_THREAD_STACK_MAX_FRAMES; ++index)
            {
                if (index < response.frameCount ? !IsKernelAddress(response.frames[index]) : response.frames[index] != 0)
                    return false;
            }

            const bool identityVerified = (response.flags & KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED) != 0;
            const bool queued = (response.flags & KSWORD_ARK_THREAD_STACK_FLAG_QUEUED) != 0;
            if (identityVerified &&
                (response.processCreationTime100ns != request.expectedProcessCreationTime100ns ||
                    response.threadCreationTime100ns != request.expectedThreadCreationTime100ns ||
                    !IsKernelAddress(response.threadObject) || !IsKernelAddress(response.processObject)))
                return false;

            if (queued)
            {
                if (!identityVerified || response.queuedTime100ns == 0 ||
                    (response.flags & KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED) == 0)
                    return false;
            }
            else if (response.queuedTime100ns != 0 || HasCaptureEvidence(response) || response.frameCount != 0 ||
                (response.flags & ~KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED) != 0)
                return false;

            // 成功取消只可能发生在尚未分发的实例上，不能同时声称产生了目标执行证据。
            if ((response.flags & KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED) != 0 &&
                (HasCaptureEvidence(response) || response.frameCount != 0 ||
                    (response.flags & ~(KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED |
                        KSWORD_ARK_THREAD_STACK_FLAG_QUEUED |
                        KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED |
                        KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED)) != 0))
                return false;

            const bool targetEvidenceValid =
                response.source == KSWORD_ARK_THREAD_STACK_SOURCE_TARGET_NORMAL_APC &&
                (response.flags & RealFrameFlags) == RealFrameFlags &&
                response.currentProcessId == request.processId && response.currentThreadId == request.threadId &&
                response.currentProcessCreationTime100ns == request.expectedProcessCreationTime100ns &&
                response.currentThreadCreationTime100ns == request.expectedThreadCreationTime100ns &&
                response.currentThreadObject == response.threadObject &&
                response.currentProcessObject == response.processObject &&
                response.captureStartTime100ns != 0 && response.captureEndTime100ns != 0 &&
                response.captureQpc != 0 && response.qpcFrequency != 0 && response.captureIrql == 1;
            if ((response.flags & KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET) != 0 && !targetEvidenceValid)
                return false;

            if (response.frameCount == 0)
            {
                if (response.result == KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL)
                    return false;
                if (response.result == KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE)
                    return response.status == StatusNotSupported && identityVerified && !queued;
                if (response.result == KSWORD_ARK_THREAD_STACK_RESULT_TIMEOUT)
                    return response.status == StatusTimeout && queued && !HasCaptureEvidence(response) &&
                        (response.flags & ~KSWORD_ARK_THREAD_STACK_FLAG_OWN_APC_CANCELLED) ==
                            (KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED |
                                KSWORD_ARK_THREAD_STACK_FLAG_QUEUED |
                                KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED);
                if (response.result == KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH)
                    return response.status < 0 &&
                        (response.flags & KSWORD_ARK_THREAD_STACK_FLAG_EXECUTED_IN_TARGET) == 0;
                return response.status < 0;
            }

            // 这里只校验驱动真实帧的契约，不会自行取得帧，也不把不可用回执提升为采集成功。
            return response.result == KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL && response.status == 0 &&
                targetEvidenceValid;
        }
    }

    bool ValidateResponse(const KSWORD_ARK_THREAD_STACK_REQUEST& request,
        const KSWORD_ARK_THREAD_STACK_RESPONSE& response, DWORD bytesReturned) noexcept
    {
        static_assert(sizeof(KSWORD_ARK_THREAD_STACK_REQUEST) == 48);
        static_assert(sizeof(KSWORD_ARK_THREAD_STACK_RESPONSE) == 680);
        return ValidateResponseWire(request, response, bytesReturned);
    }

    bool ValidateSavedResponse(const KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST& request,
        const KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE& response, const DWORD bytesReturned) noexcept
    {
        static_assert(sizeof(response) == 792); // 独立端点不改变旧 680 字节 APC 布局。
        const auto& capture = response.capture; // 公共显示字段，不冒充旧协议通过验证。
        constexpr unsigned long valid = KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED |
            KSWORD_ARK_STACK_SNAPSHOT_FROZEN | KSWORD_ARK_STACK_SNAPSHOT_USER_BOUNDARY |
            KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN | KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT;
        if (request.size != sizeof(request) || request.version != KSWORD_ARK_STACK_SNAPSHOT_VERSION ||
            !request.processId || !request.threadId || !request.expectedProcessCreationTime100ns ||
            !request.expectedThreadCreationTime100ns || !request.frameLimit || request.frameLimit > 64 ||
            !request.timeoutMs || request.timeoutMs > 5000 || request.flags || request.reserved ||
            bytesReturned != sizeof(response) || capture.size != sizeof(response) ||
            capture.version != KSWORD_ARK_STACK_SNAPSHOT_VERSION || capture.processId != request.processId ||
            capture.threadId != request.threadId || capture.frameLimit != request.frameLimit ||
            capture.timeoutMs != request.timeoutMs || capture.frameCount > request.frameLimit ||
            !capture.requestTime100ns || (capture.flags & ~valid) ||
            capture.queuedTime100ns || capture.currentProcessId || capture.currentThreadId ||
            capture.currentThreadObject || capture.currentProcessObject ||
            capture.currentProcessCreationTime100ns || capture.currentThreadCreationTime100ns)
        {
            return false; // 无目标执行或 APC 事实时不得伪填对应字段。
        }
        for (unsigned long index = 0; index < 64; ++index)
        {
            if (index < capture.frameCount ? !IsKernelAddress(capture.frames[index]) : capture.frames[index] != 0)
            {
                return false; // 原始帧和未使用尾部必须逐项核验。
            }
        }
        const bool identity = (capture.flags & KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED) != 0;
        if (identity && (capture.processCreationTime100ns != request.expectedProcessCreationTime100ns ||
            capture.threadCreationTime100ns != request.expectedThreadCreationTime100ns ||
            !IsKernelAddress(capture.threadObject) || !IsKernelAddress(capture.processObject)))
        {
            return false; // 每个来源都必须冻结两个真实对象身份。
        }
        if (capture.source == 0)
        {
            return capture.status < 0 && capture.frameCount == 0 &&
                (capture.flags & ~KSWORD_ARK_THREAD_STACK_FLAG_IDENTITY_VERIFIED) == 0 &&
                (capture.result == KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE ||
                    capture.result == KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH);
        }
        if (capture.source != KSWORD_ARK_STACK_SNAPSHOT_SOURCE || !identity ||
            (capture.flags & KSWORD_ARK_STACK_SNAPSHOT_FROZEN) == 0 || capture.captureIrql != 2 ||
            capture.captureStartTime100ns < capture.requestTime100ns ||
            capture.captureEndTime100ns < capture.captureStartTime100ns || !capture.captureQpc ||
            !capture.qpcFrequency || !IsKernelAddress(response.kernelImageBase) ||
            !IsKernelAddress(response.savedKernelStack) || !IsKernelAddress(response.stackLow) ||
            response.stackLow > response.savedKernelStack || response.stackHigh <= response.savedKernelStack ||
            response.stackHigh - response.stackLow > 65536 ||
            response.snapshotByteCount != response.stackHigh - response.savedKernelStack ||
            response.snapshotByteCount < 0x180 || response.initialStackPointer != response.savedKernelStack + 0x40 ||
            !response.processorCount || response.processorCount > 64 || response.kernelPdbAge != 1 ||
            (response.threadState != 1 && response.threadState != 3 && response.threadState != 5 &&
                response.threadState != 7 && response.threadState != 8))
        {
            return false; // 没有完整会合、范围和原始起点证据就不发布帧。
        }
        const bool win10 = response.kernelTimeDateStamp == 3986539294UL && response.kernelImageSize == 17063936UL;
        const bool win11 = response.kernelTimeDateStamp == 2952155935UL && response.kernelImageSize == 21299200UL;
        constexpr unsigned char guid10[16] = {0x2d, 0xda, 0x23, 0xf9, 0x8e, 0x23, 0x7c, 0x7c, 0xe1, 0x80, 0xb9, 0x62, 0xb1, 0x9a, 0x37, 0x81};
        constexpr unsigned char guid11[16] = {0xfe, 0xc6, 0x61, 0xb6, 0x99, 0x72, 0x16, 0x1d, 0x0f, 0xe3, 0x7c, 0x48, 0xb8, 0xbc, 0x54, 0x70};
        if ((!win10 && !win11) || response.initialInstructionPointer != response.kernelImageBase + (win10 ? 0x3fbf96ULL : 0x6b97b6ULL))
        {
            return false; // 精确起点不能由任意同模块地址代替。
        }
        for (unsigned index = 0; index < 16; ++index)
        {
            if (response.kernelPdbGuid[index] != (win10 ? guid10[index] : guid11[index]))
            {
                return false; // PE 与 RSDS 必须共同吻合。
            }
        }
        const bool complete = (capture.flags & KSWORD_ARK_STACK_SNAPSHOT_USER_BOUNDARY) != 0;
        if (!capture.frameCount)
        {
            return !complete && capture.status < 0 && capture.result == KSWORD_ARK_THREAD_STACK_RESULT_UNAVAILABLE;
        }
        if (capture.frames[0] != response.initialInstructionPointer || capture.status != 0)
        {
            return false; // 第一帧必须来自实际保存的返回点。
        }
        if (complete)
        {
            return capture.result == KSWORD_ARK_STACK_SNAPSHOT_COMPLETE &&
                response.unwindStop == KSWORD_ARK_STACK_SNAPSHOT_STOP_USER &&
                response.terminalInstructionPointer >= 0x1000 && response.terminalInstructionPointer < 0x0000800000000000ULL &&
                response.terminalStackPointer >= 0x1000 && response.terminalStackPointer < 0x0000800000000000ULL &&
                (response.terminalCodeSegment & 3U) == 3U &&
                (capture.flags & (KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN | KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT)) == 0;
        }
        return capture.result == KSWORD_ARK_THREAD_STACK_RESULT_PARTIAL &&
            (capture.flags & KSWORD_ARK_THREAD_STACK_FLAG_COMPLETENESS_UNKNOWN) != 0 &&
            response.unwindStop >= KSWORD_ARK_STACK_SNAPSHOT_STOP_LIMIT &&
            response.unwindStop <= KSWORD_ARK_STACK_SNAPSHOT_STOP_EXCEPTION &&
            (((capture.flags & KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT) != 0) ==
                (response.unwindStop == KSWORD_ARK_STACK_SNAPSHOT_STOP_LIMIT)) &&
            (response.unwindStop != KSWORD_ARK_STACK_SNAPSHOT_STOP_LIMIT || capture.frameCount == capture.frameLimit);
    }
}
