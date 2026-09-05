#include "ArkDriverClient.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace ksword::ark
{
    namespace
    {
        bool isUnsupportedHvmError(const unsigned long error)
        {
            return error == ERROR_INVALID_FUNCTION ||
                error == ERROR_NOT_SUPPORTED;
        }
    }

    HvmStatusResult DriverClient::queryHvmStatus() const
    {
        HvmStatusResult result{};
        KSWORD_ARK_QUERY_HVM_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_HVM,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM query status=" << result.response.queryStatus
            << ", state=0x" << std::hex << result.response.stateFlags
            << ", features=0x" << result.response.featureFlags
            << ", generation=" << std::dec << result.response.generation
            << ", processors=" << result.response.preparedProcessorCount
            << "/" << result.response.processorCount
            << ", vmExits=" << result.response.vmExitCount
            << ", lastExitReason=" << result.response.lastExitReason;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmControlResult DriverClient::controlHvm(
        const unsigned long command,
        const unsigned long expectedGeneration,
        const bool force,
        const bool allowNested,
        const bool uiConfirmed,
        const bool enableEptEvents,
        const bool enableNestedVmx,
        const bool enableEvmcs,
        const unsigned long soakMilliseconds) const
    {
        HvmControlResult result{};
        KSWORD_ARK_CONTROL_HVM_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = command;
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
        }
        if (force)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_FORCE;
        }
        if (allowNested)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED;
        }
        if (enableEptEvents)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS;
        }
        if (enableNestedVmx)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX;
        }
        if (enableEvmcs)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS;
        }
        if (command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST;
        }
        // 驱动只允许 SOAK 携带非零时长，其它命令必须保持该字段为零。
        if (command == KSWORD_ARK_HVM_CONTROL_SOAK)
        {
            request.soakMilliseconds = soakMilliseconds;
        }
        request.confirmationToken =
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        request.expectedGeneration = expectedGeneration;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_HVM,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM control command=" << command
            << ", status=" << result.response.status
            << ", state=0x" << std::hex
            << result.response.newStateFlags
            << ", generation=" << std::dec
            << result.response.newGeneration
            << ", prepared="
            << result.response.preparedProcessorCount
            << ", passed="
            << result.response.selfTestPassedProcessorCount
            << ", vmExits=" << result.response.vmExitCount
            << ", lastExitReason=" << result.response.lastExitReason;
        // 常驻保持自检的结论只有两项：实际保持时长与掉出 non-root 的处理器数。
        if (command == KSWORD_ARK_HVM_CONTROL_SOAK)
        {
            stream << ", soakMs="
                << result.response.soakElapsedMilliseconds
                << ", soakLost="
                << result.response.soakUnexpectedDevirtualizations;
        }
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmEptRuleResult DriverClient::controlHvmEptRule(
        const unsigned long operation,
        const unsigned long expectedGeneration,
        const unsigned long ruleId,
        const unsigned long deniedAccess,
        const std::uint64_t physicalAddress,
        const std::uint64_t pageCount,
        const bool log,
        const bool allowOnce,
        const bool uiConfirmed,
        const bool enforce) const
    {
        HvmEptRuleResult result{};
        KSWORD_ARK_HVM_EPT_RULE_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = operation;
        request.expectedGeneration = expectedGeneration;
        request.ruleId = ruleId;
        request.deniedAccess = deniedAccess;
        request.physicalAddress = physicalAddress;
        request.pageCount = pageCount;
        if (log)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG;
        }
        if (allowOnce)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE;
        }
        if (enforce)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE;
        }
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_EPT_RULE,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM EPT operation=" << operation
            << ", status=" << result.response.status
            << ", implementation=" << result.response.implementation
            << ", ruleId=" << result.response.ruleId
            << ", ruleCount=" << result.response.ruleCount
            << ", generation=" << result.response.generation;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmEventResult DriverClient::queryHvmEvents(
        const std::uint64_t afterSequence,
        const unsigned long maxRows,
        const bool clear) const
    {
        HvmEventResult result{};
        KSWORD_ARK_HVM_EVENT_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = clear
            ? KSWORD_ARK_HVM_EVENT_QUERY_CLEAR
            : KSWORD_ARK_HVM_EVENT_QUERY_READ;
        request.afterSequence = afterSequence;
        request.maxRows = (std::min)(
            maxRows,
            static_cast<unsigned long>(
                KSWORD_ARK_HVM_MAX_EVENT_ROWS));

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_EVENTS,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);

        std::ostringstream stream;
        stream << "HVM event operation=" << request.operation
            << ", returned=" << result.response.returnedRows
            << ", available=" << result.response.availableRows
            << ", dropped=" << result.response.droppedRows
            << ", newest=" << result.response.newestSequence;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmMemoryResult DriverClient::hvmMemory(
        const unsigned long operation,
        const std::uint64_t address,
        const std::uint64_t directoryBase,
        const unsigned long length,
        const unsigned char* const payload,
        const bool requireWindow,
        const bool uiConfirmed) const
    {
        HvmMemoryResult result{};
        KSWORD_ARK_HVM_MEMORY_REQUEST request{};
        request.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = operation;
        request.address = address;
        request.directoryBase = directoryBase;
        // 驱动会拒绝超长请求，这里先夹住，避免把越界长度写进 payload 拷贝。
        request.length = length > KSWORD_ARK_HVM_MEMORY_MAX_BYTES
            ? KSWORD_ARK_HVM_MEMORY_MAX_BYTES
            : length;
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
        }
        if (requireWindow)
        {
            request.flags |= KSWORD_ARK_HVM_MEMORY_FLAG_REQUIRE_WINDOW;
        }
        request.confirmationToken =
            KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
        // 只有写操作携带负载；读操作把请求数据区保持为零。
        if (payload != nullptr &&
            request.length > 0 &&
            (operation == KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL ||
             operation == KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL))
        {
            std::memcpy(request.data, payload, request.length);
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_MEMORY,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.ntStatus;

        std::ostringstream stream;
        stream << "HVM memory op=" << operation
            << ", status=" << result.response.status
            << ", address=0x" << std::hex << address
            << ", physical=0x" << result.response.physicalAddress
            << std::dec
            << ", length=" << request.length
            << ", transferred=" << result.response.bytesTransferred
            << ", window=" << static_cast<unsigned>(result.response.windowReady)
            << ", direct="
            << static_cast<unsigned>(result.response.usedDirectWindow);
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmViewResult DriverClient::controlHvmView(
        const unsigned long operation,
        const unsigned long kind,
        const unsigned long viewId,
        const unsigned long expectedGeneration,
        const std::uint64_t physicalAddress,
        const unsigned char* const shadow,
        const bool seedFromTarget,
        const bool seedZero,
        const bool log,
        const bool uiConfirmed) const
    {
        HvmViewResult result{};
        KSWORD_ARK_HVM_VIEW_REQUEST request{};
        request.version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = operation;
        request.kind = kind;
        request.viewId = viewId;
        request.expectedGeneration = expectedGeneration;
        request.physicalAddress = physicalAddress;
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        }
        if (seedFromTarget)
        {
            request.flags |= KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET;
        }
        if (seedZero)
        {
            request.flags |= KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO;
        }
        if (log)
        {
            request.flags |= KSWORD_ARK_HVM_VIEW_FLAG_LOG;
        }
        // 只有 ADD 且未指定 seed 标志时才使用调用方提供的整页影子内容。
        if (shadow != nullptr &&
            !seedFromTarget &&
            !seedZero &&
            operation == KSWORD_ARK_HVM_VIEW_OP_ADD)
        {
            std::memcpy(
                request.shadow,
                shadow,
                KSWORD_ARK_HVM_VIEW_PAGE_BYTES);
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_VIEW,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM view operation=" << operation
            << ", kind=" << kind
            << ", status=" << result.response.status
            << ", viewId=" << result.response.viewId
            << ", viewCount=" << result.response.viewCount
            << ", rows=" << result.response.returnedRows
            << ", address=0x" << std::hex << physicalAddress << std::dec;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmMsrPolicyResult DriverClient::controlHvmMsrPolicy(
        const unsigned long operation,
        const unsigned long policyId,
        const unsigned long msrIndex,
        const unsigned long access,
        const unsigned long action,
        const std::uint64_t fakeValue,
        const bool uiConfirmed) const
    {
        HvmMsrPolicyResult result{};
        KSWORD_ARK_HVM_MSR_POLICY_REQUEST request{};
        request.version = KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = operation;
        request.policyId = policyId;
        request.msrIndex = msrIndex;
        request.access = access;
        request.action = action;
        request.fakeValue = fakeValue;
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_MSR_POLICY,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM MSR policy operation=" << operation
            << ", status=" << result.response.status
            << ", policyId=" << result.response.policyId
            << ", policyCount=" << result.response.policyCount
            << ", rows=" << result.response.returnedRows
            << ", msr=0x" << std::hex << msrIndex << std::dec;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmCrPolicyResult DriverClient::controlHvmCrPolicy(
        const unsigned long operation,
        const std::uint64_t cr0PinnedMask,
        const std::uint64_t cr4PinnedMask,
        const bool trackCr3,
        const bool interceptDr,
        const bool log,
        const bool uiConfirmed) const
    {
        HvmCrPolicyResult result{};
        KSWORD_ARK_HVM_CR_POLICY_REQUEST request{};
        request.version = KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = operation;
        request.cr0PinnedMask = cr0PinnedMask;
        request.cr4PinnedMask = cr4PinnedMask;
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        }
        if (trackCr3)
        {
            request.flags |= KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3;
        }
        if (interceptDr)
        {
            request.flags |= KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR;
        }
        if (log)
        {
            request.flags |= KSWORD_ARK_HVM_CR_POLICY_FLAG_LOG;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_CR_POLICY,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM CR policy operation=" << operation
            << ", status=" << result.response.status
            << ", flags=0x" << std::hex << result.response.flags
            << ", cr0Mask=0x" << result.response.cr0PinnedMask
            << ", cr4Mask=0x" << result.response.cr4PinnedMask
            << std::dec
            << ", refused=" << result.response.refusedWriteCount
            << ", cr3Switches=" << result.response.cr3SwitchCount;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}
