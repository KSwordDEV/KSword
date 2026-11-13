#include "KswordDebuggerBackend.h"
#include "../shared/driver/KswordArkHvmNoAttachIoctl.h"

#include <cstring>
#include <fstream>
#include <limits>
#include <vector>

namespace ksword::debugger
{
    namespace
    {
        struct PreserveLastError
        {
            DWORD error = GetLastError();
            ~PreserveLastError() { SetLastError(error); }
        };
    }

    Backend& backend()
    {
        static Backend instance;
        return instance;
    }

    void Backend::log(const std::string& message)
    {
        const PreserveLastError preserve;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        wchar_t path[4096]{};
        const DWORD count = GetEnvironmentVariableW(L"KSWORD_DEBUGGER_LOG_FILE", path, _countof(path));
        if (count == 0 || count >= _countof(path)) return;
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        const bool reset = GetFileAttributesExW(path, GetFileExInfoStandard, &attributes) &&
            (attributes.nFileSizeHigh != 0 || attributes.nFileSizeLow > 16U * 1024U * 1024U);
        std::ofstream stream(path, std::ios::binary | (reset ? std::ios::trunc : std::ios::app));
        if (reset) stream << "[backend] Older logs were retired after the 16 MiB limit.\n";
        SYSTEMTIME time{};
        GetLocalTime(&time);
        char timestamp[64]{};
        (void)sprintf_s(timestamp, "%04u-%02u-%02u %02u:%02u:%02u [backend] ",
            time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
        std::string line = message.substr(0, 4000);
        for (char& c : line) if (c == '\n' || c == '\r') c = ' ';
        stream << timestamp << line << '\n';
    }

    void Backend::logRepeated(const std::string& message)
    {
        const PreserveLastError preserve;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto found = repeatedLogs_.find(message);
        if (found == repeatedLogs_.end())
        {
            constexpr SIZE_T maximumKeys = 64;
            if (repeatedLogs_.size() >= maximumKeys)
            {
                auto oldest = repeatedLogs_.begin();
                for (auto entry = repeatedLogs_.begin(); entry != repeatedLogs_.end(); ++entry)
                    if (entry->second.stamp < oldest->second.stamp) oldest = entry;
                repeatedLogs_.erase(oldest);
            }
            found = repeatedLogs_.emplace(message, RepeatedLog{}).first;
        }
        if (repeatedLogClock_ == (std::numeric_limits<std::uint64_t>::max)())
        {
            repeatedLogClock_ = 0;
            for (auto& entry : repeatedLogs_) entry.second.stamp = 0;
        }
        found->second.stamp = ++repeatedLogClock_;
        auto& occurrences = found->second.occurrences;
        if (occurrences == (std::numeric_limits<std::uint64_t>::max)()) return;
        ++occurrences;
        if (occurrences == 1) { log(message); return; }
        auto milestone = occurrences;
        while (milestone >= 10 && milestone % 10 == 0) milestone /= 10;
        if (milestone == 1)
            log(message + " [repeated diagnostic; occurrences=" + std::to_string(occurrences) + "]");
    }

    bool Backend::initialize()
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (driver_.isValid()) return true;
        driver_ = client_.open();
        if (!driver_.isValid()) return false;
        log("KSword debugger backend API v1 loaded; memory and debugger adapters ready");
        return true;
    }

    KSWORD_DEBUGGER_OPTIONS Backend::options()
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return options_;
    }

    bool Backend::preferShadowExecution()
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (options_.mode == KSWORD_DEBUGGER_MODE_STEALTH || shadowPrepared_) return true;
        if (!useHvm_ || !driver_.isValid()) return false;
        KSWORD_ARK_HVM_DEBUG_REQUEST query{}; KSWORD_ARK_HVM_DEBUG_RESPONSE response{};
        query.version = KSWORD_ARK_HVM_DEBUG_VERSION; query.size = sizeof(query);
        return breakpointRequest(query, response) == ERROR_SUCCESS && response.supported == 0;
    }

    DWORD Backend::shadowWritePageCount() const
    {
        DWORD pages = 0;
        for (const auto& target : shadowWrites_) pages += static_cast<DWORD>(target.second.pages.size());
        return pages;
    }

    bool Backend::hasShadowViews() const { return !shadowInt3_.empty() || !shadowWrites_.empty(); }

    DWORD Backend::setOptions(const KSWORD_DEBUGGER_OPTIONS& requested)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (requested.version != KSWORD_DEBUGGER_OPTIONS_VERSION || requested.size != sizeof(requested))
            return ERROR_REVISION_MISMATCH;
        if (requested.mode > KSWORD_DEBUGGER_MODE_STEALTH || requested.shadowMemoryWrites > 1 ||
            requested.allowFallback > 1 || requested.logFallback != 1 || requested.nativeContextFallback > 1 ||
            requested.nativeSuspendFallback > 1 || requested.maxShadowPages == 0 || requested.maxShadowPages > 32 ||
            requested.reserved[0] != 0 || requested.reserved[1] != 0 || requested.reserved[2] != 0)
            return ERROR_INVALID_PARAMETER;
        if (std::memcmp(&requested, &options_, sizeof(requested)) == 0) return ERROR_SUCCESS;
        if (!breakpoints_.empty() || hasShadowViews()) return ERROR_BUSY;
        options_ = requested;
        nativeContextFallback_ = false;
        log("Debugger options accepted: mode " + std::to_string(options_.mode) +
            ", Shadow writes " + std::to_string(options_.shadowMemoryWrites) +
            ", explicit fallback " + std::to_string(options_.allowFallback));
        return ERROR_SUCCESS;
    }

    KSWORD_DEBUGGER_POLICY_STATUS Backend::policyStatus()
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        KSWORD_DEBUGGER_POLICY_STATUS result{};
        result.options = options_;
        bool hasInterceptedBindings = false;
        for (const auto& entry : breakpoints_) hasInterceptedBindings |= !nativeDataOnlyRecord(entry.second);
        result.activePath = hasShadowViews() ? KSWORD_DEBUGGER_PATH_SHADOW :
            hasInterceptedBindings ? KSWORD_DEBUGGER_PATH_EPT : KSWORD_DEBUGGER_PATH_NATIVE;
        result.shadowWritePages = shadowWritePageCount();
        result.activeBreakpoints = static_cast<DWORD>(shadowInt3_.size());
        for (const auto& entry : breakpoints_)
        {
            if (!entry.second.shadow)
            { for (const auto id : entry.second.ids) if (id != 0) ++result.activeBreakpoints; }
            else
            {
                for (DWORD slot = 0; slot < 4; ++slot)
                    if ((entry.second.requested.Dr7 & (3ULL << (2 * slot))) != 0 &&
                        ((entry.second.requested.Dr7 >> (16 + 4 * slot)) & 3) != 0) ++result.activeBreakpoints;
            }
        }
        result.canChangeOptions = breakpoints_.empty() && !hasShadowViews() ? 1U : 0U;
        result.fallbackCount = fallbackCount_;
        result.lastFallbackError = lastFallbackError_;
        return result;
    }

    void Backend::recordFallback(const std::string& source, const std::string& destination,
        DWORD error, const std::string& reason)
    {
        const PreserveLastError preserve;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (fallbackCount_ != MAXDWORD) ++fallbackCount_;
        lastFallbackError_ = error;
        logRepeated("Fallback " + source + " -> " + destination + ", error " + std::to_string(error) + ": " + reason);
    }

    KSWORD_DEBUGGER_BACKEND_STATUS Backend::status()
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        retireDetachedTarget();
        KSWORD_DEBUGGER_BACKEND_STATUS result{};
        result.version = KSWORD_DEBUGGER_API_VERSION;
        result.size = sizeof(result);
        result.driverReady = driver_.isValid() ? 1U : 0U;
        result.useHvm = useHvm_ ? 1U : 0U;
        result.ownsResident = ownsResident_ ? 1U : 0U;
        result.attachedProcessId = attachedPid_;
        result.lastError = lastError_;
        if (!driver_.isValid()) return result;
        const auto window = client_.hvmMemory(KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
            0, 0, 0, nullptr, false, false, 0, &driver_);
        result.directMemoryWindow = window.io.ok && window.response.windowReady != 0 ? 1U : 0U;
        const auto hvm = client_.queryHvmStatus();
        result.residentActive = hvm.io.ok &&
            (hvm.response.stateFlags & KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0 ? 1U : 0U;
        KSWORD_ARK_HVM_DEBUG_REQUEST query{};
        KSWORD_ARK_HVM_DEBUG_RESPONSE response{};
        query.version = KSWORD_ARK_HVM_DEBUG_VERSION;
        query.size = sizeof(query);
        if (breakpointRequest(query, response) == ERROR_SUCCESS && response.supported != 0)
            result.eptBreakpointProtocol = response.version;
        return result;
    }

    DWORD Backend::setUseHvm(const bool enabled)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (enabled == useHvm_) return ERROR_SUCCESS;
        if (enabled)
        {
            const auto window = client_.hvmMemory(KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
                0, 0, 0, nullptr, false, false, 0, &driver_);
            if (!window.io.ok || window.response.windowReady == 0)
            {
                lastError_ = window.io.ok ? ERROR_NOT_SUPPORTED : window.io.win32Error;
                log("HVM unavailable: private memory window is not ready; selection rejected");
                return lastError_;
            }
        }
        else if (!breakpoints_.empty() || hasShadowViews())
        {
            lastError_ = ERROR_BUSY;
            log("Remove the active EPT breakpoints before switching off HVM");
            return lastError_;
        }
        if (!enabled && ownsResident_)
        {
            const DWORD error = releaseOwnedHvm();
            if (error != ERROR_SUCCESS) { lastError_ = error; return error; }
        }
        useHvm_ = enabled;
        lastError_ = ERROR_SUCCESS;
        log(enabled ? "HVM selected: strict private-window reads/writes; EPT debugger enabled"
            : "R0 selected: KSword memory backend; HVM is disabled for this debugger");
        return ERROR_SUCCESS;
    }

    DWORD Backend::dispatch(KSWORD_DEBUGGER_CALL& call)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        call.bytesReturned = 0;
        if (call.version != KSWORD_DEBUGGER_API_VERSION || call.size != sizeof(call) || call.reserved != 0)
            return ERROR_REVISION_MISMATCH;
        auto* output = reinterpret_cast<void*>(static_cast<std::uintptr_t>(call.output));
        const auto* input = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(call.input));
        // Layout discovery works offline and never opens a device or starts HVM.
        if (call.command == KSWORD_DEBUGGER_OPERATION_LAYOUT && input != nullptr && call.inputBytes == sizeof(DWORD))
        {
            DWORD command = 0; std::memcpy(&command, input, sizeof(command));
            if (command == KSWORD_DEBUGGER_NOATTACH)
            {
                if (output == nullptr || call.outputBytes < sizeof(KSWORD_DEBUGGER_OPERATION_INFO)) return ERROR_INSUFFICIENT_BUFFER;
                const KSWORD_DEBUGGER_OPERATION_INFO info{KSWORD_DEBUGGER_API_VERSION, command,
                    sizeof(KSWORD_ARK_HVM_NOATTACH_REQUEST), sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE),
                    KSWORD_ARK_HVM_NOATTACH_VERSION, 0};
                std::memcpy(output, &info, sizeof(info)); call.bytesReturned = sizeof(info);
                return ERROR_SUCCESS;
            }
        }
        if (call.command == KSWORD_DEBUGGER_NOATTACH)
        {
            if (input == nullptr || call.inputBytes != sizeof(KSWORD_ARK_HVM_NOATTACH_REQUEST)) return ERROR_INVALID_PARAMETER;
            if (output == nullptr || call.outputBytes < sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE)) return ERROR_INSUFFICIENT_BUFFER;
            KSWORD_ARK_HVM_NOATTACH_REQUEST request{}; std::memcpy(&request, input, sizeof(request));
            if (request.version != KSWORD_ARK_HVM_NOATTACH_VERSION || request.size != sizeof(request)) return ERROR_REVISION_MISMATCH;
            // A frontend cannot borrow a native stop, or replace an existing debug port, here.
            if (request.operation == KSWORD_ARK_HVM_NOATTACH_OPEN &&
                (attachedPid_ != 0 || attachmentOwner_ != AttachmentOwner::none || ownsResident_ ||
                 !breakpoints_.empty() || hasShadowViews() || noAttachReserved_)) return ERROR_BUSY;
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return GetLastError();
            request.ownerCreationTime = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            if (request.operation == KSWORD_ARK_HVM_NOATTACH_OPEN)
            {
                // Script/command frontends may ask this facade to freeze identities at request time.
                ark::DriverHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.processId));
                if (!process.isValid()) return GetLastError();
                ark::DriverHandle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.threadId));
                if (!thread.isValid()) return GetLastError();
                if (GetProcessIdOfThread(thread.native()) != request.processId ||
                    WaitForSingleObject(process.native(), 0) != WAIT_TIMEOUT ||
                    WaitForSingleObject(thread.native(), 0) != WAIT_TIMEOUT) return ERROR_INVALID_PARAMETER;
                if (!GetProcessTimes(process.native(), &created, &exited, &kernel, &user)) return GetLastError();
                const auto processCreation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                if (!GetThreadTimes(thread.native(), &created, &exited, &kernel, &user)) return GetLastError();
                const auto threadCreation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                if ((request.processCreationTime != 0 && request.processCreationTime != processCreation) ||
                    (request.threadCreationTime != 0 && request.threadCreationTime != threadCreation)) return ERROR_INVALID_DATA;
                request.processCreationTime = processCreation;
                request.threadCreationTime = threadCreation;
            }
            if (!noAttachDriver_.isValid()) noAttachDriver_ = client_.openSilently();
            if (!noAttachDriver_.isValid()) return ERROR_DEVICE_NOT_CONNECTED;
            if (request.operation == KSWORD_ARK_HVM_NOATTACH_OPEN) noAttachReserved_ = true;
            KSWORD_ARK_HVM_NOATTACH_RESPONSE response{};
            const auto result = client_.deviceIoControl(IOCTL_KSWORD_ARK_HVM_NOATTACH, &request, sizeof(request),
                &response, sizeof(response), &noAttachDriver_);
            if (!result.ok) return result.win32Error;
            if (result.bytesReturned != sizeof(response) || response.version != KSWORD_ARK_HVM_NOATTACH_VERSION ||
                response.size != sizeof(response) || response.state > KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING ||
                response.breakpointCount > KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS) return ERROR_INVALID_DATA;
            // Only a successful, explicit closed response releases an uncertain owner.
            if (response.status >= 0 && response.sessionId == 0 && response.state == KSWORD_ARK_HVM_NOATTACH_CLOSED)
                noAttachReserved_ = false;
            std::memcpy(output, &response, sizeof(response)); call.bytesReturned = sizeof(response);
            return ERROR_SUCCESS; // Preserve NTSTATUS separately; an accepted STEP is not a completed step.
        }
        // Keep the legacy raw native/HVM control plane out of this independent lifecycle.
        if (noAttachReserved_ && call.command >= KSWORD_DEBUGGER_HVM_STATUS && call.command <= KSWORD_DEBUGGER_NATIVE)
            return ERROR_BUSY;
        if (call.command == KSWORD_DEBUGGER_GET_OPTIONS || call.command == KSWORD_DEBUGGER_SET_OPTIONS)
        {
            if (output == nullptr || call.outputBytes < sizeof(KSWORD_DEBUGGER_OPTIONS)) return ERROR_INSUFFICIENT_BUFFER;
            DWORD error = ERROR_SUCCESS;
            if (call.command == KSWORD_DEBUGGER_SET_OPTIONS)
            {
                if (input == nullptr || call.inputBytes != sizeof(KSWORD_DEBUGGER_OPTIONS)) return ERROR_INVALID_PARAMETER;
                KSWORD_DEBUGGER_OPTIONS requested{}; std::memcpy(&requested, input, sizeof(requested));
                error = setOptions(requested);
            }
            else if (call.inputBytes != 0) return ERROR_INVALID_PARAMETER;
            const auto actual = options(); std::memcpy(output, &actual, sizeof(actual));
            call.bytesReturned = sizeof(actual); return error;
        }
        if (call.command == KSWORD_DEBUGGER_QUERY_POLICY)
        {
            if (call.inputBytes != 0) return ERROR_INVALID_PARAMETER;
            if (output == nullptr || call.outputBytes < sizeof(KSWORD_DEBUGGER_POLICY_STATUS)) return ERROR_INSUFFICIENT_BUFFER;
            const auto actual = policyStatus(); std::memcpy(output, &actual, sizeof(actual));
            call.bytesReturned = sizeof(actual); return ERROR_SUCCESS;
        }
        if (call.command == KSWORD_DEBUGGER_RESTORE_SHADOW_WRITES)
        {
            if (input == nullptr || call.inputBytes != sizeof(KSWORD_DEBUGGER_SHADOW_RESTORE)) return ERROR_INVALID_PARAMETER;
            if (output == nullptr || call.outputBytes < sizeof(KSWORD_DEBUGGER_BACKEND_STATUS)) return ERROR_INSUFFICIENT_BUFFER;
            KSWORD_DEBUGGER_SHADOW_RESTORE request{}; std::memcpy(&request, input, sizeof(request));
            if (request.version != KSWORD_DEBUGGER_OPTIONS_VERSION || request.size != sizeof(request)) return ERROR_REVISION_MISMATCH;
            const DWORD error = restoreShadowWrites(request.address, request.bytes);
            const auto actual = status(); std::memcpy(output, &actual, sizeof(actual));
            call.bytesReturned = sizeof(actual); return error;
        }
        if (call.command == KSWORD_DEBUGGER_QUERY_BACKEND || call.command == KSWORD_DEBUGGER_USE_HVM)
        {
            if (output == nullptr || call.outputBytes < sizeof(KSWORD_DEBUGGER_BACKEND_STATUS))
                return ERROR_INSUFFICIENT_BUFFER;
            if (call.command == KSWORD_DEBUGGER_USE_HVM)
            {
                if (input == nullptr || call.inputBytes != sizeof(DWORD)) return ERROR_INVALID_PARAMETER;
                DWORD enabled = 0;
                std::memcpy(&enabled, input, sizeof(enabled));
                if (enabled > 1) return ERROR_INVALID_PARAMETER;
                const DWORD error = setUseHvm(enabled != 0);
                const auto state = status();
                std::memcpy(output, &state, sizeof(state));
                call.bytesReturned = sizeof(state);
                return error;
            }
            if (call.inputBytes != 0) return ERROR_INVALID_PARAMETER;
            const auto state = status();
            std::memcpy(output, &state, sizeof(state));
            call.bytesReturned = sizeof(state);
            return ERROR_SUCCESS;
        }
        if (!driver_.isValid()) return ERROR_DEVICE_NOT_CONNECTED;
        struct Operation { DWORD command, ioctl, inputBytes, outputBytes; };
#define KSW_OPERATION(command, ioctl, request, response) \
        {command, ioctl, static_cast<DWORD>(sizeof(request)), static_cast<DWORD>(sizeof(response))}
        static constexpr Operation operations[] = {
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_STATUS, IOCTL_KSWORD_ARK_QUERY_HVM, KSWORD_ARK_QUERY_HVM_REQUEST, KSWORD_ARK_QUERY_HVM_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_CONTROL, IOCTL_KSWORD_ARK_CONTROL_HVM, KSWORD_ARK_CONTROL_HVM_REQUEST, KSWORD_ARK_CONTROL_HVM_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_MEMORY, IOCTL_KSWORD_ARK_HVM_MEMORY, KSWORD_ARK_HVM_MEMORY_REQUEST, KSWORD_ARK_HVM_MEMORY_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_EPT_RULE, IOCTL_KSWORD_ARK_HVM_EPT_RULE, KSWORD_ARK_HVM_EPT_RULE_REQUEST, KSWORD_ARK_HVM_EPT_RULE_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_EVENTS, IOCTL_KSWORD_ARK_HVM_EVENTS, KSWORD_ARK_HVM_EVENT_QUERY_REQUEST, KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_VIEW, IOCTL_KSWORD_ARK_HVM_VIEW, KSWORD_ARK_HVM_VIEW_REQUEST, KSWORD_ARK_HVM_VIEW_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_CR_POLICY, IOCTL_KSWORD_ARK_HVM_CR_POLICY, KSWORD_ARK_HVM_CR_POLICY_REQUEST, KSWORD_ARK_HVM_CR_POLICY_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_MSR_POLICY, IOCTL_KSWORD_ARK_HVM_MSR_POLICY, KSWORD_ARK_HVM_MSR_POLICY_REQUEST, KSWORD_ARK_HVM_MSR_POLICY_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_DOMAIN, IOCTL_KSWORD_ARK_HVM_DOMAIN, KSWORD_ARK_HVM_DOMAIN_REQUEST, KSWORD_ARK_HVM_DOMAIN_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_PROCESS, IOCTL_KSWORD_ARK_HVM_PROCESS, KSWORD_ARK_HVM_PROCESS_REQUEST, KSWORD_ARK_HVM_PROCESS_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_INJECT, IOCTL_KSWORD_ARK_HVM_INJECT, KSWORD_ARK_HVM_INJECT_REQUEST, KSWORD_ARK_HVM_INJECT_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_PLATFORM, IOCTL_KSWORD_ARK_HVM_PLATFORM, KSWORD_ARK_HVM_PLATFORM_REQUEST, KSWORD_ARK_HVM_PLATFORM_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_METRICS, IOCTL_KSWORD_ARK_HVM_METRICS, KSWORD_ARK_HVM_METRICS_REQUEST, KSWORD_ARK_HVM_METRICS_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_NESTED_PROBE, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE, KSWORD_ARK_HVM_NESTED_PROBE_REQUEST, KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_NESTED_PAGE, IOCTL_KSWORD_ARK_HVM_NESTED_PAGE, KSWORD_ARK_HVM_NESTED_PAGE_REQUEST, KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_HVM_BREAKPOINT, IOCTL_KSWORD_ARK_HVM_DEBUG, KSWORD_ARK_HVM_DEBUG_REQUEST, KSWORD_ARK_HVM_DEBUG_RESPONSE),
            KSW_OPERATION(KSWORD_DEBUGGER_NATIVE, IOCTL_KSWORD_ARK_DEBUGGER, KSWORD_ARK_DEBUGGER_REQUEST, KSWORD_ARK_DEBUGGER_RESPONSE)
        };
#undef KSW_OPERATION
        if (call.command == KSWORD_DEBUGGER_OPERATION_LAYOUT)
        {
            if (input == nullptr || call.inputBytes != sizeof(DWORD)) return ERROR_INVALID_PARAMETER;
            if (output == nullptr || call.outputBytes < sizeof(KSWORD_DEBUGGER_OPERATION_INFO)) return ERROR_INSUFFICIENT_BUFFER;
            DWORD command = 0; std::memcpy(&command, input, sizeof(command));
            for (const auto& operation : operations)
            {
                if (operation.command != command) continue;
                DWORD protocol = KSWORD_ARK_HVM_PROTOCOL_VERSION;
                switch (command)
                {
                case KSWORD_DEBUGGER_HVM_MEMORY: protocol = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_VIEW: protocol = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_CR_POLICY: protocol = KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_MSR_POLICY: protocol = KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_DOMAIN: protocol = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_PROCESS: protocol = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_INJECT: protocol = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_PLATFORM: protocol = KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_METRICS: protocol = KSWORD_ARK_HVM_METRICS_VERSION; break;
                case KSWORD_DEBUGGER_HVM_NESTED_PROBE: protocol = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION; break;
                case KSWORD_DEBUGGER_HVM_NESTED_PAGE: protocol = KSWORD_ARK_HVM_NESTED_PAGE_VERSION; break;
                case KSWORD_DEBUGGER_HVM_BREAKPOINT: protocol = KSWORD_ARK_HVM_DEBUG_VERSION; break;
                case KSWORD_DEBUGGER_NATIVE: protocol = KSWORD_ARK_DEBUGGER_VERSION; break;
                default: break;
                }
                const KSWORD_DEBUGGER_OPERATION_INFO info{KSWORD_DEBUGGER_API_VERSION, command,
                    operation.inputBytes, operation.outputBytes, protocol, 0};
                std::memcpy(output, &info, sizeof(info)); call.bytesReturned = sizeof(info);
                return ERROR_SUCCESS;
            }
            return ERROR_NOT_SUPPORTED;
        }
        for (const auto& operation : operations)
        {
            if (operation.command != call.command) continue;
            if (input == nullptr || call.inputBytes != operation.inputBytes) return ERROR_INVALID_PARAMETER;
            if (output == nullptr || call.outputBytes < operation.outputBytes) return ERROR_INSUFFICIENT_BUFFER;
            // Preserve input even when the caller reuses one buffer for request/response.
            std::vector<unsigned char> snapshot(call.inputBytes);
            std::memcpy(snapshot.data(), input, snapshot.size());
            if (!breakpoints_.empty() || hasShadowViews())
            {
                DWORD action = 0;
                if (snapshot.size() >= 12) std::memcpy(&action, snapshot.data() + 8, sizeof(action));
                bool conflicts = false;
                switch (call.command)
                {
                case KSWORD_DEBUGGER_HVM_CONTROL: conflicts = true; break;
                case KSWORD_DEBUGGER_HVM_EPT_RULE: conflicts = action != KSWORD_ARK_HVM_EPT_RULE_QUERY && action != KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY; break;
                case KSWORD_DEBUGGER_HVM_VIEW: conflicts = action != KSWORD_ARK_HVM_VIEW_OP_QUERY; break;
                case KSWORD_DEBUGGER_HVM_CR_POLICY: conflicts = action != KSWORD_ARK_HVM_CR_POLICY_OP_QUERY; break;
                case KSWORD_DEBUGGER_HVM_MSR_POLICY: conflicts = action != KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY; break;
                case KSWORD_DEBUGGER_HVM_DOMAIN: conflicts = action != KSWORD_ARK_HVM_DOMAIN_OP_QUERY; break;
                case KSWORD_DEBUGGER_HVM_BREAKPOINT: conflicts = action != KSWORD_ARK_HVM_DEBUG_QUERY; break;
                case KSWORD_DEBUGGER_NATIVE:
                {
                    DWORD flags = 0;
                    std::memcpy(&flags, snapshot.data() + offsetof(KSWORD_ARK_DEBUGGER_REQUEST, contextFlags), sizeof(flags));
                    conflicts = action == KSWORD_ARK_DEBUGGER_SET_CONTEXT && (flags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS;
                    break;
                }
                default: break;
                }
                if (conflicts) { log("Raw policy edit refused while this debugger owns EPT breakpoints"); return ERROR_BUSY; }
            }
            const auto result = client_.deviceIoControl(operation.ioctl, snapshot.data(), operation.inputBytes,
                output, operation.outputBytes, &driver_);
            call.bytesReturned = result.bytesReturned;
            if (!result.ok) { log(result.message); return result.win32Error; }
            if (result.bytesReturned != operation.outputBytes) return ERROR_INVALID_DATA;
            return ERROR_SUCCESS; // Protocol-level NTSTATUS remains in the typed response.
        }
        return ERROR_NOT_SUPPORTED;
    }
}

static bool debuggerCopy(void* output, const void* input, std::size_t bytes) noexcept
{
    __try { if (bytes != 0) std::memcpy(output, input, bytes); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

extern "C" unsigned long __stdcall KSwordDebuggerCall(KSWORD_DEBUGGER_CALL* call)
{
    if (call == nullptr) return ERROR_INVALID_PARAMETER;
    KSWORD_DEBUGGER_CALL snapshot{};
    if (!debuggerCopy(&snapshot, call, sizeof(snapshot))) return ERROR_NOACCESS;
    snapshot.bytesReturned = 0;
    snapshot.error = ERROR_SUCCESS;
    try
    {
        if (snapshot.version != KSWORD_DEBUGGER_API_VERSION || snapshot.size != sizeof(snapshot) || snapshot.reserved != 0)
            snapshot.error = ERROR_REVISION_MISMATCH;
        else if (snapshot.inputBytes > 4U * 1024U * 1024U || snapshot.outputBytes > 8U * 1024U * 1024U)
            snapshot.error = ERROR_BAD_LENGTH;
        else
        {
            // Foreign pointers are accessed only through SEH copy helpers outside
            // backend locks. An invalid adapter buffer cannot strand a C++ mutex.
            std::vector<unsigned char> input(snapshot.inputBytes), output(snapshot.outputBytes);
            if (!debuggerCopy(input.data(), reinterpret_cast<const void*>(static_cast<std::uintptr_t>(snapshot.input)), input.size()))
                snapshot.error = ERROR_NOACCESS;
            else
            {
                KSWORD_DEBUGGER_CALL owned = snapshot;
                owned.input = input.empty() ? 0 : reinterpret_cast<std::uintptr_t>(input.data());
                owned.output = output.empty() ? 0 : reinterpret_cast<std::uintptr_t>(output.data());
                snapshot.error = ksword::debugger::backend().dispatch(owned);
                snapshot.bytesReturned = owned.bytesReturned;
                if (snapshot.bytesReturned > output.size()) { snapshot.error = ERROR_INVALID_DATA; snapshot.bytesReturned = 0; }
                else if (!debuggerCopy(reinterpret_cast<void*>(static_cast<std::uintptr_t>(snapshot.output)), output.data(), snapshot.bytesReturned))
                    snapshot.error = ERROR_NOACCESS;
            }
        }
    }
    catch (const std::bad_alloc&) { snapshot.error = ERROR_NOT_ENOUGH_MEMORY; }
    catch (...) { snapshot.error = ERROR_GEN_FAILURE; }
    return debuggerCopy(call, &snapshot, sizeof(snapshot)) ? snapshot.error : ERROR_NOACCESS;
}
