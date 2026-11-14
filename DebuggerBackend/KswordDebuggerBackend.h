#pragma once

#include "KswordDebuggerApi.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/driver/KswordArkHvmDebugIoctl.h"
#include "../shared/driver/KswordArkDebuggerIoctl.h"

#include <Windows.h>
#include <array>
#include <bitset>
#include <atomic>
#include <mutex>
#include <memory>
#include <unordered_map>
#include <unordered_set>

namespace ksword::debugger
{
    // One backend instance per debugger process; CE-specific ABI stays outside.
    class Backend
    {
        struct TargetIdentity;
    public:
        // 适配器的组合操作共享同一目标；只暴露私有句柄及已固定的数字身份。
        class TargetLease
        {
        public:
            TargetLease() = default;
            ~TargetLease();
            TargetLease(const TargetLease&) = delete;
            TargetLease& operator=(const TargetLease&) = delete;
            HANDLE native() const { return identity.native(); }
            DWORD processId() const { return pid; }
            DWORD threadId() const { return tid; }
            // 长期/TLS 保存前结束临时别名；身份引用继续存续，析构无需后端锁。
            void releaseAlias();
        private:
            friend class Backend;
            DWORD pid = 0;
            DWORD tid = 0;
            ark::DriverHandle identity;
            std::shared_ptr<TargetIdentity> retained;
            Backend* aliasOwner = nullptr;
            bool threadAlias = false;
            void clear();
            ark::DriverHandle* device(ark::DriverHandle& fallback) const;
        };
        bool retainTarget(HANDLE handle, bool thread, TargetLease& lease) noexcept;
        bool initialize();
        bool shutdown();
        DWORD dispatch(KSWORD_DEBUGGER_CALL& call);
        DWORD setUseHvm(bool enabled);
        KSWORD_DEBUGGER_BACKEND_STATUS status();
        KSWORD_DEBUGGER_OPTIONS options();
        DWORD setOptions(const KSWORD_DEBUGGER_OPTIONS& options);
        KSWORD_DEBUGGER_POLICY_STATUS policyStatus();
        bool preferShadowExecution();
        void recordFallback(const std::string& source, const std::string& destination,
            DWORD error, const std::string& reason);
        DWORD restoreShadowWrites(std::uint64_t address = 0, std::uint64_t bytes = 0);
        HANDLE openProcess(DWORD access, BOOL inherit, DWORD pid);
        DWORD processId(HANDLE process);
        BOOL readMemory(HANDLE process, LPCVOID address, LPVOID data, SIZE_T bytes, SIZE_T* transferred);
        // A frontend may temporarily add execute permission while editing data.
        // Adapters must verify the pre-protection transaction before using data.
        enum class MemoryWriteKind { byProtection, data };
        BOOL writeMemory(HANDLE process, LPVOID address, LPCVOID data, SIZE_T bytes, SIZE_T* transferred,
            MemoryWriteKind kind = MemoryWriteKind::byProtection);
        SIZE_T queryMemory(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION info, SIZE_T bytes);
        BOOL protectMemory(HANDLE process, LPVOID address, SIZE_T bytes, DWORD protection, PDWORD previous);
        LPVOID allocateMemory(HANDLE process, LPVOID address, SIZE_T bytes, DWORD type, DWORD protection);
        BOOL freeMemory(HANDLE process, LPVOID address, SIZE_T bytes, DWORD type);
        HANDLE createThread(HANDLE process, LPSECURITY_ATTRIBUTES attributes, SIZE_T stackBytes,
            LPTHREAD_START_ROUTINE start, LPVOID parameter, DWORD flags, LPDWORD tid);
        HANDLE openThread(DWORD access, BOOL inherit, DWORD tid);
        BOOL getContext(HANDLE thread, LPCONTEXT context);
        BOOL setContext(HANDLE thread, const CONTEXT* context);
        DWORD suspendThread(HANDLE thread);
        DWORD resumeThread(HANDLE thread);
        BOOL attach(DWORD pid);
        BOOL waitEvent(LPDEBUG_EVENT event, DWORD milliseconds);
        BOOL continueEvent(DWORD pid, DWORD tid, DWORD status);
        // Borrow a transport already owned by the frontend. These helpers never
        // attach, detach, wait for, or continue a Windows debug event.
        DWORD observeNativeSession(DWORD pid, std::uint64_t* generation = nullptr);
        DWORD observeNativeEvent(const DEBUG_EVENT& event, std::uint64_t generation = 0);
        DWORD validateNativeContinue(DWORD pid, DWORD tid, std::uint64_t generation = 0);
        DWORD releaseNativeSession(std::uint64_t generation = 0);
        DWORD retireNativeThread(DWORD tid, std::uint64_t generation = 0);
        // The native adapter keeps complete Windows/XSTATE context ownership.
        // Only debug registers cross this seam; Dr6 always comes from Windows.
        using NativeDebugWriter = BOOL(WINAPI*)(HANDLE, const CONTEXT*, BOOL rollback, void*);
        // Success also includes a valid session with no shadow yet (unchanged).
        BOOL overlayNativeDebugContext(HANDLE thread, CONTEXT* context, std::uint64_t generation = 0);
        BOOL applyNativeDebugContext(HANDLE thread, const CONTEXT* context,
            NativeDebugWriter writer, void* opaque, std::uint64_t generation = 0);
        void log(const std::string& message);
        // Coalesce exact warning keys across interleaved calls. Emit the first
        // and cumulative 10/100/1000/... occurrences; preserve caller LastError.
        void logRepeated(const std::string& message);
        void overlayShadowBytes(DWORD pid, std::uint64_t address, void* data, SIZE_T bytes);
        bool shadowPatchByte(DWORD pid, std::uint64_t address, unsigned char& byte);
        DWORD nativeExecutionBreakpointPath(std::uint64_t address);
        // 通过 R0 代理取得真实进程/线程句柄，并复制到请求者句柄表。
        // tid==0 表示进程；失败返回 nullptr 并设置 LastError。
        // 返回句柄属于本进程，由调用方用 CloseHandle 关闭。
        HANDLE brokerOpenHandle(DWORD pid, DWORD tid, DWORD desiredAccess, BOOL inherit = FALSE,
            ark::DriverHandle* targetDevice = nullptr);
    private:
#ifdef KSWORD_DEBUGGER_TESTING
        friend struct BackendTestPeer;
#endif
        struct ThreadBreakpoints
        {
            CONTEXT requested{};
            std::array<DWORD, 4> ids{};
            std::shared_ptr<ark::DriverHandle> identity;
            std::uint64_t generation = 0;
            bool shadow = false;
        };
        static bool nativeDataOnlyRecord(const ThreadBreakpoints& record);
        bool hasHvmBreakpointRules() const;
        // One lock serializes policy changes with high-frequency memory access.
        std::recursive_mutex mutex_;
        ark::DriverClient client_;
        ark::DriverHandle driver_;
        // The no-attach owner must keep one exact control file until confirmed CLOSE.
        ark::DriverHandle noAttachDriver_;
        // An uncertain OPEN ACK also reserves this adapter until QUERY/CLOSE recovers it.
        bool noAttachReserved_ = false;
        // The same session/stop numbers cannot be replayed through another transport.
        DWORD noAttachTransport_ = 0;
        // 句柄身份与目标身份分别持有；事件对象不能替代真实进程引用。
        struct TargetIdentity
        {
            DWORD pid = 0;
            DWORD tid = 0;
            HANDLE publicHandle = nullptr;
            ark::DriverHandle publicIdentity;
            ark::DriverHandle targetIdentity;
            ark::DriverHandle deviceIdentity;
        };
        std::unordered_map<HANDLE, std::shared_ptr<TargetIdentity>> processIds_;
        std::unordered_map<HANDLE, std::shared_ptr<TargetIdentity>> threadIds_;
        HANDLE rememberTarget(HANDLE handle, DWORD pid, DWORD tid = 0) noexcept;
        bool pinTarget(HANDLE handle, bool thread, TargetLease& lease) noexcept;
        static bool sameObject(HANDLE first, HANDLE second);
        // 查询句柄实际权限，识别 Ob 回调“打开成功但降权”的情况。
        static bool queryHandleAccess(HANDLE handle, DWORD& grantedAccess);
        // GENERIC_* / MAXIMUM_ALLOWED 是请求选择器，不出现在 GrantedAccess 中。
        static DWORD concreteAccess(DWORD requestedAccess);
        // 原生会话只借用前端事件，仍需持有带查询和等待权限的目标身份句柄。
        HANDLE openIdentityProcess(DWORD pid);
        std::unordered_map<DWORD, ThreadBreakpoints> breakpoints_;
        bool useHvm_ = false;
        bool ownsResident_ = false;
        bool monitorAttachment_ = false;
        bool nativeContextFallback_ = false;
        DWORD nativeContextFallbackError_ = ERROR_SUCCESS;
        KSWORD_DEBUGGER_OPTIONS options_{KSWORD_DEBUGGER_OPTIONS_VERSION, sizeof(KSWORD_DEBUGGER_OPTIONS),
            KSWORD_DEBUGGER_MODE_NORMAL, 0, 1, 1, 1, 1, 32, {0, 0, 0}};
        DWORD fallbackCount_ = 0;
        DWORD lastFallbackError_ = ERROR_SUCCESS;
        struct RepeatedLog { std::uint64_t occurrences = 0, stamp = 0; };
        std::unordered_map<std::string, RepeatedLog> repeatedLogs_;
        std::uint64_t repeatedLogClock_ = 0;
        struct ShadowWritePage
        {
            std::bitset<4096> mask;
            std::array<unsigned char, 4096> bytes{};
        };
        struct ShadowWriteTarget
        {
            std::shared_ptr<ark::DriverHandle> identity;
            std::unordered_map<std::uint64_t, ShadowWritePage> pages;
        };
        std::unordered_map<DWORD, ShadowWriteTarget> shadowWrites_;
        DWORD shadowWritePageCount() const;
        bool hasShadowViews() const;
        bool shadowMemoryWrite(DWORD pid, std::uint64_t address, const void* data,
            SIZE_T bytes, SIZE_T& transferred, bool& handled, bool dataWrite,
            ark::DriverHandle* targetDevice = nullptr);
        std::unordered_set<std::uint64_t> shadowInt3_;
        bool shadowPrepared_ = false;
        bool shadowRecoveryRequired_ = false;
        // 延迟恢复继续保留原对象，不能只保留可复用的 PID。
        std::unordered_map<DWORD, std::shared_ptr<ark::DriverHandle>> shadowQuarantinedTargets_;
        bool ordinaryDataFallback_ = false;
        std::unordered_map<std::uint64_t, DWORD> shadowReferences_;
        struct ShadowStop { std::uint64_t address; DWORD mask; bool userStep; bool stepping; };
        std::unordered_map<DWORD, ShadowStop> shadowStops_;
        DWORD ensureShadowHvm();
        DWORD removeShadowInt3(std::uint64_t address);
        DWORD addShadowInt3(std::uint64_t address);
        DWORD removeShadowRecord(DWORD tid);
        BOOL applyShadowContext(HANDLE thread, const CONTEXT* context, TargetLease* bound = nullptr);
        DWORD shadowEvent(DEBUG_EVENT& event, bool& consume);
        DWORD beginShadowStep(DWORD tid, bool automatic);
        bool shadowWrite(DWORD pid, std::uint64_t address, const void* data, SIZE_T bytes,
            SIZE_T& transferred, bool& handled);
        DWORD attachedPid_ = 0;
        enum class AttachmentOwner { none, backend, native };
        AttachmentOwner attachmentOwner_ = AttachmentOwner::none;
        ark::DriverHandle attachedIdentity_;
        std::uint64_t sessionGeneration_ = 0;
        DWORD lastError_ = ERROR_SUCCESS;
        DEBUG_EVENT lastEvent_{};
        DWORD ensureDebugHvm();
        DWORD pauseOwnedHvm(bool& restart);
        DWORD startOwnedHvm();
        DWORD releaseOwnedHvm();
        DWORD retireAttachment();
        void clearAttachment();
        bool validTargetThread(HANDLE thread) const;
        bool validTargetThread(const TargetLease& lease) const;
        bool matchesThreadRecord(HANDLE thread, const ThreadBreakpoints& record) const;
        BOOL applyDebugContext(HANDLE thread, const CONTEXT* context,
            NativeDebugWriter writer, void* opaque, TargetLease* bound = nullptr);
        void retireDetachedTarget();
        DWORD removeBreakpoints(DWORD tid);
        DWORD installBreakpoints(DWORD tid, ThreadBreakpoints& record);
        DWORD nativeRequest(KSWORD_ARK_DEBUGGER_REQUEST& request, KSWORD_ARK_DEBUGGER_RESPONSE& response,
            ark::DriverHandle* targetDevice = nullptr);
        BOOL nativeContext(HANDLE thread, CONTEXT* context, bool write, TargetLease* bound = nullptr);
        DWORD changeSuspendCount(HANDLE thread, bool suspend);
        DWORD breakpointRequest(KSWORD_ARK_HVM_DEBUG_REQUEST& request,
            KSWORD_ARK_HVM_DEBUG_RESPONSE& response);
        bool transfer(bool write, DWORD pid, std::uint64_t address, void* data,
            SIZE_T bytes, SIZE_T& transferred, bool dataWrite = false,
            ark::DriverHandle* targetDevice = nullptr);
    };
    Backend& backend();
}
