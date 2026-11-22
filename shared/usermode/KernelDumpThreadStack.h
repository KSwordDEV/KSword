#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ks::kernel_dump
{
    // 共享快照状态；非 Ok/Partial 的结果没有可发布的帧。
    enum class ThreadStackStatus
    {
        Ok,
        Partial,
        InvalidRequest,
        EngineUnavailable,
        DumpOpenFailed,
        UnsupportedDump,
        ThreadNotFound,
        IdentityMismatch,
        IdentityUnavailable,
        ContextUnavailable,
        UnwindUnavailable
    };

    inline constexpr std::uint32_t MaxThreadStackFrames = 128; // 展开帧数上限。

    struct ThreadStackRequest
    {
        std::wstring dumpPath;           // 必填：调用者选择的绝对本地转储路径。
        std::uint32_t processId = 0;     // 转储中的目标 PID。
        std::uint32_t threadId = 0;      // 转储中的目标 TID。
        std::uint64_t processCreationTime100ns = 0; // 可选：需精确核验的进程 FILETIME。
        std::uint64_t threadCreationTime100ns = 0;  // 可选：需精确核验的线程 FILETIME。
        std::uint32_t frameLimit = MaxThreadStackFrames; // 展示上限，范围 1–128。
        std::wstring symbolPath;        // 可选：调用者信任的 DbgEng 符号路径；留空禁用联网。
        std::wstring debuggerDirectory; // 可选：可信的 x64 调试工具安装目录；留空使用 SDK 默认目录。
    };

    struct ThreadStackFrame
    {
        std::uint32_t index = 0;         // 从 0 开始的帧序号。
        std::uint64_t instruction = 0;   // 当前帧指令地址。
        std::uint64_t stack = 0;         // 当前帧栈指针。
        std::uint64_t returnAddress = 0; // 展开器恢复的返回地址。
        std::wstring module;            // 空值表示模块未解析。
        std::wstring symbol;            // 空值表示函数符号未解析。
        std::uint64_t displacement = 0; // 符号内偏移；仅当 symbol 非空时有效。
    };

    struct ThreadStackResult
    {
        ThreadStackStatus status = ThreadStackStatus::InvalidRequest; // 最终状态。
        std::wstring dumpPath;                // 本次请求的转储来源。
        std::uint32_t processId = 0;          // 本次请求的 PID。
        std::uint32_t threadId = 0;           // 本次请求的 TID。
        std::uint64_t processCreationTime100ns = 0; // 转储中的已读取时间，0 表示未知。
        std::uint64_t threadCreationTime100ns = 0;  // 转储中的已读取时间，0 表示未知。
        std::uint32_t dumpTimeUnixSeconds = 0; // 调试器报告的目标时间，0 表示未知。
        std::uint32_t dumpQualifier = 0;      // DbgEng 的 DEBUG_KERNEL_* 转储类型。
        std::uint32_t hresult = 0;            // 失败阶段的 HRESULT 位模式（如有）。
        bool identityMatched = false;       // PID/TID 和所有请求的创建时间均已匹配。
        bool limited = false;               // 帧数达到上限且仍有后续帧证据。
        std::wstring diagnostic;            // 可记录的简短诊断，不是协议字段。
        std::vector<ThreadStackFrame> frames; // 仅已核验目标的真实展开帧。
    };

    // 在后台同步调用；传入冻结的转储路径与目标身份，返回结构化离线展开结果。
    // 不捕获转储、不附加进程、不开启远程或本地实时调试。
    [[nodiscard]] ThreadStackResult UnwindThreadStack(const ThreadStackRequest& request);
}
