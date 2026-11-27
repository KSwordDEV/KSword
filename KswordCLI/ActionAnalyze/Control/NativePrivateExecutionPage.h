#pragma once

#include "NativeExplicitMemorySite.h"
#include "NativeDebugOwner.h"
#include "NativeStepRuntime.h"
#include <vector>

namespace ks::cli::action_analyze::control {

// 无固定页数上限；每个范围属于同一私有分配，范围间可不连续/不同分配。
class NativePrivateExecutionPage final {
public:
    [[nodiscard]] DWORD Resolve(HANDLE process, DWORD pid, std::uint64_t address, std::uint64_t bytes);
    [[nodiscard]] DWORD AddRange(HANDLE process, DWORD pid, std::uint64_t address, std::uint64_t bytes,
        bool& rollbackComplete);
    // 输入原owner持有的process句柄；只在debug事件冻结目标期间调用。返回逐页重设NX的Win32错误。
    // 地址/大小取原页目录，输出不另建范围；仅接受同一私有分配和可恢复保护。
    [[nodiscard]] DWORD RearmExecutablePages(HANDLE process);
    [[nodiscard]] DWORD Verify(HANDLE process) const;
    [[nodiscard]] DWORD SetExecutable(HANDLE process, bool executable, std::uint64_t address = 0, std::size_t instructionBytes = 1);
    // 原事件冻结线程RIP；可能跨页时精确解码，最多开放该指令涉及的两张登记页。
    [[nodiscard]] DWORD OpenInstruction(HANDLE process, HANDLE thread, bool& opened);
    [[nodiscard]] DWORD VerifyInstruction(HANDLE process, std::uint64_t rip) const;
    [[nodiscard]] const std::optional<NativeInstructionFetch>& Instruction() const noexcept { return instruction_; }
    [[nodiscard]] DWORD Restore(HANDLE process);
    void ProcessExited() noexcept; // 仅精确EXIT_PROCESS事件允许免除已消失地址空间的保护责任。
    [[nodiscard]] bool OwnsProtection() const noexcept;
    [[nodiscard]] bool Contains(std::uint64_t address) const noexcept;
    [[nodiscard]] bool IsExecuteFault(const DEBUG_EVENT& event, std::uint64_t rip) const noexcept;
    [[nodiscard]] DWORD VerifyFaultSpan(HANDLE process, const DEBUG_EVENT& event, std::uint64_t rip) const;
    [[nodiscard]] const NativeExplicitMemorySite& Site() const noexcept { return site_; }
    [[nodiscard]] const std::vector<NativeExecutionRange>& Ranges() const noexcept { return ranges_; }

private:
    struct Page {
        NativeExplicitMemorySite site{};
        DWORD original = 0;
        DWORD nonExecutable = 0;
        DWORD expected = 0;
        bool owned = false;
        bool indeterminate = false;
        bool conflict = false;
        bool active = true; // 新增失败但恢复未完成的页仅供Close，不发布为关注范围。
    };
    [[nodiscard]] DWORD ParseRange(HANDLE process, DWORD pid, std::uint64_t address, std::uint64_t bytes,
        std::vector<Page>& resolved) const;
    [[nodiscard]] const Page* FindPage(std::uint64_t address) const noexcept;
    [[nodiscard]] DWORD ReadProtection(HANDLE process, const Page& page, DWORD& protection) const;
    [[nodiscard]] DWORD VerifyPage(HANDLE process, const Page& page) const;
    [[nodiscard]] DWORD Change(HANDLE process, Page& page, DWORD desired);
    [[nodiscard]] DWORD RestorePage(HANDLE process, Page& page);
    NativeExplicitMemorySite site_{};
    std::vector<Page> pages_; // 全部解析后才改保护；每页先记责任再Set，失败独立保留。
    std::vector<NativeExecutionRange> ranges_;
    std::optional<NativeInstructionFetch> instruction_;
    struct ExternalFetchPage { std::uint64_t address; MEMORY_BASIC_INFORMATION mapping; };
    std::optional<ExternalFetchPage> externalFetchPage_; // 未监控取指页只冻结和核验，不写保护。
};

} // namespace ks::cli::action_analyze::control
