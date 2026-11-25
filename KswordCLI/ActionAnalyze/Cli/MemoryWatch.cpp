#include "MemoryWatch.h"
#include "ThreadObservationJson.h"
#include "../../R3ProcessShared.h"

#include <cstddef>
#include <limits>
#include <stdexcept>

namespace ks::cli::action_analyze
{
namespace
{
    constexpr std::uint32_t kMaxBytes = 65536; // 每次读取的有限范围。
    constexpr std::size_t kMaxRanges = 64; // 每次比较最多保留这么多个差异区间。

    std::uint64_t FileTimeValue(const FILETIME& value)
    {
        return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }

    std::uint64_t UtcNow100ns()
    {
        FILETIME value{};
        GetSystemTimePreciseAsFileTime(&value);
        return FileTimeValue(value);
    }

    DWORD CheckRunning(HANDLE handle)
    {
        const DWORD wait = WaitForSingleObject(handle, 0);
        if (wait == WAIT_TIMEOUT) return ERROR_SUCCESS;
        if (wait == WAIT_OBJECT_0) return ERROR_PROCESS_ABORTED;
        return wait == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
    }

    struct Plan
    {
        DWORD pid = 0; // 显式选择的目标进程。
        std::uint64_t creation = 0; // 必须匹配的进程创建 FILETIME。
        std::uintptr_t address = 0; // 起始虚拟地址。
        std::uint32_t bytes = 0; // 只读的字节数。
        std::uint32_t samples = 0; // 最多尝试的快照数。
        std::uint32_t intervalMs = 0; // 相邻读取之间的最短间隔。
    };

    // 从命令参数解析有限采样计划。超范围、溢出和缺少身份都在打开目标前拒绝。
    Plan ParsePlan(const Args& args)
    {
        for (const auto* key : {L"--pid", L"--creation-time", L"--address", L"--size"})
        {
            args.require(key);
        }
        Plan plan; // 本次读取中的不可变参数。
        const auto address = args.integer(L"--address"); // 先保留输入位宽以检查溢出。
        const auto addressLimit = (std::numeric_limits<std::uintptr_t>::max)(); // 本机可表示地址上限。
        plan.pid = args.u32(L"--pid");
        plan.creation = args.integer(L"--creation-time");
        plan.bytes = args.u32(L"--size");
        plan.samples = args.u32(L"--samples", 20);
        plan.intervalMs = args.u32(L"--interval-ms", 100);
        if (!plan.pid || !plan.creation || !address || !plan.bytes || plan.bytes > kMaxBytes ||
            address > addressLimit || plan.bytes - 1 > addressLimit - address ||
            plan.samples < 2 || plan.samples > 64 || plan.intervalMs < 10 || plan.intervalMs > 1000)
        {
            throw std::invalid_argument("invalid process identity, address, size, sample count or interval");
        }
        plan.address = static_cast<std::uintptr_t>(address);
        return plan;
    }

    // 核对实际起止区域都在同一已提交且可读的区域内。映射变化时调用方终止比较。
    DWORD ReadMapping(HANDLE target, const Plan& plan, MEMORY_BASIC_INFORMATION& mapping)
    {
        if (!VirtualQueryEx(target, reinterpret_cast<void*>(plan.address), &mapping, sizeof(mapping)))
        {
            return GetLastError();
        }
        const auto base = reinterpret_cast<std::uintptr_t>(mapping.BaseAddress); // 区域首地址。
        const auto access = mapping.Protect & 0xffu; // 剥离修饰位后的基本保护类型。
        const bool readable = access == PAGE_READONLY || access == PAGE_READWRITE || access == PAGE_WRITECOPY ||
            access == PAGE_EXECUTE_READ || access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
        if (mapping.State != MEM_COMMIT || !readable || (mapping.Protect & PAGE_GUARD) ||
            plan.address < base || plan.address - base >= mapping.RegionSize ||
            plan.bytes > mapping.RegionSize - (plan.address - base))
        {
            return ERROR_INVALID_ADDRESS;
        }
        return ERROR_SUCCESS;
    }

    // 比较 Windows 可观测的映射属性。调用者保留无法识别同属性重建的限制。
    bool SameMapping(const MEMORY_BASIC_INFORMATION& first, const MEMORY_BASIC_INFORMATION& second)
    {
        return first.BaseAddress == second.BaseAddress && first.AllocationBase == second.AllocationBase &&
            first.RegionSize == second.RegionSize && first.Type == second.Type && first.State == second.State &&
            first.Protect == second.Protect && first.AllocationProtect == second.AllocationProtect;
    }

    // 只读取计划范围。记录读取窗口，供报告区分内容采样时间和真实写入时间。
    DWORD TakeSnapshot(HANDLE target, const Plan& plan, std::vector<std::uint8_t>& bytes,
        MEMORY_BASIC_INFORMATION& mapping, std::uint64_t& lower, std::uint64_t& upper)
    {
        const DWORD before = ReadMapping(target, plan, mapping); // 读之前验证区域。
        if (before != ERROR_SUCCESS)
        {
            return before;
        }
        SIZE_T count = 0; // 系统实际提供的完整字节数。
        const auto begin = UtcNow100ns(); // 读实际字节的 UTC 时间界限。
        if (!ReadProcessMemory(target, reinterpret_cast<const void*>(plan.address), bytes.data(), bytes.size(), &count))
        {
            return GetLastError();
        }
        const auto end = UtcNow100ns();
        MEMORY_BASIC_INFORMATION after{}; // 同一对象上的读后回查。
        const DWORD status = ReadMapping(target, plan, after);
        if (status != ERROR_SUCCESS || !SameMapping(mapping, after) || count != bytes.size())
        {
            return status != ERROR_SUCCESS ? status : ERROR_PARTIAL_COPY;
        }
        lower = begin;
        upper = end;
        return ERROR_SUCCESS;
    }

    // 从两个完整快照计算全部变化字节数，报告只包含有界的相对区间和长度。
    Json Compare(const std::vector<std::uint8_t>& before, const std::vector<std::uint8_t>& after)
    {
        std::size_t changed = 0; // 包括报告区间配额以外的变化字节。
        std::size_t ranges = 0; // 全部连续差异区间数。
        std::vector<Json> result; // 只序列化前若干区间。
        for (std::size_t index = 0; index < before.size();)
        {
            if (before[index] == after[index])
            {
                ++index;
                continue;
            }
            const auto start = index++; // 连续差异的相对起点。
            while (index < before.size() && before[index] != after[index])
            {
                ++index;
            }
            const auto length = index - start; // 可核对的实际差异长度。
            changed += length;
            if (++ranges <= kMaxRanges)
            {
                result.push_back(Json::object({{L"offset", Json::count(start)}, {L"length", Json::count(length)}}));
            }
        }
        return Json::object({{L"changedByteCount", Json::count(changed)},
            {L"rangeCount", Json::count(ranges)}, {L"ranges", Json::array(result)},
            {L"omittedRangeCount", Json::count(ranges - result.size())}});
    }

    // 执行有限 R3 读取，直到完成、用户取消、目标退出或映射不再可比。
    Result Run(const Args& args)
    {
        const auto plan = ParsePlan(args); // 处理期间始终绑定同一个计划。
        const process::Lease target(args, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE); // 持有原进程对象。
        const auto identity = target.creationTime; // 原生句柄读回的创建时间。
        DWORD error = target.error ? target.error : target.matches ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
        Cancellation cancellation; // 同现有 CLI 的取消通道。
        bool canceled = false; // 独立区分人为取消和系统失败。
        std::vector<Json> rows; // 仅保留有限的、已完整读回的差异观测。
        std::vector<std::uint8_t> current(plan.bytes), previous(plan.bytes); // 相邻两个完整快照。
        MEMORY_BASIC_INFORMATION baseline{}; // 本次第一份已验观察的实际映射属性。
        std::optional<memory::PassiveThreadObservation> threads;
        if (!error) threads.emplace(target.handle.get(), target.pid);
        for (std::uint32_t index = 0; !error && index < plan.samples; ++index)
        {
            if (cancellation.token->load(std::memory_order_relaxed))
            {
                canceled = true;
                break;
            }
            // 以已打开的原进程对象等待。进程退出后不会用相同 PID 重开。
            const auto wait = WaitForSingleObject(target.handle.get(), index ? plan.intervalMs : 0);
            if (wait != WAIT_TIMEOUT)
            {
                error = wait == WAIT_FAILED ? GetLastError() : ERROR_PROCESS_ABORTED;
                break;
            }
            MEMORY_BASIC_INFORMATION mapping{}; // 与已冻结的映射属性比较。
            std::uint64_t lower = 0, upper = 0; // 记录完整读取的 UTC 窗口。
            error = TakeSnapshot(target.handle.get(), plan, current, mapping, lower, upper);
            if (error)
            {
                break;
            }
            if (index && !SameMapping(baseline, mapping))
            {
                error = ERROR_INVALID_ADDRESS;
                break;
            }
            baseline = mapping;
            const auto threadObservation = threads->Observe();
            rows.push_back(Json::object({{L"ordinal", Json::number(index)}, {L"readStartUtc100ns", Json::count(lower)},
                {L"readEndUtc100ns", Json::count(upper)}, {L"difference", index ? Compare(previous, current) : Json{}},
                {L"threadObservation", ThreadObservationJson(threadObservation)}}));
            previous.swap(current);
        }
        const bool complete = !error && !canceled && rows.size() == plan.samples; // 精确区分部分观测。
        const bool targetMatched = !target.error && target.matches;
        const DWORD targetState = targetMatched ? CheckRunning(target.handle.get()) : error;
        const wchar_t* targetStatus = L"unknown";
        if (targetMatched && targetState == ERROR_SUCCESS) targetStatus = L"alive";
        if (targetMatched && targetState == ERROR_PROCESS_ABORTED) targetStatus = L"exited";
        if (!target.error && !target.matches) targetStatus = L"identity-mismatch";
        return {complete ? 0 : rows.empty() ? 3 : 6,
            Json::object({{L"pid", Json::number(plan.pid)}, {L"expectedCreationTime100ns", Json::count(plan.creation)},
                {L"observedCreationTime100ns", identity ? Json::count(identity) : Json{}},
                {L"address", Json::hex(plan.address)}, {L"bytes", Json::number(plan.bytes)},
                {L"requestedSamples", Json::number(plan.samples)}, {L"readSamples", Json::count(rows.size())},
                {L"complete", Json::boolean(complete)}, {L"canceled", Json::boolean(canceled)},
                {L"win32Error", Json::number(error)}, {L"observations", Json::array(rows)},
                {L"threadObservation", Json::object({{L"source", Json::string(L"toolhelp-and-thread-handle")},
                    {L"targetStatus", Json::string(targetStatus)}, {L"targetWin32Error", Json::number(targetState)}})}}),
            {L"Sampled content differences. Same-attribute replacement and changes between reads can be missed. Write source and execution are unknown.",
                L"Thread observations come from separate snapshots. Newly observed uses the previous listing and the queried creation time. Short-lived threads and unavailable identities can be missed."}};
    }
}

void RegisterMemoryWatch()
{
    addCommand({L"analyze memory watch",
        L"KswordCLI.exe analyze memory watch --pid PID --creation-time FILETIME --address ADDRESS --size BYTES [--samples N] [--interval-ms N] [--backend r3] [--json]",
        L"Observe byte differences across bounded read-only snapshots of an explicit memory range.",
        L"Required: --pid, --creation-time, --address, --size (1..65536). Optional: --samples (2..64, default 20), --interval-ms (10..1000, default 100), --backend r3, --json.",
        L"An original process handle and creation time bind the capture. A failed read or an observed mapping change ends the comparison. Outputs difference ranges without memory contents. Write attribution and execution evidence are unavailable.", Run});
}
}
