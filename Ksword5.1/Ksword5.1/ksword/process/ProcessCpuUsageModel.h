#pragma once

// ============================================================
// ProcessCpuUsageModel.h
// 作用：
// - 用相邻两次累计 CPU 时间与单调时钟样本计算 CPU 占用；
// - 同时给出“全系统归一化百分比”和“单核等效百分比”；
// - 保持算法不依赖 Win32/Qt，便于在非 Windows 主机做纯计算验证。
// ============================================================

#include <algorithm>
#include <cstdint>

namespace ks::process
{
    struct CpuUsageWindowResult
    {
        double systemPercent = 0.0;         // 相对全部逻辑处理器归一化，范围 0~100。
        double coreEquivalentPercent = 0.0; // 100% 等于占满一个逻辑处理器，可按并发度超过 100%。
        bool valid = false;                 // false 表示首轮、时钟回退或累计计数器回退。
    };

    inline CpuUsageWindowResult CalculateCpuUsageWindow(
        const std::uint64_t currentCpuTime100ns,
        const std::uint64_t previousCpuTime100ns,
        const std::uint64_t currentTick100ns,
        const std::uint64_t previousTick100ns,
        const std::uint32_t logicalCpuCount,
        const std::uint32_t maximumConcurrentLogicalProcessors)
    {
        CpuUsageWindowResult result{};
        if (currentTick100ns <= previousTick100ns ||
            currentCpuTime100ns < previousCpuTime100ns)
        {
            return result;
        }

        const std::uint64_t deltaTick100ns = currentTick100ns - previousTick100ns;
        const std::uint64_t deltaCpu100ns = currentCpuTime100ns - previousCpuTime100ns;
        const double logicalCpuCountSafe = static_cast<double>(std::max(1U, logicalCpuCount));
        const double concurrentCpuCountSafe = static_cast<double>(
            std::max(1U, maximumConcurrentLogicalProcessors));
        const double coreEquivalentPercent =
            (static_cast<double>(deltaCpu100ns) / static_cast<double>(deltaTick100ns)) * 100.0;

        result.coreEquivalentPercent = std::clamp(
            coreEquivalentPercent,
            0.0,
            concurrentCpuCountSafe * 100.0);
        result.systemPercent = std::clamp(
            result.coreEquivalentPercent / logicalCpuCountSafe,
            0.0,
            100.0);
        result.valid = true;
        return result;
    }
}
