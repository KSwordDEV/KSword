#pragma once

// ============================================================
// context_menu_probe.h
// 作用：
// 1) 测量"右键菜单从触发到出现"的耗时（端到端，含显示阶段，不只构建阶段）；
// 2) 给出"在算 vs 在等"判定 —— 用采样窗口内目标进程 CPU 占挂钟的比例区分：
//    CPU 占比高 = 某个组件真在计算（扩展写得烂）；占比低 = 在阻塞等待外部对象（IPC/IO/超时）；
// 3) 供 Shell 关联页的逐条耗时归因使用（临时禁用某条 → 复测 → 前后差值）。
//
// 硬约束（与项目既有风格一致）：
// - 只读、不注入输入：触发用 PostMessage(WM_CONTEXTMENU)，精确计时用 WinEvent 钩子，
//   关闭用 PostMessage(WM_CANCELMODE / WM_CLOSE)。**绝不调用 mouse_event / SendInput**，
//   否则会误触用户桌面图标与任务栏。
// - 不挂起、不写目标进程内存。
// ============================================================

#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::window
{
    // MenuProbeContext：可程序化触发的右键菜单上下文。
    // 说明：只有"空白处右键"能靠 PostMessage 触发；"选中某个文件再右键"需要跨进程
    // 选中列表项（写目标进程内存），不属于本层职责，故不在此枚举内。
    enum class MenuProbeContext
    {
        DesktopBackground, // 桌面空白处右键：桌面 SHELLDLL_DefView 下的图标列表窗口。
        FolderBackground   // 已打开的文件夹窗口空白处右键：任意 CabinetWClass 的 DefView。
    };

    // MenuProbeOptions：测量参数。
    struct MenuProbeOptions
    {
        // samples：采样次数。取中位，避免单次抖动。
        int samples = 3;
        // perSampleTimeoutMs：单次等待菜单出现的上限；超过即记为该次未观测到菜单。
        int perSampleTimeoutMs = 8000;
        // gapMs：采样之间的间隔，避免连续触发互相干扰。
        int gapMs = 250;
    };

    // MenuProbeSample：单次采样的结果。
    struct MenuProbeSample
    {
        bool menuSeen = false;  // menuSeen：本次是否观测到菜单窗口出现。
        double openMs = 0.0;    // openMs：从触发到观测到菜单出现的毫秒数。
    };

    // MenuProbeMeasurement：一组采样的汇总 + 资源消耗判定。
    struct MenuProbeMeasurement
    {
        bool attempted = false;             // attempted：false 表示整节没做（目标窗口缺失等）。
        std::vector<MenuProbeSample> samples; // samples：逐次采样结果。
        double medianMs = 0.0;              // medianMs：成功采样的中位耗时。
        double minMs = 0.0;                 // minMs：成功采样的最小耗时。
        double maxMs = 0.0;                 // maxMs：成功采样的最大耗时。

        // 采样窗口内的进程资源消耗：用于"在算 vs 在等"判定。
        bool processCpuMeasured = false;    // processCpuMeasured：是否成功读到目标进程 CPU 时间。
        double processCpuMs = 0.0;          // processCpuMs：采样窗口内目标进程 CPU 时间（毫秒）。
        double wallMs = 0.0;                // wallMs：采样窗口挂钟时间（毫秒）。
        double cpuRatio = 0.0;              // cpuRatio：processCpuMs / wallMs，判定用。

        // verdict：computing / waiting / unknown（英文枚举值，展示层负责本地化）。
        std::string verdict;
        // diagnostic：整节没做成或降级的原因，空表示正常完成。
        std::string diagnostic;
    };

    // kMenuProbeComputingRatio：判定阈值。
    // CPU 占挂钟 ≥ 该比例视为"在算"，低于则视为"在等外部对象"。
    // 取值依据：2026-09-22 实测真实案例为 6%（等），而正常构建类开销通常在 60% 以上。
    inline constexpr double kMenuProbeComputingRatio = 0.5;

    // FindProbeTargetWindow：为目标上下文找出接收 WM_CONTEXTMENU 的窗口。
    // 入参 context：目标上下文；diagnosticOut：可空，失败时写入原因。
    // 返回：找到的目标窗口句柄；未找到返回 nullptr。
    HWND FindProbeTargetWindow(MenuProbeContext context, std::string* diagnosticOut);

    // MeasureMenuOpenLatency：端到端测量右键菜单弹出耗时。
    // 入参 context：目标上下文；
    // 入参 targetProcessId：目标窗口所在进程（通常是 explorer.exe），用于 CPU 归因；
    // 入参 options：采样参数。
    // 返回：测量汇总。**会短暂弹出菜单并自动关闭**（约 0.1~3 秒），不注入任何输入事件。
    // 调用方式：必须在后台线程调用（内部自带消息泵以接收 WinEvent）。
    MenuProbeMeasurement MeasureMenuOpenLatency(
        MenuProbeContext context,
        unsigned long targetProcessId,
        const MenuProbeOptions& options);
}
