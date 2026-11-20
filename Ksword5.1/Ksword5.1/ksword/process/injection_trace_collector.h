#pragma once

// 进程注入痕迹检查（issue #196 第一阶段）的现场采集器。
//
// 分工：这一层只负责"把现场读出来"，所有判据都在 shared/evidence/InjectionSurvey.h。
// 采集器不产生结论，也不允许在这里加规则 —— 加规则要去纯判据层，那里有离线测试。
//
// 采集边界（写在这里是为了让改动的人先看见）：
//   * 权限从最小开始：先 PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ，
//     失败才退到 PROCESS_QUERY_INFORMATION | PROCESS_VM_READ。绝不请求
//     PROCESS_ALL_ACCESS。受保护进程拒绝访问时输出"访问受限"，不是"未发现注入"。
//   * 全程持有同一个句柄，并在开始和结束各核一次 PID + 创建时间。身份变了就整份
//     作废 —— 否则证据会串到另一个进程实例上。
//   * 快速模式不挂起目标、不改目标页保护属性、不对运行中的线程取上下文。
//   * 任何读取失败、超预算、路径查询失败都原样带进 SurveyReport 的缺口，
//     不折叠成"干净"。

#include "../../../../shared/evidence/InjectionSurvey.h"
// R0 扫描后端的协议常量（条目/表读上限）。协议只在 shared/driver 定义，
// 这里引用而不是在本地复制一份数字。
#include "../../../../shared/driver/KswordArkInjectionScanIoctl.h"

#include <QString>

#include <cstdint>
#include <functional>

namespace ks::process
{
    // 采集预算。不承诺"快扫必定几百毫秒"，只承诺命中上限时报告里能看见。
    struct InjectionTraceOptions
    {
        bool deepMode = false;                      // 深度模式：全部可执行映像范围
        std::uint32_t maxRegionCount = 262144U;     // VirtualQueryEx 条目上限
        std::uint32_t maxImageComparisons = 4096U;  // 比较目标上限
        std::uint64_t maxReadBytes = 64ULL * 1024ULL * 1024ULL;
        std::uint64_t maxDurationMs = 30000ULL;
        std::uint32_t maxThreads = 4096U;
        std::uint32_t maxPayloadProbeBytes = 4096U; // 每个候选区域读多少字节做结构判定

        // R0 扫描后端（VAD 树 + 用户态可执行页表叶子）。能力门控：驱动没加载、
        // 没权限、或 DynData 没为当前 build 验证过偏移时自动降级，
        // R3 那一侧的结果照常产出。
        bool useKernelBackend = true;
        std::uint32_t kernelVadMaxEntries = 8192U;
        // 取协议上限：实测 explorer.exe 需要 7266 段，重进程一次跑完才不会
        // 每次都以 Partial 收尾、进而永远背一条覆盖缺口。
        std::uint32_t kernelPteMaxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_MAX;
        std::uint32_t kernelPteMaxTableReads = 65536U;
        std::function<bool()> cancelled;
    };

    enum class InjectionTraceStatus : std::uint8_t
    {
        Completed = 0,
        ProcessIdentityUnavailable,  // 拿不到创建时间：身份无法确认
        ProcessIdentityMismatch,     // PID 已复用
        ProcessOpenDenied,           // 权限不足（受保护进程等）
        ProcessOpenFailed,
    };

    // 采集结果。report 是判据层产出的那一份；其余字段只是展示与诊断用的现场统计。
    struct InjectionTraceResult
    {
        InjectionTraceStatus status = InjectionTraceStatus::ProcessIdentityUnavailable;
        QString diagnosticText;

        Ksword::Evidence::SurveyReport report;

        // 本次**请求**的模式。report.mode 只在判据层真的跑起来时才赋值，
        // 进程打不开就一直是默认值——界面拿它显示标题会把深度扫描说成快速扫描。
        Ksword::Evidence::SurveyMode requestedMode =
            Ksword::Evidence::SurveyMode::Fast;

        std::uint32_t pid = 0;
        std::uint64_t creationTime100ns = 0;
        QString imagePath;
        QString architectureText;

        std::uint32_t regionCount = 0;
        std::uint32_t loaderModuleCount = 0;
        std::uint32_t imageMappingCount = 0;
        std::uint32_t threadCount = 0;
        std::uint32_t comparedModuleCount = 0;
        std::uint32_t comparedRangeCount = 0;
        std::uint32_t workingSetPagesQueried = 0;
        std::uint64_t bytesRead = 0;
        std::uint64_t elapsedMs = 0;

        // 栈回溯的现场账（只在深度模式非零）。walked 远小于 considered 是常态：
        // 只有停在等待里的线程才取上下文。
        std::uint32_t stackThreadsConsidered = 0;
        std::uint32_t stackThreadsWaiting = 0;
        std::uint32_t stackThreadsWalked = 0;

        // 深度模式里为"休眠载荷"检查过首页的非可执行区域数。0 表示这一档没做。
        std::uint32_t dormantRegionsScanned = 0;

        // 节对象第二参考源的账（只在深度模式 + 有驱动时非零）。
        std::uint32_t sectionModulesChecked = 0;
        std::uint32_t sectionPagesCompared = 0;
        std::uint32_t sectionPagesDiffering = 0;

        // R0 后端的现场读数。state 为 NotRequested 表示没打算用；
        // DriverUnavailable 表示想用但驱动不在（能力降级，不是缺陷）。
        Ksword::Evidence::KernelBackendState kernelVadState =
            Ksword::Evidence::KernelBackendState::NotRequested;
        Ksword::Evidence::KernelBackendState kernelPteState =
            Ksword::Evidence::KernelBackendState::NotRequested;
        std::uint32_t kernelVadRegionCount = 0;
        std::uint32_t kernelVadUnreadableNodes = 0;
        std::uint32_t kernelExecutableExtentCount = 0;
        std::uint32_t kernelExecutablePageCount = 0;
        std::uint32_t kernelPteTableReads = 0;
        QString kernelDiagnosticText;

        bool completed() const { return status == InjectionTraceStatus::Completed; }
    };

    // ScreenProcessInjectionSurface：进程列表那一列用的**廉价筛选**。
    //
    // 只做地址空间枚举 + 区域分类，**不**碰模块列表、PE 归一化、工作集、线程、驱动。
    // 实测（2026-09-12，本机 496 个进程）中位 2.52 ms/进程、p95 9.5 ms、全机 1073 ms；
    // 相比之下完整的 ScanProcessInjectionTrace 在 explorer 上冷启要 4.6 s。
    //
    // 它产出的是**计数，不是结论**：同一次采样里 310 个可打开进程有 284 个带动态代码，
    // 所以"有/无"没有区分度，能看的是数量的离群程度。打不开的进程返回 AccessDenied，
    // 调用方必须按"不知道"显示，绝不能显示 0。
    Ksword::Evidence::ProcessSurfaceScreen ScreenProcessInjectionSurface(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns);

    // 采集并评估一个进程的注入痕迹。
    // - pid / expectedCreationTime100ns：进程实例身份。expectedCreationTime100ns 为 0
    //   表示调用方没有已知基准，此时只做"扫描前后一致"的自校验。
    // - fallbackImagePath：内核路径查询失败时的显示回退，不参与判据。
    InjectionTraceResult ScanProcessInjectionTrace(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        const QString& fallbackImagePath,
        const InjectionTraceOptions& options = InjectionTraceOptions{});
}
