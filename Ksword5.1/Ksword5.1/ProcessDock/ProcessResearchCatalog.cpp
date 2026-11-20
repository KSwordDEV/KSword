#include "ProcessResearchCatalog.h"
#include "ProcessDetectionForensics.h"
#include "ProcessDetectionNativeMemory.h"

namespace ksword::detection
{
    namespace
    {
        constexpr MethodMask vol(int index) { return (1ULL << 40) << index; }
    }

    const std::array<ResearchPoint, ResearchCount>& ResearchCatalog()
    {
        using B = ResearchBackend;
        static const std::array<ResearchPoint, ResearchCount> catalog{{
            {1, QStringLiteral("活动进程链表 PsActiveProcessHead"), Cost::Moderate, B::Shared, ActiveProcesses},
            {2, QStringLiteral("EPROCESS 进程池扫描"), Cost::Slow, B::Shared, vol(1)},
            {3, QStringLiteral("无池标签 EPROCESS 结构扫描"), Cost::Slow, B::Objects, 0},
            {4, QStringLiteral("PspCidTable 进程 CID 表"), Cost::Slow, B::Shared, CidProcesses},
            {5, QStringLiteral("EPROCESS 结构与生命周期一致性"), Cost::Slow, B::Objects, 0},
            {6, QStringLiteral("ETHREAD 线程池扫描"), Cost::Slow, B::Shared, vol(2)},
            {7, QStringLiteral("EPROCESS 线程链表"), Cost::Slow, B::Shared, LinkedThreads},
            {8, QStringLiteral("ETHREAD 客户端 ID 与进程对象归属"), Cost::Slow, B::Objects, 0},
            {9, QStringLiteral("全系统进程句柄反查"), Cost::Slow, B::Shared, ProcessHandles},
            {10, QStringLiteral("CSRSS 进程句柄反查"), Cost::Slow, B::Shared, CsrssHandles},
            {11, QStringLiteral("会话、桌面与 GUI 线程归属"), Cost::Slow, B::Objects, 0},
            {12, QStringLiteral("对象头与 Process 类型验证"), Cost::Slow, B::Objects, 0},
            {13, QStringLiteral("每个处理器的当前线程"), Cost::Slow, B::Objects, 0},
            {14, QStringLiteral("调度器就绪队列"), Cost::Slow, B::Objects, 0},
            {15, QStringLiteral("等待线程与所属进程"), Cost::Slow, B::Objects, 0},
            {16, QStringLiteral("内核线程栈与执行地址"), Cost::Slow, B::Objects, 0},
            {17, QStringLiteral("上下文切换事件"), Cost::Slow, B::Shared, EtlThreads},
            {18, QStringLiteral("跨处理器线程一致性"), Cost::Slow, B::Objects, 0},
            {19, QStringLiteral("DTB / PML4 候选扫描"), Cost::Slow, B::Shared, RawPageRoots},
            {20, QStringLiteral("页表根自引用检查"), Cost::Slow, B::Shared, RawPageRoots},
            {21, QStringLiteral("处理器 CR3 与进程页表根比对"), Cost::Slow, B::Objects, 0},
            {22, QStringLiteral("处理器实际 CR3 观测"), Cost::Moderate, B::Shared, HvmWatchHistory},
            {23, QStringLiteral("地址空间全页表映射遍历"), Cost::Slow, B::Objects, 0},
            {24, QStringLiteral("物理页 PFN 数据库扫描"), Cost::Slow, B::Shared, PhysicalPageOwners},
            {25, QStringLiteral("PFN 与 PTE 反向复核"), Cost::Slow, B::Objects, 0},
            {26, QStringLiteral("私有 PFN 与进程归属"), Cost::Slow, B::Shared, PhysicalPageOwners},
            {27, QStringLiteral("VAD 与可执行 PTE 交叉验证"), Cost::Slow, B::Shared, ProcessMemorySurvey},
            {28, QStringLiteral("工作集、映射与驻留状态"), Cost::Slow, B::Shared, ResidentMappings},
            {29, QStringLiteral("Section / ControlArea 映射反查"), Cost::Slow, B::Shared, ResidentMappings},
            {30, QStringLiteral("跨进程内核映射一致性"), Cost::Slow, B::Objects, 0},
            {31, QStringLiteral("进程创建与退出回调"), Cost::Moderate, B::Shared, CallbackHistory},
            {32, QStringLiteral("子系统进程创建回调 Ex2"), Cost::Moderate, B::Shared, CallbackHistory},
            {33, QStringLiteral("线程创建与退出回调"), Cost::Moderate, B::Shared, CallbackHistory},
            {34, QStringLiteral("映像加载回调"), Cost::Moderate, B::Shared, CallbackHistory},
            {35, QStringLiteral("进程与线程句柄回调"), Cost::Moderate, B::Shared, CallbackHistory},
            {36, QStringLiteral("内核进程 ETW 生命周期"), Cost::Slow, B::Shared, EtlProcesses},
            {37, QStringLiteral("线程与调度 ETW 记录"), Cost::Slow, B::Shared, EtlThreads},
            {38, QStringLiteral("Windows 安全审计进程历史"), Cost::Moderate, B::Shared, SecurityHistory},
            {39, QStringLiteral("Sysmon 进程、远程线程、访问与篡改事件"), Cost::Moderate, B::Shared, SysmonHistory},
            {40, QStringLiteral("WMI 进程生命周期观察"), Cost::Slow, B::Activity, 0},
            {41, QStringLiteral("TCP / UDP 网络端点进程归属"), Cost::Fast, B::Shared, NetworkEndpoints},
            {42, QStringLiteral("文件与注册表 I/O 回调"), Cost::Moderate, B::Shared, CallbackHistory},
            {43, QStringLiteral("Prefetch 与 Amcache 历史执行线索"), Cost::Slow, B::Activity, 0},
            {44, QStringLiteral("外部 VMI 进程对象视图"), Cost::Slow, B::External, 0},
            {45, QStringLiteral("VM-Exit CR3 写入事件"), Cost::Moderate, B::External, 0},
            {46, QStringLiteral("EPT 页表页写入观测"), Cost::Slow, B::External, 0},
            {47, QStringLiteral("EPT 内核对象页写入观测"), Cost::Slow, B::External, 0},
            {48, QStringLiteral("EPT 执行命中"), Cost::Moderate, B::External, 0},
            {49, QStringLiteral("来宾与宿主进程交叉视图"), Cost::Slow, B::External, 0},
            {50, QStringLiteral("Intel PT 控制流与分页上下文"), Cost::Slow, B::External, 0},
            {51, QStringLiteral("外部 DMA 物理采集视图"), Cost::Slow, B::External, 0},
            {52, QStringLiteral("独立宿主虚拟机快照"), Cost::Slow, B::External, 0},
            {53, QStringLiteral("带外内核调试观察"), Cost::Slow, B::External, 0},
            {54, QStringLiteral("进程空洞化检查"), Cost::Slow, B::Shared, vol(5)},
            {55, QStringLiteral("进程 Ghosting 检查"), Cost::Slow, B::Shared, vol(6)},
            {56, QStringLiteral("PEB 模块链与实际映射"), Cost::Slow, B::Shared, vol(7)},
            {57, QStringLiteral("私有可执行内存"), Cost::Slow, B::Shared, vol(8)},
            {58, QStringLiteral("私有映射中的 PE 映像"), Cost::Slow, B::Activity, 0},
            {59, QStringLiteral("线程入口与映像归属"), Cost::Slow, B::Shared, vol(9)},
            {60, QStringLiteral("APC 回调执行异常"), Cost::Slow, B::Activity, 0},
            {61, QStringLiteral("映像代码完整性"), Cost::Slow, B::Activity, 0},
            {62, QStringLiteral("模块外内核可执行内存"), Cost::Slow, B::Activity, 0},
            {63, QStringLiteral("内核模块与驱动对象交叉检测"), Cost::Slow, B::Shared, KernelIntegrity},
            {64, QStringLiteral("内核回调地址归属"), Cost::Slow, B::Shared, vol(11)},
            {65, QStringLiteral("内核执行入口完整性"), Cost::Slow, B::Shared, CpuIntegrity},
            {66, QStringLiteral("内核工作线程、DPC 与工作项"), Cost::Moderate, B::Shared, KernelWorkItems | TimerRoutines},
        }};
        return catalog;
    }

    QString ResearchSource(const ResearchPoint& point)
    {
        if (point.id == 29 || (point.id >= 62 && point.id <= 65)) return QStringLiteral("R0 / Volatility 3");
        if (point.backend == ResearchBackend::Objects || (point.sources & (0x1fffULL << 40)))
            return QStringLiteral("Volatility 3");
        if (point.sources == EtlProcesses || point.sources == EtlThreads) return QStringLiteral("ETL");
        if (point.sources == CallbackHistory) return QStringLiteral("R0 回调记录");
        switch (point.id)
        {
        case 9: case 41: return QStringLiteral("Windows");
        case 10: return QStringLiteral("Windows / Volatility 3");
        case 19: return QStringLiteral("MemProcFS / RAW");
        case 20: return QStringLiteral("RAW");
        case 22: case 46: case 47: case 48: return QStringLiteral("HVM / EPT");
        case 26: return QStringLiteral("Windows / MemProcFS");
        case 38: case 39: return QStringLiteral("Windows 事件日志");
        case 40: return QStringLiteral("WMI");
        case 43: return QStringLiteral("Windows");
        case 44: case 49: return QStringLiteral("VMI / VMRS");
        case 45: return QStringLiteral("Xen / HVM");
        case 50: return QStringLiteral("Intel PT / libipt");
        case 51: return QStringLiteral("FPGA / MemProcFS");
        case 52: return QStringLiteral("Hyper-V VMRS");
        case 53: return QStringLiteral("KD / EXDI");
        case 58: case 60: case 61: return QStringLiteral("MemProcFS FindEvil");
        default: return QStringLiteral("R0");
        }
    }

    DetectionSelection DetectionDefaults(bool deep)
    {
        DetectionSelection selection;
        selection.sources = ProcessBaseline | ThreadOwners | DesktopWindows;
        selection.research.set(41 - 1);  // Local endpoint table.
        if (deep)
        {
            // Share each live kernel walk and each callback-ring read across the selected points.
            for (int id : {1, 4, 7, 9, 31, 32, 33, 34, 35, 42, 66}) selection.research.set(id - 1);
            selection.sources |= ProcessCrossView | ThreadCrossView | CidThreads;
        }
        return selection;
    }

}
