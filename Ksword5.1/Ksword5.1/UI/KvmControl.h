#pragma once

// KvmControl：KSwordVM（R-1 / hypervisor 层）能力门面。
//
// 存在的理由：
// - 标题栏权限按钮排里的 KVM 按钮、KernelDock 的 HVM 页、以及后续的 EPT 内存
//   保护 / 隐蔽 Hook / 内存隐藏都要读同一份状态、走同一套确认与写权限门。
//   把它们收在一个门面里，避免每个调用点各自拼 IOCTL 参数和各自判断可用性。
// - 所有查询都是同步阻塞调用（IOCTL），调用方必须放到后台线程；
//   SOAK 更是会占用驱动侧状态锁数十秒，绝不能在 UI 线程调用。

#include <QByteArray>
#include <QString>

#include "../ArkDriverClient/ArkDriverClient.h"

namespace ksword::kvm
{
    // KvmAvailability：KVM 为什么不可用，决定按钮 tooltip 与点击行为。
    enum class KvmAvailability
    {
        Available,          // 能力齐备，可以启动常驻。
        DriverNotRunning,   // KswordARK 驱动服务未运行（先点 R0）。
        UnsupportedCpu,     // 非 Intel、无 VMX/EPT，或缺 MSR bitmap 等硬门。
        FirmwareDisabled,   // 固件里关闭了虚拟化。
        HypervisorConflict, // Hyper-V/VBS 已占用 VMX root。
        NotPrepared,        // 资源尚未准备（PREPARE 未执行或已 TEARDOWN）。
        Faulted             // 存在故障或需要回滚，必须先重置。
    };

    // KvmState：一次状态快照。UI 只读这个结构，不直接解析 featureFlags。
    struct KvmState
    {
        KvmAvailability availability = KvmAvailability::DriverNotRunning;
        bool residentActive = false;   // 至少一个逻辑处理器处于 VMX non-root。
        bool residentComplete = false; // 全部逻辑处理器都在 non-root。
        bool sustainedProven = false;  // 通过过 SOAK，证明常驻能长期存活。
        bool msrBitmapReady = false;   // 有 MSR bitmap，常驻才可能存活。
        bool exitEmulationReady = false; // 分发器能完成全部无条件 exit。
        bool eptRulesReady = false;    // EPT 规则后端可用。
        bool faulted = false;          // FAULTED 或 ROLLBACK_REQUIRED。
        unsigned long generation = 0;  // 用于 compare-before 控制请求。
        unsigned long processorCount = 0;
        unsigned long residentProcessorCount = 0;
        unsigned long eptRuleCount = 0;
        unsigned long long vmExitCount = 0;
        unsigned long soakElapsedMilliseconds = 0;
        unsigned long soakUnexpectedDevirtualizations = 0;
        QString shortStatus; // 按钮 tooltip 首行。
        QString detail;      // 按钮 tooltip 详情。
    };

    // KvmCommandResult：一次控制命令的结果，供 UI 直接展示。
    struct KvmCommandResult
    {
        bool ok = false;
        unsigned long protocolStatus = 0; // KSWORD_ARK_HVM_CONTROL_STATUS_*。
        long ntStatus = 0;
        QString message; // 已本地化的失败原因或成功摘要。
    };

    // queryState：读取一次完整状态快照。阻塞，必须在后台线程调用。
    KvmState queryState();

    // ensurePrepared：按需执行 PREPARE + SELF_TEST，使常驻具备启动条件。
    // 已经准备好时直接返回成功，不重复分配资源。
    KvmCommandResult ensurePrepared();

    // startResident/stopResident：进入或离开全核 VMX non-root。
    // startResident 会在必要时先调用 ensurePrepared。
    KvmCommandResult startResident(unsigned long expectedGeneration);
    KvmCommandResult stopResident(unsigned long expectedGeneration);

    // runSoak：启动常驻、保持指定毫秒数、再停止，用于证明常驻能长期存活。
    // 驱动会把时长夹到协议上下界；调用期间驱动侧状态锁被独占。
    KvmCommandResult runSoak(
        unsigned long expectedGeneration,
        unsigned long milliseconds);

    // resetFault：清除可恢复的故障与回滚标记。常驻中会被拒绝。
    KvmCommandResult resetFault(unsigned long expectedGeneration);

    // 写权限门：
    // - 默认关闭。关闭时 KVM 只做观测，任何会改变系统状态的 R-1 操作都被拒绝；
    // - 由标题栏 KVM 菜单显式切换，并持久化到 QSettings；
    // - 这是进程内的第二道门，驱动侧仍然各自要求确认令牌与 FILE_WRITE_ACCESS。
    bool isWriteAccessEnabled();
    void setWriteAccessEnabled(bool enabled);

    // describeAvailability：把不可用原因翻译成可直接显示的一句话。
    QString describeAvailability(KvmAvailability availability);

    // KvmMemoryResult：一次 R-1 内存操作的结果。
    struct KvmMemoryResult
    {
        bool ok = false;
        // usedDirectWindow：真正走了私有页表窗口（绕开 Mm* 导出）。
        // 为 false 表示退化到 MmCopyMemory，仍能读，但不再规避内核层 Hook。
        bool usedDirectWindow = false;
        // windowReady：本机是否成功建立过私有窗口。
        bool windowReady = false;
        unsigned long long physicalAddress = 0;
        QByteArray data;
        QString message;
    };

    // isMemoryWindowReady：查询私有窗口是否可用，不触碰任何内存。
    KvmMemoryResult queryMemoryWindow();

    // readPhysical/writePhysical：物理内存读写。
    // - 单次上限由驱动协议决定（KSWORD_ARK_HVM_MEMORY_MAX_BYTES）；
    // - writePhysical 受写权限门约束，关闭时直接失败且不发起 IOCTL。
    KvmMemoryResult readPhysical(
        unsigned long long physicalAddress,
        unsigned long length);
    KvmMemoryResult writePhysical(
        unsigned long long physicalAddress,
        const QByteArray& payload);

    // readVirtual/writeVirtual：先按给定页目录基址走页表翻译，再读写。
    // directoryBase 为 0 时按当前进程（即驱动调用线程所在进程）页表解析。
    KvmMemoryResult readVirtual(
        unsigned long long directoryBase,
        unsigned long long virtualAddress,
        unsigned long length);
    KvmMemoryResult writeVirtual(
        unsigned long long directoryBase,
        unsigned long long virtualAddress,
        const QByteArray& payload);

    // translate：只做虚拟到物理翻译，不访问目标内存。
    KvmMemoryResult translate(
        unsigned long long directoryBase,
        unsigned long long virtualAddress);
}
