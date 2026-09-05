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
#include <QVector>

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
        Faulted,            // 存在故障或需要回滚，必须先重置。
        // 硬件支持虚拟化，但本版本没有对应后端（当前即 AMD SVM）。
        // 与 UnsupportedCpu 分开：前者要换机器，后者要等软件。
        BackendNotImplemented,
        // 外层已有 hypervisor（虚拟机内，或裸机开着 VBS/HVCI），但嵌套模式没开。
        // 这一态是可以由用户自己解决的，所以必须与"不支持"分开报。
        NestedNotAllowed
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
        // hypervisorPresent：外层已有 hypervisor（虚拟机内，或裸机开着 VBS/HVCI）。
        bool hypervisorPresent = false;
        // nestedResident：当前常驻是作为 L1 跑在别人之下，属于降级模式。
        bool nestedResident = false;
        // veArmed：本次常驻武装了 EPT-violation #VE 控制位。
        // 注意语义：这只说明控制位是开的，不说明 #VE 能被投递——驱动侧
        // 的两道保险（全叶项 suppress-#VE、信息区锁 busy）与本位无关。
        bool veArmed = false;
        // veSuppressedByDefault：驱动确认它装的每个 EPT 叶项都带 suppress-#VE。
        // 这一位为假时不该武装 #VE，那意味着地基没铺好。
        bool veSuppressedByDefault = false;
        // vmFuncArmed：本次常驻武装了 VMFUNC，guest 可以自行切换 EPT 视图。
        bool vmFuncArmed = false;
        // eptpSwitchingAvailable：处理器提供 VM function 0，域才有意义。
        bool eptpSwitchingAvailable = false;
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

    // 嵌套模式开关：
    // - 默认关闭，裸机独占 VT-x 仍是预期的运行方式；
    // - 打开后 PREPARE/SELF_TEST/常驻 都会带上 ALLOW_NESTED，从而可以在虚拟机里
    //   或在开着 VBS 的机器上运行。代价是每条 VMX 操作都由外层 hypervisor 模拟，
    //   性能显著下降，可用能力也只剩外层愿意暴露的那部分；
    // - 这不是危险开关（不改写任何系统状态），所以与写权限门分开。
    bool isNestedAllowed();
    void setNestedAllowed(bool allowed);

    // #VE 开关（把 EPT violation 反射成 guest 的 #VE，向量 20）：
    // - 这里的 guest 就是正在跑的这台 Windows。它的 IDT[20] 没有 #VE 处理程序，
    //   真投递一次就是 #GP -> #DF -> triple fault，机器当场断电式重启；
    // - 驱动侧有两道与本开关无关的保险：每一个 EPT 叶项（含未映射区域的空槽）
    //   都带 suppress-#VE，每 CPU 的信息区在分配时就把 busy 锁死。两道都在时，
    //   哪怕控制位开着也投递不出 #VE，EPT violation 会退回成常规 VM-exit；
    // - 所以打开它得到的是「控制位已武装」，不是「#VE 已生效」。要真的收到
    //   #VE，还得先在 guest 里装好处理程序、清 busy、再把目标页显式设为可转换；
    // - 硬件不支持时驱动直接拒绝启动常驻，而不是静默降级——否则调用方会以为
    //   自己在测 #VE，其实测的是别的东西；
    // - 【不持久化】：每次启动客户端都必须重新打开。这是刻意的。
    bool isVeEnabled();
    void setVeEnabled(bool enabled);

    // VMFUNC 开关：
    // - 武装后 guest 用一条 VMFUNC 就能在 EPTP list 的域之间切换，不产生
    //   VM exit，驱动也收不到通知。VMFUNC 不做 CPL 检查，所以「guest」在这里
    //   包括任意进程的任意 ring 3 线程；
    // - 这不是提权路径：域只能被拿掉权限，切进去最坏是自己吃 EPT violation。
    //   但它确实是一个驱动观测不到的状态切换，值得单独一道门；
    // - 与 #VE 一样【不持久化】，重启客户端即回到关闭。
    bool isVmFuncEnabled();
    void setVmFuncEnabled(bool enabled);

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

    // KvmViewEntry：一条已安装的 EPT 分离视图。
    struct KvmViewEntry
    {
        unsigned long viewId = 0;
        unsigned long kind = 0;
        unsigned long flags = 0;
        unsigned long long physicalAddress = 0;
        unsigned long long shadowPhysicalAddress = 0;
        unsigned long long flipCount = 0;
    };

    // KvmViewShadowSeed：影子页初始内容的来源。
    enum class KvmViewShadowSeed
    {
        Zero,       // 全零：读取者看到一片空白。
        FromTarget, // 冻结目标页当前内容：读取者看到安装那一刻的样子。
        Explicit    // 使用调用方提供的整页内容。
    };

    // KvmViewResult：一次视图操作的结果。
    struct KvmViewResult
    {
        bool ok = false;
        unsigned long viewId = 0;
        unsigned long viewCount = 0;
        QVector<KvmViewEntry> views;
        QString message;
    };

    // listViews：读取已安装视图，不需要写权限。
    KvmViewResult listViews();

    // addView：安装一条视图。受写权限门约束。
    // shadow 只在 seed 为 Explicit 时使用，必须恰好是一页（4096 字节）。
    KvmViewResult addView(
        unsigned long kind,
        unsigned long long physicalAddress,
        KvmViewShadowSeed seed,
        const QByteArray& shadow);

    // removeView/clearViews：移除一条或全部视图。受写权限门约束。
    KvmViewResult removeView(unsigned long viewId);
    KvmViewResult clearViews();

    // KvmDomainEntry：EPTP list 里的一个槽位。
    struct KvmDomainEntry
    {
        unsigned long domainIndex = 0;
        bool active = false;
        // 该域从共享层次里分叉出去的页表数：0 表示与默认视图完全一致。
        unsigned long privateTableCount = 0;
        unsigned long long eptPointer = 0;
    };

    // KvmDomainResult：一次执行域操作的结果。
    struct KvmDomainResult
    {
        bool ok = false;
        unsigned long domainIndex = 0;
        unsigned long domainCount = 0;
        QVector<KvmDomainEntry> domains;
        QString message;
    };

    // 执行域（EPT execution domain）：
    // - 域发布在 EPTP list 里，guest 用一条 VMFUNC 就能切过去，而 VMFUNC 不做
    //   CPL 检查——任何 ring 3 线程都能切，不产生 VM exit，驱动也不会被通知；
    // - 所以接口只有「减权限」一个方向：域出生时与默认视图完全一致，之后只能
    //   被拿掉权限。切进域的线程结构性地拿不到它原本没有的访问权；
    // - 建好域本身不改变任何行为。要让 VMFUNC 真的可用，还得用带 ENABLE_VMFUNC
    //   的常驻启动，而那是另一个独立的开关。
    KvmDomainResult listDomains();
    KvmDomainResult createDomain();
    // restrictDomain：从一个域里拿掉某段物理范围的权限。
    // deniedAccess 用 KSWORD_ARK_HVM_EPT_ACCESS_* 位。拿掉读权限需要处理器
    // 支持 execute-only 翻译，否则驱动拒绝（那样的叶项会让 VM entry 失败）。
    KvmDomainResult restrictDomain(
        unsigned long domainIndex,
        unsigned long long physicalAddress,
        unsigned long long byteCount,
        unsigned long deniedAccess);
    KvmDomainResult resetDomains();

    // KvmMsrPolicyEntry：一条已安装的 MSR 策略。
    struct KvmMsrPolicyEntry
    {
        unsigned long policyId = 0;
        unsigned long msrIndex = 0;
        unsigned long access = 0;
        unsigned long action = 0;
        unsigned long long fakeValue = 0;
        unsigned long long hitCount = 0;
    };

    // KvmMsrPolicyResult：一次 MSR 策略操作的结果。
    struct KvmMsrPolicyResult
    {
        bool ok = false;
        unsigned long policyId = 0;
        unsigned long policyCount = 0;
        QVector<KvmMsrPolicyEntry> policies;
        QString message;
    };

    // listMsrPolicies：读取已安装策略，不需要写权限。
    KvmMsrPolicyResult listMsrPolicies();

    // addMsrPolicy：安装一条策略。受写权限门约束。
    // action 为 LOG 时不能带写方向：在 VMX root 里重放 WRMSR 没有安全退路。
    KvmMsrPolicyResult addMsrPolicy(
        unsigned long msrIndex,
        unsigned long access,
        unsigned long action,
        unsigned long long fakeValue);

    // removeMsrPolicy/clearMsrPolicies：移除一条或全部策略。受写权限门约束。
    KvmMsrPolicyResult removeMsrPolicy(unsigned long policyId);
    KvmMsrPolicyResult clearMsrPolicies();

    // KvmEventEntry：一条 HVM 事件。sequence 单调递增，用作消费游标。
    struct KvmEventEntry
    {
        unsigned long long sequence = 0;
        unsigned long long timestamp = 0;
        unsigned long long guestPhysicalAddress = 0;
        unsigned long long guestLinearAddress = 0;
        unsigned long long guestRip = 0;
        unsigned long long qualification = 0;
        unsigned short processorGroup = 0;
        unsigned char processorNumber = 0;
        unsigned long type = 0;
        unsigned long exitReason = 0;
        unsigned long access = 0;
        // ruleId 对 EPT 视图翻转承载的是 viewId：两者共用这一列。
        unsigned long ruleId = 0;
        long status = 0;
    };

    // KvmEventResult：一次事件读取的结果。
    struct KvmEventResult
    {
        bool ok = false;
        // droppedRows：本次快照中被覆盖或不可用的行数，非零说明消费跟不上。
        unsigned long droppedRows = 0;
        unsigned long availableRows = 0;
        unsigned long long newestSequence = 0;
        QVector<KvmEventEntry> events;
        QString message;
    };

    // readEvents：读取 afterSequence 之后的事件。只读，不需要写权限。
    // clear 为 true 时同时清空环，用于开始一次干净的观察。
    KvmEventResult readEvents(
        unsigned long long afterSequence,
        bool clear);

    // KvmCrPolicyResult：控制寄存器策略的当前配置与计数。
    struct KvmCrPolicyResult
    {
        bool ok = false;
        unsigned long long cr0PinnedMask = 0;
        unsigned long long cr4PinnedMask = 0;
        unsigned long long cr0PinnedValue = 0;
        unsigned long long cr4PinnedValue = 0;
        unsigned long long refusedWriteCount = 0;
        unsigned long long cr3SwitchCount = 0;
        unsigned long long debugAccessCount = 0;
        bool trackCr3 = false;
        bool interceptDr = false;
        bool log = false;
        QString message;
    };

    // readCrPolicy：读取当前配置与计数。只读。
    KvmCrPolicyResult readCrPolicy();

    // applyCrPolicy：设置钉住掩码与拦截开关。受写权限门约束。
    // 掩码与开关在建 VMCS 时消费，常驻期间驱动会拒绝改动。
    KvmCrPolicyResult applyCrPolicy(
        unsigned long long cr0PinnedMask,
        unsigned long long cr4PinnedMask,
        bool trackCr3,
        bool interceptDr,
        bool log);

    // clearCrPolicy：清除全部配置与计数。受写权限门约束。
    KvmCrPolicyResult clearCrPolicy();
}
