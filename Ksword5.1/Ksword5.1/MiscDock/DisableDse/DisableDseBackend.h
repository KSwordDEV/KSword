#pragma once

// ============================================================
// DisableDseBackend.h
// 作用：
// 1) 动态定位 CI.dll!g_CiOptions —— 驱动签名强制（DSE）的总开关；
// 2) 通过 KswordARK R0 事务化内核写把该值改成 0（关闭）或写回原值（恢复）；
// 3) 汇总 CI / HVCI / 安全启动姿态，判断这台机器上改 g_CiOptions 是否真的会生效；
// 4) 每次写入前拿读回值与系统自报姿态做一致性校验，对不上就拒绝落笔 ——
//    写错地址是这类工具蓝屏的首要原因。注意 g_CiOptions 用的是 CI.dll 内部编码
//    （0x6 = 强制签名，0x8 = 放行测试签名，0 = 关闭），和
//    SystemCodeIntegrityInformation 报告的 CODEINTEGRITY_OPTION_* 不是同一套，
//    两个数值本来就不相等，只能比对“强制签名是否生效”这个语义。
//
// 定位方式不依赖任何硬编码偏移：把磁盘上的 CI.dll 按 SEC_IMAGE 映射进本进程，
// 从导出的 CiInitialize 反汇编找到 CipInitialize，再在其中找
// `mov dword ptr [rip+disp32], r32`，该目标即 g_CiOptions；最后用内核里
// CI.dll 的真实基址把 RVA 换算成内核虚拟地址。
//
// 本文件只做数据与系统访问，不含任何 QWidget 依赖；UI 在 DisableDsePage 中。
// ============================================================

#include <QString>
#include <QStringList>

#include <cstdint>

namespace ks::misc::disable_dse
{
    // PostureSource：
    // - 作用：标记这份 CI 姿态是谁给出的，UI 据此说明数据来源。
    enum class PostureSource
    {
        None = 0,    // None：两条通道都没走通。
        Win32 = 1,   // Win32：R3 NtQuerySystemInformation 取到，字段较少。
        Driver = 2   // Driver：KswordARK R0 安全状态查询，字段最全。
    };

    // BlockReason：
    // - 作用：说明当前为什么不允许改 DSE；None 之外一律禁用操作按钮。
    enum class BlockReason
    {
        None = 0,               // None：允许操作。
        DriverUnavailable,      // DriverUnavailable：R0 没上线，g_CiOptions 只能内核写。
        UnsupportedBuild,       // UnsupportedBuild：早于 Win8，开关不在 CI.dll 里。
        HvciEnabled,            // HvciEnabled：内存完整性开着，写入会被 SLAT 拦下。
        NotLocated,             // NotLocated：还没定位到 g_CiOptions。
        ValueMismatch           // ValueMismatch：读回值与系统自报值不符，地址存疑。
    };

    // CodeIntegrityPosture：
    // - 作用：一次 CI / VBS 姿态查询的完整结果，是操作前的准入依据。
    struct CodeIntegrityPosture
    {
        bool queried = false;                          // queried：是否成功拿到姿态。
        PostureSource source = PostureSource::None;    // source：本次数据由谁给出。
        std::uint32_t options = 0;                     // options：CodeIntegrityOptions 原始位图。
        bool ciEnabled = false;                        // ciEnabled：KMCI（驱动签名强制）是否开启。
        bool testSigningEnabled = false;               // testSigningEnabled：测试签名模式是否开启。
        bool umciEnabled = false;                      // umciEnabled：用户态代码完整性是否开启。
        bool hvciEnabled = false;                      // hvciEnabled：HVCI/内存完整性是否开启。
        bool hvciStrictMode = false;                   // hvciStrictMode：HVCI 严格模式。
        bool secureBootEnabled = false;                // secureBootEnabled：安全启动是否开启，仅 R0 通道有值。
        bool ciModuleLoaded = false;                   // ciModuleLoaded：CI 模块是否在内核模块表里，仅 R0 通道有值。
        std::uint32_t buildNumber = 0;                 // buildNumber：当前系统内部版本号。
        QString failureText;                           // failureText：queried 为 false 时的失败原因。
    };

    // TargetLocation：
    // - 作用：g_CiOptions 的定位结果与定位轨迹；ok 为 false 时只有 failureText 有意义。
    struct TargetLocation
    {
        bool ok = false;                  // ok：是否定位成功。
        std::uint64_t kernelAddress = 0;  // kernelAddress：g_CiOptions 在内核里的虚拟地址。
        std::uint64_t moduleBase = 0;     // moduleBase：内核中 CI 模块的加载基址。
        std::uint32_t moduleSize = 0;     // moduleSize：内核中 CI 模块的映像大小。
        std::uint32_t rva = 0;            // rva：g_CiOptions 相对模块基址的偏移。
        std::uint32_t ciInitializeRva = 0;// ciInitializeRva：磁盘 CI.dll 导出 CiInitialize 的 RVA。
        QString moduleName;               // moduleName：内核模块表里的模块名。
        QString sectionName;              // sectionName：g_CiOptions 落在哪个节，正常是 CiPolicy 或 .data。
        QString matchedInstruction;       // matchedInstruction：定位到 g_CiOptions 的写入指令。
        QStringList traceLines;           // traceLines：定位每一步的取值，供用户核对。
        QString failureText;              // failureText：ok 为 false 时的失败原因。
    };

    // ReadbackResult：
    // - 作用：一次通过 R0 读取 g_CiOptions 的结果。
    struct ReadbackResult
    {
        bool ok = false;             // ok：是否读到。
        std::uint32_t value = 0;     // value：读到的 4 字节值。
        QString failureText;         // failureText：ok 为 false 时的失败原因。
    };

    // ApplyResult：
    // - 作用：一次 g_CiOptions 写入事务的结果。
    struct ApplyResult
    {
        bool ok = false;                    // ok：写入并复读校验都通过。
        std::uint32_t previousValue = 0;    // previousValue：写入前的值，恢复时要用。
        std::uint32_t writtenValue = 0;     // writtenValue：本次写入的值。
        std::uint64_t transactionId = 0;    // transactionId：R0 事务号，可在变更审计里查到。
        QStringList traceLines;             // traceLines：事务每一步的状态。
        QString detailText;                 // detailText：失败原因或成功补充说明。
    };

    // driverAvailable：
    // - 作用：探测 KswordARK 设备是否可打开；
    // - 返回：true 表示 R0 通道在线。
    bool driverAvailable();

    // queryPosture：
    // - 作用：查询当前 CI / HVCI / 安全启动姿态；优先走 R0（字段全），R0 不可用时回退 R3；
    // - 返回：CodeIntegrityPosture；queried 为 false 时看 failureText。
    CodeIntegrityPosture queryPosture();

    // evaluateBlockReason：
    // - 输入 posture：当前姿态；location：定位结果（可为未定位状态）；
    // - 作用：把“能不能动手”的判定集中到一处，UI 与写入路径共用同一判据；
    // - 返回：None 表示允许操作，其余值说明被什么挡住了。
    BlockReason evaluateBlockReason(
        const CodeIntegrityPosture& posture,
        const TargetLocation& location);

    // blockReasonText：
    // - 输入 reason：准入判定结果；
    // - 作用：给出面向用户的原因说明与下一步建议；
    // - 返回：单行文本；None 时返回空串。
    QString blockReasonText(BlockReason reason);

    // locateCiOptions：
    // - 作用：映射磁盘 CI.dll 求出 g_CiOptions 的 RVA，再用内核模块基址换算成内核地址；
    // - 返回：TargetLocation；全过程只读，不访问驱动，也不写任何内存。
    TargetLocation locateCiOptions();

    // readCiOptions：
    // - 输入 location：已定位的目标；
    // - 作用：通过 R0 内核虚拟地址读取该处 4 字节；
    // - 返回：ReadbackResult。驱动不在线时直接失败。
    ReadbackResult readCiOptions(const TargetLocation& location);

    // writeCiOptions：
    // - 输入 location：已定位的目标；expectedValue：调用方刚读到的当前值；desiredValue：要写入的新值；
    // - 作用：按 prepare → dry-run → commit → 复读的顺序走 R0 事务化内核写；
    //   expectedValue 会作为事务的 expected-before，R0 侧比对不上会直接拒绝提交；
    // - 返回：ApplyResult；ok 为 true 表示写入并复读一致。
    ApplyResult writeCiOptions(
        const TargetLocation& location,
        std::uint32_t expectedValue,
        std::uint32_t desiredValue);

    // describeOptions：
    // - 输入 options：SystemCodeIntegrityInformation 报告的 CodeIntegrityOptions 位图；
    // - 作用：按 CODEINTEGRITY_OPTION_* 把置位的标志拆成可读名字；
    // - 返回：形如 "ENABLED | UMCI_ENABLED" 的文本；无置位时返回 "0"。
    // 注意：这套编码只适用于系统自报值，不能拿来解释 g_CiOptions。
    QString describeOptions(std::uint32_t options);

    // describeCiOptions：
    // - 输入 value：从内核读回的 CI.dll!g_CiOptions 原始值；
    // - 作用：按 CI.dll 内部编码解释该值。它与 CODEINTEGRITY_OPTION_* 不是同一套：
    //   低位 0x6 表示驱动签名强制生效，0x8 表示放行测试签名，0 表示完全关闭；
    // - 返回：可读说明文本。
    QString describeCiOptions(std::uint32_t value);

    // ciOptionsAgreesWithPosture：
    // - 输入 value：从定位地址读回的 g_CiOptions；posture：系统自报姿态；
    // - 作用：写入前的可信度判据。由于两套编码不同，不能直接比较数值相等，
    //   只能比对“强制签名此刻是否生效”这一个语义：系统说 DSE 开着，
    //   读回值就必须带强制位；系统说 DSE 关着，读回值的强制位就必须是 0。
    //   地址若定位错了，落在无关内核数据上，几乎不可能恰好满足这个关系；
    // - 返回：true 表示读回值与系统姿态自洽，允许继续写入。
    bool ciOptionsAgreesWithPosture(
        std::uint32_t value,
        const CodeIntegrityPosture& posture);

    // kDisabledValue：
    // - 作用：关闭 DSE 时写入的值。0 表示代码完整性全部关闭。
    inline constexpr std::uint32_t kDisabledValue = 0U;

    // kCiOptionEnforceMask：
    // - 作用：g_CiOptions 里代表“强制驱动签名”的位组合（CI.dll 内部编码）。
    //   正常开启的系统这两位都置上，合起来就是社区常说的 6。
    inline constexpr std::uint32_t kCiOptionEnforceMask = 0x00000006U;

    // kCiOptionTestSign：
    // - 作用：g_CiOptions 里代表“放行测试签名”的位。
    inline constexpr std::uint32_t kCiOptionTestSign = 0x00000008U;
}
