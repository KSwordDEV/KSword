#pragma once

// ============================================================
// ksword/process/process.h
// 命名空间：ks::process
// 作用：
// - 封装进程枚举、进程详情、进程控制等 Win32 API；
// - 供 ProcessDock 等 UI 层直接调用；
// - 与项目解耦后可作为独立工具库复用。
// ============================================================

#include <cstdint> // std::uint32_t/std::uint64_t：PID、计数器、时间戳。
#include <string>  // std::string：跨层统一文本类型（UTF-8）。
#include <vector>  // std::vector：进程列表容器。

#include "../../../../shared/driver/KswordArkProcessIoctl.h" // R0 进程扩展字段常量。
#include "../../../../shared/driver/KswordArkDynDataIoctl.h" // R0 DynData 字段来源常量。
#include "../../../../shared/driver/KswordArkThreadIoctl.h"  // R0 线程扩展字段常量。

namespace ks::process
{
    // ProcessEnumStrategy：进程遍历策略。
    enum class ProcessEnumStrategy
    {
        SnapshotProcess32 = 0,   // CreateToolhelp32Snapshot + Process32First/Next。
        NtQuerySystemInfo = 1,   // NtQuerySystemInformation(SystemProcessInformation)。
        Auto = 2                 // 自动：优先 NtQuery，失败时回退 Snapshot。
    };

    // ProcessFeatureState：
    // - 作用：统一表达“需要额外查询才能得到”的三/四态开关字段（DEP、控制流保护、UAC 虚拟化等）；
    // - Unknown 表示尚未采集或查询失败，UI 层据此显示占位符而不是伪造“已禁用”。
    enum class ProcessFeatureState : std::uint32_t
    {
        Unknown = 0,     // 未采集或查询失败。
        NotAllowed,      // 该特性对目标进程不适用（例如 64 位进程不支持 UAC 虚拟化）。
        Disabled,        // 已关闭。
        Enabled,         // 已启用。
        EnabledPermanent // 已启用且不可更改（DEP 永久开启）。
    };

    // ProcessDpiAwarenessLevel：
    // - 作用：表达任务管理器“DPI 感知”列的取值；
    // - Unknown 表示尚未采集或目标进程拒绝查询，UI 据此显示占位符。
    enum class ProcessDpiAwarenessLevel : std::uint32_t
    {
        Unknown = 0,        // 未采集或查询失败。
        Unaware,            // 无法识别 DPI。
        SystemAware,        // 系统 DPI 感知。
        PerMonitorAware,    // 每监视器 DPI 感知。
        PerMonitorAwareV2,  // 每监视器 DPI 感知 V2。
        UnawareGdiScaled    // 无法识别（GDI 缩放）。
    };

    // ProcessDetailDemand：
    // - 作用：描述“本轮需要额外付出代价才能采集”的进程字段集合；
    // - 调用方式：ProcessDock 按当前可见列计算位图并下发，未请求的字段保持默认值；
    // - 目的：把任务管理器对齐列的采集成本限制在用户真正显示的列上，默认布局零额外开销。
    namespace ProcessDetailDemand
    {
        constexpr std::uint32_t None = 0x00000000U;              // 不采集任何按需字段。
        constexpr std::uint32_t GuiResources = 0x00000001U;      // GDI / USER 对象计数（动态，每轮变化）。
        constexpr std::uint32_t JobObject = 0x00000002U;         // 作业对象归属（静态）。
        constexpr std::uint32_t MitigationPolicy = 0x00000004U;  // 数据执行保护与控制流保护（静态）。
        constexpr std::uint32_t UacVirtualization = 0x00000008U; // 令牌 UAC 虚拟化状态（静态）。
        constexpr std::uint32_t FileDescription = 0x00000010U;   // 映像版本资源中的“说明”（静态，按路径缓存）。
        constexpr std::uint32_t OsContext = 0x00000020U;         // 映像清单 supportedOS（静态，按路径缓存）。
        constexpr std::uint32_t EnterpriseContext = 0x00000040U; // 企业上下文（WIP/EDP，静态）。
        constexpr std::uint32_t GpuMemory = 0x00000080U;         // GPU 专用/共享显存（动态，PDH 全局一次）。
        constexpr std::uint32_t GpuEngine = 0x00000100U;         // GPU 引擎名称（动态，PDH 全局一次）。
        constexpr std::uint32_t PackageName = 0x00000200U;        // UWP 程序包全名（静态）。
        constexpr std::uint32_t DpiAwareness = 0x00000400U;       // 进程 DPI 感知级别（静态）。

        // PerProcessHandleMask：需要对每个进程单独打开句柄才能采集的位集合。
        constexpr std::uint32_t PerProcessHandleMask =
            GuiResources | JobObject | MitigationPolicy | UacVirtualization |
            EnterpriseContext | PackageName | DpiAwareness;

        // ImageFileMask：只依赖映像文件、可按路径缓存的位集合。
        constexpr std::uint32_t ImageFileMask = FileDescription | OsContext;

        // GpuMask：由 PDH 全局采样一次即可覆盖所有进程的位集合。
        constexpr std::uint32_t GpuMask = GpuMemory | GpuEngine;
    }

    // ProcessPriorityLevel：进程优先级枚举（映射 Win32 PriorityClass）。
    enum class ProcessPriorityLevel
    {
        Idle = 0,
        BelowNormal,
        Normal,
        AboveNormal,
        High,
        Realtime
    };

    // TokenPrivilegeAction：令牌特权调整动作（用于 AdjustTokenPrivileges）。
    enum class TokenPrivilegeAction
    {
        Keep = 0,   // 保持当前状态，不调整。
        Enable,     // 启用该特权。
        Disable,    // 禁用该特权。
        Remove      // 从令牌中移除该特权（高风险）。
    };

    // TokenPrivilegeEdit：单个特权的调整请求。
    struct TokenPrivilegeEdit
    {
        std::string privilegeName;               // 例如 "SeDebugPrivilege"。
        TokenPrivilegeAction action = TokenPrivilegeAction::Keep;
    };

    // TokenPrivilegeState：目标进程令牌中单个特权的查询状态。
    enum class TokenPrivilegeState : std::uint32_t
    {
        Unknown = 0,    // 特权 LUID 查询失败，不能安全显示或调整。
        NotPresent,     // 目标令牌不包含该特权。
        Disabled,       // 目标令牌包含该特权，当前未启用。
        Enabled         // 目标令牌包含该特权，当前已启用。
    };

    // TokenPrivilegeInfo：统一供进程列表、详细信息页和 R0 回退路径使用的特权快照。
    struct TokenPrivilegeInfo
    {
        std::string privilegeName;                         // Windows SDK 定义的 Se*Privilege 名称。
        TokenPrivilegeState state = TokenPrivilegeState::Unknown;
        std::uint32_t attributes = 0;                      // TOKEN_PRIVILEGES 中的原始 Attributes。
        std::uint32_t luidLowPart = 0;                     // LookupPrivilegeValue 返回的 LUID 低 32 位。
        std::int32_t luidHighPart = 0;                     // LookupPrivilegeValue 返回的 LUID 高 32 位。
        bool luidKnown = false;                            // false 表示名称无法解析为 LUID。
    };

    struct TokenPrivilegeLuidEntry
    {
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        std::uint32_t attributes = 0;
    };

    // SecurityAttributesInput：CreateProcessW 两个 SECURITY_ATTRIBUTES 参数的输入镜像。
    struct SecurityAttributesInput
    {
        bool useValue = false;                   // false -> 传 nullptr。
        std::uint32_t nLength = 0;               // 0 表示实现层使用 sizeof(SECURITY_ATTRIBUTES)。
        std::uint64_t securityDescriptor = 0;    // 指针地址（0 表示 nullptr）。
        bool inheritHandle = false;              // bInheritHandle。
    };

    // StartupInfoInput：STARTUPINFOW 输入镜像（全部字段可由 UI 自定义）。
    struct StartupInfoInput
    {
        bool useValue = false;                   // false -> 传入默认零初始化的必填 STARTUPINFOW。
        std::uint32_t cb = 0;                    // 0 表示使用 sizeof(STARTUPINFOW)。
        std::string lpReserved;
        std::string lpDesktop;
        std::string lpTitle;
        std::uint32_t dwX = 0;
        std::uint32_t dwY = 0;
        std::uint32_t dwXSize = 0;
        std::uint32_t dwYSize = 0;
        std::uint32_t dwXCountChars = 0;
        std::uint32_t dwYCountChars = 0;
        std::uint32_t dwFillAttribute = 0;
        std::uint32_t dwFlags = 0;
        std::uint16_t wShowWindow = 0;
        std::uint16_t cbReserved2 = 0;
        std::uint64_t lpReserved2 = 0;
        std::uint64_t hStdInput = 0;
        std::uint64_t hStdOutput = 0;
        std::uint64_t hStdError = 0;
    };

    // ProcessInformationInput：保留的 PROCESS_INFORMATION 表单镜像。
    // CreateProcess* 将该结构作为输出缓冲区；实现层始终传递自己的零初始化缓冲区，
    // 因此这里的预填充字段不会作为 API 输入使用。
    struct ProcessInformationInput
    {
        bool useValue = false;                   // 与既有 UI/序列化兼容；不会省略必填输出缓冲区。
        std::uint64_t hProcess = 0;
        std::uint64_t hThread = 0;
        std::uint32_t dwProcessId = 0;
        std::uint32_t dwThreadId = 0;
    };

    // CreateProcessRequest：创建进程参数对象（覆盖 CreateProcessW 全部参数 + Token 扩展）。
    struct CreateProcessRequest
    {
        bool useApplicationName = false;         // false -> lpApplicationName 传 nullptr。
        std::string applicationName;
        bool useCommandLine = false;             // false -> lpCommandLine 传 nullptr。
        std::string commandLine;

        SecurityAttributesInput processAttributes;   // lpProcessAttributes。
        SecurityAttributesInput threadAttributes;    // lpThreadAttributes。

        bool inheritHandles = false;             // bInheritHandles。
        std::uint32_t creationFlags = 0;         // dwCreationFlags。

        bool useEnvironment = false;             // false -> lpEnvironment 传 nullptr。
        bool environmentUnicode = true;          // true 时自动附加 CREATE_UNICODE_ENVIRONMENT。
        std::vector<std::string> environmentEntries; // 每行一个 "KEY=VALUE"。

        bool useCurrentDirectory = false;        // false -> lpCurrentDirectory 传 nullptr。
        std::string currentDirectory;

        StartupInfoInput startupInfo;            // lpStartupInfo。
        ProcessInformationInput processInfo;     // lpProcessInformation。

        // tokenModeEnabled=false 时调用 CreateProcessW；
        // true 时执行 “打开 PID 令牌 + 可选调权 + CreateProcessAsUserW”。
        bool tokenModeEnabled = false;
        std::uint32_t tokenSourcePid = 0;
        std::uint32_t tokenDesiredAccess = 0;    // 0 表示实现层使用默认访问掩码。
        bool duplicatePrimaryToken = true;       // true 时先 DuplicateTokenEx(TokenPrimary)。
        std::vector<TokenPrivilegeEdit> tokenPrivilegeEdits;
    };

    // CreateProcessResult：创建进程结果快照（供 UI 反馈和日志输出）。
    struct CreateProcessResult
    {
        bool success = false;
        std::uint32_t win32Error = 0;
        std::string detailText;
        bool usedTokenPath = false;
        bool usedCreateProcessWithTokenFallback = false;
        bool processInfoAvailable = false;
        std::uint64_t hProcess = 0;             // 返回快照：后端已 CloseHandle，不可再用作有效句柄。
        std::uint64_t hThread = 0;              // 返回快照：后端已 CloseHandle，不可再用作有效句柄。
        std::uint32_t dwProcessId = 0;
        std::uint32_t dwThreadId = 0;
    };

    // SuspendedProcessLaunchFailure：进程定向监控创建挂起目标时的失败分类。
    // - 供 UI 区分“需要管理员”“无法降级令牌”和普通 CreateProcess 失败。
    enum class SuspendedProcessLaunchFailure
    {
        None = 0,
        InvalidArgument,
        AdministratorRequired,
        UnelevatedTokenUnavailable,
        CreateFailed
    };

    // SuspendedProcessLaunchRequest：进程定向监控的受控创建参数。
    // - imagePath：目标可执行文件绝对路径；
    // - argumentText：原样追加到命令行的可选参数；
    // - workingDirectory：目标进程工作目录，空值表示由 Windows 决定；
    // - runAsAdministrator：true 时要求调用方当前已提升，不发起 UAC；
    // - allowElevatedFallback：普通权限令牌不可用时，允许显式回退到当前提升令牌。
    struct SuspendedProcessLaunchRequest
    {
        std::string imagePath;
        std::string argumentText;
        std::string workingDirectory;
        bool runAsAdministrator = false;
        bool allowElevatedFallback = false;
    };

    // SuspendedProcessLaunchResult：受控挂起创建结果。
    // - initialThreadHandle 和 processHandle 都是有效 Win32 句柄快照，调用方必须关闭；
    // - 保留 processHandle 可让后续终止始终作用于创建时的同一进程对象，而非重新按 PID 查询。
    struct SuspendedProcessLaunchResult
    {
        bool success = false;
        SuspendedProcessLaunchFailure failure = SuspendedProcessLaunchFailure::None;
        std::uint32_t win32Error = 0;
        std::string detailText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint64_t processHandle = 0;
        std::uint64_t initialThreadHandle = 0;
        bool usedUnelevatedToken = false;
        bool usedElevatedFallback = false;
    };

    // ProcessRecord：单进程快照数据结构。
    struct ProcessRecord
    {
        std::uint32_t pid = 0;             // 进程 ID。
        std::uint32_t parentPid = 0;       // 父进程 ID。
        std::uint32_t threadCount = 0;     // 线程数量（快照时刻统计）。
        std::uint32_t handleCount = 0;     // 句柄数量（快照时刻统计，部分策略可得）。
        std::uint32_t sessionId = 0;       // 会话 ID（用于区分登录会话）。

        // creationTime100ns：
        // - 进程创建时间（FILETIME 100ns 基准）；
        // - 与 PID 共同构成稳定 identity（用于“复用旧数据”规则）。
        std::uint64_t creationTime100ns = 0;

        std::string processName;           // 进程名（显示名）。
        std::string imagePath;             // 可执行文件完整路径。
        std::string commandLine;           // 启动参数（命令行）。
        std::string userName;              // 进程令牌用户（DOMAIN\\User）。
        // signatureState：用于 UI 直接显示的签名文本。
        // 典型值：
        // - "Microsoft Corporation (Trusted)"
        // - "Unknown Publisher (Untrusted)"
        // - "Unsigned"
        // - "Pending"
        std::string signatureState;
        std::string signaturePublisher;    // 签名发布者（厂家）名称。
        bool signatureTrusted = false;     // 是否被 Windows 信任链验证通过。
        std::string startTimeText;         // 启动时间文本（YYYY-MM-DD HH:MM:SS）。
        std::string architectureText;      // 架构文本（x64/x86/ARM/Unknown）。
        std::string priorityText;          // 优先级文本（Normal/High/...）。
        bool efficiencyModeSupported = false; // 是否成功查询效率模式状态。
        bool efficiencyModeEnabled = false;   // 是否启用效率模式（PowerThrottling ExecutionSpeed）。
        bool isAdmin = false;              // 进程令牌是否已提升（管理员权限）。
        std::uint32_t protectionLevel = 0;  // PPL 保护级别枚举值，来自手动刷新快照。
        bool protectionLevelKnown = false;  // protectionLevelKnown：true 表示本轮已手动查询 PPL。
        std::string protectionLevelText;    // protectionLevelText：PPL 枚举文本，未刷新时保持空。

        // ======== 原始性能计数器（用于相邻两轮差值计算） ========
        std::uint64_t rawCpuTime100ns = 0;      // Kernel + User 总 CPU 时间（100ns）。
        std::uint64_t rawWorkingSetBytes = 0;   // 工作集内存字节数。
        std::uint64_t rawPrivateBytes = 0;      // 私有提交/申请内存字节数。
        std::uint64_t rawIoBytes = 0;           // Read/Write/Other 传输累计字节。

        // ======== UI 直接显示的衍生性能数据 ========
        double cpuPercent = 0.0;           // CPU 百分比（相对全部逻辑处理器归一化，0~100）。
        double cpuCorePercent = 0.0;       // CPU 单核等效百分比（100%=一个逻辑处理器，可超过 100）。
        double ramMB = 0.0;                // RAM 申请内存（MB，优先 PrivateUsage）。
        double workingSetMB = 0.0;         // RAM 实际使用工作集（MB）。
        double diskMBps = 0.0;             // 磁盘吞吐（MB/s）。
        double gpuPercent = 0.0;           // GPU 百分比（R3 通过 PDH GPU Engine 按 PID 聚合）。
        double netKBps = 0.0;              // 网络总吞吐（KB/s，等于下行 + 上行）。
        double netRxKBps = 0.0;            // 网络下行吞吐（KB/s，由进程页抓包聚合写入）。
        double netTxKBps = 0.0;            // 网络上行吞吐（KB/s，由进程页抓包聚合写入）。

        bool staticDetailsReady = false;   // true 表示详情字段已完整填充。
        bool dynamicCountersReady = false; // true 表示性能计数器可用。

        // ======== 任务管理器“详细信息”页对齐字段 ========
        // 采集分层说明：
        // - 本段前半部分（调度/内存/IO）来自 NtQuerySystemInformation 或 GetProcessMemoryInfo，
        //   属于枚举时顺带得到的零额外开销数据，始终填充；
        // - 本段后半部分（GUI 资源、作业、缓解策略、映像说明、GPU 显存等）需要额外句柄或解析，
        //   仅在 ProcessDock 通过 ProcessDetailDemand 位图请求时才采集，未请求时保持默认值。

        // -------- 运行状态 --------
        std::uint32_t suspendedThreadCount = 0; // 处于 Suspended 等待状态的线程数量。
        bool processSuspended = false;          // true 表示全部线程均被挂起（任务管理器“已挂起”）。
        bool processStateKnown = false;         // true 表示本轮成功判定了运行/挂起状态。

        // -------- 调度 --------
        std::int32_t basePriority = 0;      // 基础优先级数值（0~31），任务管理器“基本优先级”。
        std::uint64_t cycleTime = 0;        // 累计 CPU 周期数，任务管理器“周期”。
        bool cycleTimeKnown = false;        // true 表示 cycleTime 有效（部分枚举路径拿不到）。

        // -------- 内存 --------
        std::uint64_t peakWorkingSetBytes = 0;    // 峰值工作集字节数。
        std::uint64_t privateWorkingSetBytes = 0; // 专用工作集字节数（WorkingSetPrivateSize）。
        std::uint64_t sharedWorkingSetBytes = 0;  // 共享工作集字节数（工作集 - 专用工作集，派生值）。
        // activePrivateWorkingSetBytes：
        // - 任务管理器“内存(活动的专用工作集)”列；
        // - 语义是“专用工作集中仍处于活动状态的部分”，被冻结/挂起的进程为 0；
        // - 由 privateWorkingSetBytes 与挂起状态派生，不额外查询。
        std::uint64_t activePrivateWorkingSetBytes = 0;
        std::uint64_t commitSizeBytes = 0;        // 提交大小（PagefileUsage）。
        std::uint64_t peakCommitSizeBytes = 0;    // 峰值提交大小（PeakPagefileUsage）。
        std::uint64_t pagedPoolBytes = 0;         // 分页缓冲池配额用量。
        std::uint64_t nonPagedPoolBytes = 0;      // 非分页缓冲池配额用量。
        std::uint64_t pageFaultCount = 0;         // 累计页面错误次数。
        std::uint64_t hardFaultCount = 0;         // 累计硬页面错误次数（NtQuery 专有）。
        std::int64_t workingSetDeltaBytes = 0;    // 相邻两轮工作集增量（可为负）。
        std::int64_t pageFaultDeltaCount = 0;     // 相邻两轮页面错误增量（可为负，PID 复用时兜底）。
        bool memoryDetailKnown = false;           // true 表示上面这组内存字段本轮已成功填充。
        bool privateWorkingSetKnown = false;      // true 表示专用/共享工作集可用（仅 NtQuery 路径提供）。

        // -------- I/O 计数 --------
        std::uint64_t ioReadOperationCount = 0;  // I/O 读取次数。
        std::uint64_t ioWriteOperationCount = 0; // I/O 写入次数。
        std::uint64_t ioOtherOperationCount = 0; // I/O 其他次数。
        std::uint64_t ioReadTransferBytes = 0;   // I/O 读取字节数。
        std::uint64_t ioWriteTransferBytes = 0;  // I/O 写入字节数。
        std::uint64_t ioOtherTransferBytes = 0;  // I/O 其他字节数。
        bool ioDetailKnown = false;              // true 表示上面这组 I/O 字段本轮已成功填充。

        // -------- GUI 资源（按需：ProcessDetailDemand::GuiResources） --------
        std::uint32_t gdiObjectCount = 0;  // GDI 对象数量。
        std::uint32_t userObjectCount = 0; // 用户对象数量。
        bool guiResourceKnown = false;     // true 表示 GetGuiResources 查询成功。

        // -------- 作业对象（按需：ProcessDetailDemand::JobObject） --------
        bool inJobObject = false;    // true 表示进程归属某个作业对象。
        bool jobObjectKnown = false; // true 表示作业归属查询成功。

        // -------- 安全与缓解策略（按需） --------
        ProcessFeatureState uacVirtualizationState = ProcessFeatureState::Unknown;  // UAC 虚拟化。
        ProcessFeatureState dataExecutionPreventionState = ProcessFeatureState::Unknown; // 数据执行保护。
        ProcessFeatureState controlFlowGuardState = ProcessFeatureState::Unknown;   // 控制流保护。
        // hardwareStackProtectionState：
        // - 任务管理器“硬件强制实施的堆栈保护”列；
        // - 数据来源为 ProcessUserShadowStackPolicy 的 EnableUserShadowStack（Intel CET 影子栈）。
        ProcessFeatureState hardwareStackProtectionState = ProcessFeatureState::Unknown;
        // dpiAwarenessLevel：任务管理器“DPI 感知”列。
        ProcessDpiAwarenessLevel dpiAwarenessLevel = ProcessDpiAwarenessLevel::Unknown;

        // -------- 映像描述（按需） --------
        std::string packageFullName;      // UWP 程序包全名，任务管理器“程序包名称”；非打包进程为空。
        bool packageNameKnown = false;    // true 表示已成功判定是否属于某个程序包。
        std::string fileDescription;      // 映像版本资源 FileDescription，任务管理器“描述”。
        std::string osContextText;        // 映像清单 supportedOS 映射出的系统名，任务管理器“操作系统上下文”。
        std::string enterpriseContextText;// 企业上下文（WIP/EDP）；未启用时为“个人”。

        // -------- GPU 扩展（按需：ProcessDetailDemand::GpuMemory / GpuEngine） --------
        std::uint64_t gpuDedicatedMemoryBytes = 0; // 专用 GPU 内存字节数。
        std::uint64_t gpuSharedMemoryBytes = 0;    // 共享 GPU 内存字节数。
        bool gpuMemoryKnown = false;               // true 表示本轮取到 GPU 显存计数器。
        std::string gpuEngineText;                 // 占用最高的 GPU 引擎名称，例如 "GPU 0 - 3D"。

        // ======== R0 / EPROCESS 扩展信息（Phase 2） ========
        std::uint32_t r0Flags = 0;          // R0 枚举行原始 flags，例如隐藏进程标记。
        std::uint32_t r0FieldFlags = 0;     // KSWORD_ARK_PROCESS_FIELD_* 可用性位图。
        std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE; // R0 扩展读取状态。
        std::uint64_t r0DynDataCapabilityMask = 0; // 驱动 DynData capability 位图快照。
        std::string r0ImagePath;            // R0 通过公开 API 返回的镜像路径（通常是 NT 路径）。

        std::uint8_t r0Protection = 0;      // EPROCESS.Protection 原始字节。
        std::uint8_t r0SignatureLevel = 0;  // EPROCESS.SignatureLevel 原始字节。
        std::uint8_t r0SectionSignatureLevel = 0; // EPROCESS.SectionSignatureLevel 原始字节。

        std::uint32_t r0SessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // Session 字段来源。
        std::uint32_t r0ImagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // 镜像路径来源。
        std::uint32_t r0ProtectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // Protection 来源。
        std::uint32_t r0SignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // SignatureLevel 来源。
        std::uint32_t r0SectionSignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // SectionSignatureLevel 来源。
        std::uint32_t r0ObjectTableSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // ObjectTable 来源。
        std::uint32_t r0SectionObjectSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // SectionObject 来源。

        std::uint32_t r0ProtectionOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.Protection 偏移。
        std::uint32_t r0SignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.SignatureLevel 偏移。
        std::uint32_t r0SectionSignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.SectionSignatureLevel 偏移。
        std::uint32_t r0ObjectTableOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.ObjectTable 偏移。
        std::uint32_t r0SectionObjectOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.SectionObject 偏移。
        std::uint64_t r0ObjectTableAddress = 0; // EPROCESS.ObjectTable 当前指针值。
        std::uint64_t r0SectionObjectAddress = 0; // EPROCESS.SectionObject 当前指针值。
    };

    // ProcessModuleRecord：进程模块列表中的单行数据。
    struct ProcessModuleRecord
    {
        std::string modulePath;                // 模块完整路径。
        std::string moduleName;                // 模块名（文件名）。
        std::uint64_t moduleBaseAddress = 0;   // 模块加载基址。
        std::uint32_t moduleSizeBytes = 0;     // 模块映像大小（字节）。
        // 模块签名显示文本与发布者/可信标记，语义与 ProcessRecord 对齐。
        std::string signatureState;            // 模块签名显示文本。
        std::string signaturePublisher;        // 模块签名发布者（厂家）。
        bool signatureTrusted = false;         // 模块签名是否受 Windows 信任。
        std::uint32_t entryPointRva = 0;       // 入口点 RVA（相对偏移）。
        std::string runningState;              // 运行状态文本（Loaded/Unknown）。
        std::uint32_t representativeThreadId = 0; // 代表线程 ID（用于线程操作快捷入口）。
        std::uint64_t representativeThreadCreationTime100ns = 0; // 代表线程创建时间（用于身份校验）。
        std::string threadIdText;              // 线程 ID 汇总文本（逗号分隔）。
    };

    // ProcessThreadRecord：进程线程列表中的单线程数据。
    struct ProcessThreadRecord
    {
        std::uint32_t threadId = 0;        // 线程 ID。
        std::uint32_t ownerPid = 0;        // 所属进程 PID。
        int basePriority = 0;              // 线程基础优先级。
        std::string stateText;             // 线程状态文本（Running/Unknown）。
    };

    // SystemThreadRecord：系统全量线程快照中的单线程数据。
    struct SystemThreadRecord
    {
        std::uint32_t threadId = 0;            // 线程 ID（TID）。
        std::uint32_t ownerPid = 0;            // 所属进程 PID。
        std::string ownerProcessName;          // 所属进程名称（用于列表展示）。
        std::uint64_t startAddress = 0;        // 线程启动地址（内核返回的指针值）。
        int priority = 0;                      // 当前动态优先级。
        int basePriority = 0;                  // 基础优先级。
        std::uint32_t threadState = 0;         // 线程状态码（KTHREAD_STATE 数值）。
        std::uint32_t waitReason = 0;          // 等待原因码（KWAIT_REASON 数值）。
        std::uint64_t kernelTime100ns = 0;     // 内核态累计时间（100ns）。
        std::uint64_t userTime100ns = 0;       // 用户态累计时间（100ns）。
        std::uint64_t createTime100ns = 0;     // 创建时间（FILETIME 100ns）。
        std::uint32_t waitTimeTick = 0;        // 等待时长计数（Nt 原始字段）。
        std::uint32_t contextSwitchCount = 0;  // 上下文切换次数（Nt 原始字段）。
        std::uint64_t stackBase = 0;           // R3 SystemExtendedProcessInformation 返回的用户栈基址。
        std::uint64_t stackLimit = 0;          // R3 SystemExtendedProcessInformation 返回的用户栈边界。
        std::uint64_t win32StartAddress = 0;   // R3 SystemExtendedProcessInformation 返回的 Win32StartAddress。
        std::uint64_t tebBaseAddress = 0;      // R3 SystemExtendedProcessInformation 返回的 TEB 基址。
        std::uint32_t r0ThreadFlags = 0;        // KSWORD_ARK_THREAD_FLAG_* cross-view 标记。
        bool isR0OnlyThread = false;            // true 表示 R3 线程快照缺失但 R0/CID 视图可见。
        std::uint32_t r0ThreadFieldFlags = 0;  // KSWORD_ARK_THREAD_FIELD_* 可用性位图。
        std::uint32_t r0ThreadStatus = KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE; // R0 KTHREAD 扩展状态。
        std::uint32_t r0StackFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE; // KTHREAD 栈字段来源。
        std::uint32_t r0IoFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;    // KTHREAD I/O counter 来源。
        std::uint64_t r0InitialStack = 0;      // KTHREAD.InitialStack。
        std::uint64_t r0StackLimit = 0;        // KTHREAD.StackLimit。
        std::uint64_t r0StackBase = 0;         // KTHREAD.StackBase。
        std::uint64_t r0KernelStack = 0;       // KTHREAD.KernelStack。
        std::uint64_t r0ReadOperationCount = 0; // KTHREAD ReadOperationCount。
        std::uint64_t r0WriteOperationCount = 0; // KTHREAD WriteOperationCount。
        std::uint64_t r0OtherOperationCount = 0; // KTHREAD OtherOperationCount。
        std::uint64_t r0ReadTransferCount = 0; // KTHREAD ReadTransferCount。
        std::uint64_t r0WriteTransferCount = 0; // KTHREAD WriteTransferCount。
        std::uint64_t r0OtherTransferCount = 0; // KTHREAD OtherTransferCount。
        std::uint32_t r0KtInitialStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtInitialStack 偏移。
        std::uint32_t r0KtStackLimitOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;   // DynData KtStackLimit 偏移。
        std::uint32_t r0KtStackBaseOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;    // DynData KtStackBase 偏移。
        std::uint32_t r0KtKernelStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;  // DynData KtKernelStack 偏移。
        std::uint32_t r0KtReadOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtReadOperationCount 偏移。
        std::uint32_t r0KtWriteOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtWriteOperationCount 偏移。
        std::uint32_t r0KtOtherOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtOtherOperationCount 偏移。
        std::uint32_t r0KtReadTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;   // DynData KtReadTransferCount 偏移。
        std::uint32_t r0KtWriteTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;  // DynData KtWriteTransferCount 偏移。
        std::uint32_t r0KtOtherTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;  // DynData KtOtherTransferCount 偏移。
        std::uint64_t r0ThreadDynDataCapabilityMask = 0; // 驱动 DynData capability 位图快照。
        double cpuPercent = 0.0;            // 相邻快照线程 CPU 单核占用（0~100）。
        bool cpuUsageReady = false;         // false 表示尚无同一线程实例的上一轮基准。
    };

    // ProcessModuleSnapshot：模块页签所需快照数据（模块 + 线程）。
    struct ProcessModuleSnapshot
    {
        std::vector<ProcessModuleRecord> modules; // 模块列表。
        std::vector<ProcessThreadRecord> threads; // 线程列表。
        std::string diagnosticText;              // 刷新诊断文本（失败原因/回退路径）。
    };

    // CounterSample：用于跨刷新轮次计算差值的历史样本。
    struct CounterSample
    {
        std::uint64_t cpuTime100ns = 0;    // 上一轮 CPU 累计值。
        std::uint64_t ioBytes = 0;         // 上一轮 IO 累计值。
        std::uint64_t networkRxBytes = 0;  // 上一轮按 PID 聚合的网络下行累计字节。
        std::uint64_t networkTxBytes = 0;  // 上一轮按 PID 聚合的网络上行累计字节。
        std::uint64_t sampleTick100ns = 0; // 采样时刻（steady_clock 转 100ns）。
        std::uint64_t workingSetBytes = 0; // 上一轮工作集字节数，用于“工作集增量”列。
        std::uint64_t pageFaultCount = 0;  // 上一轮累计页面错误次数，用于“页面错误增量”列。
        bool hasMemoryBaseline = false;    // true 表示上面两个基准值有效（首轮采样时为 false）。
    };

    // ThreadCounterSample：按 PID/TID/创建时间保存线程 CPU 差分基准。
    struct ThreadCounterSample
    {
        std::uint64_t cpuTime100ns = 0;    // 上一轮 Kernel + User 累计时间。
        std::uint64_t sampleTick100ns = 0; // 上一轮单调时钟采样点。
    };

    // BuildProcessIdentityKey 作用：
    // - 使用 “PID + 创建时间” 生成稳定 identity 字符串；
    // - 用于判断“是否同一个进程实例”。
    std::string BuildProcessIdentityKey(std::uint32_t pid, std::uint64_t creationTime100ns);

    // BuildThreadIdentityKey：使用 PID + TID + 创建时间生成线程实例稳定标识。
    std::string BuildThreadIdentityKey(
        std::uint32_t pid,
        std::uint32_t threadId,
        std::uint64_t creationTime100ns);

    // UpdateThreadCpuUsage：按相邻累计 Kernel/User 时间计算线程单核占用。
    void UpdateThreadCpuUsage(
        SystemThreadRecord& threadRecord,
        const ThreadCounterSample* previousSample,
        ThreadCounterSample& nextSampleOut,
        std::uint32_t logicalCpuCount,
        std::uint64_t currentTick100ns);

    // EnumerateProcesses 作用：
    // - 按策略返回当前系统进程列表（含基础性能计数器）；
    // - 不保证每条记录都含完整静态详情。
    // 参数 strategy：枚举策略。
    // 参数 actualStrategyOut：
    // - 可选输出参数；
    // - 返回实际执行的枚举策略（例如 Auto 可能回退到 Snapshot）。
    // 参数 detailDemandFlags：
    // - ProcessDetailDemand 位图；仅影响“需要额外采样”的字段（当前为 GPU 显存/引擎）；
    // - 传 None 时行为与旧版完全一致，不产生额外 PDH 查询。
    std::vector<ProcessRecord> EnumerateProcesses(
        ProcessEnumStrategy strategy,
        ProcessEnumStrategy* actualStrategyOut = nullptr,
        std::uint32_t detailDemandFlags = ProcessDetailDemand::None);

    // EnumerateSystemThreads 作用：
    // - 枚举当前系统全部线程（优先 NtQuerySystemInformation）；
    // - 当 Nt 路径不可用时自动回退 Toolhelp 快照。
    // 参数 usedNtQueryOut：
    // - 可选输出参数；
    // - true 表示使用了 NtQuerySystemInformation，false 表示回退 Toolhelp。
    // 参数 diagnosticTextOut：
    // - 可选输出参数；
    // - 返回本轮枚举的路径说明或失败原因，便于 UI 诊断展示。
    std::vector<SystemThreadRecord> EnumerateSystemThreads(
        bool* usedNtQueryOut = nullptr,
        std::string* diagnosticTextOut = nullptr);

    // FillProcessStaticDetails 作用：
    // - 填充路径、命令行、用户、签名、管理员等“相对静态”字段；
    // - 通常只对“新出现进程”调用一次。
    // 参数 processRecord：目标记录（按引用修改）。
    // 参数 includeSignatureCheck：
    // - true：执行 WinVerifyTrust 做签名校验（较慢）；
    // - false：跳过签名校验，仅填充基础静态信息（快速模式）。
    // 返回值：true 成功；false 表示部分字段无法获取。
    bool FillProcessStaticDetails(ProcessRecord& processRecord, bool includeSignatureCheck = true);

    // FillProcessOnDemandDetails 作用：
    // - 采集任务管理器对齐列中“需要额外句柄或额外解析”的字段；
    // - 每一位只在 ProcessDock 判定对应列可见时才置位，未请求的字段完全跳过查询。
    // 参数 processRecord：目标记录（按引用修改）。
    // 参数 detailDemandFlags：ProcessDetailDemand 位图。
    // 参数 resolvedFlagsOut：
    // - 可选输出参数；返回本次“确实采集成功”的位；
    // - 调用方据此把生命周期内不变的字段标记为已完成，避免每轮重复查询，
    //   同时让被拒绝的进程在后续轮次继续重试。
    // 返回值：
    // - true 表示至少有一项被请求的字段采集成功；
    // - false 表示目标进程无法打开或全部请求项均失败，调用方可据此保留占位显示。
    bool FillProcessOnDemandDetails(
        ProcessRecord& processRecord,
        std::uint32_t detailDemandFlags,
        std::uint32_t* resolvedFlagsOut = nullptr);

    // ProcessDetailDemandForImageFileCacheClear 作用：
    // - 清空“按映像路径缓存”的说明/操作系统上下文结果；
    // - 供长时间运行后主动释放缓存，或在磁盘上的映像被替换后强制重新解析。
    // 参数：无。
    // 返回值：无。
    void ClearProcessImageDescriptionCache();

    // RefreshProcessDynamicCounters 作用：
    // - 刷新 CPU 原始时间、RAM 工作集、IO 累计值等动态字段；
    // - 支持 Snapshot 路径下补齐性能计数器。
    // 参数 processRecord：目标记录（按引用修改）。
    // 返回值：true 成功；false 表示无法获取动态计数器。
    bool RefreshProcessDynamicCounters(ProcessRecord& processRecord);

    // QueryProcessProtectionLevelByPid 作用：
    // - 通过用户态 ProcessProtectionLevelInfo 查询目标进程 PPL 枚举；
    // - 该值为手动刷新字段，ProcessDock 不把它写入跨轮静态缓存。
    // 参数 pid：目标进程 PID。
    // 参数 levelOut：输出 PROTECTION_LEVEL_* 原始枚举值，可为空。
    // 参数 displayTextOut：输出可读文本，可为空。
    // 参数 errorMessageOut：失败原因，可为空。
    // 返回值：查询成功返回 true，失败返回 false。
    bool QueryProcessProtectionLevelByPid(
        std::uint32_t pid,
        std::uint32_t* levelOut,
        std::string* displayTextOut,
        std::string* errorMessageOut = nullptr);

    // UpdateDerivedCounters 作用：
    // - 根据“上一轮样本 + 当前原始计数器”计算 CPU%、DiskMB/s；
    // - GPU 由枚举阶段的 PDH GPU Engine 采样写入，本函数只保留该值；
    // - Net 由 ProcessDock 的抓包聚合逻辑在本函数返回后写入，非进程页调用保持 0。
    // 参数 processRecord：目标记录（按引用写入衍生值）。
    // 参数 previousSample：上一轮样本（可空）。
    // 参数 nextSampleOut：输出下一轮样本。
    // 参数 logicalCpuCount：逻辑处理器数量（CPU 百分比折算用）。
    // 参数 currentTick100ns：当前采样时刻（100ns）。
    void UpdateDerivedCounters(
        ProcessRecord& processRecord,
        const CounterSample* previousSample,
        CounterSample& nextSampleOut,
        std::uint32_t logicalCpuCount,
        std::uint64_t currentTick100ns);

    // GetProcessNameByPID 作用：按 PID 读取进程名（失败返回空串）。
    std::string GetProcessNameByPID(std::uint32_t pid);

    // QueryProcessCreationTimeByPid 作用：
    // - 读取目标 PID 当前进程实例的 FILETIME 创建时间；
    // - 调用方式：历史事件保存 identity 或跳转前检查 PID 是否已复用；
    // - 入参 pid：目标进程 PID；
    // - 出参 creationTime100nsOut：成功时返回非零的 100ns 创建时间；
    // - 出参 detailTextOut：失败时返回 Win32 诊断信息，可为空；
    // - 返回：成功读取创建时间为 true，否则为 false。
    bool QueryProcessCreationTimeByPid(
        std::uint32_t pid,
        std::uint64_t* creationTime100nsOut,
        std::string* detailTextOut = nullptr);

    // QueryProcessPathByPid 作用：按 PID 读取可执行路径（失败返回空串）。
    std::string QueryProcessPathByPid(std::uint32_t pid);

    // ExecuteTaskKill 作用：执行 taskkill 结束进程（可选 /F）。
    bool ExecuteTaskKill(std::uint32_t pid, bool forceKill, std::string* errorMessage);

    // TerminateProcessByWin32 作用：调用 TerminateProcess 结束进程。
    bool TerminateProcessByWin32(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByWin32IfCreationTimeMatches：
    // - 仅在 PID 和创建时间仍指向同一进程实例时调用 TerminateProcess；
    // - 校验与终止共用一个持有的进程句柄，避免 PID 复用的 TOCTOU 误操作。
    bool TerminateProcessByWin32IfCreationTimeMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);

    // TerminateProcessByNtNative 作用：
    // - 调用 NtTerminateProcess / ZwTerminateProcess 结束进程。
    bool TerminateProcessByNtNative(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByWtsApi 作用：
    // - 调用 WTSTerminateProcess（WTS API）结束进程。
    bool TerminateProcessByWtsApi(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByWinStationApi 作用：
    // - 调用 WinStationTerminateProcess（winsta 接口）结束进程。
    bool TerminateProcessByWinStationApi(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByJobObject 作用：
    // - 创建临时 Job，把目标进程加入后调用 TerminateJobObject 结束。
    bool TerminateProcessByJobObject(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByNtJobObject 作用：
    // - 创建临时 Job，把目标进程加入后调用 NtTerminateJobObject 结束。
    bool TerminateProcessByNtJobObject(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByRestartManager 作用：
    // - 通过 Restart Manager 注册目标进程并调用 RmShutdown；
    // - forceShutdown=true 时使用强制关闭选项。
    bool TerminateProcessByRestartManager(
        std::uint32_t pid,
        bool forceShutdown,
        std::string* errorMessage);

    // TerminateProcessByDuplicateHandlePseudo 作用：
    // - 以 PROCESS_DUP_HANDLE 打开目标进程；
    // - 复制目标进程伪句柄(-1)到当前进程后调用 TerminateProcess。
    bool TerminateProcessByDuplicateHandlePseudo(std::uint32_t pid, std::string* errorMessage);

    // TerminateAllThreadsByPid 作用：枚举并 TerminateThread 结束该进程全部线程。
    bool TerminateAllThreadsByPid(std::uint32_t pid, std::string* errorMessage);

    // TerminateAllThreadsByPidNtNative 作用：
    // - 枚举目标进程全部线程并调用 NtTerminateThread / ZwTerminateThread。
    bool TerminateAllThreadsByPidNtNative(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByNtUnmapNtdll 作用：
    // - 以 PROCESS_VM_OPERATION 打开目标进程；
    // - 定位并调用 NtUnmapViewOfSection 卸载其 ntdll.dll 映射（高风险）。
    bool TerminateProcessByNtUnmapNtdll(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByDebugAttach 作用：
    // - 通过 DebugActiveProcess 附加调试目标；
    // - 可作为调试器攻击链路的一环（不保证立即终止）。
    bool TerminateProcessByDebugAttach(std::uint32_t pid, std::string* errorMessage);

    // TerminateProcessByNtsdCommand 作用：
    // - 调用 ntsd 命令行附加并立即退出（`ntsd -c q -p <pid>`）；
    // - 作为调试器攻击链路的外部工具方式。
    bool TerminateProcessByNtsdCommand(std::uint32_t pid, std::string* errorMessage);

    // InjectInvalidShellcode 作用：远程分配并执行无效 shellcode（实验性高风险操作）。
    bool InjectInvalidShellcode(std::uint32_t pid, std::string* errorMessage);

    // SuspendProcess 作用：暂停进程（NtSuspendProcess）。
    bool SuspendProcess(std::uint32_t pid, std::string* errorMessage);

    // ResumeProcess 作用：恢复进程（NtResumeProcess）。
    bool ResumeProcess(std::uint32_t pid, std::string* errorMessage);

    // SuspendProcessIfCreationTimeMatches / ResumeProcessIfCreationTimeMatches：
    // - 先在同一进程句柄上核对 PID 对应实例的创建时间；
    // - 身份变化时拒绝动作，避免 PID 回收后影响无关进程。
    bool SuspendProcessIfCreationTimeMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    bool ResumeProcessIfCreationTimeMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);

    // SetProcessCriticalFlag 作用：设置/取消关键进程标记（NtSetInformationProcess）。
    bool SetProcessCriticalFlag(std::uint32_t pid, bool enableCritical, std::string* errorMessage);

    // SetProcessPriority 作用：设置进程优先级（SetPriorityClass）。
    bool SetProcessPriority(std::uint32_t pid, ProcessPriorityLevel priorityLevel, std::string* errorMessage);

    // SetProcessEfficiencyMode 作用：启用/关闭 Windows 进程效率模式（PowerThrottling）。
    bool SetProcessEfficiencyMode(std::uint32_t pid, bool enableEfficiencyMode, std::string* errorMessage);

    // OpenProcessFolder 作用：在资源管理器定位该进程路径所在文件。
    bool OpenProcessFolder(std::uint32_t pid, std::string* errorMessage);

    // QueryProcessStaticDetailByPid 作用：
    // - 以 PID 为入口，查询单个进程的静态详情快照；
    // - includeSignatureCheck=true 时执行签名校验，可能较慢；
    // - UI 开窗路径应传 false 或改用后台任务，避免阻塞事件循环。
    // 参数 pid：目标进程 PID。
    // 参数 outRecord：输出记录，失败时保留已获得字段。
    // 参数 includeSignatureCheck：是否同步执行 WinVerifyTrust 签名校验。
    // 返回值：基础静态详情读取成功返回 true，失败返回 false。
    bool QueryProcessStaticDetailByPid(
        std::uint32_t pid,
        ProcessRecord& outRecord,
        bool includeSignatureCheck = true);

    // EnumerateProcessModulesAndThreads 作用：
    // - 枚举目标进程模块 + 线程信息（供“模块”Tab 刷新）；
    // - includeSignatureCheck=true 时会额外做模块签名校验（较慢）。
    ProcessModuleSnapshot EnumerateProcessModulesAndThreads(
        std::uint32_t pid,
        bool includeSignatureCheck);

    // EnumerateProcessModulesAndThreadsIfIdentityMatches 作用：
    // - 在整个枚举期间保持同一进程句柄，并核验 PID + 创建时间；
    // - 身份不可用或不匹配时返回空快照，避免将复用 PID 的模块数据用于旧详情窗口。
    ProcessModuleSnapshot EnumerateProcessModulesAndThreadsIfIdentityMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        bool includeSignatureCheck);

    // UnloadModuleByBaseAddressIfIdentityMatches 作用：
    // - 在同一进程句柄上校验 PID + 创建时间后，对远程进程调用 FreeLibrary 卸载指定基址模块。
    bool UnloadModuleByBaseAddressIfIdentityMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::uint64_t moduleBaseAddress,
        std::string* errorMessage);

    // SuspendThreadById 作用：挂起指定线程。
    bool SuspendThreadById(std::uint32_t threadId, std::string* errorMessage);

    // ResumeThreadById 作用：恢复指定线程。
    bool ResumeThreadById(std::uint32_t threadId, std::string* errorMessage);

    // TerminateThreadById 作用：结束指定线程。
    bool TerminateThreadById(std::uint32_t threadId, std::string* errorMessage);

    // *IfIdentityMatches 系列：
    // - 在同一线程句柄上核验 TID、所属 PID 与 FILETIME 创建时间；
    // - 验证成功后才执行 R3 挂起/恢复/结束，避免线程 ID 复用后操作错误对象。
    bool SuspendThreadIfIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    bool ResumeThreadIfIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    bool TerminateThreadIfIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    // *IfProcessAndThreadIdentityMatches 系列：
    // - 在同一进程句柄上核验 PID + 创建时间，并保持该句柄直到线程动作返回；
    // - 再核验线程所属 PID + 创建时间，避免详情窗口落到 PID/TID 均已复用的新实例。
    bool SuspendThreadIfProcessAndThreadIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedProcessCreationTime100ns,
        std::uint64_t expectedThreadCreationTime100ns,
        std::string* errorMessage);
    bool ResumeThreadIfProcessAndThreadIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedProcessCreationTime100ns,
        std::uint64_t expectedThreadCreationTime100ns,
        std::string* errorMessage);
    bool TerminateThreadIfProcessAndThreadIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedProcessCreationTime100ns,
        std::uint64_t expectedThreadCreationTime100ns,
        std::string* errorMessage);

    // InjectDllByPath 作用：
    // - 把指定 DLL 路径注入到目标进程（LoadLibraryW 远程线程方案）。
    bool InjectDllByPath(std::uint32_t pid, const std::string& dllPath, std::string* errorMessage);

    // InjectShellcodeBuffer 作用：
    // - 把原始 shellcode 字节写入远程进程并创建远程线程执行。
    bool InjectShellcodeBuffer(
        std::uint32_t pid,
        const std::vector<std::uint8_t>& shellcodeBuffer,
        std::string* errorMessage);

    // OpenFolderByPath 作用：
    // - 在资源管理器中定位到目标路径（文件或目录）。
    bool OpenFolderByPath(const std::string& targetPath, std::string* errorMessage);

    // KnownTokenPrivilegeNames 作用：
    // - 返回当前 Windows SDK 定义的完整 Se*Privilege 目录；
    // - 启动期申请、创建进程页、进程列表和详细信息页必须复用该目录。
    const std::vector<std::string>& KnownTokenPrivilegeNames();

    // BuildKnownTokenPrivilegeSnapshot 作用：
    // - 把 R3 TOKEN_PRIVILEGES 或 R0 IOCTL 返回的 LUID/Attributes 条目映射到统一 SDK 目录；
    // - 不依赖私有 Token 布局，未出现在条目中的已知特权标记为 NotPresent。
    bool BuildKnownTokenPrivilegeSnapshot(
        const std::vector<TokenPrivilegeLuidEntry>& entries,
        std::vector<TokenPrivilegeInfo>* privilegesOut,
        std::string* errorMessage);

    // QueryTokenPrivilegesByPid 作用：
    // - 通过 Win32 Token API 查询指定进程的完整特权快照；
    // - 返回 true 表示成功读取令牌，单项 LookupPrivilegeValue 失败时以 Unknown 表示。
    bool QueryTokenPrivilegesByPid(
        std::uint32_t sourcePid,
        std::vector<TokenPrivilegeInfo>* privilegesOut,
        std::string* errorMessage);

    // QueryTokenPrivilegesByProcessHandle 作用：
    // - 复用调用方已经校验过创建时间的进程句柄读取令牌；
    // - 避免在身份校验后再次按 PID 打开进程而命中复用后的新进程。
    bool QueryTokenPrivilegesByProcessHandle(
        HANDLE processHandle,
        std::vector<TokenPrivilegeInfo>* privilegesOut,
        std::string* errorMessage);

    // ApplyTokenPrivilegeEditsByPid 作用：
    // - 打开指定 PID 的进程令牌（可选 DuplicateTokenEx）；
    // - 按 edits 调整特权（AdjustTokenPrivileges）。
    bool ApplyTokenPrivilegeEditsByPid(
        std::uint32_t sourcePid,
        std::uint32_t tokenDesiredAccess,
        bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* errorMessage);

    // ApplyTokenPrivilegeEditsByProcessHandle 作用：
    // - 直接从稳定进程句柄打开令牌并应用调整；
    // - 身份敏感 UI 必须优先使用该入口，不能在校验后退回按 PID 打开。
    bool ApplyTokenPrivilegeEditsByProcessHandle(
        HANDLE processHandle,
        std::uint32_t tokenDesiredAccess,
        bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* errorMessage);

    // LaunchProcess 作用：
    // - 按 request 调用 CreateProcessW 或 Token 路径创建进程；
    // - 对外统一返回 CreateProcessResult。
    bool LaunchProcess(
        const CreateProcessRequest& request,
        CreateProcessResult* resultOut);

    // LaunchSuspendedProcess：以 CREATE_SUSPENDED 创建进程定向监控目标。
    // - 当前进程已提升且 request.runAsAdministrator=false 时，优先使用 TokenLinkedToken
    //   创建普通权限目标；
    // - 成功时保留主线程句柄供 ResumeSuspendedProcessInitialThread 精确恢复。
    // - resultOut 必须为有效输出地址；空指针会在创建进程前直接失败，避免丢失
    //   CREATE_SUSPENDED 主线程句柄。
    bool LaunchSuspendedProcess(
        const SuspendedProcessLaunchRequest& request,
        SuspendedProcessLaunchResult* resultOut);

    // ResumeSuspendedProcessInitialThread：恢复由 LaunchSuspendedProcess 保留的主线程一次。
    bool ResumeSuspendedProcessInitialThread(
        std::uint64_t initialThreadHandle,
        std::string* errorMessage);

    // TerminateSuspendedProcessByHandle：用 LaunchSuspendedProcess 保留的原始进程句柄终止目标。
    bool TerminateSuspendedProcessByHandle(
        std::uint64_t processHandle,
        std::string* errorMessage);

    // CloseSuspendedProcessInitialThreadHandle：关闭受控挂起创建返回的主线程句柄。
    void CloseSuspendedProcessInitialThreadHandle(std::uint64_t initialThreadHandle);

    // CloseSuspendedProcessHandle：关闭受控挂起创建返回的原始进程句柄。
    void CloseSuspendedProcessHandle(std::uint64_t processHandle);

    std::wstring GetCurrentProcessPath();

}
