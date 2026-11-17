---
name: ksword-process-r0-identity
description: R0-only 进程危险动作的创建时间来源、驱动对象身份校验与旧协议兼容约束
metadata:
  type: project
---

# R0-only 进程身份校验

进程表的“仅内核枚举可见”记录可能无法通过 `OpenProcess` 得到同一对象。Rootkit 还可能篡改
`UniqueProcessId`、活动链表或用户态查询路径，因此不能用 R3 `OpenProcess + GetProcessTimes`
替代驱动对目标 `EPROCESS` 的身份判断。

## 当前链路

- `KSWORD_ARK_PROCESS_ENTRY` v3 返回 `creationTime100ns`，值来自枚举时已引用对象的
  `PsGetProcessCreateTimeQuadPart`。无法引用的 CID 弱证据行返回 0。
- `ProcessDock` 对有真实 R0 创建时间的 kernel-only 行直接使用该时间建立 identity；旧驱动或
  弱证据行才使用 `KernelOnlyCreationTimeSeed + PID` 维持稳定显示键。
- R0 结束进程与 `BreakOnTermination/APC` 特殊标志请求携带
  `expectedCreateTime100ns`。驱动先按 CID/ActiveProcessLinks/PID 解析并引用 `EPROCESS`，再比较
  `PsGetProcessCreateTimeQuadPart`，不匹配返回 `STATUS_INVALID_CID` 且不执行写操作。
- 普通 R3 可见进程继续持有经 `GetProcessTimes` 验证的 Win32 查询句柄，并同时接受驱动侧校验。
  kernel-only 目标跳过 Win32 句柄校验，只使用驱动侧对象校验。
- 新驱动按请求字段偏移接受旧版终止/特殊标志固定前缀。旧请求缺失的创建时间按 0 处理。

## 约束

- 2026-10-02：按评估要求，常规 R0 进程结束与普通线程结束中的低 PID（0–4）及
  `PsInitialSystemProcess` 拒绝代码已注释保留；中央 safety 的 Idle/System 判断仅对
  `PROCESS_TERMINATE` 豁免。创建时间、线程归属、请求结构与确认策略仍须校验。
  通用 `KswordARKValidateUserPid` 供其他动作使用，不能全局关闭；HVM 的 PID 0/4
  保护按用户要求保留。取消驱动特判不代表内核终止必然成功，尤其 PID 0 仍可能无法解析。

- 新增按 PID/CID 定位的 R0 危险动作时，优先把期望创建时间放入 `shared/driver/` 请求结构，
  并在驱动解析出的对象上校验。
- 不要把 kernel-only 行的合成 identity 时间传给驱动。合成值只用于 UI 缓存键。
- 不要全局关闭 `ProcessDock::dispatchProcessActionTargetsInParallel` 的 R3 identity hold。
  普通 R3 变更动作只对明确标记为 `isKernelOnly` 的目标跳过。
- 独立的“R0 结束进程”列表动作不依赖 R3 `OpenProcess`：R3 可见目标须携带真实
  `creationTime100ns`，由驱动在已引用的 `EPROCESS` 上校验；缺失时拒绝下发。
  R3 动作及其组合链仍保留原有 identity hold，不能为解决受保护进程问题全局跳过。

## 进程详情的逐方法结束

- 主程序进程列表的“高级结束进程（逐方法）”、主程序详情页和 Light 详情页的 R3 条目共用
  `shared/ProcessTerminateMethods.h`，目前为 14 项。组合链也从该表执行，新增方法时只改这一处。
- 两个详情页执行单项 R3 方法前，都用捕获的创建时间验证目标并持有查询句柄，避免 PID 复用；
  R0 驱动结束单列在表外，仍走各自已有的驱动调用与身份保护。
- 详情页下拉框不包含 HVM 与 DMA：HVM 需要地址和常驻状态编排，DMA 需要另行指定写入地址。

## 2026-10-02 结束方法接入

- 用户先后取消 Ctrl+C 和 Ctrl+Break；R3 共享方法表仍为原有 14 项，未新增控制台信号或辅助进程入口。
- R0 顺序为清 PP/PPL → ZwTerminateProcess → PspTerminateProcess → Normal Kernel APC → 逐线程终止 → 清零可写用户内存。Psp 只消费精确 PE/RSDS 匹配的 v4 可选 item 1401（GlobalRva/core），检查可执行节和已核对的四参数入口序列（EPROCESS/排除线程/NTSTATUS/flags），未知 ABI 返回不支持；不猜 CALL 或复用其他内核 RVA；老配置缺失该项会继续后续方法。生成器和运行时 PDB 解析器均提供此项。
- 普通进程 APC 在目标线程自身上下文调用 ZwTerminateProcess(NtCurrentProcess())；与系统线程 APC 共用注册/取消/卸载排空，另持 EPROCESS 引用并核对上下文。未导出 PsGetNextProcessThread 时用 500ms 有界 CID 查询与精确 EPROCESS 归属校验回退。排队成功不等于目标退出。
- R3-only 组合动作必须以 includeR0Fallback 守住最后实际驱动调用，不能只守住回退前的存在性检查。

- 本机配套发布矩阵仅补充了当前内核的一条 item 1401：先校验 PE SHA256、RSDS GUID/Age、PDB DBI Age 与四参数入口序列，再压缩并回读；2406 个矩阵条目均保留。其他内核需重新生成/应用匹配 PDB 配置。

## 2026-11-17：CID 已退出残留排除研究（历史方案；实现与实测见下文）

- 当前 `process_crossview.c::KswordARKCrossViewValidateActiveProcessLinks` 给链头和节点的安全引用传空 ID，而 `object_header_fallback.c::KswordARKObjectHeaderReferenceObjectSafe` 明确拒绝空 ID；主枚举因此不能取得 `activeWalkComplete`。前轮已抽取生产函数离线复现，合法环形链在遍历零节点时返回参数错误。修复不能退回对未引用候选直接读对象头或增加引用。
- 除空 ID 外，`ArkDriverTypes.h::isTrustedHiddenProcessFlags` 把活动链表缺失作为所有 R0 补充行的必要条件：R3 查询被过滤、但对象仍在活动链表的进程也会被拒绝。`process_actions.c` 又把非自有对象的 PID 字段与 CID 不同、活动链/整表遍历不完整等情况统一混入 `CID_TABLE_UNCONFIRMED`，导致对象有效性、生命周期和隐藏证据相互否决。
- 建议分开记录对象引用/类型、生命周期、各来源可用性与异常。在合法引用的 EPROCESS 上做零超时终止信号采样：精确 `STATUS_SUCCESS` 为已触发（在正常内核语义下表示已退出，不能单独成为对抗篡改时的排除条件）；`STATUS_TIMEOUT` 只是尚未触发，可含正在退出；其它结果为未知。Timeout 必须指向零值，NULL 会无限等待；不能用 `NT_SUCCESS` 判原始等待是否触发，因为超时也是 NT 成功类状态。项目 `process_terminate.c::KswordARKDriverWaitProcessExitByObject` 已有对象等待路径，但会重映射超时，不宜原样作为枚举三态接口。
- `ExitStatus`、ObjectTable、线程数、Flags、引用数和链表成员关系只作补充证据；字段缺失/读失败不等于已死，PID 不同应保留为身份异常。官方明确进程可用 259（STATUS_PENDING/STILL_ACTIVE）退出，不能凭 Pending 证明活着。有相互冲突的证据时保留异常而非静默删行。
- 当前 CID walker 是未锁定的只读槽位扫描，随后通过 PsLookupProcessByProcessId/TID 取得同址引用；它尚不能独立于 lookup 取得生命周期保护。未来基于槽位保护的引用必须核实精确目标内核的 CID 编码、entry 锁/解锁及删除协议；MmCopyMemory 成功或重复读槽相同均不提供对象存活保证，ObReferenceObjectSafe 也不能接受可能已释放的任意地址。线程 CID 归属、已验证进程/线程句柄可作为补来源；进程与线程 CID 全部被移除时，单一 CID 源无法保证发现。
- 本机 Win10 build 19045 上以自建 Python 子进程及保留的真实进程句柄实测 5 次：运行/挂起均 wait0=258、exitCode=259；退出 0 后保留句柄及再次采样均 wait0=0、exitCode=0；退出 259 后保留句柄仍 wait0=0、exitCode=259。证据 `.codex-tmp/cid-liveness-research-20261117.json`（忽略目录，非发行资产）。没有加载驱动、扫描 CID、实施隐藏或运行 GUI；尚未验证 Win11、R0 并发引用或各隐藏方式。
- 主要依据：[进程终止及对象信号](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process)、[零超时及等待返回值](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject)、[退出码 259 歧义](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess)。System Informer 的 `SystemInformer/hidnproc.c` 有 ExitTime 判终止的先例，但官方 GetProcessTimes 说明未退出时 ExitTime 内容未定义，不能直接把该先例变成跨版本硬过滤。PsGetProcessExitTime 无目标参数，只返回当前进程时间，也不能直接用于任意 CID 候选。

### 用户确认的分类原则（覆盖此前宽松排除建议）

- 后续实现采用严格的已退出残留排除：补充扫描和交叉对照发现的候选，只有多项有效证据共同、严格支持正常终止后的残留状态，且没有相互矛盾的证据时才从主列表排除。具体证据组合和跨版本适用性仍需研究与验收，不能把未经验证的组合写成已完成能力。
- 不以“能否证明尚未结束”作为候选接纳门槛。无法排除为已退出残留的异常候选一律保留并标红；引用失败、偏移缺失、读取失败、PID 不一致、扫描不完整、链表校验失败等不能再导致候选静默丢失，也不能伪造未经验证的对象类型或字段值。
- 面向用户的进程行只有正常和标红异常两种分类；未知、证据不足、正在退出或矛盾作为红色行的具体原因，不另设默认隐藏的第三类来承接这些记录。正常来源一致且无异常的普通进程仍按正常显示。
- 终止信号本身也可能被内核写入或查询路径干扰，只是证据之一；多次读取同一字段或不同等待 API 的同源结果不算多项独立证据。安全取得引用的要求保持不变，无法引用时只保留已安全观察到的证据。
- 此处正常终止后的残留指生命周期/资源状态符合已经完成退出，不要求退出码为零，不推断退出的业务原因；崩溃退出或被终止后的真实残留也应由同一证据规则处理。显示异常与危险动作执行资格分别校验。该研究阶段仅确认方案和更新记忆；后续实现与实测见下节。

### 拟议严格证据组合（待用户评审、待跨版本实测）

- 前置条件为安全取得同一 EPROCESS 的引用、确认 Process 类型、创建身份及各字段布局有效。拟采用合取条件而非打分：进程对象终止等待精确触发；ExitTime 非零且不早于同一对象 CreateTime；目标版本已核实的 ProcessExiting 语义位成立；ActiveThreads 为零且可用的进程线程链/CID 线程反证检查完整、没有归属该对象的未终止线程；ObjectTable 成功读取且为 NULL。线程残留允许存在，但不得把仅有 PsIsThreadTerminating=true 当成线程已完成退出。
- 上述条件须连续两次正常刷新均满足，且没有 PID 身份矛盾、状态回退或其它可信执行反证；首次满足时仍保留红色。每轮都重新安全取得引用并复核对象身份，不能拿跨轮裸地址当引用。时间线异常、字段缺失、反证检查截断/失败等均不满足排除条件。两次采样用于避免过渡状态，不算新的独立证据来源。
- ExitStatus 的具体值只记入诊断，不要求零，也不要求不等于 259。R3/活动链表缺失不加入死亡证明。已排除对象也必须随新扫描重新判定，不建立永久 PID/地址死亡黑名单。此组合是保守候选设计，尚未证明各 Win11 版本的普通残留均满足；未通过版本夹具验收时保持标红。
- 项目 DynData 已有 EpExitTime、EpActiveThreads、EpFlags、EpObjectTable 的字段定义和生成映射，但这不等于各精确内核 profile 全部具备，也不等于退出位的语义位位置已统一验证。多项一致只能降低正常残留误报，不能证明可抵抗同权限攻击者对全部证据的协同伪造。


## 2026-11-17：严格退出排除已实现及 Win10 VM 实测

- 协议 v4 在原 v3 创建时间之后追加 EPROCESS 诊断身份、ExitTime、退出证据掩码、对象 PID、线程数与原始等待状态；旧 v3 创建时间按字段偏移继续解析。GUI 和独立原生探针共同调用 `shared/driver/KswordArkProcessIoctl.h::KswordArkProcessExitedResidual`，不复制判据。
- `process_cid_reference.c` 对 CID HANDLE_TABLE 使用现有 `ExEnumHandleTable` 槽锁/解锁协议：先以 PID 4 精确匹配 `PsInitialSystemProcess` 校准编码，再在锁内取得对象引用，释放 entry 锁后查对象类型和采样，最后平衡引用。HtHandleContentionEvent 不可用/锚点校准失败时只回退旧 lookup 路径；保护扫描失败报告不完整，不把不完整当死亡。此保护路径只在下述精确 VM 内核实际验收，不能泛称跨版本均已验证。
- `process_lifetime.c` 在合法引用上采集：wait0 精确成功、非零且不早于创建时间的 ExitTime、导出 `PsGetProcessExitProcessCalled`、成功读取的 ActiveThreads=0/ObjectTable=NULL、完整一致线程链无未结束线程、完整 CID 线程扫描无同对象 owner 的未结束线程。任一缺失/矛盾都不能排除；不要求退出码等于 0 或不等于 259。
- `process_actions.c` 按对象地址合并活动链/CID/线程 owner；真实进程 CID 槽提供规范 PID，线程可变 Cid 字段不能覆盖已取得的真实槽身份。PID 不同单独标异常。进程 PID 槽被删但仍有线程 CID 时，线程 owner 也参与发现。移除原 0x400000 的发现 PID 上限，仅为可选成员 bitmap 保留内存上限；bitmap 分配失败不再关闭 CID 发现。
- 主枚举的 ActiveProcessLinks 校验已修复空 ID：锚点用系统持有对象的 PID；节点只安全读 PID 标量，再 lookup 同址引用。该校验不再是候选显示的必要门槛。实际生产 validator 已进入 `tools/test_driver_candidate_reference.py`：合法空环、单节点环、空节点 ID、坏反向边、零预算，加上原引用测试合计 44 项通过，能覆盖原空 ID 回归。
- `ProcessDock` 的 R0 补充行不再要求活动链缺失或 stable-liveness；已证明普通退出残留才排除，其余补充/身份矛盾行均标红，弱引用和终止 flag 不再自动变灰或丢弃。改 PID 的 R3 别名按创建身份替换为规范 CID 行。自有隐藏的显示开关不能再次隐藏内核异常候选。正常退出行原有短暂灰色动画保留，和未知候选分类分开。
- 两次确认使用同一非零对象地址+创建时间且两个证据掩码均全满足、两个 PID 均无矛盾。**覆盖历史方案“首次满足先显示红色一轮”**：冷启动或首次出现完整退出证据时，在后台刷新内追加一次独立 R0 枚举，确认后再呈现，避免普通残留闪红。已排除项每轮重新枚举、重新判定；没有永久死亡黑名单。缓存只存证据，不把跨轮裸地址当引用。
- R3 请求缓冲从 1 MiB 按实际输出容量扩展到最多 64 MiB；total>returned 也可能表示来源不完整，输出未满时不反复扩大重扫。
- 实测 VM：`E:\VMs\Windows10-20H2\Windows 10 x64.vmx`，Win10 Home 20H2 build 19042，ntoskrnl 19041.631，PDB F923DA2D-238E-7C7C-E180-B962B19A3781/Age1。精确 EX profile 186/186 应用；HtHandleContentionEvent 来自已启用 System Informer 布局。WinRM HTTPS 地址为 192.168.172.133；旧 .130 记录已过时。VIX 对 codex_remote 应使用非交互 flags=0，不能沿用 Administrator 空口令或交互 flag=0x08。凭据仅本机 DPAPI 文件读取，不落报告。
- 最终驱动 5 波各 64 目标、8 次全部计入的呈现判定：2560 次，880 次隐藏/来源缺失检测，1280 次持句柄退出残留排除，400 次正常/挂起观察，误报 0、漏报 0、隐藏恢复正常 90 次。覆盖 PID 字段修改、断链、两者组合及各自挂起状态，退出码 0/259；R3 来源过滤为消费者模拟，不是实际 API hook。4 波并发创建退出，报告时累计完成 183 个后台子进程。全机 20 轮双采样，2460 次正常观察、100 次残留排除、未解释候选 0。原生夹具为 `tools/tests/process_cid_lifetime_vm.cpp`；安全主机 `--policy` 25 项通过，变更目标的模式必须 VMware + 显式环境变量。
- 单独破坏性实验（不计为稳定套件通过）：删除受控进程 PID CID 槽并断链后，最终驱动 12/12 轮从线程 owner 找到目标，未伪造进程 CID 来源。目标请求普通退出时 guest 0x3B/C0000005；精确符号转储显示 `nt!PspClearProcessThreadCidRefs+0x35` 在缺失槽的 `ExMapHandleToPointer` 结果上解引用 NULL，调用链为 PspRundownSingleProcess/PspExitThread，无枚举栈。先前重复实验同一归因。结论限于本 build：删除 PID 槽可以暂时存活、在退出清理时崩溃，不能说任何版本一定立即蓝屏。所有进程/线程 CID 都删除时，单 CID 源无万能发现保证。
- 构建：主程序 Release/x64 HostX64 `BUILD_RESULT=SUCCESS/EXIT_CODE=0`，语言门禁 30468 项；驱动 MSVC/WDK /WX、Universal ApiValidator、INF/CAT Errors=None/Warnings=None；任务专用签名副本成功加载 VM。不要为实验调用会改宿主信任库的自动签名脚本，当前用任务临时 PFX + signtool；未把私钥/口令写入仓库。
- 最终已回滚 `Codex-CidLiveness-Before-20261117` 并 nogui 恢复运行，远程确认测试服务不存在、实验目录不存在、测试子进程 0、用户桌面原 exe/sys 保留。最终新产物在宿主 `Ksword5.1/x64/Release`，没有用试验版覆盖客体用户原目录。
- 结果和哈希见 [结构化验收记录](../../docs/validation/process-cid-lifetime-20261117.json)。逐轮 JSONL、构建日志和两次转储留在宿主 `.codex-tmp/`（忽略目录，非发行资产）。未对 Win11 实机验收；按用户禁止 computer use 的要求未做 GUI/离屏 GUI 验收，不能将驱动/共享谓词实测说成 GUI 视觉验证或任意隐藏方式零误报的保证。


## 2026-11-17：用户截图回归——冷加载缺布局，已修复并部署两机

- 用户指出 Win11 除手动隐藏 Notepad 仍有很多红色普通进程，Win10 首轮多红、第二轮消失。**此前 2560 次零观察错误不是实际启动链的完整验证**：测试先手动应用了 EX profile，掩盖了启动时布局未就绪。保留原报告并增加 followupCorrection，不能用原计数否认用户实测。
- 精确复现：两机均直接加载用户桌面的同一签名驱动 SHA256 `64AB7858EA96C30E643D1FA6F6AFC04E1ABA231E41C4C28B9F204DCE9D9E78EB`。未应用 profile 时每机 256/256 次持句柄退出残留均误标红；应用匹配 EX 后为 0。Win10 内核 19041.631，Win11 内核 26100.9711；Win11 实测此前记录的未验证范围现已补上这个精确版本。
- 根因：`MainWindow::refreshR0DynDataAfterServiceStart` 把 profile 刷新推迟到 KernelDock widget 初始化。首轮 EPROCESS.ExitTime/ThreadListHead/ETHREAD.ThreadListEntry 等 unavailable，Win11 连 HtHandleContentionEvent 也 unavailable；两次采样不能凭空补布局。不能把这个问题修成单项信号/ExitTime/ExitStatus 的宽松排除。
- 将原 `KernelDock.DynData.cpp` 的 `LocalPdbProfile` 及现有 JSON/schema/精确 PE 身份匹配/EX 投影代码移动到 `ArkDriverClient/ArkLocalDynDataProfile.cpp/.h`。KernelDock 继续调用同一解析器，翻译通过参数回调保留原 frozen resultTexts；组件只依赖 QtCore，不依赖 QWidget 或创建页面。
- 新 `ArkProcessLifetimeProfile.cpp/.h::prepareProcessLifetimeProfile` 在后台串行执行：查实际所需字段 → 精确匹配本地发布包 → apply EX → 再查字段确认。`ProcessDock::buildRefreshResult` 在首次 R0 枚举之前调用，不依赖驱动页面的惰性初始化。未命中/拒绝/缺字段仍不能证明死亡，异常候选继续保留。调用前由 ProcessDock openSilently 检查并持有连接，驱动尚未就绪时不发准备 IOCTL、不新增权限提示，保留原 R3-only 路径。原 0xff、多组证据、两次独立采样、对象+创建身份、无 PID 矛盾的排除条件没有放宽；本次没有修改驱动二进制逻辑。
- 新夹具 `tools/tests/process_lifetime_profile_prepare.cpp` 和入口 `tools/test_process_lifetime_profile.py` 使用真实共享解析/准备代码、真实 DriverClient DynData IOCTL 编码；离线仅替换传输，19 项（冷字段、已就绪不重复 apply、拒绝、readback 不完整、未知身份、并发）通过。其 `--prepare-live` 另有 VMware+环境变量 guard，在两机真 R0 下通过。原 parser 门禁改为读取抽出的生产源码，2932 profiles/4 拒绝用例通过；候选引用/validator 44、严格策略 25、功能矩阵门禁通过。
- 每机三次真正 stop/start 驱动，从无 profile 状态开始准备，然后并发 churn 压力枚举。最终共 3072 次呈现判定、1056 次异常检测、1536 次退出残留排除，误报 0/漏报 0；每机 18*3 个隐藏目标全部恢复正常。全机各 20 轮，Win10 2540 次正常/140 次残留排除，Win11 1963 次正常/40 次残留排除，未解释候选均 0。
- Win11 并发退出曾返回 total>returned，旧夹具直接断言全表完整而中止。这轮没有算通过，也没有重试掩盖。夹具现记录每次 header 并继续逐一验证全部受控目标，与生产“来源完整性独立于对象与退出证据”相符。最终第三波 call8 再现 returned189/total190，所有控制目标仍发现、退出证据独立满足，FP/FN 都 0；未声称所有 partial 都能排除残留。
- 主程序 HostX64 Release/x64 BUILD_RESULT=SUCCESS EXIT_CODE=0，33317376 bytes，SHA256 `531711CB71B9C027DE8A156108FC59BD90E42795716891D15E334037CDC0A87F`；i18n 30468 项、主题门禁通过。数据包 SHA256 `DC9F19F9D03C348F769FAECAD0FF8A8B05234A0C40A9FD93CD379A90855D3ED3`。详细记录为 [冷启动验收](../../docs/validation/process-cid-cold-start-20261117.json)。
- **已部署客体**：Win10 `C:\Users\Administrator\Desktop\Ksword-nice`；Win11 `C:\Users\User\Desktop\Release`。两机 exe/pack 哈希均读回一致。旧 exe/pack 在各自 `backups/cid-cold-layout-20261117`；本次 CodexCidRepro 服务已 stop/delete、测试子进程 0。没有为了清理再次回滚快照，避免撤销新部署和修复后的 SSH。
- Win11 连接已实测：VMX `E:\VMs\Windows11-24H2\Windows 10 x64.vmx`，IP 192.168.172.128，SSH 登录 **User**，whoami `DESKTOP-O83P0R8\User`，管理员 True。旧 codexvm 被 sshd `ga_init unable to resolve user` 拒绝，不能沿用旧 Invoke-VM.ps1 默认账号。用户在管理员 PowerShell 补入同一专用公钥到当前 User 的 .ssh/authorized_keys 和 administrators_authorized_keys，权限校正后已连通，不改密码。
- 按用户明确要求已写 `E:\VMs\Windows11-24H2\连接说明.txt` 与 `Invoke-KSwordVM.ps1`；后续先读该文件。脚本严格校验原 host-key alias，私钥继续留在原受 ACL 保护的路径，只记录位置，不复制/打印私钥。此轮 Win11 前置快照 `Codex-Cid-Win11-Before-20261117` 已保留。
- GUI 仍按用户禁止 computer use 的要求未自动启动/操作，也没有离屏 GUI。UI 影响仅进程现有列表采集时序和 KernelDock 共用纯解析器，未改布局/共享表格结构。后台、源码、构建和客体部署已验收，不能把这些说成新主程序真实首帧视觉验收或所有 Windows 版本绝对零误差。


## 2026-11-17：用户纠正方法——0x8b 与双机无精确偏移回归

- 用户明确要求修改方法，不靠精确偏移全覆盖。实体机 19041.7844 的 clinfo=0x2b 和 DynData 报告证明了原 0xff 强制合取缺布局证据的失败路径。此前冷准备仅解决已有 profile 加载时机，不是普适方法。
- 当前共享必需掩码 **0x8b**：安全引用与创建身份、进程 wait0 精确成功、导出 PsGetProcessExitProcessCalled、同 EPROCESS 没有未结束 CID 线程。ExitTime/ActiveThreads/ObjectTable 为诊断；进程线程链不再必选。仍须两次独立采样、同非零对象地址+创建时间、无 PID 矛盾；259 不作生死门槛。
- ProcessDock 已移除进程刷新前的 EX profile 准备调用。KernelDock 既有 profile 功能仍保留。退出线程检查复用通用 KswordARKCrossViewWalkCidTable，避免直接调用 Protected 绕过可用的既有回退。
- 混合 CID/释放槽由安全 lookup 和同槽复读处理；以系统 EPROCESS/当前 KTHREAD 校准公开 DISPATCHER_HEADER 的只读标量分类另一类对象和 signaled 残留线程。新 scalar 读取全部 RuntimeReadMemory，不对未引用地址调用对象 API 或增加引用。
- Win11 的稳定 CID 76 是公开查询无法引用的未 signaled 线程。既有由导出 PsGetThreadProcess 验证的 KtProcess 运行时布局可读 owner。内部 ObservedOwnerAddress 只作对应 EPROCESS 的局部否决，不声称已引用、已验证类型或建立进程发现行；未知 owner 仍作全局否决。这避免单个系统线程污染全部退出判定。
- 并发释放导致 PARTIAL_COPY/DELETE_PENDING 时，finalizer 最多作 3 次独立重采；所有尝试已发现的未结束 owner 否决始终保留。只有成功完整的后续视图可结束本轮复核；最终失败仍不排除。曾出现的中间失败未计为最终通过，新报告保留失败依据。
- 最终同一签名驱动在 Win10 ntos19041.631、Win11 ntos26100.9711 各真实 stop/start 3 次，不下发外置精确 profile，ExitTime 等保持 unavailable。3072 次判定、1056 次异常检测、1536 次退出残留排除，FP/FN/残留可见均 0；108 个隐藏目标恢复正常，230 个后台 churn 子进程完成。
- 覆盖 PID 字段修改、断链、两者结合、各自挂起状态，普通持句柄退出 0/259；R3 源缺失为消费侧模拟。另有 1536 次消费侧伪造进程信号/退出标志检查，实际 R0 CID 线程证据均否决；没有实际写内核终止信号。
- 全机各 20 轮：Win10 normal2460/residual260、Win11 normal1960/residual120，未解释候选均 0。62 项实际生产引用/CID 观测/局部否决回归、28 项共享策略、IOCTL 计划门禁通过。Release/x64 MSVC/WDK /WX、Universal、INF/CAT 零错误警告；主程序 HostX64 Build 与语言/主题门禁通过。
- 主程序 SHA256 08CC6B8E9E06B713F96BE8988CB91025353940E7A7A4366BEB16C419945A1C4A（33312256 bytes）；未签名驱动 044AE19C69EDA266CEAFBD038DCAE45B162C8E2153D8B6FEA6748FB3CA75C177；VM 签名副本 CDD1F993B40CE39A1D4F82F0BA781457BC5CE542658944AFA56994ED87BE6AB5。
- 两机桌面原目录 exe/sys 成对部署，存在的 KswordARKDriver 子目录 sys 也同步；旧版各在 backups/cid-simple-20261117，客体哈希均读回一致。CodexCidSimple 服务已删除、测试子进程 0；Win10 原 KswordARK 服务恢复运行，Win11 原无运行驱动，未自动启动 GUI。前置快照 Codex-Cid-Simple-Before-20261117 均保留，未回滚撤销部署/SSH。
- Win11 原未开启 testsigning，新签名驱动被 577 拒绝；已在该测试 VM 开启并重启，lab 证书仅加两机 Root/TrustedPublisher，保留以支持桌面测试副本。未改宿主信任库或加载宿主新驱动。用户继续禁止 CUA/窗口/离屏 GUI 自动化。
- 结构化逐轮结果、原始路径、哈希、早期失败和验证范围见 docs/validation/process-cid-simple-20261117.json。用户新偏好：结论/原因/数据在前，防御性语言与验证范围集中末尾。后续所有项目构建默认 BelowNormal，已写 AGENTS.md、构建脚本及构建记忆，并实际验证子进程继承。
