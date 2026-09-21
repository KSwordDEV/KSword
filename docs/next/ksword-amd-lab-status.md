# AMD 实验实现状态（2026-09-21，多核常驻与嵌套 SVM 开发）

## 当前进度（以下本节优先于后面的历史记录）

### 09-21 17:59 单核通用模式硬件启停 PASS

冻结候选 `3aeca4c2` 在 VMware 原生 CPL0/SVM/NPT 的 Windows 10 单核克隆上完成通用模式准备、自检、常驻、10秒空闲后唤醒、停止、重复停止、资源释放和服务卸载。导出的51份文件均核验哈希/大小；CPU0:0记录162次general硬件退出，停止后stage6、失败状态0，事件/VMCB归属清空，最终SCM STOPPED。KD查询断点命中且加载匹配private PDB（age24）。[验收证据](evidence/amd-general-resident-1cpu.json)。

该结果只证明通用模式退出循环和启停闭环。未启动新的内层操作系统，未验证内层多核并发；下一项跳至8核同候选100轮。宿主已由用户批准重启进入LabHostReady，前文“不可重启/等待切换”仅保留为历史记录。

### 09-21 开测：离线通过，硬件等待实验启动

用户随后明确暂时不可重启。新增 `Start-GuestGeneralTest.ps1`：通用模式短周期逐核证据校验，完整停止/释放后等待服务卸载；未执行内层OS时结果固定为false。新增门禁用例验证2个有效快照、17个拒绝场景、模式互斥及4种模拟SCM状态；现有采集回归通过。候选固定于 `tools/hvm_lab/artifacts/guest-bootstrap/general-smoke-20260921/`，包含本轮SYS/PDB、重新构建CLI和测试脚本，使用既有实验测试证书签名。宿主未安装该证书信任，来宾加载仍未验证；身份以目录内identity.json为准。当前不重启、不调整BCD、不启动虚拟机、不加载驱动。

实际执行全部21个 HVM 测试目标，首轮18通过、3失败。修复探针的生产问题：`KswNsvmProbeSessionIo` 没有清零完整会话参数，新增 `Pending` 指针继承栈垃圾，优化构建发生访问异常，调试构建则在反射阶段失败。现在构造前清零可选字段。另两处是 fixture 漂移：EV=0 的未定义错误码高32位应归一化；STGI 模拟输入必须设置 CR0.PE。保留原场景断言，增加 EV=1 错误码保留及 STGI 实际推进检查。

修复后整套重新编译并执行，21/21通过，包括8线程各100次模拟会话；这是用户态逻辑证据，不是8核硬件嵌套。CLI JSON 用例同步 metrics v5，并验证64位 general 序号/退出码与准备、实际退出计数分离；PS5.1 CP936 JSON、82命令目录、32有效/22拒绝参数、来宾加载器及日志采集测试均通过。标准 WDK Release x64、x64 ApiValidator Universal、CAT生成通过，零警告。

日志：`tools/hvm_lab/test-general-retry-20260921.log`、`test-cli-20260921.log`、`build-probe-init-20260921.log`；初次失败的逐项记录保留在 `tools/hvm_lab/artifacts/offline-general-20260921-172008/`，CDB定位日志为 `test-probe-av-20260921.log`、`test-probe-debug-20260921.log`。

本次环境实查：宿主 HypervisorPresent=True，KswordARK STOPPED，无 VMware VMX/KD 进程；当前工具进程非管理员，启动脚本只读检查被权限门拒绝。未装载本轮驱动、未启动虚拟机、未签名或修改启动项。需管理员执行进入实验环境脚本并重启，重新核验 LabHostReady 后继续单核，再直接8核。完整 L2 OS 与内层并发仍为 NOT_RUN。

### 09-21 本轮收尾：此前点名的三类分支已有实现，待执行验证

1. **不同 EXITINTINFO 的处理**：队列注入时临时拦截全部异常，在异常聚合之前取得退出，再区分原事件重试与原事件完成后的后续递送。EV=0 的未定义高32位不参与异步事件身份比较。提交 `c114634`。
2. **多事件跨层与跨 CPU 保存**：未投递的 guest 事件保存到共享 VMCB 身份下的有界邮箱，完整 VMEXIT 写回后才交接，下次 VMRUN 在同一物理身份的独占 lease 下恢复。当前 interrupted 事件和 physical NMI 仍分别走各自交接，不混入邮箱；邮箱不空阻止资源释放。提交 `408bec4f`。
3. **NMI 等待窗口**：shadow/已有 EVENTINJ 不再直接走未实现 WINDOW；新增独立、有界的 TF/RF 观察路径，保留原注入，恢复控制后重新检查 NMI 资格。只消费 monitor 自己的 BS，真实异常和其它退出继续分派；与 IRET 完成观察分开，超限保留故障。补上 held IRET 路径清理陈旧 EVENTINJ。

本轮构建：标准驱动 WDK Release x64、x64 ApiValidator Universal、CAT 生成通过，零警告。所有 HVM 源 fixture 编译链接通过，`TEST_EXECUTION=NOT_RUN`。日志分别为 `tools/hvm_lab/build-event-order-20260921.log`、`build-event-mailbox-20260921.log`、`build-nmi-window-20260921.log` 及各自 `*-fixtures-*` 日志。无共享协议/CLI布局变更，无加载、签名、暂存新候选或虚拟机运行。

**后续工作转为执行和调试这些候选路径，不代表可以跳过硬件验证。** 离线用例需实际运行；NMI 窗口需重点验证 TF/RF/DR6、PUSHF/POPF/IRET、调试断点、已有注入及次生异常的组合；邮箱需验证真实跨 CPU 调度与错误回滚。随后按单核完整 L2 OS → 同一内层8 vCPU并发 → 全核停止与卸载取得证据。普通路径实现齐备不等于所有输入、调试状态组合或 VMware 兼容已通过；保留 PARTIAL，完整 L2 与并发结论仍为 NOT_RUN。

### 以下为本轮前的缺口记录，以上节更新为准

### 09-21 静态收尾：已接通通用实验链，尚不能标记“仅剩测试”

本轮新增 IRET 完成观察及虚拟 NMI 屏蔽、显式通用 SVM 准备/常驻入口、准备与启动配置匹配、首次 INVALID 原生回读后的绑定清理、物理 NMI 随 L2→L1 的事务交接及 VINTR 反射。通用入口成功只发布 PARTIAL；普通常驻和固定探针各自保留原配置边界。

编译结果：驱动 Release x64 完整 WDK Build、x64 ApiValidator Universal、CAT 生成成功，零警告；hvm_ctl、KswordCLI、主程序编译链接成功。主程序有4条既有宏重定义/Qt部署警告，其构建自带 i18n/theme 门禁已运行。HVM 源用例仅编译链接，未执行；CLI 参数回归源用例已更新，未运行。没有签名、装载、暂存新候选、启动虚拟机或新增硬件验收。日志位于 `tools/hvm_lab/build-general-handoff-20260921.log`、`build-static-fixtures-general-20260921.log`、`build-cli-general-entry-20260921.log`、`build-gui-general-entry-20260921.log`。

剩余静态缺口集中在事件协调器：未阻塞 NMI 遇 interrupt shadow/无关 EVENTINJ，已 armed 事件遇不同有效 EXITINTINFO，以及多个未投递非 physical 事件跨 owner 反射。这些明确返回 WINDOW 并进入故障保留路径，不是已完成的正常等待。详见[实现记录](amd-nested-svm-implementation.md)。不能以本轮编译成功替代这些实现，也不能保证 VMware 或任意内层 OS 已可启动。

后续测试需区分四类证据：离线状态机/参数用例实际运行；普通常驻回归；通用模式单核完整 L2 OS 启动与关闭；同一内层 VM 的8个 vCPU 同时运行并持续前进，随后关机、全核 stop、teardown 和卸载。最后两项才涉及完整内层 OS 验收，固定探针串行轮询不替代它们。按用户当前要求，本轮不执行这些测试。

已有硬件证据的准确范围：09-19 实体机32逻辑处理器已完成5秒并发常驻、全核退出、资源释放与驱动卸载；09-21 固定嵌套探针8 vCPU/100轮通过的是逐核串行800次往返。完整 L2 操作系统、内层多核并发均无通过证据；两小时压力由用户中止，不记 PASS。以下更早记录中的“尚未完成实体机5秒”已被此段及[最终短常驻证据](evidence/amd-host-resident-32cpu-5seconds.json)覆盖。

### 09-18 至09-19 历史记录

**09-19 00:00 实体机32核同时进入与完整 stop 已通过，5秒测试被脚本误判中断。** 全32核实际 stage=4/ENTERED，脚本误期望3/ENTERING，导致尚未等待就进入finally；stop返回成功，逐核stage6、resident0、VMMCALL退出81、failure0。已修正脚本并增加共享协议常量及真实快照回归。[进入/停止证据](evidence/amd-host-resident-enter-stop.json)。此次资源与驱动有意保留，尚未teardown/卸载；不能记为完整5秒常驻验收通过。需要先释放已停止资源、卸载，再重跑修正脚本；不需修改驱动或重启。

**23:45 实体机32逻辑处理器逐核 SVM 自检 PASS。** CPU0:0..31 各完成一次真实 VMRUN→CPUID退出→原生返回，合计32次；每核有效退出证据/TLB请求1，32个私有VMCB及HSAVE地址互异。候选哈希、逐核集合和代次已独立核验，prepare/selfTest32、failed0，释放后processor/slatReady为0、SCM STOPPED。[原始证据索引与通过报告](evidence/amd-host-self-test-32cpu.json)。这证明本机真实 SVM 短往返可行；尚未测试全核同时常驻、持续负载或再启动 VMware 虚拟机。

**23:38 实体机准入 PASS。** `7004a13c` 候选实际装载/查询/卸载成功；原始输出、候选哈希与最终服务 STOPPED 已独立核验。backendStatus=0、rejectReason=NONE，CR4=B50EF8、XSS=800 保持不变，未关闭 CET。[准入通过证据](evidence/amd-host-admission-pass.json)。此次只探测初始查询 CPU，prepared/selfTest/resident/vmExit 均为0；逐核准备与实体机 VMRUN 尚未验证。下一项是32逻辑处理器逐核串行的短自检与完整释放，不是同时开启32核常驻。

**用户态 CET 兼容候选已实现，尚未硬件验证。** 支持 `XSS.CET_U=0x800` 与 `S_CET=0` 的组合；不关闭宿主 CET，也不修改 XSS。逐核探测读取 CET 枚举与 MSR，支持用户态 CET 时选择 XSAVES64/XRSTORS64，按 CPUID.D.1 EBX 分配 compacted 保存区，使用 XCR0|XSS 掩码；旧 XSS=0 路径保留 XSAVE64/XRSTOR64。当前明确拒绝非零 S_CET、其它 XSS 组件及 XCR0 管理的 CET，新增 v6 兼容拒绝原因 CET_STATE_UNSUPPORTED（13）。

候选归档 `tools/hvm_lab/artifacts/amd-host-cet-user-v6`，SYS/PDB GUID=f0725672-1a1e-4104-890a-1b5744c5c7a9/age13，匹配核验通过。[构建与回归证据](evidence/amd-host-cet-user-build.json) 绑定各文件及构建日志哈希。Release SYS 已按此前宿主成功装载的仓库流程签名（00797B09...）；最终内核信任检查仍报不受信任根，**本候选实际装载与准入尚未验证**。

每次进入重新核对 XCR0/XSS/CET 合约，MSRPM 禁止改变 XSS 或启用 supervisor CET；允许幂等写。VMCB 保存 S_CET/SSP/ISST_ADDR，原生返回恢复当前 ISST_ADDR/S_CET；因 S_CET 必须为零，未引入内核影子栈或伪造其返回链。嵌套固定探针的 VMRUN 状态复制与反射也包含三个 CET 字段，VMLOAD 不复制它们。自检原生返回后核验 XCR0/XSS/S_CET/ISST_ADDR 及进入前 U_CET/PL3_SSP；常驻停止只核对当前状态，不能恢复启动时的用户线程快照。

验证：驱动 Release x64 编译链接、WDK x64 API 与 CAT 校验通过，零警告；主程序、KswordCLI、hvm_ctl 同步构建通过，主程序保留4条既有警告。AMD 74056、嵌套449、生产分派模拟124、Intel85项逻辑检查通过，JSON/PS5 CP936、命令一致性、i18n 和 IOCTL 门禁通过。MASM 产物包含正确配对的 64 位 XSAVES/XRSTORS 指令。以上不代表 CET 硬件执行通过，也未完成启用 CET 的用户线程压力验证。下一步使用现有 Test-HostSvmAdmission.ps1 验证新候选的只读准入，再安排实际自检；旧 VMware 已验收候选保持原样。

**23:14 宿主拒绝原因已确定：CET 状态支持尚未实现。** HVM v6 诊断实测装载/查询/卸载成功，SYS/CLI 哈希与原始证据一致，SCM 独立确认 STOPPED/exit0。`CR4=B50EF8` 命中现有拒绝掩码的唯一位是 bit23/CET；`XSS=800` 启用 bit11/CET_U。全部状态读数有效，HSAVE 已归零，无 SVME 或 SVMDIS。此次没有 prepare、self-test 或 VMRUN，不是物理机常驻通过。[准入诊断证据](evidence/amd-host-cet-admission.json)。

这一结果把下一步限定为状态兼容实现，无需重复加载同一候选：

1. 在 `hvm_svm_resources.c` 逐核读取并验证 CET 枚举、S_CET、ISST_ADDR 等状态，区分用户 CET 与 supervisor shadow stack。XSS.CET_U 只证明该状态组件启用，不能推出内核影子栈已启用。
2. 在资源准备与 `hvm_svm_entry.asm` 配套实现所支持的 XSS 保存/恢复；若采用 XSAVES/XRSTORS，须按 CPUID 的 compacted 格式大小分配，配对保存掩码与格式，不能仅把 XSS 位并入普通 XSAVE 掩码。进入时重新验证 XCR0/XSS 与准备时一致。
3. 在 `hvm_svm_vmcb.c`、汇编及退出恢复路径处理 S_CET/SSP/ISST_ADDR。明确 supervisor CET 的支持边界；支持内核影子栈时必须处理私有 host 栈及 synthetic RET 对应的影子栈连续性。嵌套探针的状态复制/退出反射也须遵循同一边界。
4. 完成布局/状态转换回归、WDK 构建，再进行硬件验证。未补齐前保留当前拒绝；不以关闭系统 CET、清零 XSS 或跳过门槛代替修复。旧 VMware 来宾结果保持其原有范围，不能外推到这组宿主状态。

架构依据：[AMD APM Volume 2](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf)，§18.13 与 Appendix B；本地留存 Rev.3.38 原文确认 CET_U 为 U_CET/PL3_SSP，普通 VMCB 的 S_CET/SSP/ISST_ADDR 偏移为 5E0/5E8/5F0。

**宿主重启后的新阻塞：HSAVE 已归零，探测仍返回 STATUS_NOT_SUPPORTED。** 驱动装载/查询/卸载仍成功，尚未执行 SVM。已构建 HVM v6 诊断版，输出明确拒绝原因及带有效位的 CR4/XCR0/XSS；原准入条件保留。驱动 WDK/API 校验零警告，CLI/主程序构建和现有逻辑测试通过；主程序有4条既有警告，仓库签名工具的最终信任校验仍未通过。实际宿主诊断等待管理员执行 `tools/hvm_lab/Test-HostSvmAdmission.ps1`，不要把此诊断构建记为物理机常驻通过。旧 v5 来宾基线候选保留。

**宿主仅装载测试 PASS：驱动已装载、响应 status 并卸载。** CLI 输出由用户提供，宿主 SCM 独立确认 STOPPED/exit0。HVM 探测返回 STATUS_DEVICE_BUSY（0x80000011）：VM_HSAVE_PA=0x803656000 非零触发保守拒绝，EFER.SVME=0、VM_CR.SVMDIS=0；现有证据不能确认该 HSAVE 的来源或是否存在活动所有者。没有执行 prepare/self-test/resident，不能宣称物理机常驻通过。记录见 [宿主装载证据](evidence/amd-host-load-query-unload.json)。

**22:40 最新硬件结果：八核受控嵌套探针 100 轮 PASS。** 624 个回传文件独立核验；8 核各 100 次，共 800 次完整往返，完成序列均 200，每次 NPF=5、failure=0；控制顺序、逐核集合及电源代次一致，最终资源归零。[八核探针证据](evidence/amd-nested-probe-8cpu.json)。固定探针 1/2/4/8 核阶段已通过；不代表并发内层操作系统、物理宿主常驻或两小时压力通过。接下来推进通用内层 VMM 支持。

**22:37 最新硬件结果：四核受控嵌套探针 100 轮 PASS。** 回传 624 文件独立核验；4 核各 100 次、共 400 次往返，完成序列均 200，每轮 NPF=5、failure=0，控制顺序/CPU 集合/电源代次完整，最终资源归零。同一 age9 候选；报告 [四核探针证据](evidence/amd-nested-probe-4cpu.json)。仍不代表并发内层操作系统通过。

**22:33 最新硬件结果：双核受控嵌套探针 20 轮 PASS。** 144 个回传文件独立核验，CPU 0:0/0:1 各完成 20 次内层进入/反射/返回，完成序列均到 40，每次 NPF=5、failure=0；电源代次一致，最终资源归零。验证器 `tools/hvm_lab/verify_nested_probe.py`，提交内报告 [双核探针证据](evidence/amd-nested-probe-2cpu.json)。保持“逐核串行探针”范围，不视为并发多核内层操作系统通过。

**22:24 最新硬件结果：单核受控嵌套 SVM 探针 1 轮 PASS。** 30 个回传文件哈希/大小独立核验，驱动签名有效、SYS/PDB/CLI 身份匹配、KD 命中新候选。CPU 0:0 完成内层进入 1 次、NPT 缺页 5 次、退出反射 1 次，EXITCODE=0x72、marker=0x4B534E31、completion sequence=2；18 次 full-flush 请求，释放后 prepared/resident/slatReady 全零。报告 `tools/hvm_lab/artifacts/guest-results/verified-nested-probe-one-cpu.json`。此证据更新下方“新候选未加载”的历史状态；尚未测试内层操作系统或并发多核内层 VM。

**最新接线：受控嵌套 SVM 探针已连接实际汇编/退出分派。** 虚拟 MSR、VMLOAD/VMRUN/VMSAVE、真实 NPT02 缺页合成、CPUID 退出反射与原生返回均已写入候选。新增 prepare-svm-probe/self-test-svm-nested、metrics v4 逐核完成证据和一条命令的来宾加载/验收/回传脚本。标准驱动构建及 WDK 校验通过，441 项嵌套逻辑、124 项生产分派模拟和既有 AMD/Intel 检查通过；PS5、CLI、命令/i18n/IOCTL门禁通过。**新候选尚未加载执行，不宣称任意内层操作系统可运行。** 下方“未接入运行时”是前一次提交阶段的历史状态，已由本段更新。

**最新：上一阶段已提交 `4c6cd6a0`，未推送。** 用户中止 8 核压力并提供 `stop OK`：generation 304→305，prepared/selfTestPassed=8、failed/resident=0、VMEXIT=12496。两小时压力不记为通过；8 核 100 轮仍待原始日志核验。现开始嵌套 SVM 第二阶段，已增加 NPT12/NPT01 翻译、预分配影子 NPT、A/D 更新和 VMCB 状态子集模块；新增 427 次逻辑断言及既有 AMD/Intel 逻辑检查通过，WDK 编译链接/ApiValidator 通过。**尚未接入运行时，不支持在 KSword 后启动内层虚拟机。** 新 SYS 未签名/加载，当前共享候选未替换。实现与接线边界见 [第二阶段记录](amd-nested-svm-implementation.md)。

**21:03 最新：4 vCPU、100轮、10秒空闲唤醒 PASS。** 1/2/4核原始日志已回传宿主：1876文件哈希一致；独立解析验证CPU集合、全部20/20/100轮启停、电源代次、末次各核VMMCALL/stage6/failure0及最终资源归零。可复现结果 `tools/hvm_lab/artifacts/guest-results/verified-through-four-cpu.json`。下一步8核100轮及2小时持续压力；故障注入、生命周期和外部网络I/O仍待完成。负载工具在宿主原生2线程smoke通过不算SVM压力通过。

**20:56 最新硬件结果：2 vCPU、20轮、10秒空闲唤醒 PASS。** 两核退出后prepared=0/resident=0；来宾原始目录 `C:\KSwordLab\two-cpu-20260918-205615`，摘要存于 `artifacts/host-20260918/two-20cycles-pass-user-output.txt`。下一步4核100轮，尚无4/8核或持续压力通过证据。

**20:50 最新硬件结果：1 vCPU、20轮常驻启停、10秒空闲唤醒 PASS。** 结束preparedProcessorCount=0、residentProcessorCount=0，soakSeconds=0；来宾证据 `C:\KSwordLab\irqfix-retry-20260918-205003`，用户原始输出已归档 `tools/hvm_lab/artifacts/host-20260918/single-20cycles-pass-user-output.txt`。此前CPU禁用未在这20轮复现；仍不宣称2/4/8核、2小时压力、故障回滚或电源验收通过。下一步正常关机保存基线并改2 vCPU。

**20:44 复测更新：新驱动实际加载通过，测试推进到第5轮stop，采集脚本报输出文件缺失。** 根据第34条控制的顺序，10秒空闲唤醒及前4轮完整启停检查已通过；第五轮停止状态需另查，20轮/多核仍未通过。KD记录新驱动timestamp6AAD2E04及匹配私有PDB。本轮没有CPU禁用报告。采集改成直接并发读取stdout/stderr、等待EOF再写文件；PS5下300次快速退出、双流128KiB、非零退出、空JSON拒绝及超时保留检查通过。旧文件缺失的精确原因未独立复现，此修改去掉异步文件回调依赖。只更新runner后复测，不换驱动。

**20:29 最新：已修复确定存在的中断配置缺陷，硬件重测待执行。** 首次手动单核常驻/停止成功，但之后自动测试首轮 resident 在 generation=9 挂住；并非20轮通过。保留8 GiB来宾内存、原始VMware日志及旧候选，现场确认 VMCB.INTCTL=0x01000000、resident=1、自检以外无新的退出记录、BugCheck数据全零。VMware CLIHLT发生在12:14:02Z，12:16:45Z渲染进程崩溃是后续事件。没有保存成功的VM快照。

`hvm_svm_vmcb.c` 将 V_INTR_MASKING 清零，让 guest IF/CR8 管理物理中断；原值1会使用入口CLI后的host IF=0，无法通过guest STI恢复物理IRQ。依据 [AMD APM Volume 2 §15.21.1–2](https://www.cs.wm.edu/~smherwig/readings/manuals/amd/sdm/amd64_arch_programmers_manual-vol2-system_programming.pdf)。这是与停机现象一致的缺陷，不能在复测前断言它是唯一根因。runner首轮增加默认10秒空闲等待，记录唤醒及全核状态，不把繁忙循环当作中断验证，也不宣称保证每核进入HLT。

新候选位于 `tools/hvm_lab/artifacts/amd-candidate-irqfix` 并同步只读共享目录；SYS/PDB匹配，GUID f0725672-1a1e-4104-890a-1b5744c5c7a9/age5。Release x64编译链接和x64 WDK Universal校验通过；发行自动签名信任检查失败，隔离候选已改用原来宾实验签名，未新增宿主信任。AMD73907/Intel85逻辑检查通过；PS5 runner语法通过。克隆已冷启动且KD重连恢复运行；新候选加载、空闲唤醒及1核20轮尚未验证。此后才进入2/4/8核。

## 以下为早期逐次记录

**首次真实单核自检已通过（2026-09-18）**：self-test=OK，generation=3，selfTestPassed=1、failed=0；CPU 0:0 捕获一次 EXITCODE=0x72/CPUID，NRIP-RIP=2，TLB 请求=1，ring valid=1，failureStatus=0，原生返回后自检成功。尚未常驻启停或多核。下一步单核 resident/status/stop/status。通用 metrics 的 command/transition 未随 AMD 自检更新，必须使用 svmProcessors 的新代次和退出记录；该观测缺陷待修复。受控小型内核转储已生成并离线打开（有限寄存器/栈），来宾崩溃后完整转储落盘仍未验证。

单核准备与调试续记：用户 prepare/status/metrics 实测成功，generation=2、prepared=1、slatReady=1、CPU 0:0、NPT 根非零、failureStatus=0。尚未 VMRUN。控制响应 failedProcessorCount=1 是旧的总核数减自检通过数算法；通用 metrics 的 processorCount 不包含 SVM 数组；HsavePa 在 BuildVmcb 才写入。宿主 KD 已实际加载候选私有 PDB，命中一次性 KswordARKHvmQuery 断点并记录从 query、IOCTL handler 到驱动分发的调用栈，随后自动继续；日志 `tools/hvm_lab/artifacts/host-20260918/kd-svm-preflight.log`。普通断点链已验证。

2026-09-18 最新：用户已报告修复后的 Load-GuestCandidate 返回 PASS，中文 JSON 正常，signature=0/Valid，state=INITIALIZED、generation=1；资源、自检、常驻计数均为零。加载阻塞解除，下一步只执行单核 prepare 并回读 status/metrics；VMRUN 尚未执行。来宾证据位于 `C:\KSwordLab\candidate\driver-load-20260918-111425-db464b7394514425838c859184b49ac2`。

- 宿主实验启动成功，HypervisorPresent=false、VBS=0；日常恢复方向尚未测试。
- 独立 VMware 克隆为 Windows 10 家庭中文版 19042、1 vCPU/8 GiB、Secure Boot=false。CPL0、SVM/NPT 外层日志已保存；原 VM 未修改。
- 来宾初始化完成并重启；WinDbg 已连接内核。普通驱动断点、匹配符号的实际加载和受控转储链仍待验证，连接成功不替代这些证据。
- 用户实测候选加载脚本到达最后 JSON 解析处：签名信任、SCM RUNNING 检查及状态 IOCTL 已成功；AMD 响应 backend=2、slatType=2、ASID=64、physicalBits=45、msrValidMask=15、VM_CR=8、EFER=0x4D01、HSAVE=0。状态仅 INITIALIZED，未 prepare/self-test/resident。
- 阻塞根因已在宿主复现：合法 UTF-8 `没有拒绝过` 经过代码页 936 解码后，末尾 UTF-8 字节和 ASCII 引号一起变坏，JSON 解析失败；437 只乱码，65001 正常。不能归因为驱动返回了损坏的 JSON（JSON 在用户态生成）。
- 修复：共享 JSON 字符串打印器转义为 ASCII 的 Unicode escape，保留原字段及中文语义；query 使用该打印器。CLI Release /W4 /WX 构建通过；真实 query 格式化代码的模拟响应通过 PS 5.1/936 管道，含特殊字符、非 BMP 与非法 UTF-8 测例；命令一致性 60 命令通过。
- 加载脚本支持正在运行且规范化路径精确匹配的候选，不 stop/config/start；从只读共享目录更新 CLI/identity 前核对原 SYS/PDB 哈希，绝不覆盖驱动。日志分开保留 stderr；修复 PS 5.1 provider 属性递归序列化造成的耗时。7 项模拟服务/更新测试通过，修复后仍需来宾实际重跑。
- 下一步在已登录克隆运行共享目录的 Load-GuestCandidate.ps1。确认 status 可解析后，先完成 KD/转储证据，再执行单核 prepare/self-test；不能跳到多核压力。

## 2026-09-17 至 09-18 早期记录（不是当前状态）

目前是可编译的实验候选，**尚未执行第一次来宾 VMRUN，未证明单核或多核常驻可用**。
本文件用于重启后续接，不能用作硬件通过报告。源代码尚未提交；候选清单绑定基准提交与修改文件哈希。

2026-09-18 续记：上述实现已提交为 `d6218fd7`，未推送。首次管理员运行环境脚本在只读 OpenObject 处发现 WMI 嵌入对象缺少实例方法，尚未执行 BCD 修改。已补充显式实例绑定及 8 项真实 System.Management 类型/schema 回归；策略 12 项和模拟事务 21 项继续通过。等待管理员重试，宿主往返和 AMD 硬件测试仍未通过。

同日实验启动成功：脚本核验 `LabHostReady`，独立读取的宿主状态为 HypervisorPresent=false、VBS=0。独立克隆以 1 vCPU/8 GiB 冷启动；VMware 日志为 `Monitor Mode: CPL0`，并报告 hv-svm/gphys-npt、SVM/NPT/NRIP 能力，Tools 运行。该结果证明外层实验条件，**不证明 KSword 曾执行 VMRUN**。来宾 Tools 不允许使用空密码的远程操作，因此已将候选与受限 Bootstrap-GuestLab.ps1 放入只读共享目录；来宾预检、Secure Boot 处理、KD、候选加载与第一次 SVM 自检尚未执行。

## 已实现与已验证

- 新增 AMD 能力/有效位、资源账本、VMCB 布局、独立汇编入口、退出处理、完整身份 NPT、逐核诊断及公共生命周期接入。
- 逐核集合检查、准备/自检电源代次、进入失败后停止已进入核、无法证明退出时保留资源/卸载保护；实现这些路径不等于已验证其硬件行为。
- 主协议 v5、metrics v3、CLI/GUI 的 AMD 展示与 Intel 专用命令拒绝。
- 两个宿主入口、只读启动核验、独立 VMware 全克隆、来宾配置与命令日志/亲和性负载脚本。
- 标准 MSVC/WDK Release x64 编译和链接通过，驱动零警告；WDK x64 输出 `Driver is 'Universal'.`；Inf2Cat 构建目标通过。
- AMD 纯逻辑测试 73,907 次断言、既有 Intel 85 项检查通过。前者包含循环边界枚举，不能解读成同等数量的独立硬件测试。
- 启动策略 12 项、模拟 BCD 事务 21 项通过；无实际 BCD 往返。CLI 命令一致性、IOCTL 风险门禁、功能矩阵门禁通过。
- hvm_ctl、KswordCLI 和包含 AMD 主菜单修正的 GUI Release 构建通过；GUI 语言门禁通过。GUI 保留两条已有宏重定义警告及部署工具的 dxcompiler/dxil、VCINSTALLDIR 提示，不能称为零警告构建。最终本机日志为 `tools/hvm_lab/build-gui.log`。

本机日志与候选在 `tools/hvm_lab/` 的忽略目录内，不入 Git。`collect_identity.py` 从 SYS 的 RSDS 与 PDB info stream 独立核对 GUID/Age，并记录 SYS/PDB/CLI 哈希；日志哈希不等于对应测例已通过。

## 签名与加载分开记录

仓库原自动测试证书验证遇到 `0x80096019`（basic constraints），不是单纯缺少信任。
隔离候选改用 `Sign-LabCandidate.ps1` 创建的代码签名证书，已写入候选 SYS；私钥不可导出。
该脚本不安装宿主信任。公开 CER 需仅在克隆中导入并验证；**来宾证书信任、内核签名验证、实际加载都未完成**。
常规 GUI 构建仍会执行仓库既有自动签名流程，其签名写入不能当作信任验证通过。

## 实验环境与缺失证据

宿主是 Windows 10 19045、Ryzen 9 8945HX、32 逻辑处理器，最近只读清点时 Hypervisor 运行、VBS=2。
Workstation 16.2.5 build-20904516 已确认。独立完整克隆固定硬件 19、单插槽、8 GiB、初始 4 vCPU；位置见本机 `host.local.json`。
克隆清除挂起 checkpoint 引用，原 VM 未启动或修改。克隆尚未启动，实际来宾 Windows 版本、干净关机快照均未确认。

以下全部未运行：

1. 管理员执行进入脚本 → 重启 → `LabHostReady` → 日常启动恢复实测。
2. VMware 原生模式日志（CPL0）、来宾 CPUID/MSR SVM/NPT/NRIP/ASID 证据。
3. 来宾测试签名与 KD 配置、普通驱动断点、匹配符号、内核转储链验证。
4. 1 vCPU 实际 SVM 往返及 20 次启停；2 vCPU 20 次；4/8 vCPU 各 100 次。
5. 8 vCPU 两小时压力、逐核失败注入与真实回滚、并发控制、卸载、电源生命周期。
6. 外部网络 I/O、Intel 硬件回归、多 Processor Group 硬件验证。

当前会话缺少提升后的管理员令牌，不能执行宿主 BCD 切换。下一步由用户在管理员 PowerShell 中运行进入脚本；重启后回到本任务继续。不要把脚本 `PendingReboot` 当成实验已可运行。

用户决定今天暂停硬件验证：本地提交后直接正常关机，不推送、不安排实验启动；明天继续上述验证。

## 与计划的差距

- 首版强制要求 NRIP，未实现固定指令编码回退；非零 XSS、活动 CET/LA57/PKS/UINTR、物理地址超过 48 位明确拒绝。
- Intel 保留原执行路径，后端调度边界首先接入 AMD，尚未把 Intel 全部动作改成统一 ops。
- NPT 缓存属性合成、GIF/IF/NMI、XSTATE、GS/描述符及原生返回链仅做静态实现与编译，必须优先实测；不能保证首轮不会崩溃。
- 未知退出保留诊断后走确定故障路径；尚未证明 host 故障时来宾 KD 或转储一定可用。
- metrics 导出最新一致记录；完整每核 64 条 ring 需 KD/转储。故障注入点是每 CPU 分配完成、进入前、进入后，非每次分配的独立注入。
- 压力脚本的 UDP 是本机环回，不替代虚拟网卡外部网络验证。

## 可行性边界

Windows 10 的 Hyper-V 外层不满足微软对 AMD 嵌套宿主的版本要求（需要 Windows 11 或 Server 2022+）：[微软文档](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization)。本项目不通过升级系统或更换电脑解决。

本期路线是停用本次启动的宿主 Hyper-V/VBS，让 VMware 原生 AMD-V 向 Windows 10 克隆暴露 SVM，再测试 KSword；这条路线尚待本机证据确认。
“KSword 常驻后再向内层 Hyper-V/VMware 提供 SVM”未实现，也不在本期验收范围内。

## 双核阶段准备

双核阶段准备已完成：克隆正常关机后建立冷态快照 AMD-1CPU-20Cycles-PASS-20260918（listSnapshots确认1项），只修改克隆numvcpus=2/cpuid.coresPerSocket=2，内存仍8192MiB。重新冷启动，VMware日志NumVCPUs=2/MonitorMode=CPL0，KD初始断点已g，Tools running；共享已enable并重新设置readonly。KD在系统引导早期显示1 procs不代表最终拓扑，来宾runner会核验2逻辑处理器。下一步来宾Load-GuestCandidate后Invoke-GuestAcceptance -Vcpu 2 -Cycles 20；当前双核尚未运行KSword自检/常驻。

## 下一阶段范围变更

2026-09-18 用户调整优先级：不再把两小时压测作为当前阻塞项，要求立即推进AMD功能向Intel对齐，先提交当前进度且不推送。下一阶段授权实现嵌套SVM（含内层VM运行所需的VMCB/退出反射/NPT合成），不再受首期“不实现嵌套SVM”的范围约束。Win10、不换电脑、不推送仍有效。已确认硬件验收仍只记1/2核20轮、4核100轮；8核及压力未获结果，不补记成功。正在询问压力是否已启动，以便单独收尾，代码工作继续。
