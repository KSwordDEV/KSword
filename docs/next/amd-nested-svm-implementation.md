# AMD 嵌套 SVM：第二阶段实现记录

## 2026-09-21 通用实验入口（优先于下方历史）

`prepare-svm-general → self-test → resident-svm-general → stop → teardown` 已有从命令目录、协议、准备配置、逐核绑定到实际汇编入口的调用链。GENERAL 与有界 PROBE 配置互斥，启动必须匹配准备时的配置；原普通常驻不自动开启通用嵌套。成功进入只发布 `PARTIAL`，不宣布内层操作系统兼容。首次硬件 INVALID 的撤销要求 native/EFER/HSAVE 回读和严格的首次进入证据，后续执行失败不能套用该清理路径。

本次驱动标准 WDK Release x64 编译链接、x64 ApiValidator Universal 和 CAT 生成通过，零警告；`hvm_ctl`、KswordCLI、GUI 构建通过。GUI 有4条既有宏重定义/Qt部署警告；其构建自带 i18n/theme 门禁运行。新增 HVM 源用例仅编译链接，未运行；CLI 参数回归源用例已补入新命令，尚未执行。没有签名、替换共享候选、加载驱动或启动虚拟机。

此入口仍是实验实现：事件协调器中的 `WINDOW` 返回会进入保留现场的故障路径，不能视作自动恢复或无害跳过；NMI shadow/事件碰撞等剩余实现边界须按最新收尾记录处理，不能把“入口接通”写成“完整 L2 静态完成”。

2026-09-21 静态VIRQ复用：VINTR临时请求按排队IRQ与原V_IRQ的可投递条件并集唤醒，保存/恢复原vector/priority/IGN_TPR；已就绪的物理确认事件优先（APM15.21.4），原虚拟IRQ只在队列阻塞时按原IF/TPR/shadow投递，原EVENTINJ不改。L1要求VINTR反射且L2仍持确认队列时继续保留WINDOW，未伪造EXITINTINFO。扩展源用例未执行；WDK/API/CAT零警告通过build-nested-virq-20260921.log。GUI metrics v5整批构建最终成功（build-gui-metrics5-20260921.log），共8条既有宏重定义/Qt部署警告，链接器自行从32位重启到64位后成功；未手动替换工具链。GUI构建自带i18n/theme门禁自动执行，无HVM测试或硬件运行。

2026-09-21 静态重复启停：实际native寄存器核验通过后，CompleteNative再次检查general stop动作/lease/队列/NMI/窗口为空，再关闭NestedEntryEnabled与绑定标志；保留诊断至下一次明确初始化。下一次绑定重取Windows当前状态并重置本次运行计数，不复用旧continuation。部分初始化的odd sequence拒绝重试，需正常释放/重新prepare。WDK/API/CAT零警告通过，日志build-nested-retire-20260921.log，也覆盖上一阶段最后raw-exit字段微调。无运行验证。

2026-09-21 静态诊断协议：metrics独立升v5，SVM行新增general快照，以64位sequence覆盖root入口/退出/NMI事务，区分preparedEntries与实际hardwareExits，保留phase/action/GIF/lease/事件token/XSTATE/取指状态。共享头、命令引擎JSON、当前验收脚本及源fixture同步；历史证据验证器接受v4/v5不变的probe子集。驱动WDK/API/CAT与hvm_ctl、KswordCLI编译链接通过；最后raw-exit保留字段微调仍需增量编译。GUI同批构建进行中，自动运行其既有i18n/theme门禁（不是手动执行HVM测试），还未取得最终链接结果。无HVM测试/装载/签名/暂存或推送。

2026-09-21 静态汇编桥：NestedEntryEnabled新增固定偏移140并断言；完整general绑定后才发布。真实VMRUN前在最终RIP/RFLAGS/host stack就位后调用事件准备，真实VMEXIT原始计数后进入machine；非READY/NATIVE均保留故障，不能盲目继续或恢复L2为native。普通/受控probe零值保持原路径。WDK Release/API Universal/CAT零警告通过，build-nested-entry-bridge-20260921.log；无签名/装载/测试。InitializeGeneral尚无正常控制入口调用，公共能力不开放；NMI/IRET、原VIRQ优先级和复杂事件重试仍未全部实现，不能称完整静态完成。

2026-09-21 静态IRQ/异常碰撞：排队IRQ允许在既有EVENTINJ保持原值的同时挂VINTR等待窗口；原异常先投递，随后按handler实际IF/TPR/shadow等待IRQ，token不提前消费。NMIshadow/原L1 V_IRQ碰撞继续保留WINDOW，不能冒充已解决。补window离线源用例。build-tests.cmd新增--build-only；当前全部宿主测试目标/W4/WX编译链接完成，明确TEST_EXECUTION=NOT_RUN，未执行测试。日志build-static-fixtures-20260921.log。

2026-09-21 静态操作数捕获：nested_fetch从L1四级页表经NPT01读取硬件RIP..NRIP范围，逐层重查映射、限制WB/RAM、不直接解引用guest地址；跨页失败保留，不伪造guest PF。SVM隐式rAX解码识别执行模式/67h/repeated prefix/REX，覆盖VMRUN/VMLOAD/VMSAVE/INVLPGA并接general执行器。L1 legacy非LMA取指仍明确不支持；L2不暴露SVM。新增离线源用例未运行。WDK Release x64、API Universal/CAT零警告通过，日志build-nested-fetch-20260921.log；未签名、未装载，通用激活仍未开放。

2026-09-21 用户允许编译，仍不执行测试/装载。累计general/停止代码首次WDK链接因hvm_svm_nmi.c与同名.asm输出同一OBJ触发LNK4042/LNK1218；汇编改名hvm_svm_nmi_entry.asm并同步工程。随后标准MSVC/WDK Release x64完整Build退出0，ApiValidator Universal、CAT生成通过，零警告。日志tools/hvm_lab/build-nested-static-20260921-r2.log。未签名、未暂存到来宾、未运行任何新测试；不等于通用激活完成。

2026-09-21 静态停止协调：新增 nested_stop，general上下文采用同一次IPI内的逐核只读quiesce投票、统一commit/abort决定和原生恢复后的第二道屏障；核身份逐项校验，250ms软件等待预算。根模式只检查本核，不等待。投票后新NMI/故障仍可能造成部分退出，必须保留实际Active/NativeReturnSeen和卸载互锁，不声称硬件原子回滚；KeIpiGenericCall本身无可取消超时。普通常驻沿用已有路径。未编译、未执行测试/装载；通用激活与复杂事件语义仍待完成。

## 当前边界（2026-09-18）

2026-09-21 更新：权限图合并与NPT01操作数读取候选已通过1vCPU/1轮、8vCPU/100轮真实受控探针。八核导出624文件独立核验，800次逐核往返完整，最终资源释放。见[八核新路径证据](evidence/amd-nested-operand-8cpu.json)。此项仍是固定载荷的串行逐核自检，未验证并发内层vCPU或完整L2操作系统；后续应推进通用VMCB/中断/状态恢复实现，而非重复固定探针。

2026-09-19 更新：物理AMD宿主32核完成并发常驻、5秒等待、全部退出、资源释放及驱动卸载，原始证据独立回放通过，见[实体机短常驻证据](evidence/amd-host-resident-32cpu-5seconds.json)。此时KSword是L0，原Windows在L1运行。用户随后在常驻期间启动VMware，报告AMD-V/RVI不可用及MonitorMode失败；完整L2虚拟机尚未启动。普通常驻仍隐藏SVM，通用转发未开放。用户附件SHA256为`81F5388293066A4AFA7B35A41742F12EA059E5A59A69D3379D39BF3E072C338C`，附件确认32核Active，VMware错误来自用户文字而非独立VMware日志。

22:40 更新：8 vCPU/100轮串行逐核探针通过，624文件独立核验；800次往返完整，八核最后sequence均200、每轮NPF5、无失败，资源归零。[八核探针证据](evidence/amd-nested-probe-8cpu.json)。固定探针的1/2/4/8核矩阵已完成，后续工作以通用内层VMM入口与真实OS覆盖为主；仍不能据此发布任意内层VMware兼容。

22:37 更新：4 vCPU/100轮串行逐核探针通过，624文件独立核验；各核完成序列200，每轮NPF5，无失败，释放完整。[四核探针证据](evidence/amd-nested-probe-4cpu.json)记录400次CPU往返及原始导出manifest哈希。

22:33 更新：同一候选在 2 vCPU 完成 20 轮逐核探针，40 次 CPU 往返均通过。144 个文件哈希/大小、逐条控制顺序、精确 CPU 集合、递增完成序列、电源代次和最终资源释放独立核验。两核最后 sequence=40、每轮 NPF=5。报告见 [双核探针证据](evidence/amd-nested-probe-2cpu.json)，可使用 `tools/hvm_lab/verify_nested_probe.py` 从原始导出重新验证。此项仍是串行逐核执行。

22:24 更新：1 vCPU/1 次受控硬件探针已通过，导出 30 文件独立核验。每核 entries=1/reflections=1/NPF=5，原始退出0x72、内层marker0x4B534E31，原生返回后完成序列2；teardown后资源归零。SYS/PDB age9匹配，来宾签名/加载及KD私有符号已确认。下文“尚待硬件”的表述记录接线时状态，以本段为最新结果。该自检按CPU串行运行，后续多CPU探针也不能替代并发内层OS验证。

上一阶段已本地提交 `4c6cd6a0`，未推送。1/2 核各 20 轮、4 核 100 轮启停已由回传原始日志独立核验。
用户暂停 8 核压力时，`stop` 返回 OK：generation 304→305，prepared=8、selfTestPassed=8、failed=0、resident=0、累计 VMEXIT=12496。
这证明该次全核停止成功；两小时压力是用户中止，不记为通过，也不据代次数量补记 8 核 100 轮验收。

本阶段目标是在 KSword 常驻后向内层 VMM 提供 SVM。现已接通受控探针的实际资源、汇编和 VMEXIT 分派：虚拟 EFER/HSAVE、VMLOAD/VMRUN/VMSAVE、稀疏 NPT02 缺页合成、CPUID 退出反射及原生返回。**代码与模拟测试完成，新的硬件往返尚待执行；还不能启动任意内层操作系统。**
现有 AMD 常驻入口仍隐藏 SVM。专用 `prepare-svm-probe` / `self-test-svm-nested` 仅允许驱动拥有的固定 VMCB/指令序列；探针准备配置禁止 resident。新候选使用独立目录，原 irqfix 候选保留。

文中 NPT12/NPT01/NPT02 的编号以 KSword 为参考层：内层 VMM 的映射、KSword 的映射、合成映射。
“host physical”是 KSword 所见物理地址；当 KSword 自身运行于 VMware 时，不表示已经取得物理宿主的真实机器地址。

## 已写入源码

2026-09-21 操作数读取增量：新增`hvm_svm_nested_operand.c/.h`，将权限图读取接到NPT01翻译与受控RAM物理窗口。支持非身份映射及4K/2M/1G外层叶，拒绝不适用的缓存属性、缺页、不可读物理字与复制期间的结构性remap；失败清空目标页，权限图Ready保持无效。复制后的页表重验仅忽略A/D变化，不保证对并发数据写入的原子性。固定探针的VMRUN地址/标记约束仍在，尚未提供通用VMCB合法性、状态切换、IRQ/NMI/GIF和跨核失效契约。

新增1049项操作数检查，包括512个逐字失败点与非身份地址；生产分派模拟180项通过，权限图917803/AMD74056/嵌套449/Intel85回归通过。标准驱动Release编译链接、x64 API验证、CAT生成零警告，匹配CLI已构建。硬件验证需使用本轮独立候选；这些逻辑结果不能替代L2操作系统启动证据。

2026-09-19 权限图增量：`hvm_svm_nested_permissions.c/.h` 实现按启用位捕获8 KiB MSRPM/12 KiB IOPM、MAXPHYADDR完整范围检查（按APM忽略基址低12位）、失败撤销Ready、L0/L1按位OR合并以及MSR/IOIO退出归属查询。MSR范围外访问仅在MSR_PROT启用时隐式拦截；I/O按1/2/4字节检查，包括65535端口之后的三个尾部位，不能回绕到端口0。L0与L1共同请求时返回双重归属，未来分派须先反射L1，不提前执行MSR/I/O副作用。

受控探针现已实际调用捕获和合并器：每核PASSIVE_LEVEL新增20 KiB连续硬件权限图，进入内层前完成私有快照与合并，VMCB02仅使用合并后的自有物理地址；退出后恢复L1原权限图指针。探针读取适配器仅接受本CPU已拥有的固定权限图；通用L1物理地址的NPT01/RAM/cache验证读取适配器仍待接线。捕获不是相对于并发L1写入的原子快照，也没有实现跨核权限图失效；本次不得宣传通用嵌套支持。

本增量完成标准MSVC/WDK Release x64编译链接、x64 ApiValidator及CAT生成，零警告/错误；权限图917803项断言（含全端口及所有启用组合）、生产探针分派158项模拟检查、AMD74056/嵌套449/Intel85项通过。未签名、未加载、未执行新硬件验证，普通常驻仍隐藏SVM。新Release SYS不能冒充此前已签名的7004a13c候选；旧候选保存在本地`tools/hvm_lab/artifacts/amd-host-cet-user-v6`，测试脚本原哈希锁仍在。今晚按用户要求停止动态验证并关机。

| 模块 | 实际行为 |
| --- | --- |
| `hvm_svm_nested_npt.h` | AMD 四级页表遍历；4 KiB/2 MiB/1 GiB；MAXPHYADDR、保留位、Present/RW/US/NX 校验；PAT 索引解码；完整路径记录；比较交换更新 A/D；WB/UC 4 KiB 叶项合成 |
| `hvm_svm_nested_mmu.c/.h` | NPT12→NPT01 翻译，连 NPT12 的页表页也经 NPT01 转译；区分内层 NPF、外层页表 NPF、外层数据 NPF、物理读取失败；保留 EXITINFO1[33:32]；源 A/D 提交后才输出叶项 |
| `hvm_svm_nested_shadow.c/.h` | 使用预分配页创建稀疏 NPT02；最多每 CPU 256 页；预算不足不修改原树；重置推进 epoch；拒绝过期或混合来源的结果；全部修改标记需 TLB flush |
| `hvm_svm_nested_state.c/.h` | 分开搬运 VMRUN 与 VMLOAD 状态；反射 baseline VMEXIT 字段时保留 VMCB12 控制字段/物理指针；CR/DR/异常及两组杂项 intercept 分类，未知范围单独返回 |

新增 `hvm_svm_nested_resources.c` 在 PASSIVE_LEVEL 分配每核 64 页影子池、8 KiB VMCB/虚拟 HSAVE 操作数和私有栈；真实物理窗口回调仅允许保留的 RAM 清单内对齐八字节读取/CAS。`hvm_svm_nested_probe.c` 处理专用退出状态机，真实汇编探针执行虚拟 MSR/SVM 指令和内层标记。所有源码已加入工程和 filters，逐句注释、单文件小于 1000 行。

HVM v5 增加 SVM_NESTED_PROBE 控制标志（仅 prepare/self-test，Intel 拒绝）。metrics 独立升级为 v4，逐核记录 nestedProbe 的完成序列、状态、进入/反射/NPF 数和原始退出码。完成序列仅在真实返回并核对原 EFER/HSAVE 后变为有效偶数；旧 metrics v3 客户端明确拒绝。命令目录、help、双语词条与 CLI 文档同步。

## 调用约束，接线时不可省略

1. MMU 回调只接受已核验 RAM 的物理页，使用每 CPU `hvm_phys_window`；不能对任意 guest PA 做 WB 映射。Windows 适配器已接入，完整对齐八字节读、原子 compare-and-OR 均不在 root 路径分配或等待。
2. `Config.Epoch` 是证据标签，不会自动持锁或监视页表。调用者须持有同一 NPT01 生命周期/失效代次，在 VMEXIT 中解析和安装；页表/CPU 资源均预先分配。不能只把相同整数写进两个结构体就认为没有竞态。
3. 首个读映射刻意清 RW，使第一次写再次 NPF，经源叶项 D 更新后才可放开 RW。A/D 回写使用 CAS，不覆写并发 remap；失败输出 Leaf=0。部分已经设置的 A 位可以保留。
4. `FlushPending` 只是请求。下一次真实 VMRUN 必须设置 TLB_CONTROL 完整 flush；不能把软件 Reset 当作硬件失效。进入内层 VMRUN、虚拟 INVLPGA、NCR3/ASID/TLB 请求切换均需处理软件缓存失效。
5. 四级页表当前接受 32–48 位物理宽度。带 PWT/PCD 的 NCR3、五级页表及扩展保护语义尚未接入，须在入口明确拒绝，不能静默屏蔽后继续。
6. 叶项合成只实现 WB/UC 子集；这不等于完整三层 PAT/MTRR 虚拟化。正式入口还须检查内层 guest PAT、虚拟 MTRR/CD 语义；不能仅因当前某页使用 WB 就对内层 VMM 宣称全部缓存模式可用。
7. 状态搬运函数只操作已拥有的 VMCB 快照，不做 guest 物理读取或合法性审查。LBR/CET/SEV/AVIC/VGIF 等扩展不在这些 baseline 拷贝函数的支持范围。VMRUN 合法性校验、段 canonicalization、虚拟 host restore 和 GPR/RAX/RSP 特例必须在入口/退出状态机处理。
8. MSR/IOIO 原始 intercept 位只表示需要进一步查权限图，不等于直接反射。权限图捕获、合并与细粒度ownership查询已实现，受控探针已接入合并；通用分派的反射/本地仿真、并发失效仍待实现。未知退出不能盲目重入。

## 本轮验证

`tools/hvm_lab/build-tests.cmd` 使用 MSVC `/W4 /WX` 编译生产源码并执行：

- 新增嵌套逻辑 441 次断言通过：非身份页表/数据映射、大小页边界、权限/保留位、故障归属、A/D 竞争、缓存拒绝、预算回滚、过期代次、循环指针、状态字段所有权、intercept 和虚拟 MSR。
- 生产探针分派代码 124 次模拟退出检查通过，包括完整进入/NPF/反射/返回和错误操作数、错误标记、INVALID、NPF 失败的原生恢复路径。模拟不执行汇编或 SVM 指令。
- PS5.1 验收谓词 16 项通过；采集器真实子进程 300 次快速退出、双流大输出、空输出/非零退出/超时保留通过；CLI 实际 JSON 格式器与 CP936 管道、62 项命令目录和双语检查通过。
- 原有 AMD 73,907 次断言与 Intel 85 项检查通过。
- 标准 MSVC/WDK Release x64 编译链接、x64 ApiValidator（`Driver is 'Universal'.`）和目录生成通过，零警告、零错误。
- 标准构建跳过自动发行签名，候选单独进行实验签名；签名与加载分别记录。**新 SYS 尚无加载及硬件运行通过证据**。
- 主程序与 KswordCLI Release 编译链接通过。主程序有四条既有宏重定义/部署警告，自动 GUI 签名校验仍返回 0x80096019；不计为驱动候选签名结果。新驱动候选已用原实验签名证书签署并回读匹配，宿主未信任该实验根；来宾加载需独立确认。

本机原始日志：`tools/hvm_lab/artifacts/host-20260918/nested-probe-tests.log`、`tools/hvm_lab/build-nested-probe.log`。
测试回调使用模拟内存，不能证明真实页表写入、SVM 指令执行、IRQ/NMI、ASID/TLB 或内层虚拟机启动。

## 硬件入口和后续工作

在冷启动的 1 vCPU 调试克隆执行共享候选中的 `Start-GuestNestedProbe.ps1`。该入口要求原服务 STOPPED，验证 SYS/PDB/CLI 哈希后复制到新的独立目录，加载候选，再调用 `Invoke-GuestAcceptance.ps1 -NestedProbe -Vcpu 1 -Cycles 1`。逐核结果不完整即失败；超时不结束控制进程、不推断已回滚。运行日志和匹配身份清单自动回传 KSwordResults。先证明一个硬件往返，再增加轮次和 CPU。

当前探针的 NPT12 使用已拥有的身份页表，NPT02 从空树按真实 NPF 构造；非身份映射仅有逻辑测试。GIF 只在 IF=0 的固定短序列中记账，不声称支持任意 IRQ/NMI 嵌套。失败时恢复初始 Windows 快照仅适用于这个有界自检，不能用于正常运行的内层 VMM。下一步仍需：

1. 将已拥有固定 VMCB 的专用入口扩展为任意内层 VMCB 的快照/合法性检查，增加 MSRPM/IOPM 合并和实际 CPUID 能力发布门槛。
2. 将探针虚拟 MSR/VMLOAD/VMSAVE/STGI 扩展到一般入口，补齐 CLGI/INVLPGA、异常注入、IRQ/NMI/GIF 语义。HSAVE 是虚拟所有权，不能依赖真实硬件 HSAVE 格式，也不能写入真实 MSR让内层接管。
3. VMRUN 校验并保存 L1 continuation，构造 VMCB02，真实进入内层；VMEXIT 按 intercept 所有权反射或本地处理。保存/恢复 GIF/IF、CR2/DR、GPR、VMLOAD 状态；现有宿主 IF=0，不能再次错误设置 V_INTR_MASKING 导致 IRQ 饥饿。
4. 用可控的极小内层 VMRUN→CPUID 探针证明一次往返，再测非身份 NPT、内层异常/NPF/关机、全核 stop。通过后再向 VMware 内层系统开放，单核到多核推进。

架构依据：[AMD APM Volume 2](https://docs.amd.com/api/khub/documents/sD1_QL~h4Afq2_tvzxqqSQ/content)，重点 §15.5–15.7、§15.21、§15.25；可检索的 [AMD 原文镜像](https://www.scs.stanford.edu/~zyedidia/docs/x86/amd-manual.pdf)。未复制第三方 hypervisor 源代码。
