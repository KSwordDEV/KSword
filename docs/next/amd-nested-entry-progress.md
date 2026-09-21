# AMD 通用 VMRUN 事务（2026-09-21）

最终验收仍是完整 L2 操作系统启动及内层 vCPU 并发运行；本变更没有完成该验收。

最新静态增量：`nested_reflect` 统一指令与物理事件反射；先检查整个 L2 事件集合，确认 token 对应真实被打断的递送，再提交 VMCB，成功后才消费该确认记录。未开始的排队事件、不同 owner 或多项积压不伪造 EXITINTINFO，保留 WINDOW。新增交接边界用例仅编译，没有执行。标准 WDK Release x64 / API Universal / CAT 构建零警告（`tools/hvm_lab/build-nested-reflect-20260921.log`）；宿主用例编译日志明确 `TEST_EXECUTION=NOT_RUN`。通用激活及 NMI/IRET 等剩余路径未完成。

10:11 宿主冻结后硬件验证暂停，故障取证见 [事件记录](evidence/amd-host-freeze-20260921.md)。`nested-entry-20260921` 保存的是 `4ec4d724`、PDB age 5 候选，硬件未执行；后续退出路由改动只做离线测试和构建，没有覆盖该已签名候选。

已实现并接入生产受限探针：

- `hvm_svm_nested_entry` 对私有 VMCB12 做模式、ASID、权限图范围、PAT、事件等准入，区分架构 INVALID 与尚不支持的特性。组合 VMCB02 的拦截、TSC offset 与自动状态，硬件指针全部来自 L0 预分配资源。
- `hvm_svm_nested_writeback` 在稳定 NPT01 上重新验证写权限和捕获时的 HPA，再调用 RAM 窗口提交。VMEXIT、INVALID、VMSAVE 使用三个固定字段集合；保留控制指针、保留位和共享字内不属于硬件输出的位。跨页、缓存属性不符、物理映射改变都拒绝；部分提交保留进度，不能自动重试。
- `hvm_svm_nested_session` 每次 VMRUN 保存实际 L1 continuation，支持任意已翻译的 VMCB 地址。INVALID 写回后正常返回 L1，修正操作数可再次进入；真正 VMCB02 的硬件 INVALID 是 monitor 故障，不伪装为 L1 责任。反射保留当前 VMLOAD 状态、CR2、DR6 与非自动 GPR。
- 探针改为先故意 ASID=0、检查退出字段 INVALID、修正同一 VMCB 后再实际进入内层 CPUID。只有 INVALID 返回和真实往返都完成才发布探针成功。原 Windows 启动快照只用于已限定指令流的探针收尾。
- `hvm_svm_nested_route` 在修改寄存器、RIP 或执行 MSR/I/O 前判断真实退出归属。权限图启用位必须与捕获的 VMCB 相符；共享归属先反射 L1，NPF 转组合页表解析，物理 INTR/NMI/SMI/INIT 转专门事件仲裁，未知/不一致退出保留故障。
- NPF 修复/重试前以 EXITINTINFO 重建被打断的事件；没有中断中的事件就清除旧 EVENTINJ，避免重放已完成的注入。软件 INT 需要有效 NRIP，否则明确拒绝重入。此路径仅恢复已有事件，不实现新的异常合成、物理 NMI 确认或 GIF 虚拟化。

验证：标准 MSVC/WDK Release x64 编译链接、x64 API 验证、CAT 生成零警告。新增 entry 8765、writeback 622、session 65 项断言通过，session 还使用八个宿主线程各跑 100 次模拟事务；生产分派模拟检查 240 项通过，既有 AMD/NPT/权限图/Intel 逻辑回归通过。这些线程没有执行 SVM，不能当成内层硬件并发通过。候选需要另行测试签名、来宾加载和真实单核→八核回归。

冻结后的离线增量：route 1925 项通过，事件重注入使 nested 检查增至 4551 项、生产分派增至 241 项，其余上述回归通过。再次标准 WDK Release/API/CAT 构建零警告；未进行本机装载、来宾启动或硬件复现。

通用入口仍未向普通常驻来宾开放。还需实现并集成：虚拟 GIF、物理 IRQ/NMI 与 L1/L2 事件归属和重注入；XCR0/XSS 切换及完整扩展状态管理；通用 MSR/IOIO/异常处理；跨核 VMCB 所有权及 NPT 源修改/失效协作；最后使用完整内层 OS 验证并发运行、停止和卸载。当前 NPT-only、扩展控制拒绝门未放宽，不支持的状态不会通过伪造 INVALID 来掩盖。

源码依据为 AMD APM Volume 2 的 VMRUN/VMEXIT、Event Injection、Nested Paging 与 VMCB Layout；本机保存的参考文本为 revision 3.38。字段写回目前包含 decode assists 的长度及 15 个指令字节。结构性 NPT01 生命周期稳定是读写 API 的前提；路径重验不能替代未来的跨核失效协议或对同一 VMCB 的同步。

## XCR0 切换增量

新增 `hvm_svm_xstate` 的分配边界与组件依赖校验，CPU 固定汇编前缀追加 HostXcr0/GuestXcr0 并断言偏移。退出后以整数指令恢复宿主 XCR0，再用固定全掩码保存状态；进入前先恢复完整状态，再切换来宾 XCR0。XSS 保持准备时原值，保存格式与容量不随来宾缩减掩码而改变。普通常驻仍拒绝 XSETBV，通用嵌套未开放。

受限探针新增 x87-only → INVALID 返回 → 真实内层入口 → L1 恢复原 XCR0；L1 和内层代码均执行 XGETBV 硬件读回。完整通过还需两次合法 XSETBV、内层往返和最终原生回读。失败仅在这个固定探针范围内恢复原 Windows 掩码。此硬件路径尚未运行，不能据编译/模拟断言 SIMD 内容保持已被硬件验证。

本轮已完成的验证：XSTATE policy 590326 项、生产分派 390 项，既有回归通过；标准 WDK Release/API/CAT 零警告。未签名、未装载，旧共享候选未替换。用户随后要求剩余静态实现连续推进、逐阶段 commit、暂不验证；之后新增内容单独标为未验证，不沿用本轮结果。

## XSS 与 CPUID.D 静态增量（未验证）

CPU 前缀追加 HostXss/GuestXss（128/130）；与 XCR0 一样，退出恢复 root 保存掩码后再 XSAVES，进入在完整 XRSTORS 后安装 guest 掩码，原生返回保留当前 guest 掩码。允许的 XSS 范围仍只有准备时已分配的 CET_U 子集，不支持 supervisor CET。原生读回比较当前 guest 掩码，固定自检额外要求它等于原值。

准备时固定每核 CPUID.D 组件几何，校验用户/监督组件归属、标准区域不重叠、大小/对齐及实际容量。来宾 CPUID.D.0/1 用 guest XCR0/XSS 算标准/压缩大小，其他子叶保留硬件布局，只暴露已分配组件；不查询 root 当前掩码作为 guest 答案。受限探针接入 leaf D，并在真实 x87-only 窗口检查 EBX=576。普通常驻尚不开放这些写操作。补了离线用例源码但按用户要求没有运行，也没有构建、签名、装载或硬件测试。

## 异常合成静态增量（未验证）

新增 nested_event：先检查原始异常的 L1 截获，再合成 contributory/#PF/#DF，单独检查合成 #DF 与 shutdown 的截获。shutdown 返回虚拟 CPU 状态决策，不执行宿主关机/复位。#PF 注入更新 guest CR2，所有故障保持 RIP。被打断且已确认的 IRQ/NMI 在结果中标为 Deferred；调用者未保留它时拒绝提交注入。普通 #GP/#UD 注入已使用该合成器；普通路径还没有 deferred 队列，遇到该状态仍保留故障，不丢事件。新增离线用例及构建清单，按用户指令未运行验证。物理 IRQ/NMI 确认、GIF/IRET 窗口和完整队列执行器仍需继续实现。

## 跨核 VMCB 所有权静态增量（未验证）

新增所有 CPU 共享的 4096 项固定身份表：键为翻译后的 VMCB 物理页，键在准备生命周期内不移动/删除，每次持有使用唯一原子 token。不同 GPA 的同页别名竞争同一项；无全局等待锁，过期释放不能清除新持有者，身份预算或 token 用尽明确拒绝。

Session 先解析身份、获取持有权、重新读取受保护快照，再进入/写回。INVALID 完整写回或真实 VMEXIT 输出完成后释放；部分写回或捕获失败保留 token。固定探针失败也要等汇编原生返回及真实寄存器回读之后才释放，公共 teardown 额外要求表内无持有者。CPU 证据使用 Windows group:number。该表协调 monitor 的 VMRUN；尚不能阻止来宾普通内存指令并发写 VMCB 或 NPT，后者继续实现。新增竞争/别名/过期释放/预算用例但未运行，未构建。

## VMLOAD/VMSAVE 通用事务静态增量（未验证）

新增 nested_transfer，并将生产受限探针的 VMLOAD/VMSAVE 改为调用它：任意操作数先经可信 NPT01 翻译，取得与 VMRUN 共用的 HPA lease，重读后只复制 VMLOAD 字段或按 VMSAVE 白名单写回。禁止借用运行中/故障保留的 Session；NRIP 在修改前检查，部分写入保留进度与 lease。原生确认后才允许故障清理。探针自身仍限制固定操作数；通用事务无此固定地址假设。未构建、未测试。

## 虚拟 INVLPGA 静态增量（未验证）

新增处理器本地全量虚拟失效：拒绝正在 L2/持有未完成 VMCB 的 Session，重置 NPT02 全部组成缓存并推进 epoch，保留原线性地址/虚拟 ASID/失效次数；下一次真实 VMRUN 仍 TLB_CONTROL=1。探针在真实内层返回后执行一条 INVLPGA，完成门要求它被处理。没有把 guest ASID 直接交给物理 INVLPGA。

这只满足当前虚拟 CPU 的失效语义：L1 修改共享 NPT 后仍须按架构在相关 vCPU 执行 shootdown；L0 不能把一核的本地 INVLPGA 当成所有核已确认。每次虚拟 VMRUN 原有的全缓存重置继续保留。跨核事件递送/停机确认和外层 NPT01 动态修改尚未开放，不能称并发完整验收完成。代码、fixture 和工程清单已写，未验证。

## 状态 MSR 通用层静态增量（未验证）

新增 nested_register：EFER 的虚拟 SVME 与执行 VMCB 所需 SVME 分离；按当前 CPL、允许位和 CR0.PG 检查写入，LMA 保留硬件当前值。L2 不能访问/更改 L1 的 HSAVE/VM_CR。XSS 使用已分配组件的虚拟值。PAT 检查全部字节：L2 更新自己的 G_PAT，L1 改变固定 NPT01 缓存契约返回实现不支持；S_CET 非零仍明确不支持。其它 MSR 不猜测转发。生产 probe 已改用此公共层，未验证。通用调度器还需将 GP/unsupported/反射等动作连接到各自状态路径。

## 通用 CPUID 契约静态增量（未验证）

新增 nested_cpuid，动态 OSXSAVE/CPUID.D 使用 guest CR4/XCR0/XSS；SVM 叶仅在调用者明确启用且满足 NPT/NRIP/ASID 门时发布，限制为 NPT/NRIP/flush-by-ASID/decode assists。L2 不发布更深层 SVM。未保存的 MPX/AMX/PKU/PKS/LA57/UINTR、未实现 supervisor CET/SEV 与未知 leaf7 子叶不透传；AVX/AVX512 与已分配组件集一致，硬件拓扑/外层 vendor 保留。probe 的 leaf D 已经调用公共函数。完整通用路径尚未公开启用，此模块不自行放开能力门。未构建测试。

## 通用执行分派静态增量（未验证）

新增 nested_execute，将已有 VMRUN/反射、VMLOAD/VMSAVE、CPUID、状态 MSR、XSETBV、INVLPGA、异常合成与 NPF 组成事务接为一般退出引擎。L1 原始截获优先；物理事件与 GIF 变更返回专用动作，必须由平台仲裁完成后才重入，不能当成普通成功。NPF 源故障与外层故障分开，页表预算满时重置 epoch 后重新遍历；部分写回保留所有权。

按 APM 的退出码表修正上一静态阶段写错的 INVLPGA 分支：正确退出码为 0x7a，0x86 是 SKINIT；后者明确拒绝，并清除相应 CPUID 能力。fixture 同步修正。当前引擎尚未接入普通 resident，未编译、未测试，不表示物理事件桥接或完整 L2 OS 已完成。

## 已确认事件账本静态增量（未验证）

新增 nested_pending：固定 16 项、唯一 token、L1/翻译后 VMCB12 身份隔离、NMI/IRQ 优先级与同优先级 FIFO；Queued/Armed 分离，硬件 INVALID 不消费，EXITINTINFO 中断递送重排原 token，完成递送或已提交的明确反射才能移除。溢出/代次耗尽保留现场。执行器异常 Deferred 已接该账本，L2 尚有待交接事件时拒绝直接反射/释放，防止跨 IDT 错投。补了测试源码及构建清单，未执行。物理确认、注入窗口与 IRET 完成判定仍继续实现。

## 物理事件入口静态增量（未验证、尚未开放）

新增 root NMI 确认 leaf：预先复制可信当前核 IDT，仅替换 vector 2 为不调用 C/Windows ISR 的计数/IRETQ 入口。确认前要求 IF=0、描述符身份未变、无旧待交接计数；在 GIF=0 安装，有限 STGI 窗口确认真实 NMI，再 CLGI 恢复原表。精确一次才返回成功，多次/饱和/未确认均保留 Count，不伪造事件已递送。它只允许从完整 root GS/CR3/XSTATE/私有栈、S_CET=0、GIF=0 环境调用；当前没有普通 resident 调用点，不能从 Windows 普通函数直接试运行。

CPU 汇编前缀追加 HostInterruptsAllowed（138），事件仲裁可在 GIF=0 时设置 VMRUN 保存的宿主 IF；每次 VMEXIT 后立即 CLI，再保存状态和调用 C。默认零且普通 INTCTL 不变，尚无入口启用新策略。NMI 描述符纳入逐核资源，未交接计数或活动窗口阻止释放。未构建/测试，物理 NMI 的来宾重新递送、IRET 完成与通用运行开关仍未完成。

## 中断控制转换静态增量（未验证）

新增 nested_interrupt：进入前覆盖执行控制，退出后先恢复原始控制再做归属判断；L1 GIF=0 时以 V_INTR_MASKING/hostIF=0 关闭物理 IRQ，保留并暂时屏蔽 V_IRQ，拦截 NMI。L2 保留内层 masking/TPR 请求，hostIF 来自实际 L1 VMRUN 保存的 IF。硬件 V_TPR/V_IRQ 输出单独合并，mask0 时真实 CR8 是权威值。INTR 反射保持 APIC 待处理，root 不做 INTACK/EOI；NMI 必须确认后保存，SMI/INIT 未实现路径明确拒绝。V_IGN_TPR 位准入补全。

NMI 确认 leaf 调整为同 CS、IST0 的受控近返回，保留硬件 NMI blocking；避免先在 root IRET 解屏蔽，再用本身不阻塞后续 NMI 的 EVENTINJ 制造错误窗口。实际 guest IRET 完成才自然解除硬件阻塞，不能在 IRET 截获时提前宣布解除。保存原 RSP（包括硬件对齐前值）和寄存器/flags；计数必须交接，资源全局释放门同步保留其宿主栈/HSAVE。此实现未构建/运行，需要后续硬件验证，现阶段仍无普通 resident 调用点。通用调度器还需接 CR8 同步、队列窗口、停止协议。

## 运行协调器静态增量（未验证）

新增 nested_machine，串联退出控制恢复、物理事件分类/确认/排队/反射、通用指令执行、GIF 提交、下一次 TPR/控制/事件准备。首次读取真实 CR8；mask0 的 L2 对物理 CR8 修改保留给返回 L1，L1 受强制 masking 的 CR8 修改在下一次进入前同步。NMI 确认分两步，只有软件账本接收后才能清物理捕获计数。

已排队注入中遇到 NPF 时保留同一 token 并重试，不再次确认、不重复入队；真实 EXITINTINFO 可在完整 VMEXIT 写回后交给 L1。正常模拟指令完成消耗之前的单指令 interrupt shadow。停止条件逐核检查 L2/lease、虚拟 SVME/HSAVE、事件、GIF 和活动 overlay，不能从 CLI 退出推断停止。

协调器对尚未处理的注入碰撞、阻塞窗口、跨上下文待处理事件返回 WINDOW，明确禁止当作 READY 重入；这些分支和 Windows 平台绑定/公开入口继续实现，不能据此称全部静态工作完成。新增源码已入工程，修正新增测试命令在旧 exit 后不可达的问题；本阶段未构建或执行测试。

## IRQ 窗口与物理 NMI 待处理规则（静态、未验证）

新增 nested_window：对被 IF/TPR/shadow 阻塞的已确认 IRQ，使用原 vector 优先级的 V_IRQ + 强制 VINTR 截获请求可递送窗口；真实递送随后由原 queue token 完成，sentinel 不能进入来宾 IDT，退出时先撤销窗口再撤销 GIF 控制覆盖。已有 EVENTINJ/V_IRQ 碰撞不盲目覆盖。

物理 NMI 在首次注入之前单独标记 physical：L1 带待处理 NMI 再执行 VMRUN 时，若其 VMCB12 要求 NMI 截获则在首条 L2 指令前返回 NMI VMEXIT；否则该尚未开始的物理递送可绑定到 L2。已经注入/中断递送的事件不能重新绑定，且始终保留唯一 token。复杂 EVENTINJ 碰撞、NMI shadow 等窗口仍显式 WINDOW，后续平台接线和这些边界继续写；不宣布硬件或静态全部完成。未构建、未运行。

## Windows 平台绑定静态增量（未验证）

新增 nested_general，使用现有逐核 NPT01/RAM window、合并权限图、Session/lease、XSTATE 与可信 IDTR 绑定协调器。提供 root CR8 读写/回读、NMI 确认与 queue 提交、原始 CPUID 回调；不分配 root 内存、不调用 Windows ISR。私有 query/stop 在退出控制恢复后处理，L2 不得使用 L0 的停止 hypercall；SVME/HSAVE、L2、待处理事件或 GIF 未交还时 stop 返回非零并保持常驻。

通用状态全部纳入逐核堆资源，父子释放共用 Busy 判据，防止子释放保留后父层仍释放宿主栈/HSAVE。初始化仅绑定资源；公共 flag、汇编入口激活和剩余复杂窗口仍未开放/未完成，现有普通 resident 不会因这次提交开始 SVM 转发。此阶段未构建、未测试。
