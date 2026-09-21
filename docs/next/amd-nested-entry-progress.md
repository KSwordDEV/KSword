# AMD 通用 VMRUN 事务（2026-09-21）

最终验收仍是完整 L2 操作系统启动及内层 vCPU 并发运行；本变更没有完成该验收。

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
