# AMD 通用 VMRUN 事务（2026-09-21）

最终验收仍是完整 L2 操作系统启动及内层 vCPU 并发运行；本变更没有完成该验收。

已实现并接入生产受限探针：

- `hvm_svm_nested_entry` 对私有 VMCB12 做模式、ASID、权限图范围、PAT、事件等准入，区分架构 INVALID 与尚不支持的特性。组合 VMCB02 的拦截、TSC offset 与自动状态，硬件指针全部来自 L0 预分配资源。
- `hvm_svm_nested_writeback` 在稳定 NPT01 上重新验证写权限和捕获时的 HPA，再调用 RAM 窗口提交。VMEXIT、INVALID、VMSAVE 使用三个固定字段集合；保留控制指针、保留位和共享字内不属于硬件输出的位。跨页、缓存属性不符、物理映射改变都拒绝；部分提交保留进度，不能自动重试。
- `hvm_svm_nested_session` 每次 VMRUN 保存实际 L1 continuation，支持任意已翻译的 VMCB 地址。INVALID 写回后正常返回 L1，修正操作数可再次进入；真正 VMCB02 的硬件 INVALID 是 monitor 故障，不伪装为 L1 责任。反射保留当前 VMLOAD 状态、CR2、DR6 与非自动 GPR。
- 探针改为先故意 ASID=0、检查退出字段 INVALID、修正同一 VMCB 后再实际进入内层 CPUID。只有 INVALID 返回和真实往返都完成才发布探针成功。原 Windows 启动快照只用于已限定指令流的探针收尾。

验证：标准 MSVC/WDK Release x64 编译链接、x64 API 验证、CAT 生成零警告。新增 entry 8765、writeback 622、session 65 项断言通过，session 还使用八个宿主线程各跑 100 次模拟事务；生产分派模拟检查 240 项通过，既有 AMD/NPT/权限图/Intel 逻辑回归通过。这些线程没有执行 SVM，不能当成内层硬件并发通过。候选需要另行测试签名、来宾加载和真实单核→八核回归。

通用入口仍未向普通常驻来宾开放。还需实现并集成：虚拟 GIF、物理 IRQ/NMI 与 L1/L2 事件归属和重注入；XCR0/XSS 切换及完整扩展状态管理；通用 MSR/IOIO/异常处理；跨核 VMCB 所有权及 NPT 源修改/失效协作；最后使用完整内层 OS 验证并发运行、停止和卸载。当前 NPT-only、扩展控制拒绝门未放宽，不支持的状态不会通过伪造 INVALID 来掩盖。

源码依据为 AMD APM Volume 2 的 VMRUN/VMEXIT、Event Injection、Nested Paging 与 VMCB Layout；本机保存的参考文本为 revision 3.38。字段写回目前包含 decode assists 的长度及 15 个指令字节。结构性 NPT01 生命周期稳定是读写 API 的前提；路径重验不能替代未来的跨核失效协议或对同一 VMCB 的同步。
