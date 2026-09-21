# VMCB12 EVENTINJ 消费状态漏写：现场分析与离线修复

2026-09-21。已确认并修复一个可由生产代码离线复现的语义缺陷：虚拟 VMEXIT 没有清除 VMCB12 的 EVENTINJ，也没有把清除结果写回 L1 持有的操作数页。L1 再执行 VMRUN 时可重放旧注入请求。本次现场与该缺陷相符，但新候选尚未硬件执行，不能声称完整 L2 启动已修复或排除其它原因。

## 现场独立核验

原始目录 `artifacts/flightrecorder-v6-incident-20260921-193957/` 的 manifest 文件大小和 SHA256 均核验，两份导出二进制与 metrics 内十六进制 VMCB 逐字节一致。唯一一致锁存为宿主 CPU0:22，SHUTDOWN、分派前、有效 VMCB12；宿主 CPU 编号不是 VMware 来宾 vCPU 编号。

| 序号 | 观测 |
|---|---|
| 407175–407187 | IRQ 0x68 的递送被 NPF 打断，EXITINTINFO 有效，后续进入重新注入相同事件。仅这些 NPF 不能证明组合页表错误。 |
| 407188–407191 | EXITINTINFO/EVENTINJ 均为零，RSP/RIP 已改变，来宾执行继续；这与此前 IRQ 递送已经结束相符。 |
| 407192 | CR4 写拦截（exit=0x14），EVENTINJ/EXITINTINFO 均零，operandHostPa=0x58180f000、lease=68328。 |
| 407193 | 同一操作数的新会话 lease=68329，RIP 从0xFEC07D5推进到0xFEC07F4，但 EVENTINJ 又为0x80000068。单靠记录不能排除 L1 主动重注入；代码回归独立证明旧请求确实不会被清除。 |
| 407194–407205 | 再次递送0x68时发生 NPF，并重复事件恢复。 |
| 407206 | 硬件SHUTDOWN=0x7f，EXITINTINFO=0x80000b08、CR2=0xfffffc98，冻结在驱动分派前。 |

冻结的 GDTR.base=0xfffffc80，CR2=base+0x18，与当前CS选择子所指描述符位置一致。这是地址关系，缺少当时IDT和页表内存，不能据此断言具体哪个描述符访问或源页表项最先出错。

额外只读保存了 `artifacts/flightrecorder-v6-analysis/vmware-followup.log`，它记录19:38:50.484（UTC+8）的来宾vcpu-0三重故障。采集时间晚于原导出，未追加到原manifest冒充同时快照。未停止/重启/重置VM、卸载或重新加载宿主驱动。

## 修复边界

- `hvm_svm_nested_state.c`：正常反射清除完整64位EVENTINJ，包含错误码载荷；保留原始EXITINTINFO，使L1仍能识别并决定重试被打断的递送。
- `hvm_svm_nested_entry.c`：INVALID虚拟退出同样清除EVENTINJ，保留未执行的来宾save状态。
- `hvm_svm_nested_writeback.c`：正常/INVALID VMEXIT允许写回0xA8的完整清除值；VMSAVE仍不写此字段。
- 不改NPF解析、NPT权限、中断屏蔽、异常聚合或物理事件确认；原有L0内部NPF重试继续通过EXITINTINFO恢复事件。

VMEXIT清除EVENTINJ的规则与[Linux上游修复69b721a86d0d](https://github.com/torvalds/linux/commit/69b721a86d0dcb026f6db7d111dcde7550442d2e)引用的AMD VMRUN说明一致。该来源还涵盖未执行L2即返回INVALID的情形。没有复制外部实现代码。

## 验证

新增测试使用生产 SessionEnter → SessionReflect → 再次 SessionEnter，模拟硬件已清除EVENTINJ后的CR4写退出。修复前稳定失败于操作数EVENTINJ应为零的断言（`test-eventinj-before-fix.log`）；修复后覆盖正常结束、不完整递送元数据保留、无L1新请求时不重放、L1显式新请求可注入，以及INVALID清除完整错误码。

22个离线目标全通过，含90项session检查及8线程各100次模拟会话；writeback628项通过。旧INVALID用例原先假设除了退出字段全部字节不变，已将EVENTINJ的8字节明确改为零断言，其余字节仍逐项保持断言。

标准MSVC/WDK Release x64、x64 ApiValidator Universal、CAT生成通过，驱动零警告。没有协议/CLI变更，沿用配套metrics v6 CLI。独立未签名候选为 `tools/hvm_lab/artifacts/eventinj-clear-v6/`，未替换已运行候选；硬件复测仍未执行。候选身份和哈希见同目录identity.json。

原始metrics SHA256：`58eb81e10fcfdab45d244660fc44ad6934f329fbe5777eaecd0ba57bb3ffddee`。
冻结current VMCB SHA256：`1c1344556f211bea16ca66fff0b2e785e273a6bee7aed818cedbab70a8f6b838`。
冻结VMCB12 SHA256：`1979dba25fe7269f7b48ae6f7b0c34721c63c15d910e9e91b60f32d362898b0e`。
