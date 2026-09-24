# 2026-09-24 宿主崩溃排查

本轮完整开机验收失败，并升级为宿主蓝屏。停止动态测试；未重新加载驱动或启动 VM。重启后 KswordARK 为 Manual/Stopped。

## 已确认的触发链

- 候选源码 `16e850af`，运行映像为 `operand-page-v7/KswordARK.sys`。已保存签后 SYS 和匹配私有 PDB。
- WER 记录 bugcheck `0x20001(0x53564d, 0xffffb681e58ed900, 0x121, 0x400)`。
- 转储调用栈：`KswordSvmExit → KswSvmFatal → nt!KeBugCheckEx`。这是 KSword 主动触发的宿主蓝屏，不能归因于 Hyper-V 服务或仅 VMware 来宾关闭。
- CPU 标识 `0:24`，会话处于 L2，硬件退出 `0x400`，`EXITINFO1=0x100000004`，故障 GPA `0x60932d0`。
- `EXITINTINFO=0x8000042d` 是软件中断向量 0x2d 的递送现场；RIP `0xfffff806305fd103`，NRIP 为零，EVENTINJ 为零。
- 本次 MMU 解析成功：Status/FaultOwner 均零，两级 walk complete，生成叶 `0x17f1aa067`，对应当前 GPA，epoch `0x7a76`；NpfRetries 已归零。不是触发 64 次重试上限。
- `KswSvmNestedResumeEvent` 对 type=4 强制要求有效 NRIP；本现场返回 `KSW_NSVM_EVENT_NRIP_REQUIRED=2`。调用者把非 OK 转为 EXEC_FAULT，再转 MACHINE_FAULT=1；`0x120+1` 正是 bugcheck Detail `0x121`。
- 用导出的原始 VMCB 调用未修改的生产事件恢复函数，离线结果确为 2，且 VMCB 未被修改。未进行任何新的硬件重现。

首故障 ring 1727261 是进入记录（未注入事件）；1727262 捕获上述原始 NPF/software INT 递送；1727263 是处理后的 INTERNAL 锁存。这不是先前的硬件 SHUTDOWN/#DF，也不是仅凭 CPU 占用图推测的死循环。

## 修复边界

直接缺口是软件事件在 NPF 期间的恢复状态处理，以及该不完整处理最终使整个宿主 bugcheck。不能简单删除 NRIP 校验、伪造 RIP+2 或继续使用退出后清零的 NRIP。

需要区分实际执行的软件 INT 与先前注入的软件事件，分别保留/恢复正确的返回 RIP、CS 与事件身份。Linux SVM 的 `svm_complete_soft_interrupt` 也明确处理递送退出清除 next_rip 后的恢复，但该代码针对注入事件的快照规则不能直接套到本次未注入的 INT 现场。[上游实现](https://code.googlesource.com/linux/torvalds/linux/+/91542863abade2fd4f2b361991f5386ad9d19c8c/arch/x86/kvm/svm/svm.c)

本次证据没有证明整页复制产生了数据破坏，也不能据此宣称该优化没有其他问题；已确认的是以上事件恢复拒绝链。后续先补离线回归和恢复实现，不立即进行实体机重试。

## 本地证据

目录 `artifacts/host-crash-20260924-0910/`：完整 MEMORY.DMP（2,714,541,045 字节）、minidump、SYS/PDB、事件与 VMware 日志、hashes.json、private-debug.txt、failure-debug.txt、mmu-debug.txt、guest-vmcb.bin、vmcb12.bin、flight.bin/flight-decoded.json、replay-result.txt。转储只留本地，不入 Git。

内核公共符号下载等待被终止；以上结构解析使用匹配的 KSword 私有符号，未将未完成的公共符号分析写成成功。
