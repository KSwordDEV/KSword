# 2026-09-21 宿主冻结：原因未确定

用户确认整个实体机冻结后恢复。以下均为事后只读取证，不是故障复现或安全漏洞证明。

## 时间线（北京时间）

- 10:08:33：上一个八核克隆完成正常关闭，VMware 记录 `VMX exit (0)`。
- 10:10:02：单核克隆启动，Workstation 16.2.5 build 20904516，`Monitor Mode: CPL0`、`NumVCPUs 1`。开启 DX11/3D 渲染，但这只是配置事实，不是故障归因。
- 10:10:29：来宾 VMware Tools 开始运行。最后一条 VMware 日志为 10:11:10 的 GuestRpc 连接关闭，没有显式 panic/assert 或 CPU disabled 记录。
- 10:13:20：宿主本次启动时间。
- 10:13:24：Kernel-Power 41，BugcheckCode=0、SleepInProgress=0、PowerButtonTimestamp=0。
- 10:13:29：EventLog 6008 报告前次约 10:11:01 异常关闭。该推算时间不是精确冻结时刻，不能用它否定 10:11:10 的最后日志。

## 执行范围与证据限制

新候选源码提交 `4ec4d724`，共享目录 `nested-entry-20260921`，SYS/PDB GUID `e4cc4cb2-c439-411a-b14d-0a1a0f78fedc`、age 5；本轮仅构建、测试签名和暂存，尚未执行来宾候选加载脚本或新的 SVM 探针。没有在实体宿主发出装载驱动、prepare 或 resident 命令。KD 日志止于等待重连，没有已连接并暂停来宾的证据。

取证时宿主 KswordARK 服务为 Stopped，VMware/kd 测试进程不再运行；这些是重启后状态，不能倒推冻结瞬间全部驱动状态。当前 HypervisorPresent=true，与此前原生 AMD-V 实验启动条件不同，不能直接继续原测试。

未发现本次新内核/LiveKernel/VMware 转储。已有宿主转储属于 00:31，VMware 转储属于 09-18；不将它们归到本事件。对 00:31 mini dump 的只读 KD 打开遭遇访问拒绝，没有修改 ACL、提权或继续解析。窗口内未检索到 WHEA、Display、显卡驱动或 BugCheck 的归因记录；日志缺失不等于排除这些原因。

## 结论

这是与克隆启动时间相邻的宿主可用性故障，目前根因未知。没有证据证明 CPU 永久锁定、新候选执行触发、跨虚拟机权限突破或可利用安全漏洞。暂不将其归因于某个厂商、驱动或新代码。

原始证据保存在 `tools/hvm_lab/artifacts/host-freeze-20260921-101828/`，包括两个启动代次的 VMware 日志、VMX、KD 日志、事件 XML 和事后环境记录。硬件验证暂停，继续离线构建与逻辑实现；本次新候选的硬件结果仍为 NOT_RUN。以后恢复实验应重新验证宿主启动环境，不能把旧 LabHostReady 证据跨重启复用。
